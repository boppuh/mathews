from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from mathews_control_plane.app import create_app
from mathews_control_plane.approvals import (
    ApprovalConflictError,
    ApprovalPreconditionError,
    ApprovalPreconditionEvaluator,
    ApprovalRequestResult,
    ApprovalRetryAttempt,
    ApprovalService,
    BlockedOperation,
    InvalidApprovalError,
)
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.authentication import AuthenticationService
from mathews_control_plane.database import (
    Base,
    SessionFactory,
    create_database_engine,
    create_session_factory,
    create_task_record,
)
from mathews_control_plane.domain_models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalRequestType,
    ApprovalStatus,
    Brief,
    BriefApprovalDecision,
    BriefDecisionDisposition,
    EvidenceRecord,
    PolicyVersion,
    RuleCandidate,
    RuleCandidateStatus,
    Task,
    TaskEvent,
    TaskState,
)
from mathews_control_plane.settings import Settings
from pydantic import SecretStr
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


@dataclass(slots=True)
class ApprovalHarness:
    engine: Engine
    factory: SessionFactory
    store: ArtifactStore


@pytest.fixture
def approval_harness(tmp_path: Path) -> Iterator[ApprovalHarness]:
    engine = create_database_engine(
        f"sqlite:///{tmp_path / 'approvals.sqlite3'}"
    )
    Base.metadata.create_all(engine)
    yield ApprovalHarness(
        engine=engine,
        factory=create_session_factory(engine),
        store=ArtifactStore(tmp_path / "artifacts"),
    )
    engine.dispose()


def _create_task(
    harness: ApprovalHarness,
    *,
    state: TaskState,
    with_brief: bool = False,
    with_rule_candidate: bool = False,
) -> tuple[UUID, UUID, UUID | None]:
    with harness.factory.begin() as session:
        task = create_task_record(
            session,
            harness.store,
            repository="boppuh/mathews",
            base_revision="1" * 40,
            requester="local-user",
            raw_request="Implement approval handling",
            summary="Implement approvals",
            owner_id="local-user",
            actor_id="local-user",
        )
        task.state = state
        if session.scalar(
            select(PolicyVersion.id).where(
                PolicyVersion.lineage_key == "mvp",
                PolicyVersion.version == 1,
            )
        ) is None:
            session.add(
                PolicyVersion(
                    lineage_key="mvp",
                    version=1,
                    workflow_thresholds={},
                    approved_by="local-user",
                    approved_at=_NOW - timedelta(minutes=1),
                    owner_id="local-user",
                    actor_id="local-user",
                    root_correlation_id=task.root_correlation_id,
                )
            )
        session.flush()
        evidence_id = session.scalar(
            select(EvidenceRecord.id).where(
                EvidenceRecord.task_id == task.id
            )
        )
        assert evidence_id is not None
        subject_id: UUID | None = None
        context = {
            "owner_id": task.owner_id,
            "actor_id": "control-plane",
            "root_correlation_id": task.root_correlation_id,
            "causation_id": task.id,
            "parent_correlation_id": task.id,
        }
        if with_brief:
            brief = Brief(
                task_id=task.id,
                version=1,
                scope={"summary": "approval work"},
                exclusions=[],
                acceptance_criteria=[{"id": "approval"}],
                risks=[],
                affected_flow={"id": "primary"},
                test_plan=[{"id": "check"}],
                **context,
            )
            session.add(brief)
            session.flush()
            disposition = BriefApprovalDecision(
                task_id=task.id,
                brief_id=brief.id,
                disposition=(
                    BriefDecisionDisposition.HUMAN_APPROVAL_REQUIRED
                ),
                evaluator_id="brief-policy",
                reason="Approval required",
                ambiguity_flags=["scope"],
                decided_at=_NOW,
                **context,
            )
            session.add(disposition)
            session.flush()
            task.accepted_brief_id = brief.id
            task.brief_approval_decision_id = disposition.id
            subject_id = brief.id
        elif with_rule_candidate:
            candidate = RuleCandidate(
                task_id=task.id,
                proposed_rule="Retry exact formatting failures once.",
                cited_evidence_ids=[str(evidence_id)],
                recurrence_assessment="repeated",
                severity_assessment="low",
                false_positive_risks=[],
                evaluation_result={"passed": True},
                status=RuleCandidateStatus.EVALUATED,
                **context,
            )
            session.add(candidate)
            session.flush()
            subject_id = candidate.id
        session.flush()
        return task.id, evidence_id, subject_id


def _blocked_operation(name: str = "host.mutate") -> BlockedOperation:
    return BlockedOperation(
        operation_name=name,
        idempotency_key="approval-operation-1",
        input_fingerprint="a" * 64,
    )


def _service(
    harness: ApprovalHarness,
    *,
    clock: list[datetime] | None = None,
    evaluator: ApprovalPreconditionEvaluator | None = None,
) -> ApprovalService:
    current = clock or [_NOW]
    return ApprovalService(
        harness.factory,
        harness.store,
        precondition_evaluator=evaluator,
        clock=lambda: current[0],
    )


def _request(
    service: ApprovalService,
    *,
    task_id: UUID,
    evidence_id: UUID,
    expected_state: TaskState,
    request_type: ApprovalRequestType,
    subject_id: UUID | None = None,
    request_id: UUID | None = None,
    expires_at: datetime | None = None,
) -> tuple[UUID, ApprovalRequestResult]:
    identity = request_id or uuid4()
    is_brief = request_type is ApprovalRequestType.BRIEF
    is_rule = request_type is ApprovalRequestType.REVIEW_RULE
    retry_history = (
        (
            ApprovalRetryAttempt(
                attempt=1,
                error_code="VALIDATION_FAILED",
                occurred_at=_NOW - timedelta(minutes=1),
                checkpoint_evidence_id=evidence_id,
            ),
        )
        if request_type is ApprovalRequestType.RETRY_LIMIT
        else ()
    )
    result = service.request(
        task_id,
        request_id=identity,
        expected_state=expected_state,
        request_type=request_type,
        reason_code=f"{request_type.value}_REQUIRED",
        subject_type=(
            "BRIEF"
            if is_brief
            else "RULE_CANDIDATE"
            if is_rule
            else "BLOCKED_OPERATION"
        ),
        subject_id=subject_id,
        blocked_operation=(
            None if is_brief else _blocked_operation()
        ),
        retry_history=retry_history,
        evidence_ids=(evidence_id,),
        expires_at=expires_at or _NOW + timedelta(hours=1),
    )
    return identity, result


def test_exact_brief_approval_is_audited_idempotent_and_resumes(
    approval_harness: ApprovalHarness,
) -> None:
    task_id, evidence_id, brief_id = _create_task(
        approval_harness,
        state=TaskState.BRIEFING,
        with_brief=True,
    )
    assert brief_id is not None
    service = _service(approval_harness)
    request_id = uuid4()

    _, first = _request(
        service,
        task_id=task_id,
        evidence_id=evidence_id,
        expected_state=TaskState.BRIEFING,
        request_type=ApprovalRequestType.BRIEF,
        subject_id=brief_id,
        request_id=request_id,
    )
    _, replay = _request(
        service,
        task_id=task_id,
        evidence_id=evidence_id,
        expected_state=TaskState.BRIEFING,
        request_type=ApprovalRequestType.BRIEF,
        subject_id=brief_id,
        request_id=request_id,
    )
    decision_id = uuid4()
    decision = service.decide(
        request_id,
        decision_id=decision_id,
        decision=ApprovalDecision.APPROVE,
        actor_id="local-user",
    )
    decision_replay = service.decide(
        request_id,
        decision_id=decision_id,
        decision=ApprovalDecision.APPROVE,
        actor_id="local-user",
    )

    assert first.task_state is TaskState.BRIEF_PENDING_APPROVAL
    assert replay == replace(first, replayed=True)
    assert decision.task_state is TaskState.IMPLEMENTING
    assert decision.status is ApprovalStatus.APPROVED
    assert decision_replay == replace(decision, replayed=True)
    with approval_harness.factory() as session:
        task = session.get(Task, task_id)
        request = session.get(ApprovalRequest, request_id)
        brief_decision = session.get(
            BriefApprovalDecision,
            task.brief_approval_decision_id if task is not None else None,
        )
        events = list(
            session.scalars(
                select(TaskEvent)
                .where(TaskEvent.task_id == task_id)
                .order_by(TaskEvent.sequence)
            )
        )
    assert task is not None and request is not None
    assert brief_decision is not None
    assert task.state is TaskState.IMPLEMENTING
    assert request.precondition_fingerprint != "0" * 64
    assert request.request_fingerprint != "0" * 64
    assert brief_decision.human_response == ApprovalDecision.APPROVE.value
    assert [event.event_type for event in events] == [
        "TASK_STATE_TRANSITION",
        "APPROVAL_REQUESTED",
        "TASK_STATE_TRANSITION",
        "APPROVAL_DECIDED",
    ]


def test_brief_revision_returns_only_to_briefing(
    approval_harness: ApprovalHarness,
) -> None:
    task_id, evidence_id, brief_id = _create_task(
        approval_harness,
        state=TaskState.BRIEFING,
        with_brief=True,
    )
    assert brief_id is not None
    service = _service(approval_harness)
    request_id, _result = _request(
        service,
        task_id=task_id,
        evidence_id=evidence_id,
        expected_state=TaskState.BRIEFING,
        request_type=ApprovalRequestType.BRIEF,
        subject_id=brief_id,
    )

    result = service.decide(
        request_id,
        decision_id=uuid4(),
        decision=ApprovalDecision.REQUEST_REVISION,
        actor_id="local-user",
    )

    assert result.status is ApprovalStatus.REJECTED
    assert result.task_state is TaskState.BRIEFING


@pytest.mark.parametrize(
    ("request_type", "expected_options"),
    (
        (
            ApprovalRequestType.UNSAFE_ACTION,
            ["APPROVE", "DENY", "CANCEL"],
        ),
        (
            ApprovalRequestType.RETRY_LIMIT,
            ["RETRY", "ABANDON", "CANCEL"],
        ),
        (
            ApprovalRequestType.REVIEW_CONFLICT,
            ["APPROVE", "DENY", "CANCEL"],
        ),
    ),
)
def test_escalation_categories_store_exact_resume_operation_and_expiry(
    approval_harness: ApprovalHarness,
    request_type: ApprovalRequestType,
    expected_options: list[str],
) -> None:
    task_id, evidence_id, _subject_id = _create_task(
        approval_harness,
        state=TaskState.VALIDATING,
    )
    request_id, result = _request(
        _service(approval_harness),
        task_id=task_id,
        evidence_id=evidence_id,
        expected_state=TaskState.VALIDATING,
        request_type=request_type,
    )

    assert result.task_state is TaskState.ESCALATED
    with approval_harness.factory() as session:
        task = session.get(Task, task_id)
        request = session.get(ApprovalRequest, request_id)
    assert task is not None and request is not None
    assert task.escalation_resume_state is TaskState.VALIDATING
    assert request.resume_state is TaskState.VALIDATING
    assert request.blocked_operation == _blocked_operation().to_dict()
    assert request.options == expected_options
    assert request.expires_at is not None
    assert request.expires_at.replace(tzinfo=UTC) == _NOW + timedelta(hours=1)
    assert len(request.retry_history) == (
        1 if request_type is ApprovalRequestType.RETRY_LIMIT else 0
    )


def test_request_rejects_checkpoint_not_in_supporting_evidence(
    approval_harness: ApprovalHarness,
) -> None:
    task_id, evidence_id, _subject_id = _create_task(
        approval_harness,
        state=TaskState.IMPLEMENTING,
    )

    with pytest.raises(
        InvalidApprovalError,
        match="checkpoint evidence",
    ):
        _service(approval_harness).request(
            task_id,
            request_id=uuid4(),
            expected_state=TaskState.IMPLEMENTING,
            request_type=ApprovalRequestType.UNSAFE_ACTION,
            reason_code="UNSAFE_ACTION_REQUIRED",
            subject_type="BLOCKED_OPERATION",
            subject_id=None,
            blocked_operation=BlockedOperation(
                operation_name="host.mutate",
                idempotency_key="approval-operation-1",
                input_fingerprint="a" * 64,
                checkpoint_evidence_id=uuid4(),
            ),
            evidence_ids=(evidence_id,),
            expires_at=_NOW + timedelta(hours=1),
        )


def test_retry_limit_approval_resumes_only_the_recorded_state(
    approval_harness: ApprovalHarness,
) -> None:
    task_id, evidence_id, _subject_id = _create_task(
        approval_harness,
        state=TaskState.REPAIRING,
    )
    service = _service(approval_harness)
    request_id, _result = _request(
        service,
        task_id=task_id,
        evidence_id=evidence_id,
        expected_state=TaskState.REPAIRING,
        request_type=ApprovalRequestType.RETRY_LIMIT,
    )

    result = service.decide(
        request_id,
        decision_id=uuid4(),
        decision=ApprovalDecision.RETRY,
        actor_id="local-user",
    )

    assert result.status is ApprovalStatus.APPROVED
    assert result.task_state is TaskState.REPAIRING
    with approval_harness.factory() as session:
        task = session.get(Task, task_id)
    assert task is not None
    assert task.escalation_resume_state is None
    assert task.terminal_outcome is None


@pytest.mark.parametrize(
    ("request_type", "decision", "status", "target"),
    (
        (
            ApprovalRequestType.UNSAFE_ACTION,
            ApprovalDecision.DENY,
            ApprovalStatus.REJECTED,
            TaskState.FAILED,
        ),
        (
            ApprovalRequestType.RETRY_LIMIT,
            ApprovalDecision.ABANDON,
            ApprovalStatus.REJECTED,
            TaskState.FAILED,
        ),
        (
            ApprovalRequestType.UNSAFE_ACTION,
            ApprovalDecision.CANCEL,
            ApprovalStatus.CANCELLED,
            TaskState.CANCELLED,
        ),
    ),
)
def test_deny_abandon_and_cancel_have_explicit_terminal_outcomes(
    approval_harness: ApprovalHarness,
    request_type: ApprovalRequestType,
    decision: ApprovalDecision,
    status: ApprovalStatus,
    target: TaskState,
) -> None:
    task_id, evidence_id, _subject_id = _create_task(
        approval_harness,
        state=TaskState.IMPLEMENTING,
    )
    service = _service(approval_harness)
    request_id, _result = _request(
        service,
        task_id=task_id,
        evidence_id=evidence_id,
        expected_state=TaskState.IMPLEMENTING,
        request_type=request_type,
    )

    result = service.decide(
        request_id,
        decision_id=uuid4(),
        decision=decision,
        actor_id="local-user",
    )

    assert result.status is status
    assert result.task_state is target
    with approval_harness.factory() as session:
        task = session.get(Task, task_id)
    assert task is not None
    assert task.state is target
    assert task.terminal_outcome == target.value


class RejectingPreconditions:
    def recheck(
        self,
        session: Session,
        task: Task,
        request: ApprovalRequest,
        decision: ApprovalDecision,
        *,
        now: datetime,
    ) -> bool:
        del session, task, request, decision, now
        return False


def test_changed_preconditions_block_resume_without_consuming_decision(
    approval_harness: ApprovalHarness,
) -> None:
    task_id, evidence_id, _subject_id = _create_task(
        approval_harness,
        state=TaskState.PR_ACTIVE,
    )
    service = _service(
        approval_harness,
        evaluator=RejectingPreconditions(),
    )
    request_id, _result = _request(
        service,
        task_id=task_id,
        evidence_id=evidence_id,
        expected_state=TaskState.PR_ACTIVE,
        request_type=ApprovalRequestType.REVIEW_CONFLICT,
    )

    with pytest.raises(
        ApprovalPreconditionError,
        match="preconditions changed",
    ):
        service.decide(
            request_id,
            decision_id=uuid4(),
            decision=ApprovalDecision.APPROVE,
            actor_id="local-user",
        )

    with approval_harness.factory() as session:
        task = session.get(Task, task_id)
        request = session.get(ApprovalRequest, request_id)
    assert task is not None and request is not None
    assert task.state is TaskState.ESCALATED
    assert task.escalation_resume_state is TaskState.PR_ACTIVE
    assert request.status is ApprovalStatus.PENDING
    assert request.decision_id is None


def test_rule_candidate_approval_is_non_executable_until_recorded(
    approval_harness: ApprovalHarness,
) -> None:
    task_id, evidence_id, candidate_id = _create_task(
        approval_harness,
        state=TaskState.REPAIRING,
        with_rule_candidate=True,
    )
    assert candidate_id is not None
    service = _service(approval_harness)
    request_id, _result = _request(
        service,
        task_id=task_id,
        evidence_id=evidence_id,
        expected_state=TaskState.REPAIRING,
        request_type=ApprovalRequestType.REVIEW_RULE,
        subject_id=candidate_id,
    )

    result = service.decide(
        request_id,
        decision_id=uuid4(),
        decision=ApprovalDecision.APPROVE,
        actor_id="local-user",
    )

    assert result.task_state is TaskState.REPAIRING
    with approval_harness.factory() as session:
        candidate = session.get(RuleCandidate, candidate_id)
    assert candidate is not None
    assert candidate.status is RuleCandidateStatus.APPROVED


def test_rule_candidate_rejection_records_decision_and_resumes(
    approval_harness: ApprovalHarness,
) -> None:
    task_id, evidence_id, candidate_id = _create_task(
        approval_harness,
        state=TaskState.REPAIRING,
        with_rule_candidate=True,
    )
    assert candidate_id is not None
    service = _service(approval_harness)
    request_id, _result = _request(
        service,
        task_id=task_id,
        evidence_id=evidence_id,
        expected_state=TaskState.REPAIRING,
        request_type=ApprovalRequestType.REVIEW_RULE,
        subject_id=candidate_id,
    )

    result = service.decide(
        request_id,
        decision_id=uuid4(),
        decision=ApprovalDecision.REJECT,
        actor_id="local-user",
    )

    assert result.status is ApprovalStatus.REJECTED
    assert result.task_state is TaskState.REPAIRING
    with approval_harness.factory() as session:
        candidate = session.get(RuleCandidate, candidate_id)
        task = session.get(Task, task_id)
    assert candidate is not None and task is not None
    assert candidate.status is RuleCandidateStatus.REJECTED
    assert task.escalation_resume_state is None
    assert task.terminal_outcome is None


def test_cancelling_rule_review_does_not_reject_candidate(
    approval_harness: ApprovalHarness,
) -> None:
    task_id, evidence_id, candidate_id = _create_task(
        approval_harness,
        state=TaskState.REPAIRING,
        with_rule_candidate=True,
    )
    assert candidate_id is not None
    service = _service(approval_harness)
    request_id, _result = _request(
        service,
        task_id=task_id,
        evidence_id=evidence_id,
        expected_state=TaskState.REPAIRING,
        request_type=ApprovalRequestType.REVIEW_RULE,
        subject_id=candidate_id,
    )

    result = service.decide(
        request_id,
        decision_id=uuid4(),
        decision=ApprovalDecision.CANCEL,
        actor_id="local-user",
    )

    assert result.task_state is TaskState.CANCELLED
    with approval_harness.factory() as session:
        candidate = session.get(RuleCandidate, candidate_id)
    assert candidate is not None
    assert candidate.status is RuleCandidateStatus.EVALUATED


def test_expiry_is_audited_and_fails_instead_of_completing(
    approval_harness: ApprovalHarness,
) -> None:
    clock = [_NOW]
    task_id, evidence_id, _subject_id = _create_task(
        approval_harness,
        state=TaskState.VALIDATING,
    )
    service = _service(approval_harness, clock=clock)
    request_id, _result = _request(
        service,
        task_id=task_id,
        evidence_id=evidence_id,
        expected_state=TaskState.VALIDATING,
        request_type=ApprovalRequestType.RETRY_LIMIT,
        expires_at=_NOW + timedelta(minutes=5),
    )
    clock[0] = _NOW + timedelta(minutes=6)

    results = service.expire_due()

    assert len(results) == 1
    assert results[0].request_id == request_id
    assert results[0].decision is ApprovalDecision.EXPIRE
    assert results[0].status is ApprovalStatus.EXPIRED
    assert results[0].task_state is TaskState.FAILED
    with approval_harness.factory() as session:
        request = session.get(ApprovalRequest, request_id)
        event_count = session.scalar(
            select(func.count())
            .select_from(TaskEvent)
            .where(
                TaskEvent.task_id == task_id,
                TaskEvent.event_type == "APPROVAL_EXPIRED",
            )
        )
    assert request is not None
    assert request.decision == ApprovalDecision.EXPIRE.value
    assert event_count == 1


def test_expiry_reconciliation_skips_uninitialized_legacy_rows(
    approval_harness: ApprovalHarness,
) -> None:
    task_id, _evidence_id, _subject_id = _create_task(
        approval_harness,
        state=TaskState.INTAKE,
    )
    request_id = uuid4()
    with approval_harness.factory.begin() as session:
        task = session.get(Task, task_id)
        assert task is not None
        session.add(
            ApprovalRequest(
                id=request_id,
                task_id=task.id,
                request_type=ApprovalRequestType.BRIEF.value,
                subject_type="BRIEF",
                reason="LEGACY_APPROVAL",
                options=[
                    ApprovalDecision.APPROVE.value,
                    ApprovalDecision.CANCEL.value,
                ],
                supporting_evidence_ids=[],
                requesting_state=TaskState.INTAKE,
                expires_at=_NOW - timedelta(minutes=1),
                status=ApprovalStatus.PENDING,
                owner_id=task.owner_id,
                actor_id="control-plane",
                root_correlation_id=task.root_correlation_id,
            )
        )

    assert _service(approval_harness).expire_due() == ()
    with approval_harness.factory() as session:
        request = session.get(ApprovalRequest, request_id)
    assert request is not None
    assert request.status is ApprovalStatus.PENDING
    assert request.decision_id is None


def test_expiry_reconciliation_skips_stale_row_and_continues(
    approval_harness: ApprovalHarness,
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = [_NOW]
    stale_task_id, stale_evidence_id, _subject_id = _create_task(
        approval_harness,
        state=TaskState.IMPLEMENTING,
    )
    valid_task_id, valid_evidence_id, _subject_id = _create_task(
        approval_harness,
        state=TaskState.VALIDATING,
    )
    service = _service(approval_harness, clock=clock)
    stale_request_id, _result = _request(
        service,
        task_id=stale_task_id,
        evidence_id=stale_evidence_id,
        expected_state=TaskState.IMPLEMENTING,
        request_type=ApprovalRequestType.UNSAFE_ACTION,
        request_id=UUID(int=1),
        expires_at=_NOW + timedelta(minutes=1),
    )
    valid_request_id, _result = _request(
        service,
        task_id=valid_task_id,
        evidence_id=valid_evidence_id,
        expected_state=TaskState.VALIDATING,
        request_type=ApprovalRequestType.RETRY_LIMIT,
        request_id=UUID(int=2),
        expires_at=_NOW + timedelta(minutes=2),
    )
    with approval_harness.factory.begin() as session:
        stale_task = session.get(Task, stale_task_id)
        assert stale_task is not None
        stale_task.state = TaskState.FAILED
        stale_task.escalation_resume_state = None
        stale_task.terminal_outcome = TaskState.FAILED.value
    clock[0] = _NOW + timedelta(minutes=3)

    with caplog.at_level("WARNING"):
        results = service.expire_due(limit=1)

    assert [result.request_id for result in results] == [
        valid_request_id
    ]
    assert str(stale_request_id) in caplog.text
    with approval_harness.factory() as session:
        stale_request = session.get(ApprovalRequest, stale_request_id)
        valid_request = session.get(ApprovalRequest, valid_request_id)
    assert stale_request is not None and valid_request is not None
    assert stale_request.status is ApprovalStatus.PENDING
    assert valid_request.status is ApprovalStatus.EXPIRED
    application = create_app(
        Settings(
            database_url=SecretStr(str(approval_harness.engine.url)),
            artifact_root=approval_harness.store.root,
        ),
        session_factory=approval_harness.factory,
        authentication_service=AuthenticationService(
            approval_harness.factory
        ),
        approval_service=service,
    )
    with TestClient(application, base_url="https://localhost"):
        pass


def test_decision_rejects_request_and_decision_evidence_over_combined_cap(
    approval_harness: ApprovalHarness,
) -> None:
    task_id, evidence_id, _subject_id = _create_task(
        approval_harness,
        state=TaskState.IMPLEMENTING,
    )
    service = _service(approval_harness)
    request_id, _result = _request(
        service,
        task_id=task_id,
        evidence_id=evidence_id,
        expected_state=TaskState.IMPLEMENTING,
        request_type=ApprovalRequestType.UNSAFE_ACTION,
    )

    with pytest.raises(
        InvalidApprovalError,
        match="combined approval evidence",
    ):
        service.decide(
            request_id,
            decision_id=uuid4(),
            decision=ApprovalDecision.DENY,
            actor_id="local-user",
            evidence_ids=tuple(uuid4() for _ in range(100)),
        )

    with approval_harness.factory() as session:
        request = session.get(ApprovalRequest, request_id)
    assert request is not None
    assert request.status is ApprovalStatus.PENDING
    assert request.decision_id is None


def test_startup_drains_every_expired_approval_batch(
    approval_harness: ApprovalHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(approval_harness)
    batch = tuple(object() for _ in range(100))
    results = iter((batch, batch, (object(),)))
    limits: list[int] = []

    def expire_due(*, limit: int = 100) -> tuple[object, ...]:
        limits.append(limit)
        return next(results)

    monkeypatch.setattr(service, "expire_due", expire_due)
    application = create_app(
        Settings(
            database_url=SecretStr(str(approval_harness.engine.url)),
            artifact_root=approval_harness.store.root,
        ),
        session_factory=approval_harness.factory,
        authentication_service=AuthenticationService(
            approval_harness.factory
        ),
        approval_service=service,
    )

    with TestClient(application, base_url="https://localhost"):
        pass

    assert limits == [100, 100, 100]


def test_request_and_decision_ids_reject_semantic_reuse(
    approval_harness: ApprovalHarness,
) -> None:
    task_id, evidence_id, _subject_id = _create_task(
        approval_harness,
        state=TaskState.IMPLEMENTING,
    )
    service = _service(approval_harness)
    request_id, _result = _request(
        service,
        task_id=task_id,
        evidence_id=evidence_id,
        expected_state=TaskState.IMPLEMENTING,
        request_type=ApprovalRequestType.UNSAFE_ACTION,
    )
    decision_id = uuid4()
    service.decide(
        request_id,
        decision_id=decision_id,
        decision=ApprovalDecision.DENY,
        actor_id="local-user",
    )

    with pytest.raises(ApprovalConflictError):
        service.decide(
            request_id,
            decision_id=decision_id,
            decision=ApprovalDecision.CANCEL,
            actor_id="local-user",
        )


def test_concurrent_human_decisions_have_one_durable_winner(
    approval_harness: ApprovalHarness,
) -> None:
    task_id, evidence_id, _subject_id = _create_task(
        approval_harness,
        state=TaskState.IMPLEMENTING,
    )
    service = _service(approval_harness)
    request_id, _result = _request(
        service,
        task_id=task_id,
        evidence_id=evidence_id,
        expected_state=TaskState.IMPLEMENTING,
        request_type=ApprovalRequestType.UNSAFE_ACTION,
    )

    def decide(value: ApprovalDecision) -> object:
        try:
            return service.decide(
                request_id,
                decision_id=uuid4(),
                decision=value,
                actor_id="local-user",
            )
        except ApprovalConflictError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(
            executor.map(
                decide,
                (ApprovalDecision.DENY, ApprovalDecision.CANCEL),
            )
        )

    assert sum(isinstance(value, ApprovalConflictError) for value in outcomes) == 1
    with approval_harness.factory() as session:
        task = session.get(Task, task_id)
        request = session.get(ApprovalRequest, request_id)
        event_count = session.scalar(
            select(func.count())
            .select_from(TaskEvent)
            .where(TaskEvent.task_id == task_id)
        )
    assert task is not None and request is not None
    assert task.state in {TaskState.FAILED, TaskState.CANCELLED}
    assert request.status in {
        ApprovalStatus.REJECTED,
        ApprovalStatus.CANCELLED,
    }
    assert request.decision_id is not None
    assert event_count == 4
