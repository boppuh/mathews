from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest
from mathews_control_plane.app import create_app
from mathews_control_plane.approvals import (
    ApprovalConflictError,
    ApprovalPreconditionError,
    ApprovalPreconditionEvaluator,
    ApprovalRecentPasswordRequiredError,
    ApprovalRequestResult,
    ApprovalRetryAttempt,
    ApprovalService,
    BlockedOperation,
    InvalidApprovalError,
)
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.authentication import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    AuthenticationService,
    generate_bootstrap_token,
)
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
    PolicyVersionPromptTemplate,
    PolicyVersionReviewRule,
    ReviewRule,
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
_ORIGIN = "http://localhost:3000"
_PASSWORD = "correct horse battery staple"  # noqa: S105


@dataclass(slots=True)
class ApprovalHarness:
    engine: Engine
    factory: SessionFactory
    store: ArtifactStore


@pytest.fixture
def approval_harness(tmp_path: Path) -> Iterator[ApprovalHarness]:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'approvals.sqlite3'}")
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
        if (
            session.scalar(
                select(PolicyVersion.id).where(
                    PolicyVersion.lineage_key == "mvp",
                    PolicyVersion.version == 1,
                )
            )
            is None
        ):
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
            select(EvidenceRecord.id).where(EvidenceRecord.task_id == task.id)
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
                disposition=(BriefDecisionDisposition.HUMAN_APPROVAL_REQUIRED),
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
                evaluation_result={
                    "passed": True,
                    "review_rule": {
                        "lineage_key": "format-repair",
                        "scope": {"repository": "boppuh/mathews"},
                        "matcher": {"check": "formatter"},
                        "permitted_action": "repair.format",
                        "risk_class": "low",
                        "evidence_requirements": ["formatter-output"],
                    },
                },
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
            "BRIEF" if is_brief else "RULE_CANDIDATE" if is_rule else "BLOCKED_OPERATION"
        ),
        subject_id=subject_id,
        blocked_operation=(None if is_brief else _blocked_operation()),
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
                select(TaskEvent).where(TaskEvent.task_id == task_id).order_by(TaskEvent.sequence)
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


def test_rule_candidate_approval_versions_rule_and_policy_without_prompts(
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
        rules = session.scalars(select(ReviewRule).order_by(ReviewRule.version)).all()
        policies = session.scalars(select(PolicyVersion).order_by(PolicyVersion.version)).all()
        memberships = session.scalars(select(PolicyVersionReviewRule)).all()
        prompt_memberships = session.scalars(select(PolicyVersionPromptTemplate)).all()
    assert candidate is not None
    assert candidate.status is RuleCandidateStatus.APPROVED
    assert len(rules) == 1
    assert rules[0].lineage_key == "format-repair"
    assert rules[0].version == 1
    assert rules[0].candidate_id == candidate_id
    assert rules[0].approval_request_id == request_id
    assert rules[0].permitted_action == "repair.format"
    assert rules[0].matcher == {"check": "formatter"}
    assert len(policies) == 2
    assert policies[1].version == 2
    assert policies[1].predecessor_id == policies[0].id
    assert policies[1].rollback_policy_version_id == policies[0].id
    assert [(item.policy_version_id, item.review_rule_id) for item in memberships] == [
        (policies[1].id, rules[0].id)
    ]
    assert prompt_memberships == []


def test_authenticated_inboxes_expose_bounded_decisions_and_record_audit(
    approval_harness: ApprovalHarness,
) -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    task_id, evidence_id, candidate_id = _create_task(
        approval_harness,
        state=TaskState.REPAIRING,
        with_rule_candidate=True,
    )
    assert candidate_id is not None
    service_clock = [now]
    service = _service(approval_harness, clock=service_clock)
    request_id, _result = _request(
        service,
        task_id=task_id,
        evidence_id=evidence_id,
        expected_state=TaskState.REPAIRING,
        request_type=ApprovalRequestType.REVIEW_RULE,
        subject_id=candidate_id,
        expires_at=now + timedelta(hours=1),
    )
    authentication = AuthenticationService(approval_harness.factory)
    bootstrap_token = generate_bootstrap_token(approval_harness.factory)
    application = create_app(
        Settings(
            database_url=SecretStr(str(approval_harness.engine.url)),
            artifact_root=approval_harness.store.root,
        ),
        session_factory=approval_harness.factory,
        authentication_service=authentication,
        approval_service=service,
    )
    client = TestClient(application, base_url="https://localhost")
    try:
        assert client.get("/api/approvals/inbox").status_code == 401
        assert client.get("/api/auth/status").status_code == 200
        csrf_token = client.cookies.get(CSRF_COOKIE_NAME)
        assert csrf_token is not None
        bootstrap = client.post(
            "/api/auth/bootstrap",
            json={
                "bootstrap_token": bootstrap_token,
                "password": _PASSWORD,
            },
            headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
        )
        assert bootstrap.status_code == 201
        bound_csrf = client.cookies.get(CSRF_COOKIE_NAME)
        assert bound_csrf is not None

        response = client.get("/api/approvals/inbox")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.json() == {
            "approvals": [
                {
                    "id": str(request_id),
                    "task": {
                        "id": str(task_id),
                        "summary": "Implement approvals",
                        "repository": "boppuh/mathews",
                        "cockpit_path": f"/tasks/{task_id}",
                    },
                    "request_type": "REVIEW_RULE",
                    "type_label": "Review rule",
                    "reason_code": "REVIEW_RULE_REQUIRED",
                    "options": ["APPROVE", "REJECT", "CANCEL"],
                    "requesting_state": "REPAIRING",
                    "resume_state": "REPAIRING",
                    "created_at": now.isoformat().replace("+00:00", "Z"),
                    "expires_at": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
                    "operation_name": "host.mutate",
                    "operation_fingerprint": "a" * 64,
                    "supporting_evidence_ids": [str(evidence_id)],
                }
            ],
            "rule_candidates": [
                {
                    "candidate_id": str(candidate_id),
                    "approval_request_id": str(request_id),
                    "task": {
                        "id": str(task_id),
                        "summary": "Implement approvals",
                        "repository": "boppuh/mathews",
                        "cockpit_path": f"/tasks/{task_id}",
                    },
                    "proposed_rule": "Retry exact formatting failures once.",
                    "recurrence_assessment": "repeated",
                    "severity_assessment": "low",
                    "false_positive_risks": [],
                    "cited_evidence_ids": [str(evidence_id)],
                    "lineage_key": "format-repair",
                    "permitted_action": "repair.format",
                    "risk_class": "low",
                    "scope": {"repository": "boppuh/mathews"},
                    "matcher": {"check": "formatter"},
                    "evidence_requirements": ["formatter-output"],
                }
            ],
        }
        missing_csrf = client.post(
            f"/api/approvals/{request_id}/decisions",
            json={"decision": "APPROVE"},
            headers={"Origin": _ORIGIN},
        )
        assert missing_csrf.status_code == 403
        oversized = client.post(
            f"/api/approvals/{request_id}/decisions",
            content=b"x" * 4_097,
            headers={
                "Content-Type": "application/json",
                "Origin": _ORIGIN,
                CSRF_HEADER_NAME: bound_csrf,
            },
        )
        assert oversized.status_code == 413
        decided = client.post(
            f"/api/approvals/{request_id}/decisions",
            json={"decision": "APPROVE"},
            headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: bound_csrf},
        )
        assert decided.status_code == 200, decided.text
        assert decided.json()["task_state"] == "REPAIRING"
        assert decided.json()["status"] == "APPROVED"
        assert client.get("/api/approvals/inbox").json() == {
            "approvals": [],
            "rule_candidates": [],
        }
        with approval_harness.factory() as session:
            audit = session.get(TaskEvent, UUID(decided.json()["audit_event_id"]))
        assert audit is not None
        assert audit.event_type == "APPROVAL_DECIDED"
        assert audit.payload["approval_request_id"] == str(request_id)

        expired_task_id, expired_evidence_id, _subject_id = _create_task(
            approval_harness,
            state=TaskState.REPAIRING,
        )
        expired_request_id, _result = _request(
            service,
            task_id=expired_task_id,
            evidence_id=expired_evidence_id,
            expected_state=TaskState.REPAIRING,
            request_type=ApprovalRequestType.REVIEW_CONFLICT,
            expires_at=now + timedelta(minutes=1),
        )
        service_clock[0] = now + timedelta(minutes=2)
        assert client.get("/api/approvals/inbox").json() == {
            "approvals": [],
            "rule_candidates": [],
        }
        with approval_harness.factory() as session:
            expired_task = session.get(Task, expired_task_id)
            expired_request = session.get(ApprovalRequest, expired_request_id)
        assert expired_task is not None and expired_request is not None
        assert expired_task.state is TaskState.FAILED
        assert expired_request.status is ApprovalStatus.EXPIRED

        stale_task_id, stale_evidence_id, _subject_id = _create_task(
            approval_harness,
            state=TaskState.REPAIRING,
        )
        stale_request_id, _result = _request(
            service,
            task_id=stale_task_id,
            evidence_id=stale_evidence_id,
            expected_state=TaskState.REPAIRING,
            request_type=ApprovalRequestType.REVIEW_CONFLICT,
            expires_at=service_clock[0] + timedelta(minutes=1),
        )
        service_clock[0] += timedelta(minutes=2)
        stale = client.post(
            f"/api/approvals/{stale_request_id}/decisions",
            json={"decision": "APPROVE"},
            headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: bound_csrf},
        )
        assert stale.status_code == 409
        with approval_harness.factory() as session:
            stale_task = session.get(Task, stale_task_id)
        assert stale_task is not None
        assert stale_task.state is TaskState.FAILED
    finally:
        client.close()


def test_policy_and_terminal_decisions_require_recent_password(
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

    with pytest.raises(ApprovalRecentPasswordRequiredError):
        service.decide(
            request_id,
            decision_id=uuid4(),
            decision=ApprovalDecision.APPROVE,
            actor_id="local-user",
            recent_password_verified=False,
        )

    with approval_harness.factory() as session:
        task = session.get(Task, task_id)
        request = session.get(ApprovalRequest, request_id)
        candidate = session.get(RuleCandidate, candidate_id)
    assert task is not None and request is not None and candidate is not None
    assert task.state is TaskState.ESCALATED
    assert request.status is ApprovalStatus.PENDING
    assert candidate.status is RuleCandidateStatus.EVALUATED


def test_rule_promotion_rejects_changed_or_unbound_candidate_evidence(
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
    with approval_harness.factory.begin() as session:
        candidate = session.get(RuleCandidate, candidate_id)
        assert candidate is not None
        candidate.cited_evidence_ids = []

    with pytest.raises(ApprovalPreconditionError):
        service.decide(
            request_id,
            decision_id=uuid4(),
            decision=ApprovalDecision.APPROVE,
            actor_id="local-user",
        )

    with approval_harness.factory() as session:
        request = session.get(ApprovalRequest, request_id)
        rule_count = session.scalar(select(func.count(ReviewRule.id)))
    assert request is not None
    assert request.status is ApprovalStatus.PENDING
    assert rule_count == 0


def test_rule_promotion_uses_current_policy_and_preserves_lineage_position(
    approval_harness: ApprovalHarness,
) -> None:
    service = _service(approval_harness)

    def approve_candidate(lineage_key: str) -> tuple[UUID, UUID]:
        task_id, evidence_id, candidate_id = _create_task(
            approval_harness,
            state=TaskState.REPAIRING,
            with_rule_candidate=True,
        )
        assert candidate_id is not None
        with approval_harness.factory.begin() as session:
            candidate = session.get(RuleCandidate, candidate_id)
            assert candidate is not None and candidate.evaluation_result is not None
            candidate.evaluation_result = {
                **candidate.evaluation_result,
                "review_rule": {
                    **cast(
                        dict[str, object],
                        candidate.evaluation_result["review_rule"],
                    ),
                    "lineage_key": lineage_key,
                },
            }
        request_id, _result = _request(
            service,
            task_id=task_id,
            evidence_id=evidence_id,
            expected_state=TaskState.REPAIRING,
            request_type=ApprovalRequestType.REVIEW_RULE,
            subject_id=candidate_id,
        )
        service.decide(
            request_id,
            decision_id=uuid4(),
            decision=ApprovalDecision.APPROVE,
            actor_id="local-user",
        )
        return task_id, candidate_id

    approve_candidate("format-repair")
    approve_candidate("lint-repair")
    task_id, _candidate_id = approve_candidate("format-repair")

    with approval_harness.factory() as session:
        latest_policy = session.scalar(
            select(PolicyVersion)
            .where(PolicyVersion.owner_id == "local-user")
            .order_by(PolicyVersion.version.desc())
            .limit(1)
        )
        assert latest_policy is not None
        lineages = session.scalars(
            select(ReviewRule.lineage_key)
            .join(
                PolicyVersionReviewRule,
                PolicyVersionReviewRule.review_rule_id == ReviewRule.id,
            )
            .where(PolicyVersionReviewRule.policy_version_id == latest_policy.id)
            .order_by(PolicyVersionReviewRule.position)
        ).all()
        task = session.get(Task, task_id)
    assert task is not None
    assert lineages == ["format-repair", "lint-repair"]


def test_rule_promotion_does_not_copy_a_future_policy(
    approval_harness: ApprovalHarness,
) -> None:
    task_id, evidence_id, candidate_id = _create_task(
        approval_harness,
        state=TaskState.REPAIRING,
        with_rule_candidate=True,
    )
    assert candidate_id is not None
    with approval_harness.factory.begin() as session:
        task = session.get(Task, task_id)
        assert task is not None
        session.add(
            PolicyVersion(
                lineage_key="mvp",
                version=2,
                workflow_thresholds={"future": True},
                approved_by="local-user",
                approved_at=_NOW + timedelta(days=1),
                owner_id="local-user",
                actor_id="local-user",
                root_correlation_id=task.root_correlation_id,
            )
        )
    service = _service(approval_harness)
    request_id, _result = _request(
        service,
        task_id=task_id,
        evidence_id=evidence_id,
        expected_state=TaskState.REPAIRING,
        request_type=ApprovalRequestType.REVIEW_RULE,
        subject_id=candidate_id,
    )
    service.decide(
        request_id,
        decision_id=uuid4(),
        decision=ApprovalDecision.APPROVE,
        actor_id="local-user",
    )

    with approval_harness.factory() as session:
        policies = session.scalars(select(PolicyVersion).order_by(PolicyVersion.version)).all()
    assert [policy.version for policy in policies] == [1, 2, 3]
    assert policies[2].predecessor_id == policies[0].id
    assert policies[2].rollback_policy_version_id == policies[0].id
    assert policies[2].workflow_thresholds == {}


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
        rule_count = session.scalar(select(func.count(ReviewRule.id)))
        policy_count = session.scalar(select(func.count(PolicyVersion.id)))
    assert candidate is not None and task is not None
    assert candidate.status is RuleCandidateStatus.REJECTED
    assert task.escalation_resume_state is None
    assert task.terminal_outcome is None
    assert rule_count == 0
    assert policy_count == 1


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

    assert [result.request_id for result in results] == [valid_request_id]
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
        authentication_service=AuthenticationService(approval_harness.factory),
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
        authentication_service=AuthenticationService(approval_harness.factory),
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
            select(func.count()).select_from(TaskEvent).where(TaskEvent.task_id == task_id)
        )
    assert task is not None and request is not None
    assert task.state in {TaskState.FAILED, TaskState.CANCELLED}
    assert request.status in {
        ApprovalStatus.REJECTED,
        ApprovalStatus.CANCELLED,
    }
    assert request.decision_id is not None
    assert event_count == 4
