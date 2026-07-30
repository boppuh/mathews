from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from uuid import UUID, uuid4

import pytest
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.database import (
    Base,
    SessionFactory,
    create_database_engine,
    create_session_factory,
    create_task_record,
)
from mathews_control_plane.domain_models import (
    Brief,
    BriefApprovalDecision,
    BriefDecisionDisposition,
    EvidenceDeletionRequest,
    EvidenceRecord,
    PolicyVersion,
    RepositoryConfiguration,
    Task,
    TaskEvent,
    TaskEventEvidenceReference,
    TaskState,
    TaskTerminalOutcome,
    ValidationContract,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
)
from mathews_control_plane.task_state_machine import (
    MAX_TRANSITION_EVIDENCE_REFERENCES,
    ClosedTaskTransitionGateEvaluator,
    DraftPrGateFacts,
    InvalidTaskTransitionError,
    ReadinessGateFacts,
    TaskTransitionConflictError,
    TaskTransitionGateEvaluator,
    TaskTransitionGuards,
    TaskTransitionKind,
    TaskTransitionNotFoundError,
    TaskTransitionResult,
    TaskTransitionService,
    TaskTransitionSnapshot,
    evaluate_task_transition,
)
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
_SHA = "a" * 40
_BRIEF_REVISION_REQUEST_ID = UUID("11111111-1111-1111-1111-111111111111")
_RESUME_DECISION_ID = UUID("22222222-2222-2222-2222-222222222222")


@dataclass(slots=True)
class StateMachineHarness:
    engine: Engine
    factory: SessionFactory
    store: ArtifactStore


@pytest.fixture
def state_machine_harness(tmp_path: Path) -> Iterator[StateMachineHarness]:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'state-machine.sqlite3'}")
    Base.metadata.create_all(engine)
    yield StateMachineHarness(
        engine=engine,
        factory=create_session_factory(engine),
        store=ArtifactStore(tmp_path / "artifacts"),
    )
    engine.dispose()


def _draft_pr_facts(**overrides: object) -> DraftPrGateFacts:
    values: dict[str, object] = {
        "current_head_sha": _SHA,
        "validation_commit_sha": _SHA,
        "local_branch_sha": _SHA,
        "remote_branch_sha": _SHA,
        "pull_request_head_sha": _SHA,
        "validation_passed": True,
        "required_artifacts_present": True,
        "branch_clean": True,
        "pull_request_is_draft": True,
        "no_unresolved_approval": True,
        "cancellation_clear": True,
    }
    values.update(overrides)
    return DraftPrGateFacts(**values)  # type: ignore[arg-type]


def _readiness_facts(**overrides: object) -> ReadinessGateFacts:
    values: dict[str, object] = {
        "draft_pr": _draft_pr_facts(),
        "required_ci_green": True,
        "no_blocking_review": True,
        "repairs_authorized": True,
    }
    values.update(overrides)
    return ReadinessGateFacts(**values)  # type: ignore[arg-type]


def _positive_guards(kind: TaskTransitionKind) -> TaskTransitionGuards:
    if kind is TaskTransitionKind.AUTO_ACCEPT_BRIEF:
        return TaskTransitionGuards(brief_policy_bypass_authorized=True)
    if kind is TaskTransitionKind.REQUEST_BRIEF_APPROVAL:
        return TaskTransitionGuards(brief_approval_required=True)
    if kind is TaskTransitionKind.REVISE_BRIEF:
        return TaskTransitionGuards(
            brief_revision_request_id=_BRIEF_REVISION_REQUEST_ID
        )
    if kind is TaskTransitionKind.APPROVE_EXACT_BRIEF:
        return TaskTransitionGuards(exact_brief_human_approval=True)
    if kind is TaskTransitionKind.BEGIN_REPAIR:
        return TaskTransitionGuards(repair_authorized=True)
    if kind is TaskTransitionKind.OPEN_VERIFIED_DRAFT_PR:
        return TaskTransitionGuards(draft_pr=_draft_pr_facts())
    if kind is TaskTransitionKind.MARK_MERGE_READY:
        return TaskTransitionGuards(readiness=_readiness_facts())
    if kind is TaskTransitionKind.INVALIDATE_READINESS:
        return TaskTransitionGuards(readiness_invalidation_current=True)
    if kind is TaskTransitionKind.ACKNOWLEDGE_HANDOFF:
        return TaskTransitionGuards(
            readiness=_readiness_facts(),
            human_handoff_acknowledged=True,
        )
    if kind is TaskTransitionKind.RESUME:
        return TaskTransitionGuards(
            resume_decision_id=_RESUME_DECISION_ID,
            resume_decision_current=True,
            resume_preconditions_rechecked=True,
        )
    if kind is TaskTransitionKind.SCOPE_STEER:
        return TaskTransitionGuards(
            work_fence_verified=True,
            scope_decisions_invalidated=True,
        )
    return TaskTransitionGuards()


def _expected_target(
    state: TaskState,
    kind: TaskTransitionKind,
) -> TaskState | None:
    if state in {TaskState.HANDED_OFF, TaskState.FAILED, TaskState.CANCELLED}:
        return None
    if kind is TaskTransitionKind.CANCEL:
        return TaskState.CANCELLED
    if kind is TaskTransitionKind.FAIL:
        return TaskState.FAILED
    if kind is TaskTransitionKind.ESCALATE:
        return None if state is TaskState.ESCALATED else TaskState.ESCALATED
    if kind is TaskTransitionKind.RESUME:
        return TaskState.BRIEFING if state is TaskState.ESCALATED else None
    if kind is TaskTransitionKind.SCOPE_STEER:
        return (
            TaskState.BRIEFING
            if state is not TaskState.ESCALATED
            else None
        )
    return {
        (TaskState.INTAKE, TaskTransitionKind.START_BRIEFING): TaskState.BRIEFING,
        (
            TaskState.BRIEFING,
            TaskTransitionKind.AUTO_ACCEPT_BRIEF,
        ): TaskState.IMPLEMENTING,
        (
            TaskState.BRIEFING,
            TaskTransitionKind.REQUEST_BRIEF_APPROVAL,
        ): TaskState.BRIEF_PENDING_APPROVAL,
        (
            TaskState.BRIEF_PENDING_APPROVAL,
            TaskTransitionKind.REVISE_BRIEF,
        ): TaskState.BRIEFING,
        (
            TaskState.BRIEF_PENDING_APPROVAL,
            TaskTransitionKind.APPROVE_EXACT_BRIEF,
        ): TaskState.IMPLEMENTING,
        (
            TaskState.IMPLEMENTING,
            TaskTransitionKind.BEGIN_VALIDATION,
        ): TaskState.VALIDATING,
        (
            TaskState.VALIDATING,
            TaskTransitionKind.BEGIN_REPAIR,
        ): TaskState.REPAIRING,
        (
            TaskState.PR_ACTIVE,
            TaskTransitionKind.BEGIN_REPAIR,
        ): TaskState.REPAIRING,
        (
            TaskState.REPAIRING,
            TaskTransitionKind.REVALIDATE,
        ): TaskState.VALIDATING,
        (
            TaskState.VALIDATING,
            TaskTransitionKind.OPEN_VERIFIED_DRAFT_PR,
        ): TaskState.PR_ACTIVE,
        (
            TaskState.PR_ACTIVE,
            TaskTransitionKind.MARK_MERGE_READY,
        ): TaskState.READY_FOR_HUMAN_MERGE,
        (
            TaskState.READY_FOR_HUMAN_MERGE,
            TaskTransitionKind.INVALIDATE_READINESS,
        ): TaskState.PR_ACTIVE,
        (
            TaskState.READY_FOR_HUMAN_MERGE,
            TaskTransitionKind.ACKNOWLEDGE_HANDOFF,
        ): TaskState.HANDED_OFF,
    }.get((state, kind))


def test_pure_engine_exhaustively_enforces_the_typed_transition_matrix() -> None:
    for state in TaskState:
        for kind in TaskTransitionKind:
            snapshot = TaskTransitionSnapshot(
                state=state,
                escalation_resume_state=(
                    TaskState.BRIEFING if state is TaskState.ESCALATED else None
                ),
                verified_pr_head_sha=(
                    _SHA
                    if state
                    in {
                        TaskState.PR_ACTIVE,
                        TaskState.READY_FOR_HUMAN_MERGE,
                    }
                    else None
                ),
            )
            expected = _expected_target(state, kind)
            if expected is None:
                with pytest.raises(InvalidTaskTransitionError):
                    evaluate_task_transition(
                        snapshot,
                        kind,
                        _positive_guards(kind),
                    )
            else:
                plan = evaluate_task_transition(
                    snapshot,
                    kind,
                    _positive_guards(kind),
                )
                assert plan.from_state is state
                assert plan.to_state is expected


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("current_head_sha", "b" * 40),
        ("validation_commit_sha", "b" * 40),
        ("local_branch_sha", "b" * 40),
        ("remote_branch_sha", "b" * 40),
        ("pull_request_head_sha", "b" * 40),
        ("validation_passed", False),
        ("required_artifacts_present", False),
        ("branch_clean", False),
        ("pull_request_is_draft", False),
        ("no_unresolved_approval", False),
        ("cancellation_clear", False),
    ),
)
def test_verified_draft_gate_rejects_every_mismatched_dimension(
    field: str,
    value: object,
) -> None:
    guards = replace(
        _positive_guards(TaskTransitionKind.OPEN_VERIFIED_DRAFT_PR),
        draft_pr=_draft_pr_facts(**{field: value}),
    )

    with pytest.raises(InvalidTaskTransitionError, match="verified draft"):
        evaluate_task_transition(
            TaskTransitionSnapshot(state=TaskState.VALIDATING),
            TaskTransitionKind.OPEN_VERIFIED_DRAFT_PR,
            guards,
        )


@pytest.mark.parametrize(
    "readiness",
    (
        _readiness_facts(required_ci_green=False),
        _readiness_facts(no_blocking_review=False),
        _readiness_facts(repairs_authorized=False),
    ),
)
def test_readiness_requires_every_current_head_gate(
    readiness: ReadinessGateFacts,
) -> None:
    guards = replace(
        _positive_guards(TaskTransitionKind.MARK_MERGE_READY),
        readiness=readiness,
    )

    with pytest.raises(InvalidTaskTransitionError, match="readiness gate"):
        evaluate_task_transition(
            TaskTransitionSnapshot(
                state=TaskState.PR_ACTIVE,
                verified_pr_head_sha=_SHA,
            ),
            TaskTransitionKind.MARK_MERGE_READY,
            guards,
        )


def test_readiness_rejects_a_stale_previously_verified_head() -> None:
    with pytest.raises(InvalidTaskTransitionError, match="readiness gate"):
        evaluate_task_transition(
            TaskTransitionSnapshot(
                state=TaskState.PR_ACTIVE,
                verified_pr_head_sha="b" * 40,
            ),
            TaskTransitionKind.MARK_MERGE_READY,
            _positive_guards(TaskTransitionKind.MARK_MERGE_READY),
        )


def test_escalation_and_terminal_projection_is_derived_not_caller_selected() -> None:
    escalated = evaluate_task_transition(
        TaskTransitionSnapshot(state=TaskState.VALIDATING),
        TaskTransitionKind.ESCALATE,
        TaskTransitionGuards(),
    )
    cancelled = evaluate_task_transition(
        TaskTransitionSnapshot(
            state=TaskState.ESCALATED,
            escalation_resume_state=TaskState.VALIDATING,
        ),
        TaskTransitionKind.CANCEL,
        TaskTransitionGuards(),
    )
    failed = evaluate_task_transition(
        TaskTransitionSnapshot(state=TaskState.REPAIRING),
        TaskTransitionKind.FAIL,
        TaskTransitionGuards(),
    )

    assert escalated.escalation_resume_state is TaskState.VALIDATING
    assert cancelled.terminal_outcome is TaskTerminalOutcome.CANCELLED
    assert failed.terminal_outcome is TaskTerminalOutcome.FAILED


def test_scope_steering_requires_both_fences_and_invalidates_prior_scope() -> None:
    snapshot = TaskTransitionSnapshot(state=TaskState.PR_ACTIVE)
    for guards in (
        TaskTransitionGuards(scope_decisions_invalidated=True),
        TaskTransitionGuards(work_fence_verified=True),
    ):
        with pytest.raises(InvalidTaskTransitionError, match="fencing"):
            evaluate_task_transition(
                snapshot,
                TaskTransitionKind.SCOPE_STEER,
                guards,
            )

    plan = evaluate_task_transition(
        snapshot,
        TaskTransitionKind.SCOPE_STEER,
        TaskTransitionGuards(
            work_fence_verified=True,
            scope_decisions_invalidated=True,
        ),
    )

    assert plan.to_state is TaskState.BRIEFING
    assert plan.invalidate_scope_bindings


def test_readiness_invalidation_requires_a_current_authoritative_signal() -> None:
    snapshot = TaskTransitionSnapshot(
        state=TaskState.READY_FOR_HUMAN_MERGE,
        verified_pr_head_sha=_SHA,
    )
    with pytest.raises(InvalidTaskTransitionError):
        evaluate_task_transition(
            snapshot,
            TaskTransitionKind.INVALIDATE_READINESS,
            TaskTransitionGuards(),
        )

    plan = evaluate_task_transition(
        snapshot,
        TaskTransitionKind.INVALIDATE_READINESS,
        TaskTransitionGuards(readiness_invalidation_current=True),
    )

    assert plan.to_state is TaskState.PR_ACTIVE


def test_brief_revision_requires_an_authoritative_human_request() -> None:
    snapshot = TaskTransitionSnapshot(state=TaskState.BRIEF_PENDING_APPROVAL)
    with pytest.raises(InvalidTaskTransitionError):
        evaluate_task_transition(
            snapshot,
            TaskTransitionKind.REVISE_BRIEF,
            TaskTransitionGuards(),
        )

    plan = evaluate_task_transition(
        snapshot,
        TaskTransitionKind.REVISE_BRIEF,
        TaskTransitionGuards(
            brief_revision_request_id=_BRIEF_REVISION_REQUEST_ID
        ),
    )

    assert plan.to_state is TaskState.BRIEFING


@dataclass(slots=True)
class StaticGateEvaluator(TaskTransitionGateEvaluator):
    guards: TaskTransitionGuards

    def evaluate(
        self,
        session: Session,
        task: Task,
        kind: TaskTransitionKind,
        *,
        policy: PolicyVersion,
        now: datetime,
    ) -> TaskTransitionGuards:
        del session, task, kind, policy, now
        return self.guards


@dataclass(slots=True)
class PolicyCapturingGateEvaluator(TaskTransitionGateEvaluator):
    policy_id: UUID | None = None

    def evaluate(
        self,
        session: Session,
        task: Task,
        kind: TaskTransitionKind,
        *,
        policy: PolicyVersion,
        now: datetime,
    ) -> TaskTransitionGuards:
        del session, task, kind, now
        self.policy_id = policy.id
        return TaskTransitionGuards()


class PositiveGateEvaluator(TaskTransitionGateEvaluator):
    def evaluate(
        self,
        session: Session,
        task: Task,
        kind: TaskTransitionKind,
        *,
        policy: PolicyVersion,
        now: datetime,
    ) -> TaskTransitionGuards:
        del session, task, policy, now
        return _positive_guards(kind)


@dataclass(slots=True)
class BlockingGateEvaluator(TaskTransitionGateEvaluator):
    entered: Event
    release: Event

    def evaluate(
        self,
        session: Session,
        task: Task,
        kind: TaskTransitionKind,
        *,
        policy: PolicyVersion,
        now: datetime,
    ) -> TaskTransitionGuards:
        del session, task, kind, policy, now
        self.entered.set()
        if not self.release.wait(timeout=5):
            raise TimeoutError("test did not release the transition gate")
        return TaskTransitionGuards()


def _create_task_policy_and_evidence(
    harness: StateMachineHarness,
    *,
    policy_versions: int = 1,
) -> tuple[UUID, UUID]:
    with harness.factory.begin() as session:
        task = create_task_record(
            session,
            harness.store,
            repository="boppuh/mathews",
            base_revision="1" * 40,
            requester="local-user",
            raw_request="Implement the next task",
            summary="Implement task",
            owner_id="local-user",
            actor_id="local-user",
        )
        existing_version = session.scalar(
            select(func.max(PolicyVersion.version)).where(
                PolicyVersion.lineage_key == "mvp"
            )
        )
        for version in range(int(existing_version or 0) + 1, policy_versions + 1):
            session.add(
                PolicyVersion(
                    lineage_key="mvp",
                    version=version,
                    predecessor_id=None,
                    workflow_thresholds={},
                    approved_by="local-user",
                    approved_at=_NOW,
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
        return task.id, evidence_id


def _service(
    harness: StateMachineHarness,
    evaluator: TaskTransitionGateEvaluator | None = None,
) -> TaskTransitionService:
    return TaskTransitionService(
        harness.factory,
        harness.store,
        gate_evaluator=evaluator,
        clock=lambda: _NOW,
    )


def test_transition_service_is_idempotent_and_writes_typed_provenance(
    state_machine_harness: StateMachineHarness,
) -> None:
    task_id, evidence_id = _create_task_policy_and_evidence(
        state_machine_harness,
        policy_versions=2,
    )
    evaluator = PolicyCapturingGateEvaluator()
    service = _service(state_machine_harness, evaluator)
    transition_id = uuid4()

    first = service.transition(
        task_id,
        transition_id=transition_id,
        expected_state=TaskState.INTAKE,
        kind=TaskTransitionKind.START_BRIEFING,
        reason_code="REQUEST_ACCEPTED",
        evidence_ids=(evidence_id,),
    )
    replay = service.transition(
        task_id,
        transition_id=transition_id,
        expected_state=TaskState.INTAKE,
        kind=TaskTransitionKind.START_BRIEFING,
        reason_code="REQUEST_ACCEPTED",
        evidence_ids=(evidence_id,),
    )

    assert replay == replace(first, replayed=True)
    with state_machine_harness.factory() as session:
        task = session.get(Task, task_id)
        event = session.get(TaskEvent, first.event_id)
        references = list(
            session.scalars(
                select(TaskEventEvidenceReference).where(
                    TaskEventEvidenceReference.task_event_id == first.event_id
                )
            )
        )
        event_count = session.scalar(
            select(func.count())
            .select_from(TaskEvent)
            .where(TaskEvent.task_id == task_id)
        )
        active_policy = session.scalar(
            select(PolicyVersion)
            .where(PolicyVersion.lineage_key == "mvp")
            .order_by(PolicyVersion.version.desc())
        )

    assert task is not None and task.state is TaskState.BRIEFING
    assert event is not None and active_policy is not None
    assert event.transition_id == transition_id
    assert event.transition_kind == TaskTransitionKind.START_BRIEFING.value
    assert event.transition_from_state is TaskState.INTAKE
    assert event.transition_to_state is TaskState.BRIEFING
    assert event.transition_reason_code == "REQUEST_ACCEPTED"
    assert event.policy_lineage_key == "mvp"
    assert event.policy_version_id == active_policy.id
    assert evaluator.policy_id == active_policy.id
    assert event.actor_id == "control-plane"
    assert [reference.evidence_id for reference in references] == [evidence_id]
    assert event_count == 1


def test_transition_evidence_reference_limits_and_order_are_enforced(
    state_machine_harness: StateMachineHarness,
) -> None:
    task_id, first_evidence_id = _create_task_policy_and_evidence(
        state_machine_harness
    )
    with state_machine_harness.factory.begin() as session:
        task = session.get(Task, task_id)
        assert task is not None
        second = capture_evidence(
            session,
            state_machine_harness.store,
            payload={"status": "second"},
            media_type="application/json",
            source_kind=EvidenceSourceKind.RESULT,
            evidence_type="test-result",
            origin="validator",
            access_classification=EvidenceAccessClass.TASK_OWNER,
            retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
            owner_id=task.owner_id,
            actor_id="validator",
            root_correlation_id=task.root_correlation_id,
            task_id=task.id,
            captured_at=_NOW,
        )
        second_evidence_id = second.record.id

    service = _service(state_machine_harness)
    for evidence_ids in (
        (),
        (first_evidence_id, first_evidence_id),
        tuple(uuid4() for _ in range(MAX_TRANSITION_EVIDENCE_REFERENCES + 1)),
    ):
        with pytest.raises(
            InvalidTaskTransitionError,
            match="evidence references are invalid",
        ):
            service.transition(
                task_id,
                transition_id=uuid4(),
                expected_state=TaskState.INTAKE,
                kind=TaskTransitionKind.START_BRIEFING,
                reason_code="INVALID_EVIDENCE_REFERENCES",
                evidence_ids=evidence_ids,
            )

    transition_id = uuid4()
    result = service.transition(
        task_id,
        transition_id=transition_id,
        expected_state=TaskState.INTAKE,
        kind=TaskTransitionKind.START_BRIEFING,
        reason_code="ORDERED_EVIDENCE_REFERENCES",
        evidence_ids=(second_evidence_id, first_evidence_id),
    )
    reordered_replay = service.transition(
        task_id,
        transition_id=transition_id,
        expected_state=TaskState.INTAKE,
        kind=TaskTransitionKind.START_BRIEFING,
        reason_code="ORDERED_EVIDENCE_REFERENCES",
        evidence_ids=(first_evidence_id, second_evidence_id),
    )
    with state_machine_harness.factory() as session:
        references = list(
            session.scalars(
                select(TaskEventEvidenceReference)
                .where(TaskEventEvidenceReference.task_event_id == result.event_id)
                .order_by(TaskEventEvidenceReference.position)
            )
        )
        event_count = session.scalar(
            select(func.count())
            .select_from(TaskEvent)
            .where(TaskEvent.task_id == task_id)
        )

    assert [reference.evidence_id for reference in references] == [
        second_evidence_id,
        first_evidence_id,
    ]
    assert [reference.position for reference in references] == [1, 2]
    assert event_count == 1
    assert reordered_replay == replace(result, replayed=True)


def test_same_transition_id_with_different_command_conflicts(
    state_machine_harness: StateMachineHarness,
) -> None:
    task_id, evidence_id = _create_task_policy_and_evidence(state_machine_harness)
    service = _service(state_machine_harness)
    transition_id = uuid4()
    service.transition(
        task_id,
        transition_id=transition_id,
        expected_state=TaskState.INTAKE,
        kind=TaskTransitionKind.START_BRIEFING,
        reason_code="REQUEST_ACCEPTED",
        evidence_ids=(evidence_id,),
    )

    with pytest.raises(TaskTransitionConflictError, match="different command"):
        service.transition(
            task_id,
            transition_id=transition_id,
            expected_state=TaskState.INTAKE,
            kind=TaskTransitionKind.START_BRIEFING,
            reason_code="DIFFERENT_REASON",
            evidence_ids=(evidence_id,),
        )


def test_sqlite_serializes_same_task_transitions_as_domain_conflicts(
    state_machine_harness: StateMachineHarness,
) -> None:
    task_id, evidence_id = _create_task_policy_and_evidence(state_machine_harness)
    entered = Event()
    release = Event()
    service = _service(
        state_machine_harness,
        BlockingGateEvaluator(entered=entered, release=release),
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(
            service.transition,
            task_id,
            transition_id=uuid4(),
            expected_state=TaskState.INTAKE,
            kind=TaskTransitionKind.START_BRIEFING,
            reason_code="START_BRIEFING",
            evidence_ids=(evidence_id,),
        )
        assert entered.wait(timeout=5)
        second = executor.submit(
            service.transition,
            task_id,
            transition_id=uuid4(),
            expected_state=TaskState.INTAKE,
            kind=TaskTransitionKind.CANCEL,
            reason_code="CANCEL",
            evidence_ids=(evidence_id,),
        )
        try:
            with pytest.raises(FutureTimeoutError):
                second.result(timeout=0.2)
        finally:
            release.set()
        assert first.result(timeout=5).to_state is TaskState.BRIEFING
        with pytest.raises(TaskTransitionConflictError):
            second.result(timeout=5)


def test_global_transition_id_collision_is_always_a_domain_conflict(
    state_machine_harness: StateMachineHarness,
) -> None:
    first_task_id, first_evidence_id = _create_task_policy_and_evidence(
        state_machine_harness
    )
    second_task_id, second_evidence_id = _create_task_policy_and_evidence(
        state_machine_harness
    )
    transition_id = uuid4()
    service = _service(state_machine_harness)

    def transition(
        task_and_evidence: tuple[UUID, UUID],
    ) -> TaskTransitionResult | TaskTransitionConflictError:
        task_id, evidence_id = task_and_evidence
        try:
            return service.transition(
                task_id,
                transition_id=transition_id,
                expected_state=TaskState.INTAKE,
                kind=TaskTransitionKind.START_BRIEFING,
                reason_code="START_BRIEFING",
                evidence_ids=(evidence_id,),
            )
        except TaskTransitionConflictError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                transition,
                (
                    (first_task_id, first_evidence_id),
                    (second_task_id, second_evidence_id),
                ),
            )
        )

    assert sum(isinstance(result, TaskTransitionResult) for result in results) == 1
    assert (
        sum(
            isinstance(result, TaskTransitionConflictError)
            for result in results
        )
        == 1
    )


def test_rejected_transition_rolls_back_without_an_event(
    state_machine_harness: StateMachineHarness,
) -> None:
    task_id, evidence_id = _create_task_policy_and_evidence(state_machine_harness)

    with pytest.raises(InvalidTaskTransitionError):
        _service(state_machine_harness).transition(
            task_id,
            transition_id=uuid4(),
            expected_state=TaskState.INTAKE,
            kind=TaskTransitionKind.BEGIN_VALIDATION,
            reason_code="INVALID_EDGE",
            evidence_ids=(evidence_id,),
        )

    with state_machine_harness.factory() as session:
        task = session.get(Task, task_id)
        event_count = session.scalar(
            select(func.count())
            .select_from(TaskEvent)
            .where(TaskEvent.task_id == task_id)
        )
    assert task is not None and task.state is TaskState.INTAKE
    assert event_count == 0


def test_complex_capability_gates_default_closed(
    state_machine_harness: StateMachineHarness,
) -> None:
    task_id, evidence_id = _create_task_policy_and_evidence(state_machine_harness)
    service = _service(
        state_machine_harness,
        ClosedTaskTransitionGateEvaluator(),
    )
    service.transition(
        task_id,
        transition_id=uuid4(),
        expected_state=TaskState.INTAKE,
        kind=TaskTransitionKind.START_BRIEFING,
        reason_code="START_BRIEFING",
        evidence_ids=(evidence_id,),
    )

    with pytest.raises(InvalidTaskTransitionError):
        service.transition(
            task_id,
            transition_id=uuid4(),
            expected_state=TaskState.BRIEFING,
            kind=TaskTransitionKind.AUTO_ACCEPT_BRIEF,
            reason_code="UNTRUSTED_BYPASS",
            evidence_ids=(evidence_id,),
        )


def test_scope_steering_atomically_clears_and_audits_prior_bindings(
    state_machine_harness: StateMachineHarness,
) -> None:
    task_id, evidence_id = _create_task_policy_and_evidence(state_machine_harness)
    with state_machine_harness.factory.begin() as session:
        task = session.get(Task, task_id)
        assert task is not None
        context = {
            "owner_id": task.owner_id,
            "actor_id": "control-plane",
            "root_correlation_id": task.root_correlation_id,
        }
        brief = Brief(
            task_id=task.id,
            version=1,
            scope={},
            exclusions=[],
            acceptance_criteria=[],
            risks=[],
            affected_flow={},
            test_plan=[],
            **context,
        )
        repository_configuration = RepositoryConfiguration(
            repository_key=task.repository,
            version=1,
            repository_settings={},
            git_settings={},
            xcode_settings={},
            operations=[],
            e2e_assertions=[],
            artifact_settings={},
            prohibited_paths=[],
            secret_references=[],
            **context,
        )
        session.add_all([brief, repository_configuration])
        session.flush()
        decision = BriefApprovalDecision(
            task_id=task.id,
            brief_id=brief.id,
            disposition=BriefDecisionDisposition.HUMAN_APPROVAL_REQUIRED,
            evaluator_id="control-plane",
            policy_version_id=None,
            reason="Exact brief was approved",
            ambiguity_flags=[],
            human_response="approve",
            decided_at=_NOW,
            **context,
        )
        contract = ValidationContract(
            task_id=task.id,
            version=1,
            brief_id=brief.id,
            repository_configuration_id=repository_configuration.id,
            required_operations=[],
            simulator_setup={},
            clean_state_setup={},
            e2e_flow={},
            typed_assertions=[],
            evidence_requirements=[],
            timeouts={},
            outcome_rules={},
            **context,
        )
        session.add_all([decision, contract])
        session.flush()
        task.state = TaskState.PR_ACTIVE
        task.accepted_brief_id = brief.id
        task.brief_approval_decision_id = decision.id
        task.repository_configuration_id = repository_configuration.id
        task.validation_contract_id = contract.id
        expected_invalidated_ids = {
            "accepted_brief_id": str(brief.id),
            "brief_approval_decision_id": str(decision.id),
            "validation_contract_id": str(contract.id),
        }

    with pytest.raises(InvalidTaskTransitionError):
        _service(
            state_machine_harness,
            StaticGateEvaluator(
                TaskTransitionGuards(work_fence_verified=True)
            ),
        ).transition(
            task_id,
            transition_id=uuid4(),
            expected_state=TaskState.PR_ACTIVE,
            kind=TaskTransitionKind.SCOPE_STEER,
            reason_code="USER_CHANGED_SCOPE",
            evidence_ids=(evidence_id,),
        )
    with state_machine_harness.factory() as session:
        assert session.scalar(
            select(func.count())
            .select_from(TaskEvent)
            .where(TaskEvent.task_id == task_id)
        ) == 0

    result = _service(
        state_machine_harness,
        StaticGateEvaluator(
            TaskTransitionGuards(
                work_fence_verified=True,
                scope_decisions_invalidated=True,
            )
        ),
    ).transition(
        task_id,
        transition_id=uuid4(),
        expected_state=TaskState.PR_ACTIVE,
        kind=TaskTransitionKind.SCOPE_STEER,
        reason_code="USER_CHANGED_SCOPE",
        evidence_ids=(evidence_id,),
    )

    with state_machine_harness.factory() as session:
        task = session.get(Task, task_id)
        event = session.get(TaskEvent, result.event_id)
        references = list(
            session.scalars(
                select(TaskEventEvidenceReference).where(
                    TaskEventEvidenceReference.task_event_id == result.event_id
                )
            )
        )
    assert task is not None and event is not None
    assert task.state is TaskState.BRIEFING
    assert task.accepted_brief_id is None
    assert task.brief_approval_decision_id is None
    assert task.validation_contract_id is None
    assert task.repository_configuration_id is not None
    assert event.payload["invalidated_ids"] == expected_invalidated_ids
    assert [reference.evidence_id for reference in references] == [evidence_id]


def test_full_verified_draft_readiness_and_handoff_path_records_exact_head(
    state_machine_harness: StateMachineHarness,
) -> None:
    task_id, evidence_id = _create_task_policy_and_evidence(state_machine_harness)
    service = _service(
        state_machine_harness,
        PositiveGateEvaluator(),
    )
    transitions = (
        (TaskState.INTAKE, TaskTransitionKind.START_BRIEFING),
        (TaskState.BRIEFING, TaskTransitionKind.AUTO_ACCEPT_BRIEF),
        (TaskState.IMPLEMENTING, TaskTransitionKind.BEGIN_VALIDATION),
        (TaskState.VALIDATING, TaskTransitionKind.OPEN_VERIFIED_DRAFT_PR),
        (TaskState.PR_ACTIVE, TaskTransitionKind.MARK_MERGE_READY),
        (
            TaskState.READY_FOR_HUMAN_MERGE,
            TaskTransitionKind.ACKNOWLEDGE_HANDOFF,
        ),
    )
    for expected_state, kind in transitions:
        service.transition(
            task_id,
            transition_id=uuid4(),
            expected_state=expected_state,
            kind=kind,
            reason_code=kind.value,
            evidence_ids=(evidence_id,),
        )

    with state_machine_harness.factory() as session:
        task = session.get(Task, task_id)
        events = list(
            session.scalars(
                select(TaskEvent)
                .where(TaskEvent.task_id == task_id)
                .order_by(TaskEvent.sequence)
            )
        )
    assert task is not None
    assert task.state is TaskState.HANDED_OFF
    assert task.terminal_outcome == TaskTerminalOutcome.AUTOMATION_HANDED_OFF.value
    assert events[-3].gate_head_sha == _SHA
    assert events[-2].gate_head_sha == _SHA
    assert events[-1].gate_head_sha == _SHA
    assert events[-1].payload["meaning"] == (
        "automation responsibility handed off; not merged, deployed, or released"
    )


def test_escalation_resumes_only_to_recorded_state_after_trusted_recheck(
    state_machine_harness: StateMachineHarness,
) -> None:
    task_id, evidence_id = _create_task_policy_and_evidence(state_machine_harness)
    service = _service(state_machine_harness)
    service.transition(
        task_id,
        transition_id=uuid4(),
        expected_state=TaskState.INTAKE,
        kind=TaskTransitionKind.START_BRIEFING,
        reason_code="START",
        evidence_ids=(evidence_id,),
    )
    service.transition(
        task_id,
        transition_id=uuid4(),
        expected_state=TaskState.BRIEFING,
        kind=TaskTransitionKind.ESCALATE,
        reason_code="DEPENDENCY_OUTAGE",
        evidence_ids=(evidence_id,),
    )
    with pytest.raises(InvalidTaskTransitionError, match="recorded state"):
        _service(
            state_machine_harness,
            StaticGateEvaluator(
                TaskTransitionGuards(resume_preconditions_rechecked=True)
            ),
        ).transition(
            task_id,
            transition_id=uuid4(),
            expected_state=TaskState.ESCALATED,
            kind=TaskTransitionKind.RESUME,
            reason_code="UNTRUSTED_RESUME",
            evidence_ids=(evidence_id,),
        )
    with state_machine_harness.factory() as session:
        task = session.get(Task, task_id)
        event_count = session.scalar(
            select(func.count())
            .select_from(TaskEvent)
            .where(TaskEvent.task_id == task_id)
        )
    assert task is not None and task.state is TaskState.ESCALATED
    assert event_count == 2

    resumed = _service(
        state_machine_harness,
        StaticGateEvaluator(
            TaskTransitionGuards(
                resume_decision_id=_RESUME_DECISION_ID,
                resume_decision_current=True,
                resume_preconditions_rechecked=True,
            )
        ),
    ).transition(
        task_id,
        transition_id=uuid4(),
        expected_state=TaskState.ESCALATED,
        kind=TaskTransitionKind.RESUME,
        reason_code="DEPENDENCY_RECOVERED",
        evidence_ids=(evidence_id,),
    )

    assert resumed.to_state is TaskState.BRIEFING
    with state_machine_harness.factory() as session:
        task = session.get(Task, task_id)
        event = session.get(TaskEvent, resumed.event_id)
    assert task is not None and event is not None
    assert task.escalation_resume_state is None
    assert task.terminal_outcome is None
    gate_facts = event.payload["gate_facts"]
    assert isinstance(gate_facts, dict)
    assert gate_facts["resume_decision_id"] == str(_RESUME_DECISION_ID)


def test_cross_task_deleted_and_corrected_evidence_are_rejected(
    state_machine_harness: StateMachineHarness,
) -> None:
    first_task_id, first_evidence_id = _create_task_policy_and_evidence(
        state_machine_harness
    )
    second_task_id, second_evidence_id = _create_task_policy_and_evidence(
        state_machine_harness
    )
    service = _service(state_machine_harness)

    with pytest.raises(TaskTransitionNotFoundError):
        service.transition(
            first_task_id,
            transition_id=uuid4(),
            expected_state=TaskState.INTAKE,
            kind=TaskTransitionKind.START_BRIEFING,
            reason_code="CROSS_TASK_EVIDENCE",
            evidence_ids=(second_evidence_id,),
        )

    with state_machine_harness.factory.begin() as session:
        evidence = session.get(EvidenceRecord, first_evidence_id)
        assert evidence is not None
        session.add(
            EvidenceDeletionRequest(
                evidence_id=evidence.id,
                reason_code="SECURITY_RESPONSE",
                requested_at=_NOW,
                owner_id=evidence.owner_id,
                actor_id="control-plane",
                root_correlation_id=evidence.root_correlation_id,
            )
        )
    with pytest.raises(TaskTransitionNotFoundError):
        service.transition(
            first_task_id,
            transition_id=uuid4(),
            expected_state=TaskState.INTAKE,
            kind=TaskTransitionKind.START_BRIEFING,
            reason_code="DELETED_EVIDENCE",
            evidence_ids=(first_evidence_id,),
        )

    # The unrelated task remains usable; a correction successor makes its
    # original evidence stale even before any projection consumes it.
    with state_machine_harness.factory.begin() as session:
        original = session.get(EvidenceRecord, second_evidence_id)
        assert original is not None
        session.add(
            EvidenceRecord(
                task_id=original.task_id,
                validation_run_id=original.validation_run_id,
                evidence_type=original.evidence_type,
                origin="local-user:correction",
                content_hash=original.content_hash,
                content_address=original.content_address,
                captured_at=_NOW,
                access_classification=original.access_classification,
                retention_policy=original.retention_policy,
                correction_of_id=original.id,
                owner_id=original.owner_id,
                actor_id="local-user",
                root_correlation_id=original.root_correlation_id,
            )
        )
    with pytest.raises(TaskTransitionNotFoundError):
        service.transition(
            second_task_id,
            transition_id=uuid4(),
            expected_state=TaskState.INTAKE,
            kind=TaskTransitionKind.START_BRIEFING,
            reason_code="STALE_EVIDENCE",
            evidence_ids=(second_evidence_id,),
        )


def test_corrupt_evidence_cannot_authorize_a_transition(
    state_machine_harness: StateMachineHarness,
) -> None:
    task_id, evidence_id = _create_task_policy_and_evidence(state_machine_harness)
    with state_machine_harness.factory() as session:
        evidence = session.get(EvidenceRecord, evidence_id)
        assert evidence is not None and evidence.content_address is not None
        digest = evidence.content_address.removeprefix("sha256:")
    artifact_path = (
        state_machine_harness.store.root
        / "sha256"
        / digest[:2]
        / digest[2:]
    )
    artifact_path.write_bytes(b"corrupt transition evidence")

    with pytest.raises(TaskTransitionNotFoundError):
        _service(state_machine_harness).transition(
            task_id,
            transition_id=uuid4(),
            expected_state=TaskState.INTAKE,
            kind=TaskTransitionKind.START_BRIEFING,
            reason_code="REQUEST_ACCEPTED",
            evidence_ids=(evidence_id,),
        )

    with state_machine_harness.factory() as session:
        task = session.get(Task, task_id)
        event_count = session.scalar(
            select(func.count())
            .select_from(TaskEvent)
            .where(TaskEvent.task_id == task_id)
        )
    assert task is not None and task.state is TaskState.INTAKE
    assert event_count == 0


def test_transition_rejects_an_unstructured_reason_code(
    state_machine_harness: StateMachineHarness,
) -> None:
    task_id, evidence_id = _create_task_policy_and_evidence(state_machine_harness)

    with pytest.raises(InvalidTaskTransitionError):
        _service(state_machine_harness).transition(
            task_id,
            transition_id=uuid4(),
            expected_state=TaskState.INTAKE,
            kind=TaskTransitionKind.START_BRIEFING,
            reason_code="reason with spaces",
            evidence_ids=(evidence_id,),
        )


def test_transition_service_rejects_a_sensitive_configured_principal(
    state_machine_harness: StateMachineHarness,
) -> None:
    with pytest.raises(InvalidTaskTransitionError):
        TaskTransitionService(
            state_machine_harness.factory,
            state_machine_harness.store,
            principal_id="ghp_" + ("A" * 24),
        )
