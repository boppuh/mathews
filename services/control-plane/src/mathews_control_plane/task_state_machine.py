"""Pure task transitions and the audited control-plane transaction boundary."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    EvidenceDeletionRequest,
    EvidenceRecord,
    PolicyVersion,
    Task,
    TaskEvent,
    TaskEventEvidenceReference,
    TaskState,
    TaskTerminalOutcome,
)
from mathews_control_plane.evidence import (
    EvidenceError,
    load_evidence,
    redact_evidence_content,
)
from mathews_control_plane.readiness_contract import HANDOFF_MEANING

TASK_TRANSITION_EVENT_TYPE = "TASK_STATE_TRANSITION"
TASK_TRANSITION_SCHEMA_VERSION = 1
MAX_TRANSITION_EVIDENCE_REFERENCES = 100

_ACTOR_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]*\Z")
_REASON_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,99}\Z")
_TERMINAL_STATES = frozenset(
    {
        TaskState.HANDED_OFF,
        TaskState.FAILED,
        TaskState.CANCELLED,
    }
)
_ACTIVE_STATES = frozenset(state for state in TaskState if state not in _TERMINAL_STATES)
_SCOPE_STEERING_STATES = _ACTIVE_STATES - {TaskState.ESCALATED}


class TaskTransitionKind(StrEnum):
    """Typed intent; each member selects one legal edge and guard set."""

    START_BRIEFING = "START_BRIEFING"
    AUTO_ACCEPT_BRIEF = "AUTO_ACCEPT_BRIEF"
    REQUEST_BRIEF_APPROVAL = "REQUEST_BRIEF_APPROVAL"
    REVISE_BRIEF = "REVISE_BRIEF"
    APPROVE_EXACT_BRIEF = "APPROVE_EXACT_BRIEF"
    BEGIN_VALIDATION = "BEGIN_VALIDATION"
    BEGIN_REPAIR = "BEGIN_REPAIR"
    REVALIDATE = "REVALIDATE"
    OPEN_VERIFIED_DRAFT_PR = "OPEN_VERIFIED_DRAFT_PR"
    MARK_MERGE_READY = "MARK_MERGE_READY"
    INVALIDATE_READINESS = "INVALIDATE_READINESS"
    ACKNOWLEDGE_HANDOFF = "ACKNOWLEDGE_HANDOFF"
    ESCALATE = "ESCALATE"
    RESUME = "RESUME"
    CANCEL = "CANCEL"
    FAIL = "FAIL"
    SCOPE_STEER = "SCOPE_STEER"


class TaskTransitionError(RuntimeError):
    """Base class for safe task-transition failures."""


class InvalidTaskTransitionError(TaskTransitionError):
    """Raised when a requested edge or its authoritative guards are invalid."""


class TaskTransitionNotFoundError(TaskTransitionError):
    """Raised when a task, policy, or evidence reference is unavailable."""


class TaskTransitionConflictError(TaskTransitionError):
    """Raised when durable state no longer matches the command."""


@dataclass(frozen=True, slots=True)
class DraftPrGateFacts:
    """Server-built facts proving one exact current head has a verified draft."""

    current_head_sha: str
    validation_commit_sha: str
    local_branch_sha: str
    remote_branch_sha: str
    pull_request_head_sha: str
    validation_passed: bool
    required_artifacts_present: bool
    branch_clean: bool
    pull_request_is_draft: bool
    no_unresolved_approval: bool
    cancellation_clear: bool


@dataclass(frozen=True, slots=True)
class ValidationCandidate:
    """Exact Git objects fenced to one validation transition."""

    commit_sha: str
    tree_sha: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "commit_sha", _normalized_git_sha(self.commit_sha))
        object.__setattr__(self, "tree_sha", _normalized_git_sha(self.tree_sha))


@dataclass(frozen=True, slots=True)
class ReadinessGateFacts:
    """Server-built facts required to offer one exact head for human action."""

    draft_pr: DraftPrGateFacts
    required_ci_green: bool
    no_blocking_review: bool
    repairs_authorized: bool


@dataclass(frozen=True, slots=True)
class TaskTransitionGuards:
    """Trusted gate output resolved inside the locked transaction."""

    brief_policy_bypass_authorized: bool = False
    brief_approval_required: bool = False
    brief_revision_request_id: UUID | None = None
    exact_brief_human_approval: bool = False
    repair_authorized: bool = False
    draft_pr: DraftPrGateFacts | None = None
    readiness: ReadinessGateFacts | None = None
    readiness_invalidation_current: bool = False
    human_handoff_acknowledged: bool = False
    resume_decision_id: UUID | None = None
    resume_decision_current: bool = False
    resume_preconditions_rechecked: bool = False
    work_fence_verified: bool = False
    scope_decisions_invalidated: bool = False


class TaskTransitionGateEvaluator(Protocol):
    """Resolve authoritative task gates; callers never submit gate booleans."""

    def evaluate(
        self,
        session: Session,
        task: Task,
        kind: TaskTransitionKind,
        *,
        policy: PolicyVersion,
        now: datetime,
    ) -> TaskTransitionGuards: ...


class ClosedTaskTransitionGateEvaluator:
    """Default-close capabilities whose authoritative adapters are not installed."""

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
        return TaskTransitionGuards()


@dataclass(frozen=True, slots=True)
class TaskTransitionSnapshot:
    """Persistence-independent state consumed by the pure engine."""

    state: TaskState
    escalation_resume_state: TaskState | None = None
    verified_pr_head_sha: str | None = None


@dataclass(frozen=True, slots=True)
class TaskTransitionPlan:
    """Accepted pure transition output applied atomically by the service."""

    from_state: TaskState
    to_state: TaskState
    kind: TaskTransitionKind
    escalation_resume_state: TaskState | None
    terminal_outcome: TaskTerminalOutcome | None
    gate_head_sha: str | None
    retry_delta: int = 0
    invalidate_scope_bindings: bool = False


@dataclass(frozen=True, slots=True)
class TaskTransitionResult:
    """Committed transition identity returned without evidence content."""

    task_id: UUID
    transition_id: UUID
    event_id: UUID
    sequence: int
    from_state: TaskState
    to_state: TaskState
    replayed: bool = False


def _normalized_git_sha(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise InvalidTaskTransitionError("gate contains an invalid Git object ID")
    return normalized


def _verified_draft_head(facts: DraftPrGateFacts) -> str:
    current_head = _normalized_git_sha(facts.current_head_sha)
    correlated_heads = {
        _normalized_git_sha(facts.validation_commit_sha),
        _normalized_git_sha(facts.local_branch_sha),
        _normalized_git_sha(facts.remote_branch_sha),
        _normalized_git_sha(facts.pull_request_head_sha),
    }
    if correlated_heads != {current_head} or not all(
        (
            facts.validation_passed,
            facts.required_artifacts_present,
            facts.branch_clean,
            facts.pull_request_is_draft,
            facts.no_unresolved_approval,
            facts.cancellation_clear,
        )
    ):
        raise InvalidTaskTransitionError(
            "the exact-head verified draft PR gate is not satisfied"
        )
    return current_head


def _readiness_head(
    snapshot: TaskTransitionSnapshot,
    facts: ReadinessGateFacts,
) -> str:
    current_head = _verified_draft_head(facts.draft_pr)
    if (
        snapshot.verified_pr_head_sha is None
        or _normalized_git_sha(snapshot.verified_pr_head_sha) != current_head
        or not all(
            (
                facts.required_ci_green,
                facts.no_blocking_review,
                facts.repairs_authorized,
            )
        )
    ):
        raise InvalidTaskTransitionError(
            "the exact-current-head readiness gate is not satisfied"
        )
    return current_head


def _plan(
    snapshot: TaskTransitionSnapshot,
    kind: TaskTransitionKind,
    target: TaskState,
    *,
    resume: TaskState | None = None,
    outcome: TaskTerminalOutcome | None = None,
    gate_head: str | None = None,
    retry_delta: int = 0,
    invalidate_scope_bindings: bool = False,
) -> TaskTransitionPlan:
    return TaskTransitionPlan(
        from_state=snapshot.state,
        to_state=target,
        kind=kind,
        escalation_resume_state=resume,
        terminal_outcome=outcome,
        gate_head_sha=gate_head,
        retry_delta=retry_delta,
        invalidate_scope_bindings=invalidate_scope_bindings,
    )


def evaluate_task_transition(
    snapshot: TaskTransitionSnapshot,
    kind: TaskTransitionKind,
    guards: TaskTransitionGuards,
) -> TaskTransitionPlan:
    """Purely validate one typed intent and return its durable projection."""

    current = snapshot.state
    if current in _TERMINAL_STATES:
        raise InvalidTaskTransitionError("terminal tasks cannot transition")

    if kind is TaskTransitionKind.CANCEL:
        return _plan(
            snapshot,
            kind,
            TaskState.CANCELLED,
            outcome=TaskTerminalOutcome.CANCELLED,
        )
    if kind is TaskTransitionKind.FAIL:
        return _plan(
            snapshot,
            kind,
            TaskState.FAILED,
            outcome=TaskTerminalOutcome.FAILED,
        )
    if kind is TaskTransitionKind.ESCALATE:
        if current is TaskState.ESCALATED:
            raise InvalidTaskTransitionError("an escalated task cannot escalate again")
        return _plan(
            snapshot,
            kind,
            TaskState.ESCALATED,
            resume=current,
        )
    if kind is TaskTransitionKind.RESUME:
        target = snapshot.escalation_resume_state
        if (
            current is not TaskState.ESCALATED
            or target is None
            or target in _TERMINAL_STATES
            or target is TaskState.ESCALATED
            or guards.resume_decision_id is None
            or not guards.resume_decision_current
            or not guards.resume_preconditions_rechecked
        ):
            raise InvalidTaskTransitionError(
                "escalation may resume only to the recorded state after recheck"
            )
        return _plan(snapshot, kind, target)
    if kind is TaskTransitionKind.SCOPE_STEER:
        if (
            current not in _SCOPE_STEERING_STATES
            or not guards.work_fence_verified
            or not guards.scope_decisions_invalidated
        ):
            raise InvalidTaskTransitionError(
                "scope steering requires trusted fencing and invalidation"
            )
        return _plan(
            snapshot,
            kind,
            TaskState.BRIEFING,
            invalidate_scope_bindings=True,
        )

    if kind is TaskTransitionKind.START_BRIEFING:
        valid = current is TaskState.INTAKE
        target = TaskState.BRIEFING
    elif kind is TaskTransitionKind.AUTO_ACCEPT_BRIEF:
        valid = (
            current is TaskState.BRIEFING
            and guards.brief_policy_bypass_authorized
        )
        target = TaskState.IMPLEMENTING
    elif kind is TaskTransitionKind.REQUEST_BRIEF_APPROVAL:
        valid = current is TaskState.BRIEFING and guards.brief_approval_required
        target = TaskState.BRIEF_PENDING_APPROVAL
    elif kind is TaskTransitionKind.REVISE_BRIEF:
        valid = (
            current is TaskState.BRIEF_PENDING_APPROVAL
            and guards.brief_revision_request_id is not None
        )
        target = TaskState.BRIEFING
    elif kind is TaskTransitionKind.APPROVE_EXACT_BRIEF:
        valid = (
            current is TaskState.BRIEF_PENDING_APPROVAL
            and guards.exact_brief_human_approval
        )
        target = TaskState.IMPLEMENTING
    elif kind is TaskTransitionKind.BEGIN_VALIDATION:
        valid = current is TaskState.IMPLEMENTING
        target = TaskState.VALIDATING
    elif kind is TaskTransitionKind.BEGIN_REPAIR:
        valid = (
            current in {TaskState.VALIDATING, TaskState.PR_ACTIVE}
            and guards.repair_authorized
        )
        target = TaskState.REPAIRING
    elif kind is TaskTransitionKind.REVALIDATE:
        valid = current is TaskState.REPAIRING
        target = TaskState.VALIDATING
    elif kind is TaskTransitionKind.OPEN_VERIFIED_DRAFT_PR:
        valid = current is TaskState.VALIDATING and guards.draft_pr is not None
        target = TaskState.PR_ACTIVE
    elif kind is TaskTransitionKind.MARK_MERGE_READY:
        valid = current is TaskState.PR_ACTIVE and guards.readiness is not None
        target = TaskState.READY_FOR_HUMAN_MERGE
    elif kind is TaskTransitionKind.INVALIDATE_READINESS:
        valid = (
            current is TaskState.READY_FOR_HUMAN_MERGE
            and guards.readiness_invalidation_current
        )
        target = TaskState.PR_ACTIVE
    elif kind is TaskTransitionKind.ACKNOWLEDGE_HANDOFF:
        valid = (
            current is TaskState.READY_FOR_HUMAN_MERGE
            and guards.human_handoff_acknowledged
            and guards.readiness is not None
        )
        target = TaskState.HANDED_OFF
    else:
        valid = False
        target = current
    if not valid:
        raise InvalidTaskTransitionError("task transition is not allowed")

    gate_head: str | None = None
    retry_delta = 1 if kind is TaskTransitionKind.BEGIN_REPAIR else 0
    if kind is TaskTransitionKind.OPEN_VERIFIED_DRAFT_PR:
        if guards.draft_pr is None:
            raise InvalidTaskTransitionError("task transition is not allowed")
        gate_head = _verified_draft_head(guards.draft_pr)
    elif kind in {
        TaskTransitionKind.MARK_MERGE_READY,
        TaskTransitionKind.ACKNOWLEDGE_HANDOFF,
    }:
        if guards.readiness is None:
            raise InvalidTaskTransitionError("task transition is not allowed")
        gate_head = _readiness_head(snapshot, guards.readiness)

    outcome = (
        TaskTerminalOutcome.AUTOMATION_HANDED_OFF
        if target is TaskState.HANDED_OFF
        else None
    )
    return _plan(
        snapshot,
        kind,
        target,
        outcome=outcome,
        gate_head=gate_head,
        retry_delta=retry_delta,
    )


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _required_actor(value: str) -> str:
    normalized = value.strip()
    prepared = redact_evidence_content(
        normalized,
        media_type="text/plain; charset=utf-8",
    )
    if (
        not normalized
        or len(normalized) > 255
        or _ACTOR_IDENTIFIER.fullmatch(normalized) is None
        or "://" in normalized
        or "//" in normalized
        or ".." in normalized
        or normalized.startswith("/")
        or prepared.manifest
    ):
        raise InvalidTaskTransitionError("transition actor is invalid")
    return normalized


def _required_reason_code(value: str) -> str:
    normalized = value.strip().upper()
    if _REASON_CODE.fullmatch(normalized) is None:
        raise InvalidTaskTransitionError("transition reason code is invalid")
    return normalized


def _command_fingerprint(
    *,
    task_id: UUID,
    transition_id: UUID,
    expected_state: TaskState,
    kind: TaskTransitionKind,
    reason_code: str,
    actor_id: str,
    evidence_ids: Sequence[UUID],
    validation_candidate: ValidationCandidate | None,
) -> str:
    command: dict[str, object] = {
        "actor_id": actor_id,
        "evidence_ids": sorted(str(evidence_id) for evidence_id in evidence_ids),
        "expected_state": expected_state.value,
        "kind": kind.value,
        "reason_code": reason_code,
        "task_id": str(task_id),
        "transition_id": str(transition_id),
    }
    if validation_candidate is not None:
        command["validation_candidate"] = {
            "commit_sha": validation_candidate.commit_sha,
            "tree_sha": validation_candidate.tree_sha,
        }
    payload = json.dumps(
        command,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _latest_verified_pr_head(session: Session, task_id: UUID) -> str | None:
    value = session.scalar(
        select(TaskEvent.gate_head_sha)
        .where(
            TaskEvent.task_id == task_id,
            TaskEvent.event_type == TASK_TRANSITION_EVENT_TYPE,
            TaskEvent.gate_head_sha.is_not(None),
        )
        .order_by(TaskEvent.sequence.desc())
        .limit(1)
    )
    if value is None:
        return None
    try:
        return _normalized_git_sha(value)
    except InvalidTaskTransitionError:
        raise TaskTransitionConflictError(
            "stored transition gate head is invalid"
        ) from None


def _next_event_sequence(session: Session, task_id: UUID) -> int:
    current = session.scalar(
        select(func.max(TaskEvent.sequence)).where(TaskEvent.task_id == task_id)
    )
    return int(current or 0) + 1


def _active_policy(
    session: Session,
    task: Task,
    *,
    lineage_key: str,
    now: datetime,
) -> PolicyVersion:
    policy = session.scalar(
        select(PolicyVersion)
        .where(
            PolicyVersion.lineage_key == lineage_key,
            PolicyVersion.owner_id == task.owner_id,
            PolicyVersion.approved_at <= now,
        )
        .order_by(PolicyVersion.version.desc())
        .limit(1)
        .with_for_update()
    )
    if policy is None:
        raise TaskTransitionNotFoundError("active policy version is unavailable")
    return policy


def _replayed_result(
    event: TaskEvent,
    *,
    task_id: UUID,
    transition_id: UUID,
    kind: TaskTransitionKind,
    validation_candidate: ValidationCandidate | None,
    fingerprint: str,
) -> TaskTransitionResult:
    stored_candidate = event.payload.get("validation_candidate")
    candidate_matches = True
    if kind in {
        TaskTransitionKind.BEGIN_VALIDATION,
        TaskTransitionKind.REVALIDATE,
    }:
        candidate_matches = (
            validation_candidate is not None
            and isinstance(stored_candidate, Mapping)
            and set(stored_candidate) == {"commit_sha", "tree_sha"}
            and stored_candidate.get("commit_sha")
            == validation_candidate.commit_sha
            and stored_candidate.get("tree_sha") == validation_candidate.tree_sha
        )
    if (
        event.task_id != task_id
        or event.transition_kind != kind.value
        or not candidate_matches
        or event.transition_fingerprint != fingerprint
        or event.transition_from_state is None
        or event.transition_to_state is None
    ):
        raise TaskTransitionConflictError(
            "transition id was already used for a different command"
        )
    return TaskTransitionResult(
        task_id=task_id,
        transition_id=transition_id,
        event_id=event.id,
        sequence=event.sequence,
        from_state=TaskState(event.transition_from_state),
        to_state=TaskState(event.transition_to_state),
        replayed=True,
    )


def _verify_transition_evidence(
    session: Session,
    artifact_store: ArtifactStore,
    task: Task,
    evidence_ids: Sequence[UUID],
) -> list[EvidenceRecord]:
    records = list(
        session.scalars(
            select(EvidenceRecord)
            .where(EvidenceRecord.id.in_(evidence_ids))
            .with_for_update()
        )
    )
    records_by_id = {record.id: record for record in records}
    if len(records_by_id) != len(evidence_ids):
        raise TaskTransitionNotFoundError("transition evidence is unavailable")
    correction_source_ids = {
        correction_of_id
        for correction_of_id in session.scalars(
            select(EvidenceRecord.correction_of_id).where(
                EvidenceRecord.correction_of_id.in_(evidence_ids)
            )
        )
        if correction_of_id is not None
    }
    deletion_requested_ids = set(
        session.scalars(
            select(EvidenceDeletionRequest.evidence_id).where(
                EvidenceDeletionRequest.evidence_id.in_(evidence_ids)
            )
        )
    )
    ordered: list[EvidenceRecord] = []
    for evidence_id in evidence_ids:
        record = records_by_id[evidence_id]
        if (
            record.task_id != task.id
            or record.owner_id != task.owner_id
            or record.root_correlation_id != task.root_correlation_id
            or record.id in correction_source_ids
            or record.id in deletion_requested_ids
        ):
            raise TaskTransitionNotFoundError("transition evidence is unavailable")
        try:
            load_evidence(session, artifact_store, record)
        except EvidenceError:
            raise TaskTransitionNotFoundError(
                "transition evidence is unavailable"
            ) from None
        ordered.append(record)
    return ordered


def _transition_task(
    session: Session,
    artifact_store: ArtifactStore,
    *,
    task_id: UUID,
    transition_id: UUID,
    expected_state: TaskState,
    kind: TaskTransitionKind,
    reason_code: str,
    actor_id: str,
    evidence_ids: Sequence[UUID],
    validation_candidate: ValidationCandidate | None,
    gate_evaluator: TaskTransitionGateEvaluator,
    active_policy_lineage: str,
    occurred_at: datetime,
) -> TaskTransitionResult:
    """Lock, verify, idempotently audit, and apply one state transition."""

    now = _as_utc(occurred_at)
    normalized_actor = _required_actor(actor_id)
    normalized_reason = _required_reason_code(reason_code)
    unique_evidence_ids = tuple(dict.fromkeys(evidence_ids))
    if (
        not unique_evidence_ids
        or len(unique_evidence_ids) != len(evidence_ids)
        or len(unique_evidence_ids) > MAX_TRANSITION_EVIDENCE_REFERENCES
    ):
        raise InvalidTaskTransitionError("transition evidence references are invalid")
    if kind in {
        TaskTransitionKind.BEGIN_VALIDATION,
        TaskTransitionKind.REVALIDATE,
    }:
        if validation_candidate is None:
            raise InvalidTaskTransitionError(
                "validation transition requires exact candidate Git objects"
            )
    elif validation_candidate is not None:
        raise InvalidTaskTransitionError(
            "validation candidate is not allowed for this transition"
        )
    fingerprint = _command_fingerprint(
        task_id=task_id,
        transition_id=transition_id,
        expected_state=expected_state,
        kind=kind,
        reason_code=normalized_reason,
        actor_id=normalized_actor,
        evidence_ids=unique_evidence_ids,
        validation_candidate=validation_candidate,
    )

    task = session.scalar(select(Task).where(Task.id == task_id).with_for_update())
    if task is None:
        raise TaskTransitionNotFoundError("task is unavailable")
    existing = session.scalar(
        select(TaskEvent).where(TaskEvent.transition_id == transition_id)
    )
    if existing is not None:
        return _replayed_result(
            existing,
            task_id=task_id,
            transition_id=transition_id,
            kind=kind,
            validation_candidate=validation_candidate,
            fingerprint=fingerprint,
        )
    if TaskState(task.state) is not expected_state:
        raise TaskTransitionConflictError("task state no longer matches expected state")

    policy = _active_policy(
        session,
        task,
        lineage_key=active_policy_lineage,
        now=now,
    )
    evidence_records = _verify_transition_evidence(
        session,
        artifact_store,
        task,
        unique_evidence_ids,
    )
    snapshot = TaskTransitionSnapshot(
        state=TaskState(task.state),
        escalation_resume_state=(
            None
            if task.escalation_resume_state is None
            else TaskState(task.escalation_resume_state)
        ),
        verified_pr_head_sha=_latest_verified_pr_head(session, task.id),
    )
    guards = gate_evaluator.evaluate(
        session,
        task,
        kind,
        policy=policy,
        now=now,
    )
    plan = evaluate_task_transition(snapshot, kind, guards)
    sequence = _next_event_sequence(session, task.id)
    invalidated_ids = (
        {
            "accepted_brief_id": (
                None if task.accepted_brief_id is None else str(task.accepted_brief_id)
            ),
            "brief_approval_decision_id": (
                None
                if task.brief_approval_decision_id is None
                else str(task.brief_approval_decision_id)
            ),
            "validation_contract_id": (
                None
                if task.validation_contract_id is None
                else str(task.validation_contract_id)
            ),
        }
        if plan.invalidate_scope_bindings
        else None
    )
    gate_facts = asdict(guards)
    for identity_field in ("brief_revision_request_id", "resume_decision_id"):
        identity = gate_facts[identity_field]
        gate_facts[identity_field] = (
            None if identity is None else str(identity)
        )
    payload: dict[str, object] = {
        "schema_version": TASK_TRANSITION_SCHEMA_VERSION,
        "kind": plan.kind.value,
        "gate_facts": gate_facts,
        "invalidated_ids": invalidated_ids,
        "meaning": HANDOFF_MEANING if plan.to_state is TaskState.HANDED_OFF else None,
    }
    if validation_candidate is not None:
        payload["validation_candidate"] = {
            "commit_sha": validation_candidate.commit_sha,
            "tree_sha": validation_candidate.tree_sha,
        }
    event = TaskEvent(
        task_id=task.id,
        sequence=sequence,
        event_type=TASK_TRANSITION_EVENT_TYPE,
        payload=payload,
        occurred_at=now,
        transition_id=transition_id,
        transition_fingerprint=fingerprint,
        transition_kind=plan.kind.value,
        transition_from_state=plan.from_state,
        transition_to_state=plan.to_state,
        transition_reason_code=normalized_reason,
        policy_lineage_key=policy.lineage_key,
        policy_version_id=policy.id,
        gate_head_sha=plan.gate_head_sha,
        owner_id=task.owner_id,
        actor_id=normalized_actor,
        root_correlation_id=task.root_correlation_id,
        causation_id=task.id,
        parent_correlation_id=task.parent_correlation_id,
    )
    session.add(event)
    session.flush()
    for position, evidence in enumerate(evidence_records, start=1):
        session.add(
            TaskEventEvidenceReference(
                task_id=task.id,
                task_event_id=event.id,
                evidence_id=evidence.id,
                position=position,
                owner_id=task.owner_id,
                actor_id=normalized_actor,
                root_correlation_id=task.root_correlation_id,
                causation_id=event.id,
                parent_correlation_id=task.id,
            )
        )
    session.flush()

    task.state = plan.to_state
    task.escalation_resume_state = plan.escalation_resume_state
    task.terminal_outcome = (
        None if plan.terminal_outcome is None else plan.terminal_outcome.value
    )
    task.retry_count += plan.retry_delta
    task.actor_id = normalized_actor
    task.causation_id = event.id
    if plan.invalidate_scope_bindings:
        task.accepted_brief_id = None
        task.brief_approval_decision_id = None
        task.validation_contract_id = None
    session.flush()
    return TaskTransitionResult(
        task_id=task.id,
        transition_id=transition_id,
        event_id=event.id,
        sequence=sequence,
        from_state=plan.from_state,
        to_state=plan.to_state,
    )


class TaskTransitionService:
    """Committed control-plane boundary for all durable state changes."""

    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        *,
        gate_evaluator: TaskTransitionGateEvaluator | None = None,
        active_policy_lineage: str = "mvp",
        principal_id: str = "control-plane",
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._factory = factory
        self._artifact_store = artifact_store
        self._gate_evaluator = (
            gate_evaluator or ClosedTaskTransitionGateEvaluator()
        )
        self._active_policy_lineage = active_policy_lineage
        self._principal_id = _required_actor(principal_id)
        self._clock = clock

    def transition(
        self,
        task_id: UUID,
        *,
        transition_id: UUID,
        expected_state: TaskState,
        kind: TaskTransitionKind,
        reason_code: str,
        evidence_ids: Sequence[UUID],
        validation_candidate: ValidationCandidate | None = None,
    ) -> TaskTransitionResult:
        with self._factory() as session, session.begin():
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            try:
                with session.begin_nested():
                    return _transition_task(
                        session,
                        self._artifact_store,
                        task_id=task_id,
                        transition_id=transition_id,
                        expected_state=expected_state,
                        kind=kind,
                        reason_code=reason_code,
                        actor_id=self._principal_id,
                        evidence_ids=evidence_ids,
                        validation_candidate=validation_candidate,
                        gate_evaluator=self._gate_evaluator,
                        active_policy_lineage=self._active_policy_lineage,
                        occurred_at=_as_utc(self._clock()),
                    )
            except IntegrityError:
                existing = session.scalar(
                    select(TaskEvent).where(
                        TaskEvent.transition_id == transition_id
                    )
                )
                if existing is None:
                    raise
                fingerprint = _command_fingerprint(
                    task_id=task_id,
                    transition_id=transition_id,
                    expected_state=expected_state,
                    kind=kind,
                    reason_code=_required_reason_code(reason_code),
                    actor_id=self._principal_id,
                    evidence_ids=tuple(dict.fromkeys(evidence_ids)),
                    validation_candidate=validation_candidate,
                )
                return _replayed_result(
                    existing,
                    task_id=task_id,
                    transition_id=transition_id,
                    kind=kind,
                    validation_candidate=validation_candidate,
                    fingerprint=fingerprint,
                )
