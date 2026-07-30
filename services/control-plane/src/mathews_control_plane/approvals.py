"""Durable human approvals and exact-state resumable escalation."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast
from uuid import NAMESPACE_URL, UUID, uuid5

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.database import SessionFactory
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
    TaskEventEvidenceReference,
    TaskState,
)
from mathews_control_plane.task_state_machine import (
    TaskTransitionError,
    TaskTransitionGateEvaluator,
    TaskTransitionGuards,
    TaskTransitionKind,
    _transition_task,
)

APPROVAL_EVENT_SCHEMA_VERSION = 1
MAX_APPROVAL_LIFETIME = timedelta(days=30)
MAX_APPROVAL_EVIDENCE_REFERENCES = 100
MAX_RETRY_HISTORY_ENTRIES = 100
_UNINITIALIZED_FINGERPRINT = "0" * 64

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]*\Z")
_OPERATION_NAME = re.compile(
    r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,4}\Z"
)
_REASON_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,99}\Z")
_ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,99}\Z")
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_REQUEST_OPTIONS: Mapping[ApprovalRequestType, tuple[ApprovalDecision, ...]] = {
    ApprovalRequestType.BRIEF: (
        ApprovalDecision.APPROVE,
        ApprovalDecision.REQUEST_REVISION,
        ApprovalDecision.CANCEL,
    ),
    ApprovalRequestType.UNSAFE_ACTION: (
        ApprovalDecision.APPROVE,
        ApprovalDecision.DENY,
        ApprovalDecision.CANCEL,
    ),
    ApprovalRequestType.RETRY_LIMIT: (
        ApprovalDecision.RETRY,
        ApprovalDecision.ABANDON,
        ApprovalDecision.CANCEL,
    ),
    ApprovalRequestType.REVIEW_CONFLICT: (
        ApprovalDecision.APPROVE,
        ApprovalDecision.DENY,
        ApprovalDecision.CANCEL,
    ),
    ApprovalRequestType.REVIEW_RULE: (
        ApprovalDecision.APPROVE,
        ApprovalDecision.REJECT,
        ApprovalDecision.CANCEL,
    ),
}
_APPROVING_DECISIONS = frozenset(
    {
        ApprovalDecision.APPROVE,
        ApprovalDecision.RETRY,
    }
)
_PRECONDITIONED_DECISIONS = _APPROVING_DECISIONS | {
    ApprovalDecision.REJECT,
    ApprovalDecision.REQUEST_REVISION
}


class ApprovalError(RuntimeError):
    """Base class for safe approval-service failures."""


class InvalidApprovalError(ApprovalError):
    """The approval command or durable record is invalid."""


class ApprovalNotFoundError(ApprovalError):
    """The approval or one of its exact subjects is unavailable."""


class ApprovalConflictError(ApprovalError):
    """The task, request, decision, or precondition changed."""


class ApprovalPreconditionError(ApprovalError):
    """The approved operation no longer satisfies its captured preconditions."""


@dataclass(frozen=True, slots=True)
class BlockedOperation:
    """Non-secret identity of the exact operation waiting for a decision."""

    operation_name: str
    idempotency_key: str
    input_fingerprint: str
    checkpoint_evidence_id: UUID | None = None

    def __post_init__(self) -> None:
        if _OPERATION_NAME.fullmatch(self.operation_name) is None:
            raise InvalidApprovalError("blocked operation name is invalid")
        if (
            not self.idempotency_key
            or len(self.idempotency_key) > 255
            or _IDENTIFIER.fullmatch(self.idempotency_key) is None
        ):
            raise InvalidApprovalError(
                "blocked operation idempotency key is invalid"
            )
        if _HEX_DIGEST.fullmatch(self.input_fingerprint) is None:
            raise InvalidApprovalError("blocked operation fingerprint is invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "checkpoint_evidence_id": (
                None
                if self.checkpoint_evidence_id is None
                else str(self.checkpoint_evidence_id)
            ),
            "idempotency_key": self.idempotency_key,
            "input_fingerprint": self.input_fingerprint,
            "operation_name": self.operation_name,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> BlockedOperation:
        if set(value) != {
            "checkpoint_evidence_id",
            "idempotency_key",
            "input_fingerprint",
            "operation_name",
        }:
            raise ApprovalConflictError("stored blocked operation is invalid")
        checkpoint_value = value["checkpoint_evidence_id"]
        try:
            checkpoint = (
                None
                if checkpoint_value is None
                else UUID(cast(str, checkpoint_value))
            )
            return cls(
                operation_name=cast(str, value["operation_name"]),
                idempotency_key=cast(str, value["idempotency_key"]),
                input_fingerprint=cast(str, value["input_fingerprint"]),
                checkpoint_evidence_id=checkpoint,
            )
        except (TypeError, ValueError, InvalidApprovalError):
            raise ApprovalConflictError(
                "stored blocked operation is invalid"
            ) from None


@dataclass(frozen=True, slots=True)
class ApprovalRetryAttempt:
    """Bounded safe retry history captured with an escalation."""

    attempt: int
    error_code: str
    occurred_at: datetime
    checkpoint_evidence_id: UUID | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.attempt <= MAX_RETRY_HISTORY_ENTRIES:
            raise InvalidApprovalError("retry attempt is invalid")
        if _ERROR_CODE.fullmatch(self.error_code) is None:
            raise InvalidApprovalError("retry error code is invalid")
        object.__setattr__(self, "occurred_at", _as_utc(self.occurred_at))

    def to_dict(self) -> dict[str, object]:
        return {
            "attempt": self.attempt,
            "checkpoint_evidence_id": (
                None
                if self.checkpoint_evidence_id is None
                else str(self.checkpoint_evidence_id)
            ),
            "error_code": self.error_code,
            "occurred_at": self.occurred_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> ApprovalRetryAttempt:
        if set(value) != {
            "attempt",
            "checkpoint_evidence_id",
            "error_code",
            "occurred_at",
        }:
            raise ApprovalConflictError("stored retry history is invalid")
        checkpoint_value = value["checkpoint_evidence_id"]
        try:
            checkpoint = (
                None
                if checkpoint_value is None
                else UUID(cast(str, checkpoint_value))
            )
            return cls(
                attempt=cast(int, value["attempt"]),
                error_code=cast(str, value["error_code"]),
                occurred_at=datetime.fromisoformat(
                    cast(str, value["occurred_at"])
                ),
                checkpoint_evidence_id=checkpoint,
            )
        except (TypeError, ValueError, InvalidApprovalError):
            raise ApprovalConflictError(
                "stored retry history is invalid"
            ) from None


@dataclass(frozen=True, slots=True)
class ApprovalRequestResult:
    task_id: UUID
    request_id: UUID
    status: ApprovalStatus
    task_state: TaskState
    transition_event_id: UUID
    audit_event_id: UUID
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class ApprovalDecisionResult:
    task_id: UUID
    request_id: UUID
    decision_id: UUID
    decision: ApprovalDecision
    status: ApprovalStatus
    task_state: TaskState
    transition_event_id: UUID
    audit_event_id: UUID
    replayed: bool = False


class ApprovalPreconditionEvaluator(Protocol):
    """Apply any adapter-specific checks after durable checks pass."""

    def recheck(
        self,
        session: Session,
        task: Task,
        request: ApprovalRequest,
        decision: ApprovalDecision,
        *,
        now: datetime,
    ) -> bool: ...


class DurableOnlyApprovalPreconditionEvaluator:
    """Use the service's exact durable recheck with no additional adapter."""

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
        return True


@dataclass(frozen=True, slots=True)
class _TransitionGates(TaskTransitionGateEvaluator):
    brief_approval_required: bool = False
    exact_brief_human_approval: bool = False
    brief_revision_request_id: UUID | None = None
    resume_decision_id: UUID | None = None

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
        return TaskTransitionGuards(
            brief_approval_required=self.brief_approval_required,
            exact_brief_human_approval=self.exact_brief_human_approval,
            brief_revision_request_id=self.brief_revision_request_id,
            resume_decision_id=self.resume_decision_id,
            resume_decision_current=self.resume_decision_id is not None,
            resume_preconditions_rechecked=self.resume_decision_id is not None,
        )


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _required_identifier(value: str, *, field: str, maximum: int = 255) -> str:
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > maximum
        or _IDENTIFIER.fullmatch(normalized) is None
        or "://" in normalized
        or "//" in normalized
        or ".." in normalized
        or normalized.startswith("/")
    ):
        raise InvalidApprovalError(f"{field} is invalid")
    return normalized


def _required_reason_code(value: str) -> str:
    normalized = value.strip().upper()
    if _REASON_CODE.fullmatch(normalized) is None:
        raise InvalidApprovalError("approval reason code is invalid")
    return normalized


def _fingerprint(value: Mapping[str, object]) -> str:
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    except (TypeError, ValueError):
        raise InvalidApprovalError("approval identity is invalid") from None
    return hashlib.sha256(payload).hexdigest()


def _evidence_ids(values: Sequence[UUID]) -> tuple[UUID, ...]:
    normalized = tuple(values)
    if (
        not normalized
        or len(normalized) > MAX_APPROVAL_EVIDENCE_REFERENCES
        or len(set(normalized)) != len(normalized)
    ):
        raise InvalidApprovalError("approval evidence references are invalid")
    return normalized


def _stored_evidence_ids(request: ApprovalRequest) -> tuple[UUID, ...]:
    try:
        values = tuple(
            UUID(cast(str, value))
            for value in request.supporting_evidence_ids
        )
    except (TypeError, ValueError):
        raise ApprovalConflictError(
            "stored approval evidence references are invalid"
        ) from None
    if (
        not values
        or len(values) > MAX_APPROVAL_EVIDENCE_REFERENCES
        or len(set(values)) != len(values)
    ):
        raise ApprovalConflictError(
            "stored approval evidence references are invalid"
        )
    return values


def _retry_history(
    values: Sequence[ApprovalRetryAttempt],
    *,
    request_type: ApprovalRequestType,
) -> tuple[ApprovalRetryAttempt, ...]:
    normalized = tuple(values)
    if len(normalized) > MAX_RETRY_HISTORY_ENTRIES:
        raise InvalidApprovalError("approval retry history is too large")
    attempts = tuple(entry.attempt for entry in normalized)
    if attempts != tuple(sorted(set(attempts))):
        raise InvalidApprovalError("approval retry history is invalid")
    if request_type is ApprovalRequestType.RETRY_LIMIT and not normalized:
        raise InvalidApprovalError(
            "retry-limit approval requires retry history"
        )
    if request_type is not ApprovalRequestType.RETRY_LIMIT and normalized:
        raise InvalidApprovalError(
            "retry history is only valid for a retry-limit approval"
        )
    return normalized


def _stored_retry_history(
    request: ApprovalRequest,
) -> tuple[ApprovalRetryAttempt, ...]:
    try:
        values = tuple(
            ApprovalRetryAttempt.from_dict(cast(Mapping[str, object], value))
            for value in request.retry_history
        )
    except (TypeError, ApprovalConflictError):
        raise ApprovalConflictError("stored retry history is invalid") from None
    attempts = tuple(entry.attempt for entry in values)
    if (
        len(values) > MAX_RETRY_HISTORY_ENTRIES
        or attempts != tuple(sorted(set(attempts)))
    ):
        raise ApprovalConflictError("stored retry history is invalid")
    return values


def _validate_request_shape(
    request_type: ApprovalRequestType,
    *,
    subject_type: str | None,
    subject_id: UUID | None,
    blocked_operation: BlockedOperation | None,
    retry_history: Sequence[ApprovalRetryAttempt],
) -> tuple[str, UUID | None]:
    if request_type is ApprovalRequestType.RETRY_LIMIT and not retry_history:
        raise InvalidApprovalError(
            "retry-limit approval requires retry history"
        )
    if request_type is not ApprovalRequestType.RETRY_LIMIT and retry_history:
        raise InvalidApprovalError(
            "retry history is only valid for a retry-limit approval"
        )
    if request_type is ApprovalRequestType.BRIEF:
        if (
            subject_type != "BRIEF"
            or subject_id is None
            or blocked_operation is not None
            or retry_history
        ):
            raise InvalidApprovalError("brief approval subject is invalid")
        return "BRIEF", subject_id
    if blocked_operation is None:
        raise InvalidApprovalError(
            "resumable approval requires a blocked operation"
        )
    if request_type is ApprovalRequestType.REVIEW_RULE:
        if subject_type != "RULE_CANDIDATE" or subject_id is None:
            raise InvalidApprovalError("review-rule approval subject is invalid")
        return "RULE_CANDIDATE", subject_id
    if subject_type != "BLOCKED_OPERATION" or subject_id is not None:
        raise InvalidApprovalError("approval subject is invalid")
    return "BLOCKED_OPERATION", None


def _precondition_identity(
    *,
    task_id: UUID,
    request_type: ApprovalRequestType,
    requesting_state: TaskState,
    resume_state: TaskState | None,
    subject_type: str,
    subject_id: UUID | None,
    blocked_operation: BlockedOperation | None,
    retry_history: Sequence[ApprovalRetryAttempt],
) -> dict[str, object]:
    return {
        "blocked_operation": (
            None if blocked_operation is None else blocked_operation.to_dict()
        ),
        "request_type": request_type.value,
        "requesting_state": requesting_state.value,
        "resume_state": (
            None if resume_state is None else resume_state.value
        ),
        "retry_history": [entry.to_dict() for entry in retry_history],
        "subject_id": None if subject_id is None else str(subject_id),
        "subject_type": subject_type,
        "task_id": str(task_id),
    }


def _request_fingerprint(
    *,
    precondition_fingerprint: str,
    reason_code: str,
    options: Sequence[ApprovalDecision],
    evidence_ids: Sequence[UUID],
    expires_at: datetime,
) -> str:
    return _fingerprint(
        {
            "evidence_ids": [str(value) for value in evidence_ids],
            "expires_at": _as_utc(expires_at).isoformat(),
            "options": [value.value for value in options],
            "precondition_fingerprint": precondition_fingerprint,
            "reason_code": reason_code,
        }
    )


def _decision_fingerprint(
    *,
    request_id: UUID,
    decision_id: UUID,
    decision: ApprovalDecision,
    actor_id: str,
    evidence_ids: Sequence[UUID],
) -> str:
    return _fingerprint(
        {
            "actor_id": actor_id,
            "decision": decision.value,
            "decision_evidence_ids": [str(value) for value in evidence_ids],
            "decision_id": str(decision_id),
            "request_id": str(request_id),
        }
    )


def _begin_serialized(session: Session) -> None:
    if session.get_bind().dialect.name == "sqlite":
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")


def _next_event_sequence(session: Session, task_id: UUID) -> int:
    current = session.scalar(
        select(func.max(TaskEvent.sequence)).where(
            TaskEvent.task_id == task_id
        )
    )
    return int(current or 0) + 1


def _append_approval_event(
    session: Session,
    *,
    task: Task,
    request: ApprovalRequest,
    event_type: str,
    actor_id: str,
    evidence_ids: Sequence[UUID],
    occurred_at: datetime,
) -> TaskEvent:
    blocked_operation = _stored_blocked_operation(request)
    event = TaskEvent(
        task_id=task.id,
        sequence=_next_event_sequence(session, task.id),
        event_type=event_type,
        payload={
            "approval_request_id": str(request.id),
            "blocked_operation": (
                None
                if blocked_operation is None
                else {
                    "input_fingerprint": blocked_operation.input_fingerprint,
                    "operation_name": blocked_operation.operation_name,
                }
            ),
            "decision": request.decision,
            "expires_at": (
                None
                if request.expires_at is None
                else _as_utc(request.expires_at).isoformat()
            ),
            "precondition_fingerprint": request.precondition_fingerprint,
            "request_type": request.request_type,
            "resume_state": (
                None
                if request.resume_state is None
                else TaskState(request.resume_state).value
            ),
            "schema_version": APPROVAL_EVENT_SCHEMA_VERSION,
            "status": ApprovalStatus(request.status).value,
            "subject_id": (
                None if request.subject_id is None else str(request.subject_id)
            ),
            "subject_type": request.subject_type,
        },
        occurred_at=occurred_at,
        owner_id=task.owner_id,
        actor_id=actor_id,
        root_correlation_id=task.root_correlation_id,
        causation_id=request.id,
        parent_correlation_id=task.id,
    )
    session.add(event)
    session.flush()
    records = {
        record.id: record
        for record in session.scalars(
            select(EvidenceRecord).where(EvidenceRecord.id.in_(evidence_ids))
        )
    }
    if len(records) != len(evidence_ids):
        raise ApprovalConflictError("approval evidence is unavailable")
    for position, evidence_id in enumerate(evidence_ids, start=1):
        session.add(
            TaskEventEvidenceReference(
                task_id=task.id,
                task_event_id=event.id,
                evidence_id=evidence_id,
                position=position,
                owner_id=task.owner_id,
                actor_id=actor_id,
                root_correlation_id=task.root_correlation_id,
                causation_id=event.id,
                parent_correlation_id=task.id,
            )
        )
    session.flush()
    return event


def _request_type(request: ApprovalRequest) -> ApprovalRequestType:
    try:
        return ApprovalRequestType(request.request_type)
    except ValueError:
        raise ApprovalConflictError(
            "stored approval request type is invalid"
        ) from None


def _stored_blocked_operation(
    request: ApprovalRequest,
) -> BlockedOperation | None:
    if request.blocked_operation is None:
        return None
    if not isinstance(request.blocked_operation, dict):
        raise ApprovalConflictError("stored blocked operation is invalid")
    return BlockedOperation.from_dict(request.blocked_operation)


def _durable_preconditions_are_current(
    session: Session,
    task: Task,
    request: ApprovalRequest,
) -> bool:
    request_type = _request_type(request)
    blocked_operation = _stored_blocked_operation(request)
    retry_history = _stored_retry_history(request)
    subject_type, subject_id = _validate_request_shape(
        request_type,
        subject_type=request.subject_type,
        subject_id=request.subject_id,
        blocked_operation=blocked_operation,
        retry_history=retry_history,
    )
    precondition_fingerprint = _fingerprint(
        _precondition_identity(
            task_id=task.id,
            request_type=request_type,
            requesting_state=TaskState(request.requesting_state),
            resume_state=(
                None
                if request.resume_state is None
                else TaskState(request.resume_state)
            ),
            subject_type=subject_type,
            subject_id=subject_id,
            blocked_operation=blocked_operation,
            retry_history=retry_history,
        )
    )
    options = _REQUEST_OPTIONS[request_type]
    if request.expires_at is None:
        return False
    fingerprint = _request_fingerprint(
        precondition_fingerprint=precondition_fingerprint,
        reason_code=_required_reason_code(request.reason),
        options=options,
        evidence_ids=_stored_evidence_ids(request),
        expires_at=request.expires_at,
    )
    if (
        request.precondition_fingerprint != precondition_fingerprint
        or request.request_fingerprint != fingerprint
        or request.options != [value.value for value in options]
    ):
        return False
    if request_type is ApprovalRequestType.BRIEF:
        decision = session.scalar(
            select(BriefApprovalDecision)
            .where(
                BriefApprovalDecision.id
                == task.brief_approval_decision_id
            )
            .with_for_update()
        )
        brief = session.scalar(
            select(Brief)
            .where(Brief.id == request.subject_id)
            .with_for_update()
        )
        return bool(
            TaskState(task.state) is TaskState.BRIEF_PENDING_APPROVAL
            and request.resume_state is None
            and task.accepted_brief_id == request.subject_id
            and brief is not None
            and brief.task_id == task.id
            and decision is not None
            and decision.task_id == task.id
            and decision.brief_id == request.subject_id
            and decision.disposition
            is BriefDecisionDisposition.HUMAN_APPROVAL_REQUIRED
            and decision.human_response is None
        )
    if (
        TaskState(task.state) is not TaskState.ESCALATED
        or task.escalation_resume_state is None
        or request.resume_state is None
        or TaskState(task.escalation_resume_state)
        is not TaskState(request.resume_state)
    ):
        return False
    if request_type is ApprovalRequestType.REVIEW_RULE:
        candidate = session.scalar(
            select(RuleCandidate)
            .where(RuleCandidate.id == request.subject_id)
            .with_for_update()
        )
        return bool(
            candidate is not None
            and candidate.task_id == task.id
            and candidate.status is RuleCandidateStatus.EVALUATED
            and candidate.evaluation_result is not None
        )
    return True


def _decision_projection(
    request_type: ApprovalRequestType,
    decision: ApprovalDecision,
    *,
    decision_id: UUID,
) -> tuple[ApprovalStatus, TaskTransitionKind, _TransitionGates]:
    if decision is ApprovalDecision.CANCEL:
        return ApprovalStatus.CANCELLED, TaskTransitionKind.CANCEL, _TransitionGates()
    if decision is ApprovalDecision.EXPIRE:
        return ApprovalStatus.EXPIRED, TaskTransitionKind.FAIL, _TransitionGates()
    if request_type is ApprovalRequestType.BRIEF:
        if decision is ApprovalDecision.APPROVE:
            return (
                ApprovalStatus.APPROVED,
                TaskTransitionKind.APPROVE_EXACT_BRIEF,
                _TransitionGates(exact_brief_human_approval=True),
            )
        if decision is ApprovalDecision.REQUEST_REVISION:
            return (
                ApprovalStatus.REJECTED,
                TaskTransitionKind.REVISE_BRIEF,
                _TransitionGates(
                    brief_revision_request_id=decision_id,
                ),
            )
    if (
        request_type is ApprovalRequestType.REVIEW_RULE
        and decision is ApprovalDecision.REJECT
    ):
        return (
            ApprovalStatus.REJECTED,
            TaskTransitionKind.RESUME,
            _TransitionGates(resume_decision_id=decision_id),
        )
    if decision in _APPROVING_DECISIONS:
        return (
            ApprovalStatus.APPROVED,
            TaskTransitionKind.RESUME,
            _TransitionGates(resume_decision_id=decision_id),
        )
    if decision in {
        ApprovalDecision.DENY,
        ApprovalDecision.REJECT,
        ApprovalDecision.ABANDON,
    }:
        return ApprovalStatus.REJECTED, TaskTransitionKind.FAIL, _TransitionGates()
    raise InvalidApprovalError("approval decision is not supported")


class ApprovalService:
    """Atomically request, decide, expire, audit, and transition approvals."""

    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        *,
        precondition_evaluator: ApprovalPreconditionEvaluator | None = None,
        active_policy_lineage: str = "mvp",
        principal_id: str = "control-plane",
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._factory = factory
        self._artifact_store = artifact_store
        self._precondition_evaluator = (
            precondition_evaluator
            or DurableOnlyApprovalPreconditionEvaluator()
        )
        self._active_policy_lineage = _required_identifier(
            active_policy_lineage,
            field="approval policy lineage",
        )
        self._principal_id = _required_identifier(
            principal_id,
            field="approval principal",
        )
        self._clock = clock

    def request(
        self,
        task_id: UUID,
        *,
        request_id: UUID,
        expected_state: TaskState,
        request_type: ApprovalRequestType,
        reason_code: str,
        subject_type: str | None,
        subject_id: UUID | None,
        blocked_operation: BlockedOperation | None,
        retry_history: Sequence[ApprovalRetryAttempt] = (),
        evidence_ids: Sequence[UUID],
        expires_at: datetime,
    ) -> ApprovalRequestResult:
        normalized_reason = _required_reason_code(reason_code)
        normalized_evidence_ids = _evidence_ids(evidence_ids)
        normalized_expiry = _as_utc(expires_at)
        normalized_retry_history = _retry_history(
            retry_history,
            request_type=request_type,
        )
        checkpoint_evidence_ids = {
            entry.checkpoint_evidence_id
            for entry in normalized_retry_history
            if entry.checkpoint_evidence_id is not None
        }
        if (
            blocked_operation is not None
            and blocked_operation.checkpoint_evidence_id is not None
        ):
            checkpoint_evidence_ids.add(
                blocked_operation.checkpoint_evidence_id
            )
        if not checkpoint_evidence_ids.issubset(
            normalized_evidence_ids
        ):
            raise InvalidApprovalError(
                "checkpoint evidence must support the approval request"
            )
        normalized_subject_type, normalized_subject_id = _validate_request_shape(
            request_type,
            subject_type=subject_type,
            subject_id=subject_id,
            blocked_operation=blocked_operation,
            retry_history=normalized_retry_history,
        )
        resume_state = (
            None if request_type is ApprovalRequestType.BRIEF else expected_state
        )
        precondition_fingerprint = _fingerprint(
            _precondition_identity(
                task_id=task_id,
                request_type=request_type,
                requesting_state=expected_state,
                resume_state=resume_state,
                subject_type=normalized_subject_type,
                subject_id=normalized_subject_id,
                blocked_operation=blocked_operation,
                retry_history=normalized_retry_history,
            )
        )
        options = _REQUEST_OPTIONS[request_type]
        request_fingerprint = _request_fingerprint(
            precondition_fingerprint=precondition_fingerprint,
            reason_code=normalized_reason,
            options=options,
            evidence_ids=normalized_evidence_ids,
            expires_at=normalized_expiry,
        )
        try:
            with self._factory() as session, session.begin():
                _begin_serialized(session)
                task = session.scalar(
                    select(Task)
                    .where(Task.id == task_id)
                    .with_for_update()
                )
                if task is None:
                    raise ApprovalNotFoundError("task is unavailable")
                existing = session.get(ApprovalRequest, request_id)
                if existing is not None:
                    if (
                        existing.task_id != task_id
                        or existing.request_fingerprint
                        != request_fingerprint
                    ):
                        raise ApprovalConflictError(
                            "approval request id conflicts"
                        )
                    return ApprovalRequestResult(
                        task_id=task.id,
                        request_id=existing.id,
                        status=ApprovalStatus(existing.status),
                        task_state=TaskState(task.state),
                        transition_event_id=_transition_event_id(
                            session,
                            request_id,
                        ),
                        audit_event_id=_approval_audit_event_id(
                            session,
                            task.id,
                            request_id,
                            "APPROVAL_REQUESTED",
                        ),
                        replayed=True,
                    )
                now = _as_utc(self._clock())
                if (
                    normalized_expiry <= now
                    or normalized_expiry - now > MAX_APPROVAL_LIFETIME
                ):
                    raise InvalidApprovalError(
                        "approval expiration is invalid"
                    )
                if TaskState(task.state) is not expected_state:
                    raise ApprovalConflictError(
                        "task state no longer matches approval request"
                    )
                if session.scalar(
                    select(ApprovalRequest.id).where(
                        ApprovalRequest.task_id == task.id,
                        ApprovalRequest.status == ApprovalStatus.PENDING,
                    )
                ) is not None:
                    raise ApprovalConflictError(
                        "task already has a pending approval"
                    )
                self._validate_exact_subject(
                    session,
                    task,
                    request_type=request_type,
                    subject_id=normalized_subject_id,
                )
                request = ApprovalRequest(
                    id=request_id,
                    task_id=task.id,
                    request_type=request_type.value,
                    subject_type=normalized_subject_type,
                    subject_id=normalized_subject_id,
                    reason=normalized_reason,
                    options=[value.value for value in options],
                    supporting_evidence_ids=[
                        str(value) for value in normalized_evidence_ids
                    ],
                    requesting_state=expected_state,
                    expires_at=normalized_expiry,
                    status=ApprovalStatus.PENDING,
                    request_fingerprint=request_fingerprint,
                    precondition_fingerprint=precondition_fingerprint,
                    resume_state=resume_state,
                    blocked_operation=(
                        None
                        if blocked_operation is None
                        else blocked_operation.to_dict()
                    ),
                    retry_history=[
                        value.to_dict()
                        for value in normalized_retry_history
                    ],
                    owner_id=task.owner_id,
                    actor_id=self._principal_id,
                    root_correlation_id=task.root_correlation_id,
                    causation_id=task.id,
                    parent_correlation_id=task.parent_correlation_id,
                    created_at=now,
                    updated_at=now,
                )
                session.add(request)
                session.flush()
                transition_kind = (
                    TaskTransitionKind.REQUEST_BRIEF_APPROVAL
                    if request_type is ApprovalRequestType.BRIEF
                    else TaskTransitionKind.ESCALATE
                )
                transition = _transition_task(
                    session,
                    self._artifact_store,
                    task_id=task.id,
                    transition_id=request.id,
                    expected_state=expected_state,
                    kind=transition_kind,
                    reason_code=normalized_reason,
                    actor_id=self._principal_id,
                    evidence_ids=normalized_evidence_ids,
                    gate_evaluator=_TransitionGates(
                        brief_approval_required=(
                            request_type is ApprovalRequestType.BRIEF
                        )
                    ),
                    active_policy_lineage=self._active_policy_lineage,
                    occurred_at=now,
                )
                event = _append_approval_event(
                    session,
                    task=task,
                    request=request,
                    event_type="APPROVAL_REQUESTED",
                    actor_id=self._principal_id,
                    evidence_ids=normalized_evidence_ids,
                    occurred_at=now,
                )
                return ApprovalRequestResult(
                    task_id=task.id,
                    request_id=request.id,
                    status=ApprovalStatus.PENDING,
                    task_state=TaskState(task.state),
                    transition_event_id=transition.event_id,
                    audit_event_id=event.id,
                )
        except IntegrityError:
            raise ApprovalConflictError(
                "approval request conflicts with durable state"
            ) from None
        except TaskTransitionError as error:
            raise ApprovalConflictError(str(error)) from None

    def decide(
        self,
        request_id: UUID,
        *,
        decision_id: UUID,
        decision: ApprovalDecision,
        actor_id: str,
        evidence_ids: Sequence[UUID] = (),
    ) -> ApprovalDecisionResult:
        normalized_actor = _required_identifier(
            actor_id,
            field="approval actor",
        )
        decision_evidence_ids = tuple(evidence_ids)
        if (
            len(decision_evidence_ids) > MAX_APPROVAL_EVIDENCE_REFERENCES
            or len(set(decision_evidence_ids))
            != len(decision_evidence_ids)
        ):
            raise InvalidApprovalError(
                "decision evidence references are invalid"
            )
        try:
            with self._factory() as session, session.begin():
                _begin_serialized(session)
                request = session.scalar(
                    select(ApprovalRequest)
                    .where(ApprovalRequest.id == request_id)
                    .with_for_update()
                )
                if request is None:
                    raise ApprovalNotFoundError(
                        "approval request is unavailable"
                    )
                task = session.scalar(
                    select(Task)
                    .where(Task.id == request.task_id)
                    .with_for_update()
                )
                if task is None:
                    raise ApprovalNotFoundError("task is unavailable")
                now = _as_utc(self._clock())
                effective_decision = (
                    ApprovalDecision.EXPIRE
                    if (
                        request.decision == ApprovalDecision.EXPIRE.value
                        or (
                            request.status is ApprovalStatus.PENDING
                            and request.expires_at is not None
                            and _as_utc(request.expires_at) <= now
                        )
                    )
                    else decision
                )
                combined_evidence_ids = tuple(
                    dict.fromkeys(
                        (
                            *_stored_evidence_ids(request),
                            *decision_evidence_ids,
                        )
                    )
                )
                if (
                    len(combined_evidence_ids)
                    > MAX_APPROVAL_EVIDENCE_REFERENCES
                ):
                    raise InvalidApprovalError(
                        "combined approval evidence is too large"
                    )
                fingerprint = _decision_fingerprint(
                    request_id=request.id,
                    decision_id=decision_id,
                    decision=effective_decision,
                    actor_id=normalized_actor,
                    evidence_ids=decision_evidence_ids,
                )
                if request.status is not ApprovalStatus.PENDING:
                    if (
                        request.decision_id != decision_id
                        or request.decision_fingerprint != fingerprint
                        or request.decision != effective_decision.value
                    ):
                        raise ApprovalConflictError(
                            "approval request is already decided"
                        )
                    return ApprovalDecisionResult(
                        task_id=task.id,
                        request_id=request.id,
                        decision_id=decision_id,
                        decision=effective_decision,
                        status=ApprovalStatus(request.status),
                        task_state=TaskState(task.state),
                        transition_event_id=_transition_event_id(
                            session,
                            decision_id,
                        ),
                        audit_event_id=_approval_audit_event_id(
                            session,
                            task.id,
                            request.id,
                            _decision_event_type(effective_decision),
                        ),
                        replayed=True,
                    )
                if effective_decision is ApprovalDecision.EXPIRE:
                    if (
                        request.expires_at is None
                        or _as_utc(request.expires_at) > now
                    ):
                        raise InvalidApprovalError(
                            "approval request has not expired"
                        )
                elif effective_decision.value not in request.options:
                    raise InvalidApprovalError(
                        "approval decision is not an offered option"
                    )
                if session.scalar(
                    select(ApprovalRequest.id).where(
                        ApprovalRequest.decision_id == decision_id
                    )
                ) is not None:
                    raise ApprovalConflictError(
                        "approval decision id conflicts"
                    )
                request_type = _request_type(request)
                status, transition_kind, gates = _decision_projection(
                    request_type,
                    effective_decision,
                    decision_id=decision_id,
                )
                if effective_decision in _PRECONDITIONED_DECISIONS:
                    if (
                        not _durable_preconditions_are_current(
                            session,
                            task,
                            request,
                        )
                        or not self._precondition_evaluator.recheck(
                            session,
                            task,
                            request,
                            effective_decision,
                            now=now,
                        )
                    ):
                        raise ApprovalPreconditionError(
                            "approval preconditions changed"
                        )
                transition = _transition_task(
                    session,
                    self._artifact_store,
                    task_id=task.id,
                    transition_id=decision_id,
                    expected_state=(
                        TaskState.BRIEF_PENDING_APPROVAL
                        if request_type is ApprovalRequestType.BRIEF
                        else TaskState.ESCALATED
                    ),
                    kind=transition_kind,
                    reason_code=f"APPROVAL_{effective_decision.value}",
                    actor_id=normalized_actor,
                    evidence_ids=combined_evidence_ids,
                    gate_evaluator=gates,
                    active_policy_lineage=self._active_policy_lineage,
                    occurred_at=now,
                )
                request.status = status
                request.decision = effective_decision.value
                request.decision_id = decision_id
                request.decision_fingerprint = fingerprint
                request.decided_by = normalized_actor
                request.decided_at = now
                request.actor_id = normalized_actor
                request.updated_at = now
                self._project_subject_decision(
                    session,
                    task,
                    request,
                    decision=effective_decision,
                    actor_id=normalized_actor,
                    decided_at=now,
                )
                session.flush()
                event = _append_approval_event(
                    session,
                    task=task,
                    request=request,
                    event_type=_decision_event_type(effective_decision),
                    actor_id=normalized_actor,
                    evidence_ids=combined_evidence_ids,
                    occurred_at=now,
                )
                return ApprovalDecisionResult(
                    task_id=task.id,
                    request_id=request.id,
                    decision_id=decision_id,
                    decision=effective_decision,
                    status=status,
                    task_state=TaskState(task.state),
                    transition_event_id=transition.event_id,
                    audit_event_id=event.id,
                )
        except IntegrityError:
            raise ApprovalConflictError(
                "approval decision conflicts with durable state"
            ) from None
        except TaskTransitionError as error:
            raise ApprovalConflictError(str(error)) from None

    def expire_due(self, *, limit: int = 100) -> tuple[ApprovalDecisionResult, ...]:
        if not 1 <= limit <= 1000:
            raise InvalidApprovalError("approval expiry limit is invalid")
        now = _as_utc(self._clock())
        with self._factory() as session:
            request_rows = tuple(
                session.execute(
                    select(ApprovalRequest.id, ApprovalRequest.expires_at)
                    .where(
                        ApprovalRequest.status == ApprovalStatus.PENDING,
                        ApprovalRequest.expires_at.is_not(None),
                        ApprovalRequest.expires_at <= now,
                        ApprovalRequest.request_fingerprint
                        != _UNINITIALIZED_FINGERPRINT,
                        ApprovalRequest.precondition_fingerprint
                        != _UNINITIALIZED_FINGERPRINT,
                    )
                    .order_by(
                        ApprovalRequest.expires_at,
                        ApprovalRequest.id,
                    )
                    .limit(limit)
                )
            )
        results: list[ApprovalDecisionResult] = []
        for request_id, expires_at in request_rows:
            if expires_at is None:
                continue
            decision_id = uuid5(
                NAMESPACE_URL,
                f"mathews:approval-expiry:{request_id}:{_as_utc(expires_at).isoformat()}",
            )
            results.append(
                self.decide(
                    request_id,
                    decision_id=decision_id,
                    decision=ApprovalDecision.EXPIRE,
                    actor_id=self._principal_id,
                )
            )
        return tuple(results)

    @staticmethod
    def _validate_exact_subject(
        session: Session,
        task: Task,
        *,
        request_type: ApprovalRequestType,
        subject_id: UUID | None,
    ) -> None:
        if request_type is ApprovalRequestType.BRIEF:
            brief = session.scalar(
                select(Brief)
                .where(Brief.id == subject_id)
                .with_for_update()
            )
            decision = session.scalar(
                select(BriefApprovalDecision)
                .where(
                    BriefApprovalDecision.id
                    == task.brief_approval_decision_id
                )
                .with_for_update()
            )
            if (
                brief is None
                or brief.task_id != task.id
                or task.accepted_brief_id != subject_id
                or decision is None
                or decision.task_id != task.id
                or decision.brief_id != subject_id
                or decision.disposition
                is not BriefDecisionDisposition.HUMAN_APPROVAL_REQUIRED
                or decision.human_response is not None
            ):
                raise ApprovalNotFoundError(
                    "exact brief approval subject is unavailable"
                )
        elif request_type is ApprovalRequestType.REVIEW_RULE:
            candidate = session.scalar(
                select(RuleCandidate)
                .where(RuleCandidate.id == subject_id)
                .with_for_update()
            )
            if (
                candidate is None
                or candidate.task_id != task.id
                or candidate.status is not RuleCandidateStatus.EVALUATED
                or candidate.evaluation_result is None
            ):
                raise ApprovalNotFoundError(
                    "evaluated rule candidate is unavailable"
                )

    @staticmethod
    def _project_subject_decision(
        session: Session,
        task: Task,
        request: ApprovalRequest,
        *,
        decision: ApprovalDecision,
        actor_id: str,
        decided_at: datetime,
    ) -> None:
        request_type = _request_type(request)
        if request_type is ApprovalRequestType.BRIEF:
            brief_decision = session.scalar(
                select(BriefApprovalDecision)
                .where(
                    BriefApprovalDecision.id
                    == task.brief_approval_decision_id
                )
                .with_for_update()
            )
            if (
                brief_decision is None
                or brief_decision.task_id != task.id
                or brief_decision.brief_id != request.subject_id
                or brief_decision.disposition
                is not BriefDecisionDisposition.HUMAN_APPROVAL_REQUIRED
                or brief_decision.human_response is not None
            ):
                raise ApprovalConflictError(
                    "exact brief approval subject is unavailable"
                )
            brief_decision.human_response = decision.value
            brief_decision.decided_at = decided_at
            brief_decision.actor_id = actor_id
            brief_decision.updated_at = decided_at
        elif request_type is ApprovalRequestType.REVIEW_RULE:
            if decision not in {
                ApprovalDecision.APPROVE,
                ApprovalDecision.REJECT,
            }:
                return
            candidate = session.scalar(
                select(RuleCandidate)
                .where(RuleCandidate.id == request.subject_id)
                .with_for_update()
            )
            if (
                candidate is None
                or candidate.task_id != task.id
                or candidate.status is not RuleCandidateStatus.EVALUATED
                or candidate.evaluation_result is None
            ):
                raise ApprovalConflictError(
                    "evaluated rule candidate is unavailable"
                )
            candidate.status = (
                RuleCandidateStatus.APPROVED
                if decision is ApprovalDecision.APPROVE
                else RuleCandidateStatus.REJECTED
            )
            candidate.actor_id = actor_id
            candidate.updated_at = decided_at


def _decision_event_type(decision: ApprovalDecision) -> str:
    return (
        "APPROVAL_EXPIRED"
        if decision is ApprovalDecision.EXPIRE
        else "APPROVAL_DECIDED"
    )


def _approval_audit_event_id(
    session: Session,
    task_id: UUID,
    request_id: UUID,
    event_type: str,
) -> UUID:
    events = session.scalars(
        select(TaskEvent).where(
            TaskEvent.task_id == task_id,
            TaskEvent.event_type == event_type,
        )
    )
    for event in events:
        if event.payload.get("approval_request_id") == str(request_id):
            return event.id
    raise ApprovalConflictError("approval audit event is unavailable")


def _transition_event_id(session: Session, transition_id: UUID) -> UUID:
    event_id = session.scalar(
        select(TaskEvent.id).where(
            TaskEvent.transition_id == transition_id
        )
    )
    if event_id is None:
        raise ApprovalConflictError(
            "approval transition event is unavailable"
        )
    return event_id
