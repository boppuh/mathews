"""Durable human approvals and exact-state resumable escalation."""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal, Protocol, cast
from uuid import NAMESPACE_URL, UUID, uuid5

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.authentication import (
    AuthenticatedSession,
    require_authenticated_session,
)
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalRequestType,
    ApprovalStatus,
    BackgroundJob,
    BackgroundJobStatus,
    Brief,
    BriefApprovalDecision,
    BriefDecisionDisposition,
    DependencyOutageAttempt,
    EvidenceRecord,
    PolicyVersion,
    PolicyVersionPromptTemplate,
    PolicyVersionReviewRule,
    ReviewRule,
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
MAX_APPROVAL_DECISION_BYTES = 4 * 1024
MAX_RULE_PROPOSED_CHARACTERS = 10_000
MAX_RULE_RECURRENCE_CHARACTERS = 2_000
MAX_INBOX_JSON_DEPTH = 10
MAX_INBOX_JSON_COLLECTION_ITEMS = 100
MAX_INBOX_JSON_KEY_CHARACTERS = 255
_UNINITIALIZED_FINGERPRINT = "0" * 64

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]*\Z")
_OPERATION_NAME = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,4}\Z")
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
_REQUEST_TYPE_LABELS: Mapping[ApprovalRequestType, str] = {
    ApprovalRequestType.BRIEF: "Brief approval",
    ApprovalRequestType.UNSAFE_ACTION: "Unsafe action",
    ApprovalRequestType.RETRY_LIMIT: "Retry limit",
    ApprovalRequestType.REVIEW_CONFLICT: "One-off repair",
    ApprovalRequestType.REVIEW_RULE: "Review rule",
}
_APPROVING_DECISIONS = frozenset(
    {
        ApprovalDecision.APPROVE,
        ApprovalDecision.RETRY,
    }
)
_PRECONDITIONED_DECISIONS = _APPROVING_DECISIONS | {
    ApprovalDecision.REJECT,
    ApprovalDecision.REQUEST_REVISION,
}
_LOGGER = logging.getLogger(__name__)
_LOCAL_USER_ID = 1
_LOCAL_OWNER_ID = "local-user"
AuthenticatedApprovalSession = Annotated[
    AuthenticatedSession,
    Depends(require_authenticated_session),
]
PublicApprovalDecision = Literal[
    "APPROVE",
    "REQUEST_REVISION",
    "RETRY",
    "DENY",
    "REJECT",
    "ABANDON",
    "CANCEL",
]


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


class ApprovalRecentPasswordRequiredError(ApprovalError):
    """The requested human decision requires recent password verification."""


class ApprovalTaskSummary(BaseModel):
    id: UUID
    summary: str
    repository: str
    cockpit_path: str


class BriefInboxItem(BaseModel):
    id: UUID
    version: int
    scope: dict[str, object]
    exclusions: list[object]
    acceptance_criteria: list[object]
    risks: list[object]
    affected_flow: dict[str, object]
    test_plan: list[object]


class ApprovalInboxItem(BaseModel):
    id: UUID
    task: ApprovalTaskSummary
    request_type: Literal[
        "BRIEF",
        "UNSAFE_ACTION",
        "RETRY_LIMIT",
        "REVIEW_CONFLICT",
        "REVIEW_RULE",
    ]
    type_label: str
    reason_code: str
    options: list[PublicApprovalDecision]
    requesting_state: TaskState
    resume_state: TaskState | None = None
    created_at: datetime
    expires_at: datetime | None = None
    operation_name: str | None = None
    operation_fingerprint: str | None = None
    operation_idempotency_key: str | None = None
    operation_checkpoint_evidence_id: UUID | None = None
    brief: BriefInboxItem | None = None
    supporting_evidence_ids: list[UUID]
    actionable: bool = True
    unavailable_reason: Literal["RULE_CANDIDATE_UNAVAILABLE"] | None = None


class RuleInboxItem(BaseModel):
    candidate_id: UUID
    approval_request_id: UUID
    task: ApprovalTaskSummary
    proposed_rule: str
    recurrence_assessment: str
    severity_assessment: str
    false_positive_risks: list[str]
    cited_evidence_ids: list[UUID]
    lineage_key: str
    permitted_action: str
    risk_class: str
    scope: dict[str, object]
    matcher: dict[str, object]
    evidence_requirements: list[str]


class ApprovalInboxResponse(BaseModel):
    approvals: list[ApprovalInboxItem]
    rule_candidates: list[RuleInboxItem]


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    decision: PublicApprovalDecision


class ApprovalDecisionResponse(BaseModel):
    request_id: UUID
    decision: PublicApprovalDecision
    status: ApprovalStatus
    task_id: UUID
    task_state: TaskState
    audit_event_id: UUID


@dataclass(frozen=True, slots=True)
class _EvaluatedReviewRule:
    lineage_key: str
    scope: dict[str, object]
    matcher: dict[str, object]
    permitted_action: str
    risk_class: str
    evidence_requirements: list[str]


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
            raise InvalidApprovalError("blocked operation idempotency key is invalid")
        if _HEX_DIGEST.fullmatch(self.input_fingerprint) is None:
            raise InvalidApprovalError("blocked operation fingerprint is invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "checkpoint_evidence_id": (
                None if self.checkpoint_evidence_id is None else str(self.checkpoint_evidence_id)
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
            checkpoint = None if checkpoint_value is None else UUID(cast(str, checkpoint_value))
            return cls(
                operation_name=cast(str, value["operation_name"]),
                idempotency_key=cast(str, value["idempotency_key"]),
                input_fingerprint=cast(str, value["input_fingerprint"]),
                checkpoint_evidence_id=checkpoint,
            )
        except (TypeError, ValueError, InvalidApprovalError):
            raise ApprovalConflictError("stored blocked operation is invalid") from None


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
                None if self.checkpoint_evidence_id is None else str(self.checkpoint_evidence_id)
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
            checkpoint = None if checkpoint_value is None else UUID(cast(str, checkpoint_value))
            return cls(
                attempt=cast(int, value["attempt"]),
                error_code=cast(str, value["error_code"]),
                occurred_at=datetime.fromisoformat(cast(str, value["occurred_at"])),
                checkpoint_evidence_id=checkpoint,
            )
        except (TypeError, ValueError, InvalidApprovalError):
            raise ApprovalConflictError("stored retry history is invalid") from None


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
    expected_policy_version_id: UUID | None = None

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
        if (
            self.expected_policy_version_id is not None
            and policy.id != self.expected_policy_version_id
        ):
            return TaskTransitionGuards()
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
        values = tuple(UUID(cast(str, value)) for value in request.supporting_evidence_ids)
    except (TypeError, ValueError):
        raise ApprovalConflictError("stored approval evidence references are invalid") from None
    if (
        not values
        or len(values) > MAX_APPROVAL_EVIDENCE_REFERENCES
        or len(set(values)) != len(values)
    ):
        raise ApprovalConflictError("stored approval evidence references are invalid")
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
        raise InvalidApprovalError("retry-limit approval requires retry history")
    if request_type is not ApprovalRequestType.RETRY_LIMIT and normalized:
        raise InvalidApprovalError("retry history is only valid for a retry-limit approval")
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
    if len(values) > MAX_RETRY_HISTORY_ENTRIES or attempts != tuple(sorted(set(attempts))):
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
        raise InvalidApprovalError("retry-limit approval requires retry history")
    if request_type is not ApprovalRequestType.RETRY_LIMIT and retry_history:
        raise InvalidApprovalError("retry history is only valid for a retry-limit approval")
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
        raise InvalidApprovalError("resumable approval requires a blocked operation")
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
    subject_fingerprint: str | None,
) -> dict[str, object]:
    return {
        "blocked_operation": (None if blocked_operation is None else blocked_operation.to_dict()),
        "request_type": request_type.value,
        "requesting_state": requesting_state.value,
        "resume_state": (None if resume_state is None else resume_state.value),
        "retry_history": [entry.to_dict() for entry in retry_history],
        "subject_id": None if subject_id is None else str(subject_id),
        "subject_fingerprint": subject_fingerprint,
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
        select(func.max(TaskEvent.sequence)).where(TaskEvent.task_id == task_id)
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
                None if request.expires_at is None else _as_utc(request.expires_at).isoformat()
            ),
            "precondition_fingerprint": request.precondition_fingerprint,
            "request_type": request.request_type,
            "resume_state": (
                None if request.resume_state is None else TaskState(request.resume_state).value
            ),
            "schema_version": APPROVAL_EVENT_SCHEMA_VERSION,
            "status": ApprovalStatus(request.status).value,
            "subject_id": (None if request.subject_id is None else str(request.subject_id)),
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
        raise ApprovalConflictError("stored approval request type is invalid") from None


def _stored_blocked_operation(
    request: ApprovalRequest,
) -> BlockedOperation | None:
    if request.blocked_operation is None:
        return None
    if not isinstance(request.blocked_operation, dict):
        raise ApprovalConflictError("stored blocked operation is invalid")
    return BlockedOperation.from_dict(request.blocked_operation)


def _validate_inbox_json(value: object, *, depth: int = 0) -> None:
    if depth > MAX_INBOX_JSON_DEPTH:
        raise ApprovalConflictError("evaluated rule candidate is invalid")
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(value, float) and not math.isfinite(value):
            raise ApprovalConflictError("evaluated rule candidate is invalid")
        return
    if isinstance(value, list):
        if len(value) > MAX_INBOX_JSON_COLLECTION_ITEMS:
            raise ApprovalConflictError("evaluated rule candidate is invalid")
        for item in value:
            _validate_inbox_json(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if not value or len(value) > MAX_INBOX_JSON_COLLECTION_ITEMS:
            raise ApprovalConflictError("evaluated rule candidate is invalid")
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > MAX_INBOX_JSON_KEY_CHARACTERS:
                raise ApprovalConflictError("evaluated rule candidate is invalid")
            _validate_inbox_json(item, depth=depth + 1)
        return
    raise ApprovalConflictError("evaluated rule candidate is invalid")


def _evaluated_review_rule(candidate: RuleCandidate) -> _EvaluatedReviewRule:
    evaluation = candidate.evaluation_result
    if (
        not isinstance(evaluation, dict)
        or set(evaluation) != {"passed", "review_rule"}
        or evaluation.get("passed") is not True
    ):
        raise ApprovalConflictError("evaluated rule candidate is invalid")
    value = evaluation.get("review_rule")
    expected = {
        "lineage_key",
        "scope",
        "matcher",
        "permitted_action",
        "risk_class",
        "evidence_requirements",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ApprovalConflictError("evaluated rule candidate is invalid")
    scope = value.get("scope")
    matcher = value.get("matcher")
    raw_requirements = value.get("evidence_requirements")
    if (
        not isinstance(scope, dict)
        or not scope
        or not isinstance(matcher, dict)
        or not matcher
        or not isinstance(raw_requirements, list)
        or not raw_requirements
        or len(raw_requirements) > 100
        or any(
            not isinstance(item, str) or not item.strip() or len(item) > 255
            for item in raw_requirements
        )
    ):
        raise ApprovalConflictError("evaluated rule candidate is invalid")
    requirements = [item.strip() for item in raw_requirements]
    if len(set(requirements)) != len(requirements):
        raise ApprovalConflictError("evaluated rule candidate is invalid")
    try:
        lineage_key = _required_identifier(
            cast(str, value.get("lineage_key")),
            field="review rule lineage",
        )
        permitted_action = _required_identifier(
            cast(str, value.get("permitted_action")),
            field="review rule action",
        )
        risk_class = _required_identifier(
            cast(str, value.get("risk_class")),
            field="review rule risk class",
            maximum=100,
        )
        _validate_inbox_json(scope)
        _validate_inbox_json(matcher)
        _fingerprint({"matcher": matcher, "scope": scope})
    except (TypeError, InvalidApprovalError):
        raise ApprovalConflictError("evaluated rule candidate is invalid") from None
    return _EvaluatedReviewRule(
        lineage_key=lineage_key,
        scope=scope,
        matcher=matcher,
        permitted_action=permitted_action,
        risk_class=risk_class,
        evidence_requirements=requirements,
    )


def _stored_string_list(
    value: object,
    *,
    field: str,
    maximum: int = 100,
) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > maximum
        or any(not isinstance(item, str) or not item.strip() or len(item) > 500 for item in value)
    ):
        raise ApprovalConflictError(f"stored {field} is invalid")
    return [cast(str, item).strip() for item in value]


def _candidate_evidence_ids(
    session: Session,
    task: Task,
    candidate: RuleCandidate,
) -> tuple[UUID, ...]:
    try:
        values = tuple(UUID(cast(str, value)) for value in candidate.cited_evidence_ids)
    except (TypeError, ValueError):
        raise ApprovalConflictError("stored rule candidate evidence is invalid") from None
    if (
        not values
        or len(values) > MAX_APPROVAL_EVIDENCE_REFERENCES
        or len(set(values)) != len(values)
    ):
        raise ApprovalConflictError("stored rule candidate evidence is invalid")
    records = session.scalars(
        select(EvidenceRecord).where(
            EvidenceRecord.id.in_(values),
            EvidenceRecord.task_id == task.id,
            EvidenceRecord.owner_id == task.owner_id,
            EvidenceRecord.deleted_at.is_(None),
        )
    ).all()
    if len(records) != len(values):
        raise ApprovalConflictError("rule candidate evidence is unavailable")
    return values


def _validated_rule_candidate(
    session: Session,
    task: Task,
    candidate: RuleCandidate,
) -> tuple[_EvaluatedReviewRule, tuple[UUID, ...], str]:
    if (
        not isinstance(candidate.proposed_rule, str)
        or not candidate.proposed_rule.strip()
        or len(candidate.proposed_rule) > MAX_RULE_PROPOSED_CHARACTERS
        or not isinstance(candidate.recurrence_assessment, str)
        or not candidate.recurrence_assessment.strip()
        or len(candidate.recurrence_assessment) > MAX_RULE_RECURRENCE_CHARACTERS
        or not isinstance(candidate.severity_assessment, str)
        or not candidate.severity_assessment.strip()
        or len(candidate.severity_assessment) > 100
    ):
        raise ApprovalConflictError("evaluated rule candidate is invalid")
    false_positive_risks = _stored_string_list(
        candidate.false_positive_risks,
        field="rule candidate risks",
    )
    rule = _evaluated_review_rule(candidate)
    cited_evidence_ids = _candidate_evidence_ids(session, task, candidate)
    try:
        fingerprint = _fingerprint(
            {
                "candidate_id": str(candidate.id),
                "cited_evidence_ids": [str(value) for value in cited_evidence_ids],
                "false_positive_risks": false_positive_risks,
                "proposed_rule": candidate.proposed_rule,
                "recurrence_assessment": candidate.recurrence_assessment,
                "review_rule": {
                    "evidence_requirements": rule.evidence_requirements,
                    "lineage_key": rule.lineage_key,
                    "matcher": rule.matcher,
                    "permitted_action": rule.permitted_action,
                    "risk_class": rule.risk_class,
                    "scope": rule.scope,
                },
                "severity_assessment": candidate.severity_assessment,
            }
        )
    except InvalidApprovalError:
        raise ApprovalConflictError("evaluated rule candidate is invalid") from None
    return rule, cited_evidence_ids, fingerprint


def _brief_fingerprint(brief: Brief) -> str:
    try:
        for value in (
            brief.scope,
            brief.exclusions,
            brief.acceptance_criteria,
            brief.risks,
            brief.affected_flow,
            brief.test_plan,
        ):
            _validate_inbox_json(value)
        return _fingerprint(
            {
                "acceptance_criteria": brief.acceptance_criteria,
                "affected_flow": brief.affected_flow,
                "exclusions": brief.exclusions,
                "id": str(brief.id),
                "predecessor_id": (
                    None if brief.predecessor_id is None else str(brief.predecessor_id)
                ),
                "risks": brief.risks,
                "scope": brief.scope,
                "test_plan": brief.test_plan,
                "version": brief.version,
            }
        )
    except (ApprovalConflictError, InvalidApprovalError):
        raise ApprovalConflictError("stored brief is invalid") from None


def _approval_principal(authentication: AuthenticatedSession) -> str:
    if authentication.user_id != _LOCAL_USER_ID:
        raise ApprovalNotFoundError("approval inbox is unavailable")
    return _LOCAL_OWNER_ID


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
    stored_evidence_ids = _stored_evidence_ids(request)
    brief: Brief | None = None
    candidate: RuleCandidate | None = None
    subject_fingerprint: str | None = None
    if request_type is ApprovalRequestType.BRIEF:
        brief = session.scalar(
            select(Brief).where(Brief.id == request.subject_id).with_for_update()
        )
        if brief is None or brief.task_id != task.id or brief.owner_id != task.owner_id:
            return False
        try:
            subject_fingerprint = _brief_fingerprint(brief)
        except ApprovalConflictError:
            return False
    elif request_type is ApprovalRequestType.REVIEW_RULE:
        candidate = session.scalar(
            select(RuleCandidate).where(RuleCandidate.id == request.subject_id).with_for_update()
        )
        if not (
            candidate is not None
            and candidate.task_id == task.id
            and candidate.owner_id == task.owner_id
            and candidate.status is RuleCandidateStatus.EVALUATED
            and candidate.evaluation_result is not None
        ):
            return False
        try:
            _rule, cited_evidence_ids, subject_fingerprint = _validated_rule_candidate(
                session,
                task,
                candidate,
            )
        except ApprovalConflictError:
            return False
        if not set(cited_evidence_ids).issubset(stored_evidence_ids):
            return False
    precondition_fingerprint = _fingerprint(
        _precondition_identity(
            task_id=task.id,
            request_type=request_type,
            requesting_state=TaskState(request.requesting_state),
            resume_state=(
                None if request.resume_state is None else TaskState(request.resume_state)
            ),
            subject_type=subject_type,
            subject_id=subject_id,
            blocked_operation=blocked_operation,
            retry_history=retry_history,
            subject_fingerprint=subject_fingerprint,
        )
    )
    options = _REQUEST_OPTIONS[request_type]
    if request.expires_at is None:
        return False
    fingerprint = _request_fingerprint(
        precondition_fingerprint=precondition_fingerprint,
        reason_code=_required_reason_code(request.reason),
        options=options,
        evidence_ids=stored_evidence_ids,
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
            .where(BriefApprovalDecision.id == task.brief_approval_decision_id)
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
            and decision.disposition is BriefDecisionDisposition.HUMAN_APPROVAL_REQUIRED
            and decision.human_response is None
        )
    if (
        TaskState(task.state) is not TaskState.ESCALATED
        or task.escalation_resume_state is None
        or request.resume_state is None
        or TaskState(task.escalation_resume_state) is not TaskState(request.resume_state)
    ):
        return False
    if request_type is ApprovalRequestType.REVIEW_RULE:
        return candidate is not None
    if (
        request_type is ApprovalRequestType.RETRY_LIMIT
        and blocked_operation is not None
        and blocked_operation.operation_name.startswith("dependency.")
    ):
        outage = session.scalar(
            select(DependencyOutageAttempt)
            .where(
                DependencyOutageAttempt.approval_request_id == request.id,
                DependencyOutageAttempt.exhausted.is_(True),
                DependencyOutageAttempt.resolved_at.is_(None),
                DependencyOutageAttempt.checkpoint_evidence_id
                == blocked_operation.checkpoint_evidence_id,
            )
            .with_for_update()
        )
        if outage is None:
            return False
        job = session.scalar(
            select(BackgroundJob).where(BackgroundJob.id == outage.job_id).with_for_update()
        )
        return bool(
            job is not None
            and job.task_id == task.id
            and job.status is BackgroundJobStatus.FAILED
            and job.input_fingerprint == blocked_operation.input_fingerprint
            and blocked_operation.idempotency_key == f"outage:{job.id}:{outage.attempt}"
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
    if request_type is ApprovalRequestType.REVIEW_RULE and decision is ApprovalDecision.REJECT:
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
            precondition_evaluator or DurableOnlyApprovalPreconditionEvaluator()
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

    def inbox(
        self,
        authentication: AuthenticatedSession,
    ) -> ApprovalInboxResponse:
        owner_id = _approval_principal(authentication)
        while len(self.expire_due(limit=100)) == 100:
            pass
        now = _as_utc(self._clock())
        with self._factory() as session:
            rows = session.execute(
                select(ApprovalRequest, Task)
                .join(Task, Task.id == ApprovalRequest.task_id)
                .where(
                    ApprovalRequest.owner_id == owner_id,
                    Task.owner_id == owner_id,
                    ApprovalRequest.status == ApprovalStatus.PENDING,
                    or_(
                        ApprovalRequest.expires_at.is_(None),
                        ApprovalRequest.expires_at > now,
                    ),
                )
                .order_by(ApprovalRequest.created_at, ApprovalRequest.id)
                .limit(200)
            ).all()
            approvals: list[ApprovalInboxItem] = []
            rule_candidates: list[RuleInboxItem] = []
            for request, task in rows:
                request_type = _request_type(request)
                blocked_operation = _stored_blocked_operation(request)
                evidence_ids = list(_stored_evidence_ids(request))
                try:
                    options = cast(
                        list[PublicApprovalDecision],
                        [ApprovalDecision(cast(str, value)).value for value in request.options],
                    )
                except (TypeError, ValueError):
                    raise ApprovalConflictError("stored approval options are invalid") from None
                if options != [value.value for value in _REQUEST_OPTIONS[request_type]]:
                    raise ApprovalConflictError("stored approval options are invalid")
                task_summary = ApprovalTaskSummary(
                    id=task.id,
                    summary=task.summary,
                    repository=task.repository,
                    cockpit_path=f"/tasks/{task.id}",
                )
                brief_item: BriefInboxItem | None = None
                if request_type is ApprovalRequestType.BRIEF:
                    brief = session.scalar(
                        select(Brief).where(
                            Brief.id == request.subject_id,
                            Brief.task_id == task.id,
                            Brief.owner_id == owner_id,
                        )
                    )
                    if brief is None:
                        raise ApprovalConflictError("exact brief approval subject is unavailable")
                    _brief_fingerprint(brief)
                    brief_item = BriefInboxItem(
                        id=brief.id,
                        version=brief.version,
                        scope=brief.scope,
                        exclusions=brief.exclusions,
                        acceptance_criteria=brief.acceptance_criteria,
                        risks=brief.risks,
                        affected_flow=brief.affected_flow,
                        test_plan=brief.test_plan,
                    )
                approval_item = ApprovalInboxItem(
                    id=request.id,
                    task=task_summary,
                    request_type=request_type.value,
                    type_label=_REQUEST_TYPE_LABELS[request_type],
                    reason_code=_required_reason_code(request.reason),
                    options=options,
                    requesting_state=TaskState(request.requesting_state),
                    resume_state=(
                        None if request.resume_state is None else TaskState(request.resume_state)
                    ),
                    created_at=_as_utc(request.created_at),
                    expires_at=(
                        None if request.expires_at is None else _as_utc(request.expires_at)
                    ),
                    operation_name=(
                        None if blocked_operation is None else blocked_operation.operation_name
                    ),
                    operation_fingerprint=(
                        None if blocked_operation is None else blocked_operation.input_fingerprint
                    ),
                    operation_idempotency_key=(
                        None if blocked_operation is None else blocked_operation.idempotency_key
                    ),
                    operation_checkpoint_evidence_id=(
                        None
                        if blocked_operation is None
                        else blocked_operation.checkpoint_evidence_id
                    ),
                    brief=brief_item,
                    supporting_evidence_ids=evidence_ids,
                )
                approvals.append(approval_item)
                if request_type is not ApprovalRequestType.REVIEW_RULE:
                    continue
                candidate = session.scalar(
                    select(RuleCandidate).where(
                        RuleCandidate.id == request.subject_id,
                        RuleCandidate.task_id == task.id,
                        RuleCandidate.owner_id == owner_id,
                        RuleCandidate.status == RuleCandidateStatus.EVALUATED,
                    )
                )
                if candidate is None:
                    _LOGGER.warning(
                        "Skipped unavailable rule candidate for approval %s",
                        request.id,
                    )
                    approval_item.actionable = False
                    approval_item.unavailable_reason = "RULE_CANDIDATE_UNAVAILABLE"
                    continue
                try:
                    rule, stored_cited_evidence_ids, _candidate_fingerprint = (
                        _validated_rule_candidate(session, task, candidate)
                    )
                    cited_evidence_ids = list(stored_cited_evidence_ids)
                    if not set(cited_evidence_ids).issubset(evidence_ids):
                        raise ApprovalConflictError(
                            "rule candidate evidence is not bound to the approval"
                        )
                    if not _durable_preconditions_are_current(session, task, request):
                        raise ApprovalConflictError("rule candidate changed after escalation")
                except ApprovalConflictError:
                    _LOGGER.warning(
                        "Skipped invalid rule candidate for approval %s",
                        request.id,
                    )
                    approval_item.actionable = False
                    approval_item.unavailable_reason = "RULE_CANDIDATE_UNAVAILABLE"
                    continue
                rule_candidates.append(
                    RuleInboxItem(
                        candidate_id=candidate.id,
                        approval_request_id=request.id,
                        task=task_summary,
                        proposed_rule=candidate.proposed_rule,
                        recurrence_assessment=candidate.recurrence_assessment,
                        severity_assessment=candidate.severity_assessment,
                        false_positive_risks=_stored_string_list(
                            candidate.false_positive_risks,
                            field="rule candidate risks",
                        ),
                        cited_evidence_ids=cited_evidence_ids,
                        lineage_key=rule.lineage_key,
                        permitted_action=rule.permitted_action,
                        risk_class=rule.risk_class,
                        scope=rule.scope,
                        matcher=rule.matcher,
                        evidence_requirements=rule.evidence_requirements,
                    )
                )
            return ApprovalInboxResponse(
                approvals=approvals,
                rule_candidates=rule_candidates,
            )

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
        if blocked_operation is not None and blocked_operation.checkpoint_evidence_id is not None:
            checkpoint_evidence_ids.add(blocked_operation.checkpoint_evidence_id)
        if not checkpoint_evidence_ids.issubset(normalized_evidence_ids):
            raise InvalidApprovalError("checkpoint evidence must support the approval request")
        normalized_subject_type, normalized_subject_id = _validate_request_shape(
            request_type,
            subject_type=subject_type,
            subject_id=subject_id,
            blocked_operation=blocked_operation,
            retry_history=normalized_retry_history,
        )
        resume_state = None if request_type is ApprovalRequestType.BRIEF else expected_state
        options = _REQUEST_OPTIONS[request_type]
        try:
            with self._factory() as session, session.begin():
                _begin_serialized(session)
                task = session.scalar(select(Task).where(Task.id == task_id).with_for_update())
                if task is None:
                    raise ApprovalNotFoundError("task is unavailable")
                existing = session.get(ApprovalRequest, request_id)
                subject_fingerprint = self._validate_exact_subject(
                    session,
                    task,
                    request_type=request_type,
                    subject_id=normalized_subject_id,
                    evidence_ids=normalized_evidence_ids,
                    require_actionable=existing is None,
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
                        subject_fingerprint=subject_fingerprint,
                    )
                )
                request_fingerprint = _request_fingerprint(
                    precondition_fingerprint=precondition_fingerprint,
                    reason_code=normalized_reason,
                    options=options,
                    evidence_ids=normalized_evidence_ids,
                    expires_at=normalized_expiry,
                )
                if existing is not None:
                    if (
                        existing.task_id != task_id
                        or existing.request_fingerprint != request_fingerprint
                    ):
                        raise ApprovalConflictError("approval request id conflicts")
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
                if normalized_expiry <= now or normalized_expiry - now > MAX_APPROVAL_LIFETIME:
                    raise InvalidApprovalError("approval expiration is invalid")
                if TaskState(task.state) is not expected_state:
                    raise ApprovalConflictError("task state no longer matches approval request")
                if (
                    session.scalar(
                        select(ApprovalRequest.id).where(
                            ApprovalRequest.task_id == task.id,
                            ApprovalRequest.status == ApprovalStatus.PENDING,
                        )
                    )
                    is not None
                ):
                    raise ApprovalConflictError("task already has a pending approval")
                expected_policy_version_id: UUID | None = None
                if request_type is ApprovalRequestType.BRIEF:
                    exact_decision = session.scalar(
                        select(BriefApprovalDecision).where(
                            BriefApprovalDecision.id == task.brief_approval_decision_id
                        )
                    )
                    if exact_decision is None:
                        raise ApprovalNotFoundError("exact brief approval subject is unavailable")
                    expected_policy_version_id = exact_decision.policy_version_id
                request = ApprovalRequest(
                    id=request_id,
                    task_id=task.id,
                    request_type=request_type.value,
                    subject_type=normalized_subject_type,
                    subject_id=normalized_subject_id,
                    reason=normalized_reason,
                    options=[value.value for value in options],
                    supporting_evidence_ids=[str(value) for value in normalized_evidence_ids],
                    requesting_state=expected_state,
                    expires_at=normalized_expiry,
                    status=ApprovalStatus.PENDING,
                    request_fingerprint=request_fingerprint,
                    precondition_fingerprint=precondition_fingerprint,
                    resume_state=resume_state,
                    blocked_operation=(
                        None if blocked_operation is None else blocked_operation.to_dict()
                    ),
                    retry_history=[value.to_dict() for value in normalized_retry_history],
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
                        brief_approval_required=(request_type is ApprovalRequestType.BRIEF),
                        expected_policy_version_id=(expected_policy_version_id),
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
            raise ApprovalConflictError("approval request conflicts with durable state") from None
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
        expected_owner_id: str | None = None,
        recent_password_verified: bool | None = None,
    ) -> ApprovalDecisionResult:
        normalized_actor = _required_identifier(
            actor_id,
            field="approval actor",
        )
        decision_evidence_ids = tuple(evidence_ids)
        if len(decision_evidence_ids) > MAX_APPROVAL_EVIDENCE_REFERENCES or len(
            set(decision_evidence_ids)
        ) != len(decision_evidence_ids):
            raise InvalidApprovalError("decision evidence references are invalid")
        try:
            with self._factory() as session, session.begin():
                _begin_serialized(session)
                approval_task_id = session.scalar(
                    select(ApprovalRequest.task_id).where(
                        ApprovalRequest.id == request_id,
                        *(
                            (ApprovalRequest.owner_id == expected_owner_id,)
                            if expected_owner_id is not None
                            else ()
                        ),
                    )
                )
                if approval_task_id is None:
                    raise ApprovalNotFoundError("approval request is unavailable")
                task = session.scalar(
                    select(Task)
                    .where(
                        Task.id == approval_task_id,
                        *(
                            (Task.owner_id == expected_owner_id,)
                            if expected_owner_id is not None
                            else ()
                        ),
                    )
                    .with_for_update()
                )
                if task is None:
                    raise ApprovalNotFoundError("task is unavailable")
                request = session.scalar(
                    select(ApprovalRequest)
                    .where(
                        ApprovalRequest.id == request_id,
                        *(
                            (ApprovalRequest.owner_id == expected_owner_id,)
                            if expected_owner_id is not None
                            else ()
                        ),
                    )
                    .with_for_update()
                )
                if request is None or request.task_id != task.id:
                    raise ApprovalConflictError("approval request changed while acquiring locks")
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
                if len(combined_evidence_ids) > MAX_APPROVAL_EVIDENCE_REFERENCES:
                    raise InvalidApprovalError("combined approval evidence is too large")
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
                        raise ApprovalConflictError("approval request is already decided")
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
                    if request.expires_at is None or _as_utc(request.expires_at) > now:
                        raise InvalidApprovalError("approval request has not expired")
                elif effective_decision.value not in request.options:
                    raise InvalidApprovalError("approval decision is not an offered option")
                if (
                    session.scalar(
                        select(ApprovalRequest.id).where(ApprovalRequest.decision_id == decision_id)
                    )
                    is not None
                ):
                    raise ApprovalConflictError("approval decision id conflicts")
                request_type = _request_type(request)
                status, transition_kind, gates = _decision_projection(
                    request_type,
                    effective_decision,
                    decision_id=decision_id,
                )
                if (
                    recent_password_verified is False
                    and effective_decision is not ApprovalDecision.EXPIRE
                    and (
                        (
                            request_type is ApprovalRequestType.REVIEW_RULE
                            and effective_decision is ApprovalDecision.APPROVE
                        )
                        or transition_kind in {TaskTransitionKind.CANCEL, TaskTransitionKind.FAIL}
                    )
                ):
                    raise ApprovalRecentPasswordRequiredError(
                        "recent password authentication required"
                    )
                if (
                    request_type is ApprovalRequestType.BRIEF
                    and effective_decision is ApprovalDecision.APPROVE
                ):
                    exact_decision = session.scalar(
                        select(BriefApprovalDecision).where(
                            BriefApprovalDecision.id == task.brief_approval_decision_id
                        )
                    )
                    if exact_decision is None:
                        raise ApprovalNotFoundError("exact brief approval subject is unavailable")
                    gates = replace(
                        gates,
                        expected_policy_version_id=(exact_decision.policy_version_id),
                    )
                if effective_decision in _PRECONDITIONED_DECISIONS:
                    if not _durable_preconditions_are_current(
                        session,
                        task,
                        request,
                    ) or not self._precondition_evaluator.recheck(
                        session,
                        task,
                        request,
                        effective_decision,
                        now=now,
                    ):
                        raise ApprovalPreconditionError("approval preconditions changed")
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
                session.flush()
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
            raise ApprovalConflictError("approval decision conflicts with durable state") from None
        except TaskTransitionError as error:
            raise ApprovalConflictError(str(error)) from None

    def expire_due(self, *, limit: int = 100) -> tuple[ApprovalDecisionResult, ...]:
        if not 1 <= limit <= 1000:
            raise InvalidApprovalError("approval expiry limit is invalid")
        now = _as_utc(self._clock())
        results: list[ApprovalDecisionResult] = []
        cursor: tuple[datetime, UUID] | None = None
        while len(results) < limit:
            with self._factory() as session:
                query = select(
                    ApprovalRequest.id,
                    ApprovalRequest.expires_at,
                ).where(
                    ApprovalRequest.status == ApprovalStatus.PENDING,
                    ApprovalRequest.expires_at.is_not(None),
                    ApprovalRequest.expires_at <= now,
                    ApprovalRequest.request_fingerprint != _UNINITIALIZED_FINGERPRINT,
                    ApprovalRequest.precondition_fingerprint != _UNINITIALIZED_FINGERPRINT,
                )
                if cursor is not None:
                    cursor_expiry, cursor_id = cursor
                    query = query.where(
                        or_(
                            ApprovalRequest.expires_at > cursor_expiry,
                            and_(
                                ApprovalRequest.expires_at == cursor_expiry,
                                ApprovalRequest.id > cursor_id,
                            ),
                        )
                    )
                request_rows = tuple(
                    session.execute(
                        query.order_by(
                            ApprovalRequest.expires_at,
                            ApprovalRequest.id,
                        ).limit(limit)
                    )
                )
            if not request_rows:
                break
            for request_id, expires_at in request_rows:
                if expires_at is None:
                    continue
                normalized_expiry = _as_utc(expires_at)
                cursor = (normalized_expiry, request_id)
                decision_id = uuid5(
                    NAMESPACE_URL,
                    f"mathews:approval-expiry:{request_id}:{normalized_expiry.isoformat()}",
                )
                try:
                    results.append(
                        self.decide(
                            request_id,
                            decision_id=decision_id,
                            decision=ApprovalDecision.EXPIRE,
                            actor_id=self._principal_id,
                        )
                    )
                except ApprovalError as error:
                    _LOGGER.warning(
                        "Skipped stale approval expiry %s (%s)",
                        request_id,
                        type(error).__name__,
                    )
                if len(results) == limit:
                    break
        return tuple(results)

    @staticmethod
    def _validate_exact_subject(
        session: Session,
        task: Task,
        *,
        request_type: ApprovalRequestType,
        subject_id: UUID | None,
        evidence_ids: Sequence[UUID],
        require_actionable: bool = True,
    ) -> str | None:
        if request_type is ApprovalRequestType.BRIEF:
            brief = session.scalar(select(Brief).where(Brief.id == subject_id).with_for_update())
            decision = session.scalar(
                select(BriefApprovalDecision)
                .where(BriefApprovalDecision.id == task.brief_approval_decision_id)
                .with_for_update()
            )
            if (
                brief is None
                or brief.task_id != task.id
                or brief.owner_id != task.owner_id
                or task.accepted_brief_id != subject_id
                or decision is None
                or decision.task_id != task.id
                or decision.brief_id != subject_id
                or decision.disposition is not BriefDecisionDisposition.HUMAN_APPROVAL_REQUIRED
                or (require_actionable and decision.human_response is not None)
            ):
                raise ApprovalNotFoundError("exact brief approval subject is unavailable")
            return _brief_fingerprint(brief)
        elif request_type is ApprovalRequestType.REVIEW_RULE:
            candidate = session.scalar(
                select(RuleCandidate).where(RuleCandidate.id == subject_id).with_for_update()
            )
            if (
                candidate is None
                or candidate.task_id != task.id
                or candidate.owner_id != task.owner_id
                or (require_actionable and candidate.status is not RuleCandidateStatus.EVALUATED)
                or candidate.evaluation_result is None
            ):
                raise ApprovalNotFoundError("evaluated rule candidate is unavailable")
            _rule, cited_evidence_ids, fingerprint = _validated_rule_candidate(
                session,
                task,
                candidate,
            )
            if not set(cited_evidence_ids).issubset(evidence_ids):
                raise ApprovalConflictError("rule candidate evidence must support the approval")
            return fingerprint
        return None

    def _project_subject_decision(
        self,
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
                .where(BriefApprovalDecision.id == task.brief_approval_decision_id)
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
                raise ApprovalConflictError("exact brief approval subject is unavailable")
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
                or candidate.owner_id != task.owner_id
                or candidate.status is not RuleCandidateStatus.EVALUATED
                or candidate.evaluation_result is None
            ):
                raise ApprovalConflictError("evaluated rule candidate is unavailable")
            candidate.status = (
                RuleCandidateStatus.APPROVED
                if decision is ApprovalDecision.APPROVE
                else RuleCandidateStatus.REJECTED
            )
            candidate.actor_id = actor_id
            candidate.updated_at = decided_at
            if decision is ApprovalDecision.APPROVE:
                self._promote_review_rule(
                    session,
                    task,
                    request,
                    candidate,
                    actor_id=actor_id,
                    approved_at=decided_at,
                )

    def _promote_review_rule(
        self,
        session: Session,
        task: Task,
        request: ApprovalRequest,
        candidate: RuleCandidate,
        *,
        actor_id: str,
        approved_at: datetime,
    ) -> None:
        definition = _evaluated_review_rule(candidate)
        cited_evidence_ids = _candidate_evidence_ids(session, task, candidate)
        if not set(cited_evidence_ids).issubset(_stored_evidence_ids(request)):
            raise ApprovalConflictError("rule candidate evidence is not bound to the approval")
        predecessor = session.scalar(
            select(ReviewRule)
            .where(
                ReviewRule.lineage_key == definition.lineage_key,
                ReviewRule.owner_id == task.owner_id,
            )
            .order_by(ReviewRule.version.desc())
            .limit(1)
            .with_for_update()
        )
        active = session.scalar(
            select(PolicyVersion)
            .where(
                PolicyVersion.lineage_key == self._active_policy_lineage,
                PolicyVersion.owner_id == task.owner_id,
                PolicyVersion.approved_at <= approved_at,
            )
            .order_by(PolicyVersion.version.desc())
            .limit(1)
            .with_for_update()
        )
        if active is None:
            raise ApprovalConflictError("active approval policy is unavailable")
        next_rule_version = (
            session.scalar(
                select(func.max(ReviewRule.version)).where(
                    ReviewRule.lineage_key == definition.lineage_key
                )
            )
            or 0
        ) + 1
        next_policy_version = (
            session.scalar(
                select(func.max(PolicyVersion.version)).where(
                    PolicyVersion.lineage_key == self._active_policy_lineage
                )
            )
            or 0
        ) + 1
        context = {
            "owner_id": task.owner_id,
            "actor_id": actor_id,
            "root_correlation_id": task.root_correlation_id,
            "causation_id": request.id,
            "parent_correlation_id": task.id,
            "created_at": approved_at,
            "updated_at": approved_at,
        }
        rule = ReviewRule(
            lineage_key=definition.lineage_key,
            version=next_rule_version,
            predecessor_id=None if predecessor is None else predecessor.id,
            candidate_id=candidate.id,
            approval_request_id=request.id,
            approval_status=ApprovalStatus.APPROVED,
            approval_request_type=ApprovalRequestType.REVIEW_RULE.value,
            approval_subject_type="RULE_CANDIDATE",
            scope=definition.scope,
            matcher=definition.matcher,
            permitted_action=definition.permitted_action,
            risk_class=definition.risk_class,
            evidence_requirements=definition.evidence_requirements,
            provenance={
                "approval_request_id": str(request.id),
                "candidate_id": str(candidate.id),
                "cited_evidence_ids": [str(value) for value in cited_evidence_ids],
                "evaluation_fingerprint": _fingerprint(
                    cast(Mapping[str, object], candidate.evaluation_result)
                ),
                "schema_version": 1,
            },
            approved_by=actor_id,
            approved_at=approved_at,
            **context,
        )
        session.add(rule)
        session.flush()
        policy = PolicyVersion(
            lineage_key=active.lineage_key,
            version=next_policy_version,
            predecessor_id=active.id,
            workflow_thresholds=active.workflow_thresholds,
            approved_by=actor_id,
            approved_at=approved_at,
            rollback_policy_version_id=active.id,
            **context,
        )
        session.add(policy)
        session.flush()
        active_rules = session.execute(
            select(PolicyVersionReviewRule, ReviewRule)
            .join(
                ReviewRule,
                ReviewRule.id == PolicyVersionReviewRule.review_rule_id,
            )
            .where(PolicyVersionReviewRule.policy_version_id == active.id)
            .order_by(PolicyVersionReviewRule.position)
        ).all()
        replacement_rule_ids: list[UUID] = []
        replaced = False
        for _membership, existing_rule in active_rules:
            if existing_rule.lineage_key == definition.lineage_key:
                if not replaced:
                    replacement_rule_ids.append(rule.id)
                    replaced = True
                continue
            replacement_rule_ids.append(existing_rule.id)
        if not replaced:
            replacement_rule_ids.append(rule.id)
        for position, review_rule_id in enumerate(replacement_rule_ids, start=1):
            session.add(
                PolicyVersionReviewRule(
                    policy_version_id=policy.id,
                    review_rule_id=review_rule_id,
                    position=position,
                    **context,
                )
            )
        active_prompts = session.scalars(
            select(PolicyVersionPromptTemplate)
            .where(PolicyVersionPromptTemplate.policy_version_id == active.id)
            .order_by(PolicyVersionPromptTemplate.position)
        ).all()
        for prompt in active_prompts:
            session.add(
                PolicyVersionPromptTemplate(
                    policy_version_id=policy.id,
                    prompt_template_version_id=(prompt.prompt_template_version_id),
                    prompt_promoted=True,
                    position=prompt.position,
                    **context,
                )
            )
        session.flush()


def _decision_event_type(decision: ApprovalDecision) -> str:
    return "APPROVAL_EXPIRED" if decision is ApprovalDecision.EXPIRE else "APPROVAL_DECIDED"


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
    event_id = session.scalar(select(TaskEvent.id).where(TaskEvent.transition_id == transition_id))
    if event_id is None:
        raise ApprovalConflictError("approval transition event is unavailable")
    return event_id


class ApprovalBodyLimitMiddleware:
    """Bound approval-decision JSON before request parsing buffers it."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        maximum_bytes: int = MAX_APPROVAL_DECISION_BYTES,
    ) -> None:
        self._app = app
        self._maximum_bytes = maximum_bytes

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        path = scope.get("path", "")
        bounded = (
            scope["type"] == "http"
            and scope.get("method") == "POST"
            and isinstance(path, str)
            and path.startswith("/api/approvals/")
            and path.endswith("/decisions")
        )
        if not bounded:
            await self._app(scope, receive, send)
            return
        content_length = self._content_length(scope)
        if content_length is not None and content_length > self._maximum_bytes:
            await self._send_too_large(scope, receive, send)
            return
        received_bytes = 0
        captured_messages: list[Message] = []
        while True:
            message = await receive()
            captured_messages.append(message)
            if message["type"] == "http.disconnect":
                break
            if message["type"] != "http.request":
                continue
            received_bytes += len(message.get("body", b""))
            if received_bytes > self._maximum_bytes:
                await self._send_too_large(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        message_index = 0

        async def replay_receive() -> Message:
            nonlocal message_index
            if message_index < len(captured_messages):
                message = captured_messages[message_index]
                message_index += 1
                return message
            return await receive()

        await self._app(scope, replay_receive, send)

    @staticmethod
    def _content_length(scope: Scope) -> int | None:
        for name, value in scope["headers"]:
            if name.lower() != b"content-length":
                continue
            try:
                return max(0, int(value))
            except ValueError:
                return None
        return None

    @staticmethod
    async def _send_too_large(
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        response = JSONResponse(
            {"detail": "approval decision body too large"},
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )
        await response(scope, receive, send)


def create_approval_router(service: ApprovalService) -> APIRouter:
    router = APIRouter(prefix="/api/approvals", tags=["approvals"])

    @router.get("/inbox", response_model=ApprovalInboxResponse)
    def inbox(
        response: Response,
        authentication: AuthenticatedApprovalSession,
    ) -> ApprovalInboxResponse:
        response.headers["Cache-Control"] = "no-store"
        try:
            return service.inbox(authentication)
        except (ApprovalNotFoundError, ApprovalConflictError) as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="approval inbox is unavailable",
            ) from error

    @router.post(
        "/{request_id}/decisions",
        response_model=ApprovalDecisionResponse,
    )
    def decide(
        request_id: UUID,
        body: ApprovalDecisionRequest,
        response: Response,
        authentication: AuthenticatedApprovalSession,
    ) -> ApprovalDecisionResponse:
        response.headers["Cache-Control"] = "no-store"
        try:
            owner_id = _approval_principal(authentication)
            decision = ApprovalDecision(body.decision)
            result = service.decide(
                request_id,
                decision_id=uuid5(
                    NAMESPACE_URL,
                    f"mathews:browser-approval:{owner_id}:{request_id}:{decision.value}",
                ),
                decision=decision,
                actor_id=owner_id,
                expected_owner_id=owner_id,
                recent_password_verified=(authentication.recent_password_verified),
            )
            if result.decision is ApprovalDecision.EXPIRE:
                raise ApprovalConflictError("approval request expired")
        except ApprovalNotFoundError as error:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="approval request is unavailable",
            ) from error
        except InvalidApprovalError as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="approval decision is invalid",
            ) from error
        except (ApprovalConflictError, ApprovalPreconditionError) as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="approval request changed",
            ) from error
        except ApprovalRecentPasswordRequiredError as error:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="recent password authentication required",
            ) from error
        return ApprovalDecisionResponse(
            request_id=result.request_id,
            decision=cast(PublicApprovalDecision, result.decision.value),
            status=result.status,
            task_id=result.task_id,
            task_state=result.task_state,
            audit_event_id=result.audit_event_id,
        )

    return router
