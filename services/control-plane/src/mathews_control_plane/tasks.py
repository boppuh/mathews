"""Authenticated task intake and work-queue projections."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Callable, Sequence
from datetime import UTC, datetime
from typing import Annotated, Literal, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from mathews_configuration import AssertionKind
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse, StreamingResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.authentication import (
    AuthenticatedSession,
    require_authenticated_session,
)
from mathews_control_plane.background_jobs import (
    BackgroundJobConflictError,
    BackgroundJobNotFoundError,
)
from mathews_control_plane.database import (
    AuthSession,
    SessionFactory,
    create_task_record,
)
from mathews_control_plane.domain_models import (
    ApprovalRequest,
    ApprovalStatus,
    BackgroundJob,
    Brief,
    DependencyOutageAttempt,
    EvidenceDeletionRequest,
    EvidenceRecord,
    EvidenceTombstone,
    ReconciliationStatus,
    ReconciliationTarget,
    Task,
    TaskEvent,
    TaskEventEvidenceReference,
    TaskState,
    ValidationContract,
    ValidationRun,
)
from mathews_control_plane.evidence import redact_evidence_content
from mathews_control_plane.github_webhooks import (
    GITHUB_CHECK_UPDATED_EVENT,
    GITHUB_PR_BOUND_EVENT,
    GITHUB_PR_HEAD_CHANGED_EVENT,
    GITHUB_PULL_REQUEST_UPDATED_EVENT,
    GITHUB_REVIEW_UPDATED_EVENT,
)
from mathews_control_plane.reliability import (
    CancellationService,
    ReliabilityConflictError,
)
from mathews_control_plane.steering import (
    STEERING_EVENT_TYPE,
    SteeringClassification,
    SteeringConflictError,
    SteeringImpact,
    SteeringNotFoundError,
    SteeringResult,
    SteeringService,
)
from mathews_control_plane.task_state_machine import (
    TaskTransitionError,
    TaskTransitionKind,
)

TASK_INTAKE_EVENT_TYPE = "TASK_CREATED"
TASK_INTAKE_EVENT_SCHEMA_VERSION = 1
MAX_TASK_REQUEST_CHARACTERS = 20_000
MAX_TASK_REQUEST_BYTES = 64 * 1024
MAX_STEERING_MESSAGE_CHARACTERS = 2_000
TASK_EVENT_STREAM_BATCH_SIZE = 100
TASK_EVENT_POLL_INTERVAL_SECONDS = 1.0
TASK_EVENT_HEARTBEAT_SECONDS = 15.0
MAX_TASK_EVENT_SEQUENCE = (1 << 63) - 1
_LOCAL_USER_ID = 1
_LOCAL_OWNER_ID = "local-user"

RepositoryText = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        to_lower=True,
        min_length=3,
        max_length=140,
        pattern=(
            r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/"
            r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$"
        ),
    ),
]
GitObjectId = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        to_lower=True,
        pattern=r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$",
    ),
]
TaskRequestText = Annotated[str, StringConstraints(max_length=MAX_TASK_REQUEST_CHARACTERS)]
AuthenticatedTaskSession = Annotated[
    AuthenticatedSession,
    Depends(require_authenticated_session),
]
Clock = Callable[[], datetime]


class TaskAccessError(RuntimeError):
    """The authenticated principal is not a supported local task owner."""


class TaskCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    repository: RepositoryText
    base_revision: GitObjectId
    request: TaskRequestText

    @field_validator("request")
    @classmethod
    def request_must_have_content(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("task request must not be empty")
        return value

    @field_validator("repository")
    @classmethod
    def repository_must_not_use_transport_suffix(cls, value: str) -> str:
        if value.endswith(".git"):
            raise ValueError("repository key must not use a transport suffix")
        return value


class TaskSteeringRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    steering_id: UUID
    expected_state: TaskState
    message: Annotated[
        str,
        StringConstraints(
            strip_whitespace=True,
            min_length=1,
            max_length=MAX_STEERING_MESSAGE_CHARACTERS,
        ),
    ]
    impacts: tuple[SteeringImpact, ...] = Field(default=(), max_length=4)

    @field_validator("impacts")
    @classmethod
    def impacts_are_unique(
        cls,
        values: tuple[SteeringImpact, ...],
    ) -> tuple[SteeringImpact, ...]:
        if len(values) != len(set(values)):
            raise ValueError("steering impacts must be unique")
        return values


class TaskSteeringResponse(BaseModel):
    steering_id: UUID
    task_id: UUID
    classification: SteeringClassification
    impacts: list[SteeringImpact]
    task_state: TaskState
    evidence_id: UUID
    request_evidence_id: UUID
    event_id: UUID
    invalidated_brief_id: UUID | None = None
    invalidated_validation_contract_id: UUID | None = None
    revoked_lease_count: int = Field(ge=0)
    revoked_tool_grant_count: int = Field(ge=0)
    replayed: bool


class TaskCancellationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    cancellation_id: UUID
    expected_state: TaskState
    reason_code: Literal["USER_REQUEST"] = "USER_REQUEST"


class TaskCancellationResponse(BaseModel):
    cancellation_id: UUID
    task_id: UUID
    task_state: TaskState
    partial_evidence_id: UUID
    revoked_lease_count: int = Field(ge=0)
    revoked_tool_grant_count: int = Field(ge=0)
    cleanup_complete: bool
    replayed: bool


class TaskBlockerResponse(BaseModel):
    code: Literal[
        "APPROVAL_REQUIRED",
        "DEPENDENCY_OUTAGE",
        "RECONCILIATION_REQUIRED",
    ]
    label: str
    count: int = Field(ge=1)


class TaskSummaryResponse(BaseModel):
    id: UUID
    summary: str
    state: TaskState
    repository: str
    base_revision: str
    created_at: datetime
    last_activity_at: datetime
    blockers: list[TaskBlockerResponse]
    cockpit_path: str


class TaskListResponse(BaseModel):
    tasks: list[TaskSummaryResponse]


class TaskStateContextResponse(BaseModel):
    kind: Literal[
        "ACTIVE",
        "RESUMABLE_ESCALATION",
        "TERMINAL",
        "VERIFIED_DRAFT_PR",
        "HUMAN_MERGE_READY",
        "AUTOMATION_HANDED_OFF",
    ]
    label: str
    detail: str
    resume_state: TaskState | None = None


class TaskEventResponse(BaseModel):
    id: UUID
    sequence: int = Field(ge=1)
    kind: Literal["CREATED", "STATE_TRANSITION", "APPROVAL", "ACTIVITY"]
    summary: str
    occurred_at: datetime
    from_state: TaskState | None = None
    to_state: TaskState | None = None
    evidence_count: int = Field(ge=0)


class TaskEvidenceResponse(BaseModel):
    id: UUID
    evidence_type: str
    captured_at: datetime
    status: Literal["AVAILABLE", "CORRECTION", "SUPERSEDED", "DELETED"]
    category: Literal[
        "CRITERIA",
        "CHANGE",
        "TEST",
        "LOG",
        "NETWORK",
        "PR_CI",
        "ARTIFACT",
        "OTHER",
    ]
    content_access: Literal[
        "AVAILABLE",
        "RECENT_PASSWORD_REQUIRED",
        "DELETED",
    ]
    correction_of_id: UUID | None = None
    corrected_by_id: UUID | None = None
    deletion_reason: Literal[
        "USER_REQUEST",
        "RETENTION_EXPIRED",
        "SOURCE_REVOKED",
        "SECURITY_RESPONSE",
    ] | None = None
    deleted_at: datetime | None = None
    download_path: str | None = None


class TaskAcceptanceAssertionResponse(BaseModel):
    assertion_id: str
    kind: Literal[
        "ELEMENT_VALUE_PRESENT",
        "NAVIGATION_STATE_REACHED",
        "EXPECTED_NETWORK_RESPONSE",
        "EXPECTED_LOG_EVENT",
        "NO_CRASH",
    ]
    verifier_catalog_key: str
    status: Literal["PENDING", "PASSED", "FAILED", "BLOCKED"]
    result_code: str
    evidence_ids: list[UUID]


class TaskAcceptanceCriterionResponse(BaseModel):
    id: str
    requirement: str
    verification: Literal[
        "AUTOMATED_TEST",
        "SIMULATOR_ASSERTION",
        "STATIC_CHECK",
        "HUMAN_INSPECTION",
    ]
    status: Literal["PENDING", "PASSED", "FAILED", "BLOCKED"]
    validation_run_id: UUID | None = None
    validation_contract_version: int | None = Field(default=None, ge=1)
    commit_sha: GitObjectId | None = None
    tree_sha: GitObjectId | None = None
    evidence_ids: list[UUID] = Field(default_factory=list)
    assertions: list[TaskAcceptanceAssertionResponse] = Field(default_factory=list)


class TaskApprovalResponse(BaseModel):
    id: UUID
    type_label: str
    status: ApprovalStatus
    requesting_state: TaskState
    resume_state: TaskState | None = None
    created_at: datetime
    expires_at: datetime | None = None


class TaskGitHubStatusResponse(BaseModel):
    linked: bool
    pull_request_number: int | None = None
    task_branch: str | None = None
    head_sha: str | None = None
    ci_status: Literal["NOT_LINKED", "NOT_RUN", "PENDING", "PASSED", "FAILED"]
    review_status: Literal[
        "NOT_LINKED",
        "NOT_REVIEWED",
        "COMMENTED",
        "APPROVED",
        "CHANGES_REQUESTED",
    ]
    checks_total: int = Field(ge=0)
    checks_passed: int = Field(ge=0)
    blocking_reviews: int = Field(ge=0)
    review_comments: int = Field(ge=0)
    last_updated_at: datetime | None = None


class TaskCockpitResponse(BaseModel):
    task: TaskSummaryResponse
    state_context: TaskStateContextResponse
    events: list[TaskEventResponse]
    acceptance_criteria: list[TaskAcceptanceCriterionResponse]
    evidence: list[TaskEvidenceResponse]
    approvals: list[TaskApprovalResponse]
    github: TaskGitHubStatusResponse


class TaskNotFoundError(RuntimeError):
    """The task is absent or outside the authenticated owner's scope."""


class InvalidTaskEventCursorError(ValueError):
    """The SSE resume cursor is not a canonical task-event sequence."""


class TaskService:
    """Persist task intake and project the authenticated operator's queue."""

    def __init__(
        self,
        session_factory: SessionFactory,
        artifact_store: ArtifactStore,
        *,
        clock: Clock | None = None,
    ) -> None:
        self._factory = session_factory
        self._artifact_store = artifact_store
        self._clock = clock or (lambda: datetime.now(UTC))
        self._steering = SteeringService(
            session_factory,
            artifact_store,
            clock=self._clock,
        )

    def create(
        self,
        body: TaskCreateRequest,
        authentication: AuthenticatedSession,
    ) -> TaskSummaryResponse:
        owner_id = _principal(authentication)
        occurred_at = _as_utc(self._clock())
        summary = _request_summary(body.request)

        with self._factory.begin() as session:
            task = create_task_record(
                session,
                self._artifact_store,
                repository=body.repository,
                base_revision=body.base_revision,
                requester=owner_id,
                raw_request=body.request,
                summary=summary,
                owner_id=owner_id,
                actor_id=owner_id,
            )
            request_evidence_id = UUID(task.raw_request.removeprefix("evidence://"))
            event = TaskEvent(
                task_id=task.id,
                sequence=1,
                event_type=TASK_INTAKE_EVENT_TYPE,
                payload={
                    "schema_version": TASK_INTAKE_EVENT_SCHEMA_VERSION,
                    "request_evidence_id": str(request_evidence_id),
                    "summary": task.summary,
                },
                occurred_at=occurred_at,
                owner_id=task.owner_id,
                actor_id=owner_id,
                root_correlation_id=task.root_correlation_id,
                causation_id=task.id,
            )
            session.add(event)
            session.flush()
            session.add(
                TaskEventEvidenceReference(
                    task_id=task.id,
                    task_event_id=event.id,
                    evidence_id=request_evidence_id,
                    position=1,
                    owner_id=task.owner_id,
                    actor_id=owner_id,
                    root_correlation_id=task.root_correlation_id,
                    causation_id=event.id,
                    parent_correlation_id=task.id,
                )
            )
            session.flush()
            return _task_response(
                task,
                last_activity_at=event.occurred_at,
                blockers=(),
            )

    def list(self, authentication: AuthenticatedSession) -> TaskListResponse:
        owner_id = _principal(authentication)
        last_event_at = (
            select(func.max(TaskEvent.occurred_at))
            .where(TaskEvent.task_id == Task.id)
            .correlate(Task)
            .scalar_subquery()
        )
        with self._factory() as session:
            rows = session.execute(
                select(
                    Task,
                    func.coalesce(last_event_at, Task.updated_at).label(
                        "last_activity_at"
                    ),
                )
                .where(Task.owner_id == owner_id)
                .order_by(
                    func.coalesce(last_event_at, Task.updated_at).desc(),
                    Task.id.desc(),
                )
            ).all()
            task_ids = tuple(task.id for task, _last_activity_at in rows)
            blockers = _blockers_by_task(session, task_ids)
            return TaskListResponse(
                tasks=[
                    _task_response(
                        task,
                        last_activity_at=last_activity_at,
                        blockers=blockers.get(task.id, ()),
                    )
                    for task, last_activity_at in rows
                ]
            )

    def steer(
        self,
        task_id: UUID,
        body: TaskSteeringRequest,
        authentication: AuthenticatedSession,
    ) -> TaskSteeringResponse:
        owner_id = _principal(authentication)
        result: SteeringResult = self._steering.steer(
            task_id,
            steering_id=body.steering_id,
            expected_state=body.expected_state,
            message=body.message,
            impacts=body.impacts,
            owner_id=owner_id,
        )
        return TaskSteeringResponse(
            steering_id=result.steering_id,
            task_id=result.task_id,
            classification=result.classification,
            impacts=list(result.impacts),
            task_state=result.task_state,
            evidence_id=result.evidence_id,
            request_evidence_id=result.request_evidence_id,
            event_id=result.event_id,
            invalidated_brief_id=result.invalidated_brief_id,
            invalidated_validation_contract_id=(
                result.invalidated_validation_contract_id
            ),
            revoked_lease_count=result.revoked_lease_count,
            revoked_tool_grant_count=result.revoked_tool_grant_count,
            replayed=result.replayed,
        )

    def cancel(
        self,
        task_id: UUID,
        body: TaskCancellationRequest,
        authentication: AuthenticatedSession,
    ) -> TaskCancellationResponse:
        owner_id = _principal(authentication)
        now = _as_utc(self._clock())
        if not (
            authentication.recent_password_verified
            and _as_utc(authentication.reauthenticated_until) > now
        ):
            raise PermissionError("recent password authentication required")
        with self._factory() as session:
            task = session.scalar(
                select(Task).where(Task.id == task_id, Task.owner_id == owner_id)
            )
        if task is None:
            raise TaskNotFoundError("task is unavailable")
        result = CancellationService(
            self._factory,
            self._artifact_store,
            principal_id=owner_id,
            clock=self._clock,
        ).cancel_task(
            task_id,
            cancellation_id=body.cancellation_id,
            expected_state=body.expected_state,
            reason_code=body.reason_code,
        )
        return TaskCancellationResponse(
            cancellation_id=result.cancellation_id,
            task_id=result.task_id,
            task_state=result.task_state,
            partial_evidence_id=result.partial_evidence_id,
            revoked_lease_count=result.revoked_lease_count,
            revoked_tool_grant_count=result.revoked_tool_grant_count,
            cleanup_complete=result.cleanup_complete,
            replayed=result.replayed,
        )

    def detail(
        self,
        task_id: UUID,
        authentication: AuthenticatedSession,
    ) -> TaskCockpitResponse:
        owner_id = _principal(authentication)
        with self._factory() as session:
            task = session.scalar(
                select(Task).where(
                    Task.id == task_id,
                    Task.owner_id == owner_id,
                )
            )
            if task is None:
                raise TaskNotFoundError("task is unavailable")

            events = tuple(
                session.scalars(
                    select(TaskEvent)
                    .where(
                        TaskEvent.task_id == task.id,
                        TaskEvent.owner_id == owner_id,
                    )
                    .order_by(TaskEvent.sequence, TaskEvent.id)
                )
            )
            evidence = tuple(
                session.scalars(
                    select(EvidenceRecord)
                    .where(
                        EvidenceRecord.task_id == task.id,
                        EvidenceRecord.owner_id == owner_id,
                        EvidenceRecord.access_classification != "INTERNAL",
                    )
                    .order_by(EvidenceRecord.captured_at, EvidenceRecord.id)
                )
            )
            evidence_ids = tuple(record.id for record in evidence)
            deletion_requests = {
                request.evidence_id: request
                for request in session.scalars(
                    select(EvidenceDeletionRequest).where(
                        EvidenceDeletionRequest.evidence_id.in_(evidence_ids)
                    )
                )
            } if evidence_ids else {}
            tombstones = {
                tombstone.evidence_id: tombstone
                for tombstone in session.scalars(
                    select(EvidenceTombstone).where(
                        EvidenceTombstone.evidence_id.in_(evidence_ids)
                    )
                )
            } if evidence_ids else {}
            corrected_by = {
                record.correction_of_id: record.id
                for record in evidence
                if record.correction_of_id is not None
            }
            accepted_brief = (
                None
                if task.accepted_brief_id is None
                else session.get(Brief, task.accepted_brief_id)
            )
            validation_contract = (
                None
                if task.validation_contract_id is None
                else session.get(ValidationContract, task.validation_contract_id)
            )
            latest_validation_run = (
                None
                if validation_contract is None
                else session.scalar(
                    select(ValidationRun)
                    .where(
                        ValidationRun.task_id == task.id,
                        ValidationRun.validation_contract_id == validation_contract.id,
                    )
                    .order_by(ValidationRun.created_at.desc(), ValidationRun.id.desc())
                    .limit(1)
                )
            )
            approvals = tuple(
                session.scalars(
                    select(ApprovalRequest)
                    .where(
                        ApprovalRequest.task_id == task.id,
                        ApprovalRequest.owner_id == owner_id,
                    )
                    .order_by(ApprovalRequest.created_at.desc(), ApprovalRequest.id.desc())
                )
            )
            reference_counts = _event_evidence_counts(
                session,
                tuple(event.id for event in events),
            )
            blockers = _blockers_by_task(session, (task.id,)).get(task.id, ())
            last_activity_at = max(
                (event.occurred_at for event in events),
                default=task.updated_at,
            )
            now = _as_utc(self._clock())
            return TaskCockpitResponse(
                task=_task_response(
                    task,
                    last_activity_at=last_activity_at,
                    blockers=blockers,
                ),
                state_context=_task_state_context(task),
                events=[
                    _event_response(
                        event,
                        evidence_count=reference_counts.get(event.id, 0),
                    )
                    for event in events
                ],
                acceptance_criteria=_acceptance_criteria_response(
                    accepted_brief,
                    latest_validation_run,
                    validation_contract,
                ),
                evidence=[
                    _evidence_response(
                        record,
                        deletion_request=deletion_requests.get(record.id),
                        tombstone=tombstones.get(record.id),
                        corrected_by_id=corrected_by.get(record.id),
                        authentication=authentication,
                        now=now,
                    )
                    for record in evidence
                ],
                approvals=[_approval_response(request) for request in approvals],
                github=_github_status(events),
            )

    def events_after(
        self,
        task_id: UUID,
        authentication: AuthenticatedSession,
        *,
        after_sequence: int,
        limit: int = TASK_EVENT_STREAM_BATCH_SIZE,
    ) -> Sequence[TaskEventResponse]:
        owner_id = _principal(authentication)
        if not 0 <= after_sequence <= MAX_TASK_EVENT_SEQUENCE:
            raise InvalidTaskEventCursorError("task event cursor is invalid")
        if not 1 <= limit <= TASK_EVENT_STREAM_BATCH_SIZE:
            raise ValueError("task event batch size is invalid")

        with self._factory() as session:
            now = _as_utc(self._clock())
            active_session = session.scalar(
                select(AuthSession.id).where(
                    AuthSession.id == authentication.session_id,
                    AuthSession.user_id == authentication.user_id,
                    AuthSession.revoked_at.is_(None),
                    AuthSession.expires_at > now,
                    AuthSession.absolute_expires_at > now,
                )
            )
            if active_session is None:
                raise TaskAccessError("task session is unavailable")
            task_exists = session.scalar(
                select(Task.id).where(
                    Task.id == task_id,
                    Task.owner_id == owner_id,
                )
            )
            if task_exists is None:
                raise TaskNotFoundError("task is unavailable")
            events = tuple(
                session.scalars(
                    select(TaskEvent)
                    .where(
                        TaskEvent.task_id == task_id,
                        TaskEvent.owner_id == owner_id,
                        TaskEvent.sequence > after_sequence,
                    )
                    .order_by(TaskEvent.sequence, TaskEvent.id)
                    .limit(limit)
                )
            )
            reference_counts = _event_evidence_counts(
                session,
                tuple(event.id for event in events),
            )
            return [
                _event_response(
                    event,
                    evidence_count=reference_counts.get(event.id, 0),
                )
                for event in events
            ]


def _principal(authentication: AuthenticatedSession) -> str:
    if authentication.user_id != _LOCAL_USER_ID:
        raise TaskAccessError("task owner is unavailable")
    return _LOCAL_OWNER_ID


def _request_summary(raw_request: str) -> str:
    redacted = redact_evidence_content(
        raw_request,
        media_type="text/plain; charset=utf-8",
    )
    normalized = " ".join(str(redacted.value).split())
    if len(normalized) <= 160:
        return normalized
    truncated = normalized[:157].rstrip()
    if truncated.rfind("[") > truncated.rfind("]"):
        truncated = truncated[: truncated.rfind("[")].rstrip()
    return f"{truncated}..."


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _last_event_sequence(value: str | None) -> int:
    if value is None:
        return 0
    if (
        not value
        or not value.isascii()
        or not value.isdecimal()
        or len(value) > 19
        or (len(value) > 1 and value.startswith("0"))
    ):
        raise InvalidTaskEventCursorError("task event cursor is invalid")
    sequence = int(value)
    if sequence > MAX_TASK_EVENT_SEQUENCE:
        raise InvalidTaskEventCursorError("task event cursor is invalid")
    return sequence


def _format_sse_event(event: TaskEventResponse) -> str:
    return (
        f"id: {event.sequence}\n"
        "event: task-event\n"
        f"data: {event.model_dump_json()}\n\n"
    )


async def _task_event_stream(
    request: Request,
    service: TaskService,
    task_id: UUID,
    authentication: AuthenticatedSession,
    *,
    after_sequence: int,
    initial_events: Sequence[TaskEventResponse],
) -> AsyncIterator[str]:
    cursor = after_sequence
    pending: Sequence[TaskEventResponse] = tuple(initial_events)
    last_heartbeat = time.monotonic()
    yield "retry: 1000\n\n"

    while not await request.is_disconnected():
        if pending:
            for event in pending:
                if event.sequence <= cursor:
                    continue
                yield _format_sse_event(event)
                cursor = event.sequence
            try:
                pending = await run_in_threadpool(
                    service.events_after,
                    task_id,
                    authentication,
                    after_sequence=cursor,
                )
            except (TaskAccessError, TaskNotFoundError):
                return
            continue

        now = time.monotonic()
        if now - last_heartbeat >= TASK_EVENT_HEARTBEAT_SECONDS:
            yield ": keep-alive\n\n"
            last_heartbeat = now
        await asyncio.sleep(TASK_EVENT_POLL_INTERVAL_SECONDS)
        try:
            pending = await run_in_threadpool(
                service.events_after,
                task_id,
                authentication,
                after_sequence=cursor,
            )
        except (TaskAccessError, TaskNotFoundError):
            return


def _count_rows(
    rows: Sequence[tuple[UUID | None, int]],
) -> dict[UUID, int]:
    return {
        task_id: int(count)
        for task_id, count in rows
        if task_id is not None
    }


def _event_evidence_counts(
    session: Session,
    event_ids: Sequence[UUID],
) -> dict[UUID, int]:
    if not event_ids:
        return {}
    return _count_rows(
        session.execute(
            select(
                TaskEventEvidenceReference.task_event_id,
                func.count(),
            )
            .where(TaskEventEvidenceReference.task_event_id.in_(event_ids))
            .group_by(TaskEventEvidenceReference.task_event_id)
        ).tuples().all()
    )


def _blockers_by_task(
    session: Session,
    task_ids: Sequence[UUID],
) -> dict[UUID, tuple[TaskBlockerResponse, ...]]:
    if not task_ids:
        return {}

    approval_counts = _count_rows(
        session.execute(
            select(ApprovalRequest.task_id, func.count())
            .where(
                ApprovalRequest.task_id.in_(task_ids),
                ApprovalRequest.status == ApprovalStatus.PENDING,
            )
            .group_by(ApprovalRequest.task_id)
        ).tuples().all()
    )
    outage_counts = _count_rows(
        session.execute(
            select(
                BackgroundJob.task_id,
                func.count(func.distinct(BackgroundJob.id)),
            )
            .join(
                DependencyOutageAttempt,
                DependencyOutageAttempt.job_id == BackgroundJob.id,
            )
            .where(
                BackgroundJob.task_id.in_(task_ids),
                DependencyOutageAttempt.exhausted.is_(True),
                DependencyOutageAttempt.resolved_at.is_(None),
            )
            .group_by(BackgroundJob.task_id)
        ).tuples().all()
    )
    reconciliation_counts = _count_rows(
        session.execute(
            select(ReconciliationTarget.task_id, func.count())
            .where(
                ReconciliationTarget.task_id.in_(task_ids),
                ReconciliationTarget.status.in_(
                    (
                        ReconciliationStatus.PENDING,
                        ReconciliationStatus.QUARANTINED,
                        ReconciliationStatus.RETRY_REQUIRED,
                    )
                ),
            )
            .group_by(ReconciliationTarget.task_id)
        ).tuples().all()
    )

    blockers: dict[UUID, tuple[TaskBlockerResponse, ...]] = {}
    for task_id in task_ids:
        task_blockers: list[TaskBlockerResponse] = []
        approval_count = approval_counts.get(task_id, 0)
        if approval_count:
            task_blockers.append(
                TaskBlockerResponse(
                    code="APPROVAL_REQUIRED",
                    label=(
                        "Approval required"
                        if approval_count == 1
                        else "Approvals required"
                    ),
                    count=approval_count,
                )
            )
        outage_count = outage_counts.get(task_id, 0)
        if outage_count:
            task_blockers.append(
                TaskBlockerResponse(
                    code="DEPENDENCY_OUTAGE",
                    label=(
                        "Dependency outage"
                        if outage_count == 1
                        else "Dependency outages"
                    ),
                    count=outage_count,
                )
            )
        reconciliation_count = reconciliation_counts.get(task_id, 0)
        if reconciliation_count:
            task_blockers.append(
                TaskBlockerResponse(
                    code="RECONCILIATION_REQUIRED",
                    label=(
                        "Reconciliation required"
                        if reconciliation_count == 1
                        else "Reconciliations required"
                    ),
                    count=reconciliation_count,
                )
            )
        if task_blockers:
            blockers[task_id] = tuple(task_blockers)
    return blockers


def _task_state_context(task: Task) -> TaskStateContextResponse:
    state = TaskState(task.state)
    if state is TaskState.ESCALATED:
        resume_state = (
            None
            if task.escalation_resume_state is None
            else TaskState(task.escalation_resume_state)
        )
        return TaskStateContextResponse(
            kind="RESUMABLE_ESCALATION",
            label="Resumable escalation",
            detail=(
                "Automation is paused for a human decision and can resume from "
                f"{_state_label(resume_state)}."
                if resume_state is not None
                else "Automation is paused for a human decision before it can resume."
            ),
            resume_state=resume_state,
        )
    if state is TaskState.FAILED:
        return TaskStateContextResponse(
            kind="TERMINAL",
            label="Terminal failure",
            detail="Automation ended in failure. This task cannot resume.",
        )
    if state is TaskState.CANCELLED:
        return TaskStateContextResponse(
            kind="TERMINAL",
            label="Terminal cancellation",
            detail="Automation was cancelled. Late results cannot restart this task.",
        )
    if state is TaskState.PR_ACTIVE:
        return TaskStateContextResponse(
            kind="VERIFIED_DRAFT_PR",
            label="Verified draft PR active",
            detail=(
                "The draft pull request is bound to a verified candidate head; "
                "it is not yet ready for human merge."
            ),
        )
    if state is TaskState.READY_FOR_HUMAN_MERGE:
        return TaskStateContextResponse(
            kind="HUMAN_MERGE_READY",
            label="Ready for human merge",
            detail=(
                "The exact pull-request head passed its readiness gates. "
                "A human merge decision is still required."
            ),
        )
    if state is TaskState.HANDED_OFF:
        return TaskStateContextResponse(
            kind="AUTOMATION_HANDED_OFF",
            label="Automation handed off",
            detail=(
                "Automation responsibility has ended. Handoff does not mean "
                "the change was merged, delivered, or released."
            ),
        )
    return TaskStateContextResponse(
        kind="ACTIVE",
        label=_state_label(state),
        detail={
            TaskState.INTAKE: "The request is captured and waiting for briefing.",
            TaskState.BRIEFING: "The implementation brief is being prepared.",
            TaskState.BRIEF_PENDING_APPROVAL: (
                "The exact brief is waiting for a human decision."
            ),
            TaskState.IMPLEMENTING: "Approved implementation work is in progress.",
            TaskState.VALIDATING: "The current candidate is being validated.",
            TaskState.REPAIRING: "A bounded repair is in progress before revalidation.",
        }.get(state, "Automation is working on this task."),
    )


def _state_label(state: TaskState) -> str:
    acronyms = {"PR"}
    return " ".join(
        part if part in acronyms else part.title()
        for part in state.value.split("_")
    )


def _github_status(events: Sequence[TaskEvent]) -> TaskGitHubStatusResponse:
    binding = next(
        (event for event in reversed(events) if event.event_type == GITHUB_PR_BOUND_EVENT),
        None,
    )
    if binding is None:
        return _unlinked_github_status()
    head_sha = binding.payload.get("head_sha")
    pull_request_number = binding.payload.get("pull_request_number")
    task_branch = binding.payload.get("task_branch")
    required_checks = binding.payload.get("required_checks")
    if (
        not isinstance(head_sha, str)
        or len(head_sha) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in head_sha)
        or isinstance(pull_request_number, bool)
        or not isinstance(pull_request_number, int)
        or pull_request_number <= 0
        or not isinstance(task_branch, str)
        or not task_branch
        or not isinstance(required_checks, list)
        or not required_checks
        or any(not isinstance(check, str) or not check for check in required_checks)
        or len(required_checks) != len(set(required_checks))
    ):
        return _unlinked_github_status()
    head_change = next(
        (
            event
            for event in reversed(events)
            if event.sequence > binding.sequence
            and event.event_type == GITHUB_PR_HEAD_CHANGED_EVENT
            and event.payload.get("pull_request_number") == pull_request_number
            and event.payload.get("task_branch") == task_branch
        ),
        None,
    )
    projection_start = binding.sequence
    if head_change is not None and isinstance(head_change.payload.get("head_sha"), str):
        head_sha = cast(str, head_change.payload["head_sha"])
        projection_start = head_change.sequence
    latest: dict[tuple[object, object], TaskEvent] = {}
    for event in events:
        if event.event_type not in {
            GITHUB_CHECK_UPDATED_EVENT,
            GITHUB_REVIEW_UPDATED_EVENT,
            GITHUB_PULL_REQUEST_UPDATED_EVENT,
            GITHUB_PR_HEAD_CHANGED_EVENT,
        } or (
            event.sequence < projection_start
            or event.payload.get("head_sha") != head_sha
            or event.payload.get("pull_request_number") != pull_request_number
            or event.payload.get("task_branch") != task_branch
        ):
            continue
        latest[
            (event.payload.get("resource_type"), event.payload.get("resource_id"))
        ] = event
    latest_checks_by_name: dict[str, TaskEvent] = {}
    for (resource_type, _resource_id), event in latest.items():
        label = event.payload.get("resource_label")
        if resource_type == "check_run" and isinstance(label, str):
            latest_checks_by_name[label] = event
    checks = [
        latest_checks_by_name[check]
        for check in cast(list[str], required_checks)
        if check in latest_checks_by_name
    ]
    reviews = [
        event
        for (resource_type, _resource_id), event in latest.items()
        if resource_type == "review"
    ]
    comments = [
        event
        for (resource_type, _resource_id), event in latest.items()
        if resource_type == "review_comment"
    ]
    review_threads = [
        event
        for (resource_type, _resource_id), event in latest.items()
        if resource_type == "review_thread"
    ]
    check_states = [str(event.payload.get("state")) for event in checks]
    if not checks:
        ci_status: Literal["NOT_RUN", "PENDING", "PASSED", "FAILED"] = "NOT_RUN"
    elif any(state in {"FAILED", "CANCELLED"} for state in check_states):
        ci_status = "FAILED"
    elif len(checks) < len(required_checks) or any(
        state in {"QUEUED", "IN_PROGRESS"} for state in check_states
    ):
        ci_status = "PENDING"
    else:
        ci_status = "PASSED"
    review_states = [str(event.payload.get("state")) for event in reviews]
    open_comments = sum(
        event.payload.get("state") == "OPEN" for event in review_threads
    )
    if "CHANGES_REQUESTED" in review_states:
        review_status: Literal[
            "NOT_REVIEWED", "COMMENTED", "APPROVED", "CHANGES_REQUESTED"
        ] = "CHANGES_REQUESTED"
    elif "APPROVED" in review_states:
        review_status = "APPROVED"
    elif reviews or comments or open_comments:
        review_status = "COMMENTED"
    else:
        review_status = "NOT_REVIEWED"
    updated: list[datetime] = []
    for event in latest.values():
        source_updated_at = event.payload.get("source_updated_at")
        if not isinstance(source_updated_at, str):
            continue
        try:
            updated.append(
                datetime.fromisoformat(source_updated_at.replace("Z", "+00:00"))
            )
        except ValueError:
            continue
    return TaskGitHubStatusResponse(
        linked=True,
        pull_request_number=pull_request_number,
        task_branch=task_branch,
        head_sha=head_sha,
        ci_status=ci_status,
        review_status=review_status,
        checks_total=len(required_checks),
        checks_passed=sum(state in {"PASSED", "NEUTRAL"} for state in check_states),
        blocking_reviews=sum(state == "CHANGES_REQUESTED" for state in review_states),
        review_comments=open_comments,
        last_updated_at=max(updated, default=None),
    )


def _unlinked_github_status() -> TaskGitHubStatusResponse:
    return TaskGitHubStatusResponse(
        linked=False,
        ci_status="NOT_LINKED",
        review_status="NOT_LINKED",
        checks_total=0,
        checks_passed=0,
        blocking_reviews=0,
        review_comments=0,
    )


def _event_response(
    event: TaskEvent,
    *,
    evidence_count: int,
) -> TaskEventResponse:
    from_state = (
        None
        if event.transition_from_state is None
        else TaskState(event.transition_from_state)
    )
    to_state = (
        None
        if event.transition_to_state is None
        else TaskState(event.transition_to_state)
    )
    if event.event_type == TASK_INTAKE_EVENT_TYPE:
        kind: Literal["CREATED", "STATE_TRANSITION", "APPROVAL", "ACTIVITY"] = (
            "CREATED"
        )
        summary = "Task request captured."
    elif event.event_type == "TASK_STATE_TRANSITION":
        kind = "STATE_TRANSITION"
        if event.transition_kind == TaskTransitionKind.CANCEL.value:
            summary = "Task cancelled; active automation was fenced."
        elif event.transition_kind == TaskTransitionKind.SCOPE_STEER.value:
            summary = "Scope changed; a new brief and validation contract are required."
        else:
            summary = (
                f"State changed from {_state_label(from_state)} "
                f"to {_state_label(to_state)}."
                if from_state is not None and to_state is not None
                else "Task state changed."
            )
    elif event.event_type == STEERING_EVENT_TYPE:
        kind = "ACTIVITY"
        summary = (
            "In-scope clarification recorded."
            if event.payload.get("classification")
            == SteeringClassification.CLARIFICATION.value
            else "Scope-changing steering recorded."
        )
    elif event.event_type == "APPROVAL_REQUESTED":
        kind = "APPROVAL"
        summary = "Human approval requested."
    elif event.event_type == "APPROVAL_EXPIRED":
        kind = "APPROVAL"
        summary = "An approval request expired."
    elif event.event_type == "APPROVAL_DECIDED":
        kind = "APPROVAL"
        summary = "A human approval decision was recorded."
    elif event.event_type == GITHUB_PR_BOUND_EVENT:
        kind = "ACTIVITY"
        summary = "Pull request linked to this task."
    elif event.event_type == GITHUB_CHECK_UPDATED_EVENT:
        kind = "ACTIVITY"
        summary = f"GitHub check is {str(event.payload.get('state', 'updated')).lower()}."
    elif event.event_type == GITHUB_REVIEW_UPDATED_EVENT:
        kind = "ACTIVITY"
        summary = "GitHub review activity was recorded."
    elif event.event_type == GITHUB_PULL_REQUEST_UPDATED_EVENT:
        kind = "ACTIVITY"
        summary = "Pull request state was updated."
    elif event.event_type == GITHUB_PR_HEAD_CHANGED_EVENT:
        kind = "ACTIVITY"
        summary = "Pull request head changed; prior GitHub status was invalidated."
    else:
        kind = "ACTIVITY"
        summary = "Task activity was recorded."
    return TaskEventResponse(
        id=event.id,
        sequence=event.sequence,
        kind=kind,
        summary=summary,
        occurred_at=_as_utc(event.occurred_at),
        from_state=from_state,
        to_state=to_state,
        evidence_count=evidence_count,
    )


def _evidence_response(
    record: EvidenceRecord,
    *,
    deletion_request: EvidenceDeletionRequest | None,
    tombstone: EvidenceTombstone | None,
    corrected_by_id: UUID | None,
    authentication: AuthenticatedSession,
    now: datetime,
) -> TaskEvidenceResponse:
    deleted = deletion_request is not None or record.deleted_at is not None
    status_value: Literal["AVAILABLE", "CORRECTION", "SUPERSEDED", "DELETED"]
    if deleted:
        status_value = "DELETED"
    elif corrected_by_id is not None:
        status_value = "SUPERSEDED"
    elif record.correction_of_id is not None:
        status_value = "CORRECTION"
    else:
        status_value = "AVAILABLE"
    content_access: Literal[
        "AVAILABLE",
        "RECENT_PASSWORD_REQUIRED",
        "DELETED",
    ]
    if deleted:
        content_access = "DELETED"
    elif record.access_classification == "RECENT_PASSWORD" and not (
        authentication.recent_password_verified
        and _as_utc(authentication.reauthenticated_until) > now
    ):
        content_access = "RECENT_PASSWORD_REQUIRED"
    else:
        content_access = "AVAILABLE"
    return TaskEvidenceResponse(
        id=record.id,
        evidence_type=record.evidence_type,
        captured_at=_as_utc(record.captured_at),
        status=status_value,
        category=_evidence_category(record.evidence_type),
        content_access=content_access,
        correction_of_id=record.correction_of_id,
        corrected_by_id=corrected_by_id,
        deletion_reason=(
            None
            if deletion_request is None
            else cast(
                Literal[
                    "USER_REQUEST",
                    "RETENTION_EXPIRED",
                    "SOURCE_REVOKED",
                    "SECURITY_RESPONSE",
                ],
                deletion_request.reason_code,
            )
        ),
        deleted_at=(
            _as_utc(tombstone.deleted_at)
            if tombstone is not None
            else (
                None
                if record.deleted_at is None
                else _as_utc(record.deleted_at)
            )
        ),
        download_path=(
            f"/api/evidence/{record.id}/download"
            if content_access == "AVAILABLE"
            else None
        ),
    )


def _evidence_category(
    evidence_type: str,
) -> Literal[
    "CRITERIA",
    "CHANGE",
    "TEST",
    "LOG",
    "NETWORK",
    "PR_CI",
    "ARTIFACT",
    "OTHER",
]:
    normalized = evidence_type.casefold()
    if any(token in normalized for token in ("brief", "criterion", "contract")):
        return "CRITERIA"
    if any(token in normalized for token in ("diff", "patch", "commit", "code-change")):
        return "CHANGE"
    if any(token in normalized for token in ("artifact", "screenshot", "video", "attachment")):
        return "ARTIFACT"
    if any(token in normalized for token in ("network", "performance", "metric")):
        return "NETWORK"
    if any(token in normalized for token in ("github", "pull-request", "review", "ci-")):
        return "PR_CI"
    if any(token in normalized for token in ("log", "console", "crash", "error-signal")):
        return "LOG"
    if any(token in normalized for token in ("test", "build", "validation", "simulator")):
        return "TEST"
    return "OTHER"


def _acceptance_criteria_response(
    brief: Brief | None,
    validation_run: ValidationRun | None = None,
    validation_contract: ValidationContract | None = None,
) -> list[TaskAcceptanceCriterionResponse]:
    if brief is None:
        return []
    result: list[TaskAcceptanceCriterionResponse] = []
    seen_criterion_ids: set[str] = set()
    allowed_verifications = {
        "AUTOMATED_TEST",
        "SIMULATOR_ASSERTION",
        "STATIC_CHECK",
        "HUMAN_INSPECTION",
    }
    recorded_results = _recorded_criterion_results(
        validation_run,
        validation_contract,
    )
    for value in brief.acceptance_criteria:
        if not isinstance(value, dict):
            continue
        criterion_id = value.get("criterion_id")
        requirement = value.get("requirement")
        verification = value.get("verification")
        if (
            not isinstance(criterion_id, str)
            or not criterion_id
            or len(criterion_id) > 128
            or not isinstance(requirement, str)
            or not requirement
            or len(requirement) > 2_000
            or not isinstance(verification, str)
            or verification not in allowed_verifications
        ):
            continue
        if criterion_id in seen_criterion_ids:
            continue
        seen_criterion_ids.add(criterion_id)
        recorded = recorded_results.get(criterion_id)
        result.append(
            TaskAcceptanceCriterionResponse(
                id=criterion_id,
                requirement=requirement,
                verification=cast(
                    Literal[
                        "AUTOMATED_TEST",
                        "SIMULATOR_ASSERTION",
                        "STATIC_CHECK",
                        "HUMAN_INSPECTION",
                    ],
                    verification,
                ),
                status=(
                    "PENDING"
                    if recorded is None
                    else cast(
                        Literal["PENDING", "PASSED", "FAILED", "BLOCKED"],
                        recorded["status"],
                    )
                ),
                validation_run_id=(
                    None
                    if recorded is None
                    else cast(UUID, recorded["validation_run_id"])
                ),
                validation_contract_version=(
                    None
                    if recorded is None
                    else cast(int, recorded["validation_contract_version"])
                ),
                commit_sha=(
                    None if recorded is None else cast(str, recorded["commit_sha"])
                ),
                tree_sha=(
                    None if recorded is None else cast(str, recorded["tree_sha"])
                ),
                evidence_ids=(
                    [] if recorded is None else cast(list[UUID], recorded["evidence_ids"])
                ),
                assertions=(
                    []
                    if recorded is None
                    else cast(
                        list[TaskAcceptanceAssertionResponse],
                        recorded["assertions"],
                    )
                ),
            )
        )
    return result


def _recorded_criterion_results(
    validation_run: ValidationRun | None,
    validation_contract: ValidationContract | None,
) -> dict[str, dict[str, object]]:
    if (
        validation_run is None
        or validation_contract is None
        or validation_run.validation_contract_id != validation_contract.id
    ):
        return {}
    result: dict[str, dict[str, object]] = {}
    allowed_statuses = {"PENDING", "PASSED", "FAILED", "BLOCKED"}
    allowed_kinds = {kind.value for kind in AssertionKind}
    for value in validation_run.acceptance_criterion_results:
        if not isinstance(value, dict):
            continue
        criterion_id = value.get("criterion_id")
        status_value = value.get("status")
        contract_version = value.get("validation_contract_version")
        commit_sha = value.get("commit_sha")
        tree_sha = value.get("tree_sha")
        raw_evidence_ids = value.get("evidence_ids")
        raw_assertions = value.get("assertions")
        if (
            not isinstance(criterion_id, str)
            or not criterion_id
            or status_value not in allowed_statuses
            or contract_version != validation_contract.version
            or commit_sha != validation_run.commit_sha
            or tree_sha != validation_run.tree_sha
            or not isinstance(raw_evidence_ids, list)
            or not isinstance(raw_assertions, list)
            or not raw_assertions
        ):
            continue
        try:
            evidence_ids = [UUID(item) for item in raw_evidence_ids if isinstance(item, str)]
        except ValueError:
            continue
        if len(evidence_ids) != len(raw_evidence_ids):
            continue
        assertions: list[TaskAcceptanceAssertionResponse] = []
        seen_assertion_ids: set[str] = set()
        valid = True
        for assertion in raw_assertions:
            if not isinstance(assertion, dict):
                valid = False
                break
            assertion_id = assertion.get("assertion_id")
            kind = assertion.get("kind")
            catalog_key = assertion.get("verifier_catalog_key")
            assertion_status = assertion.get("status")
            result_code = assertion.get("result_code")
            raw_assertion_evidence = assertion.get("evidence_ids")
            if (
                not isinstance(assertion_id, str)
                or not assertion_id
                or kind not in allowed_kinds
                or not isinstance(catalog_key, str)
                or not catalog_key
                or assertion_status not in allowed_statuses
                or not isinstance(result_code, str)
                or not result_code
                or not isinstance(raw_assertion_evidence, list)
                or assertion_id in seen_assertion_ids
            ):
                valid = False
                break
            try:
                assertion_evidence = [
                    UUID(item)
                    for item in raw_assertion_evidence
                    if isinstance(item, str)
                ]
            except ValueError:
                valid = False
                break
            if (
                len(assertion_evidence) != len(raw_assertion_evidence)
                or len(assertion_evidence) != len(set(assertion_evidence))
                or (
                    assertion_status == "PENDING" and bool(assertion_evidence)
                )
                or (
                    assertion_status != "PENDING" and not assertion_evidence
                )
            ):
                valid = False
                break
            seen_assertion_ids.add(assertion_id)
            assertions.append(
                TaskAcceptanceAssertionResponse(
                    assertion_id=assertion_id,
                    kind=cast(
                        Literal[
                            "ELEMENT_VALUE_PRESENT",
                            "NAVIGATION_STATE_REACHED",
                            "EXPECTED_NETWORK_RESPONSE",
                            "EXPECTED_LOG_EVENT",
                            "NO_CRASH",
                        ],
                        kind,
                    ),
                    verifier_catalog_key=catalog_key,
                    status=cast(
                        Literal["PENDING", "PASSED", "FAILED", "BLOCKED"],
                        assertion_status,
                    ),
                    result_code=result_code,
                    evidence_ids=assertion_evidence,
                )
            )
        assertion_evidence_ids = {
            evidence_id
            for assertion in assertions
            for evidence_id in assertion.evidence_ids
        }
        assertion_statuses = {assertion.status for assertion in assertions}
        expected_status = (
            "FAILED"
            if "FAILED" in assertion_statuses
            else "BLOCKED"
            if "BLOCKED" in assertion_statuses
            else "PENDING"
            if "PENDING" in assertion_statuses
            else "PASSED"
        )
        if (
            not valid
            or criterion_id in result
            or len(evidence_ids) != len(set(evidence_ids))
            or set(evidence_ids) != assertion_evidence_ids
            or status_value != expected_status
        ):
            continue
        result[criterion_id] = {
            "status": status_value,
            "validation_run_id": validation_run.id,
            "validation_contract_version": contract_version,
            "commit_sha": commit_sha,
            "tree_sha": tree_sha,
            "evidence_ids": evidence_ids,
            "assertions": assertions,
        }
    return result


def _approval_response(request: ApprovalRequest) -> TaskApprovalResponse:
    labels = {
        "BRIEF": "Brief approval",
        "UNSAFE_ACTION": "Unsafe action approval",
        "RETRY_LIMIT": "Retry-limit decision",
        "REVIEW_CONFLICT": "Review conflict decision",
        "REVIEW_RULE": "Review rule decision",
    }
    return TaskApprovalResponse(
        id=request.id,
        type_label=labels.get(request.request_type, "Human decision"),
        status=ApprovalStatus(request.status),
        requesting_state=TaskState(request.requesting_state),
        resume_state=(
            None
            if request.resume_state is None
            else TaskState(request.resume_state)
        ),
        created_at=_as_utc(request.created_at),
        expires_at=(
            None if request.expires_at is None else _as_utc(request.expires_at)
        ),
    )


def _task_response(
    task: Task,
    *,
    last_activity_at: datetime,
    blockers: Sequence[TaskBlockerResponse],
) -> TaskSummaryResponse:
    return TaskSummaryResponse(
        id=task.id,
        summary=task.summary,
        state=TaskState(task.state),
        repository=task.repository,
        base_revision=task.base_revision,
        created_at=_as_utc(task.created_at),
        last_activity_at=_as_utc(last_activity_at),
        blockers=list(blockers),
        cockpit_path=f"/tasks/{task.id}",
    )


class TaskBodyLimitMiddleware:
    """Bound task-intake JSON before request parsing buffers it."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        maximum_bytes: int = MAX_TASK_REQUEST_BYTES,
    ) -> None:
        self._app = app
        self._maximum_bytes = maximum_bytes

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        bounded = (
            scope["type"] == "http"
            and scope.get("method") == "POST"
            and self._bounded_path(str(scope.get("path", "")))
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
    def _bounded_path(path: str) -> bool:
        if path == "/api/tasks":
            return True
        parts = path.split("/")
        return (
            len(parts) == 5
            and parts[:3] == ["", "api", "tasks"]
            and bool(parts[3])
            and parts[4] in {"steering", "cancellations"}
        )

    @staticmethod
    def _content_length(scope: Scope) -> int | None:
        for name, value in scope["headers"]:
            if name.lower() != b"content-length":
                continue
            try:
                parsed = int(value)
            except ValueError:
                return None
            return max(0, parsed)
        return None

    @staticmethod
    async def _send_too_large(
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        response = JSONResponse(
            {"detail": "task request body too large"},
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )
        await response(scope, receive, send)


def create_task_router(service: TaskService) -> APIRouter:
    router = APIRouter(prefix="/api/tasks", tags=["tasks"])

    @router.get("", response_model=TaskListResponse)
    def list_tasks(
        authentication: AuthenticatedTaskSession,
        response: Response,
    ) -> TaskListResponse:
        response.headers["Cache-Control"] = "no-store"
        try:
            return service.list(authentication)
        except TaskAccessError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="tasks unavailable",
            ) from None

    @router.get("/{task_id}", response_model=TaskCockpitResponse)
    def task_detail(
        task_id: UUID,
        authentication: AuthenticatedTaskSession,
        response: Response,
    ) -> TaskCockpitResponse:
        response.headers["Cache-Control"] = "no-store"
        try:
            return service.detail(task_id, authentication)
        except (TaskAccessError, TaskNotFoundError):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="task unavailable",
            ) from None

    @router.post(
        "/{task_id}/steering",
        response_model=TaskSteeringResponse,
    )
    def steer_task(
        task_id: UUID,
        body: TaskSteeringRequest,
        authentication: AuthenticatedTaskSession,
        response: Response,
    ) -> TaskSteeringResponse:
        response.headers["Cache-Control"] = "no-store"
        try:
            return service.steer(task_id, body, authentication)
        except (TaskAccessError, SteeringNotFoundError):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="task unavailable",
            ) from None
        except (SteeringConflictError, TaskTransitionError):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="task steering conflicts with durable state",
            ) from None

    @router.post(
        "/{task_id}/cancellations",
        response_model=TaskCancellationResponse,
    )
    def cancel_task(
        task_id: UUID,
        body: TaskCancellationRequest,
        authentication: AuthenticatedTaskSession,
        response: Response,
    ) -> TaskCancellationResponse:
        response.headers["Cache-Control"] = "no-store"
        try:
            return service.cancel(task_id, body, authentication)
        except PermissionError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="recent password authentication required",
            ) from None
        except (TaskAccessError, TaskNotFoundError, BackgroundJobNotFoundError):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="task unavailable",
            ) from None
        except (
            BackgroundJobConflictError,
            ReliabilityConflictError,
            TaskTransitionError,
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="task cancellation conflicts with durable state",
            ) from None

    @router.get("/{task_id}/events")
    async def task_events(
        task_id: UUID,
        request: Request,
        authentication: AuthenticatedTaskSession,
    ) -> StreamingResponse:
        try:
            after_sequence = _last_event_sequence(
                request.headers.get("last-event-id")
            )
            initial_events = await run_in_threadpool(
                service.events_after,
                task_id,
                authentication,
                after_sequence=after_sequence,
            )
        except InvalidTaskEventCursorError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid task event cursor",
            ) from None
        except (TaskAccessError, TaskNotFoundError):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="task unavailable",
            ) from None

        return StreamingResponse(
            _task_event_stream(
                request,
                service,
                task_id,
                authentication,
                after_sequence=after_sequence,
                initial_events=initial_events,
            ),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    @router.post(
        "",
        response_model=TaskSummaryResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def create_task(
        body: TaskCreateRequest,
        authentication: AuthenticatedTaskSession,
        response: Response,
    ) -> TaskSummaryResponse:
        response.headers["Cache-Control"] = "no-store"
        try:
            return service.create(body, authentication)
        except TaskAccessError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="tasks unavailable",
            ) from None

    return router
