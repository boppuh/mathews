"""Authenticated task intake and work-queue projections."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.authentication import (
    AuthenticatedSession,
    require_authenticated_session,
)
from mathews_control_plane.database import SessionFactory, create_task_record
from mathews_control_plane.domain_models import (
    ApprovalRequest,
    ApprovalStatus,
    BackgroundJob,
    DependencyOutageAttempt,
    EvidenceRecord,
    ReconciliationStatus,
    ReconciliationTarget,
    Task,
    TaskEvent,
    TaskEventEvidenceReference,
    TaskState,
)
from mathews_control_plane.evidence import redact_evidence_content

TASK_INTAKE_EVENT_TYPE = "TASK_CREATED"
TASK_INTAKE_EVENT_SCHEMA_VERSION = 1
MAX_TASK_REQUEST_CHARACTERS = 20_000
MAX_TASK_REQUEST_BYTES = 64 * 1024
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
    status: Literal["AVAILABLE", "CORRECTION", "DELETED"]


class TaskApprovalResponse(BaseModel):
    id: UUID
    type_label: str
    status: ApprovalStatus
    requesting_state: TaskState
    resume_state: TaskState | None = None
    created_at: datetime
    expires_at: datetime | None = None


class TaskCockpitResponse(BaseModel):
    task: TaskSummaryResponse
    state_context: TaskStateContextResponse
    events: list[TaskEventResponse]
    evidence: list[TaskEvidenceResponse]
    approvals: list[TaskApprovalResponse]


class TaskNotFoundError(RuntimeError):
    """The task is absent or outside the authenticated owner's scope."""


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
                    )
                    .order_by(EvidenceRecord.captured_at, EvidenceRecord.id)
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
                evidence=[_evidence_response(record) for record in evidence],
                approvals=[_approval_response(request) for request in approvals],
            )


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
        }[state],
    )


def _state_label(state: TaskState) -> str:
    acronyms = {"PR"}
    return " ".join(
        part if part in acronyms else part.title()
        for part in state.value.split("_")
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
        summary = (
            f"State changed from {_state_label(from_state)} "
            f"to {_state_label(to_state)}."
            if from_state is not None and to_state is not None
            else "Task state changed."
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


def _evidence_response(record: EvidenceRecord) -> TaskEvidenceResponse:
    status_value: Literal["AVAILABLE", "CORRECTION", "DELETED"]
    if record.deleted_at is not None:
        status_value = "DELETED"
    elif record.correction_of_id is not None:
        status_value = "CORRECTION"
    else:
        status_value = "AVAILABLE"
    return TaskEvidenceResponse(
        id=record.id,
        evidence_type=record.evidence_type,
        captured_at=_as_utc(record.captured_at),
        status=status_value,
    )


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
            and scope.get("path") == "/api/tasks"
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
