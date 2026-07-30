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
        created_at=task.created_at,
        last_activity_at=last_activity_at,
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
