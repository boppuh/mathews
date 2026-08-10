"""Verified, durable GitHub webhook intake and task correlation."""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request, Response, status
from mathews_configuration import GITHUB_WEBHOOK_EVENTS, GitHubAppConfiguration
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mathews_control_plane.api_paths import GITHUB_WEBHOOK_ENDPOINT
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    BackgroundJob,
    BackgroundJobStatus,
    EvidenceRecord,
    Task,
    TaskEvent,
    TaskEventEvidenceReference,
    TaskState,
    WebhookDelivery,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
    load_evidence,
)
from mathews_control_plane.github_app import (
    GitHubWebhookVerificationError,
    GitHubWebhookVerifier,
)

GITHUB_PR_BOUND_EVENT = "GITHUB_PR_BOUND"
GITHUB_CHECK_UPDATED_EVENT = "GITHUB_CHECK_UPDATED"
GITHUB_REVIEW_UPDATED_EVENT = "GITHUB_REVIEW_UPDATED"
GITHUB_PULL_REQUEST_UPDATED_EVENT = "GITHUB_PULL_REQUEST_UPDATED"
MAX_GITHUB_WEBHOOK_BYTES = 1024 * 1024
MAX_GITHUB_WEBHOOK_CHUNKS = 1024

_OWNER = "local-user"
_ACTOR = "github-webhook"
_DELIVERY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,254}\Z")
_BRANCH_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,254}\Z")
_SHA_PATTERN = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_TERMINAL_STATES = frozenset(
    {TaskState.HANDED_OFF, TaskState.FAILED, TaskState.CANCELLED}
)
_EVENT_ACTIONS = {
    "check_run": frozenset({"created", "rerequested", "completed", "requested_action"}),
    "pull_request": frozenset(
        {
            "opened",
            "closed",
            "reopened",
            "synchronize",
            "converted_to_draft",
            "ready_for_review",
        }
    ),
    "pull_request_review": frozenset({"submitted", "edited", "dismissed"}),
    "pull_request_review_comment": frozenset({"created", "edited", "deleted"}),
}


class GitHubWebhookPayloadError(ValueError):
    """The verified delivery is not a bounded canonical JSON object."""


class GitHubWebhookConflictError(RuntimeError):
    """A delivery identifier was reused for different raw bytes."""


class GitHubWebhookIngestionResponse(BaseModel):
    delivery_id: UUID
    disposition: Literal["ACCEPTED", "REPLAYED", "STALE", "QUARANTINED"]
    task_id: UUID | None = None
    event_id: UUID | None = None
    job_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class _WebhookUpdate:
    event_type: str
    installation_id: int
    repository_id: int
    repository_key: str
    pull_request_number: int
    task_branch: str
    head_sha: str
    action: str
    resource_type: str
    resource_id: str
    resource_label: str
    state: str
    source_updated_at: datetime

    def event_payload(self, delivery: WebhookDelivery) -> dict[str, object]:
        return {
            "schema_version": 1,
            "delivery_id": delivery.provider_delivery_id,
            "event_name": cast(dict[str, object], delivery.processing_result)[
                "event_name"
            ],
            "action": self.action,
            "installation_id": self.installation_id,
            "repository_id": self.repository_id,
            "repository_key": self.repository_key,
            "pull_request_number": self.pull_request_number,
            "task_branch": self.task_branch,
            "head_sha": self.head_sha,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "resource_label": self.resource_label,
            "state": self.state,
            "source_updated_at": _timestamp(self.source_updated_at),
        }


class GitHubWebhookService:
    """Store verified delivery evidence before idempotent task processing."""

    def __init__(
        self,
        session_factory: SessionFactory,
        artifact_store: ArtifactStore,
        configuration: GitHubAppConfiguration,
        *,
        verifier: GitHubWebhookVerifier,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._factory = session_factory
        self._store = artifact_store
        self._configuration = configuration
        self._verifier = verifier
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.RLock()

    def bind_pull_request(
        self,
        task_id: UUID,
        *,
        installation_id: int,
        repository_id: int,
        pull_request_number: int,
        task_branch: str,
        head_sha: str,
    ) -> UUID:
        """Append the exact PR identity used by all later webhook correlation."""

        with self._lock:
            return self._bind_pull_request(
                task_id,
                installation_id=installation_id,
                repository_id=repository_id,
                pull_request_number=pull_request_number,
                task_branch=task_branch,
                head_sha=head_sha,
            )

    def _bind_pull_request(
        self,
        task_id: UUID,
        *,
        installation_id: int,
        repository_id: int,
        pull_request_number: int,
        task_branch: str,
        head_sha: str,
    ) -> UUID:

        branch = _required_branch(task_branch)
        sha = _required_sha(head_sha)
        if (
            installation_id != self._configuration.installation_id
            or repository_id != self._configuration.repository_id
            or pull_request_number <= 0
        ):
            raise GitHubWebhookPayloadError("pull request binding is invalid")
        payload: dict[str, object] = {
            "schema_version": 1,
            "installation_id": installation_id,
            "repository_id": repository_id,
            "repository_key": self._configuration.repository_key,
            "pull_request_number": pull_request_number,
            "task_branch": branch,
            "head_sha": sha,
        }
        with self._factory.begin() as session:
            task = session.scalar(
                select(Task).where(Task.id == task_id).with_for_update()
            )
            if (
                task is None
                or task.owner_id != _OWNER
                or task.repository.casefold() != self._configuration.repository_key
                or TaskState(task.state) in _TERMINAL_STATES
            ):
                raise GitHubWebhookPayloadError("task cannot be bound")
            current = _latest_binding(session, task.id)
            if current is not None and current.payload == payload:
                return current.id
            event = _append_task_event(
                session,
                task,
                event_type=GITHUB_PR_BOUND_EVENT,
                payload=payload,
                occurred_at=_utc(self._clock()),
                causation_id=task.id,
            )
            return event.id

    def ingest(
        self,
        *,
        event_name: str | None,
        delivery_id: str | None,
        signature_header: str | None,
        body: bytes,
    ) -> GitHubWebhookIngestionResponse:
        with self._lock:
            return self._ingest(
                event_name=event_name,
                delivery_id=delivery_id,
                signature_header=signature_header,
                body=body,
            )

    def _ingest(
        self,
        *,
        event_name: str | None,
        delivery_id: str | None,
        signature_header: str | None,
        body: bytes,
    ) -> GitHubWebhookIngestionResponse:
        verified = self._verifier.verify(
            signature_header=signature_header,
            body=body,
        )
        normalized_delivery = _required_delivery_id(delivery_id)
        normalized_event = _required_event_name(event_name)
        payload = _decode_payload(body)
        now = _utc(self._clock())

        with self._factory.begin() as session:
            existing = session.scalar(
                select(WebhookDelivery).where(
                    WebhookDelivery.provider == "github",
                    WebhookDelivery.provider_delivery_id == normalized_delivery,
                )
            )
            if existing is not None:
                prior_result = cast(
                    dict[str, object],
                    existing.processing_result or {},
                )
                if prior_result.get("body_sha256") != verified.body_sha256:
                    raise GitHubWebhookConflictError(
                        "delivery identifier does not match the original body"
                    )
                existing_id = existing.id
            else:
                delivery_uuid = uuid4()
                captured = capture_evidence(
                    session,
                    self._store,
                    payload={
                        "schema_version": 1,
                        "provider_delivery_id": normalized_delivery,
                        "event_name": normalized_event,
                        "verification": verified.to_dict(),
                        "payload": payload,
                    },
                    media_type="application/json",
                    source_kind=EvidenceSourceKind.EXTERNAL_EVENT,
                    evidence_type="github-webhook",
                    origin="github:webhook",
                    access_classification=EvidenceAccessClass.INTERNAL,
                    retention_policy=EvidenceRetentionClass.AUDIT,
                    owner_id=_OWNER,
                    actor_id=_ACTOR,
                    root_correlation_id=delivery_uuid,
                    causation_id=delivery_uuid,
                    captured_at=now,
                )
                identity = _best_effort_identity(payload)
                delivery = WebhookDelivery(
                    id=delivery_uuid,
                    provider="github",
                    provider_delivery_id=normalized_delivery,
                    installation_id=identity[0],
                    repository_id=identity[1],
                    pull_request_number=identity[2],
                    head_sha=identity[3],
                    signature_verified=True,
                    payload_evidence_id=captured.record.id,
                    processing_result={
                        "stage": "RECEIVED",
                        "body_sha256": verified.body_sha256,
                        "event_name": normalized_event,
                    },
                    quarantine_reason=None,
                    received_at=now,
                    processed_at=None,
                    owner_id=_OWNER,
                    actor_id=_ACTOR,
                    root_correlation_id=delivery_uuid,
                    causation_id=delivery_uuid,
                )
                session.add(delivery)
                session.flush()
                existing_id = delivery.id

        processed = self._process(existing_id)
        if existing is not None:
            return processed.model_copy(update={"disposition": "REPLAYED"})
        return processed

    def process_pending(self, *, limit: int = 100) -> int:
        if not 1 <= limit <= 1000:
            raise ValueError("pending webhook limit is invalid")
        with self._factory() as session:
            ids = tuple(
                session.scalars(
                    select(WebhookDelivery.id)
                    .where(
                        WebhookDelivery.provider == "github",
                        WebhookDelivery.processed_at.is_(None),
                    )
                    .order_by(WebhookDelivery.received_at, WebhookDelivery.id)
                    .limit(limit)
                )
            )
        with self._lock:
            for delivery_id in ids:
                self._process(delivery_id)
        return len(ids)

    def _process(self, delivery_id: UUID) -> GitHubWebhookIngestionResponse:
        now = _utc(self._clock())
        with self._factory.begin() as session:
            delivery = session.scalar(
                select(WebhookDelivery)
                .where(WebhookDelivery.id == delivery_id)
                .with_for_update()
            )
            if delivery is None:
                raise GitHubWebhookPayloadError("delivery is unavailable")
            prior = cast(dict[str, object], delivery.processing_result or {})
            if delivery.processed_at is not None:
                return GitHubWebhookIngestionResponse(
                    delivery_id=delivery.id,
                    disposition=cast(
                        Literal["ACCEPTED", "REPLAYED", "STALE", "QUARANTINED"],
                        prior.get("disposition", "QUARANTINED"),
                    ),
                    task_id=_optional_uuid(prior.get("task_id")),
                    event_id=_optional_uuid(prior.get("event_id")),
                    job_id=_optional_uuid(prior.get("job_id")),
                )
            if delivery.payload_evidence_id is None:
                return self._quarantine(session, delivery, "payload_evidence_missing", now)
            evidence = session.get(EvidenceRecord, delivery.payload_evidence_id)
            if evidence is None:
                return self._quarantine(session, delivery, "payload_evidence_missing", now)
            loaded = load_evidence(session, self._store, evidence)
            captured = cast(dict[str, object], loaded.content)
            event_name = cast(str, captured.get("event_name", ""))
            payload = cast(dict[str, object], captured.get("payload"))
            try:
                update = _normalize_update(event_name, payload)
            except GitHubWebhookPayloadError as error:
                return self._quarantine(session, delivery, str(error), now)
            mismatch = _configuration_mismatch(update, self._configuration)
            if mismatch is not None:
                return self._quarantine(session, delivery, mismatch, now)
            delivery.installation_id = str(update.installation_id)
            delivery.repository_id = str(update.repository_id)
            delivery.pull_request_number = update.pull_request_number
            delivery.head_sha = update.head_sha

            candidates = _correlation_candidates(session, update)
            if not candidates:
                stale = _same_pr_different_head(session, update)
                if stale is not None:
                    return self._finish(
                        delivery,
                        disposition="STALE",
                        now=now,
                        task=stale,
                        reason="head_sha_not_current",
                    )
                return self._quarantine(session, delivery, "correlation_unknown", now)
            if len(candidates) != 1:
                return self._quarantine(session, delivery, "correlation_ambiguous", now)
            task = session.scalar(
                select(Task).where(Task.id == candidates[0].id).with_for_update()
            )
            if task is None:
                return self._quarantine(session, delivery, "correlation_unknown", now)
            if TaskState(task.state) in _TERMINAL_STATES:
                return self._quarantine(session, delivery, "task_not_active", now)

            previous = _latest_resource_event(session, task.id, update)
            if previous is not None:
                previous_at = _parse_timestamp(
                    previous.payload.get("source_updated_at"),
                    "source_updated_at",
                )
                if update.source_updated_at <= previous_at:
                    return self._finish(
                        delivery,
                        disposition="STALE",
                        now=now,
                        task=task,
                        reason="source_update_not_newer",
                    )

            event = _append_task_event(
                session,
                task,
                event_type=update.event_type,
                payload=update.event_payload(delivery),
                occurred_at=now,
                causation_id=delivery.id,
                parent_correlation_id=delivery.id,
            )
            session.add(
                TaskEventEvidenceReference(
                    task_id=task.id,
                    task_event_id=event.id,
                    evidence_id=evidence.id,
                    position=1,
                    owner_id=task.owner_id,
                    actor_id=_ACTOR,
                    root_correlation_id=task.root_correlation_id,
                    causation_id=event.id,
                    parent_correlation_id=delivery.id,
                )
            )
            job_payload: dict[str, object] = {
                "schema_version": 1,
                "delivery_id": delivery.provider_delivery_id,
                "task_event_id": str(event.id),
                "head_sha": update.head_sha,
            }
            job = BackgroundJob(
                task_id=task.id,
                job_type="github-webhook",
                input_payload=job_payload,
                input_fingerprint=_fingerprint(job_payload),
                status=BackgroundJobStatus.QUEUED,
                idempotency_key=f"github-webhook:{delivery.provider_delivery_id}",
                attempt_count=0,
                max_attempts=5,
                retry_base_seconds=1,
                retry_max_seconds=300,
                available_at=now,
                checkpoint_version=0,
                owner_id=task.owner_id,
                actor_id=_ACTOR,
                root_correlation_id=task.root_correlation_id,
                causation_id=event.id,
                parent_correlation_id=delivery.id,
            )
            session.add(job)
            session.flush()
            return self._finish(
                delivery,
                disposition="ACCEPTED",
                now=now,
                task=task,
                event=event,
                job=job,
            )

    def _quarantine(
        self,
        _session: Session,
        delivery: WebhookDelivery,
        reason: str,
        now: datetime,
    ) -> GitHubWebhookIngestionResponse:
        delivery.quarantine_reason = reason[:500]
        return self._finish(
            delivery,
            disposition="QUARANTINED",
            now=now,
            reason=reason,
        )

    @staticmethod
    def _finish(
        delivery: WebhookDelivery,
        *,
        disposition: Literal["ACCEPTED", "STALE", "QUARANTINED"],
        now: datetime,
        task: Task | None = None,
        event: TaskEvent | None = None,
        job: BackgroundJob | None = None,
        reason: str | None = None,
    ) -> GitHubWebhookIngestionResponse:
        prior = cast(dict[str, object], delivery.processing_result or {})
        delivery.processing_result = {
            **prior,
            "stage": "PROCESSED",
            "disposition": disposition,
            "reason": reason,
            "task_id": None if task is None else str(task.id),
            "event_id": None if event is None else str(event.id),
            "job_id": None if job is None else str(job.id),
        }
        delivery.processed_at = now
        return GitHubWebhookIngestionResponse(
            delivery_id=delivery.id,
            disposition=disposition,
            task_id=None if task is None else task.id,
            event_id=None if event is None else event.id,
            job_id=None if job is None else job.id,
        )


def create_github_webhook_router(service: GitHubWebhookService) -> APIRouter:
    router = APIRouter(prefix="/api/github", tags=["github-webhooks"])

    @router.post(
        "/webhooks",
        response_model=GitHubWebhookIngestionResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def receive_webhook(request: Request, response: Response) -> object:
        try:
            result = await run_in_threadpool(
                service.ingest,
                event_name=request.headers.get("X-GitHub-Event"),
                delivery_id=request.headers.get("X-GitHub-Delivery"),
                signature_header=request.headers.get("X-Hub-Signature-256"),
                body=await request.body(),
            )
        except GitHubWebhookVerificationError as error:
            code = (
                status.HTTP_503_SERVICE_UNAVAILABLE
                if error.code == "webhook.secret_unavailable"
                else status.HTTP_401_UNAUTHORIZED
            )
            raise HTTPException(code, "webhook verification failed") from None
        except GitHubWebhookPayloadError:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid webhook") from None
        except GitHubWebhookConflictError:
            raise HTTPException(status.HTTP_409_CONFLICT, "webhook delivery conflict") from None
        response.headers["Cache-Control"] = "no-store"
        if result.disposition == "REPLAYED":
            response.status_code = status.HTTP_200_OK
        return result

    return router


class GitHubWebhookBodyLimitMiddleware:
    """Bound the exact external body before FastAPI buffers it."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or (scope["method"], scope["path"]) != (
            "POST",
            GITHUB_WEBHOOK_ENDPOINT,
        ):
            await self._app(scope, receive, send)
            return
        captured: list[Message] = []
        received = 0
        chunks = 0
        while True:
            message = await receive()
            captured.append(message)
            if message["type"] == "http.disconnect":
                break
            if message["type"] != "http.request":
                continue
            chunks += 1
            received += len(message.get("body", b""))
            if received > MAX_GITHUB_WEBHOOK_BYTES or chunks > MAX_GITHUB_WEBHOOK_CHUNKS:
                response = JSONResponse(
                    {"detail": "webhook request body too large"},
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    headers={"Cache-Control": "no-store"},
                )
                await response(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        index = 0

        async def replay() -> Message:
            nonlocal index
            if index < len(captured):
                message = captured[index]
                index += 1
                return message
            return await receive()

        await self._app(scope, replay, send)


def _decode_payload(body: bytes) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(
            body.decode("utf-8", "strict"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise GitHubWebhookPayloadError("payload_invalid") from None
    if not isinstance(value, dict):
        raise GitHubWebhookPayloadError("payload_not_object")
    nodes = 0
    pending: list[tuple[object, int]] = [(value, 1)]
    while pending:
        candidate, depth = pending.pop()
        nodes += 1
        if nodes > 100_000 or depth > 32:
            raise GitHubWebhookPayloadError("payload_bounds_exceeded")
        if isinstance(candidate, dict):
            for key, child in candidate.items():
                if len(key) > 10_000:
                    raise GitHubWebhookPayloadError("payload_bounds_exceeded")
                pending.append((child, depth + 1))
        elif isinstance(candidate, list):
            pending.extend((child, depth + 1) for child in candidate)
        elif isinstance(candidate, str) and len(candidate) > MAX_GITHUB_WEBHOOK_BYTES:
            raise GitHubWebhookPayloadError("payload_bounds_exceeded")
    return cast(dict[str, object], value)


def _normalize_update(event_name: str, payload: dict[str, object]) -> _WebhookUpdate:
    if event_name not in GITHUB_WEBHOOK_EVENTS:
        raise GitHubWebhookPayloadError("event_not_allowed")
    installation = _mapping(payload, "installation")
    repository = _mapping(payload, "repository")
    installation_id = _positive_int(installation, "id")
    repository_id = _positive_int(repository, "id")
    repository_key = _required_string(repository, "full_name", 140).casefold()
    action = _required_string(payload, "action", 50)
    if action not in _EVENT_ACTIONS[event_name]:
        raise GitHubWebhookPayloadError("event_action_unknown")

    if event_name == "check_run":
        check = _mapping(payload, "check_run")
        prs = check.get("pull_requests")
        if not isinstance(prs, list) or len(prs) != 1 or not isinstance(prs[0], dict):
            raise GitHubWebhookPayloadError("check_pull_request_ambiguous")
        pr_number = _positive_int(cast(dict[str, object], prs[0]), "number")
        suite = _mapping(check, "check_suite")
        branch = _required_branch(_required_string(suite, "head_branch", 255))
        sha = _required_sha(_required_string(check, "head_sha", 64))
        status_value = _required_string(check, "status", 30)
        conclusion = check.get("conclusion")
        if status_value != "completed":
            state = "IN_PROGRESS" if status_value == "in_progress" else "QUEUED"
        elif conclusion in {"success", "neutral", "skipped"}:
            state = "PASSED" if conclusion == "success" else "NEUTRAL"
        elif conclusion in {"cancelled", "timed_out"}:
            state = "CANCELLED"
        else:
            state = "FAILED"
        return _WebhookUpdate(
            GITHUB_CHECK_UPDATED_EVENT,
            installation_id,
            repository_id,
            repository_key,
            pr_number,
            branch,
            sha,
            action,
            "check_run",
            str(_positive_int(check, "id")),
            _required_string(check, "name", 255),
            state,
            _parse_timestamp(check.get("updated_at"), "updated_at"),
        )

    pull_request = _mapping(payload, "pull_request")
    pr_number = _positive_int(pull_request, "number")
    head = _mapping(pull_request, "head")
    branch = _required_branch(_required_string(head, "ref", 255))
    sha = _required_sha(_required_string(head, "sha", 64))
    if event_name == "pull_request_review":
        review = _mapping(payload, "review")
        state = _required_string(review, "state", 40).upper()
        if state not in {"APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED"}:
            raise GitHubWebhookPayloadError("review_state_unknown")
        return _WebhookUpdate(
            GITHUB_REVIEW_UPDATED_EVENT,
            installation_id,
            repository_id,
            repository_key,
            pr_number,
            branch,
            sha,
            action,
            "review",
            str(_positive_int(review, "id")),
            "Pull request review",
            state,
            _parse_timestamp(
                review.get("submitted_at") or review.get("updated_at"),
                "review timestamp",
            ),
        )
    if event_name == "pull_request_review_comment":
        comment = _mapping(payload, "comment")
        return _WebhookUpdate(
            GITHUB_REVIEW_UPDATED_EVENT,
            installation_id,
            repository_id,
            repository_key,
            pr_number,
            branch,
            sha,
            action,
            "review_comment",
            str(_positive_int(comment, "id")),
            "Review comment",
            "DELETED" if action == "deleted" else "OPEN",
            _parse_timestamp(
                comment.get("updated_at") or comment.get("created_at"),
                "comment timestamp",
            ),
        )
    state = (
        "MERGED"
        if pull_request.get("merged") is True
        else _required_string(pull_request, "state", 20).upper()
    )
    if pull_request.get("draft") is True and state == "OPEN":
        state = "DRAFT"
    return _WebhookUpdate(
        GITHUB_PULL_REQUEST_UPDATED_EVENT,
        installation_id,
        repository_id,
        repository_key,
        pr_number,
        branch,
        sha,
        action,
        "pull_request",
        str(pr_number),
        f"Pull request #{pr_number}",
        state,
        _parse_timestamp(pull_request.get("updated_at"), "updated_at"),
    )


def _correlation_candidates(session: Session, update: _WebhookUpdate) -> list[Task]:
    return _binding_candidates(session, update, include_head=True)


def _same_pr_different_head(session: Session, update: _WebhookUpdate) -> Task | None:
    matches = _binding_candidates(session, update, include_head=False)
    return matches[0] if len(matches) == 1 else None


def _binding_candidates(
    session: Session,
    update: _WebhookUpdate,
    *,
    include_head: bool,
) -> list[Task]:
    latest_binding_sequence = (
        select(func.max(TaskEvent.sequence))
        .where(
            TaskEvent.task_id == Task.id,
            TaskEvent.event_type == GITHUB_PR_BOUND_EVENT,
        )
        .correlate(Task)
        .scalar_subquery()
    )
    filters = [
        TaskEvent.payload["installation_id"].as_integer() == update.installation_id,
        TaskEvent.payload["repository_id"].as_integer() == update.repository_id,
        TaskEvent.payload["repository_key"].as_string() == update.repository_key,
        TaskEvent.payload["pull_request_number"].as_integer()
        == update.pull_request_number,
        TaskEvent.payload["task_branch"].as_string() == update.task_branch,
    ]
    if include_head:
        filters.append(TaskEvent.payload["head_sha"].as_string() == update.head_sha)
    return list(
        session.scalars(
            select(Task)
            .join(TaskEvent, TaskEvent.task_id == Task.id)
            .where(
                Task.owner_id == _OWNER,
                TaskEvent.event_type == GITHUB_PR_BOUND_EVENT,
                TaskEvent.sequence == latest_binding_sequence,
                *filters,
            )
            .order_by(Task.id)
            .limit(2)
        )
    )


def _latest_binding(session: Session, task_id: UUID) -> TaskEvent | None:
    return session.scalar(
        select(TaskEvent)
        .where(TaskEvent.task_id == task_id, TaskEvent.event_type == GITHUB_PR_BOUND_EVENT)
        .order_by(TaskEvent.sequence.desc(), TaskEvent.id.desc())
        .limit(1)
    )


def _latest_resource_event(
    session: Session,
    task_id: UUID,
    update: _WebhookUpdate,
) -> TaskEvent | None:
    return session.scalar(
        select(TaskEvent)
        .where(
            TaskEvent.task_id == task_id,
            TaskEvent.event_type == update.event_type,
            TaskEvent.payload["head_sha"].as_string() == update.head_sha,
            TaskEvent.payload["resource_type"].as_string() == update.resource_type,
            TaskEvent.payload["resource_id"].as_string() == update.resource_id,
        )
        .order_by(TaskEvent.sequence.desc(), TaskEvent.id.desc())
        .limit(1)
    )


def _append_task_event(
    session: Session,
    task: Task,
    *,
    event_type: str,
    payload: dict[str, object],
    occurred_at: datetime,
    causation_id: UUID,
    parent_correlation_id: UUID | None = None,
) -> TaskEvent:
    sequence = int(
        session.scalar(select(func.max(TaskEvent.sequence)).where(TaskEvent.task_id == task.id))
        or 0
    ) + 1
    event = TaskEvent(
        task_id=task.id,
        sequence=sequence,
        event_type=event_type,
        payload=payload,
        occurred_at=occurred_at,
        owner_id=task.owner_id,
        actor_id=_ACTOR,
        root_correlation_id=task.root_correlation_id,
        causation_id=causation_id,
        parent_correlation_id=parent_correlation_id,
    )
    session.add(event)
    session.flush()
    return event


def _configuration_mismatch(
    update: _WebhookUpdate,
    configuration: GitHubAppConfiguration,
) -> str | None:
    if update.installation_id != configuration.installation_id:
        return "installation_mismatch"
    if update.repository_id != configuration.repository_id:
        return "repository_id_mismatch"
    if update.repository_key != configuration.repository_key:
        return "repository_key_mismatch"
    return None


def _best_effort_identity(payload: dict[str, object]) -> tuple[str, str, int | None, str | None]:
    installation = payload.get("installation")
    repository = payload.get("repository")
    installation_id = installation.get("id") if isinstance(installation, dict) else "unknown"
    repository_id = repository.get("id") if isinstance(repository, dict) else "unknown"
    pr = payload.get("pull_request")
    head = pr.get("head") if isinstance(pr, dict) else None
    sha = head.get("sha") if isinstance(head, dict) else None
    number = pr.get("number") if isinstance(pr, dict) else None
    check_run = payload.get("check_run")
    if isinstance(check_run, dict):
        sha = check_run.get("head_sha")
        pull_requests = check_run.get("pull_requests")
        if (
            isinstance(pull_requests, list)
            and len(pull_requests) == 1
            and isinstance(pull_requests[0], dict)
        ):
            number = pull_requests[0].get("number")
    return (
        str(installation_id)[:255],
        str(repository_id)[:255],
        number if isinstance(number, int) and not isinstance(number, bool) and number > 0 else None,
        sha if isinstance(sha, str) and _SHA_PATTERN.fullmatch(sha.casefold()) else None,
    )


def _mapping(value: dict[str, object], key: str) -> dict[str, object]:
    candidate = value.get(key)
    if not isinstance(candidate, dict):
        raise GitHubWebhookPayloadError(f"{key}_invalid")
    return cast(dict[str, object], candidate)


def _positive_int(value: dict[str, object], key: str) -> int:
    candidate = value.get(key)
    if isinstance(candidate, bool) or not isinstance(candidate, int) or candidate <= 0:
        raise GitHubWebhookPayloadError(f"{key}_invalid")
    return candidate


def _required_string(value: dict[str, object], key: str, maximum: int) -> str:
    candidate = value.get(key)
    if not isinstance(candidate, str) or not candidate or len(candidate) > maximum:
        raise GitHubWebhookPayloadError(f"{key}_invalid")
    return candidate


def _required_delivery_id(value: str | None) -> str:
    if value is None or _DELIVERY_PATTERN.fullmatch(value) is None:
        raise GitHubWebhookPayloadError("delivery_id_invalid")
    return value


def _required_event_name(value: str | None) -> str:
    if value is None or not value or len(value) > 100 or not value.isascii():
        raise GitHubWebhookPayloadError("event_name_invalid")
    return value


def _required_branch(value: str) -> str:
    if _BRANCH_PATTERN.fullmatch(value) is None or ".." in value or value.endswith("/"):
        raise GitHubWebhookPayloadError("task_branch_invalid")
    return value


def _required_sha(value: str) -> str:
    normalized = value.casefold()
    if _SHA_PATTERN.fullmatch(normalized) is None:
        raise GitHubWebhookPayloadError("head_sha_invalid")
    return normalized


def _parse_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise GitHubWebhookPayloadError(f"{field}_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise GitHubWebhookPayloadError(f"{field}_invalid") from None
    if parsed.tzinfo is None:
        raise GitHubWebhookPayloadError(f"{field}_invalid")
    return parsed.astimezone(UTC)


def _optional_uuid(value: object) -> UUID | None:
    if not isinstance(value, str):
        return None
    try:
        return UUID(value)
    except ValueError:
        return None


def _fingerprint(value: dict[str, object]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _timestamp(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
