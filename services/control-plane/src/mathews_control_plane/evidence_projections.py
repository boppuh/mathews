"""Verified, access-preserving views over canonical evidence envelopes."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.authentication import (
    AuthenticatedSession,
    require_authenticated_session,
)
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    EvidenceDeletionRequest,
    EvidenceDerivative,
    EvidenceRecord,
    EvidenceTombstone,
    Task,
    TaskEvent,
    TaskEventEvidenceReference,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceAuditEventType,
    EvidenceError,
    EvidenceNotFoundError,
    EvidenceSourceKind,
    EvidenceValidationError,
    append_evidence_audit_event,
    authorize_evidence_access,
    load_evidence,
    normalize_evidence_timestamp,
    resolve_evidence_principal,
)

Clock = Callable[[], datetime]
MAX_PROJECTION_RESULTS = 200


def _utc_now() -> datetime:
    return datetime.now(UTC)


class EvidenceProjectionClass(StrEnum):
    REQUEST = "REQUEST"
    REPOSITORY_STATE = "REPOSITORY_STATE"
    TOOL_OPERATION = "TOOL_OPERATION"
    TEST_ARTIFACT = "TEST_ARTIFACT"
    CI = "CI"
    REVIEW = "REVIEW"
    RESULT = "RESULT"
    EXTERNAL_EVENT = "EXTERNAL_EVENT"


class EvidenceVerificationStatus(StrEnum):
    VERIFIED = "VERIFIED"
    DELETION_PENDING = "DELETION_PENDING"
    DELETED = "DELETED"


class EvidenceLineageStatus(StrEnum):
    CURRENT = "CURRENT"
    SUPERSEDED = "SUPERSEDED"


class EvidenceDerivativeStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    DELETED = "DELETED"


class ProvenanceEdgeKind(StrEnum):
    PARENT = "PARENT"
    CORRECTS = "CORRECTS"


_EVIDENCE_TYPE_CLASSES: Mapping[str, EvidenceProjectionClass] = {
    "task-request": EvidenceProjectionClass.REQUEST,
    "task-steering-message": EvidenceProjectionClass.REQUEST,
    "repository-preflight-request": EvidenceProjectionClass.REQUEST,
    "validation-rerun-request": EvidenceProjectionClass.REQUEST,
    "repository-preflight": EvidenceProjectionClass.REPOSITORY_STATE,
    "workspace-diff": EvidenceProjectionClass.REPOSITORY_STATE,
    "validation-repair-candidate": EvidenceProjectionClass.REPOSITORY_STATE,
    "review-repair-candidate": EvidenceProjectionClass.REPOSITORY_STATE,
    "review-resolution-assessment": EvidenceProjectionClass.REVIEW,
    "hermes-tool-proposal": EvidenceProjectionClass.TOOL_OPERATION,
    "hermes-tool-authorization": EvidenceProjectionClass.TOOL_OPERATION,
    "hermes-tool-result": EvidenceProjectionClass.TOOL_OPERATION,
    "validation-unit-test-output": EvidenceProjectionClass.TEST_ARTIFACT,
    "validation-integration-test-output": EvidenceProjectionClass.TEST_ARTIFACT,
    "validation-simulator-artifact": EvidenceProjectionClass.TEST_ARTIFACT,
    "validation-application-log": EvidenceProjectionClass.TEST_ARTIFACT,
    "validation-crash-signal": EvidenceProjectionClass.TEST_ARTIFACT,
    "validation-error-signal": EvidenceProjectionClass.TEST_ARTIFACT,
    "validation-network-signal": EvidenceProjectionClass.TEST_ARTIFACT,
    "validation-performance-signal": EvidenceProjectionClass.TEST_ARTIFACT,
}


@dataclass(frozen=True, slots=True)
class EvidenceDerivativeProjection:
    derivative_id: UUID
    derivative_type: str
    content_hash: str
    captured_at: datetime
    status: EvidenceDerivativeStatus


@dataclass(frozen=True, slots=True)
class TaskEventReferenceProjection:
    task_event_id: UUID
    task_id: UUID
    sequence: int
    event_type: str
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class VerifiedEvidenceProjection:
    evidence_id: UUID
    projection_class: EvidenceProjectionClass
    evidence_type: str
    source_kind: EvidenceSourceKind | None
    origin: str
    actor_id: str
    task_id: UUID | None
    validation_run_id: UUID | None
    captured_at: datetime
    root_correlation_id: UUID
    causation_id: UUID | None
    parent_correlation_id: UUID | None
    envelope_hash: str
    content_hash: str | None
    verification_status: EvidenceVerificationStatus
    lineage_status: EvidenceLineageStatus
    access_classification: EvidenceAccessClass
    retention_policy: str
    correction_of_id: UUID | None
    corrected_by_id: UUID | None
    deletion_reason: str | None
    deleted_at: datetime | None
    derivatives: tuple[EvidenceDerivativeProjection, ...]
    task_event_references: tuple[TaskEventReferenceProjection, ...]


@dataclass(frozen=True, slots=True)
class TaskEvidenceProjectionView:
    task_id: UUID
    projections: tuple[VerifiedEvidenceProjection, ...]
    truncated: bool
    next_cursor: UUID | None


@dataclass(frozen=True, slots=True)
class ProvenanceEdge:
    source_evidence_id: UUID
    target_evidence_id: UUID
    kind: ProvenanceEdgeKind


@dataclass(frozen=True, slots=True)
class EvidenceProvenanceView:
    root_evidence_id: UUID
    nodes: tuple[VerifiedEvidenceProjection, ...]
    edges: tuple[ProvenanceEdge, ...]
    truncated: bool


class EvidenceDerivativeProjectionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    derivative_id: UUID
    derivative_type: str
    content_hash: str
    captured_at: datetime
    status: EvidenceDerivativeStatus


class TaskEventReferenceProjectionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    task_event_id: UUID
    task_id: UUID
    sequence: int
    event_type: str
    occurred_at: datetime


class VerifiedEvidenceProjectionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    evidence_id: UUID
    projection_class: EvidenceProjectionClass
    evidence_type: str
    source_kind: EvidenceSourceKind | None
    origin: str
    actor_id: str
    task_id: UUID | None
    validation_run_id: UUID | None
    captured_at: datetime
    root_correlation_id: UUID
    causation_id: UUID | None
    parent_correlation_id: UUID | None
    envelope_hash: str
    content_hash: str | None
    verification_status: EvidenceVerificationStatus
    lineage_status: EvidenceLineageStatus
    access_classification: EvidenceAccessClass
    retention_policy: str
    correction_of_id: UUID | None
    corrected_by_id: UUID | None
    deletion_reason: str | None
    deleted_at: datetime | None
    derivatives: tuple[EvidenceDerivativeProjectionResponse, ...]
    task_event_references: tuple[TaskEventReferenceProjectionResponse, ...]


class TaskEvidenceProjectionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    task_id: UUID
    projections: tuple[VerifiedEvidenceProjectionResponse, ...]
    truncated: bool
    next_cursor: UUID | None


class ProvenanceEdgeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source_evidence_id: UUID
    target_evidence_id: UUID
    kind: ProvenanceEdgeKind


class EvidenceProvenanceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    root_evidence_id: UUID
    nodes: tuple[VerifiedEvidenceProjectionResponse, ...]
    edges: tuple[ProvenanceEdgeResponse, ...]
    truncated: bool


@dataclass(frozen=True, slots=True)
class _ProjectionState:
    corrections: Mapping[UUID, UUID]
    deletion_requests: Mapping[UUID, EvidenceDeletionRequest]
    tombstones: Mapping[UUID, EvidenceTombstone]
    derivatives: Mapping[UUID, tuple[EvidenceDerivative, ...]]
    references: Mapping[UUID, tuple[TaskEventReferenceProjection, ...]]


class EvidenceProjectionService:
    """Build bounded projections without persisting a second evidence format."""

    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        *,
        clock: Clock = _utc_now,
    ) -> None:
        self._factory = factory
        self._artifact_store = artifact_store
        self._clock = clock

    @property
    def artifact_root(self) -> Path:
        """Return the canonical artifact root used to verify projections."""

        return self._artifact_store.root

    def task_projections(
        self,
        task_id: UUID,
        authentication: AuthenticatedSession,
        *,
        limit: int = 100,
        after: UUID | None = None,
    ) -> TaskEvidenceProjectionView:
        limit = _bounded_limit(limit)
        now = self._clock()
        with self._factory.begin() as session:
            principal = resolve_evidence_principal(authentication, now=now)
            task = session.get(Task, task_id)
            if task is None or task.owner_id != principal:
                raise EvidenceNotFoundError("task evidence is unavailable")
            records = self._task_records(
                session,
                task,
                limit=limit + 1,
                browser_authentication=authentication,
                now=now,
                after=after,
            )
            fetched_full_page = len(records) > limit
            authorized = tuple(
                record
                for record in records
                if self._browser_authorized(session, record, authentication, now=now)
            )
            truncated = fetched_full_page or len(authorized) > limit
            selected = authorized[:limit]
            projections = self._project(session, selected)
            self._audit(
                session,
                selected,
                actor_id=principal,
                session_id=authentication.session_id,
                view="task-projections",
                now=now,
            )
            return TaskEvidenceProjectionView(
                task_id,
                projections,
                truncated,
                selected[-1].id if truncated and selected else None,
            )

    def task_projections_internal(
        self,
        task_id: UUID,
        *,
        actor_id: str,
        limit: int = 100,
        after: UUID | None = None,
    ) -> TaskEvidenceProjectionView:
        """Trusted worker view, including INTERNAL CI and review evidence."""

        limit = _bounded_limit(limit)
        now = self._clock()
        with self._factory.begin() as session:
            task = session.get(Task, task_id)
            if task is None:
                raise EvidenceNotFoundError("task evidence is unavailable")
            records = self._task_records(
                session, task, limit=limit + 1, after=after
            )
            truncated = len(records) > limit
            selected = records[:limit]
            projections = self._project(session, selected)
            self._audit(
                session,
                selected,
                actor_id=_internal_actor(actor_id),
                session_id=None,
                view="internal-task-projections",
                now=now,
            )
            return TaskEvidenceProjectionView(
                task_id,
                projections,
                truncated,
                selected[-1].id if truncated and selected else None,
            )

    def provenance(
        self,
        evidence_id: UUID,
        authentication: AuthenticatedSession,
        *,
        limit: int = 100,
    ) -> EvidenceProvenanceView:
        limit = _bounded_limit(limit)
        now = self._clock()
        with self._factory.begin() as session:
            root = session.get(EvidenceRecord, evidence_id)
            if root is None:
                raise EvidenceNotFoundError("evidence is unavailable")
            principal = authorize_evidence_access(
                session, root, authentication, now=now
            )

            def allowed(record: EvidenceRecord) -> bool:
                return self._browser_authorized(
                    session, record, authentication, now=now
                )

            nodes, edges, truncated = self._walk_provenance(
                session, root, allowed=allowed, limit=limit
            )
            projections = self._project(session, nodes)
            self._audit(
                session,
                nodes,
                actor_id=principal,
                session_id=authentication.session_id,
                view="provenance",
                now=now,
            )
            return EvidenceProvenanceView(evidence_id, projections, edges, truncated)

    def provenance_internal(
        self,
        evidence_id: UUID,
        *,
        actor_id: str,
        limit: int = 100,
    ) -> EvidenceProvenanceView:
        limit = _bounded_limit(limit)
        now = self._clock()
        with self._factory.begin() as session:
            root = session.get(EvidenceRecord, evidence_id)
            if root is None:
                raise EvidenceNotFoundError("evidence is unavailable")
            nodes, edges, truncated = self._walk_provenance(
                session,
                root,
                allowed=lambda record: record.owner_id == root.owner_id,
                limit=limit,
            )
            projections = self._project(session, nodes)
            self._audit(
                session,
                nodes,
                actor_id=_internal_actor(actor_id),
                session_id=None,
                view="internal-provenance",
                now=now,
            )
            return EvidenceProvenanceView(evidence_id, projections, edges, truncated)

    @staticmethod
    def _browser_authorized(
        session: Session,
        record: EvidenceRecord,
        authentication: AuthenticatedSession,
        *,
        now: datetime,
    ) -> bool:
        try:
            authorize_evidence_access(session, record, authentication, now=now)
        except EvidenceNotFoundError:
            return False
        return True

    @staticmethod
    def _task_records(
        session: Session,
        task: Task,
        *,
        limit: int,
        browser_authentication: AuthenticatedSession | None = None,
        now: datetime | None = None,
        after: UUID | None = None,
    ) -> tuple[EvidenceRecord, ...]:
        referenced_ids = select(TaskEventEvidenceReference.evidence_id).where(
            TaskEventEvidenceReference.task_id == task.id
        )
        filters = [
            EvidenceRecord.owner_id == task.owner_id,
            or_(
                EvidenceRecord.task_id == task.id,
                EvidenceRecord.id.in_(referenced_ids),
            ),
        ]
        if browser_authentication is not None:
            recent_password = bool(
                now is not None
                and browser_authentication.recent_password_verified
                and normalize_evidence_timestamp(
                    browser_authentication.reauthenticated_until
                )
                > normalize_evidence_timestamp(now)
            )
            direct_access = [EvidenceAccessClass.OWNER.value]
            if recent_password:
                direct_access.append(EvidenceAccessClass.RECENT_PASSWORD.value)
            filters.append(
                or_(
                    EvidenceRecord.access_classification.in_(direct_access),
                    and_(
                        EvidenceRecord.access_classification
                        == EvidenceAccessClass.TASK_OWNER.value,
                        EvidenceRecord.task_id == task.id,
                    ),
                )
            )
        if after is not None:
            cursor = session.scalar(
                select(EvidenceRecord).where(
                    EvidenceRecord.id == after,
                    *filters,
                )
            )
            if cursor is None:
                raise EvidenceNotFoundError("evidence projection cursor is unavailable")
            filters.append(
                or_(
                    EvidenceRecord.captured_at > cursor.captured_at,
                    and_(
                        EvidenceRecord.captured_at == cursor.captured_at,
                        EvidenceRecord.id > cursor.id,
                    ),
                )
            )
        return tuple(
            session.scalars(
                select(EvidenceRecord)
                .where(*filters)
                .order_by(EvidenceRecord.captured_at, EvidenceRecord.id)
                .limit(limit)
            )
        )

    def _project(
        self,
        session: Session,
        records: Iterable[EvidenceRecord],
    ) -> tuple[VerifiedEvidenceProjection, ...]:
        selected = tuple(records)
        state = self._projection_state(session, selected)
        return tuple(self._one_projection(session, record, state) for record in selected)

    def _one_projection(
        self,
        session: Session,
        record: EvidenceRecord,
        state: _ProjectionState,
    ) -> VerifiedEvidenceProjection:
        deletion_request = state.deletion_requests.get(record.id)
        tombstone = state.tombstones.get(record.id)
        loaded = None
        if tombstone is not None:
            verification_status = EvidenceVerificationStatus.DELETED
        elif deletion_request is not None:
            verification_status = EvidenceVerificationStatus.DELETION_PENDING
        else:
            loaded = load_evidence(session, self._artifact_store, record)
            verification_status = EvidenceVerificationStatus.VERIFIED

        source_kind = None
        content_hash = None
        content: object = None
        if loaded is not None:
            source_value = loaded.envelope.get("source_kind")
            hash_value = loaded.envelope.get("content_hash")
            if not isinstance(source_value, str) or not isinstance(hash_value, str):
                raise EvidenceValidationError("evidence projection metadata is invalid")
            try:
                source_kind = EvidenceSourceKind(source_value)
            except ValueError:
                raise EvidenceValidationError(
                    "evidence projection source kind is invalid"
                ) from None
            content_hash = hash_value
            content = loaded.content

        deleted_at = (
            normalize_evidence_timestamp(tombstone.deleted_at)
            if tombstone is not None
            else None
        )
        deletion_reason = (
            tombstone.reason_code
            if tombstone is not None
            else deletion_request.reason_code
            if deletion_request is not None
            else None
        )
        references = state.references.get(record.id, ())
        return VerifiedEvidenceProjection(
            evidence_id=record.id,
            projection_class=_classify(record, source_kind, content, references),
            evidence_type=record.evidence_type,
            source_kind=source_kind,
            origin=record.origin,
            actor_id=record.actor_id,
            task_id=record.task_id,
            validation_run_id=record.validation_run_id,
            captured_at=normalize_evidence_timestamp(record.captured_at),
            root_correlation_id=record.root_correlation_id,
            causation_id=record.causation_id,
            parent_correlation_id=record.parent_correlation_id,
            envelope_hash=record.content_hash,
            content_hash=content_hash,
            verification_status=verification_status,
            lineage_status=(
                EvidenceLineageStatus.SUPERSEDED
                if record.id in state.corrections
                else EvidenceLineageStatus.CURRENT
            ),
            access_classification=EvidenceAccessClass(record.access_classification),
            retention_policy=record.retention_policy,
            correction_of_id=record.correction_of_id,
            corrected_by_id=state.corrections.get(record.id),
            deletion_reason=deletion_reason,
            deleted_at=deleted_at,
            derivatives=tuple(
                EvidenceDerivativeProjection(
                    derivative_id=derivative.id,
                    derivative_type=derivative.derivative_type,
                    content_hash=derivative.content_hash,
                    captured_at=normalize_evidence_timestamp(
                        derivative.captured_at
                    ),
                    status=(
                        EvidenceDerivativeStatus.DELETED
                        if derivative.deleted_at is not None
                        else EvidenceDerivativeStatus.AVAILABLE
                    ),
                )
                for derivative in state.derivatives.get(record.id, ())
            ),
            task_event_references=references,
        )

    @staticmethod
    def _projection_state(
        session: Session,
        records: tuple[EvidenceRecord, ...],
    ) -> _ProjectionState:
        ids = tuple(record.id for record in records)
        if not ids:
            return _ProjectionState({}, {}, {}, {}, {})
        corrections = {
            record.correction_of_id: record.id
            for record in session.scalars(
                select(EvidenceRecord).where(EvidenceRecord.correction_of_id.in_(ids))
            )
            if record.correction_of_id is not None
        }
        requests = {
            request.evidence_id: request
            for request in session.scalars(
                select(EvidenceDeletionRequest).where(
                    EvidenceDeletionRequest.evidence_id.in_(ids)
                )
            )
        }
        tombstones = {
            tombstone.evidence_id: tombstone
            for tombstone in session.scalars(
                select(EvidenceTombstone).where(EvidenceTombstone.evidence_id.in_(ids))
            )
        }
        derivatives: dict[UUID, list[EvidenceDerivative]] = {}
        for derivative in session.scalars(
            select(EvidenceDerivative)
            .where(EvidenceDerivative.evidence_id.in_(ids))
            .order_by(EvidenceDerivative.captured_at, EvidenceDerivative.id)
        ):
            derivatives.setdefault(derivative.evidence_id, []).append(derivative)
        references: dict[UUID, list[TaskEventReferenceProjection]] = {}
        rows = session.execute(
            select(TaskEventEvidenceReference, TaskEvent)
            .join(
                TaskEvent,
                TaskEvent.id == TaskEventEvidenceReference.task_event_id,
            )
            .where(TaskEventEvidenceReference.evidence_id.in_(ids))
            .order_by(TaskEvent.sequence, TaskEventEvidenceReference.position)
        )
        for reference, event in rows:
            references.setdefault(reference.evidence_id, []).append(
                TaskEventReferenceProjection(
                    task_event_id=event.id,
                    task_id=event.task_id,
                    sequence=event.sequence,
                    event_type=event.event_type,
                    occurred_at=normalize_evidence_timestamp(event.occurred_at),
                )
            )
        return _ProjectionState(
            corrections,
            requests,
            tombstones,
            {key: tuple(value) for key, value in derivatives.items()},
            {key: tuple(value) for key, value in references.items()},
        )

    @staticmethod
    def _walk_provenance(
        session: Session,
        root: EvidenceRecord,
        *,
        allowed: Callable[[EvidenceRecord], bool],
        limit: int,
    ) -> tuple[tuple[EvidenceRecord, ...], tuple[ProvenanceEdge, ...], bool]:
        queue = deque([root])
        nodes: dict[UUID, EvidenceRecord] = {}
        edges: set[ProvenanceEdge] = set()
        examined: set[UUID] = set()
        truncated = False
        while queue:
            frontier: list[EvidenceRecord] = []
            for _ in range(len(queue)):
                record = queue.popleft()
                if record.id in examined:
                    continue
                examined.add(record.id)
                if allowed(record):
                    frontier.append(record)
            available = limit - len(nodes)
            if len(frontier) > available:
                frontier = frontier[:available]
                truncated = True
            for record in frontier:
                nodes[record.id] = record
            if truncated or not frontier:
                if truncated:
                    break
                continue
            frontier_ids = {record.id for record in frontier}
            relation_ids = set(frontier_ids)
            relation_ids.update(
                record.correction_of_id
                for record in frontier
                if record.correction_of_id is not None
            )
            relation_ids.update(
                record.parent_correlation_id
                for record in frontier
                if record.parent_correlation_id is not None
            )
            direct_related = tuple(
                session.scalars(
                    select(EvidenceRecord).where(
                        EvidenceRecord.owner_id == root.owner_id,
                        EvidenceRecord.id.in_(relation_ids),
                    )
                )
            )
            remaining_capacity = limit - len(nodes)
            children = tuple(
                session.scalars(
                    select(EvidenceRecord)
                    .where(
                        EvidenceRecord.owner_id == root.owner_id,
                        or_(
                            EvidenceRecord.correction_of_id.in_(frontier_ids),
                            EvidenceRecord.parent_correlation_id.in_(frontier_ids),
                        ),
                    )
                    .order_by(EvidenceRecord.captured_at, EvidenceRecord.id)
                    .limit(remaining_capacity + 1)
                )
            )
            related = tuple(
                {record.id: record for record in (*direct_related, *children)}.values()
            )
            for candidate in related:
                if candidate.id not in frontier_ids:
                    queue.append(candidate)
                for record in frontier:
                    _add_relation_edges(edges, record, candidate)
        visible = set(nodes)
        visible_edges = tuple(
            sorted(
                (
                    edge
                    for edge in edges
                    if edge.source_evidence_id in visible
                    and edge.target_evidence_id in visible
                ),
                key=lambda edge: (
                    str(edge.source_evidence_id),
                    str(edge.target_evidence_id),
                    edge.kind.value,
                ),
            )
        )
        ordered = tuple(
            sorted(nodes.values(), key=lambda item: (item.captured_at, str(item.id)))
        )
        return ordered, visible_edges, truncated or bool(queue)

    @staticmethod
    def _audit(
        session: Session,
        records: Iterable[EvidenceRecord],
        *,
        actor_id: str,
        session_id: UUID | None,
        view: str,
        now: datetime,
    ) -> None:
        for record in records:
            append_evidence_audit_event(
                session,
                record=record,
                event_type=EvidenceAuditEventType.METADATA_READ,
                actor_id=actor_id,
                occurred_at=now,
                details={"view": view},
                session_id=session_id,
            )


def _add_relation_edges(
    edges: set[ProvenanceEdge],
    current: EvidenceRecord,
    candidate: EvidenceRecord,
) -> None:
    for record in (current, candidate):
        other = candidate if record is current else current
        if record.correction_of_id == other.id:
            edges.add(ProvenanceEdge(other.id, record.id, ProvenanceEdgeKind.CORRECTS))
        if record.parent_correlation_id == other.id:
            edges.add(ProvenanceEdge(other.id, record.id, ProvenanceEdgeKind.PARENT))


def _classify(
    record: EvidenceRecord,
    source_kind: EvidenceSourceKind | None,
    content: object,
    references: tuple[TaskEventReferenceProjection, ...],
) -> EvidenceProjectionClass:
    evidence_type = record.evidence_type.lower()
    event_name_value = content.get("event_name") if isinstance(content, dict) else None
    event_name = event_name_value if isinstance(event_name_value, str) else None
    event_types = {reference.event_type for reference in references}
    if event_name in {
            "check_run",
            "check_suite",
            "status",
            "workflow_job",
            "workflow_run",
        } or "GITHUB_CHECK_UPDATED" in event_types:
        return EvidenceProjectionClass.CI
    if event_name in {
            "issue_comment",
            "pull_request",
            "pull_request_review",
            "pull_request_review_comment",
            "pull_request_review_thread",
        } or "GITHUB_REVIEW_UPDATED" in event_types:
        return EvidenceProjectionClass.REVIEW
    if source_kind is EvidenceSourceKind.REQUEST:
        return EvidenceProjectionClass.REQUEST
    if source_kind is EvidenceSourceKind.REPOSITORY_SNAPSHOT:
        return EvidenceProjectionClass.REPOSITORY_STATE
    if source_kind is EvidenceSourceKind.TOOL_OPERATION:
        return EvidenceProjectionClass.TOOL_OPERATION
    if (
        source_kind is EvidenceSourceKind.EXTERNAL_EVENT
        or evidence_type == "github-webhook"
    ):
        return EvidenceProjectionClass.EXTERNAL_EVENT
    return _EVIDENCE_TYPE_CLASSES.get(evidence_type, EvidenceProjectionClass.RESULT)


def _bounded_limit(limit: int) -> int:
    if not 1 <= limit <= MAX_PROJECTION_RESULTS:
        raise EvidenceValidationError("evidence projection limit is invalid")
    return limit


def _internal_actor(actor_id: str) -> str:
    normalized = actor_id.strip()
    if not normalized or len(normalized) > 255:
        raise EvidenceValidationError("internal projection actor is invalid")
    return normalized


def _http_error(error: EvidenceError) -> HTTPException:
    if isinstance(error, EvidenceValidationError):
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="evidence projection request is invalid",
        )
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="evidence not found",
    )


AuthenticatedEvidenceSession = Annotated[
    AuthenticatedSession,
    Depends(require_authenticated_session),
]


def create_evidence_projection_router(service: EvidenceProjectionService) -> APIRouter:
    router = APIRouter(prefix="/api/evidence", tags=["evidence"])

    @router.get(
        "/tasks/{task_id}/projections",
        response_model=TaskEvidenceProjectionResponse,
    )
    def task_projections(
        task_id: UUID,
        response: Response,
        authentication: AuthenticatedEvidenceSession,
        limit: Annotated[int, Query(ge=1, le=MAX_PROJECTION_RESULTS)] = 100,
        after: UUID | None = None,
    ) -> TaskEvidenceProjectionResponse:
        try:
            result = service.task_projections(
                task_id,
                authentication,
                limit=limit,
                after=after,
            )
        except EvidenceError as error:
            raise _http_error(error) from None
        response.headers["Cache-Control"] = "no-store"
        return TaskEvidenceProjectionResponse.model_validate(result)

    @router.get(
        "/{evidence_id}/provenance",
        response_model=EvidenceProvenanceResponse,
    )
    def provenance(
        evidence_id: UUID,
        response: Response,
        authentication: AuthenticatedEvidenceSession,
        limit: Annotated[int, Query(ge=1, le=MAX_PROJECTION_RESULTS)] = 100,
    ) -> EvidenceProvenanceResponse:
        try:
            result = service.provenance(evidence_id, authentication, limit=limit)
        except EvidenceError as error:
            raise _http_error(error) from None
        response.headers["Cache-Control"] = "no-store"
        return EvidenceProvenanceResponse.model_validate(result)

    return router
