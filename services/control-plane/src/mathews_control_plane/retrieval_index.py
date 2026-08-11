"""Disposable, access-preserving retrieval chunks derived from verified evidence."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import exists, or_, select
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
    RetrievalIndexChunk,
    RetrievalIndexGeneration,
    Task,
    TaskEvent,
    TaskEventEvidenceReference,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceAuditEventType,
    EvidenceError,
    EvidenceNotFoundError,
    EvidenceValidationError,
    append_evidence_audit_event,
    authorize_evidence_access,
    load_evidence,
    load_evidence_derivative,
    normalize_evidence_timestamp,
    register_evidence_derivative,
    resolve_evidence_principal,
)
from mathews_control_plane.evidence_projections import (
    EvidenceLineageStatus,
    EvidenceProjectionClass,
    EvidenceProjectionService,
    EvidenceVerificationStatus,
    VerifiedEvidenceProjection,
)

Clock = Callable[[], datetime]

RETRIEVAL_DERIVATIVE_TYPE_PREFIX = "retrieval-index:"
RETRIEVAL_CHUNK_SCHEMA_VERSION = 1
RETRIEVAL_CHUNKER_VERSION = "mvp-char-v1"
RETRIEVAL_VERIFIER_VERSION = "evidence-envelope-v1"
RETRIEVAL_DEFAULT_INDEX_VERSION = "mvp-lexical-v1"
RETRIEVAL_CHUNK_CHARACTERS = 1_000
RETRIEVAL_CHUNK_OVERLAP = 100
MAX_INDEX_SOURCES = 1_000
MAX_INDEX_CHUNKS = 5_000
MAX_SEARCH_RESULTS = 50
MAX_SEARCH_VERIFY_CHUNKS = 500
MAX_SEARCH_QUERY_CHARACTERS = 500
MAX_REFRESH_TASKS = 1_000
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}\Z")
_TERM = re.compile(r"[\w./:-]+", re.UNICODE)
_CHUNK_KEYS = {
    "access_classification",
    "chunk_hash",
    "chunker_version",
    "end_offset",
    "evidence_id",
    "generation_id",
    "index_version",
    "indexed_at",
    "ordinal",
    "projection_class",
    "schema_version",
    "source_captured_at",
    "source_envelope_hash",
    "source_hash",
    "start_offset",
    "task_id",
    "text",
    "verifier_version",
}


def _utc_now() -> datetime:
    return datetime.now(UTC)


class RetrievalIndexError(RuntimeError):
    """Base class for safe retrieval-index failures."""


class RetrievalIndexValidationError(RetrievalIndexError):
    """Raised when index input or derived metadata is invalid."""


class RetrievalIndexNotFoundError(RetrievalIndexError):
    """Raised when a task or cursor must not be enumerable."""


@dataclass(frozen=True, slots=True)
class RetrievalIndexBuildResult:
    task_id: UUID
    generation_id: UUID
    index_version: str
    chunker_version: str
    verifier_version: str
    indexed_at: datetime
    source_count: int
    chunk_count: int
    removed_chunk_count: int


@dataclass(frozen=True, slots=True)
class RetrievalHit:
    evidence_id: UUID
    derivative_id: UUID
    projection_class: EvidenceProjectionClass
    generation_id: UUID
    index_version: str
    chunker_version: str
    verifier_version: str
    ordinal: int
    start_offset: int
    end_offset: int
    text: str
    score: float
    source_hash: str
    source_envelope_hash: str
    chunk_hash: str
    access_classification: EvidenceAccessClass
    source_captured_at: datetime
    indexed_at: datetime


@dataclass(frozen=True, slots=True)
class RetrievalSearchResult:
    task_id: UUID
    generation_id: UUID | None
    index_version: str | None
    hits: tuple[RetrievalHit, ...]


class RetrievalHitResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    evidence_id: UUID
    derivative_id: UUID
    projection_class: EvidenceProjectionClass
    generation_id: UUID
    index_version: str
    chunker_version: str
    verifier_version: str
    ordinal: int
    start_offset: int
    end_offset: int
    text: str
    score: float
    source_hash: str
    source_envelope_hash: str
    chunk_hash: str
    access_classification: EvidenceAccessClass
    source_captured_at: datetime
    indexed_at: datetime


class RetrievalSearchResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    task_id: UUID
    generation_id: UUID | None
    index_version: str | None
    hits: tuple[RetrievalHitResponse, ...]


@dataclass(frozen=True, slots=True)
class _ChunkPayload:
    task_id: UUID
    evidence_id: UUID
    generation_id: UUID
    index_version: str
    chunker_version: str
    verifier_version: str
    projection_class: EvidenceProjectionClass
    access_classification: EvidenceAccessClass
    source_hash: str
    source_envelope_hash: str
    chunk_hash: str
    source_captured_at: datetime
    indexed_at: datetime
    ordinal: int
    start_offset: int
    end_offset: int
    text: str


class RetrievalIndexService:
    """Build and query disposable chunks while treating evidence as authority."""

    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        projection_service: EvidenceProjectionService,
        *,
        clock: Clock = _utc_now,
    ) -> None:
        self._factory = factory
        self._artifact_store = artifact_store
        self._projection_service = projection_service
        self._clock = clock

    def rebuild_task_index_internal(
        self,
        task_id: UUID,
        *,
        index_version: str,
        actor_id: str,
    ) -> RetrievalIndexBuildResult:
        """Delete all prior task chunks and rebuild from current verified sources."""

        version = _required_version(index_version)
        actor = _required_actor(actor_id)
        projections = self._verified_task_projections(task_id, actor_id=actor)
        now = normalize_evidence_timestamp(self._clock())
        generation_id = uuid4()
        chunk_count = 0
        source_count = 0
        created_addresses: list[str] = []
        retired_addresses: list[str] = []
        removed = 0
        try:
            with self._factory.begin() as session:
                task = session.scalar(select(Task).where(Task.id == task_id).with_for_update())
                if task is None:
                    raise RetrievalIndexNotFoundError("retrieval task is unavailable")
                removed, retired_addresses = self._retire_index_in_session(
                    session, task_id=task_id, deleted_at=now
                )
                generation = RetrievalIndexGeneration(
                    id=generation_id,
                    task_id=task_id,
                    index_version=version,
                    chunker_version=RETRIEVAL_CHUNKER_VERSION,
                    verifier_version=RETRIEVAL_VERIFIER_VERSION,
                    indexed_at=now,
                    source_count=0,
                    chunk_count=0,
                    owner_id=task.owner_id,
                    actor_id=actor,
                    root_correlation_id=task.root_correlation_id,
                    causation_id=task.id,
                    parent_correlation_id=task.parent_correlation_id,
                )
                session.add(generation)
                session.flush()
                for projection in projections:
                    record = session.get(EvidenceRecord, projection.evidence_id)
                    if record is None or session.scalar(
                        select(exists().where(EvidenceRecord.correction_of_id == record.id))
                    ):
                        continue
                    loaded = load_evidence(session, self._artifact_store, record)
                    source_hash = loaded.envelope.get("content_hash")
                    if (
                        not isinstance(source_hash, str)
                        or source_hash != projection.content_hash
                        or record.content_hash != projection.envelope_hash
                        or record.access_classification != projection.access_classification.value
                    ):
                        raise RetrievalIndexValidationError("retrieval source projection is stale")
                    source_count += 1
                    text_value = _source_text(loaded.content, loaded.media_type)
                    for ordinal, start, end, chunk_text in _chunks(text_value):
                        chunk_count += 1
                        if chunk_count > MAX_INDEX_CHUNKS:
                            raise RetrievalIndexValidationError(
                                "retrieval index exceeds the chunk limit"
                            )
                        chunk_hash = _digest(chunk_text.encode("utf-8"))
                        derivative = register_evidence_derivative(
                            session,
                            self._artifact_store,
                            evidence_id=record.id,
                            derivative_type=_derivative_type(task_id),
                            payload={
                                "schema_version": RETRIEVAL_CHUNK_SCHEMA_VERSION,
                                "generation_id": str(generation_id),
                                "index_version": version,
                                "chunker_version": RETRIEVAL_CHUNKER_VERSION,
                                "verifier_version": RETRIEVAL_VERIFIER_VERSION,
                                "evidence_id": str(record.id),
                                "task_id": str(task_id),
                                "projection_class": projection.projection_class.value,
                                "access_classification": record.access_classification,
                                "source_hash": source_hash,
                                "source_envelope_hash": record.content_hash,
                                "chunk_hash": chunk_hash,
                                "source_captured_at": _timestamp(record.captured_at),
                                "indexed_at": _timestamp(now),
                                "ordinal": ordinal,
                                "start_offset": start,
                                "end_offset": end,
                                "text": chunk_text,
                            },
                            media_type="application/json",
                            actor_id=actor,
                            captured_at=now,
                        )
                        if derivative.content_address is None:
                            raise RetrievalIndexValidationError("retrieval chunk was not persisted")
                        created_addresses.append(derivative.content_address)
                        session.add(
                            RetrievalIndexChunk(
                                generation_id=generation_id,
                                task_id=task_id,
                                evidence_id=record.id,
                                derivative_id=derivative.id,
                                projection_class=projection.projection_class.value,
                                access_classification=record.access_classification,
                                source_hash=source_hash,
                                source_envelope_hash=record.content_hash,
                                chunk_hash=chunk_hash,
                                index_version=version,
                                chunker_version=RETRIEVAL_CHUNKER_VERSION,
                                verifier_version=RETRIEVAL_VERIFIER_VERSION,
                                source_captured_at=record.captured_at,
                                indexed_at=now,
                                ordinal=ordinal,
                                start_offset=start,
                                end_offset=end,
                                lexical_term_frequencies=_term_frequencies(
                                    chunk_text, generation_id
                                ),
                                owner_id=task.owner_id,
                                actor_id=actor,
                                root_correlation_id=task.root_correlation_id,
                                causation_id=derivative.id,
                                parent_correlation_id=record.id,
                            )
                        )
                generation.source_count = source_count
                generation.chunk_count = chunk_count
        except Exception:
            for address in created_addresses:
                self._artifact_store.delete_bytes(address)
            raise
        for address in retired_addresses:
            self._artifact_store.delete_bytes(address)
        return RetrievalIndexBuildResult(
            task_id=task_id,
            generation_id=generation_id,
            index_version=version,
            chunker_version=RETRIEVAL_CHUNKER_VERSION,
            verifier_version=RETRIEVAL_VERIFIER_VERSION,
            indexed_at=now,
            source_count=source_count,
            chunk_count=chunk_count,
            removed_chunk_count=removed,
        )

    def delete_task_index_internal(self, task_id: UUID, *, actor_id: str) -> int:
        """Destroy every live retrieval derivative associated with one task."""

        _required_actor(actor_id)
        now = normalize_evidence_timestamp(self._clock())
        retired_addresses: list[str]
        with self._factory.begin() as session:
            task = session.scalar(select(Task).where(Task.id == task_id).with_for_update())
            if task is None:
                raise RetrievalIndexNotFoundError("retrieval task is unavailable")
            removed, retired_addresses = self._retire_index_in_session(
                session, task_id=task_id, deleted_at=now
            )
        for address in retired_addresses:
            self._artifact_store.delete_bytes(address)
        return removed

    def refresh_stale_task_indexes_internal(
        self,
        *,
        actor_id: str,
        limit: int = MAX_REFRESH_TASKS,
    ) -> tuple[UUID, ...]:
        """Rebuild task indexes whose evidence activity is newer than generation."""

        actor = _required_actor(actor_id)
        if not 1 <= limit <= MAX_REFRESH_TASKS:
            raise RetrievalIndexValidationError("retrieval refresh limit is invalid")
        with self._factory() as session:
            task_ids = tuple(session.scalars(select(Task.id).order_by(Task.id).limit(limit)))
            stale = tuple(
                task_id for task_id in task_ids if self._task_index_is_stale(session, task_id)
            )
        rebuilt: list[UUID] = []
        for task_id in stale:
            self.rebuild_task_index_internal(
                task_id,
                index_version=RETRIEVAL_DEFAULT_INDEX_VERSION,
                actor_id=actor,
            )
            rebuilt.append(task_id)
        return tuple(rebuilt)

    @staticmethod
    def _task_index_is_stale(session: Session, task_id: UUID) -> bool:
        generation = session.scalar(
            select(RetrievalIndexGeneration).where(
                RetrievalIndexGeneration.task_id == task_id,
                RetrievalIndexGeneration.deleted_at.is_(None),
            )
        )
        if generation is None:
            return True
        referenced_ids = select(TaskEventEvidenceReference.evidence_id).where(
            TaskEventEvidenceReference.task_id == task_id
        )
        related_ids = select(EvidenceRecord.id).where(
            or_(
                EvidenceRecord.task_id == task_id,
                EvidenceRecord.id.in_(referenced_ids),
            )
        )
        changed_evidence = exists().where(
            EvidenceRecord.id.in_(related_ids),
            or_(
                EvidenceRecord.captured_at > generation.indexed_at,
                EvidenceRecord.deleted_at > generation.indexed_at,
            ),
        )
        changed_correction = exists().where(
            EvidenceRecord.correction_of_id.in_(related_ids),
            EvidenceRecord.captured_at > generation.indexed_at,
        )
        changed_reference = exists().where(
            TaskEvent.id == TaskEventEvidenceReference.task_event_id,
            TaskEventEvidenceReference.task_id == task_id,
            TaskEvent.occurred_at > generation.indexed_at,
        )
        changed_deletion = exists().where(
            EvidenceDeletionRequest.evidence_id.in_(related_ids),
            EvidenceDeletionRequest.requested_at > generation.indexed_at,
        )
        return bool(
            session.scalar(
                select(changed_evidence | changed_correction | changed_reference | changed_deletion)
            )
        )

    def search(
        self,
        task_id: UUID,
        query: str,
        authentication: AuthenticatedSession,
        *,
        limit: int = 20,
    ) -> RetrievalSearchResult:
        """Rank cheaply, then verify and authorize a bounded candidate window."""

        terms = _query_terms(query)
        if not 1 <= limit <= MAX_SEARCH_RESULTS:
            raise RetrievalIndexValidationError("retrieval result limit is invalid")
        now = normalize_evidence_timestamp(self._clock())
        with self._factory() as session:
            principal = resolve_evidence_principal(authentication, now=now)
            task = session.get(Task, task_id)
            if task is None or task.owner_id != principal:
                raise RetrievalIndexNotFoundError("retrieval task is unavailable")
            generation = session.scalar(
                select(RetrievalIndexGeneration).where(
                    RetrievalIndexGeneration.task_id == task_id,
                    RetrievalIndexGeneration.deleted_at.is_(None),
                )
            )
            if generation is None:
                return RetrievalSearchResult(task_id, None, None, ())
            if (
                generation.chunker_version != RETRIEVAL_CHUNKER_VERSION
                or generation.verifier_version != RETRIEVAL_VERIFIER_VERSION
            ):
                raise RetrievalIndexValidationError("retrieval generation version is unsupported")
            chunks = tuple(
                session.scalars(
                    select(RetrievalIndexChunk)
                    .where(
                        RetrievalIndexChunk.generation_id == generation.id,
                        RetrievalIndexChunk.task_id == task_id,
                        RetrievalIndexChunk.deleted_at.is_(None),
                    )
                    .limit(MAX_INDEX_CHUNKS + 1)
                )
            )
            if len(chunks) > MAX_INDEX_CHUNKS:
                raise RetrievalIndexValidationError("retrieval index exceeds the query limit")
            query_hashes = tuple(_term_key(term, generation.id) for term in terms)
            cheaply_ranked = sorted(
                (
                    (_projected_score(chunk.lexical_term_frequencies, query_hashes), chunk)
                    for chunk in chunks
                    if _may_be_browser_accessible(chunk, authentication, now=now)
                ),
                key=lambda item: (-item[0], str(item[1].evidence_id), item[1].ordinal),
            )
            verify_limit = min(MAX_SEARCH_VERIFY_CHUNKS, max(100, limit * 10))
            selected = tuple((score, chunk) for score, chunk in cheaply_ranked if score > 0)[
                :verify_limit
            ]
            if not selected:
                return RetrievalSearchResult(task_id, generation.id, generation.index_version, ())
            successor_ids = set(
                session.scalars(
                    select(EvidenceRecord.correction_of_id).where(
                        EvidenceRecord.correction_of_id.in_(
                            tuple({chunk.evidence_id for _, chunk in selected})
                        )
                    )
                )
            )
            source_cache: dict[UUID, tuple[EvidenceRecord, str, str]] = {}
            candidates: list[RetrievalHit] = []
            for projected_score, chunk in selected:
                if chunk.evidence_id in successor_ids:
                    continue
                record = session.get(EvidenceRecord, chunk.evidence_id)
                if record is None:
                    continue
                cached = source_cache.get(record.id)
                if cached is None:
                    try:
                        authorize_evidence_access(
                            session,
                            record,
                            authentication,
                            now=now,
                        )
                    except EvidenceNotFoundError:
                        continue
                    loaded_source = load_evidence(session, self._artifact_store, record)
                    source_hash_value = loaded_source.envelope.get("content_hash")
                    if not isinstance(source_hash_value, str):
                        raise RetrievalIndexValidationError("retrieval source hash is invalid")
                    cached = (
                        record,
                        source_hash_value,
                        _source_text(loaded_source.content, loaded_source.media_type),
                    )
                    source_cache[record.id] = cached
                derivative = session.get(EvidenceDerivative, chunk.derivative_id)
                if (
                    derivative is None
                    or derivative.deleted_at is not None
                    or derivative.content_address is None
                ):
                    continue
                loaded_derivative = load_evidence_derivative(
                    session,
                    self._artifact_store,
                    derivative,
                )
                payload = _chunk_payload(loaded_derivative.content)
                _verify_chunk_payload(
                    payload,
                    task_id=task_id,
                    generation=generation,
                    chunk=chunk,
                    derivative=derivative,
                    record=cached[0],
                    source_hash=cached[1],
                    source_text=cached[2],
                )
                score = _lexical_score(payload.text, terms)
                if score <= 0 or score != projected_score:
                    raise RetrievalIndexValidationError(
                        "retrieval lexical projection verification failed"
                    )
                candidates.append(
                    RetrievalHit(
                        evidence_id=record.id,
                        derivative_id=derivative.id,
                        projection_class=payload.projection_class,
                        generation_id=payload.generation_id,
                        index_version=payload.index_version,
                        chunker_version=payload.chunker_version,
                        verifier_version=payload.verifier_version,
                        ordinal=payload.ordinal,
                        start_offset=payload.start_offset,
                        end_offset=payload.end_offset,
                        text=payload.text,
                        score=score,
                        source_hash=payload.source_hash,
                        source_envelope_hash=payload.source_envelope_hash,
                        chunk_hash=payload.chunk_hash,
                        access_classification=payload.access_classification,
                        source_captured_at=payload.source_captured_at,
                        indexed_at=payload.indexed_at,
                    )
                )
            unaudited_hits = tuple(
                sorted(
                    candidates,
                    key=lambda hit: (
                        -hit.score,
                        str(hit.evidence_id),
                        hit.ordinal,
                    ),
                )[:limit]
            )
            result_generation_id = generation.id
            result_index_version = generation.index_version
        authorized_ids = self._audit_hits(
            unaudited_hits,
            authentication,
            principal=principal,
            now=now,
        )
        hits = tuple(hit for hit in unaudited_hits if hit.evidence_id in authorized_ids)
        return RetrievalSearchResult(task_id, result_generation_id, result_index_version, hits)

    def _audit_hits(
        self,
        hits: tuple[RetrievalHit, ...],
        authentication: AuthenticatedSession,
        *,
        principal: str,
        now: datetime,
    ) -> frozenset[UUID]:
        authorized: set[UUID] = set()
        with self._factory.begin() as session:
            for evidence_id in {hit.evidence_id for hit in hits}:
                record = session.get(EvidenceRecord, evidence_id)
                if record is None or session.scalar(
                    select(exists().where(EvidenceRecord.correction_of_id == evidence_id))
                ):
                    continue
                try:
                    authorize_evidence_access(session, record, authentication, now=now)
                    load_evidence(session, self._artifact_store, record)
                except EvidenceNotFoundError:
                    continue
                append_evidence_audit_event(
                    session,
                    record=record,
                    event_type=EvidenceAuditEventType.CONTENT_DOWNLOADED,
                    actor_id=principal,
                    occurred_at=now,
                    details={"view": "retrieval-index"},
                    session_id=authentication.session_id,
                )
                authorized.add(evidence_id)
        return frozenset(authorized)

    def _retire_index_in_session(
        self,
        session: Session,
        *,
        task_id: UUID,
        deleted_at: datetime,
    ) -> tuple[int, list[str]]:
        generation = session.scalar(
            select(RetrievalIndexGeneration)
            .where(
                RetrievalIndexGeneration.task_id == task_id,
                RetrievalIndexGeneration.deleted_at.is_(None),
            )
            .with_for_update()
        )
        if generation is None:
            return 0, []
        chunks = tuple(
            session.scalars(
                select(RetrievalIndexChunk)
                .where(
                    RetrievalIndexChunk.generation_id == generation.id,
                    RetrievalIndexChunk.deleted_at.is_(None),
                )
                .with_for_update()
            )
        )
        addresses: list[str] = []
        removed = 0
        for chunk in chunks:
            derivative = session.get(EvidenceDerivative, chunk.derivative_id)
            if (
                derivative is not None
                and derivative.deleted_at is None
                and derivative.content_address is not None
            ):
                addresses.append(derivative.content_address)
                derivative.content_address = None
                derivative.deleted_at = deleted_at
                removed += 1
            chunk.lexical_term_frequencies = {}
            chunk.deleted_at = deleted_at
        generation.deleted_at = deleted_at
        session.flush()
        return removed, addresses

    def _verified_task_projections(
        self,
        task_id: UUID,
        *,
        actor_id: str,
    ) -> tuple[VerifiedEvidenceProjection, ...]:
        projections: list[VerifiedEvidenceProjection] = []
        after: UUID | None = None
        scanned = 0
        while True:
            page = self._projection_service.task_projections_internal(
                task_id,
                actor_id=actor_id,
                limit=200,
                after=after,
            )
            scanned += len(page.projections)
            if scanned > MAX_INDEX_SOURCES:
                raise RetrievalIndexValidationError("retrieval index exceeds the source limit")
            projections.extend(
                item
                for item in page.projections
                if item.verification_status is EvidenceVerificationStatus.VERIFIED
                and item.lineage_status is EvidenceLineageStatus.CURRENT
                and item.content_hash is not None
            )
            if page.next_cursor is None:
                break
            after = page.next_cursor
        return tuple(projections)


def _source_text(content: object, media_type: str) -> str:
    if media_type == "text/plain; charset=utf-8" and isinstance(content, str):
        return content
    if media_type == "application/json":
        return json.dumps(
            content,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    raise RetrievalIndexValidationError("retrieval source media type is invalid")


def _chunks(text: str) -> tuple[tuple[int, int, int, str], ...]:
    if not text:
        return ()
    chunks: list[tuple[int, int, int, str]] = []
    start = 0
    ordinal = 1
    while start < len(text):
        end = min(len(text), start + RETRIEVAL_CHUNK_CHARACTERS)
        value = text[start:end]
        if value:
            chunks.append((ordinal, start, end, value))
            ordinal += 1
        if end == len(text):
            break
        start = end - RETRIEVAL_CHUNK_OVERLAP
    return tuple(chunks)


def _chunk_payload(content: object) -> _ChunkPayload:
    if not isinstance(content, dict) or set(content) != _CHUNK_KEYS:
        raise RetrievalIndexValidationError("retrieval chunk metadata is invalid")
    try:
        task_id = UUID(_required_string(content, "task_id"))
        evidence_id = UUID(_required_string(content, "evidence_id"))
        generation_id = UUID(_required_string(content, "generation_id"))
        projection_class = EvidenceProjectionClass(_required_string(content, "projection_class"))
        access = EvidenceAccessClass(_required_string(content, "access_classification"))
        source_captured_at = _parse_timestamp(content.get("source_captured_at"))
        indexed_at = _parse_timestamp(content.get("indexed_at"))
    except (ValueError, TypeError):
        raise RetrievalIndexValidationError("retrieval chunk metadata is invalid") from None
    ordinal = _required_integer(content, "ordinal", minimum=1)
    start = _required_integer(content, "start_offset", minimum=0)
    end = _required_integer(content, "end_offset", minimum=start + 1)
    text = _required_string(content, "text", allow_empty=False)
    if end - start != len(text):
        raise RetrievalIndexValidationError("retrieval chunk span is invalid")
    return _ChunkPayload(
        task_id=task_id,
        evidence_id=evidence_id,
        generation_id=generation_id,
        index_version=_required_version(_required_string(content, "index_version")),
        chunker_version=_required_version(_required_string(content, "chunker_version")),
        verifier_version=_required_version(_required_string(content, "verifier_version")),
        projection_class=projection_class,
        access_classification=access,
        source_hash=_required_hash(content, "source_hash"),
        source_envelope_hash=_required_hash(content, "source_envelope_hash"),
        chunk_hash=_required_hash(content, "chunk_hash"),
        source_captured_at=source_captured_at,
        indexed_at=indexed_at,
        ordinal=ordinal,
        start_offset=start,
        end_offset=end,
        text=text,
    )


def _verify_chunk_payload(
    payload: _ChunkPayload,
    *,
    task_id: UUID,
    generation: RetrievalIndexGeneration,
    chunk: RetrievalIndexChunk,
    derivative: EvidenceDerivative,
    record: EvidenceRecord,
    source_hash: str,
    source_text: str,
) -> None:
    expected_start = (payload.ordinal - 1) * (RETRIEVAL_CHUNK_CHARACTERS - RETRIEVAL_CHUNK_OVERLAP)
    expected_end = min(len(source_text), expected_start + RETRIEVAL_CHUNK_CHARACTERS)
    if (
        payload.task_id != task_id
        or payload.task_id != chunk.task_id
        or payload.evidence_id != record.id
        or payload.evidence_id != chunk.evidence_id
        or derivative.evidence_id != record.id
        or derivative.id != chunk.derivative_id
        or payload.generation_id != generation.id
        or payload.generation_id != chunk.generation_id
        or payload.index_version != generation.index_version
        or payload.index_version != chunk.index_version
        or payload.chunker_version != generation.chunker_version
        or payload.chunker_version != chunk.chunker_version
        or payload.chunker_version != RETRIEVAL_CHUNKER_VERSION
        or payload.verifier_version != generation.verifier_version
        or payload.verifier_version != chunk.verifier_version
        or payload.verifier_version != RETRIEVAL_VERIFIER_VERSION
        or payload.projection_class.value != chunk.projection_class
        or payload.source_hash != source_hash
        or payload.source_hash != chunk.source_hash
        or payload.source_envelope_hash != record.content_hash
        or payload.source_envelope_hash != chunk.source_envelope_hash
        or payload.access_classification.value != record.access_classification
        or payload.access_classification.value != chunk.access_classification
        or payload.source_captured_at != normalize_evidence_timestamp(record.captured_at)
        or payload.source_captured_at != normalize_evidence_timestamp(chunk.source_captured_at)
        or payload.indexed_at != normalize_evidence_timestamp(derivative.captured_at)
        or payload.indexed_at != normalize_evidence_timestamp(generation.indexed_at)
        or payload.indexed_at != normalize_evidence_timestamp(chunk.indexed_at)
        or payload.ordinal != chunk.ordinal
        or payload.start_offset != chunk.start_offset
        or payload.end_offset != chunk.end_offset
        or payload.start_offset != expected_start
        or payload.end_offset != expected_end
        or payload.text != source_text[expected_start:expected_end]
        or payload.chunk_hash != chunk.chunk_hash
        or payload.chunk_hash != _digest(payload.text.encode("utf-8"))
        or chunk.lexical_term_frequencies != _term_frequencies(payload.text, generation.id)
    ):
        raise RetrievalIndexValidationError("retrieval chunk verification failed")


def _query_terms(query: str) -> tuple[str, ...]:
    normalized = query.strip()
    if not normalized or len(normalized) > MAX_SEARCH_QUERY_CHARACTERS:
        raise RetrievalIndexValidationError("retrieval query is invalid")
    terms = tuple(dict.fromkeys(_TERM.findall(normalized.casefold())))
    if not terms:
        raise RetrievalIndexValidationError("retrieval query is invalid")
    return terms


def _lexical_score(text: str, terms: tuple[str, ...]) -> float:
    frequencies = Counter(_TERM.findall(text.casefold()))
    matches = sum(frequencies[term] for term in terms)
    return matches / len(terms)


def _term_key(term: str, generation_id: UUID) -> str:
    payload = generation_id.bytes + b"\0" + term.encode("utf-8")
    return _digest(payload)


def _term_frequencies(text: str, generation_id: UUID) -> dict[str, int]:
    frequencies = Counter(_TERM.findall(text.casefold()))
    return {_term_key(term, generation_id): count for term, count in sorted(frequencies.items())}


def _projected_score(
    frequencies: Mapping[str, int],
    query_hashes: tuple[str, ...],
) -> float:
    return sum(frequencies.get(term_hash, 0) for term_hash in query_hashes) / len(query_hashes)


def _may_be_browser_accessible(
    chunk: RetrievalIndexChunk,
    authentication: AuthenticatedSession,
    *,
    now: datetime,
) -> bool:
    if chunk.access_classification == EvidenceAccessClass.INTERNAL.value:
        return False
    if chunk.access_classification == EvidenceAccessClass.RECENT_PASSWORD.value:
        return (
            authentication.recent_password_verified
            and normalize_evidence_timestamp(authentication.reauthenticated_until) > now
        )
    return True


def _required_string(
    content: Mapping[object, object],
    key: str,
    *,
    allow_empty: bool = True,
) -> str:
    value = content.get(key)
    if not isinstance(value, str) or (not allow_empty and not value):
        raise RetrievalIndexValidationError("retrieval chunk metadata is invalid")
    return value


def _required_integer(
    content: Mapping[object, object],
    key: str,
    *,
    minimum: int,
) -> int:
    value = content.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise RetrievalIndexValidationError("retrieval chunk metadata is invalid")
    return value


def _required_hash(content: Mapping[object, object], key: str) -> str:
    value = _required_string(content, key)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise RetrievalIndexValidationError("retrieval chunk hash is invalid")
    return value


def _required_version(value: str) -> str:
    normalized = value.strip()
    if not _VERSION.fullmatch(normalized):
        raise RetrievalIndexValidationError("retrieval index version is invalid")
    return normalized


def _required_actor(value: str) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > 255:
        raise RetrievalIndexValidationError("retrieval actor is invalid")
    return normalized


def _derivative_type(task_id: UUID) -> str:
    return f"{RETRIEVAL_DERIVATIVE_TYPE_PREFIX}{task_id}"


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise RetrievalIndexValidationError("retrieval chunk timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise RetrievalIndexValidationError("retrieval chunk timestamp is invalid") from None
    return normalize_evidence_timestamp(parsed)


def _timestamp(value: datetime) -> str:
    return normalize_evidence_timestamp(value).isoformat().replace("+00:00", "Z")


def _digest(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _http_error(error: RetrievalIndexError | EvidenceError) -> HTTPException:
    if isinstance(error, (RetrievalIndexValidationError, EvidenceValidationError)):
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="retrieval request is invalid",
        )
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="retrieval index not found",
    )


AuthenticatedRetrievalSession = Annotated[
    AuthenticatedSession,
    Depends(require_authenticated_session),
]


def create_retrieval_index_router(service: RetrievalIndexService) -> APIRouter:
    router = APIRouter(prefix="/api/retrieval", tags=["retrieval"])

    @router.get(
        "/tasks/{task_id}/search",
        response_model=RetrievalSearchResponse,
    )
    def search(
        task_id: UUID,
        response: Response,
        authentication: AuthenticatedRetrievalSession,
        q: Annotated[str, Query(min_length=1, max_length=MAX_SEARCH_QUERY_CHARACTERS)],
        limit: Annotated[int, Query(ge=1, le=MAX_SEARCH_RESULTS)] = 20,
    ) -> RetrievalSearchResponse:
        try:
            result = service.search(task_id, q, authentication, limit=limit)
        except (RetrievalIndexError, EvidenceError) as error:
            raise _http_error(error) from None
        response.headers["Cache-Control"] = "no-store"
        return RetrievalSearchResponse.model_validate(result)

    return router
