from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from mathews_control_plane.app import create_app
from mathews_control_plane.artifacts import ArtifactNotFoundError, ArtifactStore
from mathews_control_plane.authentication import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    AuthenticatedSession,
    AuthenticationService,
    generate_bootstrap_token,
)
from mathews_control_plane.database import (
    Base,
    SessionFactory,
    create_database_engine,
    create_session_factory,
)
from mathews_control_plane.domain_models import (
    EvidenceAuditEvent,
    EvidenceDerivative,
    EvidenceRecord,
    RetrievalIndexChunk,
    RetrievalIndexGeneration,
    Task,
    TaskEvent,
    TaskEventEvidenceReference,
    TaskState,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceAuditEventType,
    EvidenceDeletionReason,
    EvidenceRetentionClass,
    EvidenceService,
    EvidenceSourceKind,
    capture_evidence,
    create_correction,
    destroy_evidence_derivative,
    load_evidence,
    load_evidence_derivative,
    register_evidence_derivative,
)
from mathews_control_plane.evidence_projections import EvidenceProjectionService
from mathews_control_plane.retrieval_index import (
    RETRIEVAL_CHUNKER_VERSION,
    RETRIEVAL_DERIVATIVE_TYPE_PREFIX,
    RETRIEVAL_VERIFIER_VERSION,
    RetrievalIndexService,
    RetrievalIndexValidationError,
    _term_frequencies,
)
from mathews_control_plane.settings import Settings
from pydantic import SecretStr
from sqlalchemy import Engine, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

_ORIGIN = "http://localhost:3000"
_PASSWORD = "correct horse battery staple"  # noqa: S105 - test-only credential


@dataclass(slots=True)
class RetrievalHarness:
    engine: Engine
    factory: SessionFactory
    store: ArtifactStore
    now: datetime


@pytest.fixture
def retrieval_harness(tmp_path: Path) -> Iterator[RetrievalHarness]:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'retrieval.sqlite3'}")
    Base.metadata.create_all(engine)
    harness = RetrievalHarness(
        engine=engine,
        factory=create_session_factory(engine),
        store=ArtifactStore(tmp_path / "artifacts"),
        now=datetime(2026, 8, 11, 12, 0, tzinfo=UTC),
    )
    try:
        yield harness
    finally:
        engine.dispose()


def _authentication(
    now: datetime,
    *,
    recent_password_verified: bool = True,
) -> AuthenticatedSession:
    return AuthenticatedSession(
        session_id=uuid4(),
        user_id=1,
        csrf_token_digest=b"x" * 32,
        expires_at=now + timedelta(minutes=30),
        absolute_expires_at=now + timedelta(hours=2),
        reauthenticated_until=now + timedelta(minutes=5),
        evaluated_at=now,
        recent_password_verified=recent_password_verified,
    )


def _task() -> Task:
    root = uuid4()
    return Task(
        repository="boppuh/mathews",
        base_revision="a" * 40,
        requester="local-user",
        raw_request="build a retrieval index",
        summary="Build a retrieval index",
        state=TaskState.INTAKE,
        owner_id="local-user",
        actor_id="local-user",
        root_correlation_id=root,
    )


def _capture(
    harness: RetrievalHarness,
    session: Session,
    *,
    task_id: UUID | None,
    content: object,
    evidence_type: str = "task-request",
    source_kind: EvidenceSourceKind = EvidenceSourceKind.REQUEST,
    access: EvidenceAccessClass = EvidenceAccessClass.OWNER,
) -> EvidenceRecord:
    return capture_evidence(
        session,
        harness.store,
        payload=content,
        media_type="application/json",
        source_kind=source_kind,
        evidence_type=evidence_type,
        origin="test:retrieval",
        access_classification=access,
        retention_policy=EvidenceRetentionClass.AUDIT,
        owner_id="local-user",
        actor_id="retrieval-test",
        root_correlation_id=uuid4(),
        task_id=task_id,
        captured_at=harness.now,
    ).record


def _link_internal_source(
    session: Session,
    *,
    task: Task,
    evidence: EvidenceRecord,
    occurred_at: datetime,
) -> None:
    event = TaskEvent(
        task_id=task.id,
        sequence=1,
        event_type="GITHUB_CHECK_UPDATED",
        payload={"status": "completed"},
        occurred_at=occurred_at,
        owner_id=task.owner_id,
        actor_id="github-webhook-worker",
        root_correlation_id=task.root_correlation_id,
    )
    session.add(event)
    session.flush()
    session.add(
        TaskEventEvidenceReference(
            task_id=task.id,
            task_event_id=event.id,
            evidence_id=evidence.id,
            position=1,
            owner_id=task.owner_id,
            actor_id="github-webhook-worker",
            root_correlation_id=task.root_correlation_id,
        )
    )


def _service(harness: RetrievalHarness) -> RetrievalIndexService:
    projections = EvidenceProjectionService(
        harness.factory,
        harness.store,
        clock=lambda: harness.now,
    )
    return RetrievalIndexService(
        harness.factory,
        harness.store,
        projections,
        clock=lambda: harness.now,
    )


def test_rebuild_indexes_verified_sources_and_filters_every_search_by_access(
    retrieval_harness: RetrievalHarness,
) -> None:
    with retrieval_harness.factory.begin() as session:
        task = _task()
        session.add(task)
        session.flush()
        owner = _capture(
            retrieval_harness,
            session,
            task_id=task.id,
            content={"message": "searchable alpha owner"},
        )
        recent = _capture(
            retrieval_harness,
            session,
            task_id=task.id,
            content={"message": "searchable beta protected"},
            evidence_type="protected-result",
            source_kind=EvidenceSourceKind.RESULT,
            access=EvidenceAccessClass.RECENT_PASSWORD,
        )
        internal = _capture(
            retrieval_harness,
            session,
            task_id=None,
            content={"event_name": "check_run", "message": "searchable gamma internal"},
            evidence_type="github-webhook",
            source_kind=EvidenceSourceKind.EXTERNAL_EVENT,
            access=EvidenceAccessClass.INTERNAL,
        )
        _link_internal_source(
            session,
            task=task,
            evidence=internal,
            occurred_at=retrieval_harness.now,
        )
        task_id = task.id

    service = _service(retrieval_harness)
    built = service.rebuild_task_index_internal(
        task_id,
        index_version="retrieval-v1",
        actor_id="retrieval-indexer",
    )
    assert built.source_count == 3
    assert built.chunk_count == 3
    assert built.removed_chunk_count == 0
    assert built.chunker_version == RETRIEVAL_CHUNKER_VERSION
    assert built.verifier_version == RETRIEVAL_VERIFIER_VERSION

    ordinary = service.search(
        task_id,
        "searchable",
        _authentication(
            retrieval_harness.now,
            recent_password_verified=False,
        ),
    )
    assert {hit.evidence_id for hit in ordinary.hits} == {owner.id}
    assert all(hit.generation_id == built.generation_id for hit in ordinary.hits)
    assert all(hit.source_hash.startswith("sha256:") for hit in ordinary.hits)
    assert all(hit.chunk_hash.startswith("sha256:") for hit in ordinary.hits)
    assert all(hit.indexed_at.tzinfo == UTC for hit in ordinary.hits)

    reauthenticated = service.search(
        task_id,
        "searchable",
        _authentication(retrieval_harness.now),
    )
    assert {hit.evidence_id for hit in reauthenticated.hits} == {
        owner.id,
        recent.id,
    }
    assert internal.id not in {hit.evidence_id for hit in reauthenticated.hits}
    with retrieval_harness.factory() as session:
        assert session.scalar(select(func.count()).select_from(EvidenceRecord)) == 3
        assert (
            session.scalar(
                select(func.count())
                .select_from(EvidenceDerivative)
                .where(
                    EvidenceDerivative.derivative_type.startswith(RETRIEVAL_DERIVATIVE_TYPE_PREFIX)
                )
            )
            == 3
        )
        downloaded = set(
            session.scalars(
                select(EvidenceAuditEvent.evidence_id).where(
                    EvidenceAuditEvent.event_type == EvidenceAuditEventType.CONTENT_DOWNLOADED.value
                )
            )
        )
        assert {owner.id, recent.id} <= downloaded


def test_source_deletion_destroys_chunks_and_rebuild_cannot_reconstruct_them(
    retrieval_harness: RetrievalHarness,
) -> None:
    with retrieval_harness.factory.begin() as session:
        task = _task()
        session.add(task)
        session.flush()
        source = _capture(
            retrieval_harness,
            session,
            task_id=task.id,
            content={"message": "deletion sentinel"},
        )
        task_id = task.id
    service = _service(retrieval_harness)
    built = service.rebuild_task_index_internal(
        task_id,
        index_version="retrieval-v1",
        actor_id="retrieval-indexer",
    )
    assert built.chunk_count == 1
    with retrieval_harness.factory() as session:
        derivative = session.scalar(
            select(EvidenceDerivative).where(
                EvidenceDerivative.evidence_id == source.id,
                EvidenceDerivative.deleted_at.is_(None),
            )
        )
        assert derivative is not None
        address = derivative.content_address
    assert address is not None

    evidence_service = EvidenceService(
        retrieval_harness.factory,
        retrieval_harness.store,
        clock=lambda: retrieval_harness.now + timedelta(minutes=1),
    )
    evidence_service.delete(
        source.id,
        _authentication(retrieval_harness.now + timedelta(minutes=1)),
        EvidenceDeletionReason.USER_REQUEST,
    )
    with pytest.raises(ArtifactNotFoundError):
        retrieval_harness.store.get_bytes(address)
    with retrieval_harness.factory() as session:
        deleted_chunk = session.scalar(
            select(RetrievalIndexChunk).where(RetrievalIndexChunk.evidence_id == source.id)
        )
        assert deleted_chunk is not None
        assert deleted_chunk.deleted_at is not None
        assert deleted_chunk.lexical_term_frequencies == {}
    result = service.search(
        task_id,
        "sentinel",
        _authentication(retrieval_harness.now),
    )
    assert result.hits == ()
    rebuilt = service.rebuild_task_index_internal(
        task_id,
        index_version="retrieval-v2",
        actor_id="retrieval-indexer",
    )
    assert rebuilt.source_count == 0
    assert rebuilt.chunk_count == 0
    with retrieval_harness.factory() as session:
        live = session.scalar(
            select(func.count())
            .select_from(EvidenceDerivative)
            .where(
                EvidenceDerivative.evidence_id == source.id,
                EvidenceDerivative.deleted_at.is_(None),
            )
        )
    assert live == 0


def test_index_deletion_and_rebuild_preserve_canonical_source(
    retrieval_harness: RetrievalHarness,
) -> None:
    with retrieval_harness.factory.begin() as session:
        task = _task()
        session.add(task)
        session.flush()
        source = _capture(
            retrieval_harness,
            session,
            task_id=task.id,
            content={"message": "durable source searchable"},
        )
        task_id = task.id
    service = _service(retrieval_harness)
    first = service.rebuild_task_index_internal(
        task_id,
        index_version="retrieval-v1",
        actor_id="retrieval-indexer",
    )
    with retrieval_harness.factory() as session:
        first_derivative = session.scalar(
            select(EvidenceDerivative).where(
                EvidenceDerivative.evidence_id == source.id,
                EvidenceDerivative.deleted_at.is_(None),
            )
        )
        assert first_derivative is not None
        first_address = first_derivative.content_address
    assert first_address is not None

    second = service.rebuild_task_index_internal(
        task_id,
        index_version="retrieval-v2",
        actor_id="retrieval-indexer",
    )
    assert second.removed_chunk_count == first.chunk_count
    assert second.generation_id != first.generation_id
    with pytest.raises(ArtifactNotFoundError):
        retrieval_harness.store.get_bytes(first_address)
    with retrieval_harness.factory() as session:
        persisted_source = session.get(EvidenceRecord, source.id)
        assert persisted_source is not None
        assert load_evidence(
            session,
            retrieval_harness.store,
            persisted_source,
        ).content == {"message": "durable source searchable"}
    searched = service.search(
        task_id,
        "durable",
        _authentication(retrieval_harness.now),
    )
    assert searched.generation_id == second.generation_id
    assert searched.index_version == "retrieval-v2"
    assert [hit.evidence_id for hit in searched.hits] == [source.id]
    with retrieval_harness.factory() as session:
        generations = tuple(
            session.scalars(
                select(RetrievalIndexGeneration)
                .where(RetrievalIndexGeneration.task_id == task_id)
                .order_by(RetrievalIndexGeneration.indexed_at)
            )
        )
        assert len(generations) == 2
        assert [item.id for item in generations if item.deleted_at is None] == [
            second.generation_id
        ]
        live_chunk_generations = set(
            session.scalars(
                select(RetrievalIndexChunk.generation_id).where(
                    RetrievalIndexChunk.deleted_at.is_(None)
                )
            )
        )
        assert live_chunk_generations == {second.generation_id}


def test_database_rejects_two_current_generations_for_one_task(
    retrieval_harness: RetrievalHarness,
) -> None:
    with retrieval_harness.factory.begin() as session:
        task = _task()
        session.add(task)
        session.flush()
        task_id = task.id
        context = {
            "task_id": task_id,
            "index_version": "retrieval-v1",
            "chunker_version": RETRIEVAL_CHUNKER_VERSION,
            "verifier_version": RETRIEVAL_VERIFIER_VERSION,
            "indexed_at": retrieval_harness.now,
            "source_count": 0,
            "chunk_count": 0,
            "owner_id": task.owner_id,
            "actor_id": "retrieval-indexer",
            "root_correlation_id": task.root_correlation_id,
        }
        session.add(RetrievalIndexGeneration(**context))

    with pytest.raises(IntegrityError):
        with retrieval_harness.factory.begin() as session:
            session.add(RetrievalIndexGeneration(**context))


def test_search_rejects_unverified_chunk_versions(
    retrieval_harness: RetrievalHarness,
) -> None:
    with retrieval_harness.factory.begin() as session:
        task = _task()
        session.add(task)
        session.flush()
        _capture(
            retrieval_harness,
            session,
            task_id=task.id,
            content={"message": "version sentinel"},
        )


def test_search_rejects_a_chunk_that_is_not_the_canonical_source_slice(
    retrieval_harness: RetrievalHarness,
) -> None:
    with retrieval_harness.factory.begin() as session:
        task = _task()
        session.add(task)
        session.flush()
        _capture(
            retrieval_harness,
            session,
            task_id=task.id,
            content={"message": "canonical sentinel"},
        )
        task_id = task.id
    service = _service(retrieval_harness)
    service.rebuild_task_index_internal(
        task_id,
        index_version="retrieval-v1",
        actor_id="retrieval-indexer",
    )
    with retrieval_harness.factory.begin() as session:
        generation = session.scalar(
            select(RetrievalIndexGeneration).where(
                RetrievalIndexGeneration.task_id == task_id,
                RetrievalIndexGeneration.deleted_at.is_(None),
            )
        )
        chunk = session.scalar(
            select(RetrievalIndexChunk).where(
                RetrievalIndexChunk.task_id == task_id,
                RetrievalIndexChunk.deleted_at.is_(None),
            )
        )
        assert generation is not None and chunk is not None
        derivative = session.get(EvidenceDerivative, chunk.derivative_id)
        assert derivative is not None
        content = load_evidence_derivative(
            session,
            retrieval_harness.store,
            derivative,
        ).content
        assert isinstance(content, dict)
        forged = dict(content)
        forged_text = str(forged["text"]).replace("canonical", "malicious")
        assert len(forged_text) == len(str(forged["text"]))
        forged_hash = f"sha256:{hashlib.sha256(forged_text.encode()).hexdigest()}"
        forged["text"] = forged_text
        forged["chunk_hash"] = forged_hash
        destroy_evidence_derivative(
            retrieval_harness.store,
            derivative,
            deleted_at=retrieval_harness.now,
        )
        replacement = register_evidence_derivative(
            session,
            retrieval_harness.store,
            evidence_id=chunk.evidence_id,
            derivative_type=f"{RETRIEVAL_DERIVATIVE_TYPE_PREFIX}{task_id}",
            payload=forged,
            media_type="application/json",
            actor_id="malformed-builder",
            captured_at=retrieval_harness.now,
        )
        chunk.derivative_id = replacement.id
        chunk.chunk_hash = forged_hash
        chunk.lexical_term_frequencies = _term_frequencies(forged_text, generation.id)

    with pytest.raises(RetrievalIndexValidationError, match="verification failed"):
        service.search(
            task_id,
            "malicious",
            _authentication(retrieval_harness.now),
        )
        task_id = task.id
    service = _service(retrieval_harness)
    service.rebuild_task_index_internal(
        task_id,
        index_version="retrieval-v1",
        actor_id="retrieval-indexer",
    )
    with retrieval_harness.factory.begin() as session:
        chunk = session.scalar(
            select(RetrievalIndexChunk).where(
                RetrievalIndexChunk.task_id == task_id,
                RetrievalIndexChunk.deleted_at.is_(None),
            )
        )
        assert chunk is not None
        chunk.chunker_version = "unsupported-v0"

    with pytest.raises(RetrievalIndexValidationError, match="verification failed"):
        service.search(
            task_id,
            "sentinel",
            _authentication(retrieval_harness.now),
        )


def test_search_verifies_only_a_bounded_ranked_candidate_window(
    retrieval_harness: RetrievalHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with retrieval_harness.factory.begin() as session:
        task = _task()
        session.add(task)
        session.flush()
        _capture(
            retrieval_harness,
            session,
            task_id=task.id,
            content={"message": f"{'filler ' * 20_000} needlespecial"},
        )
        task_id = task.id
    service = _service(retrieval_harness)
    built = service.rebuild_task_index_internal(
        task_id,
        index_version="retrieval-v1",
        actor_id="retrieval-indexer",
    )
    assert built.chunk_count > 100
    artifact_reads = 0
    original_get_bytes = retrieval_harness.store.get_bytes

    def counted_get_bytes(address: str) -> bytes:
        nonlocal artifact_reads
        artifact_reads += 1
        return original_get_bytes(address)

    monkeypatch.setattr(retrieval_harness.store, "get_bytes", counted_get_bytes)
    result = service.search(
        task_id,
        "needlespecial",
        _authentication(retrieval_harness.now),
    )
    assert len(result.hits) == 1
    assert artifact_reads <= 4


def test_task_scoped_generations_do_not_delete_shared_source_chunks(
    retrieval_harness: RetrievalHarness,
) -> None:
    with retrieval_harness.factory.begin() as session:
        first_task = _task()
        second_task = _task()
        session.add_all((first_task, second_task))
        session.flush()
        shared = _capture(
            retrieval_harness,
            session,
            task_id=None,
            content={"message": "shared retrieval source"},
            evidence_type="external-event",
            source_kind=EvidenceSourceKind.EXTERNAL_EVENT,
        )
        _link_internal_source(
            session,
            task=first_task,
            evidence=shared,
            occurred_at=retrieval_harness.now,
        )
        _link_internal_source(
            session,
            task=second_task,
            evidence=shared,
            occurred_at=retrieval_harness.now,
        )
        first_task_id = first_task.id
        second_task_id = second_task.id
    service = _service(retrieval_harness)
    service.rebuild_task_index_internal(
        first_task_id,
        index_version="retrieval-v1",
        actor_id="retrieval-indexer",
    )
    second_build = service.rebuild_task_index_internal(
        second_task_id,
        index_version="retrieval-v1",
        actor_id="retrieval-indexer",
    )

    assert (
        service.delete_task_index_internal(
            first_task_id,
            actor_id="retrieval-indexer",
        )
        == 1
    )
    second_result = service.search(
        second_task_id,
        "shared",
        _authentication(retrieval_harness.now),
    )
    assert second_result.generation_id == second_build.generation_id
    assert [hit.evidence_id for hit in second_result.hits] == [shared.id]


def test_correction_invalidates_stale_chunks_until_rebuild(
    retrieval_harness: RetrievalHarness,
) -> None:
    authentication = _authentication(retrieval_harness.now)
    with retrieval_harness.factory.begin() as session:
        task = _task()
        session.add(task)
        session.flush()
        original = _capture(
            retrieval_harness,
            session,
            task_id=task.id,
            content={"message": "legacyterm"},
            evidence_type="owner-result",
            source_kind=EvidenceSourceKind.RESULT,
        )
        task_id = task.id
    service = _service(retrieval_harness)
    service.rebuild_task_index_internal(
        task_id,
        index_version="retrieval-v1",
        actor_id="retrieval-indexer",
    )
    with retrieval_harness.factory.begin() as session:
        correction = create_correction(
            session,
            retrieval_harness.store,
            evidence_id=original.id,
            payload={"message": "correctedterm"},
            media_type="application/json",
            authentication=authentication,
            now=retrieval_harness.now + timedelta(seconds=1),
        )
    stale = service.search(task_id, "legacyterm", authentication)
    assert stale.hits == ()

    service.rebuild_task_index_internal(
        task_id,
        index_version="retrieval-v2",
        actor_id="retrieval-indexer",
    )
    current = service.search(task_id, "correctedterm", authentication)
    assert [hit.evidence_id for hit in current.hits] == [correction.record.id]


def test_retrieval_route_requires_authentication_and_disables_caching(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'retrieval-api.sqlite3'}"
    engine = create_database_engine(database_url)
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    now = datetime.now(UTC).replace(microsecond=0)
    store = ArtifactStore(tmp_path / "artifacts")
    harness = RetrievalHarness(engine, factory, store, now)
    projections = EvidenceProjectionService(factory, store, clock=lambda: now)
    retrieval = RetrievalIndexService(
        factory,
        store,
        projections,
        clock=lambda: now,
    )
    authentication_service = AuthenticationService(factory, clock=lambda: now)
    with factory.begin() as session:
        task = _task()
        session.add(task)
        session.flush()
        source = _capture(
            harness,
            session,
            task_id=task.id,
            content={"message": "api retrieval sentinel"},
        )
        task_id = task.id
    retrieval.rebuild_task_index_internal(
        task_id,
        index_version="retrieval-v1",
        actor_id="retrieval-indexer",
    )
    app = create_app(
        Settings(database_url=SecretStr(database_url), artifact_root=store.root),
        session_factory=factory,
        authentication_service=authentication_service,
        evidence_projection_service=projections,
        retrieval_index_service=retrieval,
    )
    client = TestClient(app, base_url="https://localhost")
    try:
        path = f"/api/retrieval/tasks/{task_id}/search?q=sentinel"
        assert client.get(path).status_code == 401
        bootstrap_token = generate_bootstrap_token(factory)
        assert client.get("/api/auth/status").status_code == 200
        csrf_token = client.cookies.get(CSRF_COOKIE_NAME)
        assert csrf_token is not None
        bootstrap = client.post(
            "/api/auth/bootstrap",
            json={"bootstrap_token": bootstrap_token, "password": _PASSWORD},
            headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
        )
        assert bootstrap.status_code == 201
        response = client.get(path)
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        assert response.json()["hits"][0]["evidence_id"] == str(source.id)
        assert response.json()["index_version"] == "retrieval-v1"
    finally:
        client.close()
        engine.dispose()


def test_default_app_retrieval_service_uses_the_configured_artifact_root(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'default-retrieval.sqlite3'}"
    engine = create_database_engine(database_url)
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    artifact_root = tmp_path / "configured-artifacts"
    store = ArtifactStore(artifact_root)
    settings = Settings(
        database_url=SecretStr(database_url),
        artifact_root=artifact_root,
    )
    try:
        with factory.begin() as session:
            task = _task()
            session.add(task)
            session.flush()
            _capture(
                RetrievalHarness(engine, factory, store, datetime.now(UTC)),
                session,
                task_id=task.id,
                content={"message": "default construction"},
            )
            task_id = task.id
        app = create_app(settings, session_factory=factory)
        with TestClient(app, base_url="https://localhost"):
            pass
        with factory() as session:
            generation = session.scalar(
                select(RetrievalIndexGeneration).where(
                    RetrievalIndexGeneration.task_id == task_id,
                    RetrievalIndexGeneration.deleted_at.is_(None),
                )
            )
            assert generation is not None
            assert generation.chunk_count == 1
    finally:
        engine.dispose()


def test_refresh_worker_rebuilds_an_index_after_new_evidence_activity(
    retrieval_harness: RetrievalHarness,
) -> None:
    with retrieval_harness.factory.begin() as session:
        task = _task()
        session.add(task)
        session.flush()
        _capture(
            retrieval_harness,
            session,
            task_id=task.id,
            content={"message": "initial evidence"},
        )
        task_id = task.id
    first_service = _service(retrieval_harness)
    assert first_service.refresh_stale_task_indexes_internal(actor_id="retrieval-index-worker") == (
        task_id,
    )
    assert (
        first_service.refresh_stale_task_indexes_internal(actor_id="retrieval-index-worker") == ()
    )

    later = retrieval_harness.now + timedelta(minutes=2)
    later_harness = RetrievalHarness(
        retrieval_harness.engine,
        retrieval_harness.factory,
        retrieval_harness.store,
        later,
    )
    with retrieval_harness.factory.begin() as session:
        second = _capture(
            later_harness,
            session,
            task_id=task_id,
            content={"message": "newly indexed evidence"},
        )
    later_service = _service(later_harness)
    assert later_service.refresh_stale_task_indexes_internal(actor_id="retrieval-index-worker") == (
        task_id,
    )
    result = later_service.search(
        task_id,
        "newly",
        _authentication(later),
    )
    assert [hit.evidence_id for hit in result.hits] == [second.id]


def test_default_retrieval_service_rejects_a_projection_store_mismatch(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'mismatched-retrieval.sqlite3'}"
    engine = create_database_engine(database_url)
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    configured_root = tmp_path / "configured-artifacts"
    projections = EvidenceProjectionService(
        factory,
        ArtifactStore(tmp_path / "different-artifacts"),
    )
    try:
        with pytest.raises(ValueError, match="must share an artifact root"):
            create_app(
                Settings(
                    database_url=SecretStr(database_url),
                    artifact_root=configured_root,
                ),
                session_factory=factory,
                evidence_projection_service=projections,
            )
    finally:
        engine.dispose()
