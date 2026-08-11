from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from mathews_control_plane.app import create_app
from mathews_control_plane.artifacts import ArtifactStore
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
    EvidenceDerivative,
    EvidenceRecord,
    Task,
    TaskEvent,
    TaskEventEvidenceReference,
    TaskState,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceDeletionReason,
    EvidenceNotFoundError,
    EvidenceRetentionClass,
    EvidenceService,
    EvidenceSourceKind,
    capture_evidence,
    create_correction,
    register_evidence_derivative,
)
from mathews_control_plane.evidence_projections import (
    EvidenceDerivativeStatus,
    EvidenceLineageStatus,
    EvidenceProjectionClass,
    EvidenceProjectionService,
    EvidenceVerificationStatus,
    ProvenanceEdgeKind,
)
from mathews_control_plane.settings import Settings
from pydantic import SecretStr
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

_ORIGIN = "http://localhost:3000"
_PASSWORD = "correct horse battery staple"  # noqa: S105 - test-only credential


@dataclass(slots=True)
class ProjectionHarness:
    engine: Engine
    factory: SessionFactory
    store: ArtifactStore
    now: datetime


@pytest.fixture
def projection_harness(tmp_path: Path) -> Iterator[ProjectionHarness]:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'projections.sqlite3'}")
    Base.metadata.create_all(engine)
    harness = ProjectionHarness(
        engine=engine,
        factory=create_session_factory(engine),
        store=ArtifactStore(tmp_path / "artifacts"),
        now=datetime(2026, 8, 10, 12, 0, tzinfo=UTC),
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
    correlation_id = uuid4()
    return Task(
        repository="boppuh/mathews",
        base_revision="a" * 40,
        requester="local-user",
        raw_request="project verified evidence",
        summary="Project verified evidence",
        state=TaskState.INTAKE,
        owner_id="local-user",
        actor_id="local-user",
        root_correlation_id=correlation_id,
    )


def _capture(
    harness: ProjectionHarness,
    session: Session,
    *,
    task_id: UUID | None,
    evidence_type: str,
    source_kind: EvidenceSourceKind,
    content: object,
    access: EvidenceAccessClass = EvidenceAccessClass.OWNER,
    parent_correlation_id: UUID | None = None,
) -> EvidenceRecord:
    captured = capture_evidence(
        session,
        harness.store,
        payload=content,
        media_type="application/json",
        source_kind=source_kind,
        evidence_type=evidence_type,
        origin="test:projection",
        access_classification=access,
        retention_policy=EvidenceRetentionClass.AUDIT,
        owner_id="local-user",
        actor_id="projection-test",
        root_correlation_id=uuid4(),
        task_id=task_id,
        parent_correlation_id=parent_correlation_id,
        captured_at=harness.now,
    )
    return captured.record


def _link_to_task(
    session: Session,
    *,
    task: Task,
    evidence: tuple[EvidenceRecord, ...],
    occurred_at: datetime,
) -> None:
    event = TaskEvent(
        task_id=task.id,
        sequence=1,
        event_type="GITHUB_UPDATE",
        payload={"count": len(evidence)},
        occurred_at=occurred_at,
        owner_id=task.owner_id,
        actor_id="github-webhook-worker",
        root_correlation_id=task.root_correlation_id,
    )
    session.add(event)
    session.flush()
    for position, record in enumerate(evidence, start=1):
        session.add(
            TaskEventEvidenceReference(
                task_id=task.id,
                task_event_id=event.id,
                evidence_id=record.id,
                position=position,
                owner_id=task.owner_id,
                actor_id="github-webhook-worker",
                root_correlation_id=task.root_correlation_id,
            )
        )


def test_internal_task_view_classifies_all_verified_sources_without_copying(
    projection_harness: ProjectionHarness,
) -> None:
    with projection_harness.factory.begin() as session:
        task = _task()
        session.add(task)
        session.flush()
        request = _capture(
            projection_harness,
            session,
            task_id=task.id,
            evidence_type="task-request",
            source_kind=EvidenceSourceKind.REQUEST,
            content={"request": "implement"},
        )
        _capture(
            projection_harness,
            session,
            task_id=task.id,
            evidence_type="workspace-diff",
            source_kind=EvidenceSourceKind.REPOSITORY_SNAPSHOT,
            content={"head": "a" * 40},
            parent_correlation_id=request.id,
        )
        _capture(
            projection_harness,
            session,
            task_id=task.id,
            evidence_type="hermes-tool-result",
            source_kind=EvidenceSourceKind.TOOL_OPERATION,
            content={"exit_code": 0},
        )
        _capture(
            projection_harness,
            session,
            task_id=task.id,
            evidence_type="validation-unit-test-output",
            source_kind=EvidenceSourceKind.RESULT,
            content={"passed": True},
        )
        review_assessment = _capture(
            projection_harness,
            session,
            task_id=task.id,
            evidence_type="review-resolution-assessment",
            source_kind=EvidenceSourceKind.RESULT,
            content={"authorized": True},
        )
        review_candidate = _capture(
            projection_harness,
            session,
            task_id=task.id,
            evidence_type="review-repair-candidate",
            source_kind=EvidenceSourceKind.RESULT,
            content={"commit_sha": "a" * 40},
        )
        ci = _capture(
            projection_harness,
            session,
            task_id=None,
            evidence_type="github-webhook",
            source_kind=EvidenceSourceKind.EXTERNAL_EVENT,
            content={"event_name": "check_run", "payload": {}},
            access=EvidenceAccessClass.INTERNAL,
        )
        review = _capture(
            projection_harness,
            session,
            task_id=None,
            evidence_type="github-webhook",
            source_kind=EvidenceSourceKind.EXTERNAL_EVENT,
            content={"event_name": "pull_request_review", "payload": {}},
            access=EvidenceAccessClass.INTERNAL,
        )
        schema_free = _capture(
            projection_harness,
            session,
            task_id=task.id,
            evidence_type="schema-free-result",
            source_kind=EvidenceSourceKind.RESULT,
            content={"event_name": ["not", "a", "string"]},
        )
        _link_to_task(
            session,
            task=task,
            evidence=(ci, review),
            occurred_at=projection_harness.now,
        )
        task_id = task.id

    service = EvidenceProjectionService(
        projection_harness.factory,
        projection_harness.store,
        clock=lambda: projection_harness.now,
    )
    result = service.task_projections_internal(
        task_id, actor_id="projection-worker"
    )

    assert {item.projection_class for item in result.projections} == {
        EvidenceProjectionClass.REQUEST,
        EvidenceProjectionClass.REPOSITORY_STATE,
        EvidenceProjectionClass.TOOL_OPERATION,
        EvidenceProjectionClass.TEST_ARTIFACT,
        EvidenceProjectionClass.CI,
        EvidenceProjectionClass.REVIEW,
        EvidenceProjectionClass.RESULT,
    }
    assert all(
        item.verification_status is EvidenceVerificationStatus.VERIFIED
        and item.source_kind is not None
        and item.envelope_hash.startswith("sha256:")
        and item.content_hash is not None
        and item.content_hash.startswith("sha256:")
        for item in result.projections
    )
    repository = next(
        item
        for item in result.projections
        if item.evidence_type == "workspace-diff"
    )
    assert repository.parent_correlation_id == request.id
    ci_view = next(item for item in result.projections if item.evidence_id == ci.id)
    assert len(ci_view.task_event_references) == 1
    assessment_view = next(
        item for item in result.projections if item.evidence_id == review_assessment.id
    )
    candidate_view = next(
        item for item in result.projections if item.evidence_id == review_candidate.id
    )
    assert assessment_view.projection_class is EvidenceProjectionClass.REVIEW
    assert candidate_view.projection_class is EvidenceProjectionClass.REPOSITORY_STATE
    assert next(
        item for item in result.projections if item.evidence_id == schema_free.id
    ).projection_class is EvidenceProjectionClass.RESULT
    with projection_harness.factory() as session:
        assert session.scalar(select(func.count()).select_from(EvidenceRecord)) == 9
        assert session.scalar(select(func.count()).select_from(EvidenceDerivative)) == 0


def test_browser_views_preserve_each_original_access_class(
    projection_harness: ProjectionHarness,
) -> None:
    with projection_harness.factory.begin() as session:
        task = _task()
        session.add(task)
        session.flush()
        owner = _capture(
            projection_harness,
            session,
            task_id=task.id,
            evidence_type="owner-result",
            source_kind=EvidenceSourceKind.RESULT,
            content={"status": "ready"},
        )
        recent = _capture(
            projection_harness,
            session,
            task_id=task.id,
            evidence_type="protected-result",
            source_kind=EvidenceSourceKind.RESULT,
            content={"status": "protected"},
            access=EvidenceAccessClass.RECENT_PASSWORD,
        )
        internal = _capture(
            projection_harness,
            session,
            task_id=task.id,
            evidence_type="internal-result",
            source_kind=EvidenceSourceKind.RESULT,
            content={"status": "internal"},
            access=EvidenceAccessClass.INTERNAL,
        )
        task_id = task.id

    service = EvidenceProjectionService(
        projection_harness.factory,
        projection_harness.store,
        clock=lambda: projection_harness.now,
    )
    ordinary = _authentication(
        projection_harness.now, recent_password_verified=False
    )
    result = service.task_projections(task_id, ordinary)
    assert {item.evidence_id for item in result.projections} == {owner.id}
    assert result.truncated is False
    with pytest.raises(EvidenceNotFoundError):
        service.provenance(recent.id, ordinary)
    with pytest.raises(EvidenceNotFoundError):
        service.provenance(internal.id, _authentication(projection_harness.now))

    reauthenticated = service.task_projections(
        task_id, _authentication(projection_harness.now)
    )
    assert {item.evidence_id for item in reauthenticated.projections} == {
        owner.id,
        recent.id,
    }
    limited = service.task_projections(
        task_id,
        _authentication(projection_harness.now),
        limit=1,
    )
    assert len(limited.projections) == 1
    assert limited.truncated is True
    assert limited.next_cursor == limited.projections[-1].evidence_id
    final_page = service.task_projections(
        task_id,
        _authentication(projection_harness.now),
        limit=1,
        after=limited.next_cursor,
    )
    assert len(final_page.projections) == 1
    assert final_page.projections[0].evidence_id != limited.projections[0].evidence_id
    assert final_page.truncated is False
    assert final_page.next_cursor is None


def test_corrections_deletions_and_derivatives_propagate_to_provenance(
    projection_harness: ProjectionHarness,
) -> None:
    authentication = _authentication(projection_harness.now)
    with projection_harness.factory.begin() as session:
        task = _task()
        session.add(task)
        session.flush()
        original = _capture(
            projection_harness,
            session,
            task_id=task.id,
            evidence_type="validation-unit-test-output",
            source_kind=EvidenceSourceKind.RESULT,
            content={"passed": False},
        )
        derivative = register_evidence_derivative(
            session,
            projection_harness.store,
            evidence_id=original.id,
            derivative_type="search-index",
            payload={"summary": "failed"},
            media_type="application/json",
            actor_id="projection-indexer",
            captured_at=projection_harness.now,
        )
        correction = create_correction(
            session,
            projection_harness.store,
            evidence_id=original.id,
            payload={"passed": True},
            media_type="application/json",
            authentication=authentication,
            now=projection_harness.now,
        )
        task_id = task.id

    evidence_service = EvidenceService(
        projection_harness.factory,
        projection_harness.store,
        clock=lambda: projection_harness.now,
    )
    evidence_service.delete(
        original.id,
        authentication,
        EvidenceDeletionReason.USER_REQUEST,
    )
    projection_service = EvidenceProjectionService(
        projection_harness.factory,
        projection_harness.store,
        clock=lambda: projection_harness.now,
    )
    task_view = projection_service.task_projections(task_id, authentication)
    original_view = next(
        item for item in task_view.projections if item.evidence_id == original.id
    )
    correction_view = next(
        item for item in task_view.projections if item.evidence_id == correction.record.id
    )
    assert original_view.verification_status is EvidenceVerificationStatus.DELETED
    assert original_view.lineage_status is EvidenceLineageStatus.SUPERSEDED
    assert original_view.corrected_by_id == correction.record.id
    assert original_view.content_hash is None
    assert original_view.deletion_reason == EvidenceDeletionReason.USER_REQUEST.value
    assert original_view.captured_at.tzinfo == UTC
    assert original_view.deleted_at is not None
    assert original_view.deleted_at.tzinfo == UTC
    assert original_view.derivatives[0].derivative_id == derivative.id
    assert original_view.derivatives[0].status is EvidenceDerivativeStatus.DELETED
    assert original_view.derivatives[0].captured_at.tzinfo == UTC
    assert correction_view.correction_of_id == original.id

    provenance = projection_service.provenance(correction.record.id, authentication)
    assert {item.evidence_id for item in provenance.nodes} == {
        original.id,
        correction.record.id,
    }
    assert any(
        edge.source_evidence_id == original.id
        and edge.target_evidence_id == correction.record.id
        and edge.kind is ProvenanceEdgeKind.CORRECTS
        for edge in provenance.edges
    )


def test_provenance_navigation_omits_inaccessible_related_nodes(
    projection_harness: ProjectionHarness,
) -> None:
    with projection_harness.factory.begin() as session:
        task = _task()
        session.add(task)
        session.flush()
        parent = _capture(
            projection_harness,
            session,
            task_id=task.id,
            evidence_type="repository-preflight",
            source_kind=EvidenceSourceKind.REPOSITORY_SNAPSHOT,
            content={"clean": True},
        )
        child = _capture(
            projection_harness,
            session,
            task_id=task.id,
            evidence_type="workspace-diff",
            source_kind=EvidenceSourceKind.REPOSITORY_SNAPSHOT,
            content={"changed": ["a.py"]},
            parent_correlation_id=parent.id,
        )
        restricted = _capture(
            projection_harness,
            session,
            task_id=task.id,
            evidence_type="protected-result",
            source_kind=EvidenceSourceKind.RESULT,
            content={"secret": "redacted"},
            access=EvidenceAccessClass.RECENT_PASSWORD,
            parent_correlation_id=child.id,
        )

    service = EvidenceProjectionService(
        projection_harness.factory,
        projection_harness.store,
        clock=lambda: projection_harness.now,
    )
    result = service.provenance(
        parent.id,
        _authentication(
            projection_harness.now, recent_password_verified=False
        ),
    )
    assert {item.evidence_id for item in result.nodes} == {parent.id, child.id}
    assert restricted.id not in {item.evidence_id for item in result.nodes}
    assert any(
        edge.source_evidence_id == parent.id
        and edge.target_evidence_id == child.id
        and edge.kind is ProvenanceEdgeKind.PARENT
        for edge in result.edges
    )
    limited = service.provenance(
        parent.id,
        _authentication(projection_harness.now),
        limit=1,
    )
    assert [item.evidence_id for item in limited.nodes] == [parent.id]
    assert limited.truncated is True


def test_projection_routes_require_authentication_and_disable_caching(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'projection-api.sqlite3'}"
    engine = create_database_engine(database_url)
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    now = datetime.now(UTC).replace(microsecond=0)
    store = ArtifactStore(tmp_path / "artifacts")
    authentication_service = AuthenticationService(factory, clock=lambda: now)
    projection_service = EvidenceProjectionService(factory, store, clock=lambda: now)
    with factory.begin() as session:
        task = _task()
        session.add(task)
        session.flush()
        captured = _capture(
            ProjectionHarness(engine, factory, store, now),
            session,
            task_id=task.id,
            evidence_type="task-request",
            source_kind=EvidenceSourceKind.REQUEST,
            content={"request": "api"},
        )
        task_id = task.id
        evidence_id = captured.id
    app = create_app(
        Settings(database_url=SecretStr(database_url), artifact_root=store.root),
        session_factory=factory,
        authentication_service=authentication_service,
        evidence_projection_service=projection_service,
    )
    client = TestClient(app, base_url="https://localhost")
    try:
        path = f"/api/evidence/tasks/{task_id}/projections"
        provenance_path = f"/api/evidence/{evidence_id}/provenance"
        assert client.get(path).status_code == 401
        assert client.get(provenance_path).status_code == 401
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
        assert response.json()["projections"][0]["projection_class"] == "REQUEST"
        assert response.json()["projections"][0]["captured_at"].endswith(
            ("Z", "+00:00")
        )
        provenance = client.get(provenance_path)
        assert provenance.status_code == 200, provenance.text
        assert provenance.headers["cache-control"] == "no-store"
        assert provenance.json()["root_evidence_id"] == str(evidence_id)
    finally:
        client.close()
        engine.dispose()
