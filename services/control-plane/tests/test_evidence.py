from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from mathews_configuration import SecretValue
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
    create_task_record,
)
from mathews_control_plane.domain_models import (
    EvidenceAuditEvent,
    EvidenceDeletionRequest,
    EvidenceDerivative,
    EvidenceRecord,
    EvidenceTombstone,
    Task,
    TaskState,
)
from mathews_control_plane.evidence import (
    EVIDENCE_ENVELOPE_SCHEMA_VERSION,
    MAX_EVIDENCE_REQUEST_BYTES,
    EvidenceAccessClass,
    EvidenceAuditEventType,
    EvidenceConflictError,
    EvidenceDeletionReason,
    EvidenceNotFoundError,
    EvidenceRetentionClass,
    EvidenceService,
    EvidenceSourceKind,
    EvidenceValidationError,
    capture_evidence,
    create_correction,
    load_evidence,
    redact_evidence_content,
    register_evidence_derivative,
)
from mathews_control_plane.settings import Settings
from pydantic import SecretStr
from sqlalchemy import Engine, select

_ORIGIN = "http://localhost:3000"
_PASSWORD = "correct horse battery staple"


@dataclass(slots=True)
class EvidenceHarness:
    engine: Engine
    factory: SessionFactory
    store: ArtifactStore
    now: datetime


@pytest.fixture
def evidence_harness(tmp_path: Path) -> Iterator[EvidenceHarness]:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'evidence.sqlite3'}")
    Base.metadata.create_all(engine)
    harness = EvidenceHarness(
        engine=engine,
        factory=create_session_factory(engine),
        store=ArtifactStore(tmp_path / "artifacts"),
        now=datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
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


def _task(root_correlation_id: UUID) -> Task:
    return Task(
        repository="boppuh/mathews",
        base_revision="a" * 40,
        requester="local-user",
        raw_request="safe projection",
        summary="Capture evidence",
        state=TaskState.INTAKE,
        owner_id="local-user",
        actor_id="local-user",
        root_correlation_id=root_correlation_id,
    )


def _capture(
    harness: EvidenceHarness,
    *,
    access_classification: EvidenceAccessClass = EvidenceAccessClass.OWNER,
) -> tuple[UUID, str, UUID]:
    root_correlation_id = uuid4()
    with harness.factory.begin() as session:
        task = _task(root_correlation_id)
        session.add(task)
        session.flush()
        captured = capture_evidence(
            session,
            harness.store,
            payload={"status": "ready"},
            media_type="application/json",
            source_kind=EvidenceSourceKind.RESULT,
            evidence_type="test-result",
            origin="validator",
            access_classification=access_classification,
            retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
            owner_id="local-user",
            actor_id="validator",
            root_correlation_id=root_correlation_id,
            task_id=task.id,
            captured_at=harness.now,
        )
        return captured.record.id, captured.envelope_address, task.id


def test_redaction_is_deterministic_and_precedes_persistence(
    evidence_harness: EvidenceHarness,
) -> None:
    known_secret = "overlapping-known-secret-value"
    payload = {
        "password": known_secret,
        "nested": {
            "message": (
                f"Authorization: Bearer {known_secret}\r\n"
                "Contact alice@example.com or +1 (212) 555-0198 "
                "at https://alice:password@example.test/path?api_key=raw-key"
            ),
        },
    }
    first = redact_evidence_content(
        payload,
        media_type="application/json",
        secrets=(SecretValue(known_secret),),
    )
    second = redact_evidence_content(
        {
            "nested": payload["nested"],
            "password": known_secret,
        },
        media_type="application/json",
        secrets=(SecretValue(known_secret),),
    )

    assert first == second
    assert known_secret.encode() not in first.canonical_bytes
    assert b"alice@example.com" not in first.canonical_bytes
    assert b"212" not in first.canonical_bytes
    assert b"raw-key" not in first.canonical_bytes
    assert first.manifest == {
        "authorization": 1,
        "email": 1,
        "known-secret": 1,
        "phone": 1,
        "query-secret": 1,
        "sensitive-field": 1,
        "url-credentials": 1,
    }

    with evidence_harness.factory.begin() as session:
        captured = capture_evidence(
            session,
            evidence_harness.store,
            payload=payload,
            media_type="application/json",
            source_kind=EvidenceSourceKind.REQUEST,
            evidence_type="request",
            origin="test",
            access_classification=EvidenceAccessClass.OWNER,
            retention_policy=EvidenceRetentionClass.AUDIT,
            owner_id="local-user",
            actor_id="local-user",
            root_correlation_id=uuid4(),
            captured_at=evidence_harness.now,
            secrets=(SecretValue(known_secret),),
        )
        artifact = evidence_harness.store.get_bytes(captured.envelope_address)

    assert known_secret.encode() not in artifact
    assert b"alice@example.com" not in artifact
    assert not any(
        known_secret.encode() in path.read_bytes()
        for path in evidence_harness.store.root.rglob("*")
        if path.is_file()
    )


def test_canonical_envelope_binds_content_and_lineage(
    evidence_harness: EvidenceHarness,
) -> None:
    evidence_id = uuid4()
    task_id = uuid4()
    root_correlation_id = uuid4()
    causation_id = uuid4()
    parent_correlation_id = uuid4()
    with evidence_harness.factory.begin() as session:
        session.add(_task(task_id))
        session.flush()
        task = session.scalar(select(Task).where(Task.root_correlation_id == task_id))
        assert task is not None
        captured = capture_evidence(
            session,
            evidence_harness.store,
            payload="result\r\nready",
            media_type="text/plain; charset=utf-8",
            source_kind=EvidenceSourceKind.TOOL_OPERATION,
            evidence_type="tool-output",
            origin="host-agent:xcodebuild",
            access_classification=EvidenceAccessClass.TASK_OWNER,
            retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
            owner_id="local-user",
            actor_id="host-agent",
            root_correlation_id=root_correlation_id,
            task_id=task.id,
            causation_id=causation_id,
            parent_correlation_id=parent_correlation_id,
            evidence_id=evidence_id,
            captured_at=evidence_harness.now,
        )
        loaded = load_evidence(session, evidence_harness.store, captured.record)

    assert loaded.content == "result\nready"
    assert loaded.envelope["schema_version"] == EVIDENCE_ENVELOPE_SCHEMA_VERSION
    assert loaded.envelope["evidence_id"] == str(evidence_id)
    assert loaded.envelope["task_id"] == str(task.id)
    assert loaded.envelope["actor_id"] == "host-agent"
    assert loaded.envelope["origin"] == "host-agent:xcodebuild"
    assert loaded.envelope["root_correlation_id"] == str(root_correlation_id)
    assert loaded.envelope["causation_id"] == str(causation_id)
    assert loaded.envelope["parent_correlation_id"] == str(parent_correlation_id)
    assert loaded.envelope["access_classification"] == "TASK_OWNER"
    assert loaded.envelope["retention_policy"] == "TASK_LIFETIME"
    assert captured.record.content_hash == captured.envelope_address


@pytest.mark.parametrize(
    "unsafe_origin",
    (
        "https://user:password@example.test/result",
        "ghp_" + ("A" * 24),
        "sk-" + ("B" * 24),
        "eyJabcdefghijk.abcdefghijklmno.abcdefghijklmnop",
        "password:raw-secret",
        "token:raw-secret",
        "client_secret:raw-secret",
    ),
)
def test_unsafe_metadata_is_rejected_before_artifact_persistence(
    evidence_harness: EvidenceHarness,
    unsafe_origin: str,
) -> None:
    with evidence_harness.factory.begin() as session:
        with pytest.raises(EvidenceValidationError, match="origin is invalid"):
            capture_evidence(
                session,
                evidence_harness.store,
                payload={"safe": True},
                media_type="application/json",
                source_kind=EvidenceSourceKind.RESULT,
                evidence_type="result",
                origin=unsafe_origin,
                access_classification=EvidenceAccessClass.OWNER,
                retention_policy=EvidenceRetentionClass.AUDIT,
                owner_id="local-user",
                actor_id="validator",
                root_correlation_id=uuid4(),
            )

    assert not evidence_harness.store.root.exists()


def test_redaction_covers_sensitive_keys_assignments_and_token_formats() -> None:
    github_token = "ghp_" + ("A" * 24)
    jwt = (
        "eyJabcdefghijk."
        "abcdefghijklmno."
        "abcdefghijklmnop"
    )
    prepared = redact_evidence_content(
        {
            "token": "raw-json-token",
            "output": (
                f"password=raw-assignment {github_token} {jwt}"
            ),
        },
        media_type="application/json",
    )

    assert b"raw-json-token" not in prepared.canonical_bytes
    assert b"raw-assignment" not in prepared.canonical_bytes
    assert github_token.encode() not in prepared.canonical_bytes
    assert jwt.encode() not in prepared.canonical_bytes
    assert prepared.manifest == {
        "assigned-secret": 1,
        "jwt": 1,
        "opaque-token": 1,
        "sensitive-field": 1,
    }


@pytest.mark.parametrize(
    ("unsafe", "secret"),
    (
        ("Authorization: token ghp_abcdefghijklmnopqrstuvwxyz", "ghp_abcdefghijklmnopqrstuvwxyz"),
        ("Authorization: ApiKey raw-api-key", "raw-api-key"),
        ("Authorization: Digest raw-digest", "raw-digest"),
        ("Authorization: AWS4-HMAC-SHA256 raw-aws-signature", "raw-aws-signature"),
        ("Proxy-Authorization: Negotiate raw-negotiate", "raw-negotiate"),
        ("X-Api-Key: raw-header-key", "raw-header-key"),
        ("GH_TOKEN=raw-environment-token", "raw-environment-token"),
        ("OPENAI_API_KEY=raw-openai-key", "raw-openai-key"),
        ("authorization=Bearer raw-assignment-secret", "raw-assignment-secret"),
        (
            "proxy_authorization=Negotiate raw-proxy-ticket",
            "raw-proxy-ticket",
        ),
        ("cookie=session=raw-cookie", "raw-cookie"),
        ("https://example.test/?client_secret=raw-client", "raw-client"),
        ("https://example.test/?refresh_token=raw-refresh", "raw-refresh"),
        ("https://example.test/?session_token=raw-session", "raw-session"),
        ("https://example.test/?pwd=raw-password", "raw-password"),
        ("https://example.test/?gh_token=raw-github", "raw-github"),
        ("https://example.test/?auth_token=raw-auth", "raw-auth"),
        ("https://example.test/?id_token=raw-id", "raw-id"),
        ("https://example.test/?oauth_token=raw-oauth", "raw-oauth"),
        ("https://example.test/?private_token=raw-private", "raw-private"),
    ),
)
def test_common_credential_forms_never_survive_text_redaction(
    unsafe: str,
    secret: str,
) -> None:
    prepared = redact_evidence_content(
        unsafe,
        media_type="text/plain; charset=utf-8",
    )

    assert secret.encode() not in prepared.canonical_bytes


def test_pwd_json_field_is_sensitive() -> None:
    prepared = redact_evidence_content(
        {"pwd": "raw-password"},
        media_type="application/json",
    )

    assert b"raw-password" not in prepared.canonical_bytes
    assert prepared.manifest == {"sensitive-field": 1}


def test_reads_require_session_policy_and_append_audit_after_success(
    evidence_harness: EvidenceHarness,
) -> None:
    evidence_id, _, _ = _capture(evidence_harness)
    service = EvidenceService(
        evidence_harness.factory,
        evidence_harness.store,
        clock=lambda: evidence_harness.now,
    )
    ordinary = _authentication(
        evidence_harness.now,
        recent_password_verified=False,
    )

    metadata = service.metadata(evidence_id, ordinary)
    downloaded = service.download(evidence_id, ordinary)

    assert metadata.evidence_id == evidence_id
    assert downloaded.content == b'{"status":"ready"}'
    with evidence_harness.factory() as session:
        events = list(
            session.scalars(
                select(EvidenceAuditEvent)
                .where(EvidenceAuditEvent.evidence_id == evidence_id)
                .order_by(EvidenceAuditEvent.occurred_at, EvidenceAuditEvent.event_type)
            )
        )
    assert {event.event_type for event in events} == {
        EvidenceAuditEventType.CAPTURED.value,
        EvidenceAuditEventType.CONTENT_DOWNLOADED.value,
        EvidenceAuditEventType.METADATA_READ.value,
    }
    assert {
        event.session_id
        for event in events
        if event.event_type != EvidenceAuditEventType.CAPTURED.value
    } == {ordinary.session_id}

    restricted_id, _, _ = _capture(
        evidence_harness,
        access_classification=EvidenceAccessClass.RECENT_PASSWORD,
    )
    with pytest.raises(EvidenceNotFoundError):
        service.download(restricted_id, ordinary)

    internal_id, _, _ = _capture(
        evidence_harness,
        access_classification=EvidenceAccessClass.INTERNAL,
    )
    with pytest.raises(EvidenceNotFoundError):
        service.metadata(
            internal_id,
            _authentication(evidence_harness.now),
        )


def test_correction_is_a_single_append_only_successor(
    evidence_harness: EvidenceHarness,
) -> None:
    evidence_id, original_address, _ = _capture(evidence_harness)
    authentication = _authentication(evidence_harness.now)
    with evidence_harness.factory.begin() as session:
        correction = create_correction(
            session,
            evidence_harness.store,
            evidence_id=evidence_id,
            payload={"status": "corrected"},
            media_type="application/json",
            authentication=authentication,
            now=evidence_harness.now + timedelta(seconds=1),
        )
        correction_id = correction.record.id

    with evidence_harness.factory() as session:
        original = session.get(EvidenceRecord, evidence_id)
        successor = session.get(EvidenceRecord, correction_id)
        assert original is not None
        assert successor is not None
        assert original.content_address == original_address
        assert original.correction_of_id is None
        assert successor.correction_of_id == original.id
        assert load_evidence(session, evidence_harness.store, original).content == {
            "status": "ready"
        }
        assert load_evidence(session, evidence_harness.store, successor).content == {
            "status": "corrected"
        }

    with evidence_harness.factory.begin() as session:
        with pytest.raises(EvidenceConflictError, match="already has"):
            create_correction(
                session,
                evidence_harness.store,
                evidence_id=evidence_id,
                payload={"status": "fork"},
                media_type="application/json",
                authentication=authentication,
                now=evidence_harness.now + timedelta(seconds=2),
            )


def test_deletion_fences_reads_destroys_derivatives_and_appends_tombstone(
    evidence_harness: EvidenceHarness,
) -> None:
    evidence_id, evidence_address, _ = _capture(evidence_harness)
    with evidence_harness.factory.begin() as session:
        derivative = register_evidence_derivative(
            session,
            evidence_harness.store,
            evidence_id=evidence_id,
            derivative_type="retrieval-chunk",
            payload={"chunk": "safe derived content"},
            media_type="application/json",
            actor_id="retrieval-indexer",
            captured_at=evidence_harness.now,
        )
        derivative_id = derivative.id
        derivative_address = derivative.content_address
    assert derivative_address is not None

    service = EvidenceService(
        evidence_harness.factory,
        evidence_harness.store,
        clock=lambda: evidence_harness.now + timedelta(minutes=1),
    )
    tombstone = service.delete(
        evidence_id,
        _authentication(evidence_harness.now + timedelta(minutes=1)),
        EvidenceDeletionReason.USER_REQUEST,
    )

    assert tombstone.evidence_id == evidence_id
    assert tombstone.reason_code == EvidenceDeletionReason.USER_REQUEST.value
    assert tombstone.removed_derivative_count == 1
    with pytest.raises(ArtifactNotFoundError):
        evidence_harness.store.get_bytes(evidence_address)
    with pytest.raises(ArtifactNotFoundError):
        evidence_harness.store.get_bytes(derivative_address)
    with pytest.raises(EvidenceNotFoundError):
        service.metadata(
            evidence_id,
            _authentication(evidence_harness.now + timedelta(minutes=1)),
        )

    with evidence_harness.factory() as session:
        request = session.scalar(
            select(EvidenceDeletionRequest).where(
                EvidenceDeletionRequest.evidence_id == evidence_id
            )
        )
        persisted_tombstone = session.scalar(
            select(EvidenceTombstone).where(
                EvidenceTombstone.evidence_id == evidence_id
            )
        )
        persisted_derivative = session.get(EvidenceDerivative, derivative_id)
        destroyed = session.scalar(
            select(EvidenceAuditEvent).where(
                EvidenceAuditEvent.evidence_id == evidence_id,
                EvidenceAuditEvent.event_type
                == EvidenceAuditEventType.CONTENT_DESTROYED.value,
            )
        )
    assert request is not None
    assert persisted_tombstone is not None
    assert persisted_derivative is not None
    assert persisted_derivative.content_address is None
    assert persisted_derivative.deleted_at is not None
    assert destroyed is not None
    assert destroyed.details == {
        "deletion_request_id": str(request.id),
        "removed_derivative_count": 1,
        "tombstone_id": str(persisted_tombstone.id),
    }


def test_failed_content_removal_stays_fenced_and_restart_can_resume(
    evidence_harness: EvidenceHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_id, evidence_address, _ = _capture(evidence_harness)
    service = EvidenceService(
        evidence_harness.factory,
        evidence_harness.store,
        clock=lambda: evidence_harness.now,
    )
    authentication = _authentication(evidence_harness.now)
    original_delete = evidence_harness.store.delete_bytes

    def fail_removal(_address: str) -> bool:
        raise OSError("simulated artifact device failure")

    monkeypatch.setattr(evidence_harness.store, "delete_bytes", fail_removal)
    with pytest.raises(OSError, match="simulated"):
        service.delete(
            evidence_id,
            authentication,
            EvidenceDeletionReason.SECURITY_RESPONSE,
        )

    with pytest.raises(EvidenceNotFoundError):
        service.download(evidence_id, authentication)
    with evidence_harness.factory() as session:
        assert session.scalar(
            select(EvidenceDeletionRequest).where(
                EvidenceDeletionRequest.evidence_id == evidence_id
            )
        )
        assert session.scalar(
            select(EvidenceTombstone).where(
                EvidenceTombstone.evidence_id == evidence_id
            )
        ) is None

    monkeypatch.setattr(evidence_harness.store, "delete_bytes", original_delete)
    restarted_app = create_app(
        Settings(
            database_url=SecretStr(str(evidence_harness.engine.url)),
            artifact_root=evidence_harness.store.root,
        ),
        session_factory=evidence_harness.factory,
        authentication_service=AuthenticationService(
            evidence_harness.factory,
            clock=lambda: evidence_harness.now,
        ),
        evidence_service=service,
    )
    with TestClient(restarted_app, base_url="https://localhost"):
        pass
    with pytest.raises(ArtifactNotFoundError):
        evidence_harness.store.get_bytes(evidence_address)
    with evidence_harness.factory() as session:
        assert session.scalar(
            select(EvidenceTombstone).where(
                EvidenceTombstone.evidence_id == evidence_id
            )
        ) is not None


def test_startup_drains_every_pending_deletion_batch(
    evidence_harness: EvidenceHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = EvidenceService(evidence_harness.factory, evidence_harness.store)
    results = iter((100, 100, 1))
    limits: list[int] = []

    def resume(*, limit: int = 100) -> int:
        limits.append(limit)
        return next(results)

    monkeypatch.setattr(service, "resume_pending_deletions", resume)
    restarted_app = create_app(
        Settings(
            database_url=SecretStr(str(evidence_harness.engine.url)),
            artifact_root=evidence_harness.store.root,
        ),
        session_factory=evidence_harness.factory,
        authentication_service=AuthenticationService(evidence_harness.factory),
        evidence_service=service,
    )

    with TestClient(restarted_app, base_url="https://localhost"):
        pass

    assert limits == [100, 100, 100]


def test_deleting_task_request_scrubs_its_database_projection(
    evidence_harness: EvidenceHarness,
) -> None:
    with evidence_harness.factory.begin() as session:
        task = create_task_record(
            session,
            evidence_harness.store,
            repository="boppuh/mathews",
            base_revision="a" * 40,
            requester="local-user",
            raw_request="Delete this request after capture",
            summary="Delete this request after capture",
            owner_id="local-user",
            actor_id="local-user",
        )
        task_id = task.id
        request_evidence = session.scalar(
            select(EvidenceRecord).where(
                EvidenceRecord.task_id == task.id,
                EvidenceRecord.evidence_type == "task-request",
            )
        )
        assert request_evidence is not None
        evidence_id = request_evidence.id

    service = EvidenceService(
        evidence_harness.factory,
        evidence_harness.store,
        clock=lambda: evidence_harness.now,
    )
    service.delete(
        evidence_id,
        _authentication(evidence_harness.now),
        EvidenceDeletionReason.USER_REQUEST,
    )

    with evidence_harness.factory() as session:
        persisted_task = session.get(Task, task_id)
    assert persisted_task is not None
    assert persisted_task.raw_request == f"deleted-evidence://{evidence_id}"
    assert persisted_task.summary == "Deleted task request"
    assert "Delete this request" not in persisted_task.raw_request
    assert "Delete this request" not in persisted_task.summary


def test_task_request_correction_repoints_projection_and_old_deletion_preserves_it(
    evidence_harness: EvidenceHarness,
) -> None:
    with evidence_harness.factory.begin() as session:
        task = create_task_record(
            session,
            evidence_harness.store,
            repository="boppuh/mathews",
            base_revision="a" * 40,
            requester="local-user",
            raw_request="Original request",
            summary="Original request",
            owner_id="local-user",
            actor_id="local-user",
        )
        task_id = task.id
        original = session.scalar(
            select(EvidenceRecord).where(
                EvidenceRecord.task_id == task.id,
                EvidenceRecord.evidence_type == "task-request",
            )
        )
        assert original is not None
        original_id = original.id

    service = EvidenceService(
        evidence_harness.factory,
        evidence_harness.store,
        clock=lambda: evidence_harness.now,
    )
    authentication = _authentication(evidence_harness.now)
    correction = service.correct(
        original_id,
        "Corrected request",
        "text/plain; charset=utf-8",
        authentication,
    )
    correction_id = correction.record.id

    with evidence_harness.factory() as session:
        corrected_task = session.get(Task, task_id)
    assert corrected_task is not None
    assert corrected_task.raw_request == f"evidence://{correction_id}"
    assert corrected_task.summary == "Corrected task request"

    service.delete(
        original_id,
        authentication,
        EvidenceDeletionReason.USER_REQUEST,
    )
    with evidence_harness.factory() as session:
        preserved_task = session.get(Task, task_id)
    assert preserved_task is not None
    assert preserved_task.raw_request == f"evidence://{correction_id}"
    assert preserved_task.summary == "Corrected task request"


def test_internal_retention_worker_uses_same_tombstone_workflow(
    evidence_harness: EvidenceHarness,
) -> None:
    evidence_id, address, _ = _capture(
        evidence_harness,
        access_classification=EvidenceAccessClass.INTERNAL,
    )
    service = EvidenceService(
        evidence_harness.factory,
        evidence_harness.store,
        clock=lambda: evidence_harness.now,
    )

    tombstone = service.delete_internal(
        evidence_id,
        actor_id="retention-worker",
        reason=EvidenceDeletionReason.RETENTION_EXPIRED,
    )

    assert tombstone.evidence_id == evidence_id
    assert tombstone.actor_id == "retention-worker"
    assert tombstone.reason_code == "RETENTION_EXPIRED"
    with pytest.raises(ArtifactNotFoundError):
        evidence_harness.store.get_bytes(address)
    with evidence_harness.factory() as session:
        request = session.scalar(
            select(EvidenceDeletionRequest).where(
                EvidenceDeletionRequest.evidence_id == evidence_id
            )
        )
    assert request is not None
    assert request.actor_id == "retention-worker"


def test_authenticated_api_enforces_session_csrf_and_recent_password(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'api.sqlite3'}"
    engine = create_database_engine(database_url)
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    now = datetime.now(UTC).replace(microsecond=0)
    store = ArtifactStore(tmp_path / "artifacts")
    authentication_service = AuthenticationService(factory, clock=lambda: now)
    evidence_service = EvidenceService(factory, store, clock=lambda: now)
    app = create_app(
        Settings(
            database_url=SecretStr(database_url),
            artifact_root=store.root,
        ),
        session_factory=factory,
        authentication_service=authentication_service,
        evidence_service=evidence_service,
    )
    client = TestClient(app, base_url="https://localhost")
    try:
        with factory.begin() as session:
            captured = capture_evidence(
                session,
                store,
                payload={"status": "ready"},
                media_type="application/json",
                source_kind=EvidenceSourceKind.RESULT,
                evidence_type="api-result",
                origin="validator",
                access_classification=EvidenceAccessClass.OWNER,
                retention_policy=EvidenceRetentionClass.AUDIT,
                owner_id="local-user",
                actor_id="validator",
                root_correlation_id=uuid4(),
                captured_at=now,
            )
            evidence_id = captured.record.id

        assert client.get(f"/api/evidence/{evidence_id}").status_code == 401
        bootstrap_token = generate_bootstrap_token(factory)
        status_response = client.get("/api/auth/status")
        csrf_token = client.cookies.get(CSRF_COOKIE_NAME)
        assert status_response.status_code == 200
        assert csrf_token is not None
        bootstrap = client.post(
            "/api/auth/bootstrap",
            json={
                "bootstrap_token": bootstrap_token,
                "password": _PASSWORD,
            },
            headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
        )
        assert bootstrap.status_code == 201
        bound_csrf = client.cookies.get(CSRF_COOKIE_NAME)
        assert bound_csrf is not None

        metadata = client.get(f"/api/evidence/{evidence_id}")
        download = client.get(f"/api/evidence/{evidence_id}/download")
        assert metadata.status_code == 200, metadata.text
        assert metadata.json()["evidence_id"] == str(evidence_id)
        assert download.status_code == 200
        assert download.json() == {"status": "ready"}

        missing_csrf = client.post(
            f"/api/evidence/{evidence_id}/corrections",
            json={"media_type": "application/json", "content": {"status": "fixed"}},
            headers={"Origin": _ORIGIN},
        )
        assert missing_csrf.status_code == 403
        oversized = client.post(
            f"/api/evidence/{evidence_id}/corrections",
            json={
                "media_type": "text/plain; charset=utf-8",
                "content": "x" * MAX_EVIDENCE_REQUEST_BYTES,
            },
            headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: bound_csrf},
        )
        assert oversized.status_code == 413
        correction = client.post(
            f"/api/evidence/{evidence_id}/corrections",
            json={"media_type": "application/json", "content": {"status": "fixed"}},
            headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: bound_csrf},
        )
        assert correction.status_code == 201, correction.text

        deleted = client.request(
            "DELETE",
            f"/api/evidence/{evidence_id}",
            json={"reason": "USER_REQUEST"},
            headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: bound_csrf},
        )
        assert deleted.status_code == 204, deleted.text
        assert client.get(f"/api/evidence/{evidence_id}/download").status_code == 404

        preflight = client.options(
            f"/api/evidence/{evidence_id}",
            headers={
                "Access-Control-Request-Method": "DELETE",
                "Origin": _ORIGIN,
            },
        )
        assert preflight.status_code == 200
        assert "DELETE" in preflight.headers["access-control-allow-methods"]
    finally:
        client.close()
        engine.dispose()


def test_envelope_artifact_is_canonical_json(
    evidence_harness: EvidenceHarness,
) -> None:
    evidence_id, address, _ = _capture(evidence_harness)
    payload = evidence_harness.store.get_bytes(address)
    decoded = json.loads(payload)

    assert payload == json.dumps(
        decoded,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()
    assert decoded["evidence_id"] == str(evidence_id)
