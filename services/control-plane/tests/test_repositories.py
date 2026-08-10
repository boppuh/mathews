from __future__ import annotations

import asyncio
import copy
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from mathews_configuration import (
    HostRequestMessage,
    HostResponseMessage,
    HostResponseStatus,
    PreflightCheck,
    PreflightCheckCode,
    PreflightStatus,
    RepositoryHostAuthority,
    RepositoryPreflightReport,
)
from mathews_configuration.host_protocol import JsonValue
from mathews_control_plane.app import create_app
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.authentication import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    AuthenticationService,
    generate_bootstrap_token,
)
from mathews_control_plane.database import (
    Base,
    SessionFactory,
    create_database_engine,
    create_session_factory,
    session_scope,
)
from mathews_control_plane.domain_models import EvidenceRecord, RepositoryConfiguration
from mathews_control_plane.host_gateway import HostGatewayError
from mathews_control_plane.repositories import (
    MAX_REPOSITORY_BODY_BYTES,
    RepositoryBodyLimitMiddleware,
    RepositoryService,
)
from mathews_control_plane.settings import Settings
from pydantic import SecretStr
from sqlalchemy import Engine, delete, select
from starlette.types import Message, Receive, Scope, Send
from test_repository_configuration import _configuration

_ORIGIN = "http://localhost:3000"
_PASSWORD = "correct horse battery staple"


@dataclass(slots=True)
class RecordingGateway:
    requests: list[HostRequestMessage]
    failure_code: str | None = None

    def execute(self, request: HostRequestMessage) -> HostResponseMessage:
        self.requests.append(request)
        if self.failure_code is not None:
            raise HostGatewayError(self.failure_code)
        arguments = request.operation.arguments
        assert isinstance(request.authority, RepositoryHostAuthority)
        configuration = cast(dict[str, object], arguments["configuration"])
        report = RepositoryPreflightReport(
            attempt_id=UUID(cast(str, arguments["attempt_id"])),
            configuration_id=request.authority.configuration_id,
            configuration_version=cast(int, configuration["version"]),
            configuration_digest=request.authority.configuration_digest,
            status=PreflightStatus.PASSED,
            checks=tuple(
                PreflightCheck.for_status(code, PreflightStatus.PASSED)
                for code in PreflightCheckCode
            ),
            resolved_base_sha="a" * 40,
        )
        return HostResponseMessage(
            request_id=request.request_id,
            operation_name=request.operation.name,
            idempotency_key=request.operation.idempotency_key,
            host_id="test-host",
            host_version="test-v1",
            status=HostResponseStatus.OK,
            code="PREFLIGHT_OK",
            replayed=False,
            completed_at_ms=int(datetime.now(UTC).timestamp() * 1000),
            result=cast(dict[str, JsonValue], report.to_dict()),
        )


@dataclass(slots=True)
class RepositoryHarness:
    client: TestClient
    engine: Engine
    factory: SessionFactory
    gateway: RecordingGateway
    configuration: RepositoryConfiguration
    bootstrap_token: str


@pytest.fixture
def repository_harness(tmp_path: Path) -> Iterator[RepositoryHarness]:
    database_url = f"sqlite:///{tmp_path / 'repositories-api.sqlite3'}"
    engine = create_database_engine(database_url)
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    store = ArtifactStore(tmp_path / "artifacts")
    with session_scope(factory) as session:
        configuration = _configuration(session)
    gateway = RecordingGateway([])
    authentication_service = AuthenticationService(factory)
    repository_service = RepositoryService(
        factory,
        store,
        host_gateway=gateway,
    )
    app = create_app(
        Settings(database_url=SecretStr(database_url), artifact_root=store.root),
        session_factory=factory,
        authentication_service=authentication_service,
        repository_service=repository_service,
    )
    client = TestClient(app, base_url="https://localhost")
    harness = RepositoryHarness(
        client=client,
        engine=engine,
        factory=factory,
        gateway=gateway,
        configuration=configuration,
        bootstrap_token=generate_bootstrap_token(factory),
    )
    try:
        yield harness
    finally:
        client.close()
        engine.dispose()


def _authenticate(harness: RepositoryHarness) -> dict[str, str]:
    assert harness.client.get("/api/auth/status").status_code == 200
    csrf = harness.client.cookies.get(CSRF_COOKIE_NAME)
    assert csrf is not None
    response = harness.client.post(
        "/api/auth/bootstrap",
        json={"bootstrap_token": harness.bootstrap_token, "password": _PASSWORD},
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf},
    )
    assert response.status_code == 201, response.text
    csrf = harness.client.cookies.get(CSRF_COOKIE_NAME)
    assert csrf is not None
    return {"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf}


def _write_body(configuration: RepositoryConfiguration) -> dict[str, object]:
    git_settings = copy.deepcopy(configuration.git_settings)
    push_credential = cast(str, git_settings.pop("push_credential"))
    operations = copy.deepcopy(configuration.operations)
    test_account = ""
    for operation in operations:
        if isinstance(operation, dict) and isinstance(operation.get("e2e_flow"), dict):
            test_account = cast(str, operation["e2e_flow"].pop("test_account"))
    return {
        "repository_key": configuration.repository_key,
        "expected_configuration_version": configuration.version,
        "repository_settings": copy.deepcopy(configuration.repository_settings),
        "git_settings": git_settings,
        "xcode_settings": copy.deepcopy(configuration.xcode_settings),
        "operations": operations,
        "e2e_assertions": copy.deepcopy(configuration.e2e_assertions),
        "artifact_settings": copy.deepcopy(configuration.artifact_settings),
        "prohibited_paths": copy.deepcopy(configuration.prohibited_paths),
        "secret_updates": {
            "push_credential": push_credential,
            "e2e_test_account": test_account,
            "additional": copy.deepcopy(configuration.secret_references),
        },
        "approve_sensitive_change": True,
    }


def test_repository_projection_requires_auth_and_never_returns_secret_references(
    repository_harness: RepositoryHarness,
) -> None:
    assert repository_harness.client.get("/api/repository").status_code == 401
    _authenticate(repository_harness)

    response = repository_harness.client.get("/api/repository")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    payload = response.json()
    serialized = response.text
    assert payload["configured"] is True
    assert payload["mutation_blocked"] is True
    assert payload["preflight"]["status"] == "NOT_RUN"
    assert payload["configuration"]["secrets"] == {
        "push_credential_configured": True,
        "e2e_test_account_configured": True,
        "additional_reference_count": 0,
    }
    assert "keychain://" not in serialized


def test_sensitive_save_requires_confirmation_and_preserves_omitted_secrets(
    repository_harness: RepositoryHarness,
) -> None:
    headers = _authenticate(repository_harness)
    body = _write_body(repository_harness.configuration)
    body["approve_sensitive_change"] = False
    denied = repository_harness.client.post("/api/repository/versions", json=body, headers=headers)
    assert denied.status_code == 403

    body["approve_sensitive_change"] = True
    cast(dict[str, object], body["secret_updates"]).clear()
    response = repository_harness.client.post(
        "/api/repository/versions", json=body, headers=headers
    )

    assert response.status_code == 201, response.text
    assert response.json()["configuration"]["version"] == 2
    assert "keychain://" not in response.text
    with repository_harness.factory() as session:
        versions = session.scalars(
            select(RepositoryConfiguration).order_by(RepositoryConfiguration.version)
        ).all()
        assert len(versions) == 2
        assert versions[1].predecessor_id == versions[0].id
        assert (
            versions[1].git_settings["push_credential"]
            == (versions[0].git_settings["push_credential"])
        )


def test_first_save_and_rotation_keep_only_current_designated_secret_references(
    repository_harness: RepositoryHarness,
) -> None:
    headers = _authenticate(repository_harness)
    body = _write_body(repository_harness.configuration)
    body["expected_configuration_version"] = None
    body["secret_updates"] = {
        "push_credential": "keychain://mathews/git-first",
        "e2e_test_account": "keychain://mathews/account-first",
    }
    with repository_harness.factory() as session, session.begin():
        session.execute(delete(RepositoryConfiguration))

    first = repository_harness.client.post("/api/repository/versions", json=body, headers=headers)

    assert first.status_code == 201, first.text
    assert first.json()["configuration"]["version"] == 1
    body["expected_configuration_version"] = 1
    body["secret_updates"] = {
        "push_credential": "keychain://mathews/git-rotated",
        "e2e_test_account": "keychain://mathews/account-rotated",
    }

    rotated = repository_harness.client.post("/api/repository/versions", json=body, headers=headers)

    assert rotated.status_code == 201, rotated.text
    with repository_harness.factory() as session:
        latest = session.scalar(
            select(RepositoryConfiguration).order_by(RepositoryConfiguration.version.desc())
        )
        assert latest is not None
        assert latest.secret_references == [
            "keychain://mathews/git-rotated",
            "keychain://mathews/account-rotated",
        ]


def test_explicit_empty_additional_secret_list_clears_existing_references(
    repository_harness: RepositoryHarness,
) -> None:
    headers = _authenticate(repository_harness)
    body = _write_body(repository_harness.configuration)
    cast(dict[str, object], body["secret_updates"])["additional"] = ["keychain://mathews/extra"]
    added = repository_harness.client.post("/api/repository/versions", json=body, headers=headers)
    assert added.status_code == 201, added.text

    body["expected_configuration_version"] = 2
    body["secret_updates"] = {"additional": []}
    cleared = repository_harness.client.post("/api/repository/versions", json=body, headers=headers)

    assert cleared.status_code == 201, cleared.text
    assert cleared.json()["configuration"]["secrets"]["additional_reference_count"] == 0
    with repository_harness.factory() as session:
        latest = session.scalar(
            select(RepositoryConfiguration).order_by(RepositoryConfiguration.version.desc())
        )
        assert latest is not None
        assert "keychain://mathews/extra" not in latest.secret_references


def test_invalid_configuration_creates_no_version(
    repository_harness: RepositoryHarness,
) -> None:
    headers = _authenticate(repository_harness)
    body = _write_body(repository_harness.configuration)
    cast(dict[str, object], body["repository_settings"])["root"] = "relative"

    response = repository_harness.client.post(
        "/api/repository/versions", json=body, headers=headers
    )

    assert response.status_code == 422
    with repository_harness.factory() as session:
        assert len(session.scalars(select(RepositoryConfiguration)).all()) == 1


def test_stale_configuration_version_cannot_overwrite_the_latest_secrets(
    repository_harness: RepositoryHarness,
) -> None:
    headers = _authenticate(repository_harness)
    body = _write_body(repository_harness.configuration)
    body["expected_configuration_version"] = 99

    response = repository_harness.client.post(
        "/api/repository/versions", json=body, headers=headers
    )

    assert response.status_code == 409
    with repository_harness.factory() as session:
        assert len(session.scalars(select(RepositoryConfiguration)).all()) == 1


def test_preflight_invokes_only_typed_read_only_operation_and_projects_readiness(
    repository_harness: RepositoryHarness,
) -> None:
    headers = _authenticate(repository_harness)
    assert repository_harness.client.get("/api/repository").json()["configured"] is True

    response = repository_harness.client.post(
        "/api/repository/preflights", json={}, headers=headers
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["mutation_blocked"] is False
    assert payload["preflight"]["status"] == "PASSED"
    assert payload["preflight"]["resolved_base_sha"] == "a" * 40
    assert len(payload["preflight"]["checks"]) == len(PreflightCheckCode)
    assert len(repository_harness.gateway.requests) == 1
    request = repository_harness.gateway.requests[0]
    assert request.operation.name == "repository.preflight"
    assert isinstance(request.authority, RepositoryHostAuthority)
    assert request.authority.repository_key == "boppuh/mathews"


def test_failed_host_preflight_clears_request_without_fabricating_host_evidence(
    repository_harness: RepositoryHarness,
) -> None:
    headers = _authenticate(repository_harness)
    repository_harness.gateway.failure_code = "HOST_UNAVAILABLE"

    response = repository_harness.client.post(
        "/api/repository/preflights", json={}, headers=headers
    )

    assert response.status_code == 503
    current = repository_harness.client.get("/api/repository")
    assert current.status_code == 200
    payload = current.json()
    assert payload["mutation_blocked"] is True
    assert payload["preflight"]["status"] == "NOT_RUN"
    assert payload["preflight"]["checks"] == []
    with repository_harness.factory() as session:
        configuration = session.get(RepositoryConfiguration, repository_harness.configuration.id)
        assert configuration is not None
        assert configuration.preflight_evidence_id is None
        evidence = session.scalars(select(EvidenceRecord)).all()
        assert {record.evidence_type for record in evidence} == {"repository-preflight-request"}


def test_oversized_repository_write_is_rejected_before_decoding(
    repository_harness: RepositoryHarness,
) -> None:
    headers = _authenticate(repository_harness)

    response = repository_harness.client.post(
        "/api/repository/versions",
        content=b"x" * (MAX_REPOSITORY_BODY_BYTES + 1),
        headers={**headers, "Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert response.headers["Cache-Control"] == "no-store"
    with repository_harness.factory() as session:
        assert len(session.scalars(select(RepositoryConfiguration)).all()) == 1


def test_repository_body_buffer_rejects_excessive_empty_chunks() -> None:
    downstream_called = False
    sent: list[Message] = []

    async def downstream(_scope: Scope, _receive: Receive, _send: Send) -> None:
        nonlocal downstream_called
        downstream_called = True

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": True}

    async def send(message: Message) -> None:
        sent.append(message)

    middleware = RepositoryBodyLimitMiddleware(downstream)
    scope = cast(
        Scope,
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "scheme": "https",
            "method": "POST",
            "path": "/api/repository/versions",
            "raw_path": b"/api/repository/versions",
            "query_string": b"",
            "root_path": "",
            "headers": [],
            "client": ("127.0.0.1", 1),
            "server": ("localhost", 443),
        },
    )

    asyncio.run(middleware(scope, receive, send))

    assert downstream_called is False
    start = next(message for message in sent if message["type"] == "http.response.start")
    assert start["status"] == 413
