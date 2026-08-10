from __future__ import annotations

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
from mathews_control_plane.domain_models import RepositoryConfiguration
from mathews_control_plane.repositories import RepositoryService
from mathews_control_plane.settings import Settings
from pydantic import SecretStr
from sqlalchemy import Engine, select
from test_repository_configuration import _configuration

_ORIGIN = "http://localhost:3000"
_PASSWORD = "correct horse battery staple"


@dataclass(slots=True)
class RecordingGateway:
    requests: list[HostRequestMessage]

    def execute(self, request: HostRequestMessage) -> HostResponseMessage:
        self.requests.append(request)
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
    assert payload["configuration"]["secrets"] == {
        "push_credential_configured": True,
        "e2e_test_account_configured": True,
        "additional_reference_count": 2,
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


def test_oversized_repository_write_is_rejected_before_decoding(
    repository_harness: RepositoryHarness,
) -> None:
    headers = _authenticate(repository_harness)

    response = repository_harness.client.post(
        "/api/repository/versions",
        content=b"x" * (512 * 1024 + 1),
        headers={**headers, "Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert response.headers["Cache-Control"] == "no-store"
    with repository_harness.factory() as session:
        assert len(session.scalars(select(RepositoryConfiguration)).all()) == 1
