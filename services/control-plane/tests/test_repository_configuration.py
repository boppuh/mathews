import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest
from mathews_configuration import (
    MANDATORY_PROHIBITED_OPERATIONS,
    PreflightCheck,
    PreflightCheckCode,
    PreflightStatus,
    RepositoryConfigurationError,
    RepositoryPreflightReport,
)
from mathews_configuration import (
    RepositoryConfiguration as ValidatedRepositoryConfiguration,
)
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.database import (
    Base,
    SessionFactory,
    create_database_engine,
    create_session_factory,
    session_scope,
)
from mathews_control_plane.domain_models import EvidenceRecord, RepositoryConfiguration
from mathews_control_plane.repository_configuration import (
    RepositoryPreflightBindingError,
    RepositoryPreflightNotReadyError,
    begin_preflight_attempt,
    capture_preflight_report,
    create_repository_configuration,
    get_latest_repository_configuration,
    repository_configuration_digest,
    require_preflight_ready,
)
from sqlalchemy import select
from sqlalchemy.orm import Session


def _configuration(
    session: Session,
    repository_key: str = "boppuh/mathews",
) -> RepositoryConfiguration:
    return create_repository_configuration(
        session,
        repository_key=repository_key,
        repository_settings={
            "root": "/tmp/mathews",
            "prohibited_operations": sorted(
                operation.value for operation in MANDATORY_PROHIBITED_OPERATIONS
            ),
        },
        git_settings={
            "default_base_ref": "refs/remotes/origin/main",
            "task_branch_template": "codex/{task_id}",
            "remote_name": "origin",
            "author": {"name": "Mathews", "email": "mathews@example.com"},
            "committer": {"name": "Mathews", "email": "mathews@example.com"},
        },
        xcode_settings={
            "container_path": "Mathews.xcodeproj",
            "container_kind": "PROJECT",
            "scheme": "Mathews",
            "simulator": {
                "runtime_identifier": "com.apple.iOS-18-5",
                "device_type_identifier": "com.apple.iPhone-16-Pro",
            },
        },
        operations=[
            {
                "operation_id": "build",
                "kind": "BUILD",
                "argv": [
                    "xcodebuild",
                    "build",
                    "-project",
                    "Mathews.xcodeproj",
                    "-scheme",
                    "Mathews",
                    "-destination",
                    "MATHEWS_CONFIGURED_SIMULATOR",
                ],
                "timeout_seconds": 600,
                "e2e_flow": None,
            },
            {
                "operation_id": "unit-tests",
                "kind": "UNIT_TEST",
                "argv": [
                    "xcodebuild",
                    "test",
                    "-project",
                    "Mathews.xcodeproj",
                    "-scheme",
                    "Mathews",
                    "-destination",
                    "MATHEWS_CONFIGURED_SIMULATOR",
                ],
                "timeout_seconds": 600,
                "e2e_flow": None,
            },
            {
                "operation_id": "integration-tests",
                "kind": "INTEGRATION_TEST",
                "argv": [
                    "xcodebuild",
                    "test",
                    "-project",
                    "Mathews.xcodeproj",
                    "-scheme",
                    "Mathews",
                    "-destination",
                    "MATHEWS_CONFIGURED_SIMULATOR",
                ],
                "timeout_seconds": 900,
                "e2e_flow": None,
            },
            {
                "operation_id": "simulator-e2e",
                "kind": "SIMULATOR_E2E",
                "argv": [
                    "xcodebuild",
                    "test",
                    "-project",
                    "Mathews.xcodeproj",
                    "-scheme",
                    "Mathews",
                    "-destination",
                    "MATHEWS_CONFIGURED_SIMULATOR",
                ],
                "timeout_seconds": 900,
                "e2e_flow": {
                    "flow_id": "primary",
                    "version": 1,
                    "entry_point": "launch",
                    "terminal_state": "ready",
                    "fixture_id": "default",
                    "fixture_version": 1,
                    "test_account": "keychain://mathews/test-account",
                    "clean_state_steps": [
                        "SHUTDOWN",
                        "ERASE",
                        "BOOT",
                        "INSTALL_CANDIDATE",
                    ],
                    "expected_network_signals": ["api.ready"],
                    "expected_log_signals": ["app.ready"],
                    "acceptable_warnings": [],
                },
            },
        ],
        e2e_assertions=[
            {
                "assertion_id": "no-crash",
                "kind": "NO_CRASH",
                "catalog_key": "app.no_crash",
            }
        ],
        artifact_settings={"collection_paths": ["artifacts/test.log"]},
        prohibited_paths=[".git", ".env"],
        secret_references=["keychain://mathews/test-account"],
        owner_id="local-user",
        actor_id="local-user",
        root_correlation_id=uuid4(),
    )


def _report(
    configuration: RepositoryConfiguration,
    attempt_id: UUID,
    *,
    status: str = "PASSED",
    base_sha: str | None = "a" * 40,
) -> RepositoryPreflightReport:
    preflight_status = PreflightStatus(status)
    return RepositoryPreflightReport(
        attempt_id=attempt_id,
        configuration_id=configuration.id,
        configuration_version=configuration.version,
        configuration_digest=repository_configuration_digest(configuration),
        status=preflight_status,
        checks=tuple(
            PreflightCheck.for_status(code, preflight_status)
            for code in PreflightCheckCode
        ),
        resolved_base_sha=base_sha,
    )


def _begin_preflight(
    session: Session,
    store: ArtifactStore,
    configuration: RepositoryConfiguration,
) -> UUID:
    return begin_preflight_attempt(
        session,
        store,
        configuration_id=configuration.id,
        owner_id="local-user",
        actor_id="control-plane",
        root_correlation_id=uuid4(),
    ).attempt_id


@pytest.fixture
def repository_database(tmp_path: Path) -> Iterator[SessionFactory]:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'repository.sqlite3'}")
    Base.metadata.create_all(engine)
    try:
        yield create_session_factory(engine)
    finally:
        engine.dispose()


def test_allocates_immutable_versions_and_authoritative_latest(
    repository_database: SessionFactory,
) -> None:
    with session_scope(repository_database) as session:
        first = _configuration(session)
        second = _configuration(session)

        assert (first.version, first.predecessor_id) == (1, None)
        assert (second.version, second.predecessor_id) == (2, first.id)
        latest = get_latest_repository_configuration(session, " boppuh/mathews ")
        assert latest is second
        assert first.preflight_evidence_id is None
        assert second.preflight_evidence_id is None


def test_digest_matches_host_canonical_payload(
    repository_database: SessionFactory,
) -> None:
    with session_scope(repository_database) as session:
        configuration = _configuration(session)
        payload = {
            "repository_key": configuration.repository_key,
            "version": configuration.version,
            "repository_settings": configuration.repository_settings,
            "git_settings": configuration.git_settings,
            "xcode_settings": configuration.xcode_settings,
            "operations": configuration.operations,
            "e2e_assertions": configuration.e2e_assertions,
            "artifact_settings": configuration.artifact_settings,
            "prohibited_paths": configuration.prohibited_paths,
            "secret_references": configuration.secret_references,
        }
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()

        assert repository_configuration_digest(configuration) == (
            f"sha256:{hashlib.sha256(canonical).hexdigest()}"
        )
        assert repository_configuration_digest(configuration) == (
            ValidatedRepositoryConfiguration.from_dict(
                configuration.id,
                payload,
            ).digest
        )


def test_invalid_typed_configuration_never_flushes(
    repository_database: SessionFactory,
) -> None:
    with session_scope(repository_database) as session:
        with pytest.raises(RepositoryConfigurationError):
            create_repository_configuration(
                session,
                repository_key="boppuh/mathews",
                repository_settings={
                    "root": ".",
                    "prohibited_operations": sorted(
                        operation.value
                        for operation in MANDATORY_PROHIBITED_OPERATIONS
                    ),
                },
                git_settings={},
                xcode_settings={},
                operations=[],
                e2e_assertions=[],
                artifact_settings={},
                prohibited_paths=[],
                secret_references=[],
                owner_id="local-user",
                actor_id="local-user",
                root_correlation_id=uuid4(),
            )

        assert session.scalars(select(RepositoryConfiguration)).all() == []


def test_capture_persists_canonical_evidence_and_require_verifies_exact_binding(
    repository_database: SessionFactory,
    tmp_path: Path,
) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    with session_scope(repository_database) as session:
        configuration = _configuration(session)
        report = _report(
            configuration,
            _begin_preflight(session, store, configuration),
        )

        captured = capture_preflight_report(
            session,
            store,
            report=report,
            owner_id="local-user",
            actor_id="host-agent",
            root_correlation_id=uuid4(),
        )
        replayed = capture_preflight_report(
            session,
            store,
            report=report,
            owner_id="local-user",
            actor_id="host-agent",
            root_correlation_id=uuid4(),
        )

        assert configuration.preflight_evidence_id == captured.evidence_id
        assert replayed == captured
        evidence = session.get(EvidenceRecord, captured.evidence_id)
        assert evidence is not None
        assert evidence.content_hash == captured.evidence_address
        assert evidence.content_address == captured.evidence_address
        artifact = json.loads(store.get_bytes(captured.evidence_address))
        assert artifact == {
            "schema_version": 1,
            "repository_key": "boppuh/mathews",
            **report.to_dict(),
        }

        ready = require_preflight_ready(
            session,
            store,
            repository_key=configuration.repository_key,
            configuration_id=configuration.id,
            configuration_version=configuration.version,
            configuration_digest=report.configuration_digest,
            resolved_base_sha=cast(str, report.resolved_base_sha),
        )

        assert ready.binding.configuration_id == configuration.id
        assert ready.binding.resolved_base_sha == "a" * 40
        assert ready.evidence_id == captured.evidence_id


def test_capture_rejects_any_inexact_host_binding_before_writing_artifact(
    repository_database: SessionFactory,
    tmp_path: Path,
) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    with session_scope(repository_database) as session:
        configuration = _configuration(session)
        report = _report(
            configuration,
            _begin_preflight(session, store, configuration),
        )
        mismatched = report.to_dict()
        mismatched["configuration_digest"] = f"sha256:{'0' * 64}"

        with pytest.raises(RepositoryPreflightBindingError):
            capture_preflight_report(
                session,
                store,
                report=mismatched,
                owner_id="local-user",
                actor_id="host-agent",
                root_correlation_id=uuid4(),
            )

        assert configuration.preflight_evidence_id == report.attempt_id
        assert session.get(EvidenceRecord, report.attempt_id) is not None


def test_capture_rejects_unknown_or_raw_check_fields_before_writing_artifact(
    repository_database: SessionFactory,
    tmp_path: Path,
) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    with session_scope(repository_database) as session:
        configuration = _configuration(session)
        forged = _report(
            configuration,
            _begin_preflight(session, store, configuration),
        ).to_dict()
        checks = cast(list[dict[str, object]], forged["checks"])
        checks[0]["raw_output"] = "credential material"

        with pytest.raises(RepositoryPreflightBindingError):
            capture_preflight_report(
                session,
                store,
                report=forged,
                owner_id="local-user",
                actor_id="host-agent",
                root_correlation_id=uuid4(),
            )

        assert configuration.preflight_evidence_id == UUID(
            cast(str, forged["attempt_id"])
        )


def test_blocked_report_is_evidence_but_never_readiness(
    repository_database: SessionFactory,
    tmp_path: Path,
) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    with session_scope(repository_database) as session:
        configuration = _configuration(session)
        report = _report(
            configuration,
            _begin_preflight(session, store, configuration),
            status="BLOCKED",
            base_sha=None,
        )
        capture_preflight_report(
            session,
            store,
            report=report,
            owner_id="local-user",
            actor_id="host-agent",
            root_correlation_id=uuid4(),
        )

        with pytest.raises(RepositoryPreflightNotReadyError, match="did not pass"):
            require_preflight_ready(
                session,
                store,
                repository_key=configuration.repository_key,
                configuration_id=configuration.id,
                configuration_version=configuration.version,
                configuration_digest=report.configuration_digest,
                resolved_base_sha="a" * 40,
            )


def test_later_preflight_advances_pointer_without_deleting_immutable_attempt(
    repository_database: SessionFactory,
    tmp_path: Path,
) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    with session_scope(repository_database) as session:
        configuration = _configuration(session)
        blocked = capture_preflight_report(
            session,
            store,
            report=_report(
                configuration,
                _begin_preflight(session, store, configuration),
                status="BLOCKED",
                base_sha=None,
            ),
            owner_id="local-user",
            actor_id="host-agent",
            root_correlation_id=uuid4(),
        )
        passed_report = _report(
            configuration,
            _begin_preflight(session, store, configuration),
        )
        passed = capture_preflight_report(
            session,
            store,
            report=passed_report,
            owner_id="local-user",
            actor_id="host-agent",
            root_correlation_id=uuid4(),
        )

        assert passed.evidence_id != blocked.evidence_id
        assert configuration.preflight_evidence_id == passed.evidence_id
        assert session.get(EvidenceRecord, blocked.evidence_id) is not None
        assert require_preflight_ready(
            session,
            store,
            repository_key=configuration.repository_key,
            configuration_id=configuration.id,
            configuration_version=configuration.version,
            configuration_digest=passed_report.configuration_digest,
            resolved_base_sha=cast(str, passed_report.resolved_base_sha),
        ).evidence_id == passed.evidence_id


def test_delayed_report_cannot_supersede_a_newer_issued_attempt(
    repository_database: SessionFactory,
    tmp_path: Path,
) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    with session_scope(repository_database) as session:
        configuration = _configuration(session)
        stale_report = _report(
            configuration,
            _begin_preflight(session, store, configuration),
        )
        current_attempt_id = _begin_preflight(session, store, configuration)

        with pytest.raises(RepositoryPreflightBindingError, match="active issued attempt"):
            capture_preflight_report(
                session,
                store,
                report=stale_report,
                owner_id="local-user",
                actor_id="host-agent",
                root_correlation_id=uuid4(),
            )

        current = capture_preflight_report(
            session,
            store,
            report=_report(configuration, current_attempt_id),
            owner_id="local-user",
            actor_id="host-agent",
            root_correlation_id=uuid4(),
        )
        assert configuration.preflight_evidence_id == current.evidence_id


def test_missing_evidence_blocks_the_exact_latest_configuration(
    repository_database: SessionFactory,
    tmp_path: Path,
) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    with session_scope(repository_database) as session:
        configuration = _configuration(session)
        digest = repository_configuration_digest(configuration)

        with pytest.raises(
            RepositoryPreflightNotReadyError,
            match="no preflight evidence",
        ):
            require_preflight_ready(
                session,
                store,
                repository_key=configuration.repository_key,
                configuration_id=configuration.id,
                configuration_version=configuration.version,
                configuration_digest=digest,
                resolved_base_sha="a" * 40,
            )


def test_newer_unready_configuration_never_falls_back_to_older_ready_version(
    repository_database: SessionFactory,
    tmp_path: Path,
) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    with session_scope(repository_database) as session:
        first = _configuration(session)
        report = _report(first, _begin_preflight(session, store, first))
        capture_preflight_report(
            session,
            store,
            report=report,
            owner_id="local-user",
            actor_id="host-agent",
            root_correlation_id=uuid4(),
        )
        second = _configuration(session)

        with pytest.raises(
            RepositoryPreflightNotReadyError,
            match="not the authoritative latest",
        ):
            require_preflight_ready(
                session,
                store,
                repository_key=first.repository_key,
                configuration_id=first.id,
                configuration_version=first.version,
                configuration_digest=report.configuration_digest,
                resolved_base_sha=cast(str, report.resolved_base_sha),
            )

        assert second.preflight_evidence_id is None


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("configuration_id", uuid4()),
        ("configuration_version", 2),
        ("configuration_digest", f"sha256:{'f' * 64}"),
        ("resolved_base_sha", "b" * 40),
    ),
)
def test_require_fails_closed_for_each_requested_binding_mismatch(
    repository_database: SessionFactory,
    tmp_path: Path,
    field: str,
    replacement: object,
) -> None:
    store = ArtifactStore(tmp_path / f"artifacts-{field}")
    with session_scope(repository_database) as session:
        configuration = _configuration(session, repository_key=f"boppuh/{field}")
        report = _report(
            configuration,
            _begin_preflight(session, store, configuration),
        )
        capture_preflight_report(
            session,
            store,
            report=report,
            owner_id="local-user",
            actor_id="host-agent",
            root_correlation_id=uuid4(),
        )
        configuration_id = configuration.id
        configuration_version = configuration.version
        configuration_digest = report.configuration_digest
        resolved_base_sha = cast(str, report.resolved_base_sha)
        if field == "configuration_id":
            configuration_id = cast(UUID, replacement)
        elif field == "configuration_version":
            configuration_version = cast(int, replacement)
        elif field == "configuration_digest":
            configuration_digest = cast(str, replacement)
        else:
            resolved_base_sha = cast(str, replacement)

        with pytest.raises(RepositoryPreflightNotReadyError):
            require_preflight_ready(
                session,
                store,
                repository_key=configuration.repository_key,
                configuration_id=configuration_id,
                configuration_version=configuration_version,
                configuration_digest=configuration_digest,
                resolved_base_sha=resolved_base_sha,
            )
