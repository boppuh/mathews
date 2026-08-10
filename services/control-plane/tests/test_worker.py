import logging
import sys
from pathlib import Path

import pytest
from mathews_configuration import SecretReference
from pydantic import AnyHttpUrl, SecretStr


def test_worker_probe() -> None:
    from mathews_control_plane.background_jobs import WorkerRunOutcome
    from mathews_control_plane.worker import _poll_delay, probe

    assert probe() == "worker:0.1.0:local"
    assert _poll_delay(WorkerRunOutcome.IDLE) == 1
    assert _poll_delay(WorkerRunOutcome.FAILED) == 0.5
    assert _poll_delay(WorkerRunOutcome.LEASE_LOST) == 0.5
    assert _poll_delay(WorkerRunOutcome.RETRY_SCHEDULED) == 0.5
    assert _poll_delay(WorkerRunOutcome.ESCALATED) is None
    assert _poll_delay(WorkerRunOutcome.SUCCEEDED) is None


def test_once_mode_remains_a_side_effect_free_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mathews_control_plane import worker

    def unexpected_worker_build(*args: object, **kwargs: object) -> None:
        raise AssertionError((args, kwargs))

    monkeypatch.setattr(sys, "argv", ["mathews-worker", "--once"])
    monkeypatch.setattr(worker, "build_worker", unexpected_worker_build)

    worker.main()


def test_empty_handler_registry_is_reported_as_fail_closed(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from mathews_control_plane.settings import Settings
    from mathews_control_plane.worker import build_worker

    runtime_settings = Settings(
        environment="test",
        database_url=SecretStr(f"sqlite:///{tmp_path / 'worker.sqlite3'}"),
        artifact_root=tmp_path / "artifacts",
    )
    with caplog.at_level(logging.WARNING, logger="mathews.worker"):
        _worker, engine = build_worker(runtime_settings, handlers={})
    try:
        assert "no registered handlers" in caplog.text
        assert "remain idle" in caplog.text
    finally:
        engine.dispose()


def test_custom_handlers_do_not_resolve_an_unused_host_gateway(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mathews_control_plane import worker as worker_module
    from mathews_control_plane.settings import Settings

    runtime_settings = Settings(
        environment="test",
        database_url=SecretStr(f"sqlite:///{tmp_path / 'worker.sqlite3'}"),
        artifact_root=tmp_path / "artifacts",
        target_repository_root=tmp_path,
        host_socket_path=tmp_path / "host.sock",
        host_auth_key_ref=SecretReference.parse("keychain://mathews.host/control-plane"),
        hermes_endpoint=AnyHttpUrl("https://hermes.example.test"),
        hermes_api_key_ref=SecretReference.parse("keychain://mathews.hermes/api-key"),
        github_app_id=1,
        github_installation_id=2,
        github_repository_id=3,
        github_private_key_ref=SecretReference.parse("keychain://mathews.github/private-key"),
        github_webhook_secret_ref=SecretReference.parse("keychain://mathews.github/webhook"),
    )

    def unexpected_gateway(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("custom handlers must not resolve the host gateway")

    monkeypatch.setattr(worker_module, "configured_local_host_gateway", unexpected_gateway)

    _worker, engine = worker_module.build_worker(runtime_settings, handlers={})
    engine.dispose()


def test_default_worker_registers_the_fail_closed_hermes_handler(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from mathews_control_plane.settings import Settings
    from mathews_control_plane.worker import build_worker

    runtime_settings = Settings(
        environment="test",
        database_url=SecretStr(f"sqlite:///{tmp_path / 'worker.sqlite3'}"),
        artifact_root=tmp_path / "artifacts",
    )
    with caplog.at_level(logging.WARNING, logger="mathews.worker"):
        worker, engine = build_worker(runtime_settings)
    try:
        assert set(worker._handlers) == {"github-webhook", "hermes-run"}
        assert "no registered handlers" not in caplog.text
    finally:
        engine.dispose()


def test_worker_registers_validation_evidence_handler_with_host_gateway(
    tmp_path: Path,
) -> None:
    from mathews_configuration import HostRequestMessage, HostResponseMessage
    from mathews_control_plane.settings import Settings
    from mathews_control_plane.worker import build_worker

    class FakeHostGateway:
        def execute(self, _request: HostRequestMessage) -> HostResponseMessage:
            raise AssertionError("handler registration must not call the host")

    runtime_settings = Settings(
        environment="test",
        database_url=SecretStr(f"sqlite:///{tmp_path / 'worker.sqlite3'}"),
        artifact_root=tmp_path / "artifacts",
    )
    worker, engine = build_worker(
        runtime_settings,
        host_gateway=FakeHostGateway(),
    )
    try:
        assert set(worker._handlers) == {
            "github-webhook",
            "hermes-run",
            "validation-evidence",
            "validation-evidence-v2",
        }
    finally:
        engine.dispose()
