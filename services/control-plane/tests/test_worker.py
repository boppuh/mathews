import logging
import sys
from pathlib import Path

import pytest
from pydantic import SecretStr


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
        _worker, engine = build_worker(runtime_settings)
    try:
        assert "no registered handlers" in caplog.text
        assert "remain idle" in caplog.text
    finally:
        engine.dispose()
