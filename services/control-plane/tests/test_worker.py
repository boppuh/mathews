import sys

import pytest


def test_worker_probe() -> None:
    from mathews_control_plane.worker import probe

    assert probe() == "worker:0.1.0:local"


def test_once_mode_remains_a_side_effect_free_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mathews_control_plane import worker

    def unexpected_worker_build(*args: object, **kwargs: object) -> None:
        raise AssertionError((args, kwargs))

    monkeypatch.setattr(sys, "argv", ["mathews-worker", "--once"])
    monkeypatch.setattr(worker, "build_worker", unexpected_worker_build)

    worker.main()
