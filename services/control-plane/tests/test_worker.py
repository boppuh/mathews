from mathews_control_plane.worker import run_once


def test_worker_probe() -> None:
    assert run_once() == "worker:0.1.0:local"
