def test_worker_probe() -> None:
    from mathews_control_plane.worker import probe

    assert probe() == "worker:0.1.0:local"
