def test_worker_probe(local_settings_environment: None) -> None:
    from mathews_control_plane.worker import run_once

    assert run_once() == "worker:0.1.0:local"
