from fastapi.testclient import TestClient


def test_health(local_settings_environment: None) -> None:
    from mathews_control_plane.app import app

    response = TestClient(app).get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "environment": "local",
        "service": "api",
        "status": "ok",
        "version": "0.1.0",
    }
