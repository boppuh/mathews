from fastapi.testclient import TestClient
from mathews_control_plane.app import app


def test_health() -> None:
    response = TestClient(app).get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "environment": "local",
        "service": "api",
        "status": "ok",
        "version": "0.1.0",
    }
