from fastapi.testclient import TestClient


def test_health() -> None:
    from mathews_control_plane.app import app

    client = TestClient(app)
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "configuration_ready": False,
        "environment": "local",
        "service": "api",
        "status": "ok",
        "version": "0.1.0",
    }

    preflight = client.options(
        "/health",
        headers={
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Last-Event-ID",
            "Origin": "http://localhost:3000",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert "Last-Event-ID" in preflight.headers["access-control-allow-headers"]
