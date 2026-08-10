from fastapi.testclient import TestClient


def test_health() -> None:
    from mathews_control_plane.app import app

    client = TestClient(app)
    assert any(
        getattr(candidate, "path", None)
        == "/api/validation-evidence/collections"
        for route in app.routes
        for candidate in getattr(
            getattr(route, "original_router", None),
            "routes",
            (route,),
        )
    )
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "configuration_ready": False,
        "environment": "local",
        "service": "api",
        "status": "ok",
        "version": "0.1.0",
    }

    oversized = client.post(
        "/api/validation-evidence/collections",
        content=b"x" * (1024 * 1024 + 1),
        headers={"Content-Type": "application/json"},
    )
    assert oversized.status_code == 413
    assert oversized.json() == {
        "detail": "validation evidence request body too large"
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
