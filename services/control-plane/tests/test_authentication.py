from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from mathews_control_plane.app import create_app
from mathews_control_plane.authentication import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
    AuthenticatedSession,
    AuthenticationService,
    BootstrapAlreadyCompletedError,
    InvalidCredentialsError,
    RecentPasswordSession,
    generate_bootstrap_token,
    require_recent_password,
)
from mathews_control_plane.database import (
    AuthenticationState,
    AuthSession,
    Base,
    LocalUser,
    SessionFactory,
    create_database_engine,
    create_session_factory,
)
from mathews_control_plane.settings import Settings
from pydantic import SecretStr
from sqlalchemy import Engine, func, select

_ORIGIN = "http://localhost:3000"
_PASSWORD = "correct horse battery staple"


@dataclass(slots=True)
class MutableClock:
    now: datetime

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


@dataclass(slots=True)
class AuthHarness:
    app: FastAPI
    client: TestClient
    engine: Engine
    factory: SessionFactory
    service: AuthenticationService
    clock: MutableClock
    bootstrap_token: str


def _new_harness(tmp_path: Path, *, issue_bootstrap_token: bool = True) -> AuthHarness:
    database_url = f"sqlite:///{tmp_path / 'authentication.sqlite3'}"
    engine = create_database_engine(database_url)
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    clock = MutableClock(datetime.now(UTC).replace(microsecond=0))
    service = AuthenticationService(
        factory,
        idle_ttl=timedelta(minutes=30),
        absolute_ttl=timedelta(hours=2),
        reauthentication_ttl=timedelta(minutes=5),
        clock=clock,
    )
    app = create_app(
        Settings(database_url=SecretStr(database_url)),
        session_factory=factory,
        authentication_service=service,
    )
    client = TestClient(app, base_url="https://localhost")
    bootstrap_token = generate_bootstrap_token(factory) if issue_bootstrap_token else ""
    return AuthHarness(
        app=app,
        client=client,
        engine=engine,
        factory=factory,
        service=service,
        clock=clock,
        bootstrap_token=bootstrap_token,
    )


@pytest.fixture
def harness(tmp_path: Path) -> Iterator[AuthHarness]:
    current = _new_harness(tmp_path)
    try:
        yield current
    finally:
        current.client.close()
        current.engine.dispose()


def _preauthentication_csrf(harness: AuthHarness) -> str:
    response = harness.client.get("/api/auth/status")
    assert response.status_code == 200
    csrf_token = harness.client.cookies.get(CSRF_COOKIE_NAME)
    assert csrf_token is not None
    return csrf_token


def _bootstrap(harness: AuthHarness, *, password: str = _PASSWORD) -> tuple[str, str]:
    csrf_token = _preauthentication_csrf(harness)
    response = harness.client.post(
        "/api/auth/bootstrap",
        json={
            "bootstrap_token": harness.bootstrap_token,
            "password": password,
        },
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )
    assert response.status_code == 201, response.text
    session_token = harness.client.cookies.get(SESSION_COOKIE_NAME)
    bound_csrf_token = harness.client.cookies.get(CSRF_COOKIE_NAME)
    assert session_token is not None
    assert bound_csrf_token is not None
    return session_token, bound_csrf_token


def _authenticated_headers(harness: AuthHarness) -> dict[str, str]:
    csrf_token = harness.client.cookies.get(CSRF_COOKIE_NAME)
    assert csrf_token is not None
    return {"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token}


def _attach_sensitive_routes(app: FastAPI) -> None:
    @app.post("/api/secrets/test")
    def mutate_secret(
        _authentication: RecentPasswordSession,
    ) -> dict[str, bool]:
        return {"allowed": True}

    @app.post("/api/repository-policy/test")
    def mutate_repository_policy(
        _authentication: Annotated[
            AuthenticatedSession,
            Depends(require_recent_password),
        ],
    ) -> dict[str, bool]:
        return {"allowed": True}

    @app.post("/api/tasks/test/terminal")
    def mutate_terminal_task(
        _authentication: Annotated[
            AuthenticatedSession,
            Depends(require_recent_password),
        ],
    ) -> dict[str, bool]:
        return {"allowed": True}


def test_status_reports_cli_bootstrap_availability_and_sets_preauth_csrf(
    harness: AuthHarness,
) -> None:
    response = harness.client.get("/api/auth/status")

    assert response.status_code == 200
    assert response.json() == {
        "bootstrap_required": True,
        "bootstrap_available": True,
    }
    assert response.headers["cache-control"] == "no-store"
    csrf_cookie = next(
        header
        for header in response.headers.get_list("set-cookie")
        if header.startswith(f"{CSRF_COOKIE_NAME}=")
    )
    assert "Secure" in csrf_cookie
    assert "SameSite=strict" in csrf_cookie
    assert "Path=/" in csrf_cookie
    assert "HttpOnly" not in csrf_cookie
    assert "Domain=" not in csrf_cookie


def test_status_fails_closed_when_no_bootstrap_token_was_generated(tmp_path: Path) -> None:
    harness = _new_harness(tmp_path, issue_bootstrap_token=False)
    try:
        response = harness.client.get("/api/auth/status")
        assert response.json() == {
            "bootstrap_required": True,
            "bootstrap_available": False,
        }
    finally:
        harness.client.close()
        harness.engine.dispose()


def test_bootstrap_requires_exact_origin_and_preauthentication_csrf(
    harness: AuthHarness,
) -> None:
    csrf_token = _preauthentication_csrf(harness)
    body = {
        "bootstrap_token": harness.bootstrap_token,
        "password": _PASSWORD,
    }

    missing_origin = harness.client.post(
        "/api/auth/bootstrap",
        json=body,
        headers={CSRF_HEADER_NAME: csrf_token},
    )
    wrong_origin = harness.client.post(
        "/api/auth/bootstrap",
        json=body,
        headers={"Origin": "http://127.0.0.1:3000", CSRF_HEADER_NAME: csrf_token},
    )
    missing_csrf = harness.client.post(
        "/api/auth/bootstrap",
        json=body,
        headers={"Origin": _ORIGIN},
    )

    assert missing_origin.status_code == 403
    assert wrong_origin.status_code == 403
    assert missing_csrf.status_code == 403
    assert missing_origin.json() == {"detail": "trusted origin required"}
    assert missing_csrf.json() == {"detail": "CSRF validation failed"}


@pytest.mark.parametrize(
    ("path", "body"),
    [
        (
            "/api/auth/bootstrap",
            {"bootstrap_token": "a" * 43, "password": _PASSWORD},
        ),
        ("/api/auth/login", {"password": _PASSWORD}),
    ],
)
def test_public_auth_rejects_non_ascii_csrf_as_403(
    harness: AuthHarness,
    path: str,
    body: dict[str, str],
) -> None:
    harness.client.cookies.clear()
    response = harness.client.post(
        path,
        json=body,
        headers=[
            (b"origin", _ORIGIN.encode()),
            (
                b"cookie",
                f"{CSRF_COOKIE_NAME}=".encode() + b"\xff",
            ),
            (CSRF_HEADER_NAME.lower().encode(), b"\xff"),
        ],
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "CSRF validation failed"}


def test_bootstrap_consumes_only_digest_and_sets_hardened_rotated_cookies(
    harness: AuthHarness,
) -> None:
    preauth_csrf = _preauthentication_csrf(harness)
    response = harness.client.post(
        "/api/auth/bootstrap",
        json={
            "bootstrap_token": harness.bootstrap_token,
            "password": _PASSWORD,
        },
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: preauth_csrf},
    )

    assert response.status_code == 201
    assert response.json()["authenticated"] is True
    assert harness.bootstrap_token not in response.text
    assert _PASSWORD not in response.text
    session_token = harness.client.cookies.get(SESSION_COOKIE_NAME)
    bound_csrf = harness.client.cookies.get(CSRF_COOKIE_NAME)
    assert session_token is not None
    assert bound_csrf is not None
    assert bound_csrf != preauth_csrf

    cookies = response.headers.get_list("set-cookie")
    session_cookie = next(
        header for header in cookies if header.startswith(f"{SESSION_COOKIE_NAME}=")
    )
    csrf_cookie = next(
        header for header in cookies if header.startswith(f"{CSRF_COOKIE_NAME}=")
    )
    assert "Secure" in session_cookie
    assert "HttpOnly" in session_cookie
    assert "SameSite=strict" in session_cookie
    assert "Path=/" in session_cookie
    assert "Domain=" not in session_cookie
    assert "Secure" in csrf_cookie
    assert "HttpOnly" not in csrf_cookie

    with harness.factory() as session:
        state = session.get(AuthenticationState, 1)
        user = session.get(LocalUser, 1)
        auth_session = session.scalar(select(AuthSession))

    assert state is not None
    assert state.bootstrap_token_digest is None
    assert user is not None
    assert user.password_hash.startswith("$argon2id$")
    assert _PASSWORD not in user.password_hash
    assert auth_session is not None
    assert auth_session.token_digest != session_token.encode()
    assert auth_session.csrf_token_digest != bound_csrf.encode()

    status_response = harness.client.get("/api/auth/status")
    assert status_response.status_code == 200
    assert status_response.json() == {
        "bootstrap_required": False,
        "bootstrap_available": False,
    }
    assert harness.client.cookies.get(CSRF_COOKIE_NAME) == bound_csrf
    assert not any(
        header.startswith(f"{CSRF_COOKIE_NAME}=")
        for header in status_response.headers.get_list("set-cookie")
    )


def test_bootstrap_token_rotation_invalidates_prior_raw_value(
    harness: AuthHarness,
) -> None:
    first_token = harness.bootstrap_token
    harness.bootstrap_token = generate_bootstrap_token(harness.factory)
    csrf_token = _preauthentication_csrf(harness)

    rejected = harness.client.post(
        "/api/auth/bootstrap",
        json={"bootstrap_token": first_token, "password": _PASSWORD},
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )
    accepted = harness.client.post(
        "/api/auth/bootstrap",
        json={"bootstrap_token": harness.bootstrap_token, "password": _PASSWORD},
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )

    assert rejected.status_code == 403
    assert rejected.json() == {"detail": "bootstrap authorization failed"}
    assert first_token not in rejected.text
    assert accepted.status_code == 201
    with pytest.raises(BootstrapAlreadyCompletedError, match="already configured"):
        generate_bootstrap_token(harness.factory)


@pytest.mark.parametrize(
    "password",
    [
        "short-password",
        "😀" * 257,
    ],
)
def test_bootstrap_password_bounds_are_checked_before_argon2(
    harness: AuthHarness,
    password: str,
) -> None:
    csrf_token = _preauthentication_csrf(harness)

    response = harness.client.post(
        "/api/auth/bootstrap",
        json={"bootstrap_token": harness.bootstrap_token, "password": password},
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )

    assert response.status_code == 422
    assert response.json() == {
        "detail": "password must contain at least 15 characters and at most 1024 UTF-8 bytes"
    }
    assert password not in response.text


def test_auth_request_validation_never_echoes_secret_or_extra_input(
    harness: AuthHarness,
) -> None:
    csrf_token = _preauthentication_csrf(harness)
    marker = "secret-value-that-must-not-be-reflected"

    response = harness.client.post(
        "/api/auth/bootstrap",
        json={
            "bootstrap_token": harness.bootstrap_token,
            "password": _PASSWORD,
            "unexpected": marker,
        },
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}
    assert marker not in response.text
    assert harness.bootstrap_token not in response.text
    assert _PASSWORD not in response.text


def test_auth_content_length_limit_rejects_before_password_verification(
    harness: AuthHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    csrf_token = _preauthentication_csrf(harness)

    def unexpected_login(
        *,
        password: str,
        existing_session_token: str | None,
    ) -> None:
        raise AssertionError(
            f"login must not run: {len(password)}, {existing_session_token is not None}"
        )

    monkeypatch.setattr(harness.service, "login", unexpected_login)
    oversized_body = b'{"password":"' + (b"x" * (17 * 1024)) + b'"}'

    response = harness.client.post(
        "/api/auth/login",
        content=oversized_body,
        headers={
            "Content-Type": "application/json",
            "Origin": _ORIGIN,
            CSRF_HEADER_NAME: csrf_token,
        },
    )

    assert response.status_code == 413, response.text
    assert response.json() == {"detail": "authentication request body too large"}
    assert response.headers["cache-control"] == "no-store"


def test_streamed_auth_body_limit_rejects_before_bootstrap_hashing(
    harness: AuthHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    csrf_token = _preauthentication_csrf(harness)

    def unexpected_bootstrap(
        *,
        bootstrap_token: str,
        password: str,
    ) -> None:
        raise AssertionError(
            f"bootstrap must not run: {len(bootstrap_token)}, {len(password)}"
        )

    monkeypatch.setattr(harness.service, "bootstrap", unexpected_bootstrap)

    def oversized_chunks() -> Iterator[bytes]:
        yield b'{"bootstrap_token":"'
        yield b"a" * 43
        yield b'","password":"'
        yield b"x" * (17 * 1024)
        yield b'"}'

    response = harness.client.post(
        "/api/auth/bootstrap",
        content=oversized_chunks(),
        headers={
            "Content-Type": "application/json",
            "Origin": _ORIGIN,
            CSRF_HEADER_NAME: csrf_token,
        },
    )

    assert response.status_code == 413, response.text
    assert response.json() == {"detail": "authentication request body too large"}
    assert response.headers["cache-control"] == "no-store"


def test_default_deny_protects_tasks_artifacts_sse_and_disabled_docs(
    harness: AuthHarness,
) -> None:
    for path in (
        "/api/tasks",
        "/api/artifacts/sha256:missing",
        "/api/events",
        "/openapi.json",
        "/docs",
    ):
        response = harness.client.get(path)
        assert response.status_code == 401
        assert response.headers["cache-control"] == "no-store"

    health = harness.client.get("/health")
    assert health.status_code == 200
    assert harness.client.options("/api/tasks").status_code == 401

    _bootstrap(harness)
    for path in (
        "/api/tasks",
        "/api/artifacts/sha256:missing",
        "/api/events",
        "/openapi.json",
        "/docs",
    ):
        response = harness.client.get(path)
        assert response.status_code == 404
        assert response.headers["cache-control"] == "no-store"


def test_authenticated_mutations_require_exact_origin_and_bound_csrf(
    harness: AuthHarness,
) -> None:
    _attach_sensitive_routes(harness.app)
    _bootstrap(harness)
    csrf_token = harness.client.cookies.get(CSRF_COOKIE_NAME)
    assert csrf_token is not None

    missing_origin = harness.client.post(
        "/api/secrets/test",
        headers={CSRF_HEADER_NAME: csrf_token},
    )
    wrong_header = harness.client.post(
        "/api/secrets/test",
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: "not-the-cookie"},
    )
    accepted = harness.client.post(
        "/api/secrets/test",
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )

    assert missing_origin.status_code == 403
    assert wrong_header.status_code == 403
    assert accepted.status_code == 200


def test_authenticated_mutation_rejects_non_ascii_csrf_as_403(
    harness: AuthHarness,
) -> None:
    _attach_sensitive_routes(harness.app)
    session_token, _csrf_token = _bootstrap(harness)
    harness.client.cookies.clear()

    response = harness.client.post(
        "/api/secrets/test",
        headers=[
            (b"origin", _ORIGIN.encode()),
            (
                b"cookie",
                (
                    f"{SESSION_COOKIE_NAME}={session_token}; "
                    f"{CSRF_COOKIE_NAME}="
                ).encode()
                + b"\xff",
            ),
            (CSRF_HEADER_NAME.lower().encode(), b"\xff"),
        ],
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "CSRF validation failed"}


def test_login_requires_public_csrf_and_rotates_existing_session(
    harness: AuthHarness,
) -> None:
    old_session, old_csrf = _bootstrap(harness)

    missing_origin = harness.client.post(
        "/api/auth/login",
        json={"password": _PASSWORD},
        headers={CSRF_HEADER_NAME: old_csrf},
    )
    missing_csrf = harness.client.post(
        "/api/auth/login",
        json={"password": _PASSWORD},
        headers={"Origin": _ORIGIN},
    )
    accepted = harness.client.post(
        "/api/auth/login",
        json={"password": _PASSWORD},
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: old_csrf},
    )

    assert missing_origin.status_code == 403
    assert missing_csrf.status_code == 403
    assert accepted.status_code == 200
    assert harness.client.cookies.get(SESSION_COOKIE_NAME) != old_session
    assert harness.client.cookies.get(CSRF_COOKIE_NAME) != old_csrf

    old_client = TestClient(harness.app, base_url="https://localhost")
    try:
        old_client.cookies.set(SESSION_COOKIE_NAME, old_session)
        assert old_client.get("/api/auth/session").status_code == 401
    finally:
        old_client.close()


def test_session_get_self_heals_missing_csrf_without_overwriting_valid_cookie(
    harness: AuthHarness,
) -> None:
    session_token, csrf_token = _bootstrap(harness)

    unchanged = harness.client.get("/api/auth/session")
    assert unchanged.status_code == 200
    assert not any(
        header.startswith(f"{CSRF_COOKIE_NAME}=")
        for header in unchanged.headers.get_list("set-cookie")
    )

    harness.client.cookies.clear()
    harness.client.cookies.set(SESSION_COOKIE_NAME, session_token)
    healed = harness.client.get("/api/auth/session")
    healed_csrf = harness.client.cookies.get(CSRF_COOKIE_NAME)

    assert healed.status_code == 200
    assert healed_csrf is not None
    assert healed_csrf != csrf_token
    accepted = harness.client.post(
        "/api/repository-policy/test",
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: healed_csrf},
    )
    # The route is absent, but middleware accepted both authentication and CSRF.
    assert accepted.status_code == 404


def test_reauthentication_rotates_session_and_gates_three_sensitive_mutations(
    harness: AuthHarness,
) -> None:
    _attach_sensitive_routes(harness.app)
    old_session, old_csrf = _bootstrap(harness)
    harness.clock.advance(timedelta(minutes=6))

    for path in (
        "/api/secrets/test",
        "/api/repository-policy/test",
        "/api/tasks/test/terminal",
    ):
        response = harness.client.post(path, headers=_authenticated_headers(harness))
        assert response.status_code == 403
        assert response.json() == {"detail": "recent password authentication required"}

    response = harness.client.post(
        "/api/auth/reauthenticate",
        json={"password": _PASSWORD},
        headers=_authenticated_headers(harness),
    )
    assert response.status_code == 200
    assert response.json()["authenticated"] is True
    new_session = harness.client.cookies.get(SESSION_COOKIE_NAME)
    new_csrf = harness.client.cookies.get(CSRF_COOKIE_NAME)
    assert new_session is not None and new_session != old_session
    assert new_csrf is not None and new_csrf != old_csrf

    for path in (
        "/api/secrets/test",
        "/api/repository-policy/test",
        "/api/tasks/test/terminal",
    ):
        assert (
            harness.client.post(path, headers=_authenticated_headers(harness)).status_code
            == 200
        )

    old_client = TestClient(harness.app, base_url="https://localhost")
    try:
        old_client.cookies.set(SESSION_COOKIE_NAME, old_session)
        old_client.cookies.set(CSRF_COOKIE_NAME, old_csrf)
        assert old_client.get("/api/auth/session").status_code == 401
    finally:
        old_client.close()


def test_future_dated_reauthentication_fails_closed(harness: AuthHarness) -> None:
    _attach_sensitive_routes(harness.app)
    _bootstrap(harness)
    with harness.factory.begin() as session:
        record = session.scalar(select(AuthSession))
        assert record is not None
        record.reauthenticated_at = harness.clock.now + timedelta(hours=1)

    session_response = harness.client.get("/api/auth/session")
    protected = harness.client.post(
        "/api/secrets/test",
        headers=_authenticated_headers(harness),
    )

    assert session_response.status_code == 200
    assert datetime.fromisoformat(session_response.json()["reauthenticated_until"]) <= (
        harness.clock.now
    )
    assert protected.status_code == 403


def test_reauthentication_failures_share_durable_progressive_throttle(
    harness: AuthHarness,
) -> None:
    session_token, csrf_token = _bootstrap(harness)

    for password in ("x", "bad", "wrong", "no", "still-wrong"):
        response = harness.client.post(
            "/api/auth/reauthenticate",
            json={"password": password},
            headers=_authenticated_headers(harness),
        )
        assert response.status_code == 401
        assert response.json() == {"detail": "invalid credentials"}

    blocked = harness.client.post(
        "/api/auth/reauthenticate",
        json={"password": _PASSWORD},
        headers=_authenticated_headers(harness),
    )
    assert blocked.status_code == 401

    restarted_service = AuthenticationService(
        harness.factory,
        idle_ttl=timedelta(minutes=30),
        absolute_ttl=timedelta(hours=2),
        reauthentication_ttl=timedelta(minutes=5),
        clock=harness.clock,
    )
    restarted_app = create_app(
        Settings(),
        session_factory=harness.factory,
        authentication_service=restarted_service,
    )
    restarted_client = TestClient(restarted_app, base_url="https://localhost")
    try:
        restarted_client.cookies.set(SESSION_COOKIE_NAME, session_token)
        restarted_client.cookies.set(CSRF_COOKIE_NAME, csrf_token)
        still_blocked = restarted_client.post(
            "/api/auth/reauthenticate",
            json={"password": _PASSWORD},
            headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
        )
        assert still_blocked.status_code == 401

        harness.clock.advance(timedelta(seconds=3))
        accepted = restarted_client.post(
            "/api/auth/reauthenticate",
            json={"password": _PASSWORD},
            headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
        )
        assert accepted.status_code == 200
        session_cookie = next(
            header
            for header in accepted.headers.get_list("set-cookie")
            if header.startswith(f"{SESSION_COOKIE_NAME}=")
        )
        assert not session_cookie.startswith(f"{SESSION_COOKIE_NAME}={session_token};")
    finally:
        restarted_client.close()


def test_logout_revocation_and_session_expiry_survive_restart(
    harness: AuthHarness,
) -> None:
    session_token, csrf_token = _bootstrap(harness)

    restarted_service = AuthenticationService(
        harness.factory,
        idle_ttl=timedelta(minutes=30),
        absolute_ttl=timedelta(hours=2),
        reauthentication_ttl=timedelta(minutes=5),
        clock=harness.clock,
    )
    restarted_app = create_app(
        Settings(),
        session_factory=harness.factory,
        authentication_service=restarted_service,
    )
    restarted_client = TestClient(restarted_app, base_url="https://localhost")
    try:
        restarted_client.cookies.set(SESSION_COOKIE_NAME, session_token)
        restarted_client.cookies.set(CSRF_COOKIE_NAME, csrf_token)
        assert restarted_client.get("/api/auth/session").status_code == 200
        assert restarted_client.get("/api/auth/status").json() == {
            "bootstrap_required": False,
            "bootstrap_available": False,
        }

        logout = restarted_client.post(
            "/api/auth/logout",
            headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
        )
        assert logout.status_code == 204

        after_restart = TestClient(restarted_app, base_url="https://localhost")
        try:
            after_restart.cookies.set(SESSION_COOKIE_NAME, session_token)
            assert after_restart.get("/api/auth/session").status_code == 401
        finally:
            after_restart.close()
    finally:
        restarted_client.close()


def test_idle_and_absolute_expiry_delete_server_side_sessions(
    harness: AuthHarness,
) -> None:
    session_token, _csrf_token = _bootstrap(harness)

    harness.clock.advance(timedelta(minutes=31))
    assert harness.service.authenticate(session_token) is None
    with harness.factory() as session:
        assert session.scalar(select(func.count()).select_from(AuthSession)) == 0

    csrf_token = _preauthentication_csrf(harness)
    login = harness.client.post(
        "/api/auth/login",
        json={"password": _PASSWORD},
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )
    assert login.status_code == 200
    sliding_token = harness.client.cookies.get(SESSION_COOKIE_NAME)
    assert sliding_token is not None
    for _ in range(3):
        harness.clock.advance(timedelta(minutes=25))
        assert harness.service.authenticate(sliding_token) is not None
    harness.clock.advance(timedelta(minutes=46))
    assert harness.service.authenticate(sliding_token) is None


def test_login_failures_are_generic_bounded_and_durably_throttled(
    harness: AuthHarness,
) -> None:
    _bootstrap(harness)
    harness.client.cookies.clear()
    csrf_token = _preauthentication_csrf(harness)

    for password in ("x", "bad", "wrong", "no", "still-wrong"):
        response = harness.client.post(
            "/api/auth/login",
            json={"password": password},
            headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
        )
        assert response.status_code == 401
        assert response.json() == {"detail": "invalid credentials"}
        assert password not in response.text

    with harness.factory() as session:
        state = session.get(AuthenticationState, 1)
        assert state is not None
        assert state.failed_login_attempts == 5
        assert state.login_blocked_until is not None

    blocked = harness.client.post(
        "/api/auth/login",
        json={"password": _PASSWORD},
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )
    assert blocked.status_code == 401
    assert blocked.json() == {"detail": "invalid credentials"}

    harness.clock.advance(timedelta(seconds=3))
    accepted = harness.client.post(
        "/api/auth/login",
        json={"password": _PASSWORD},
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )
    assert accepted.status_code == 200

    oversized = "😀" * 257
    harness.client.cookies.clear()
    csrf_token = _preauthentication_csrf(harness)
    rejected = harness.client.post(
        "/api/auth/login",
        json={"password": oversized},
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )
    assert rejected.status_code == 401
    assert rejected.json() == {"detail": "invalid credentials"}
    assert oversized not in rejected.text


def test_login_without_a_user_uses_same_generic_failure(harness: AuthHarness) -> None:
    csrf_token = _preauthentication_csrf(harness)

    with pytest.raises(InvalidCredentialsError, match="invalid credentials"):
        harness.service.login(password="short", existing_session_token=None)

    response = harness.client.post(
        "/api/auth/login",
        json={"password": "short"},
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "invalid credentials"}
