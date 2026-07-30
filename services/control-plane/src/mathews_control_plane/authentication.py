"""Durable single-user authentication for the local control plane."""

from __future__ import annotations

import hmac
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Annotated, Literal
from uuid import UUID

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, SecretStr
from sqlalchemy import delete, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mathews_control_plane.database import (
    AuthenticationState,
    AuthSession,
    LocalUser,
    SessionFactory,
    create_database_engine,
    create_session_factory,
    session_scope,
)
from mathews_control_plane.settings import get_settings

SESSION_COOKIE_NAME = "__Host-mathews-session"
CSRF_COOKIE_NAME = "__Host-mathews-csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"

_LOCAL_USER_ID = 1
_AUTHENTICATION_STATE_ID = 1
_TOKEN_BYTES = 32
_MIN_PASSWORD_CHARACTERS = 15
_MAX_PASSWORD_BYTES = 1024
_LOGIN_THROTTLE_START = 5
_LOGIN_THROTTLE_MAX_SECONDS = 5 * 60
_LOGIN_THROTTLE_MAX_FAILURES = 16
_MAX_AUTHENTICATION_BODY_BYTES = 16 * 1024
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_INVALID_TOKEN_DIGEST = sha256(b"invalid-mathews-authentication-token").digest()

_PASSWORD_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)
# A missing or corrupt credential takes the same expensive verification path as
# a wrong password. The value is process-local, random-salted, and never valid.
_DUMMY_PASSWORD_HASH = _PASSWORD_HASHER.hash("mathews-dummy-credential-never-valid")


class AuthenticationFailure(RuntimeError):
    """Base class for safe authentication-domain failures."""


class InvalidCredentialsError(AuthenticationFailure):
    """Raised for any failed password authentication attempt."""


class BootstrapUnavailableError(AuthenticationFailure):
    """Raised when no one-time bootstrap token is awaiting consumption."""


class BootstrapAlreadyCompletedError(AuthenticationFailure):
    """Raised when the singleton local user has already been created."""


class InvalidBootstrapTokenError(AuthenticationFailure):
    """Raised when a bootstrap claim does not match the stored digest."""


class PasswordPolicyError(AuthenticationFailure):
    """Raised before hashing when a password violates fixed size bounds."""


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticatedSession:
    """Non-secret request authentication context."""

    session_id: UUID
    user_id: int
    csrf_token_digest: bytes
    expires_at: datetime
    absolute_expires_at: datetime
    reauthenticated_until: datetime
    evaluated_at: datetime
    recent_password_verified: bool


@dataclass(frozen=True, slots=True, repr=False)
class IssuedSession:
    """Raw credentials used only to populate response cookies."""

    authentication: AuthenticatedSession
    session_token: str
    csrf_token: str


@dataclass(frozen=True, slots=True)
class BootstrapStatus:
    bootstrap_required: bool
    bootstrap_available: bool


class BootstrapStatusResponse(BaseModel):
    bootstrap_required: bool
    bootstrap_available: bool


class SessionResponse(BaseModel):
    authenticated: Literal[True] = True
    expires_at: datetime
    reauthenticated_until: datetime


class _SecretRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class BootstrapRequest(_SecretRequest):
    bootstrap_token: SecretStr
    password: SecretStr


class PasswordRequest(_SecretRequest):
    password: SecretStr


Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _token_digest(token: str) -> bytes:
    return sha256(token.encode("utf-8")).digest()


def _token_is_canonical(token: str | None) -> bool:
    return token is not None and _TOKEN_PATTERN.fullmatch(token) is not None


def _new_token() -> str:
    return secrets.token_urlsafe(_TOKEN_BYTES)


def _validate_new_password(password: str) -> None:
    byte_length = len(password.encode("utf-8"))
    if len(password) < _MIN_PASSWORD_CHARACTERS or byte_length > _MAX_PASSWORD_BYTES:
        raise PasswordPolicyError(
            "password must contain at least 15 characters and at most 1024 UTF-8 bytes"
        )


def _authentication_input_is_bounded(password: str) -> bool:
    return len(password.encode("utf-8")) <= _MAX_PASSWORD_BYTES


def _password_matches(password_hash: str, candidate: str) -> bool:
    try:
        return _PASSWORD_HASHER.verify(password_hash, candidate)
    except (InvalidHashError, VerificationError):
        return False


def _get_or_create_authentication_state(session: Session) -> AuthenticationState:
    state = session.scalar(
        select(AuthenticationState)
        .where(AuthenticationState.id == _AUTHENTICATION_STATE_ID)
        .with_for_update()
    )
    if state is not None:
        return state

    try:
        with session.begin_nested():
            state = AuthenticationState(id=_AUTHENTICATION_STATE_ID)
            session.add(state)
            session.flush()
    except IntegrityError:
        state = session.scalar(
            select(AuthenticationState)
            .where(AuthenticationState.id == _AUTHENTICATION_STATE_ID)
            .with_for_update()
        )

    if state is None:
        raise RuntimeError("authentication state could not be initialized")
    return state


def generate_bootstrap_token(factory: SessionFactory) -> str:
    """Create or rotate the one-time setup claim before a user exists.

    Only the SHA-256 digest is committed. The returned 256-bit token is the
    caller's sole opportunity to present or store the raw value.
    """

    raw_token = _new_token()
    with session_scope(factory) as session:
        state = _get_or_create_authentication_state(session)
        if session.get(LocalUser, _LOCAL_USER_ID) is not None:
            raise BootstrapAlreadyCompletedError("local authentication is already configured")
        state.bootstrap_token_digest = _token_digest(raw_token)
        session.flush()
    return raw_token


class AuthenticationService:
    """Transaction boundary for bootstrap, password checks, and sessions."""

    def __init__(
        self,
        factory: SessionFactory,
        *,
        idle_ttl: timedelta = timedelta(minutes=30),
        absolute_ttl: timedelta = timedelta(hours=8),
        reauthentication_ttl: timedelta = timedelta(minutes=5),
        clock: Clock = _utc_now,
    ) -> None:
        if idle_ttl <= timedelta(0) or absolute_ttl <= timedelta(0):
            raise ValueError("session lifetimes must be positive")
        if idle_ttl > absolute_ttl:
            raise ValueError("idle session lifetime must not exceed the absolute lifetime")
        if reauthentication_ttl <= timedelta(0):
            raise ValueError("reauthentication lifetime must be positive")

        self._factory = factory
        self._idle_ttl = idle_ttl
        self._absolute_ttl = absolute_ttl
        self._reauthentication_ttl = reauthentication_ttl
        self._clock = clock

    @property
    def reauthentication_ttl(self) -> timedelta:
        return self._reauthentication_ttl

    def bootstrap_status(self) -> BootstrapStatus:
        with session_scope(self._factory) as session:
            state = _get_or_create_authentication_state(session)
            user_exists = session.get(LocalUser, _LOCAL_USER_ID) is not None
            return BootstrapStatus(
                bootstrap_required=not user_exists,
                bootstrap_available=(
                    not user_exists and state.bootstrap_token_digest is not None
                ),
            )

    def bootstrap(self, *, bootstrap_token: str, password: str) -> IssuedSession:
        _validate_new_password(password)
        now = _as_utc(self._clock())

        with session_scope(self._factory) as session:
            state = _get_or_create_authentication_state(session)
            if session.get(LocalUser, _LOCAL_USER_ID) is not None:
                raise BootstrapAlreadyCompletedError(
                    "local authentication is already configured"
                )
            expected_digest = state.bootstrap_token_digest
            if expected_digest is None:
                raise BootstrapUnavailableError("bootstrap is not available")
            presented_digest = (
                _token_digest(bootstrap_token)
                if _token_is_canonical(bootstrap_token)
                else _INVALID_TOKEN_DIGEST
            )
            if not hmac.compare_digest(expected_digest, presented_digest):
                raise InvalidBootstrapTokenError("bootstrap authorization failed")

            password_hash = _PASSWORD_HASHER.hash(password)
            state.bootstrap_token_digest = None
            state.failed_login_attempts = 0
            state.login_blocked_until = None
            session.add(LocalUser(id=_LOCAL_USER_ID, password_hash=password_hash))
            session.flush()
            return self._issue_session(session, now=now)

    def login(self, *, password: str, existing_session_token: str | None) -> IssuedSession:
        now = _as_utc(self._clock())
        if not _authentication_input_is_bounded(password):
            raise InvalidCredentialsError("invalid credentials")

        authentication_failed = False
        with session_scope(self._factory) as session:
            state = _get_or_create_authentication_state(session)
            user = session.get(LocalUser, _LOCAL_USER_ID)
            password_hash = user.password_hash if user is not None else _DUMMY_PASSWORD_HASH

            blocked_until = (
                _as_utc(state.login_blocked_until)
                if state.login_blocked_until is not None
                else None
            )
            if blocked_until is not None and now < blocked_until:
                _password_matches(_DUMMY_PASSWORD_HASH, password)
                authentication_failed = True
            elif not _password_matches(password_hash, password) or user is None:
                self._record_login_failure(state, now=now)
                authentication_failed = True
            else:
                state.failed_login_attempts = 0
                state.login_blocked_until = None
                if _PASSWORD_HASHER.check_needs_rehash(user.password_hash):
                    user.password_hash = _PASSWORD_HASHER.hash(password)
                self._revoke_token(session, existing_session_token, now=now)
                return self._issue_session(session, now=now)

        if authentication_failed:
            raise InvalidCredentialsError("invalid credentials")
        raise RuntimeError("login transaction reached an invalid state")

    def authenticate(self, session_token: str | None) -> AuthenticatedSession | None:
        if not _token_is_canonical(session_token):
            return None
        assert session_token is not None
        now = _as_utc(self._clock())

        with session_scope(self._factory) as session:
            record = session.scalar(
                select(AuthSession).where(
                    AuthSession.token_digest == _token_digest(session_token)
                )
            )
            if record is None or record.revoked_at is not None:
                return None

            expires_at = _as_utc(record.expires_at)
            absolute_expires_at = _as_utc(record.absolute_expires_at)
            if now >= expires_at or now >= absolute_expires_at:
                session.delete(record)
                return None

            record.last_seen_at = now
            record.expires_at = min(now + self._idle_ttl, absolute_expires_at)
            return self._authentication_from_record(record, now=now)

    def reauthenticate(
        self,
        authentication: AuthenticatedSession,
        *,
        password: str,
    ) -> IssuedSession:
        now = _as_utc(self._clock())
        if not _authentication_input_is_bounded(password):
            raise InvalidCredentialsError("invalid credentials")

        authentication_failed = False
        with session_scope(self._factory) as session:
            state = _get_or_create_authentication_state(session)
            blocked_until = (
                _as_utc(state.login_blocked_until)
                if state.login_blocked_until is not None
                else None
            )
            if blocked_until is not None and now < blocked_until:
                _password_matches(_DUMMY_PASSWORD_HASH, password)
                authentication_failed = True
            else:
                record = session.scalar(
                    select(AuthSession)
                    .where(AuthSession.id == authentication.session_id)
                    .with_for_update()
                )
                if record is None or record.revoked_at is not None:
                    _password_matches(_DUMMY_PASSWORD_HASH, password)
                    authentication_failed = True
                elif now >= _as_utc(record.expires_at) or now >= _as_utc(
                    record.absolute_expires_at
                ):
                    session.delete(record)
                    _password_matches(_DUMMY_PASSWORD_HASH, password)
                    authentication_failed = True
                else:
                    user = session.get(LocalUser, record.user_id)
                    password_hash = (
                        user.password_hash if user is not None else _DUMMY_PASSWORD_HASH
                    )
                    if not _password_matches(password_hash, password) or user is None:
                        self._record_login_failure(state, now=now)
                        authentication_failed = True
                    else:
                        state.failed_login_attempts = 0
                        state.login_blocked_until = None
                        if _PASSWORD_HASHER.check_needs_rehash(user.password_hash):
                            user.password_hash = _PASSWORD_HASHER.hash(password)
                        record.revoked_at = now
                        return self._issue_session(session, now=now)

        if authentication_failed:
            raise InvalidCredentialsError("invalid credentials")
        raise RuntimeError("reauthentication transaction reached an invalid state")

    def logout(self, authentication: AuthenticatedSession) -> None:
        now = _as_utc(self._clock())
        with session_scope(self._factory) as session:
            record = session.get(AuthSession, authentication.session_id)
            if record is not None and record.revoked_at is None:
                record.revoked_at = now

    def verify_bound_csrf(
        self,
        authentication: AuthenticatedSession,
        *,
        cookie_token: str | None,
        header_token: str | None,
    ) -> bool:
        if not self.verify_double_submit_csrf(
            cookie_token=cookie_token,
            header_token=header_token,
        ):
            return False
        assert header_token is not None
        return hmac.compare_digest(
            authentication.csrf_token_digest,
            _token_digest(header_token),
        )

    def csrf_cookie_is_bound(
        self,
        authentication: AuthenticatedSession,
        cookie_token: str | None,
    ) -> bool:
        if not _token_is_canonical(cookie_token):
            return False
        assert cookie_token is not None
        return hmac.compare_digest(
            authentication.csrf_token_digest,
            _token_digest(cookie_token),
        )

    def rotate_csrf(self, authentication: AuthenticatedSession) -> str:
        raw_token = _new_token()
        now = _as_utc(self._clock())
        with session_scope(self._factory) as session:
            record = session.get(AuthSession, authentication.session_id)
            if record is None or record.revoked_at is not None:
                raise InvalidCredentialsError("invalid credentials")
            if now >= _as_utc(record.expires_at) or now >= _as_utc(
                record.absolute_expires_at
            ):
                session.delete(record)
                raise InvalidCredentialsError("invalid credentials")
            record.csrf_token_digest = _token_digest(raw_token)
        return raw_token

    @staticmethod
    def verify_double_submit_csrf(
        *,
        cookie_token: str | None,
        header_token: str | None,
    ) -> bool:
        if (
            not _token_is_canonical(cookie_token)
            or not _token_is_canonical(header_token)
        ):
            return False
        assert cookie_token is not None
        assert header_token is not None
        return hmac.compare_digest(cookie_token, header_token)

    @staticmethod
    def issue_preauthentication_csrf() -> str:
        return _new_token()

    def cleanup_stale_sessions(self) -> None:
        now = _as_utc(self._clock())
        with session_scope(self._factory) as session:
            self._delete_stale_sessions(session, now=now)

    def _issue_session(self, session: Session, *, now: datetime) -> IssuedSession:
        self._delete_stale_sessions(session, now=now)
        session_token = _new_token()
        csrf_token = _new_token()
        absolute_expires_at = now + self._absolute_ttl
        record = AuthSession(
            user_id=_LOCAL_USER_ID,
            token_digest=_token_digest(session_token),
            csrf_token_digest=_token_digest(csrf_token),
            last_seen_at=now,
            expires_at=min(now + self._idle_ttl, absolute_expires_at),
            absolute_expires_at=absolute_expires_at,
            reauthenticated_at=now,
        )
        session.add(record)
        session.flush()
        return IssuedSession(
            authentication=self._authentication_from_record(record, now=now),
            session_token=session_token,
            csrf_token=csrf_token,
        )

    def _authentication_from_record(
        self,
        record: AuthSession,
        *,
        now: datetime,
    ) -> AuthenticatedSession:
        reauthenticated_at = _as_utc(record.reauthenticated_at)
        reauthenticated_until = reauthenticated_at + self._reauthentication_ttl
        reauthentication_is_valid = (
            reauthenticated_at <= now < reauthenticated_until
        )
        if reauthenticated_at > now:
            reauthenticated_until = now
        return AuthenticatedSession(
            session_id=record.id,
            user_id=record.user_id,
            csrf_token_digest=record.csrf_token_digest,
            expires_at=_as_utc(record.expires_at),
            absolute_expires_at=_as_utc(record.absolute_expires_at),
            reauthenticated_until=reauthenticated_until,
            evaluated_at=now,
            recent_password_verified=reauthentication_is_valid,
        )

    @staticmethod
    def _delete_stale_sessions(session: Session, *, now: datetime) -> None:
        session.execute(
            delete(AuthSession).where(
                or_(
                    AuthSession.revoked_at.is_not(None),
                    AuthSession.expires_at <= now,
                    AuthSession.absolute_expires_at <= now,
                )
            )
        )

    @staticmethod
    def _revoke_token(
        session: Session,
        session_token: str | None,
        *,
        now: datetime,
    ) -> None:
        if not _token_is_canonical(session_token):
            return
        assert session_token is not None
        existing = session.scalar(
            select(AuthSession).where(
                AuthSession.token_digest == _token_digest(session_token)
            )
        )
        if existing is not None and existing.revoked_at is None:
            existing.revoked_at = now

    @staticmethod
    def _record_login_failure(state: AuthenticationState, *, now: datetime) -> None:
        failures = min(
            state.failed_login_attempts + 1,
            _LOGIN_THROTTLE_MAX_FAILURES,
        )
        state.failed_login_attempts = failures
        if failures >= _LOGIN_THROTTLE_START:
            exponent = failures - _LOGIN_THROTTLE_START + 1
            delay_seconds = min(2**exponent, _LOGIN_THROTTLE_MAX_SECONDS)
            state.login_blocked_until = now + timedelta(seconds=delay_seconds)


def _session_response(authentication: AuthenticatedSession) -> SessionResponse:
    return SessionResponse(
        expires_at=authentication.expires_at,
        reauthenticated_until=authentication.reauthenticated_until,
    )


def _set_csrf_cookie(
    response: Response,
    csrf_token: str,
    *,
    expires: datetime | None = None,
) -> None:
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        expires=expires,
        httponly=False,
        secure=True,
        samesite="strict",
        path="/",
    )


def _set_authenticated_cookies(response: Response, issued: IssuedSession) -> None:
    max_age = max(
        0,
        int(
            (
                issued.authentication.absolute_expires_at
                - issued.authentication.evaluated_at
            ).total_seconds()
        ),
    )
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=issued.session_token,
        max_age=max_age,
        expires=issued.authentication.absolute_expires_at,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )
    _set_csrf_cookie(
        response,
        issued.csrf_token,
        expires=issued.authentication.absolute_expires_at,
    )


def clear_authentication_cookies(response: Response) -> None:
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )
    response.delete_cookie(
        CSRF_COOKIE_NAME,
        path="/",
        secure=True,
        httponly=False,
        samesite="strict",
    )


def require_authenticated_session(request: Request) -> AuthenticatedSession:
    authentication = getattr(request.state, "authenticated_session", None)
    if not isinstance(authentication, AuthenticatedSession):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
        )
    return authentication


def require_recent_password(
    request: Request,
) -> AuthenticatedSession:
    authentication = require_authenticated_session(request)
    if not authentication.recent_password_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="recent password authentication required",
        )
    return authentication


RecentPasswordSession = Annotated[
    AuthenticatedSession,
    Depends(require_recent_password),
]


class AuthenticationBodyLimitMiddleware:
    """Reject oversized credential bodies before FastAPI buffers or decodes them."""

    _BODY_ENDPOINTS = frozenset(
        {
            ("POST", "/api/auth/bootstrap"),
            ("POST", "/api/auth/login"),
            ("POST", "/api/auth/reauthenticate"),
        }
    )

    def __init__(
        self,
        app: ASGIApp,
        *,
        maximum_bytes: int = _MAX_AUTHENTICATION_BODY_BYTES,
    ) -> None:
        if maximum_bytes <= 0:
            raise ValueError("authentication body limit must be positive")
        self._app = app
        self._maximum_bytes = maximum_bytes

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http" or (
            scope["method"],
            scope["path"],
        ) not in self._BODY_ENDPOINTS:
            await self._app(scope, receive, send)
            return

        content_length = self._content_length(scope)
        if content_length is not None and content_length > self._maximum_bytes:
            await self._send_too_large(scope, receive, send)
            return

        received_bytes = 0
        captured_messages: list[Message] = []
        while True:
            message = await receive()
            captured_messages.append(message)
            if message["type"] == "http.disconnect":
                break
            if message["type"] != "http.request":
                continue
            received_bytes += len(message.get("body", b""))
            if received_bytes > self._maximum_bytes:
                await self._send_too_large(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        message_index = 0

        async def replay_receive() -> Message:
            nonlocal message_index
            if message_index < len(captured_messages):
                message = captured_messages[message_index]
                message_index += 1
                return message
            return await receive()

        await self._app(scope, replay_receive, send)

    @staticmethod
    def _content_length(scope: Scope) -> int | None:
        for name, value in scope["headers"]:
            if name.lower() != b"content-length":
                continue
            try:
                parsed = int(value)
            except ValueError:
                return None
            return max(0, parsed)
        return None

    @staticmethod
    async def _send_too_large(
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        response = JSONResponse(
            {"detail": "authentication request body too large"},
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
            },
        )
        await response(scope, receive, send)


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Default-deny every control-plane route outside the exact public allowlist."""

    _PUBLIC_ENDPOINTS = frozenset(
        {
            ("GET", "/health"),
            ("GET", "/api/auth/status"),
            ("POST", "/api/auth/bootstrap"),
            ("POST", "/api/auth/login"),
        }
    )
    _SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
    _PUBLIC_UNSAFE_ENDPOINTS = frozenset(
        {
            ("POST", "/api/auth/bootstrap"),
            ("POST", "/api/auth/login"),
        }
    )

    def __init__(
        self,
        app: ASGIApp,
        *,
        service: AuthenticationService,
        trusted_origin: str,
    ) -> None:
        super().__init__(app)
        self._service = service
        self._trusted_origin = trusted_origin.rstrip("/")

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        endpoint = (request.method, request.url.path)
        is_authentication_endpoint = request.url.path.startswith("/api/auth/")
        is_protected_endpoint = endpoint not in self._PUBLIC_ENDPOINTS
        no_store = is_authentication_endpoint or is_protected_endpoint
        response: Response

        is_unsafe = request.method not in self._SAFE_METHODS
        if is_unsafe and request.headers.get("origin") != self._trusted_origin:
            response = JSONResponse(
                {"detail": "trusted origin required"},
                status_code=status.HTTP_403_FORBIDDEN,
            )
            return self._prevent_authentication_caching(
                response,
                enabled=no_store,
            )

        if endpoint in self._PUBLIC_ENDPOINTS:
            if endpoint in self._PUBLIC_UNSAFE_ENDPOINTS and not (
                self._service.verify_double_submit_csrf(
                    cookie_token=request.cookies.get(CSRF_COOKIE_NAME),
                    header_token=request.headers.get(CSRF_HEADER_NAME),
                )
            ):
                response = JSONResponse(
                    {"detail": "CSRF validation failed"},
                    status_code=status.HTTP_403_FORBIDDEN,
                )
                return self._prevent_authentication_caching(
                    response,
                    enabled=no_store,
                )
            response = await call_next(request)
            return self._prevent_authentication_caching(
                response,
                enabled=no_store,
            )

        authentication = await run_in_threadpool(
            self._service.authenticate,
            request.cookies.get(SESSION_COOKIE_NAME),
        )
        if authentication is None:
            response = JSONResponse(
                {"detail": "authentication required"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
            clear_authentication_cookies(response)
            return self._prevent_authentication_caching(
                response,
                enabled=no_store,
            )
        request.state.authenticated_session = authentication

        if is_unsafe and not self._service.verify_bound_csrf(
            authentication,
            cookie_token=request.cookies.get(CSRF_COOKIE_NAME),
            header_token=request.headers.get(CSRF_HEADER_NAME),
        ):
            response = JSONResponse(
                {"detail": "CSRF validation failed"},
                status_code=status.HTTP_403_FORBIDDEN,
            )
            return self._prevent_authentication_caching(
                response,
                enabled=no_store,
            )
        response = await call_next(request)
        return self._prevent_authentication_caching(
            response,
            enabled=no_store,
        )

    @staticmethod
    def _prevent_authentication_caching(
        response: Response,
        *,
        enabled: bool,
    ) -> Response:
        if enabled:
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response


def create_authentication_router(service: AuthenticationService) -> APIRouter:
    router = APIRouter(prefix="/api/auth", tags=["authentication"])

    @router.get("/status", response_model=BootstrapStatusResponse)
    def authentication_status(request: Request, response: Response) -> BootstrapStatus:
        current = service.authenticate(request.cookies.get(SESSION_COOKIE_NAME))
        csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)
        if current is None:
            _set_csrf_cookie(response, service.issue_preauthentication_csrf())
        elif not service.csrf_cookie_is_bound(current, csrf_cookie):
            try:
                _set_csrf_cookie(
                    response,
                    service.rotate_csrf(current),
                    expires=current.absolute_expires_at,
                )
            except InvalidCredentialsError:
                clear_authentication_cookies(response)
        return service.bootstrap_status()

    @router.post(
        "/bootstrap",
        response_model=SessionResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def bootstrap(payload: BootstrapRequest, response: Response) -> SessionResponse:
        try:
            issued = service.bootstrap(
                bootstrap_token=payload.bootstrap_token.get_secret_value(),
                password=payload.password.get_secret_value(),
            )
        except PasswordPolicyError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from None
        except BootstrapAlreadyCompletedError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from None
        except BootstrapUnavailableError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
            ) from None
        except InvalidBootstrapTokenError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="bootstrap authorization failed",
            ) from None
        _set_authenticated_cookies(response, issued)
        return _session_response(issued.authentication)

    @router.post("/login", response_model=SessionResponse)
    def login(
        request: Request,
        payload: PasswordRequest,
        response: Response,
    ) -> SessionResponse:
        try:
            issued = service.login(
                password=payload.password.get_secret_value(),
                existing_session_token=request.cookies.get(SESSION_COOKIE_NAME),
            )
        except InvalidCredentialsError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid credentials",
            ) from None
        _set_authenticated_cookies(response, issued)
        return _session_response(issued.authentication)

    @router.get("/session", response_model=SessionResponse)
    def current_session(
        request: Request,
        response: Response,
        authentication: Annotated[
            AuthenticatedSession,
            Depends(require_authenticated_session),
        ],
    ) -> SessionResponse:
        if not service.csrf_cookie_is_bound(
            authentication,
            request.cookies.get(CSRF_COOKIE_NAME),
        ):
            try:
                _set_csrf_cookie(
                    response,
                    service.rotate_csrf(authentication),
                    expires=authentication.absolute_expires_at,
                )
            except InvalidCredentialsError:
                clear_authentication_cookies(response)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="authentication required",
                ) from None
        return _session_response(authentication)

    @router.post("/reauthenticate", response_model=SessionResponse)
    def reauthenticate(
        payload: PasswordRequest,
        response: Response,
        authentication: Annotated[
            AuthenticatedSession,
            Depends(require_authenticated_session),
        ],
    ) -> SessionResponse:
        try:
            issued = service.reauthenticate(
                authentication,
                password=payload.password.get_secret_value(),
            )
        except InvalidCredentialsError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid credentials",
            ) from None
        _set_authenticated_cookies(response, issued)
        return _session_response(issued.authentication)

    @router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
    def logout(
        response: Response,
        authentication: Annotated[
            AuthenticatedSession,
            Depends(require_authenticated_session),
        ],
    ) -> None:
        service.logout(authentication)
        clear_authentication_cookies(response)

    return router


def bootstrap_token_main() -> None:
    """Generate or rotate the one-time bootstrap token and print it once."""

    settings = get_settings()
    engine = create_database_engine(settings.database_url)
    try:
        token = generate_bootstrap_token(create_session_factory(engine))
    except BootstrapAlreadyCompletedError as exc:
        raise SystemExit(str(exc)) from None
    finally:
        engine.dispose()
    print(token)
