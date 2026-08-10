"""Authenticated repository configuration and read-only preflight API."""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal, Protocol, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Response, status
from mathews_configuration import (
    HostOperation,
    HostRequestMessage,
    HostResponseMessage,
    HostResponseStatus,
    RepositoryHostAuthority,
)
from mathews_configuration import (
    RepositoryConfigurationError as SharedRepositoryConfigurationError,
)
from mathews_configuration.host_protocol import JsonValue
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.authentication import (
    AuthenticatedSession,
    require_authenticated_session,
)
from mathews_control_plane.database import LocalUser, SessionFactory
from mathews_control_plane.domain_models import (
    RepositoryConfiguration as RepositoryConfigurationRecord,
)
from mathews_control_plane.host_gateway import HostGatewayError
from mathews_control_plane.repository_configuration import (
    RepositoryConfigurationConflictError,
    RepositoryPreflightAttempt,
    RepositoryPreflightBindingError,
    RepositoryPreflightNotReadyError,
    begin_preflight_attempt,
    capture_preflight_report,
    clear_preflight_attempt,
    create_repository_configuration,
    get_latest_repository_configuration,
    get_repository_preflight_report,
    repository_configuration_digest,
    validated_repository_configuration,
)

ALLOWED_REPOSITORY_KEY = "boppuh/mathews"
MAX_REPOSITORY_BODY_BYTES = 512 * 1024
_MAX_REPOSITORY_BODY_CHUNKS = 4096
_OWNER_ID = "local-user"
_USER_ID = 1
_PREFLIGHT_LIFETIME = timedelta(seconds=30)

RepositoryKey = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        to_lower=True,
        min_length=3,
        max_length=140,
        pattern=r"^[a-z0-9](?:[a-z0-9-]{0,38})/[a-z0-9](?:[a-z0-9._-]{0,99})$",
    ),
]
Clock = Callable[[], datetime]
AuthenticatedRepositorySession = Annotated[
    AuthenticatedSession,
    Depends(require_authenticated_session),
]


class RepositoryHostGateway(Protocol):
    def execute(self, request: HostRequestMessage) -> HostResponseMessage: ...


class RepositoryUnavailableError(RuntimeError):
    """The single allowed repository has no configuration yet."""


class SecretReferenceUpdates(BaseModel):
    """Write-only opaque references. Omitted fields preserve current values."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    push_credential: str | None = Field(default=None, max_length=2048)
    e2e_test_account: str | None = Field(default=None, max_length=2048)
    additional: list[str] | None = Field(default=None, max_length=64)


class RepositoryConfigurationWriteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    repository_key: RepositoryKey
    expected_configuration_version: int | None = Field(default=None, ge=1)
    repository_settings: dict[str, object]
    git_settings: dict[str, object]
    xcode_settings: dict[str, object]
    operations: list[object] = Field(max_length=16)
    e2e_assertions: list[object] = Field(max_length=256)
    artifact_settings: dict[str, object]
    prohibited_paths: list[object] = Field(max_length=256)
    secret_updates: SecretReferenceUpdates = Field(default_factory=SecretReferenceUpdates)
    approve_sensitive_change: bool = False


class RepositorySecretStatus(BaseModel):
    push_credential_configured: bool
    e2e_test_account_configured: bool
    additional_reference_count: int = Field(ge=0)


class RepositoryConfigurationProjection(BaseModel):
    id: UUID
    repository_key: str
    version: int = Field(gt=0)
    digest: str
    created_at: datetime
    actor_id: str
    repository_settings: dict[str, object]
    git_settings: dict[str, object]
    xcode_settings: dict[str, object]
    operations: list[object]
    e2e_assertions: list[object]
    artifact_settings: dict[str, object]
    prohibited_paths: list[object]
    secrets: RepositorySecretStatus


class RepositoryPreflightCheckProjection(BaseModel):
    code: str
    status: Literal["PASSED", "BLOCKED"]
    detail_code: str


class RepositoryPreflightProjection(BaseModel):
    status: Literal["NOT_RUN", "RUNNING", "PASSED", "BLOCKED"]
    attempt_id: UUID | None = None
    configuration_id: UUID | None = None
    configuration_version: int | None = None
    configuration_digest: str | None = None
    resolved_base_sha: str | None = None
    checks: list[RepositoryPreflightCheckProjection] = Field(default_factory=list)


class RepositoryProjection(BaseModel):
    repository_key: str
    configured: bool
    mutation_blocked: bool
    configuration: RepositoryConfigurationProjection | None
    preflight: RepositoryPreflightProjection
    host_available: bool


class RepositoryService:
    """Own immutable configuration saves and exact-version preflight calls."""

    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        *,
        host_gateway: RepositoryHostGateway | None = None,
        clock: Clock | None = None,
        repository_key: str = ALLOWED_REPOSITORY_KEY,
    ) -> None:
        self._factory = factory
        self._artifact_store = artifact_store
        self._host_gateway = host_gateway
        self._clock = clock or (lambda: datetime.now(UTC))
        self._repository_key = repository_key

    def current(self, authentication: AuthenticatedSession) -> RepositoryProjection:
        self._principal(authentication)
        with self._factory() as session:
            configuration = get_latest_repository_configuration(session, self._repository_key)
            return self._projection(session, configuration)

    def create_version(
        self,
        body: RepositoryConfigurationWriteRequest,
        authentication: AuthenticatedSession,
    ) -> RepositoryProjection:
        actor_id = self._principal(authentication)
        if body.repository_key != self._repository_key:
            raise ValueError("only the configured repository may be changed")
        now = _as_utc(self._clock())
        if not body.approve_sensitive_change:
            raise PermissionError("explicit approval is required")
        if not (
            authentication.recent_password_verified
            and _as_utc(authentication.reauthenticated_until) > now
        ):
            raise PermissionError("recent password authentication is required")

        with self._factory() as session, session.begin():
            _lock_repository_writer(session)
            latest = get_latest_repository_configuration(
                session, self._repository_key, for_update=True
            )
            expected_version = body.expected_configuration_version
            if (latest is None and expected_version is not None) or (
                latest is not None and expected_version != latest.version
            ):
                raise RepositoryConfigurationConflictError(
                    "repository configuration changed; reload and try again"
                )
            materialized = _materialize_configuration(body, latest)
            root_id = uuid4()
            created = create_repository_configuration(
                session,
                repository_key=self._repository_key,
                repository_settings=cast(Mapping[str, object], materialized["repository_settings"]),
                git_settings=cast(Mapping[str, object], materialized["git_settings"]),
                xcode_settings=cast(Mapping[str, object], materialized["xcode_settings"]),
                operations=cast(list[object], materialized["operations"]),
                e2e_assertions=cast(list[object], materialized["e2e_assertions"]),
                artifact_settings=cast(Mapping[str, object], materialized["artifact_settings"]),
                prohibited_paths=cast(list[object], materialized["prohibited_paths"]),
                secret_references=cast(list[object], materialized["secret_references"]),
                owner_id=_OWNER_ID,
                actor_id=actor_id,
                root_correlation_id=root_id,
            )
            return self._projection(session, created)

    def preflight(self, authentication: AuthenticatedSession) -> RepositoryProjection:
        actor_id = self._principal(authentication)
        if self._host_gateway is None:
            raise HostGatewayError("HOST_UNAVAILABLE")
        now = _as_utc(self._clock())
        root_id = uuid4()
        with self._factory() as session, session.begin():
            configuration = get_latest_repository_configuration(session, self._repository_key)
            if configuration is None:
                raise RepositoryUnavailableError("repository configuration is unavailable")
            attempt = begin_preflight_attempt(
                session,
                self._artifact_store,
                configuration_id=configuration.id,
                owner_id=_OWNER_ID,
                actor_id=actor_id,
                root_correlation_id=root_id,
                requested_at=now,
            )
            validated = validated_repository_configuration(configuration)

        issued_at_ms = int(now.timestamp() * 1000)
        request = HostRequestMessage(
            request_id=uuid4(),
            issued_at_ms=issued_at_ms,
            expires_at_ms=int((now + _PREFLIGHT_LIFETIME).timestamp() * 1000),
            authority=RepositoryHostAuthority(
                repository_key=attempt.repository_key,
                configuration_id=attempt.configuration_id,
                configuration_digest=attempt.configuration_digest,
            ),
            operation=HostOperation(
                name="repository.preflight",
                idempotency_key=f"repository-preflight:{attempt.attempt_id}",
                arguments=cast(
                    dict[str, JsonValue],
                    {
                        "attempt_id": str(attempt.attempt_id),
                        "configuration": validated.to_dict(),
                    },
                ),
            ),
        )
        try:
            response = self._host_gateway.execute(request)
            if response.status is not HostResponseStatus.OK:
                raise HostGatewayError("HOST_REJECTED_PREFLIGHT")
        except HostGatewayError:
            self._clear_failed_preflight(attempt)
            raise

        try:
            with self._factory() as session, session.begin():
                capture_preflight_report(
                    session,
                    self._artifact_store,
                    report=cast(Mapping[str, object], response.result),
                    owner_id=_OWNER_ID,
                    actor_id=actor_id,
                    root_correlation_id=root_id,
                    captured_at=_as_utc(self._clock()),
                    causation_id=request.request_id,
                )
                configuration = get_latest_repository_configuration(session, self._repository_key)
                return self._projection(session, configuration)
        except RepositoryPreflightBindingError:
            self._clear_failed_preflight(attempt)
            raise

    def _clear_failed_preflight(self, attempt: RepositoryPreflightAttempt) -> None:
        with self._factory() as session, session.begin():
            clear_preflight_attempt(
                session,
                self._artifact_store,
                attempt=attempt,
            )

    def _projection(
        self,
        session: Session,
        configuration: RepositoryConfigurationRecord | None,
    ) -> RepositoryProjection:
        if configuration is None:
            return RepositoryProjection(
                repository_key=self._repository_key,
                configured=False,
                mutation_blocked=True,
                configuration=None,
                preflight=RepositoryPreflightProjection(status="NOT_RUN"),
                host_available=self._host_gateway is not None,
            )
        try:
            report = get_repository_preflight_report(session, self._artifact_store, configuration)
            if report is None:
                preflight = RepositoryPreflightProjection(
                    status=(
                        "RUNNING" if configuration.preflight_evidence_id is not None else "NOT_RUN"
                    )
                )
            else:
                preflight = RepositoryPreflightProjection(
                    status=report.status.value,
                    attempt_id=report.attempt_id,
                    configuration_id=report.configuration_id,
                    configuration_version=report.configuration_version,
                    configuration_digest=report.configuration_digest,
                    resolved_base_sha=report.resolved_base_sha,
                    checks=[
                        RepositoryPreflightCheckProjection(
                            code=check.code.value,
                            status=check.status.value,
                            detail_code=check.detail_code,
                        )
                        for check in report.checks
                    ],
                )
        except RepositoryPreflightNotReadyError:
            preflight = RepositoryPreflightProjection(status="BLOCKED")
        projection = _configuration_projection(configuration)
        return RepositoryProjection(
            repository_key=self._repository_key,
            configured=True,
            mutation_blocked=preflight.status != "PASSED",
            configuration=projection,
            preflight=preflight,
            host_available=self._host_gateway is not None,
        )

    @staticmethod
    def _principal(authentication: AuthenticatedSession) -> str:
        if authentication.user_id != _USER_ID:
            raise PermissionError("repository configuration is unavailable")
        return _OWNER_ID


def _materialize_configuration(
    body: RepositoryConfigurationWriteRequest,
    latest: RepositoryConfigurationRecord | None,
) -> dict[str, object]:
    repository_settings = copy.deepcopy(body.repository_settings)
    git_settings = copy.deepcopy(body.git_settings)
    xcode_settings = copy.deepcopy(body.xcode_settings)
    operations = copy.deepcopy(body.operations)
    e2e_assertions = copy.deepcopy(body.e2e_assertions)
    artifact_settings = copy.deepcopy(body.artifact_settings)
    prohibited_paths = copy.deepcopy(body.prohibited_paths)

    if "push_credential" in git_settings:
        raise ValueError("push credential must use the write-only secret field")
    previous_push = None if latest is None else latest.git_settings.get("push_credential")
    git_settings["push_credential"] = (
        body.secret_updates.push_credential
        if body.secret_updates.push_credential is not None
        else previous_push
    )

    previous_account = _e2e_test_account(latest.operations) if latest is not None else None
    for operation in operations:
        if not isinstance(operation, dict):
            continue
        flow = operation.get("e2e_flow")
        if not isinstance(flow, dict):
            continue
        if "test_account" in flow:
            raise ValueError("E2E account must use the write-only secret field")
        flow["test_account"] = (
            body.secret_updates.e2e_test_account
            if body.secret_updates.e2e_test_account is not None
            else previous_account
        )

    additional = (
        copy.deepcopy(body.secret_updates.additional)
        if body.secret_updates.additional is not None
        else copy.deepcopy(latest.secret_references if latest is not None else [])
    )
    previous_designated = {
        value for value in (previous_push, previous_account) if isinstance(value, str)
    }
    secret_references = [
        reference
        for reference in additional
        if not isinstance(reference, str) or reference not in previous_designated
    ]
    for reference in (git_settings["push_credential"], _e2e_test_account(operations)):
        if isinstance(reference, str) and reference not in secret_references:
            secret_references.append(reference)
    return {
        "repository_settings": repository_settings,
        "git_settings": git_settings,
        "xcode_settings": xcode_settings,
        "operations": operations,
        "e2e_assertions": e2e_assertions,
        "artifact_settings": artifact_settings,
        "prohibited_paths": prohibited_paths,
        "secret_references": secret_references,
    }


def _lock_repository_writer(session: Session) -> None:
    """Serialize all version writers, including the first configuration insert."""

    if session.get_bind().dialect.name == "sqlite":
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")
    owner = session.get(LocalUser, _USER_ID, with_for_update=True)
    if owner is None:
        raise PermissionError("repository configuration is unavailable")


def _configuration_projection(
    configuration: RepositoryConfigurationRecord,
) -> RepositoryConfigurationProjection:
    git_settings = copy.deepcopy(configuration.git_settings)
    push_configured = bool(git_settings.pop("push_credential", None))
    operations = copy.deepcopy(configuration.operations)
    e2e_configured = False
    for operation in operations:
        if not isinstance(operation, dict):
            continue
        flow = operation.get("e2e_flow")
        if isinstance(flow, dict):
            e2e_configured = bool(flow.pop("test_account", None)) or e2e_configured
    designated_references = {
        reference
        for reference in (
            configuration.git_settings.get("push_credential"),
            _e2e_test_account(configuration.operations),
        )
        if isinstance(reference, str)
    }
    additional_reference_count = sum(
        1
        for reference in configuration.secret_references
        if not isinstance(reference, str) or reference not in designated_references
    )
    return RepositoryConfigurationProjection(
        id=configuration.id,
        repository_key=configuration.repository_key,
        version=configuration.version,
        digest=repository_configuration_digest(configuration),
        created_at=configuration.created_at,
        actor_id=configuration.actor_id,
        repository_settings=copy.deepcopy(configuration.repository_settings),
        git_settings=git_settings,
        xcode_settings=copy.deepcopy(configuration.xcode_settings),
        operations=operations,
        e2e_assertions=copy.deepcopy(configuration.e2e_assertions),
        artifact_settings=copy.deepcopy(configuration.artifact_settings),
        prohibited_paths=copy.deepcopy(configuration.prohibited_paths),
        secrets=RepositorySecretStatus(
            push_credential_configured=push_configured,
            e2e_test_account_configured=e2e_configured,
            additional_reference_count=additional_reference_count,
        ),
    )


def _e2e_test_account(operations: list[object]) -> object:
    for operation in operations:
        if isinstance(operation, dict) and isinstance(operation.get("e2e_flow"), dict):
            return cast(dict[str, object], operation["e2e_flow"]).get("test_account")
    return None


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def create_repository_router(service: RepositoryService) -> APIRouter:
    router = APIRouter(prefix="/api/repository", tags=["repository"])

    @router.get("", response_model=RepositoryProjection)
    async def current(
        authentication: AuthenticatedRepositorySession,
        response: Response,
    ) -> RepositoryProjection:
        response.headers["Cache-Control"] = "no-store"
        try:
            return await run_in_threadpool(service.current, authentication)
        except PermissionError:
            raise HTTPException(status_code=404, detail="repository is unavailable") from None

    @router.post("/versions", response_model=RepositoryProjection, status_code=201)
    async def create_version(
        body: RepositoryConfigurationWriteRequest,
        authentication: AuthenticatedRepositorySession,
        response: Response,
    ) -> RepositoryProjection:
        response.headers["Cache-Control"] = "no-store"
        try:
            return await run_in_threadpool(service.create_version, body, authentication)
        except PermissionError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="recent password authentication and explicit approval are required",
            ) from None
        except RepositoryConfigurationConflictError:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="repository configuration changed; reload and try again",
            ) from None
        except (ValueError, SharedRepositoryConfigurationError):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="repository configuration is invalid",
            ) from None

    @router.post("/preflights", response_model=RepositoryProjection)
    async def preflight(
        authentication: AuthenticatedRepositorySession,
        response: Response,
    ) -> RepositoryProjection:
        response.headers["Cache-Control"] = "no-store"
        try:
            return await run_in_threadpool(service.preflight, authentication)
        except RepositoryUnavailableError:
            raise HTTPException(status_code=409, detail="configure the repository first") from None
        except (HostGatewayError, RepositoryPreflightBindingError):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="repository preflight is unavailable",
            ) from None

    return router


class RepositoryBodyLimitMiddleware:
    """Reject oversized repository writes before request decoding."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope.get("method") != "POST"
            or not str(scope.get("path", "")).startswith("/api/repository/")
        ):
            await self._app(scope, receive, send)
            return
        content_length = self._content_length(scope)
        if content_length is not None and content_length > MAX_REPOSITORY_BODY_BYTES:
            await self._send_too_large(scope, receive, send)
            return

        received_bytes = 0
        received_chunks = 0
        captured_messages: list[Message] = []
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                captured_messages.append(message)
                break
            if message["type"] != "http.request":
                captured_messages.append(message)
                continue
            received_chunks += 1
            if received_chunks > _MAX_REPOSITORY_BODY_CHUNKS:
                await self._send_too_large(scope, receive, send)
                return
            captured_messages.append(message)
            received_bytes += len(message.get("body", b""))
            if received_bytes > MAX_REPOSITORY_BODY_BYTES:
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
    async def _send_too_large(scope: Scope, receive: Receive, send: Send) -> None:
        response = JSONResponse(
            {"detail": "repository request body too large"},
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )
        await response(scope, receive, send)
