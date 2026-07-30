from datetime import timedelta
from typing import Literal

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.responses import JSONResponse

from mathews_control_plane import __version__
from mathews_control_plane.authentication import (
    CSRF_HEADER_NAME,
    AuthenticationBodyLimitMiddleware,
    AuthenticationMiddleware,
    AuthenticationService,
    create_authentication_router,
)
from mathews_control_plane.database import (
    SessionFactory,
    create_database_engine,
    create_session_factory,
)
from mathews_control_plane.settings import Settings, settings


class HealthResponse(BaseModel):
    service: Literal["api"]
    status: Literal["ok"]
    version: str
    environment: str
    configuration_ready: bool


def create_app(
    current_settings: Settings,
    *,
    session_factory: SessionFactory | None = None,
    authentication_service: AuthenticationService | None = None,
) -> FastAPI:
    """Create a default-deny API with an injectable persistence boundary."""

    application = FastAPI(
        title="Mathews control plane",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    if authentication_service is None:
        if session_factory is None:
            database_engine = create_database_engine(current_settings.database_url)
            session_factory = create_session_factory(database_engine)
            application.state.database_engine = database_engine
        authentication_service = AuthenticationService(
            session_factory,
            idle_ttl=timedelta(
                seconds=current_settings.auth_session_idle_ttl_seconds
            ),
            absolute_ttl=timedelta(
                seconds=current_settings.auth_session_absolute_ttl_seconds
            ),
            reauthentication_ttl=timedelta(
                seconds=current_settings.auth_reauthentication_ttl_seconds
            ),
        )

    application.state.authentication_service = authentication_service
    application.include_router(create_authentication_router(authentication_service))

    @application.exception_handler(RequestValidationError)
    async def sanitized_validation_error(
        _request: Request,
        _error: RequestValidationError,
    ) -> JSONResponse:
        # Request-validation details may embed rejected values. Authentication
        # bodies contain secrets, so all API validation failures use a fixed body.
        return JSONResponse(
            {"detail": "invalid request"},
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    @application.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(
            service="api",
            status="ok",
            version=__version__,
            environment=current_settings.environment,
            configuration_ready=current_settings.automation_ready,
        )

    application.add_middleware(
        AuthenticationMiddleware,
        service=authentication_service,
        trusted_origin=str(current_settings.web_origin),
    )
    application.add_middleware(AuthenticationBodyLimitMiddleware)
    # CORS is the outer layer so even authentication failures carry the exact
    # trusted-origin response headers expected by browser clients.
    application.add_middleware(
        CORSMiddleware,
        allow_credentials=True,
        allow_headers=["Content-Type", CSRF_HEADER_NAME],
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_origins=[str(current_settings.web_origin).rstrip("/")],
    )
    return application


app = create_app(settings)
