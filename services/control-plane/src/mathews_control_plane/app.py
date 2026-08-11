import asyncio
import logging
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager, suppress
from datetime import timedelta
from typing import Literal

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

from mathews_control_plane import __version__
from mathews_control_plane.approvals import (
    ApprovalBodyLimitMiddleware,
    ApprovalService,
    create_approval_router,
)
from mathews_control_plane.artifacts import ArtifactStore
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
from mathews_control_plane.domain_models import ReconciliationTargetKind
from mathews_control_plane.evidence import (
    EvidenceBodyLimitMiddleware,
    EvidenceService,
    create_evidence_router,
)
from mathews_control_plane.evidence_projections import (
    EvidenceProjectionService,
    create_evidence_projection_router,
)
from mathews_control_plane.github_app import (
    GitHubWebhookVerifier,
    build_github_app_configuration,
)
from mathews_control_plane.github_webhooks import (
    GitHubWebhookBodyLimitMiddleware,
    GitHubWebhookService,
    create_github_webhook_router,
)
from mathews_control_plane.hermes_adapter import KeychainSecretProvider
from mathews_control_plane.host_gateway import (
    HostGatewayError,
    configured_local_host_gateway,
)
from mathews_control_plane.reliability import (
    OwnedProcessTerminator,
    OwnedWorkspaceCleaner,
    ReconciliationAdapter,
    StartupRecoveryService,
)
from mathews_control_plane.repositories import (
    ALLOWED_REPOSITORY_KEY,
    RepositoryBodyLimitMiddleware,
    RepositoryService,
    create_repository_router,
)
from mathews_control_plane.retrieval_index import (
    RetrievalIndexService,
    create_retrieval_index_router,
)
from mathews_control_plane.settings import Settings, settings
from mathews_control_plane.tasks import (
    TaskBodyLimitMiddleware,
    TaskService,
    create_task_router,
)
from mathews_control_plane.validation_decisioning import (
    ValidationDecisionService,
    create_validation_decision_router,
)
from mathews_control_plane.validation_evidence import (
    ValidationEvidenceBodyLimitMiddleware,
    ValidationEvidenceJobScheduler,
    create_validation_evidence_router,
)

_LOGGER = logging.getLogger(__name__)


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
    evidence_service: EvidenceService | None = None,
    evidence_projection_service: EvidenceProjectionService | None = None,
    retrieval_index_service: RetrievalIndexService | None = None,
    task_service: TaskService | None = None,
    approval_service: ApprovalService | None = None,
    repository_service: RepositoryService | None = None,
    validation_evidence_scheduler: ValidationEvidenceJobScheduler | None = None,
    validation_decision_service: ValidationDecisionService | None = None,
    github_webhook_service: GitHubWebhookService | None = None,
    startup_recovery_service: StartupRecoveryService | None = None,
    startup_recovery_adapters: Mapping[
        ReconciliationTargetKind,
        ReconciliationAdapter,
    ]
    | None = None,
    startup_process_terminator: OwnedProcessTerminator | None = None,
    startup_workspace_cleaner: OwnedWorkspaceCleaner | None = None,
) -> FastAPI:
    """Create a default-deny API with an injectable persistence boundary."""

    database_engine = None
    if session_factory is None:
        database_engine = create_database_engine(current_settings.database_url)
        session_factory = create_session_factory(database_engine)
    if authentication_service is None:
        authentication_service = AuthenticationService(
            session_factory,
            idle_ttl=timedelta(seconds=current_settings.auth_session_idle_ttl_seconds),
            absolute_ttl=timedelta(seconds=current_settings.auth_session_absolute_ttl_seconds),
            reauthentication_ttl=timedelta(
                seconds=current_settings.auth_reauthentication_ttl_seconds
            ),
        )
    artifact_store = ArtifactStore.from_settings(current_settings)
    if evidence_service is None:
        evidence_service = EvidenceService(
            session_factory,
            artifact_store,
        )
    if evidence_projection_service is None:
        evidence_projection_service = EvidenceProjectionService(
            session_factory,
            artifact_store,
        )
    if retrieval_index_service is None:
        retrieval_index_service = RetrievalIndexService(
            session_factory,
            artifact_store,
            evidence_projection_service,
        )
    if task_service is None:
        task_service = TaskService(
            session_factory,
            artifact_store,
        )
    if approval_service is None:
        approval_service = ApprovalService(
            session_factory,
            artifact_store,
        )
    if repository_service is None:
        host_gateway = None
        if current_settings.automation_ready:
            try:
                host_gateway = configured_local_host_gateway(
                    current_settings.require_automation_configuration(),
                    secrets=KeychainSecretProvider(),
                )
            except HostGatewayError as error:
                _LOGGER.warning(
                    "repository host gateway is unavailable",
                    extra={"host_gateway_code": error.code},
                )
                host_gateway = None
        repository_service = RepositoryService(
            session_factory,
            artifact_store,
            host_gateway=host_gateway,
        )
    if validation_evidence_scheduler is None:
        validation_evidence_scheduler = ValidationEvidenceJobScheduler(
            session_factory,
            artifact_store,
        )
    if validation_decision_service is None:
        validation_decision_service = ValidationDecisionService(
            session_factory,
            artifact_store,
        )
    if startup_recovery_service is None:
        startup_recovery_service = StartupRecoveryService(
            session_factory,
            artifact_store,
        )
    if github_webhook_service is None and current_settings.automation_ready:
        github_configuration = build_github_app_configuration(
            current_settings.require_automation_configuration(),
            repository_key=ALLOWED_REPOSITORY_KEY,
        )
        github_webhook_service = GitHubWebhookService(
            session_factory,
            artifact_store,
            github_configuration,
            verifier=GitHubWebhookVerifier(
                github_configuration,
                secret_provider=KeychainSecretProvider(),
            ),
        )

    @asynccontextmanager
    async def lifespan(_application: FastAPI) -> AsyncIterator[None]:
        webhook_drain_task: asyncio.Task[None] | None = None
        if github_webhook_service is not None:
            webhook_batch_size = 100
            for _pass in range(10):
                processed = await run_in_threadpool(
                    github_webhook_service.process_pending,
                    limit=webhook_batch_size,
                )
                if processed < webhook_batch_size:
                    break
            else:
                _LOGGER.warning("github webhook backlog remains after startup drain")

            async def drain_github_webhooks() -> None:
                while True:
                    processed = await run_in_threadpool(
                        github_webhook_service.process_pending,
                        limit=webhook_batch_size,
                    )
                    await asyncio.sleep(0 if processed == webhook_batch_size else 1)

            webhook_drain_task = asyncio.create_task(drain_github_webhooks())
        approval_batch_size = 100
        while (
            len(
                await run_in_threadpool(
                    approval_service.expire_due,
                    limit=approval_batch_size,
                )
            )
            == approval_batch_size
        ):
            pass
        # Read and reconcile every durable external boundary before any worker
        # may issue a new effect after restart.
        await run_in_threadpool(
            startup_recovery_service.recover,
            adapters=startup_recovery_adapters,
            terminator=startup_process_terminator,
            cleaner=startup_workspace_cleaner,
        )
        # A committed deletion request is an unreadable durable fence. Resume
        # bounded physical cleanup before accepting traffic after any restart.
        batch_size = 100
        while (
            await run_in_threadpool(
                evidence_service.resume_pending_deletions,
                limit=batch_size,
            )
            == batch_size
        ):
            pass
        try:
            yield
        finally:
            if webhook_drain_task is not None:
                webhook_drain_task.cancel()
                with suppress(asyncio.CancelledError):
                    await webhook_drain_task

    application = FastAPI(
        title="Mathews control plane",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    if database_engine is not None:
        application.state.database_engine = database_engine
    application.state.authentication_service = authentication_service
    application.state.evidence_service = evidence_service
    application.state.evidence_projection_service = evidence_projection_service
    application.state.retrieval_index_service = retrieval_index_service
    application.state.task_service = task_service
    application.state.approval_service = approval_service
    application.state.repository_service = repository_service
    application.state.validation_evidence_scheduler = validation_evidence_scheduler
    application.state.validation_decision_service = validation_decision_service
    application.state.github_webhook_service = github_webhook_service
    application.state.startup_recovery_service = startup_recovery_service
    application.include_router(create_authentication_router(authentication_service))
    application.include_router(
        create_evidence_projection_router(evidence_projection_service)
    )
    application.include_router(create_retrieval_index_router(retrieval_index_service))
    application.include_router(create_evidence_router(evidence_service))
    application.include_router(create_task_router(task_service))
    application.include_router(create_approval_router(approval_service))
    application.include_router(create_repository_router(repository_service))
    application.include_router(
        create_validation_evidence_router(validation_evidence_scheduler)
    )
    application.include_router(
        create_validation_decision_router(validation_decision_service)
    )
    if github_webhook_service is not None:
        application.include_router(create_github_webhook_router(github_webhook_service))

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
    application.add_middleware(EvidenceBodyLimitMiddleware)
    application.add_middleware(TaskBodyLimitMiddleware)
    application.add_middleware(ApprovalBodyLimitMiddleware)
    application.add_middleware(RepositoryBodyLimitMiddleware)
    application.add_middleware(ValidationEvidenceBodyLimitMiddleware)
    application.add_middleware(GitHubWebhookBodyLimitMiddleware)
    # CORS is the outer layer so even authentication failures carry the exact
    # trusted-origin response headers expected by browser clients.
    application.add_middleware(
        CORSMiddleware,
        allow_credentials=True,
        allow_headers=["Content-Type", CSRF_HEADER_NAME, "Last-Event-ID"],
        allow_methods=["DELETE", "GET", "POST", "OPTIONS"],
        allow_origins=[str(current_settings.web_origin).rstrip("/")],
    )
    return application


app = create_app(settings)
