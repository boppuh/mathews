import argparse
import logging
import os
import time
from collections.abc import Mapping

from sqlalchemy import Engine

from mathews_control_plane import __version__
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.background_jobs import (
    BackgroundJobHandler,
    BackgroundJobService,
    DurableJobWorker,
    WorkerRunOutcome,
)
from mathews_control_plane.code_change_execution import (
    HostGateway,
    ScopedCodeExecutionService,
)
from mathews_control_plane.database import (
    create_database_engine,
    create_session_factory,
)
from mathews_control_plane.domain_models import ReconciliationTargetKind
from mathews_control_plane.github_webhooks import GitHubWebhookJobHandler
from mathews_control_plane.hermes_adapter import (
    HermesHttpRuntime,
    HermesRunJobHandler,
    HermesRuntime,
    KeychainSecretProvider,
    UnavailableHermesRuntime,
)
from mathews_control_plane.host_gateway import configured_local_host_gateway
from mathews_control_plane.reliability import (
    OwnedProcessTerminator,
    OwnedWorkspaceCleaner,
    ReconciliationAdapter,
    StartupRecoveryResult,
    StartupRecoveryService,
)
from mathews_control_plane.settings import Settings, settings
from mathews_control_plane.validation_evidence import (
    VALIDATION_EVIDENCE_JOB_TYPE,
    ValidationEvidenceJobHandler,
)

logger = logging.getLogger("mathews.worker")


def probe() -> str:
    """Return a side-effect-free worker identity for startup diagnostics."""

    return f"worker:{__version__}:{settings.environment}"


def build_worker(
    runtime_settings: Settings,
    *,
    handlers: dict[str, BackgroundJobHandler] | None = None,
    hermes_runtime: HermesRuntime | None = None,
    host_gateway: HostGateway | None = None,
) -> tuple[DurableJobWorker, Engine]:
    """Build one database-backed worker and return its disposable engine."""

    engine = create_database_engine(runtime_settings.database_url)
    factory = create_session_factory(engine)
    store = ArtifactStore(runtime_settings.artifact_root)
    if handlers is None:
        runtime = hermes_runtime or configured_hermes_runtime(runtime_settings)
        gateway = host_gateway
        if gateway is None and runtime_settings.automation_ready:
            gateway = configured_local_host_gateway(
                runtime_settings.require_automation_configuration(),
                secrets=KeychainSecretProvider(),
            )
        tool_execution = (
            None if gateway is None else ScopedCodeExecutionService(factory, store, gateway)
        )
        handler_registry: dict[str, BackgroundJobHandler] = {
            "hermes-run": HermesRunJobHandler(
                factory,
                store,
                runtime,
                tool_execution,
            ),
            "github-webhook": GitHubWebhookJobHandler(),
        }
        if gateway is not None:
            handler_registry[VALIDATION_EVIDENCE_JOB_TYPE] = ValidationEvidenceJobHandler(
                factory,
                store,
                gateway,
            )
    else:
        handler_registry = dict(handlers)
    if not handler_registry:
        logger.warning("worker has no registered handlers; durable polling will remain idle")
    service = BackgroundJobService(
        factory,
        store,
    )
    worker = DurableJobWorker(
        service,
        handler_registry,
        worker_id=f"mathews-worker:{os.getpid()}",
    )
    return worker, engine


def _poll_delay(outcome: WorkerRunOutcome) -> float | None:
    if outcome is WorkerRunOutcome.IDLE:
        return 1
    if outcome in {
        WorkerRunOutcome.FAILED,
        WorkerRunOutcome.LEASE_LOST,
        WorkerRunOutcome.RETRY_SCHEDULED,
    }:
        return 0.5
    return None


def recover_worker_startup(
    runtime_settings: Settings,
    engine: Engine,
    *,
    adapters: Mapping[
        ReconciliationTargetKind,
        ReconciliationAdapter,
    ]
    | None = None,
    terminator: OwnedProcessTerminator | None = None,
    cleaner: OwnedWorkspaceCleaner | None = None,
    hermes_runtime: HermesRuntime | None = None,
) -> StartupRecoveryResult:
    """Reconcile durable external state before the worker may claim work."""

    configured_adapters = {} if adapters is None else dict(adapters)
    if hermes_runtime is not None:
        configured_adapters.setdefault(
            ReconciliationTargetKind.HERMES_RUN,
            hermes_runtime,
        )
    return StartupRecoveryService(
        create_session_factory(engine),
        ArtifactStore(runtime_settings.artifact_root),
    ).recover(
        adapters=configured_adapters,
        terminator=terminator,
        cleaner=cleaner,
    )


def configured_hermes_runtime(runtime_settings: Settings) -> HermesRuntime:
    """Build the production Hermes boundary or a bounded fail-closed substitute."""

    if runtime_settings.hermes_endpoint is None or runtime_settings.hermes_api_key_ref is None:
        return UnavailableHermesRuntime()
    return HermesHttpRuntime(
        str(runtime_settings.hermes_endpoint),
        runtime_settings.hermes_api_key_ref,
        secrets=KeychainSecretProvider(),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Mathews control-plane worker")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--once",
        action="store_true",
        help="Run one startup probe and exit",
    )
    mode.add_argument(
        "--poll-once",
        action="store_true",
        help="Execute one durable job poll and exit",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    logger.info("worker started", extra={"environment": settings.environment})
    if args.once:
        logger.info(probe())
        return
    hermes_runtime = configured_hermes_runtime(settings)
    worker, engine = build_worker(settings, hermes_runtime=hermes_runtime)
    try:
        recovery = recover_worker_startup(
            settings,
            engine,
            hermes_runtime=hermes_runtime,
        )
        logger.info(
            "worker startup recovery completed",
            extra={
                "completed_cancellations": len(recovery.completed_cancellation_ids),
                "escalated_jobs": len(recovery.escalated_job_ids),
                "reconciled_targets": len(recovery.reconciled_target_ids),
                "recovered_jobs": len(recovery.recovered_job_ids),
                "resolved_outages": len(recovery.resolved_outage_ids),
            },
        )
        if args.poll_once:
            logger.info("worker poll completed", extra={"outcome": worker.run_once()})
            return
        while True:
            outcome = worker.run_once()
            delay = _poll_delay(outcome)
            if delay is not None:
                time.sleep(delay)
    except KeyboardInterrupt:
        logger.info("worker stopped")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
