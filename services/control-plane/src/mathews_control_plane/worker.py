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
from mathews_control_plane.database import (
    create_database_engine,
    create_session_factory,
)
from mathews_control_plane.domain_models import ReconciliationTargetKind
from mathews_control_plane.reliability import (
    OwnedProcessTerminator,
    OwnedWorkspaceCleaner,
    ReconciliationAdapter,
    StartupRecoveryResult,
    StartupRecoveryService,
)
from mathews_control_plane.settings import Settings, settings

logger = logging.getLogger("mathews.worker")


def probe() -> str:
    """Return a side-effect-free worker identity for startup diagnostics."""

    return f"worker:{__version__}:{settings.environment}"


def build_worker(
    runtime_settings: Settings,
    *,
    handlers: dict[str, BackgroundJobHandler] | None = None,
) -> tuple[DurableJobWorker, Engine]:
    """Build one database-backed worker and return its disposable engine."""

    handler_registry = {} if handlers is None else dict(handlers)
    if not handler_registry:
        logger.warning("worker has no registered handlers; durable polling will remain idle")
    engine = create_database_engine(runtime_settings.database_url)
    service = BackgroundJobService(
        create_session_factory(engine),
        ArtifactStore(runtime_settings.artifact_root),
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
) -> StartupRecoveryResult:
    """Reconcile durable external state before the worker may claim work."""

    return StartupRecoveryService(
        create_session_factory(engine),
        ArtifactStore(runtime_settings.artifact_root),
    ).recover(
        adapters=adapters,
        terminator=terminator,
        cleaner=cleaner,
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
    worker, engine = build_worker(settings)
    try:
        recovery = recover_worker_startup(settings, engine)
        logger.info(
            "worker startup recovery completed",
            extra={
                "completed_cancellations": len(
                    recovery.completed_cancellation_ids
                ),
                "escalated_jobs": len(recovery.escalated_job_ids),
                "reconciled_targets": len(
                    recovery.reconciled_target_ids
                ),
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
