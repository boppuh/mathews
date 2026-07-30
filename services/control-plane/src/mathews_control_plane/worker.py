import argparse
import logging
import os
import time

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

    engine = create_database_engine(runtime_settings.database_url)
    service = BackgroundJobService(
        create_session_factory(engine),
        ArtifactStore(runtime_settings.artifact_root),
    )
    worker = DurableJobWorker(
        service,
        handlers or {},
        worker_id=f"mathews-worker:{os.getpid()}",
    )
    return worker, engine


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Mathews control-plane worker")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one startup probe and exit",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    logger.info("worker started", extra={"environment": settings.environment})
    worker, engine = build_worker(settings)
    try:
        if args.once:
            logger.info("worker poll completed", extra={"outcome": worker.run_once()})
            return
        while True:
            outcome = worker.run_once()
            if outcome is WorkerRunOutcome.IDLE:
                time.sleep(1)
    except KeyboardInterrupt:
        logger.info("worker stopped")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
