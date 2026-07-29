import argparse
import logging
import time

from mathews_control_plane import __version__
from mathews_control_plane.settings import settings

logger = logging.getLogger("mathews.worker")


def run_once() -> str:
    return f"worker:{__version__}:{settings.environment}"


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
    if args.once:
        logger.info(run_once())
        return

    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        logger.info("worker stopped")


if __name__ == "__main__":
    main()
