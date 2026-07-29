import argparse
import logging
import platform
import time
from dataclasses import asdict, dataclass

from mathews_host_agent import __version__

logger = logging.getLogger("mathews.host_agent")


@dataclass(frozen=True)
class HostAgentProbe:
    platform: str
    service: str = "host-agent"
    status: str = "ok"
    version: str = __version__


def probe() -> dict[str, str]:
    return asdict(HostAgentProbe(platform=platform.system().lower()))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Mathews macOS host agent")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Print one health probe and exit",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    logger.info("host agent started", extra=probe())
    if args.once:
        logger.info(probe())
        return

    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        logger.info("host agent stopped")


if __name__ == "__main__":
    main()
