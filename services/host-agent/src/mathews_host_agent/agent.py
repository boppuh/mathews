"""Process entry point for the launchd-managed macOS host agent."""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import signal
import threading
from contextlib import closing
from dataclasses import asdict, dataclass
from pathlib import Path

from mathews_configuration import SecretReference, SecretReferenceError
from mathews_configuration.host_protocol import (
    HostMessageAuthenticator,
    HostProtocolError,
    validate_host_identifier,
)

from mathews_host_agent import __version__
from mathews_host_agent.dispatch import HostRequestDispatcher, default_operation_registry
from mathews_host_agent.journal import HostJournalError, HostOperationJournal
from mathews_host_agent.launchd import (
    LaunchdConfigurationError,
    activated_listener,
)
from mathews_host_agent.secrets import KeychainProviderError, KeychainSecretProvider
from mathews_host_agent.server import HostServerError, HostSocketServer, LocalSocketBinding
from mathews_host_agent.workspaces import GitWorkspaceLifecycle

logger = logging.getLogger("mathews.host_agent")
_DEFAULT_AUTH_REFERENCE = "keychain://com.boppuh.mathews.host-agent/control-plane-hmac-v1"


@dataclass(frozen=True)
class HostAgentProbe:
    platform: str
    service: str = "host-agent"
    status: str = "ok"
    version: str = __version__


@dataclass(frozen=True, slots=True)
class HostAgentSettings:
    socket_path: Path
    journal_path: Path
    authentication_reference: SecretReference
    authentication_key_id: str
    host_id: str
    launchd_socket: bool

    def __post_init__(self) -> None:
        validate_host_identifier(self.host_id)


def probe() -> dict[str, str]:
    return asdict(HostAgentProbe(platform=platform.system().lower()))


def run(settings: HostAgentSettings) -> None:
    """Resolve the host credential and serve until launchd stops the process."""

    if _running_as_root():
        raise HostServerError("host agent must run as a non-root user")
    secret = KeychainSecretProvider().get(settings.authentication_reference)
    authenticator = HostMessageAuthenticator(
        secret,
        key_id=settings.authentication_key_id,
    )
    journal = HostOperationJournal(settings.journal_path)
    dispatcher = HostRequestDispatcher(
        authenticator=authenticator,
        journal=journal,
        registry=default_operation_registry(
            workspaces=GitWorkspaceLifecycle(
                settings.journal_path.parent / "workspaces"
            )
        ),
        host_id=settings.host_id,
    )
    server = HostSocketServer(dispatcher=dispatcher)
    stopped = threading.Event()

    def request_stop(_signal_number: int, _frame: object) -> None:
        stopped.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    if settings.launchd_socket:
        with closing(activated_listener(settings.socket_path)) as listener:
            logger.info("host agent ready", extra=probe())
            server.serve_forever(listener, should_stop=stopped.is_set)
        return

    with LocalSocketBinding(settings.socket_path) as listener:
        logger.info("host agent ready", extra=probe())
        server.serve_forever(listener, should_stop=stopped.is_set)


def _environment_or_default(name: str, default: str) -> str:
    value = os.environ.get(name)
    return default if value is None or not value.strip() else value


def main() -> None:
    default_directory = Path.home() / "Library" / "Application Support" / "Mathews"
    default_socket_path = Path(
        _environment_or_default(
            "MATHEWS_HOST_SOCKET_PATH",
            str(default_directory / "host-agent.sock"),
        )
    ).expanduser()
    default_journal_path = Path(
        _environment_or_default(
            "MATHEWS_HOST_JOURNAL_PATH",
            str(default_directory / "host-agent.sqlite3"),
        )
    ).expanduser()
    parser = argparse.ArgumentParser(description="Run the Mathews macOS host agent")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Print one side-effect-free health probe and exit",
    )
    parser.add_argument(
        "--launchd-socket",
        action="store_true",
        help="Require the Unix listener supplied by launchd",
    )
    parser.add_argument(
        "--socket-path",
        type=Path,
        default=default_socket_path,
    )
    parser.add_argument(
        "--journal-path",
        type=Path,
        default=default_journal_path,
    )
    parser.add_argument(
        "--auth-reference",
        default=_environment_or_default(
            "MATHEWS_HOST_AUTH_KEY_REF",
            _DEFAULT_AUTH_REFERENCE,
        ),
        help="Opaque Keychain URI for the dedicated control-plane HMAC key",
    )
    parser.add_argument(
        "--auth-key-id",
        default=os.environ.get(
            "MATHEWS_HOST_AUTH_KEY_ID",
            "host-control-plane-v1",
        ),
    )
    parser.add_argument(
        "--host-id",
        default=os.environ.get("MATHEWS_HOST_ID", "local-macos-host"),
    )
    args = parser.parse_args()

    if args.once:
        print(json.dumps(probe(), sort_keys=True))
        return

    logging.basicConfig(level=logging.INFO)
    try:
        reference = SecretReference.parse(args.auth_reference)
        run(
            HostAgentSettings(
                socket_path=args.socket_path.expanduser().resolve(),
                journal_path=args.journal_path.expanduser().resolve(),
                authentication_reference=reference,
                authentication_key_id=args.auth_key_id,
                host_id=args.host_id,
                launchd_socket=args.launchd_socket,
            )
        )
    except (
        HostJournalError,
        HostProtocolError,
        HostServerError,
        KeychainProviderError,
        LaunchdConfigurationError,
        SecretReferenceError,
    ) as error:
        logger.error(
            "host agent failed closed",
            extra={"error_type": type(error).__name__},
        )
        raise SystemExit(2) from None


def _running_as_root() -> bool:
    return os.geteuid() == 0


if __name__ == "__main__":
    main()
