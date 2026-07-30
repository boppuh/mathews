import os
import platform
import plistlib
import socket
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from mathews_configuration import SecretReference
from mathews_host_agent.launchd import (
    LAUNCH_AGENT_LABEL,
    LAUNCHD_SOCKET_NAME,
    LaunchAgentSpecification,
    LaunchdConfigurationError,
    activated_listener,
    render_launch_agent_plist,
)
from mathews_host_agent.server import LocalSocketBinding


@pytest.fixture
def socket_runtime() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="mathews-launchd-", dir="/tmp") as value:
        runtime = Path(value)
        runtime.chmod(0o700)
        yield runtime


class FakeActivator:
    def __init__(self, descriptors: tuple[int, ...]) -> None:
        self.descriptors = descriptors
        self.names: list[str] = []

    def activate(self, socket_name: str) -> tuple[int, ...]:
        self.names.append(socket_name)
        return self.descriptors


def test_launch_agent_plist_is_fixed_non_root_and_contains_only_secret_reference(
    socket_runtime: Path,
) -> None:
    reference = SecretReference(
        provider="keychain",
        service="com.boppuh.mathews.host-agent",
        account="control-plane-hmac-v1",
    )
    specification = LaunchAgentSpecification(
        executable=Path("/usr/local/bin/mathews-host-agent"),
        socket_path=socket_runtime / "host.sock",
        journal_path=socket_runtime / "journal.sqlite3",
        authentication_reference=reference,
        host_id="mac-host-1",
    )

    payload = render_launch_agent_plist(specification)
    value = plistlib.loads(payload)

    assert value["Label"] == LAUNCH_AGENT_LABEL
    assert value["RunAtLoad"] is False
    assert value["Umask"] == 0o077
    assert value["Sockets"] == {
        LAUNCHD_SOCKET_NAME: {
            "SockPathMode": 0o600,
            "SockPathName": str(specification.socket_path),
            "SockType": "stream",
        }
    }
    arguments = value["ProgramArguments"]
    assert "--launchd-socket" in arguments
    assert reference.uri in arguments
    assert arguments[arguments.index("--auth-key-id") + 1] == "host-control-plane-v1"
    assert "secret-credential-bytes" not in payload.decode()
    assert "UserName" not in value


def test_activated_listener_accepts_exactly_one_valid_unix_listener(
    socket_runtime: Path,
) -> None:
    socket_path = socket_runtime / "host.sock"
    with LocalSocketBinding(socket_path) as original:
        activator = FakeActivator((os.dup(original.fileno()),))

        listener = activated_listener(socket_path, activator=activator)
        try:
            assert activator.names == [LAUNCHD_SOCKET_NAME]
            assert listener.family == socket.AF_UNIX
            assert listener.getsockname() == str(socket_path)
        finally:
            listener.close()


@pytest.mark.parametrize("descriptor_count", (0, 2))
def test_activated_listener_rejects_missing_or_ambiguous_descriptors(
    socket_runtime: Path,
    descriptor_count: int,
) -> None:
    socket_path = socket_runtime / "host.sock"
    with LocalSocketBinding(socket_path) as original:
        descriptors = tuple(
            os.dup(original.fileno()) for _index in range(descriptor_count)
        )
        with pytest.raises(LaunchdConfigurationError, match="exactly one"):
            activated_listener(
                socket_path,
                activator=FakeActivator(descriptors),
            )


def test_activated_listener_rejects_non_listening_socket(
    socket_runtime: Path,
) -> None:
    socket_path = socket_runtime / "expected.sock"
    original, peer = socket.socketpair()
    try:
        with pytest.raises(LaunchdConfigurationError):
            activated_listener(
                socket_path,
                activator=FakeActivator((os.dup(original.fileno()),)),
            )
    finally:
        original.close()
        peer.close()


def test_launch_agent_specification_rejects_relative_paths_and_unsafe_host_id(
    socket_runtime: Path,
) -> None:
    reference = SecretReference(
        provider="keychain",
        service="com.boppuh.mathews.host-agent",
        account="control-plane-hmac-v1",
    )
    with pytest.raises(LaunchdConfigurationError, match="absolute"):
        LaunchAgentSpecification(
            executable=Path("mathews-host-agent"),
            socket_path=socket_runtime / "host.sock",
            journal_path=socket_runtime / "journal.sqlite3",
            authentication_reference=reference,
            host_id="host-1",
        )
    with pytest.raises(LaunchdConfigurationError, match="identity"):
        LaunchAgentSpecification(
            executable=Path("/usr/local/bin/mathews-host-agent"),
            socket_path=socket_runtime / "host.sock",
            journal_path=socket_runtime / "journal.sqlite3",
            authentication_reference=reference,
            host_id="host id with spaces",
        )


@pytest.mark.skipif(
    platform.system().lower() != "darwin",
    reason="plutil is a macOS launchd validation tool",
)
def test_rendered_launch_agent_passes_plutil(socket_runtime: Path) -> None:
    payload = render_launch_agent_plist(
        LaunchAgentSpecification(
            executable=Path("/usr/local/bin/mathews-host-agent"),
            socket_path=socket_runtime / "host.sock",
            journal_path=socket_runtime / "journal.sqlite3",
            authentication_reference=SecretReference.parse(
                "keychain://com.boppuh.mathews.host-agent/control-plane-hmac-v1"
            ),
            host_id="host-1",
        )
    )

    result = subprocess.run(
        ["/usr/bin/plutil", "-lint", "-"],
        input=payload,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr.decode()
