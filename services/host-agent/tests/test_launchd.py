import os
import platform
import plistlib
import socket
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from mathews_configuration import SecretReference
from mathews_host_agent.launchd import (
    LAUNCH_AGENT_LABEL,
    LAUNCHD_SOCKET_NAME,
    LAUNCHD_SOCKET_PATH_ENVIRONMENT,
    LaunchAgentSpecification,
    LaunchdConfigurationError,
    activated_listener,
    render_launch_agent_plist,
    validate_listener,
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


def test_secure_socket_plist_uses_injected_path_and_keeps_explicit_journal(
    socket_runtime: Path,
) -> None:
    journal_path = socket_runtime / "journal.sqlite3"
    specification = LaunchAgentSpecification(
        executable=Path("/usr/local/bin/mathews-host-agent"),
        socket_path=None,
        journal_path=journal_path,
        authentication_reference=SecretReference.parse(
            "keychain://com.boppuh.mathews.host-agent/control-plane-hmac-v1"
        ),
        host_id="host-1",
        secure_socket=True,
    )

    value = plistlib.loads(render_launch_agent_plist(specification))

    assert value["Sockets"] == {
        LAUNCHD_SOCKET_NAME: {
            "SockPathMode": 0o600,
            "SockType": "stream",
            "SecureSocketWithKey": LAUNCHD_SOCKET_PATH_ENVIRONMENT,
        }
    }
    arguments = value["ProgramArguments"]
    assert "--socket-path" not in arguments
    assert "--launchd-socket" in arguments
    assert arguments[arguments.index("--journal-path") + 1] == str(journal_path)
    assert "EnvironmentVariables" not in value


def test_secure_socket_renderer_cli_emits_no_static_socket_argument(
    socket_runtime: Path,
) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mathews_host_agent.launchd",
            "--executable",
            "/usr/local/bin/mathews-host-agent",
            "--secure-socket",
            "--journal-path",
            str(socket_runtime / "journal.sqlite3"),
            "--auth-reference",
            "keychain://com.boppuh.mathews.host-agent/control-plane-hmac-v1",
            "--host-id",
            "host-1",
        ],
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr.decode()
    value = plistlib.loads(result.stdout)
    assert "--socket-path" not in value["ProgramArguments"]
    assert value["Sockets"][LAUNCHD_SOCKET_NAME]["SecureSocketWithKey"] == (
        LAUNCHD_SOCKET_PATH_ENVIRONMENT
    )


@pytest.mark.parametrize("secure_socket", (False, True))
def test_launch_agent_specification_requires_exactly_one_socket_mode(
    socket_runtime: Path,
    secure_socket: bool,
) -> None:
    with pytest.raises(LaunchdConfigurationError, match="exactly one.*mode"):
        LaunchAgentSpecification(
            executable=Path("/usr/local/bin/mathews-host-agent"),
            journal_path=socket_runtime / "journal.sqlite3",
            authentication_reference=SecretReference.parse(
                "keychain://com.boppuh.mathews.host-agent/control-plane-hmac-v1"
            ),
            host_id="host-1",
            socket_path=socket_runtime / "host.sock" if secure_socket else None,
            secure_socket=secure_socket,
        )


def test_listener_accepts_existing_filesystem_alias_without_opening_a_connection(
    socket_runtime: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    socket_path = socket_runtime / "host.sock"
    alias_root = socket_runtime / "ancestor-alias"
    alias_root.symlink_to(socket_runtime.parent, target_is_directory=True)
    alias_path = alias_root / socket_runtime.name / "host.sock"
    with LocalSocketBinding(socket_path) as listener:
        assert alias_path.lstat().st_ino == socket_path.lstat().st_ino

        def unexpected_probe(*_args: object, **_kwargs: object) -> socket.socket:
            pytest.fail("listener validation must not open a probe connection")

        monkeypatch.setattr(socket, "socket", unexpected_probe)
        validate_listener(listener, expected_path=alias_path)


@pytest.mark.skipif(platform.system().lower() != "darwin", reason="macOS /var filesystem alias")
def test_listener_accepts_var_private_var_alias() -> None:
    with tempfile.TemporaryDirectory(prefix="mathews-launchd-", dir="/var/tmp") as value:
        socket_path = Path(value) / "host.sock"
        expected_path = socket_path.resolve()
        assert str(socket_path).startswith("/var/tmp/")
        assert str(expected_path).startswith("/private/var/tmp/")
        with LocalSocketBinding(socket_path) as listener:
            validate_listener(listener, expected_path=expected_path)


@pytest.mark.parametrize("rebind_original", (False, True))
def test_listener_rejects_renamed_bound_path_even_when_original_is_rebound(
    socket_runtime: Path,
    rebind_original: bool,
) -> None:
    bound_path = socket_runtime / "original.sock"
    expected_path = socket_runtime / "host.sock"
    with LocalSocketBinding(bound_path) as listener:
        bound_path.rename(expected_path)
        if rebind_original:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as unrelated:
                unrelated.bind(str(bound_path))
                bound_path.chmod(0o600)
                unrelated.listen(1)
                assert unrelated.getsockname() == listener.getsockname()
                with pytest.raises(LaunchdConfigurationError, match="does not match"):
                    validate_listener(listener, expected_path=expected_path)
        else:
            with pytest.raises(LaunchdConfigurationError, match="path is unavailable"):
                validate_listener(listener, expected_path=expected_path)


def test_listener_rejects_unrelated_live_socket_path(socket_runtime: Path) -> None:
    bound_path = socket_runtime / "original.sock"
    expected_path = socket_runtime / "host.sock"
    with (
        LocalSocketBinding(bound_path) as listener,
        LocalSocketBinding(expected_path),
        pytest.raises(LaunchdConfigurationError, match="does not match"),
    ):
        validate_listener(listener, expected_path=expected_path)


@pytest.mark.parametrize("unsafe_target", ("parent", "socket", "symlink"))
def test_listener_rejects_unsafe_socket_path_before_alias_comparison(
    socket_runtime: Path,
    unsafe_target: str,
) -> None:
    bound_path = socket_runtime / "host.sock"
    with LocalSocketBinding(bound_path) as listener:
        if unsafe_target == "symlink":
            expected_path = socket_runtime / "link.sock"
            expected_path.symlink_to(bound_path)
        else:
            expected_path = bound_path
            if unsafe_target == "parent":
                socket_runtime.chmod(0o755)
            else:
                bound_path.chmod(0o660)
        with pytest.raises(LaunchdConfigurationError, match="permissions are unsafe"):
            validate_listener(listener, expected_path=expected_path)


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
@pytest.mark.parametrize("secure_socket", (False, True))
def test_rendered_launch_agent_passes_plutil(socket_runtime: Path, secure_socket: bool) -> None:
    payload = render_launch_agent_plist(
        LaunchAgentSpecification(
            executable=Path("/usr/local/bin/mathews-host-agent"),
            socket_path=None if secure_socket else socket_runtime / "host.sock",
            secure_socket=secure_socket,
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
