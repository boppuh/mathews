"""Strict launchd socket activation and LaunchAgent plist generation."""

from __future__ import annotations

import argparse
import ctypes
import errno
import os
import platform
import plistlib
import re
import socket
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from mathews_configuration import SecretReference

LAUNCH_AGENT_LABEL = "com.boppuh.mathews.host-agent"
LAUNCHD_SOCKET_NAME = "HostAgent"
_HOST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}\Z")


class LaunchdConfigurationError(RuntimeError):
    """A stable fail-closed launchd configuration error."""


class SocketActivator(Protocol):
    def activate(self, socket_name: str) -> tuple[int, ...]:
        """Return duplicated descriptors supplied by launchd."""


@dataclass(frozen=True, slots=True)
class LaunchAgentSpecification:
    executable: Path
    socket_path: Path
    journal_path: Path
    authentication_reference: SecretReference
    host_id: str
    authentication_key_id: str = "host-control-plane-v1"

    def __post_init__(self) -> None:
        for value in (self.executable, self.socket_path, self.journal_path):
            if not value.is_absolute():
                raise LaunchdConfigurationError("launchd paths must be absolute")
        if _HOST_ID.fullmatch(self.host_id) is None:
            raise LaunchdConfigurationError("host identity is invalid")
        if _HOST_ID.fullmatch(self.authentication_key_id) is None:
            raise LaunchdConfigurationError("authentication key identity is invalid")


class LibSystemSocketActivator:
    """Small ctypes adapter for launch_activate_socket(3)."""

    def activate(self, socket_name: str) -> tuple[int, ...]:
        if platform.system().lower() != "darwin":
            raise LaunchdConfigurationError("launchd activation requires macOS")

        library = ctypes.CDLL(None)
        activate = library.launch_activate_socket
        activate.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.POINTER(ctypes.c_int)),
            ctypes.POINTER(ctypes.c_size_t),
        ]
        activate.restype = ctypes.c_int
        descriptors = ctypes.POINTER(ctypes.c_int)()
        count = ctypes.c_size_t()
        error = activate(
            socket_name.encode("utf-8"),
            ctypes.byref(descriptors),
            ctypes.byref(count),
        )
        if error != 0:
            raise LaunchdConfigurationError("launchd socket is unavailable")
        try:
            return tuple(descriptors[index] for index in range(count.value))
        finally:
            free = library.free
            free.argtypes = [ctypes.c_void_p]
            free.restype = None
            free(descriptors)


def activated_listener(
    expected_path: Path,
    *,
    activator: SocketActivator | None = None,
) -> socket.socket:
    """Claim exactly one validated local stream listener from launchd."""

    descriptors = (activator or LibSystemSocketActivator()).activate(
        LAUNCHD_SOCKET_NAME
    )
    if len(descriptors) != 1:
        for descriptor in descriptors:
            os.close(descriptor)
        raise LaunchdConfigurationError(
            "launchd must provide exactly one host-agent socket"
        )
    try:
        listener = socket.socket(fileno=descriptors[0])
    except BaseException:
        os.close(descriptors[0])
        raise
    try:
        validate_listener(listener, expected_path=expected_path)
    except BaseException:
        listener.close()
        raise
    return listener


def validate_listener(listener: socket.socket, *, expected_path: Path) -> None:
    if (
        listener.family != socket.AF_UNIX
        or listener.type & socket.SOCK_STREAM != socket.SOCK_STREAM
    ):
        raise LaunchdConfigurationError("host agent requires a Unix stream socket")
    if not _listener_is_accepting(listener):
        raise LaunchdConfigurationError("launchd descriptor is not listening")
    if listener.getsockname() != str(expected_path):
        raise LaunchdConfigurationError("launchd socket path does not match configuration")
    try:
        parent_stat = expected_path.parent.lstat()
        socket_stat = expected_path.lstat()
    except OSError:
        raise LaunchdConfigurationError("launchd socket path is unavailable") from None
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != os.geteuid()
        or stat.S_IMODE(parent_stat.st_mode) & 0o077
        or not stat.S_ISSOCK(socket_stat.st_mode)
        or socket_stat.st_uid != os.geteuid()
        or stat.S_IMODE(socket_stat.st_mode) != 0o600
    ):
        raise LaunchdConfigurationError("launchd socket permissions are unsafe")


def render_launch_agent_plist(specification: LaunchAgentSpecification) -> bytes:
    """Render the fixed non-root LaunchAgent definition without credential bytes."""

    value = {
        "Label": LAUNCH_AGENT_LABEL,
        "ProgramArguments": [
            str(specification.executable),
            "--launchd-socket",
            "--socket-path",
            str(specification.socket_path),
            "--journal-path",
            str(specification.journal_path),
            "--auth-reference",
            specification.authentication_reference.uri,
            "--auth-key-id",
            specification.authentication_key_id,
            "--host-id",
            specification.host_id,
        ],
        "ProcessType": "Background",
        "RunAtLoad": False,
        "Sockets": {
            LAUNCHD_SOCKET_NAME: {
                "SockPathMode": 0o600,
                "SockPathName": str(specification.socket_path),
                "SockType": "stream",
            }
        },
        "Umask": 0o077,
    }
    return plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Render the fixed Mathews per-user LaunchAgent plist"
    )
    parser.add_argument("--executable", required=True, type=Path)
    parser.add_argument("--socket-path", required=True, type=Path)
    parser.add_argument("--journal-path", required=True, type=Path)
    parser.add_argument(
        "--auth-reference",
        required=True,
        type=SecretReference.parse,
    )
    parser.add_argument("--auth-key-id", default="host-control-plane-v1")
    parser.add_argument("--host-id", required=True)
    arguments = parser.parse_args()
    try:
        payload = render_launch_agent_plist(
            LaunchAgentSpecification(
                executable=arguments.executable.resolve(),
                socket_path=arguments.socket_path.resolve(),
                journal_path=arguments.journal_path.resolve(),
                authentication_reference=arguments.auth_reference,
                host_id=arguments.host_id,
                authentication_key_id=arguments.auth_key_id,
            )
        )
    except LaunchdConfigurationError as error:
        parser.error(str(error))
    sys.stdout.buffer.write(payload)


def _listener_is_accepting(listener: socket.socket) -> bool:
    try:
        return listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
    except OSError as error:
        if error.errno not in {errno.ENOPROTOOPT, errno.EOPNOTSUPP}:
            raise LaunchdConfigurationError(
                "launchd listener state is unavailable"
            ) from None

    try:
        listener.listen(16)
    except OSError as error:
        if error.errno in {errno.EINVAL, errno.ENOTCONN}:
            return False
        raise LaunchdConfigurationError(
            "launchd listener state is unavailable"
        ) from None
    return True


if __name__ == "__main__":
    main()
