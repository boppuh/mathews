"""Bounded Unix-domain-socket transport for the host agent."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import platform
import socket
import stat
import struct
import threading
import time
from collections.abc import Callable
from math import isfinite
from pathlib import Path
from types import TracebackType

from mathews_configuration.host_protocol import (
    MAX_HOST_REQUEST_BYTES,
    MAX_HOST_RESPONSE_BYTES,
    decode_signed_host_request,
    encode_signed_host_response,
)

from mathews_host_agent.dispatch import HostRequestDispatcher

_FRAME_HEADER = struct.Struct("!I")
_DEFAULT_IO_TIMEOUT_SECONDS = 5.0
_MAX_SOCKET_BACKLOG = 16
_MAX_CONCURRENT_CONNECTIONS = 8
_MAX_UNIX_SOCKET_PATH_BYTES = 103
_DEFAULT_SHUTDOWN_GRACE_SECONDS = 2.0


class HostServerError(RuntimeError):
    """A stable local transport failure."""


class LocalSocketBinding:
    """Own one safe self-bound Unix listener for development and tests."""

    def __init__(self, path: Path, *, backlog: int = _MAX_SOCKET_BACKLOG) -> None:
        if not path.is_absolute():
            raise HostServerError("socket path must be absolute")
        if len(os.fsencode(path)) > _MAX_UNIX_SOCKET_PATH_BYTES:
            raise HostServerError("socket path is too long")
        if backlog <= 0 or backlog > _MAX_SOCKET_BACKLOG:
            raise HostServerError("socket backlog is invalid")
        self._path = path
        self._backlog = backlog
        self._lock_descriptor: int | None = None
        self._listener: socket.socket | None = None
        self._socket_identity: tuple[int, int] | None = None

    def __enter__(self) -> socket.socket:
        _prepare_private_directory(self._path.parent)
        self._lock_descriptor = _acquire_lock(self._path.with_suffix(".lock"))
        bound = False
        try:
            _remove_stale_socket(self._path)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(self._path))
            bound = True
            socket_stat = self._path.lstat()
            self._socket_identity = (socket_stat.st_dev, socket_stat.st_ino)
            os.chmod(self._path, 0o600, follow_symlinks=False)
            listener.listen(self._backlog)
        except BaseException:
            if "listener" in locals():
                listener.close()
            if bound and self._socket_identity is None:
                try:
                    socket_stat = self._path.lstat()
                except OSError:
                    pass
                else:
                    if stat.S_ISSOCK(socket_stat.st_mode) and socket_stat.st_uid == os.geteuid():
                        self._socket_identity = (
                            socket_stat.st_dev,
                            socket_stat.st_ino,
                        )
            self._remove_owned_socket()
            self._release_lock()
            raise
        self._listener = listener
        return listener

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        self._remove_owned_socket()
        self._release_lock()

    def _remove_owned_socket(self) -> None:
        try:
            socket_stat = self._path.lstat()
        except OSError:
            socket_stat = None
        if (
            socket_stat is not None
            and self._socket_identity == (socket_stat.st_dev, socket_stat.st_ino)
            and stat.S_ISSOCK(socket_stat.st_mode)
            and socket_stat.st_uid == os.geteuid()
        ):
            try:
                self._path.unlink()
            except OSError:
                pass
        self._socket_identity = None

    def _release_lock(self) -> None:
        if self._lock_descriptor is not None:
            os.close(self._lock_descriptor)
            self._lock_descriptor = None


class HostSocketServer:
    """Serve one authenticated frame per same-user local connection."""

    def __init__(
        self,
        *,
        dispatcher: HostRequestDispatcher,
        io_timeout_seconds: float = _DEFAULT_IO_TIMEOUT_SECONDS,
        maximum_concurrent_connections: int = _MAX_CONCURRENT_CONNECTIONS,
        shutdown_grace_seconds: float = _DEFAULT_SHUTDOWN_GRACE_SECONDS,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        if not isfinite(io_timeout_seconds) or io_timeout_seconds <= 0 or io_timeout_seconds > 30:
            raise ValueError("host socket timeout must be between 0 and 30 seconds")
        if (
            maximum_concurrent_connections <= 0
            or maximum_concurrent_connections > _MAX_CONCURRENT_CONNECTIONS
        ):
            raise ValueError("host socket concurrency is invalid")
        if (
            not isfinite(shutdown_grace_seconds)
            or shutdown_grace_seconds <= 0
            or shutdown_grace_seconds > 5
        ):
            raise ValueError("host socket shutdown grace is invalid")
        self._dispatcher = dispatcher
        self._io_timeout_seconds = io_timeout_seconds
        self._maximum_concurrent_connections = maximum_concurrent_connections
        self._shutdown_grace_seconds = shutdown_grace_seconds
        self._monotonic = monotonic or time.monotonic

    def serve_once(self, listener: socket.socket) -> None:
        connection, _address = listener.accept()
        self._serve_connection(connection)

    def _serve_connection(self, connection: socket.socket) -> None:
        with connection:
            try:
                _require_same_user(connection)
                read_deadline = self._monotonic() + self._io_timeout_seconds
                payload = _receive_frame(
                    connection,
                    maximum=MAX_HOST_REQUEST_BYTES,
                    deadline=read_deadline,
                    monotonic=self._monotonic,
                )
                _require_write_eof(
                    connection,
                    deadline=read_deadline,
                    monotonic=self._monotonic,
                )
                request = decode_signed_host_request(payload)
                response = self._dispatcher.dispatch(request)
                write_deadline = self._monotonic() + self._io_timeout_seconds
                _send_frame(
                    connection,
                    encode_signed_host_response(response),
                    maximum=MAX_HOST_RESPONSE_BYTES,
                    deadline=write_deadline,
                    monotonic=self._monotonic,
                )
            except Exception:
                return

    def serve_forever(
        self,
        listener: socket.socket,
        *,
        should_stop: Callable[[], bool] | None = None,
    ) -> None:
        stop = should_stop or (lambda: False)
        active: dict[threading.Thread, socket.socket] = {}
        listener.settimeout(0.25)
        try:
            while not stop():
                completed = {thread for thread in active if not thread.is_alive()}
                for thread in completed:
                    thread.join()
                    active.pop(thread, None)
                if len(active) >= self._maximum_concurrent_connections:
                    next(iter(active)).join(timeout=0.05)
                    continue
                try:
                    connection, _address = listener.accept()
                except TimeoutError:
                    continue
                worker = threading.Thread(
                    target=self._serve_connection,
                    args=(connection,),
                    name="mathews-host-connection",
                    daemon=True,
                )
                active[worker] = connection
                worker.start()
        finally:
            for connection in active.values():
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
            deadline = self._monotonic() + self._shutdown_grace_seconds
            for worker in active:
                remaining = deadline - self._monotonic()
                if remaining <= 0:
                    break
                worker.join(timeout=remaining)


class HostSocketClient:
    """Small request/response client used by the trusted control-plane side."""

    def __init__(
        self,
        socket_path: Path,
        *,
        io_timeout_seconds: float = _DEFAULT_IO_TIMEOUT_SECONDS,
        response_timeout_seconds: float = 30.0,
    ) -> None:
        if not socket_path.is_absolute():
            raise ValueError("host socket path must be absolute")
        for timeout in (io_timeout_seconds, response_timeout_seconds):
            if not isfinite(timeout) or timeout <= 0 or timeout > 30:
                raise ValueError("host socket client timeout is invalid")
        self._socket_path = socket_path
        self._io_timeout_seconds = io_timeout_seconds
        self._response_timeout_seconds = response_timeout_seconds

    def exchange(self, request_payload: bytes) -> bytes:
        deadline = time.monotonic() + self._io_timeout_seconds
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(_remaining(deadline, time.monotonic))
            connection.connect(str(self._socket_path))
            _send_frame(
                connection,
                request_payload,
                maximum=MAX_HOST_REQUEST_BYTES,
                deadline=deadline,
                monotonic=time.monotonic,
            )
            connection.shutdown(socket.SHUT_WR)
            response_deadline = time.monotonic() + self._response_timeout_seconds
            return _receive_frame(
                connection,
                maximum=MAX_HOST_RESPONSE_BYTES,
                deadline=response_deadline,
                monotonic=time.monotonic,
            )


def _receive_frame(
    connection: socket.socket,
    *,
    maximum: int,
    deadline: float,
    monotonic: Callable[[], float],
) -> bytes:
    header = _receive_exact(
        connection,
        _FRAME_HEADER.size,
        deadline=deadline,
        monotonic=monotonic,
    )
    (length,) = _FRAME_HEADER.unpack(header)
    if length == 0 or length > maximum:
        raise HostServerError("invalid frame length")
    return _receive_exact(
        connection,
        length,
        deadline=deadline,
        monotonic=monotonic,
    )


def _send_frame(
    connection: socket.socket,
    payload: bytes,
    *,
    maximum: int,
    deadline: float,
    monotonic: Callable[[], float],
) -> None:
    if not payload or len(payload) > maximum:
        raise HostServerError("invalid frame length")
    framed = _FRAME_HEADER.pack(len(payload)) + payload
    view = memoryview(framed)
    while view:
        connection.settimeout(_remaining(deadline, monotonic))
        sent = connection.send(view)
        if sent <= 0:
            raise HostServerError("connection closed")
        view = view[sent:]


def _receive_exact(
    connection: socket.socket,
    length: int,
    *,
    deadline: float,
    monotonic: Callable[[], float],
) -> bytes:
    result = bytearray()
    while len(result) < length:
        connection.settimeout(_remaining(deadline, monotonic))
        chunk = connection.recv(length - len(result))
        if not chunk:
            raise HostServerError("truncated frame")
        result.extend(chunk)
    return bytes(result)


def _require_write_eof(
    connection: socket.socket,
    *,
    deadline: float,
    monotonic: Callable[[], float],
) -> None:
    connection.settimeout(_remaining(deadline, monotonic))
    if connection.recv(1):
        raise HostServerError("multiple frames are not allowed")


def _remaining(deadline: float, monotonic: Callable[[], float]) -> float:
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise HostServerError("connection deadline exceeded")
    return remaining


def _require_same_user(connection: socket.socket) -> None:
    current_uid = os.geteuid()
    getpeereid = getattr(connection, "getpeereid", None)
    if getpeereid is not None:
        peer_uid, _peer_gid = getpeereid()
        if peer_uid != current_uid:
            raise HostServerError("peer identity rejected")
        return
    if platform.system().lower() == "darwin":
        library = ctypes.CDLL(None, use_errno=True)
        get_peer_identity = library.getpeereid
        get_peer_identity.argtypes = [
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_uint),
            ctypes.POINTER(ctypes.c_uint),
        ]
        get_peer_identity.restype = ctypes.c_int
        peer_uid = ctypes.c_uint()
        peer_gid = ctypes.c_uint()
        if (
            get_peer_identity(
                connection.fileno(),
                ctypes.byref(peer_uid),
                ctypes.byref(peer_gid),
            )
            != 0
            or peer_uid.value != current_uid
        ):
            raise HostServerError("peer identity rejected")
        return
    if hasattr(socket, "SO_PEERCRED"):
        credentials = connection.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        _peer_pid, peer_uid, _peer_gid = struct.unpack("3i", credentials)
        if peer_uid != current_uid:
            raise HostServerError("peer identity rejected")
        return
    raise HostServerError("peer identity is unavailable")


def _prepare_private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory_stat = path.lstat()
    except OSError:
        raise HostServerError("socket directory is unavailable") from None
    if (
        not stat.S_ISDIR(directory_stat.st_mode)
        or directory_stat.st_uid != os.geteuid()
        or stat.S_IMODE(directory_stat.st_mode) & 0o077
    ):
        raise HostServerError("socket directory permissions are unsafe")


def _acquire_lock(path: Path) -> int:
    try:
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        lock_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(lock_stat.st_mode)
            or lock_stat.st_uid != os.geteuid()
            or stat.S_IMODE(lock_stat.st_mode) & 0o077
        ):
            raise HostServerError("socket lock permissions are unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        if "descriptor" in locals():
            os.close(descriptor)
        if error.errno in {errno.EACCES, errno.EAGAIN}:
            raise HostServerError("host agent is already running") from None
        raise HostServerError("socket lock is unavailable") from None
    except HostServerError:
        os.close(descriptor)
        raise
    return descriptor


def _remove_stale_socket(path: Path) -> None:
    try:
        socket_stat = path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise HostServerError("socket path is unavailable") from None
    if not stat.S_ISSOCK(socket_stat.st_mode) or socket_stat.st_uid != os.geteuid():
        raise HostServerError("socket path is unsafe")

    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(0.2)
        probe.connect(str(path))
    except OSError as error:
        if error.errno not in {errno.ECONNREFUSED, errno.ENOENT}:
            raise HostServerError("socket liveness is indeterminate") from None
    else:
        raise HostServerError("host agent is already running")
    finally:
        probe.close()

    try:
        current = path.lstat()
        if (
            current.st_dev != socket_stat.st_dev
            or current.st_ino != socket_stat.st_ino
            or not stat.S_ISSOCK(current.st_mode)
            or current.st_uid != os.geteuid()
        ):
            raise HostServerError("socket path changed during cleanup")
        path.unlink()
    except FileNotFoundError:
        return
    except OSError:
        raise HostServerError("stale socket could not be removed") from None
