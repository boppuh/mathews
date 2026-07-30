import errno
import socket
import struct
import tempfile
import threading
import time
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest
from mathews_configuration import (
    HostAuthorityKind,
    HostMessageAuthenticator,
    HostOperation,
    HostRequestMessage,
    JsonValue,
    SecretValue,
    SignedHostRequest,
    SignedHostResponse,
    SystemHostAuthority,
    decode_signed_host_response,
    encode_signed_host_request,
)
from mathews_host_agent.dispatch import (
    HostOperationContext,
    HostOperationDefinition,
    HostOperationRegistry,
    HostRequestDispatcher,
    default_operation_registry,
)
from mathews_host_agent.journal import HostOperationJournal
from mathews_host_agent.server import (
    HostServerError,
    HostSocketClient,
    HostSocketServer,
    LocalSocketBinding,
    _receive_frame,
)

NOW_MS = 1_800_000_000_000


@pytest.fixture
def socket_runtime() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="mathews-", dir="/tmp") as value:
        runtime = Path(value)
        runtime.chmod(0o700)
        yield runtime


def _server(
    runtime: Path,
) -> tuple[HostSocketServer, HostMessageAuthenticator]:
    authenticator = HostMessageAuthenticator(
        SecretValue("a" * 32),
        key_id="control-plane-v1",
        clock_ms=lambda: NOW_MS,
    )
    dispatcher = HostRequestDispatcher(
        authenticator=authenticator,
        journal=HostOperationJournal(
            runtime / "journal.sqlite3",
            clock_ms=lambda: NOW_MS,
        ),
        registry=default_operation_registry(),
        host_id="host-1",
        clock_ms=lambda: NOW_MS,
    )
    return HostSocketServer(dispatcher=dispatcher), authenticator


def _health_request() -> HostRequestMessage:
    return HostRequestMessage(
        request_id=uuid4(),
        issued_at_ms=NOW_MS,
        expires_at_ms=NOW_MS + 10_000,
        authority=SystemHostAuthority(),
        operation=HostOperation(
            name="host.health",
            idempotency_key="health-1",
            arguments={},
        ),
    )


def test_unix_socket_exchange_authenticates_and_returns_a_signed_response(
    socket_runtime: Path,
) -> None:
    runtime = socket_runtime
    socket_path = runtime / "host.sock"
    server, authenticator = _server(runtime)

    with LocalSocketBinding(socket_path) as listener:
        thread = threading.Thread(target=server.serve_once, args=(listener,))
        thread.start()
        response_payload = HostSocketClient(socket_path).exchange(
            encode_signed_host_request(authenticator.sign_request(_health_request()))
        )
        thread.join(timeout=5)

    assert not thread.is_alive()
    response = authenticator.verify_response(decode_signed_host_response(response_payload))
    assert response.code == "OK"
    assert response.result["service"] == "host-agent"


def test_socket_binding_is_private_single_owner_and_cleans_up(
    socket_runtime: Path,
) -> None:
    runtime = socket_runtime
    socket_path = runtime / "host.sock"

    with LocalSocketBinding(socket_path):
        assert socket_path.exists()
        assert socket_path.stat().st_mode & 0o777 == 0o600
        with pytest.raises(HostServerError, match="already running"):
            with LocalSocketBinding(socket_path):
                pass

    assert not socket_path.exists()


def test_socket_binding_refuses_non_socket_and_insecure_directory(
    socket_runtime: Path,
) -> None:
    runtime = socket_runtime
    socket_path = runtime / "host.sock"
    socket_path.write_text("do not replace")

    with pytest.raises(HostServerError, match="unsafe"):
        with LocalSocketBinding(socket_path):
            pass

    socket_path.unlink()
    runtime.chmod(0o755)
    with pytest.raises(HostServerError, match="permissions are unsafe"):
        with LocalSocketBinding(socket_path):
            pass


def test_stale_owned_socket_is_replaced_safely(socket_runtime: Path) -> None:
    runtime = socket_runtime
    socket_path = runtime / "host.sock"
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(socket_path))
    stale.close()

    with LocalSocketBinding(socket_path) as listener:
        assert listener.family == socket.AF_UNIX
        assert socket_path.is_socket()


def test_frame_reader_rejects_oversized_and_truncated_frames() -> None:
    reader, writer = socket.socketpair()
    try:
        writer.sendall(struct.pack("!I", 1025))
        with pytest.raises(HostServerError, match="invalid frame length"):
            _receive_frame(
                reader,
                maximum=1024,
                deadline=10.0,
                monotonic=lambda: 0.0,
            )
    finally:
        reader.close()
        writer.close()

    reader, writer = socket.socketpair()
    try:
        writer.sendall(struct.pack("!I", 4) + b"ab")
        writer.shutdown(socket.SHUT_WR)
        with pytest.raises(HostServerError, match="truncated frame"):
            _receive_frame(
                reader,
                maximum=1024,
                deadline=10.0,
                monotonic=lambda: 0.0,
            )
    finally:
        reader.close()
        writer.close()


def test_multiple_frames_are_rejected_before_dispatch(
    socket_runtime: Path,
) -> None:
    runtime = socket_runtime
    socket_path = runtime / "host.sock"
    server, authenticator = _server(runtime)
    payload = encode_signed_host_request(authenticator.sign_request(_health_request()))

    with LocalSocketBinding(socket_path) as listener:
        thread = threading.Thread(target=server.serve_once, args=(listener,))
        thread.start()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect(str(socket_path))
            connection.sendall(struct.pack("!I", len(payload)) + payload + b"x")
            try:
                connection.shutdown(socket.SHUT_WR)
            except OSError as error:
                assert error.errno == errno.ENOTCONN
            assert connection.recv(1) == b""
        thread.join(timeout=5)

    assert not thread.is_alive()


@pytest.mark.parametrize(
    "payload",
    (
        b'{"message":' + b"9" * 5_000 + b',"authentication":{}}',
        b'{"message":' + b"[" * 2_000 + b"]" * 2_000 + b',"authentication":{}}',
    ),
)
def test_hostile_unsigned_json_cannot_escape_connection_boundary(
    socket_runtime: Path,
    payload: bytes,
) -> None:
    server, _authenticator_value = _server(socket_runtime)
    server_connection, client_connection = socket.socketpair()
    thread = threading.Thread(
        target=server._serve_connection,
        args=(server_connection,),
    )
    thread.start()
    with client_connection:
        client_connection.settimeout(2)
        client_connection.sendall(struct.pack("!I", len(payload)) + payload)
        client_connection.shutdown(socket.SHUT_WR)
        assert client_connection.recv(1) == b""
    thread.join(timeout=5)

    assert not thread.is_alive()


def test_operation_runtime_does_not_consume_response_write_deadline(
    socket_runtime: Path,
) -> None:
    authenticator = HostMessageAuthenticator(
        SecretValue("a" * 32),
        key_id="control-plane-v1",
        clock_ms=lambda: NOW_MS,
    )

    def delayed_health(
        _context: HostOperationContext,
        _arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        time.sleep(0.08)
        return {"status": "ok"}

    dispatcher = HostRequestDispatcher(
        authenticator=authenticator,
        journal=HostOperationJournal(
            socket_runtime / "journal.sqlite3",
            clock_ms=lambda: NOW_MS,
        ),
        registry=HostOperationRegistry(
            {
                "host.health": HostOperationDefinition(
                    authority=HostAuthorityKind.SYSTEM,
                    validate=lambda arguments: arguments,
                    handle=delayed_health,
                )
            }
        ),
        host_id="host-1",
        clock_ms=lambda: NOW_MS,
    )
    server = HostSocketServer(
        dispatcher=dispatcher,
        io_timeout_seconds=0.05,
    )
    request_payload = encode_signed_host_request(authenticator.sign_request(_health_request()))
    server_connection, client_connection = socket.socketpair()
    thread = threading.Thread(
        target=server._serve_connection,
        args=(server_connection,),
    )
    thread.start()
    with client_connection:
        client_connection.sendall(struct.pack("!I", len(request_payload)) + request_payload)
        client_connection.shutdown(socket.SHUT_WR)
        payload = _receive_frame(
            client_connection,
            maximum=1024 * 1024,
            deadline=time.monotonic() + 2,
            monotonic=time.monotonic,
        )
    thread.join(timeout=5)

    assert authenticator.verify_response(decode_signed_host_response(payload)).code == "OK"


def test_slow_client_does_not_block_other_authenticated_connections(
    socket_runtime: Path,
) -> None:
    server, authenticator = _server(socket_runtime)
    stopped = threading.Event()
    slow_server, slow_client = socket.socketpair()
    fast_server, fast_client = socket.socketpair()

    class QueuedListener:
        def __init__(self) -> None:
            self.connections = [slow_server, fast_server]

        def settimeout(self, _value: float) -> None:
            pass

        def accept(self) -> tuple[socket.socket, str]:
            if self.connections:
                return self.connections.pop(0), ""
            time.sleep(0.01)
            raise TimeoutError

    listener = cast(socket.socket, QueuedListener())
    slow_client.sendall(b"\x00")
    request = replace(
        _health_request(),
        operation=HostOperation(
            name="host.health",
            idempotency_key="health-concurrent",
            arguments={},
        ),
    )
    request_payload = encode_signed_host_request(authenticator.sign_request(request))
    fast_client.sendall(struct.pack("!I", len(request_payload)) + request_payload)
    fast_client.shutdown(socket.SHUT_WR)
    server_thread = threading.Thread(
        target=server.serve_forever,
        args=(listener,),
        kwargs={"should_stop": stopped.is_set},
    )
    server_thread.start()
    try:
        response_payload = _receive_frame(
            fast_client,
            maximum=1024 * 1024,
            deadline=time.monotonic() + 2,
            monotonic=time.monotonic,
        )
    finally:
        fast_client.close()
        slow_client.close()
        stopped.set()
        server_thread.join(timeout=5)

    assert not server_thread.is_alive()
    response = authenticator.verify_response(decode_signed_host_response(response_payload))
    assert response.status.value == "OK"


def test_shutdown_is_bounded_when_an_operation_handler_is_stuck(
    socket_runtime: Path,
) -> None:
    authenticator = HostMessageAuthenticator(
        SecretValue("a" * 32),
        key_id="control-plane-v1",
        clock_ms=lambda: NOW_MS,
    )
    entered = threading.Event()
    release = threading.Event()
    completed = threading.Event()
    dispatch_completed = threading.Event()

    def stuck_handler(
        _context: HostOperationContext,
        _arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        entered.set()
        try:
            assert release.wait(timeout=2)
            return {"status": "released"}
        finally:
            completed.set()

    class ObservableDispatcher(HostRequestDispatcher):
        def dispatch(self, envelope: SignedHostRequest) -> SignedHostResponse:
            try:
                return super().dispatch(envelope)
            finally:
                dispatch_completed.set()

    dispatcher = ObservableDispatcher(
        authenticator=authenticator,
        journal=HostOperationJournal(
            socket_runtime / "journal.sqlite3",
            clock_ms=lambda: NOW_MS,
        ),
        registry=HostOperationRegistry(
            {
                "host.health": HostOperationDefinition(
                    authority=HostAuthorityKind.SYSTEM,
                    validate=lambda arguments: arguments,
                    handle=stuck_handler,
                )
            }
        ),
        host_id="host-1",
        clock_ms=lambda: NOW_MS,
    )
    server = HostSocketServer(
        dispatcher=dispatcher,
        shutdown_grace_seconds=0.05,
    )
    server_connection, client_connection = socket.socketpair()
    stopped = threading.Event()

    class OneConnectionListener:
        def __init__(self) -> None:
            self.connection: socket.socket | None = server_connection

        def settimeout(self, _value: float) -> None:
            pass

        def accept(self) -> tuple[socket.socket, str]:
            if self.connection is not None:
                connection = self.connection
                self.connection = None
                return connection, ""
            time.sleep(0.01)
            raise TimeoutError

    listener = cast(socket.socket, OneConnectionListener())
    server_thread = threading.Thread(
        target=server.serve_forever,
        args=(listener,),
        kwargs={"should_stop": stopped.is_set},
    )
    server_thread.start()
    request_payload = encode_signed_host_request(authenticator.sign_request(_health_request()))
    client_connection.sendall(struct.pack("!I", len(request_payload)) + request_payload)
    client_connection.shutdown(socket.SHUT_WR)
    assert entered.wait(timeout=2)

    stopped.set()
    server_thread.join(timeout=0.5)

    assert not server_thread.is_alive()
    release.set()
    assert completed.wait(timeout=2)
    assert dispatch_completed.wait(timeout=2)
    client_connection.close()
