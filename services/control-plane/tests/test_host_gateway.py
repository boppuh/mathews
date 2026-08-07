import socket
import struct
import tempfile
import threading
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest
from mathews_configuration import (
    HostMessageAuthenticator,
    HostOperation,
    HostRequestMessage,
    HostResponseMessage,
    HostResponseStatus,
    RepositoryConfiguration,
    RepositoryHostAuthority,
    SecretReference,
    SecretValue,
    encode_signed_host_response,
)
from mathews_control_plane.background_jobs import JobLeaseGrant
from mathews_control_plane.host_gateway import (
    HostGatewayError,
    LocalHostGateway,
    authority_for_job_lease,
    configured_local_host_gateway,
)
from mathews_control_plane.settings import AutomationConfiguration
from mathews_host_agent.dispatch import HostRequestDispatcher, default_operation_registry
from mathews_host_agent.journal import HostOperationJournal
from mathews_host_agent.server import HostSocketServer, LocalSocketBinding

NOW_MS = 1_800_000_000_000


@dataclass(frozen=True, slots=True)
class FakeRepositoryConfiguration:
    repository_key: str = "boppuh/mathews"
    configuration_id: UUID = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
    digest: str = "sha256:" + "1" * 64


@dataclass(frozen=True, slots=True)
class FakeAutomationConfiguration:
    host_socket_path: Path
    host_auth_key_ref: SecretReference
    host_auth_key_id: str = "host-control-plane-v1"


class RecordingSecrets:
    def __init__(self, value: str = "a" * 32) -> None:
        self.value = value
        self.requested: list[SecretReference] = []

    def get(self, reference: SecretReference) -> SecretValue:
        self.requested.append(reference)
        return SecretValue(self.value)


class ConnectedClient:
    def __init__(self, connection: socket.socket) -> None:
        self._connection = connection

    def __enter__(self) -> "ConnectedClient":
        return self

    def __exit__(self, *_arguments: object) -> None:
        self._connection.close()

    def settimeout(self, value: float) -> None:
        self._connection.settimeout(value)

    def connect(self, _path: str) -> None:
        pass

    def send(self, value: bytes | memoryview) -> int:
        return self._connection.send(value)

    def shutdown(self, how: int) -> None:
        self._connection.shutdown(how)

    def recv(self, length: int) -> bytes:
        return self._connection.recv(length)


def _lease(
    *,
    lease_id: UUID | None = None,
    worker_id: str = "worker-1",
    attempt: int = 1,
    fencing_token: int = 1,
) -> JobLeaseGrant:
    return JobLeaseGrant(
        job_id=UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
        task_id=UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        lease_id=lease_id or UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
        worker_id=worker_id,
        attempt=attempt,
        fencing_token=fencing_token,
        expires_at=datetime.fromtimestamp(NOW_MS / 1_000, UTC) + timedelta(seconds=60),
        job_type="host-operation",
        input_payload={},
        checkpoint=None,
        checkpoint_version=0,
        recovered=False,
    )


def _request(
    grant: JobLeaseGrant,
    *,
    idempotency_key: str,
) -> HostRequestMessage:
    configuration = cast(
        RepositoryConfiguration,
        FakeRepositoryConfiguration(),
    )
    return HostRequestMessage(
        request_id=uuid4(),
        issued_at_ms=NOW_MS,
        expires_at_ms=NOW_MS + 10_000,
        authority=authority_for_job_lease(
            grant,
            configuration=configuration,
        ),
        operation=HostOperation(
            name="task.lease_probe",
            idempotency_key=idempotency_key,
            arguments={},
        ),
    )


def _server(
    journal_path: Path,
    authenticator: HostMessageAuthenticator,
) -> HostSocketServer:
    return HostSocketServer(
        dispatcher=HostRequestDispatcher(
            authenticator=authenticator,
            journal=HostOperationJournal(
                journal_path,
                clock_ms=lambda: NOW_MS,
            ),
            registry=default_operation_registry(),
            host_id="host-1",
            clock_ms=lambda: NOW_MS,
        )
    )


def _serve_one(
    server: HostSocketServer,
    listener: object,
) -> threading.Thread:
    thread = threading.Thread(
        target=server.serve_once,
        args=(listener,),
    )
    thread.start()
    return thread


def test_control_plane_lease_survives_host_restart_and_fences_stale_worker() -> None:
    with tempfile.TemporaryDirectory(prefix="mathews-gateway-", dir="/tmp") as value:
        runtime = Path(value)
        runtime.chmod(0o700)
        socket_path = runtime / "host.sock"
        journal_path = runtime / "journal.sqlite3"
        authenticator = HostMessageAuthenticator(
            SecretValue("a" * 32),
            key_id="control-plane-v1",
            clock_ms=lambda: NOW_MS,
        )
        gateway = LocalHostGateway(
            socket_path,
            authenticator=authenticator,
        )
        first_grant = _lease()
        first_request = _request(first_grant, idempotency_key="logical-operation")

        with LocalSocketBinding(socket_path) as listener:
            first_thread = _serve_one(
                _server(journal_path, authenticator),
                listener,
            )
            first = gateway.execute(first_request)
            first_thread.join(timeout=5)

            takeover_grant = _lease(
                lease_id=uuid4(),
                worker_id="worker-2",
                attempt=2,
                fencing_token=2,
            )
            takeover_request = replace(
                _request(
                    takeover_grant,
                    idempotency_key="logical-operation",
                ),
                operation=first_request.operation,
            )
            restarted_thread = _serve_one(
                _server(journal_path, authenticator),
                listener,
            )
            replay = gateway.execute(takeover_request)
            restarted_thread.join(timeout=5)

            stale_thread = _serve_one(
                _server(journal_path, authenticator),
                listener,
            )
            stale = gateway.execute(_request(first_grant, idempotency_key="stale-operation"))
            stale_thread.join(timeout=5)

    assert first.status is HostResponseStatus.OK
    assert first.replayed is False
    assert first.execution_fencing_token == 1
    assert replay.status is HostResponseStatus.OK
    assert replay.replayed is True
    assert replay.execution_fencing_token == 1
    assert stale.status is HostResponseStatus.REJECTED
    assert stale.code == "FENCED"


def test_lease_authority_rejects_naive_expiry() -> None:
    configuration = cast(
        RepositoryConfiguration,
        FakeRepositoryConfiguration(),
    )

    with pytest.raises(HostGatewayError, match="INVALID_LEASE"):
        authority_for_job_lease(
            replace(_lease(), expires_at=datetime(2030, 1, 1)),
            configuration=configuration,
        )


def test_gateway_factory_resolves_only_the_opaque_host_reference(
    tmp_path: Path,
) -> None:
    reference = SecretReference.parse(
        "keychain://com.boppuh.mathews.host-agent/control-plane-hmac-v1"
    )
    configuration = cast(
        AutomationConfiguration,
        FakeAutomationConfiguration(
            host_socket_path=tmp_path / "host.sock",
            host_auth_key_ref=reference,
        ),
    )
    secrets = RecordingSecrets()

    gateway = configured_local_host_gateway(
        configuration,
        secrets=secrets,
    )

    assert isinstance(gateway, LocalHostGateway)
    assert secrets.requested == [reference]


def test_gateway_factory_rejects_a_weak_resolved_secret(tmp_path: Path) -> None:
    configuration = cast(
        AutomationConfiguration,
        FakeAutomationConfiguration(
            host_socket_path=tmp_path / "host.sock",
            host_auth_key_ref=SecretReference.parse(
                "keychain://com.boppuh.mathews.host-agent/control-plane-hmac-v1"
            ),
        ),
    )

    with pytest.raises(
        HostGatewayError,
        match="HOST_AUTHENTICATION_UNAVAILABLE",
    ):
        configured_local_host_gateway(
            configuration,
            secrets=RecordingSecrets("weak"),
        )


def test_preflight_response_has_an_operation_aware_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authenticator = HostMessageAuthenticator(
        SecretValue("a" * 32),
        key_id="control-plane-v1",
        clock_ms=lambda: NOW_MS,
    )
    request = HostRequestMessage(
        request_id=uuid4(),
        issued_at_ms=NOW_MS,
        expires_at_ms=NOW_MS + 30_000,
        authority=RepositoryHostAuthority(
            repository_key="boppuh/mathews",
            configuration_id=UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
            configuration_digest="sha256:" + "1" * 64,
        ),
        operation=HostOperation(
            name="repository.preflight",
            idempotency_key="preflight-replay",
            arguments={},
        ),
    )
    signed_response = encode_signed_host_response(
        authenticator.sign_response(
            HostResponseMessage(
                request_id=request.request_id,
                operation_name=request.operation.name,
                idempotency_key=request.operation.idempotency_key,
                host_id="host-1",
                host_version="0.1.0",
                status=HostResponseStatus.OK,
                code="OK",
                replayed=True,
                completed_at_ms=NOW_MS,
                result={"status": "PASSED"},
            )
        )
    )
    server_connection, client_connection = socket.socketpair()

    monkeypatch.setattr(
        socket,
        "socket",
        lambda *_arguments, **_keywords: ConnectedClient(client_connection),
    )

    def delayed_replay() -> None:
        with server_connection:
            header = server_connection.recv(4)
            (length,) = struct.unpack("!I", header)
            received = bytearray()
            while len(received) < length:
                received.extend(server_connection.recv(length - len(received)))
            assert received
            time.sleep(0.08)
            server_connection.sendall(struct.pack("!I", len(signed_response)) + signed_response)

    server_thread = threading.Thread(target=delayed_replay)
    server_thread.start()
    gateway = LocalHostGateway(
        tmp_path / "host.sock",
        authenticator=authenticator,
        connection_timeout_seconds=0.05,
        response_timeout_seconds=0.05,
        operation_response_timeouts={"repository.preflight": 1.0},
    )

    response = gateway.execute(request)
    server_thread.join(timeout=2)

    assert not server_thread.is_alive()
    assert response.status is HostResponseStatus.OK
    assert response.replayed is True


def test_default_host_deadlines_cover_bounded_push_and_preflight_operations(
    tmp_path: Path,
) -> None:
    gateway = LocalHostGateway(
        tmp_path / "host.sock",
        authenticator=HostMessageAuthenticator(
            SecretValue("a" * 32),
            key_id="control-plane-v1",
            clock_ms=lambda: NOW_MS,
        ),
    )

    assert gateway._operation_response_timeouts == {
        "git.push": 30.0,
        "repository.preflight": 30.0,
        "validation.run": 3_610.0,
    }


def test_complete_response_does_not_require_peer_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server_connection, client_connection = socket.socketpair()
    release_server = threading.Event()
    response = b"complete-response"
    monkeypatch.setattr(
        socket,
        "socket",
        lambda *_arguments, **_keywords: ConnectedClient(client_connection),
    )

    def lingering_server() -> None:
        with server_connection:
            header = server_connection.recv(4)
            (length,) = struct.unpack("!I", header)
            request = bytearray()
            while len(request) < length:
                request.extend(server_connection.recv(length - len(request)))
            assert request
            server_connection.sendall(struct.pack("!I", len(response)) + response)
            assert release_server.wait(timeout=2)

    server_thread = threading.Thread(target=lingering_server)
    server_thread.start()
    gateway = LocalHostGateway(
        tmp_path / "host.sock",
        authenticator=HostMessageAuthenticator(
            SecretValue("a" * 32),
            key_id="control-plane-v1",
            clock_ms=lambda: NOW_MS,
        ),
    )

    try:
        received = gateway._exchange(
            b"request",
            response_timeout_seconds=0.2,
        )
    finally:
        release_server.set()
        server_thread.join(timeout=2)

    assert not server_thread.is_alive()
    assert received == response


def test_trailing_response_bytes_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server_connection, client_connection = socket.socketpair()
    monkeypatch.setattr(
        socket,
        "socket",
        lambda *_arguments, **_keywords: ConnectedClient(client_connection),
    )

    def server_with_trailing_data() -> None:
        with server_connection:
            header = server_connection.recv(4)
            (length,) = struct.unpack("!I", header)
            request = bytearray()
            while len(request) < length:
                request.extend(server_connection.recv(length - len(request)))
            assert request
            response = b"complete-response"
            server_connection.sendall(
                struct.pack("!I", len(response)) + response + b"x"
            )

    server_thread = threading.Thread(target=server_with_trailing_data)
    server_thread.start()
    gateway = LocalHostGateway(
        tmp_path / "host.sock",
        authenticator=HostMessageAuthenticator(
            SecretValue("a" * 32),
            key_id="control-plane-v1",
            clock_ms=lambda: NOW_MS,
        ),
    )

    with pytest.raises(HostGatewayError, match="INVALID_RESPONSE_FRAME"):
        gateway._exchange(
            b"request",
            response_timeout_seconds=0.2,
        )
    server_thread.join(timeout=2)

    assert not server_thread.is_alive()
