"""Trusted control-plane client for the authenticated local host boundary."""

from __future__ import annotations

import socket
import struct
import time
from collections.abc import Mapping
from datetime import datetime
from math import isfinite
from pathlib import Path

from mathews_configuration import (
    MAX_HOST_REQUEST_BYTES,
    MAX_HOST_RESPONSE_BYTES,
    HostMessageAuthenticator,
    HostOperation,
    HostProtocolError,
    HostRequestMessage,
    HostResponseMessage,
    HostResponseStatus,
    RepositoryConfiguration,
    SecretProvider,
    TaskLeaseHostAuthority,
    decode_signed_host_response,
    encode_signed_host_request,
)

from mathews_control_plane.background_jobs import JobLeaseGrant
from mathews_control_plane.settings import AutomationConfiguration

_FRAME_HEADER = struct.Struct("!I")
_DEFAULT_OPERATION_RESPONSE_TIMEOUTS = {
    "git.push": 30.0,
    "repository.preflight": 30.0,
    "validation.run": 3_720.0,
}


class HostGatewayError(RuntimeError):
    """A stable host-gateway failure without local response contents."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class LocalHostGateway:
    """Exchange signed typed operations over one local Unix socket."""

    def __init__(
        self,
        socket_path: Path,
        *,
        authenticator: HostMessageAuthenticator,
        connection_timeout_seconds: float = 5.0,
        response_timeout_seconds: float = 5.0,
        operation_response_timeouts: Mapping[str, float] | None = None,
    ) -> None:
        if not socket_path.is_absolute():
            raise HostGatewayError("INVALID_SOCKET_PATH")
        _validate_timeout(connection_timeout_seconds)
        _validate_timeout(response_timeout_seconds)
        configured_timeouts = dict(
            _DEFAULT_OPERATION_RESPONSE_TIMEOUTS
            if operation_response_timeouts is None
            else operation_response_timeouts
        )
        for operation_name, timeout in configured_timeouts.items():
            try:
                HostOperation(
                    name=operation_name,
                    idempotency_key="timeout-validation",
                    arguments={},
                )
            except HostProtocolError:
                raise HostGatewayError("INVALID_TIMEOUT") from None
            _validate_timeout(timeout)
        self._socket_path = socket_path
        self._authenticator = authenticator
        self._connection_timeout_seconds = connection_timeout_seconds
        self._response_timeout_seconds = response_timeout_seconds
        self._operation_response_timeouts = configured_timeouts

    def execute(self, request: HostRequestMessage) -> HostResponseMessage:
        payload = encode_signed_host_request(self._authenticator.sign_request(request))
        response_payload = self._exchange(
            payload,
            response_timeout_seconds=self._operation_response_timeouts.get(
                request.operation.name,
                self._response_timeout_seconds,
            ),
        )
        try:
            response = self._authenticator.verify_response(
                decode_signed_host_response(response_payload)
            )
        except HostProtocolError:
            raise HostGatewayError("UNAUTHENTICATED_HOST_RESPONSE") from None
        if (
            response.request_id != request.request_id
            or response.operation_name != request.operation.name
            or response.idempotency_key != request.operation.idempotency_key
        ):
            raise HostGatewayError("HOST_RESPONSE_MISMATCH")
        _validate_execution_fence(request, response)
        return response

    def _exchange(
        self,
        payload: bytes,
        *,
        response_timeout_seconds: float,
    ) -> bytes:
        connection_deadline = time.monotonic() + self._connection_timeout_seconds
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(_remaining(connection_deadline))
                connection.connect(str(self._socket_path))
                _send_frame(connection, payload, deadline=connection_deadline)
                connection.shutdown(socket.SHUT_WR)
                response_deadline = time.monotonic() + response_timeout_seconds
                response = _receive_frame(connection, deadline=response_deadline)
                connection.settimeout(min(0.05, _remaining(response_deadline)))
                try:
                    if connection.recv(1):
                        raise HostGatewayError("INVALID_RESPONSE_FRAME")
                except TimeoutError:
                    pass
                return response
        except OSError:
            raise HostGatewayError("HOST_UNAVAILABLE") from None


def configured_local_host_gateway(
    configuration: AutomationConfiguration,
    *,
    secrets: SecretProvider,
    connection_timeout_seconds: float = 5.0,
    response_timeout_seconds: float = 5.0,
    operation_response_timeouts: Mapping[str, float] | None = None,
) -> LocalHostGateway:
    """Build the trusted client while keeping credential bytes out of settings."""

    try:
        authenticator = HostMessageAuthenticator(
            secrets.get(configuration.host_auth_key_ref),
            key_id=configuration.host_auth_key_id,
        )
    except (HostProtocolError, RuntimeError):
        raise HostGatewayError("HOST_AUTHENTICATION_UNAVAILABLE") from None
    return LocalHostGateway(
        configuration.host_socket_path,
        authenticator=authenticator,
        connection_timeout_seconds=connection_timeout_seconds,
        response_timeout_seconds=response_timeout_seconds,
        operation_response_timeouts=operation_response_timeouts,
    )


def authority_for_job_lease(
    grant: JobLeaseGrant,
    *,
    configuration: RepositoryConfiguration,
) -> TaskLeaseHostAuthority:
    """Bind an issued durable job lease to one immutable repository version."""

    if grant.expires_at.tzinfo is None:
        raise HostGatewayError("INVALID_LEASE")
    expires_at_ms = _datetime_milliseconds(grant.expires_at)
    return TaskLeaseHostAuthority(
        task_id=grant.task_id,
        job_id=grant.job_id,
        lease_id=grant.lease_id,
        worker_id=grant.worker_id,
        attempt=grant.attempt,
        fencing_token=grant.fencing_token,
        lease_expires_at_ms=expires_at_ms,
        repository_key=configuration.repository_key,
        configuration_id=configuration.configuration_id,
        configuration_digest=configuration.digest,
    )


def _validate_execution_fence(
    request: HostRequestMessage,
    response: HostResponseMessage,
) -> None:
    authority = request.authority
    if not isinstance(authority, TaskLeaseHostAuthority):
        if response.execution_fencing_token is not None:
            raise HostGatewayError("HOST_RESPONSE_MISMATCH")
        return
    token = response.execution_fencing_token
    if response.status is not HostResponseStatus.OK:
        if token is not None and token > authority.fencing_token:
            raise HostGatewayError("HOST_RESPONSE_MISMATCH")
        return
    if token is None or token > authority.fencing_token:
        raise HostGatewayError("HOST_RESPONSE_MISMATCH")
    if not response.replayed and token != authority.fencing_token:
        raise HostGatewayError("HOST_RESPONSE_MISMATCH")


def _send_frame(
    connection: socket.socket,
    payload: bytes,
    *,
    deadline: float,
) -> None:
    if not payload or len(payload) > MAX_HOST_REQUEST_BYTES:
        raise HostGatewayError("INVALID_REQUEST_FRAME")
    frame = _FRAME_HEADER.pack(len(payload)) + payload
    view = memoryview(frame)
    while view:
        connection.settimeout(_remaining(deadline))
        sent = connection.send(view)
        if sent <= 0:
            raise HostGatewayError("HOST_UNAVAILABLE")
        view = view[sent:]


def _receive_frame(
    connection: socket.socket,
    *,
    deadline: float,
) -> bytes:
    header = _receive_exact(connection, _FRAME_HEADER.size, deadline=deadline)
    (length,) = _FRAME_HEADER.unpack(header)
    if length == 0 or length > MAX_HOST_RESPONSE_BYTES:
        raise HostGatewayError("INVALID_RESPONSE_FRAME")
    return _receive_exact(connection, length, deadline=deadline)


def _receive_exact(
    connection: socket.socket,
    length: int,
    *,
    deadline: float,
) -> bytes:
    value = bytearray()
    while len(value) < length:
        connection.settimeout(_remaining(deadline))
        chunk = connection.recv(length - len(value))
        if not chunk:
            raise HostGatewayError("HOST_UNAVAILABLE")
        value.extend(chunk)
    return bytes(value)


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise HostGatewayError("HOST_UNAVAILABLE")
    return remaining


def _validate_timeout(value: float) -> None:
    if not isfinite(value) or value <= 0 or value > 3_720:
        raise HostGatewayError("INVALID_TIMEOUT")


def _datetime_milliseconds(value: datetime) -> int:
    return int(value.timestamp() * 1_000)
