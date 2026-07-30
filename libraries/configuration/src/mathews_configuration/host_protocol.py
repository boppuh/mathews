"""Canonical authenticated contracts for the local macOS host boundary."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import cast
from uuid import UUID

from mathews_configuration.secrets import SecretValue

HOST_PROTOCOL_VERSION = 1
HOST_REQUEST_ISSUER = "control-plane"
HOST_REQUEST_AUDIENCE = "local-macos-host"
MAX_HOST_REQUEST_BYTES = 1024 * 1024
MAX_HOST_RESPONSE_BYTES = 1024 * 1024
MAX_HOST_REQUEST_LIFETIME_MS = 30_000
MAX_HOST_CLOCK_SKEW_MS = 5_000

type JsonValue = None | bool | int | str | list[JsonValue] | dict[str, JsonValue]

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}\Z")
_OPERATION = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,4}\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SIGNATURE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,99}\Z")
_MAX_JSON_DEPTH = 16
_MAX_JSON_NODES = 4096
_MAX_COLLECTION_ITEMS = 512
_MAX_STRING_LENGTH = 64 * 1024
_REQUEST_DOMAIN = b"mathews-host-request-v1\0"
_RESPONSE_DOMAIN = b"mathews-host-response-v1\0"


class HostProtocolError(ValueError):
    """A stable, payload-free protocol failure."""

    def __init__(self, code: str) -> None:
        if not isinstance(code, str) or _ERROR_CODE.fullmatch(code) is None:
            code = "INVALID_RESPONSE"
        self.code = code
        super().__init__(self.code)


class HostAuthorityKind(StrEnum):
    SYSTEM = "SYSTEM"
    REPOSITORY = "REPOSITORY"
    TASK_LEASE = "TASK_LEASE"


class HostResponseStatus(StrEnum):
    OK = "OK"
    REJECTED = "REJECTED"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True, slots=True)
class SystemHostAuthority:
    kind: HostAuthorityKind = HostAuthorityKind.SYSTEM

    def to_dict(self) -> dict[str, JsonValue]:
        return {"kind": self.kind.value}


@dataclass(frozen=True, slots=True)
class RepositoryHostAuthority:
    repository_key: str
    configuration_id: UUID
    configuration_digest: str
    kind: HostAuthorityKind = HostAuthorityKind.REPOSITORY

    def __post_init__(self) -> None:
        _repository_key(self.repository_key)
        _canonical_uuid(self.configuration_id, "configuration")
        if _DIGEST.fullmatch(self.configuration_digest) is None:
            raise HostProtocolError("INVALID_AUTHORITY")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "kind": self.kind.value,
            "repository_key": self.repository_key,
            "configuration_id": str(self.configuration_id),
            "configuration_digest": self.configuration_digest,
        }


@dataclass(frozen=True, slots=True)
class TaskLeaseHostAuthority:
    task_id: UUID
    job_id: UUID
    lease_id: UUID
    worker_id: str
    attempt: int
    fencing_token: int
    lease_expires_at_ms: int
    repository_key: str
    configuration_id: UUID
    configuration_digest: str
    kind: HostAuthorityKind = HostAuthorityKind.TASK_LEASE

    def __post_init__(self) -> None:
        _canonical_uuid(self.task_id, "task")
        _canonical_uuid(self.job_id, "job")
        _canonical_uuid(self.lease_id, "lease")
        _identifier(self.worker_id, "worker")
        _positive_int(self.attempt, "attempt")
        _positive_int(self.fencing_token, "fencing token")
        _positive_int(self.lease_expires_at_ms, "lease expiry")
        _repository_key(self.repository_key)
        _canonical_uuid(self.configuration_id, "configuration")
        if _DIGEST.fullmatch(self.configuration_digest) is None:
            raise HostProtocolError("INVALID_AUTHORITY")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "kind": self.kind.value,
            "task_id": str(self.task_id),
            "job_id": str(self.job_id),
            "lease_id": str(self.lease_id),
            "worker_id": self.worker_id,
            "attempt": self.attempt,
            "fencing_token": self.fencing_token,
            "lease_expires_at_ms": self.lease_expires_at_ms,
            "repository_key": self.repository_key,
            "configuration_id": str(self.configuration_id),
            "configuration_digest": self.configuration_digest,
        }


type HostAuthority = SystemHostAuthority | RepositoryHostAuthority | TaskLeaseHostAuthority


@dataclass(frozen=True, slots=True)
class HostOperation:
    name: str
    idempotency_key: str
    arguments: dict[str, JsonValue]
    schema_version: int = 1

    def __post_init__(self) -> None:
        if _OPERATION.fullmatch(self.name) is None:
            raise HostProtocolError("INVALID_OPERATION")
        _identifier(self.idempotency_key, "idempotency key")
        if self.schema_version != 1:
            raise HostProtocolError("INVALID_OPERATION")
        normalized = _json_object(self.arguments, "operation arguments")
        object.__setattr__(self, "arguments", normalized)

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "name": self.name,
            "schema_version": self.schema_version,
            "idempotency_key": self.idempotency_key,
            "arguments": _json_object(self.arguments, "operation arguments"),
        }


@dataclass(frozen=True, slots=True)
class HostRequestMessage:
    request_id: UUID
    issued_at_ms: int
    expires_at_ms: int
    authority: HostAuthority
    operation: HostOperation
    protocol_version: int = HOST_PROTOCOL_VERSION
    issuer: str = HOST_REQUEST_ISSUER
    audience: str = HOST_REQUEST_AUDIENCE

    def __post_init__(self) -> None:
        if self.protocol_version != HOST_PROTOCOL_VERSION:
            raise HostProtocolError("UNSUPPORTED_PROTOCOL")
        if self.issuer != HOST_REQUEST_ISSUER or self.audience != HOST_REQUEST_AUDIENCE:
            raise HostProtocolError("INVALID_REQUEST")
        _canonical_uuid(self.request_id, "request")
        if self.request_id.version != 4:
            raise HostProtocolError("INVALID_REQUEST")
        _positive_int(self.issued_at_ms, "issued time")
        _positive_int(self.expires_at_ms, "expiry time")
        if (
            self.expires_at_ms <= self.issued_at_ms
            or self.expires_at_ms - self.issued_at_ms > MAX_HOST_REQUEST_LIFETIME_MS
        ):
            raise HostProtocolError("INVALID_REQUEST")

    @property
    def semantic_fingerprint(self) -> str:
        payload = {
            "authority": _semantic_authority(self.authority),
            "operation": self.operation.to_dict(),
        }
        return "sha256:" + hashlib.sha256(_canonical_json(payload)).hexdigest()

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "protocol_version": self.protocol_version,
            "request_id": str(self.request_id),
            "issuer": self.issuer,
            "audience": self.audience,
            "issued_at_ms": self.issued_at_ms,
            "expires_at_ms": self.expires_at_ms,
            "authority": self.authority.to_dict(),
            "operation": self.operation.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class SignedHostRequest:
    message: HostRequestMessage
    key_id: str
    signature: str

    def __post_init__(self) -> None:
        _identifier(self.key_id, "authentication key")
        if _SIGNATURE.fullmatch(self.signature) is None:
            raise HostProtocolError("UNAUTHENTICATED")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "message": self.message.to_dict(),
            "authentication": {
                "key_id": self.key_id,
                "signature": self.signature,
            },
        }


@dataclass(frozen=True, slots=True)
class HostResponseMessage:
    request_id: UUID
    operation_name: str
    idempotency_key: str
    host_id: str
    host_version: str
    status: HostResponseStatus
    code: str
    replayed: bool
    completed_at_ms: int
    result: dict[str, JsonValue]
    execution_fencing_token: int | None = None
    protocol_version: int = HOST_PROTOCOL_VERSION

    def __post_init__(self) -> None:
        if self.protocol_version != HOST_PROTOCOL_VERSION:
            raise HostProtocolError("UNSUPPORTED_PROTOCOL")
        _canonical_uuid(self.request_id, "request")
        if _OPERATION.fullmatch(self.operation_name) is None:
            raise HostProtocolError("INVALID_RESPONSE")
        _identifier(self.idempotency_key, "idempotency key")
        _identifier(self.host_id, "host")
        _identifier(self.host_version, "host version")
        _error_code(self.code)
        if not isinstance(self.replayed, bool):
            raise HostProtocolError("INVALID_RESPONSE")
        _positive_int(self.completed_at_ms, "completion time")
        if self.execution_fencing_token is not None:
            _positive_int(self.execution_fencing_token, "execution fencing token")
        normalized = _json_object(self.result, "operation result")
        object.__setattr__(self, "result", normalized)

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "protocol_version": self.protocol_version,
            "request_id": str(self.request_id),
            "operation_name": self.operation_name,
            "idempotency_key": self.idempotency_key,
            "host_id": self.host_id,
            "host_version": self.host_version,
            "status": self.status.value,
            "code": self.code,
            "replayed": self.replayed,
            "completed_at_ms": self.completed_at_ms,
            "execution_fencing_token": self.execution_fencing_token,
            "result": _json_object(self.result, "operation result"),
        }


@dataclass(frozen=True, slots=True)
class SignedHostResponse:
    message: HostResponseMessage
    key_id: str
    signature: str

    def __post_init__(self) -> None:
        _identifier(self.key_id, "authentication key")
        if _SIGNATURE.fullmatch(self.signature) is None:
            raise HostProtocolError("UNAUTHENTICATED")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "message": self.message.to_dict(),
            "authentication": {
                "key_id": self.key_id,
                "signature": self.signature,
            },
        }


class HostMessageAuthenticator:
    """Sign and verify bounded local protocol messages with one fixed HMAC key."""

    __slots__ = ("_key", "key_id", "_clock_ms")

    def __init__(
        self,
        secret: SecretValue,
        *,
        key_id: str,
        clock_ms: Callable[[], int] | None = None,
    ) -> None:
        key = secret.reveal().encode("utf-8")
        if len(key) < 32:
            raise HostProtocolError("HOST_NOT_READY")
        self._key = key
        self.key_id = _identifier(key_id, "authentication key")
        self._clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)

    def sign_request(self, message: HostRequestMessage) -> SignedHostRequest:
        return SignedHostRequest(
            message=message,
            key_id=self.key_id,
            signature=self._signature(_REQUEST_DOMAIN, message.to_dict()),
        )

    def verify_request(self, envelope: SignedHostRequest) -> HostRequestMessage:
        if envelope.key_id != self.key_id or not hmac.compare_digest(
            envelope.signature,
            self._signature(_REQUEST_DOMAIN, envelope.message.to_dict()),
        ):
            raise HostProtocolError("UNAUTHENTICATED")
        now = self._clock_ms()
        if envelope.message.issued_at_ms > now + MAX_HOST_CLOCK_SKEW_MS:
            raise HostProtocolError("REQUEST_EXPIRED")
        if now >= envelope.message.expires_at_ms:
            raise HostProtocolError("REQUEST_EXPIRED")
        authority = envelope.message.authority
        if isinstance(authority, TaskLeaseHostAuthority) and now >= authority.lease_expires_at_ms:
            raise HostProtocolError("LEASE_EXPIRED")
        return envelope.message

    def sign_response(self, message: HostResponseMessage) -> SignedHostResponse:
        return SignedHostResponse(
            message=message,
            key_id=self.key_id,
            signature=self._signature(_RESPONSE_DOMAIN, message.to_dict()),
        )

    def verify_response(self, envelope: SignedHostResponse) -> HostResponseMessage:
        if envelope.key_id != self.key_id or not hmac.compare_digest(
            envelope.signature,
            self._signature(_RESPONSE_DOMAIN, envelope.message.to_dict()),
        ):
            raise HostProtocolError("UNAUTHENTICATED")
        return envelope.message

    def _signature(self, domain: bytes, message: Mapping[str, JsonValue]) -> str:
        digest = hmac.new(
            self._key,
            domain + _canonical_json(message),
            hashlib.sha256,
        ).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    def __repr__(self) -> str:
        return f"HostMessageAuthenticator(key_id={self.key_id!r}, secret='[REDACTED]')"


def encode_signed_host_request(envelope: SignedHostRequest) -> bytes:
    encoded = _canonical_json(envelope.to_dict())
    if len(encoded) > MAX_HOST_REQUEST_BYTES:
        raise HostProtocolError("INVALID_REQUEST")
    return encoded


def decode_signed_host_request(payload: bytes) -> SignedHostRequest:
    root = _decode_json_object(payload, maximum=MAX_HOST_REQUEST_BYTES)
    fields = _exact_fields(root, {"message", "authentication"}, "request")
    message = _request_from_dict(_object(fields["message"], "request message"))
    authentication = _exact_fields(
        _object(fields["authentication"], "request authentication"),
        {"key_id", "signature"},
        "request authentication",
    )
    return SignedHostRequest(
        message=message,
        key_id=_string(authentication["key_id"], "authentication key"),
        signature=_string(authentication["signature"], "signature"),
    )


def encode_signed_host_response(envelope: SignedHostResponse) -> bytes:
    encoded = _canonical_json(envelope.to_dict())
    if len(encoded) > MAX_HOST_RESPONSE_BYTES:
        raise HostProtocolError("INVALID_RESPONSE")
    return encoded


def decode_signed_host_response(payload: bytes) -> SignedHostResponse:
    root = _decode_json_object(payload, maximum=MAX_HOST_RESPONSE_BYTES)
    fields = _exact_fields(root, {"message", "authentication"}, "response")
    message = _response_from_dict(_object(fields["message"], "response message"))
    authentication = _exact_fields(
        _object(fields["authentication"], "response authentication"),
        {"key_id", "signature"},
        "response authentication",
    )
    return SignedHostResponse(
        message=message,
        key_id=_string(authentication["key_id"], "authentication key"),
        signature=_string(authentication["signature"], "signature"),
    )


def normalize_host_json_object(
    value: Mapping[str, object],
) -> dict[str, JsonValue]:
    """Validate and copy one bounded protocol JSON object."""

    return _json_object(value, "host JSON object")


def validate_host_identifier(value: str) -> str:
    """Validate a host-protocol identifier at configuration boundaries."""

    return _identifier(value, "identifier")


def validate_host_response_code(value: str) -> str:
    """Validate a stable host response code read from durable storage."""

    return _error_code(value)


def validate_host_fencing_token(value: int) -> int:
    """Validate a fencing token read from durable storage."""

    return _positive_int(value, "execution fencing token")


def _request_from_dict(value: Mapping[str, object]) -> HostRequestMessage:
    fields = _exact_fields(
        value,
        {
            "protocol_version",
            "request_id",
            "issuer",
            "audience",
            "issued_at_ms",
            "expires_at_ms",
            "authority",
            "operation",
        },
        "request message",
    )
    return HostRequestMessage(
        protocol_version=_integer(fields["protocol_version"], "protocol version"),
        request_id=_uuid(fields["request_id"], "request"),
        issuer=_string(fields["issuer"], "issuer"),
        audience=_string(fields["audience"], "audience"),
        issued_at_ms=_integer(fields["issued_at_ms"], "issued time"),
        expires_at_ms=_integer(fields["expires_at_ms"], "expiry time"),
        authority=_authority_from_dict(_object(fields["authority"], "authority")),
        operation=_operation_from_dict(_object(fields["operation"], "operation")),
    )


def _response_from_dict(value: Mapping[str, object]) -> HostResponseMessage:
    fields = _exact_fields(
        value,
        {
            "protocol_version",
            "request_id",
            "operation_name",
            "idempotency_key",
            "host_id",
            "host_version",
            "status",
            "code",
            "replayed",
            "completed_at_ms",
            "execution_fencing_token",
            "result",
        },
        "response message",
    )
    try:
        status = HostResponseStatus(_string(fields["status"], "response status"))
    except ValueError:
        raise HostProtocolError("INVALID_RESPONSE") from None
    raw_token = fields["execution_fencing_token"]
    return HostResponseMessage(
        protocol_version=_integer(fields["protocol_version"], "protocol version"),
        request_id=_uuid(fields["request_id"], "request"),
        operation_name=_string(fields["operation_name"], "operation name"),
        idempotency_key=_string(fields["idempotency_key"], "idempotency key"),
        host_id=_string(fields["host_id"], "host"),
        host_version=_string(fields["host_version"], "host version"),
        status=status,
        code=_string(fields["code"], "response code"),
        replayed=_boolean(fields["replayed"], "response replay"),
        completed_at_ms=_integer(fields["completed_at_ms"], "completion time"),
        execution_fencing_token=(
            None if raw_token is None else _integer(raw_token, "execution fencing token")
        ),
        result=_json_object(
            _object(fields["result"], "operation result"),
            "operation result",
        ),
    )


def _authority_from_dict(value: Mapping[str, object]) -> HostAuthority:
    kind_text = _string(value.get("kind"), "authority kind")
    try:
        kind = HostAuthorityKind(kind_text)
    except ValueError:
        raise HostProtocolError("INVALID_AUTHORITY") from None
    if kind is HostAuthorityKind.SYSTEM:
        _exact_fields(value, {"kind"}, "system authority")
        return SystemHostAuthority()
    if kind is HostAuthorityKind.REPOSITORY:
        fields = _exact_fields(
            value,
            {
                "kind",
                "repository_key",
                "configuration_id",
                "configuration_digest",
            },
            "repository authority",
        )
        return RepositoryHostAuthority(
            repository_key=_string(fields["repository_key"], "repository"),
            configuration_id=_uuid(fields["configuration_id"], "configuration"),
            configuration_digest=_string(
                fields["configuration_digest"],
                "configuration digest",
            ),
        )
    fields = _exact_fields(
        value,
        {
            "kind",
            "task_id",
            "job_id",
            "lease_id",
            "worker_id",
            "attempt",
            "fencing_token",
            "lease_expires_at_ms",
            "repository_key",
            "configuration_id",
            "configuration_digest",
        },
        "task lease authority",
    )
    return TaskLeaseHostAuthority(
        task_id=_uuid(fields["task_id"], "task"),
        job_id=_uuid(fields["job_id"], "job"),
        lease_id=_uuid(fields["lease_id"], "lease"),
        worker_id=_string(fields["worker_id"], "worker"),
        attempt=_integer(fields["attempt"], "attempt"),
        fencing_token=_integer(fields["fencing_token"], "fencing token"),
        lease_expires_at_ms=_integer(fields["lease_expires_at_ms"], "lease expiry"),
        repository_key=_string(fields["repository_key"], "repository"),
        configuration_id=_uuid(fields["configuration_id"], "configuration"),
        configuration_digest=_string(
            fields["configuration_digest"],
            "configuration digest",
        ),
    )


def _operation_from_dict(value: Mapping[str, object]) -> HostOperation:
    fields = _exact_fields(
        value,
        {"name", "schema_version", "idempotency_key", "arguments"},
        "operation",
    )
    return HostOperation(
        name=_string(fields["name"], "operation name"),
        schema_version=_integer(fields["schema_version"], "operation schema version"),
        idempotency_key=_string(fields["idempotency_key"], "idempotency key"),
        arguments=_json_object(
            _object(fields["arguments"], "operation arguments"),
            "operation arguments",
        ),
    )


def _semantic_authority(authority: HostAuthority) -> dict[str, JsonValue]:
    value = authority.to_dict()
    if isinstance(authority, TaskLeaseHostAuthority):
        for key in (
            "lease_id",
            "worker_id",
            "attempt",
            "fencing_token",
            "lease_expires_at_ms",
        ):
            value.pop(key)
    return value


def _canonical_json(value: Mapping[str, JsonValue]) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError):
        raise HostProtocolError("INVALID_REQUEST") from None


def _decode_json_object(payload: bytes, *, maximum: int) -> dict[str, object]:
    if not payload or len(payload) > maximum:
        raise HostProtocolError("INVALID_FRAME")
    try:
        decoded = payload.decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=_unique_object,
            parse_float=_reject_number,
            parse_int=_bounded_json_integer,
            parse_constant=_reject_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        HostProtocolError,
        RecursionError,
        ValueError,
    ):
        raise HostProtocolError("INVALID_FRAME") from None
    return _object(value, "message")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise HostProtocolError("INVALID_FRAME")
        result[key] = value
    return result


def _reject_constant(_value: str) -> object:
    raise HostProtocolError("INVALID_FRAME")


def _reject_number(_value: str) -> object:
    raise HostProtocolError("INVALID_FRAME")


def _bounded_json_integer(value: str) -> int:
    if len(value) > 20:
        raise HostProtocolError("INVALID_FRAME")
    try:
        parsed = int(value)
    except ValueError:
        raise HostProtocolError("INVALID_FRAME") from None
    if not -(2**63) <= parsed < 2**63:
        raise HostProtocolError("INVALID_FRAME")
    return parsed


def _json_object(value: Mapping[str, object], field: str) -> dict[str, JsonValue]:
    nodes = [0]
    normalized = _json_value(value, field=field, depth=0, nodes=nodes)
    if not isinstance(normalized, dict):
        raise HostProtocolError("INVALID_REQUEST")
    return normalized


def _json_value(
    value: object,
    *,
    field: str,
    depth: int,
    nodes: list[int],
) -> JsonValue:
    nodes[0] += 1
    if depth > _MAX_JSON_DEPTH or nodes[0] > _MAX_JSON_NODES:
        raise HostProtocolError("INVALID_REQUEST")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not -(2**63) <= value < 2**63:
            raise HostProtocolError("INVALID_REQUEST")
        return value
    if isinstance(value, str):
        if len(value) > _MAX_STRING_LENGTH or "\x00" in value:
            raise HostProtocolError("INVALID_REQUEST")
        return value
    if isinstance(value, Mapping):
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise HostProtocolError("INVALID_REQUEST")
        result: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 255:
                raise HostProtocolError("INVALID_REQUEST")
            result[key] = _json_value(
                item,
                field=field,
                depth=depth + 1,
                nodes=nodes,
            )
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise HostProtocolError("INVALID_REQUEST")
        return [
            _json_value(
                item,
                field=field,
                depth=depth + 1,
                nodes=nodes,
            )
            for item in value
        ]
    raise HostProtocolError("INVALID_REQUEST")


def _exact_fields(
    value: Mapping[str, object],
    expected: set[str],
    _field: str,
) -> Mapping[str, object]:
    if set(value) != expected:
        raise HostProtocolError("INVALID_REQUEST")
    return value


def _object(value: object, _field: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise HostProtocolError("INVALID_REQUEST")
    return cast(dict[str, object], value)


def _string(value: object, _field: str) -> str:
    if not isinstance(value, str):
        raise HostProtocolError("INVALID_REQUEST")
    return value


def _integer(value: object, _field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise HostProtocolError("INVALID_REQUEST")
    return value


def _boolean(value: object, _field: str) -> bool:
    if not isinstance(value, bool):
        raise HostProtocolError("INVALID_RESPONSE")
    return value


def _uuid(value: object, field: str) -> UUID:
    text = _string(value, field)
    try:
        identifier = UUID(text)
    except ValueError:
        raise HostProtocolError("INVALID_REQUEST") from None
    if str(identifier) != text:
        raise HostProtocolError("INVALID_REQUEST")
    return identifier


def _canonical_uuid(value: UUID, _field: str) -> None:
    if not isinstance(value, UUID) or str(UUID(str(value))) != str(value):
        raise HostProtocolError("INVALID_REQUEST")


def _identifier(value: str, _field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise HostProtocolError("INVALID_REQUEST")
    return value


def _repository_key(value: str) -> str:
    if not isinstance(value, str) or _REPOSITORY.fullmatch(value) is None:
        raise HostProtocolError("INVALID_AUTHORITY")
    return value


def _positive_int(value: int, _field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0 or value >= 2**63:
        raise HostProtocolError("INVALID_REQUEST")
    return value


def _error_code(value: str) -> str:
    if not isinstance(value, str) or _ERROR_CODE.fullmatch(value) is None:
        raise HostProtocolError("INVALID_RESPONSE")
    return value
