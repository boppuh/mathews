import json
from dataclasses import replace
from uuid import UUID, uuid4

import pytest
from mathews_configuration import (
    HostMessageAuthenticator,
    HostOperation,
    HostProtocolError,
    HostRequestMessage,
    HostResponseMessage,
    HostResponseStatus,
    JsonValue,
    RepositoryHostAuthority,
    SecretValue,
    SignedHostRequest,
    SystemHostAuthority,
    TaskLeaseHostAuthority,
    decode_signed_host_request,
    decode_signed_host_response,
    encode_signed_host_request,
    encode_signed_host_response,
)

NOW_MS = 1_800_000_000_000


def _authenticator(
    *,
    secret: str = "a" * 32,
    now_ms: int = NOW_MS,
) -> HostMessageAuthenticator:
    return HostMessageAuthenticator(
        SecretValue(secret),
        key_id="control-plane-v1",
        clock_ms=lambda: now_ms,
    )


def _request(
    *,
    authority: (
        SystemHostAuthority | RepositoryHostAuthority | TaskLeaseHostAuthority
    )
    | None = None,
    request_id: UUID | None = None,
    issued_at_ms: int = NOW_MS,
    expires_at_ms: int = NOW_MS + 10_000,
    arguments: dict[str, JsonValue] | None = None,
) -> HostRequestMessage:
    return HostRequestMessage(
        request_id=request_id or uuid4(),
        issued_at_ms=issued_at_ms,
        expires_at_ms=expires_at_ms,
        authority=authority or SystemHostAuthority(),
        operation=HostOperation(
            name="host.health",
            idempotency_key="health-1",
            arguments=arguments or {},
        ),
    )


def _task_authority(
    *,
    lease_id: UUID | None = None,
    worker_id: str = "worker-1",
    attempt: int = 1,
    fencing_token: int = 1,
    lease_expires_at_ms: int = NOW_MS + 20_000,
) -> TaskLeaseHostAuthority:
    return TaskLeaseHostAuthority(
        task_id=UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        job_id=UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
        lease_id=lease_id or UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
        worker_id=worker_id,
        attempt=attempt,
        fencing_token=fencing_token,
        lease_expires_at_ms=lease_expires_at_ms,
        repository_key="boppuh/mathews",
        configuration_id=UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
        configuration_digest="sha256:" + "1" * 64,
    )


def test_signed_request_round_trips_and_verifies() -> None:
    authenticator = _authenticator()
    request = _request()

    decoded = decode_signed_host_request(
        encode_signed_host_request(authenticator.sign_request(request))
    )

    assert authenticator.verify_request(decoded) == request


def test_signed_response_uses_a_separate_authenticated_domain() -> None:
    authenticator = _authenticator()
    request = _request()
    response = HostResponseMessage(
        request_id=request.request_id,
        operation_name=request.operation.name,
        idempotency_key=request.operation.idempotency_key,
        host_id="host-1",
        host_version="0.1.0",
        status=HostResponseStatus.OK,
        code="OK",
        replayed=False,
        completed_at_ms=NOW_MS,
        result={"status": "ok"},
    )

    decoded = decode_signed_host_response(
        encode_signed_host_response(authenticator.sign_response(response))
    )

    assert authenticator.verify_response(decoded) == response


def test_tampered_request_and_wrong_key_are_rejected() -> None:
    authenticator = _authenticator()
    envelope = authenticator.sign_request(_request())
    tampered = SignedHostRequest(
        message=replace(
            envelope.message,
            operation=replace(envelope.message.operation, arguments={"value": 1}),
        ),
        key_id=envelope.key_id,
        signature=envelope.signature,
    )

    with pytest.raises(HostProtocolError, match="UNAUTHENTICATED"):
        authenticator.verify_request(tampered)
    with pytest.raises(HostProtocolError, match="UNAUTHENTICATED"):
        _authenticator(secret="b" * 32).verify_request(envelope)


@pytest.mark.parametrize(
    ("issued_at_ms", "expires_at_ms", "code"),
    (
        (NOW_MS - 20_000, NOW_MS, "REQUEST_EXPIRED"),
        (NOW_MS + 5_001, NOW_MS + 10_000, "REQUEST_EXPIRED"),
    ),
)
def test_request_freshness_is_bounded(
    issued_at_ms: int,
    expires_at_ms: int,
    code: str,
) -> None:
    authenticator = _authenticator()
    envelope = authenticator.sign_request(
        _request(issued_at_ms=issued_at_ms, expires_at_ms=expires_at_ms)
    )

    with pytest.raises(HostProtocolError, match=code):
        authenticator.verify_request(envelope)


def test_expired_task_lease_is_rejected_independently() -> None:
    authenticator = _authenticator()
    envelope = authenticator.sign_request(
        _request(authority=_task_authority(lease_expires_at_ms=NOW_MS))
    )

    with pytest.raises(HostProtocolError, match="LEASE_EXPIRED"):
        authenticator.verify_request(envelope)


def test_task_semantic_fingerprint_ignores_lease_takeover_fields() -> None:
    first = _request(authority=_task_authority())
    takeover = replace(
        first,
        request_id=uuid4(),
        authority=_task_authority(
            lease_id=uuid4(),
            worker_id="worker-2",
            attempt=2,
            fencing_token=2,
        ),
    )
    changed_arguments = replace(
        takeover,
        operation=replace(takeover.operation, arguments={"changed": True}),
    )

    assert first.semantic_fingerprint == takeover.semantic_fingerprint
    assert changed_arguments.semantic_fingerprint != first.semantic_fingerprint


@pytest.mark.parametrize(
    "payload",
    (
        b'{"message":{},"message":{},"authentication":{}}',
        b'{"message":NaN,"authentication":{}}',
        b'{"message":1.5,"authentication":{}}',
        b'{"message":' + b"9" * 5_000 + b',"authentication":{}}',
        b'{"message":' + b"[" * 2_000 + b"]" * 2_000 + b',"authentication":{}}',
        b"\xff",
    ),
)
def test_noncanonical_or_hostile_json_is_rejected(payload: bytes) -> None:
    with pytest.raises(HostProtocolError):
        decode_signed_host_request(payload)


def test_unknown_fields_and_non_v4_request_ids_are_rejected() -> None:
    authenticator = _authenticator()
    encoded = encode_signed_host_request(authenticator.sign_request(_request()))
    value = json.loads(encoded)
    value["message"]["unexpected"] = True

    with pytest.raises(HostProtocolError, match="INVALID_REQUEST"):
        decode_signed_host_request(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        )
    with pytest.raises(HostProtocolError, match="INVALID_REQUEST"):
        _request(request_id=UUID("aaaaaaaa-aaaa-1aaa-8aaa-aaaaaaaaaaaa"))
    with pytest.raises(HostProtocolError, match="INVALID_OPERATION"):
        HostOperation(
            name="host.health",
            idempotency_key="future-schema",
            arguments={},
            schema_version=2,
        )


def test_authenticator_requires_a_dedicated_strong_secret_and_redacts_repr() -> None:
    with pytest.raises(HostProtocolError, match="HOST_NOT_READY"):
        _authenticator(secret="too-short")

    representation = repr(_authenticator(secret="sensitive-" + "x" * 32))

    assert "sensitive" not in representation
    assert "REDACTED" in representation
