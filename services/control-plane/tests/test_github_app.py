import hashlib
import hmac
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mathews_configuration import (
    GITHUB_APP_PERMISSIONS,
    GITHUB_WEBHOOK_EVENTS,
    GitHubAppConfiguration,
    GitHubCredentialPurpose,
    SecretReference,
    SecretValue,
    github_token_permissions,
)
from mathews_control_plane.github_app import (
    GITHUB_API_VERSION,
    GitHubAppCredentialBroker,
    GitHubAuthorizationError,
    GitHubCredentialCleanupError,
    GitHubHttpResponse,
    GitHubPermissionError,
    GitHubProtocolError,
    GitHubRateLimitError,
    GitHubUnavailableError,
    GitHubWebhookVerificationError,
    GitHubWebhookVerifier,
    UrllibGitHubTransport,
)

_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
_PRIVATE_KEY_REF = SecretReference.parse(
    "keychain://com.boppuh.mathews.github-app/private-key"
)
_WEBHOOK_SECRET_REF = SecretReference.parse(
    "keychain://com.boppuh.mathews.github-app/webhook-secret"
)


class StaticSecretProvider:
    def __init__(
        self,
        *,
        private_key: str = "private-key",
        webhook_secret: str = "0123456789abcdef",
    ):
        self.private_key = private_key
        self.webhook_secret = webhook_secret
        self.requested: list[SecretReference] = []

    def get(self, reference: SecretReference) -> SecretValue:
        self.requested.append(reference)
        if reference == _PRIVATE_KEY_REF:
            return SecretValue(self.private_key)
        if reference == _WEBHOOK_SECRET_REF:
            return SecretValue(self.webhook_secret)
        raise AssertionError("unexpected secret reference")


class FailingSecretProvider:
    def get(self, reference: SecretReference) -> SecretValue:
        raise RuntimeError(f"must-not-leak:{reference.account}")


@dataclass(frozen=True)
class RecordedRequest:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes | None
    timeout_seconds: float


class QueueTransport:
    def __init__(self, *responses: GitHubHttpResponse):
        self.responses = list(responses)
        self.requests: list[RecordedRequest] = []

    def request(
        self,
        *,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> GitHubHttpResponse:
        self.requests.append(
            RecordedRequest(
                method=method,
                path=path,
                headers=dict(headers),
                body=body,
                timeout_seconds=timeout_seconds,
            )
        )
        if not self.responses:
            raise AssertionError("unexpected GitHub request")
        return self.responses.pop(0)


def _configuration() -> GitHubAppConfiguration:
    return GitHubAppConfiguration(
        app_id=101,
        installation_id=202,
        repository_id=303,
        repository_key="boppuh/mathews",
        private_key_ref=_PRIVATE_KEY_REF,
        webhook_secret_ref=_WEBHOOK_SECRET_REF,
    )


def _json_response(status: int, value: object) -> GitHubHttpResponse:
    return GitHubHttpResponse(
        status_code=status,
        content_type="application/json",
        body=json.dumps(value, separators=(",", ":")).encode(),
    )


def _installation_response(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "id": 202,
        "app_id": 101,
        "suspended_at": None,
        "repository_selection": "selected",
        "permissions": dict(GITHUB_APP_PERMISSIONS),
        "events": list(GITHUB_WEBHOOK_EVENTS),
    }
    value.update(overrides)
    return value


def _token_response(
    purpose: GitHubCredentialPurpose,
    **overrides: object,
) -> dict[str, object]:
    value: dict[str, object] = {
        "token": "ghs_test_installation_token",
        "expires_at": (_NOW + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "permissions": github_token_permissions(purpose),
        "repositories": [{"id": 303, "full_name": "Boppuh/Mathews"}],
    }
    value.update(overrides)
    return value


def _audit_token_response(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "token": "ghs_metadata_audit_token",
        "expires_at": (_NOW + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "permissions": {"metadata": "read"},
        "repository_selection": "selected",
        "repositories": [{"id": 303, "full_name": "Boppuh/Mathews"}],
    }
    value.update(overrides)
    return value


def _no_content_response() -> GitHubHttpResponse:
    return GitHubHttpResponse(status_code=204, content_type=None, body=b"")


def _verification_responses(
    *,
    installation: dict[str, object] | None = None,
    audit: dict[str, object] | None = None,
) -> tuple[GitHubHttpResponse, ...]:
    return (
        _json_response(200, [installation or _installation_response()]),
        _json_response(201, audit or _audit_token_response()),
        _no_content_response(),
    )


def _token_transport(
    response: GitHubHttpResponse,
    *,
    cleanup: bool = False,
) -> QueueTransport:
    trailing = (_no_content_response(),) if cleanup else ()
    return QueueTransport(*_verification_responses(), response, *trailing)


def _broker(
    transport: QueueTransport,
    *,
    provider: StaticSecretProvider | FailingSecretProvider | None = None,
    sleeper: Callable[[float], None] | None = None,
) -> tuple[GitHubAppCredentialBroker, list[tuple[dict[str, int | str], str]]]:
    signed: list[tuple[dict[str, int | str], str]] = []

    def signer(claims: Mapping[str, int | str], key: str) -> str:
        signed.append((dict(claims), key))
        return "app.jwt.signature"

    return (
        GitHubAppCredentialBroker(
            _configuration(),
            secret_provider=provider or StaticSecretProvider(),
            transport=transport,
            clock=lambda: _NOW,
            signer=signer,
            sleeper=sleeper or (lambda _seconds: None),
        ),
        signed,
    )


def test_installation_attestation_requires_exact_least_privilege_manifest() -> None:
    transport = QueueTransport(*_verification_responses())
    broker, signed = _broker(transport)

    attestation = broker.verify_installation()

    assert attestation.to_dict() == {
        "app_id": 101,
        "installation_id": 202,
        "repository_id": 303,
        "repository_key": "boppuh/mathews",
        "repository_selection": "selected",
        "permissions": dict(GITHUB_APP_PERMISSIONS),
        "events": sorted(GITHUB_WEBHOOK_EVENTS),
    }
    assert signed == [
        (
            {
                "iat": int((_NOW - timedelta(seconds=60)).timestamp()),
                "exp": int((_NOW + timedelta(minutes=9)).timestamp()),
                "iss": "101",
            },
            "private-key",
        )
    ]
    assert [(request.method, request.path) for request in transport.requests] == [
        ("GET", "/app/installations"),
        ("POST", "/app/installations/202/access_tokens"),
        ("DELETE", "/installation/token"),
    ]
    assert transport.requests[0].headers == {
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer app.jwt.signature",
        "User-Agent": "mathews-control-plane",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }
    assert transport.requests[0].body is None
    assert transport.requests[1].headers == {
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer app.jwt.signature",
        "Content-Type": "application/json",
        "User-Agent": "mathews-control-plane",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }
    assert json.loads(transport.requests[1].body or b"") == {
        "permissions": {"metadata": "read"}
    }
    assert transport.requests[2].headers == {
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer ghs_metadata_audit_token",
        "User-Agent": "mathews-control-plane",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }
    assert transport.requests[2].body is None
    assert all(request.timeout_seconds == 10 for request in transport.requests)


@pytest.mark.parametrize(
    "overrides",
    [
        {"id": 999},
        {"app_id": 999},
        {"suspended_at": "2026-07-30T00:00:00Z"},
        {"repository_selection": "all"},
        {"permissions": {**dict(GITHUB_APP_PERMISSIONS), "administration": "read"}},
        {"permissions": {"metadata": "read"}},
        {"events": [*GITHUB_WEBHOOK_EVENTS, "release"]},
        {"events": [*GITHUB_WEBHOOK_EVENTS, GITHUB_WEBHOOK_EVENTS[0]]},
    ],
)
def test_installation_attestation_rejects_broader_or_mismatched_authority(
    overrides: dict[str, object],
) -> None:
    transport = QueueTransport(
        _json_response(200, [_installation_response(**overrides)])
    )
    broker, _signed = _broker(transport)

    with pytest.raises(GitHubPermissionError):
        broker.verify_installation()

    assert len(transport.requests) == 1


def test_installation_attestation_rejects_a_second_app_installation() -> None:
    transport = QueueTransport(
        _json_response(
            200,
            [
                _installation_response(),
                _installation_response(id=999),
            ],
        )
    )
    broker, _signed = _broker(transport)

    with pytest.raises(GitHubPermissionError, match="exactly one installation"):
        broker.verify_installation()


@pytest.mark.parametrize(
    "repositories",
    [
        [],
        [{"id": 404, "full_name": "boppuh/other"}],
        [
            {"id": 303, "full_name": "boppuh/mathews"},
            {"id": 404, "full_name": "boppuh/other"},
        ],
    ],
)
def test_installation_attestation_rejects_unrelated_repository_authority(
    repositories: list[dict[str, object]],
) -> None:
    transport = QueueTransport(
        *_verification_responses(
            audit=_audit_token_response(repositories=repositories)
        )
    )
    broker, _signed = _broker(transport)

    with pytest.raises(GitHubPermissionError):
        broker.verify_installation()

    assert transport.requests[-1].path == "/installation/token"


def test_audit_token_revocation_retries_transient_failures() -> None:
    sleeps: list[float] = []
    transport = QueueTransport(
        _json_response(200, [_installation_response()]),
        _json_response(201, _audit_token_response()),
        GitHubHttpResponse(
            status_code=500,
            content_type="application/json",
            body=b'{"message":"temporary"}',
        ),
        GitHubHttpResponse(
            status_code=429,
            content_type="application/json",
            body=b'{"message":"slow down"}',
            retry_after="2",
        ),
        _no_content_response(),
    )
    broker, _signed = _broker(transport, sleeper=sleeps.append)

    broker.verify_installation()

    assert sleeps == [1.0, 2.0]
    assert [request.path for request in transport.requests[-3:]] == [
        "/installation/token",
        "/installation/token",
        "/installation/token",
    ]


@pytest.mark.parametrize("status_code", [404, 500])
def test_audit_token_revocation_failure_is_an_explicit_cleanup_error(
    status_code: int,
) -> None:
    sleeps: list[float] = []
    failures = tuple(
        GitHubHttpResponse(
            status_code=status_code,
            content_type="application/json",
            body=b'{"message":"must-not-leak"}',
        )
        for _ in range(3)
    )
    transport = QueueTransport(
        _json_response(200, [_installation_response()]),
        _json_response(201, _audit_token_response()),
        *failures,
    )
    broker, _signed = _broker(transport, sleeper=sleeps.append)

    with pytest.raises(GitHubCredentialCleanupError) as error:
        broker.verify_installation()

    assert str(error.value) == "github credential cleanup remains uncertain"
    assert "must-not-leak" not in str(error.value)
    assert sleeps == [1.0, 2.0]


def test_cleanup_never_retries_before_a_long_server_directed_delay() -> None:
    sleeps: list[float] = []
    transport = QueueTransport(
        _json_response(200, [_installation_response()]),
        _json_response(201, _audit_token_response()),
        GitHubHttpResponse(
            status_code=429,
            content_type="application/json",
            body=b'{"message":"slow down"}',
            retry_after="61",
        ),
    )
    broker, _signed = _broker(transport, sleeper=sleeps.append)

    with pytest.raises(GitHubCredentialCleanupError):
        broker.verify_installation()

    assert sleeps == []
    assert len(transport.requests) == 3


def test_cleanup_treats_an_invalid_token_as_already_revoked() -> None:
    transport = QueueTransport(
        _json_response(200, [_installation_response()]),
        _json_response(201, _audit_token_response()),
        GitHubHttpResponse(
            status_code=401,
            content_type="application/json",
            body=b'{"message":"bad credentials"}',
        ),
    )
    broker, _signed = _broker(transport)

    broker.verify_installation()

    assert len(transport.requests) == 3


def test_token_mint_rechecks_installation_before_requesting_a_credential() -> None:
    transport = QueueTransport(
        _json_response(
            200,
            [
                _installation_response(
                    permissions={
                        **dict(GITHUB_APP_PERMISSIONS),
                        "administration": "read",
                    }
                )
            ],
        )
    )
    broker, _signed = _broker(transport)

    with pytest.raises(GitHubPermissionError):
        broker.mint_installation_token(GitHubCredentialPurpose.OBSERVE)

    assert [request.path for request in transport.requests] == [
        "/app/installations"
    ]


@pytest.mark.parametrize("purpose", list(GitHubCredentialPurpose))
def test_installation_token_is_scoped_to_one_repository_and_one_purpose(
    purpose: GitHubCredentialPurpose,
) -> None:
    transport = _token_transport(_json_response(201, _token_response(purpose)))
    broker, _signed = _broker(transport)

    credential = broker.mint_installation_token(purpose)

    assert credential.github_authorization_header() == "Bearer ghs_test_installation_token"
    assert credential.purpose is purpose
    assert credential.repository_id == 303
    assert credential.repository_key == "boppuh/mathews"
    assert credential.expires_at == _NOW + timedelta(hours=1)
    assert credential.safe_summary() == {
        "credential": "[REDACTED]",
        "purpose": purpose.value,
        "repository_id": 303,
        "repository_key": "boppuh/mathews",
        "expires_at": (_NOW + timedelta(hours=1)).isoformat(),
        "permissions": github_token_permissions(purpose),
    }
    rendered = f"{credential!r} {credential} {credential.safe_summary()}"
    assert "ghs_test_installation_token" not in rendered

    request = transport.requests[3]
    assert request.method == "POST"
    assert request.path == "/app/installations/202/access_tokens"
    assert json.loads(request.body or b"") == {
        "permissions": github_token_permissions(purpose),
        "repository_ids": [303],
    }
    assert request.headers["Content-Type"] == "application/json"


@pytest.mark.parametrize(
    "overrides",
    [
        {"permissions": {"contents": "write", "administration": "read"}},
        {"repositories": []},
        {
            "repositories": [
                {"id": 303, "full_name": "boppuh/mathews"},
                {"id": 404, "full_name": "boppuh/other"},
            ]
        },
        {"repositories": [{"id": 404, "full_name": "boppuh/mathews"}]},
        {"repositories": [{"id": 303, "full_name": "boppuh/other"}]},
        {"expires_at": (_NOW + timedelta(days=1)).isoformat()},
        {"expires_at": (_NOW + timedelta(seconds=10)).isoformat()},
    ],
)
def test_installation_token_rejects_excess_authority_or_invalid_binding(
    overrides: dict[str, object],
) -> None:
    purpose = GitHubCredentialPurpose.PULL_REQUEST_WRITE
    transport = _token_transport(
        _json_response(201, _token_response(purpose, **overrides)),
        cleanup=True,
    )
    broker, _signed = _broker(transport)

    with pytest.raises((GitHubPermissionError, GitHubProtocolError)):
        broker.mint_installation_token(purpose)

    assert transport.requests[-1].path == "/installation/token"
    assert (
        transport.requests[-1].headers["Authorization"]
        == "Bearer ghs_test_installation_token"
    )


def test_installation_token_accepts_only_implicit_metadata_in_addition_to_purpose() -> None:
    purpose = GitHubCredentialPurpose.PULL_REQUEST_WRITE
    response = _token_response(
        purpose,
        permissions={**github_token_permissions(purpose), "metadata": "read"},
    )
    transport = _token_transport(_json_response(201, response))
    broker, _signed = _broker(transport)

    credential = broker.mint_installation_token(purpose)

    assert dict(credential.permissions) == {
        "metadata": "read",
        "pull_requests": "write",
    }


def test_installation_token_can_be_explicitly_revoked_after_bounded_use() -> None:
    purpose = GitHubCredentialPurpose.PULL_REQUEST_WRITE
    transport = _token_transport(
        _json_response(201, _token_response(purpose)),
        cleanup=True,
    )
    broker, _signed = _broker(transport)
    credential = broker.mint_installation_token(purpose)

    broker.revoke_installation_token(credential)

    assert transport.requests[-1].method == "DELETE"
    assert transport.requests[-1].path == "/installation/token"
    assert transport.requests[-1].headers["Authorization"] == (
        "Bearer ghs_test_installation_token"
    )


def test_real_signer_uses_rs256_with_bounded_github_claims() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    transport = QueueTransport(*_verification_responses())
    broker = GitHubAppCredentialBroker(
        _configuration(),
        secret_provider=StaticSecretProvider(private_key=private_pem),
        transport=transport,
        clock=lambda: _NOW,
    )

    broker.verify_installation()

    encoded = transport.requests[0].headers["Authorization"].removeprefix("Bearer ")
    assert jwt.get_unverified_header(encoded) == {"alg": "RS256", "typ": "JWT"}
    claims = jwt.decode(
        encoded,
        public_pem,
        algorithms=["RS256"],
        issuer="101",
        options={"verify_exp": False, "verify_iat": False},
    )
    assert claims == {
        "exp": int((_NOW + timedelta(minutes=9)).timestamp()),
        "iat": int((_NOW - timedelta(seconds=60)).timestamp()),
        "iss": "101",
    }


@pytest.mark.parametrize(
    ("status_code", "error_type"),
    [
        (401, GitHubAuthorizationError),
        (404, GitHubAuthorizationError),
        (500, GitHubUnavailableError),
        (302, GitHubProtocolError),
    ],
)
def test_github_failures_do_not_expose_response_or_credentials(
    status_code: int,
    error_type: type[Exception],
) -> None:
    provider = StaticSecretProvider(private_key="must-not-leak-private-key")
    transport = QueueTransport(
        GitHubHttpResponse(
            status_code=status_code,
            content_type="application/json",
            body=b'{"message":"must-not-leak-response"}',
        )
    )
    broker, _signed = _broker(transport, provider=provider)

    with pytest.raises(error_type) as error:
        broker.verify_installation()

    rendered = str(error.value)
    assert "must-not-leak" not in rendered


@pytest.mark.parametrize(
    "response",
    [
        GitHubHttpResponse(
            status_code=429,
            content_type="application/json",
            body=b'{"message":"slow down"}',
            retry_after="17",
        ),
        GitHubHttpResponse(
            status_code=403,
            content_type="application/json",
            body=b'{"message":"rate limited"}',
            rate_limit_remaining="0",
            rate_limit_reset=str(int((_NOW + timedelta(seconds=23)).timestamp())),
        ),
        GitHubHttpResponse(
            status_code=403,
            content_type="application/json",
            body=b'{"message":"secondary rate limit"}',
        ),
    ],
)
def test_rate_limits_are_retryable_with_bounded_server_delay(
    response: GitHubHttpResponse,
) -> None:
    broker, _signed = _broker(QueueTransport(response))

    with pytest.raises(GitHubRateLimitError) as error:
        broker.verify_installation()

    assert error.value.retry_after_seconds in {17, 23, 60}
    assert str(error.value) == "github rate limit requires a delayed retry"


def test_http_response_repr_never_contains_token_body() -> None:
    response = GitHubHttpResponse(
        status_code=201,
        content_type="application/json",
        body=b'{"token":"ghs_must_not_render"}',
    )

    assert "ghs_must_not_render" not in repr(response)
    assert "body=" not in repr(response)


def test_invalid_or_unavailable_private_key_fails_with_fixed_error() -> None:
    broker, _signed = _broker(
        QueueTransport(), provider=FailingSecretProvider()
    )

    with pytest.raises(GitHubAuthorizationError) as error:
        broker.verify_installation()

    assert str(error.value) == "github app private key is unavailable or invalid"
    assert "must-not-leak" not in str(error.value)


def test_webhook_verifier_accepts_github_documented_hmac_vector() -> None:
    body = b"Hello, World!"
    provider = StaticSecretProvider(webhook_secret="It's a Secret to Everybody")
    verifier = GitHubWebhookVerifier(
        _configuration(),
        secret_provider=provider,
    )

    proof = verifier.verify(
        signature_header=(
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
        ),
        body=body,
    )

    assert proof.to_dict() == {
        "algorithm": "HMAC-SHA256",
        "body_sha256": f"sha256:{hashlib.sha256(body).hexdigest()}",
        "body_bytes": len(body),
    }
    assert provider.requested == [_WEBHOOK_SECRET_REF]


@pytest.mark.parametrize(
    ("signature", "body", "code"),
    [
        (None, b"{}", "webhook.signature_missing"),
        ("sha1=" + "0" * 40, b"{}", "webhook.signature_malformed"),
        ("sha256=" + "A" * 64, b"{}", "webhook.signature_malformed"),
        ("sha256=" + "0" * 63, b"{}", "webhook.signature_malformed"),
        (" sha256=" + "0" * 64, b"{}", "webhook.signature_malformed"),
        ("sha256=" + "0" * 64 + ",sha256=" + "1" * 64, b"{}", "webhook.signature_malformed"),
        ("sha256=" + "0" * 64, b"", "webhook.body_invalid"),
    ],
)
def test_webhook_verifier_rejects_missing_or_malformed_input_without_secret_lookup(
    signature: str | None,
    body: bytes,
    code: str,
) -> None:
    provider = StaticSecretProvider()
    verifier = GitHubWebhookVerifier(_configuration(), secret_provider=provider)

    with pytest.raises(GitHubWebhookVerificationError) as error:
        verifier.verify(signature_header=signature, body=body)

    assert error.value.code == code
    assert provider.requested == []


def test_webhook_verifier_rejects_changed_or_oversized_body() -> None:
    provider = StaticSecretProvider(webhook_secret="high-entropy-webhook-secret")
    verifier = GitHubWebhookVerifier(
        _configuration(),
        secret_provider=provider,
        maximum_body_bytes=16,
    )
    original = b'{"safe":true}'
    signature = "sha256=" + hmac.new(
        b"high-entropy-webhook-secret", original, hashlib.sha256
    ).hexdigest()

    with pytest.raises(
        GitHubWebhookVerificationError, match="webhook.signature_mismatch"
    ):
        verifier.verify(signature_header=signature, body=b'{"safe":false}')
    with pytest.raises(GitHubWebhookVerificationError, match="webhook.body_too_large"):
        verifier.verify(signature_header="sha256=" + "0" * 64, body=b"x" * 17)


def test_webhook_verifier_rejects_a_short_secret_without_exposing_it() -> None:
    verifier = GitHubWebhookVerifier(
        _configuration(),
        secret_provider=StaticSecretProvider(webhook_secret="too-short"),
    )

    with pytest.raises(GitHubWebhookVerificationError) as error:
        verifier.verify(signature_header="sha256=" + "0" * 64, body=b"{}")

    assert error.value.code == "webhook.secret_invalid"
    assert "too-short" not in str(error.value)


def test_webhook_secret_failure_does_not_expose_body_or_reference() -> None:
    verifier = GitHubWebhookVerifier(
        _configuration(),
        secret_provider=FailingSecretProvider(),
    )
    body = b'{"credential":"must-not-leak-body"}'

    with pytest.raises(GitHubWebhookVerificationError) as error:
        verifier.verify(signature_header="sha256=" + "0" * 64, body=body)

    assert error.value.code == "webhook.secret_unavailable"
    assert "must-not-leak" not in str(error.value)
    assert "webhook-secret" not in str(error.value)


def test_urllib_transport_rejects_non_github_request_shapes_before_network() -> None:
    transport = UrllibGitHubTransport()

    for method, path, timeout in (
        ("DELETE", "/repos/boppuh/mathews", 10),
        ("GET", "https://example.test", 10),
        ("GET", "//example.test/path", 10),
        ("GET", "/repos/boppuh/mathews?token=secret", 10),
        ("GET", "/repos/boppuh/mathews", 31),
    ):
        with pytest.raises(GitHubProtocolError):
            transport.request(
                method=method,
                path=path,
                headers={},
                body=None,
                timeout_seconds=timeout,
            )
