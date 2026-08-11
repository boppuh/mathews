"""Repository-scoped GitHub App authentication and webhook verification."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.client import HTTPMessage
from typing import IO, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

import jwt
from mathews_configuration import (
    GITHUB_APP_PERMISSIONS,
    GITHUB_WEBHOOK_EVENTS,
    GitHubAppConfiguration,
    GitHubCredentialPurpose,
    SecretProvider,
    SecretValue,
    github_token_permissions,
)

from mathews_control_plane.settings import AutomationConfiguration

GITHUB_API_VERSION = "2026-03-10"
GITHUB_API_ORIGIN = "https://api.github.com"
MAX_GITHUB_RESPONSE_BYTES = 1_048_576
MAX_GITHUB_WEBHOOK_BYTES = 1_048_576
_JWT_LIFETIME = timedelta(minutes=9)
_JWT_BACKDATE = timedelta(seconds=60)
_TOKEN_MINIMUM_LIFETIME = timedelta(seconds=30)
_TOKEN_MAXIMUM_LIFETIME = timedelta(minutes=65)
_TOKEN_PATTERN = re.compile(r"[^\s\x00]{1,8192}")
_SIGNATURE_PATTERN = re.compile(r"sha256=[0-9a-f]{64}")

Clock = Callable[[], datetime]
JwtSigner = Callable[[Mapping[str, int | str], str], str]
Sleeper = Callable[[float], None]


class GitHubAppError(RuntimeError):
    """Base error that never includes GitHub response or credential bytes."""


class GitHubUnavailableError(GitHubAppError):
    """Raised when GitHub cannot be reached or returns a transient failure."""


class GitHubRateLimitError(GitHubUnavailableError):
    """Retryable GitHub throttle with a bounded server-directed delay."""

    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__("github rate limit requires a delayed retry")


class GitHubAuthorizationError(GitHubAppError):
    """Raised when configured GitHub App authority is rejected."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        self.status_code = status_code
        super().__init__(message)


class GitHubProtocolError(GitHubAppError):
    """Raised when GitHub violates the bounded response contract."""


class GitHubPermissionError(GitHubAppError):
    """Raised when installation authority is broader or different than allowed."""


class GitHubCredentialCleanupError(GitHubAppError):
    """Raised when a minted credential's revocation remains uncertain."""


class GitHubWebhookVerificationError(GitHubAppError):
    """Raised before an unverified webhook body can be parsed or persisted."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class GitHubHttpResponse:
    status_code: int
    content_type: str | None
    body: bytes = field(repr=False)
    retry_after: str | None = None
    rate_limit_remaining: str | None = None
    rate_limit_reset: str | None = None


class GitHubHttpTransport(Protocol):
    """Narrow transport used only against the fixed GitHub API origin."""

    def request(
        self,
        *,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> GitHubHttpResponse:
        """Send one bounded request without following redirects."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> Request | None:
        return None


class UrllibGitHubTransport:
    """HTTPS-only GitHub transport with redirect and response-size denial."""

    def request(
        self,
        *,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> GitHubHttpResponse:
        if (
            method not in {"DELETE", "GET", "POST"}
            or not path.startswith("/")
            or path.startswith("//")
            or "?" in path
            or "#" in path
            or (method == "DELETE" and path != "/installation/token")
        ):
            raise GitHubProtocolError("github request shape is not allowlisted")
        if timeout_seconds <= 0 or timeout_seconds > 30:
            raise GitHubProtocolError("github request timeout is not allowlisted")

        request = Request(
            f"{GITHUB_API_ORIGIN}{path}",
            data=body,
            headers=dict(headers),
            method=method,
        )
        opener = build_opener(_NoRedirectHandler())
        try:
            with opener.open(request, timeout=timeout_seconds) as response:
                return GitHubHttpResponse(
                    status_code=response.status,
                    content_type=response.headers.get_content_type(),
                    body=_read_bounded(response),
                    retry_after=response.headers.get("Retry-After"),
                    rate_limit_remaining=response.headers.get("X-RateLimit-Remaining"),
                    rate_limit_reset=response.headers.get("X-RateLimit-Reset"),
                )
        except HTTPError as error:
            with error:
                return GitHubHttpResponse(
                    status_code=error.code,
                    content_type=error.headers.get_content_type(),
                    body=_read_bounded(error),
                    retry_after=error.headers.get("Retry-After"),
                    rate_limit_remaining=error.headers.get("X-RateLimit-Remaining"),
                    rate_limit_reset=error.headers.get("X-RateLimit-Reset"),
                )
        except (OSError, TimeoutError, URLError):
            raise GitHubUnavailableError("github request failed") from None


@dataclass(frozen=True, slots=True)
class GitHubInstallationAttestation:
    """Credential-free proof of the exact installed authority."""

    app_id: int
    installation_id: int
    repository_id: int
    repository_key: str
    repository_selection: str
    permissions: tuple[tuple[str, str], ...]
    events: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "app_id": self.app_id,
            "installation_id": self.installation_id,
            "repository_id": self.repository_id,
            "repository_key": self.repository_key,
            "repository_selection": self.repository_selection,
            "permissions": dict(self.permissions),
            "events": list(self.events),
        }


@dataclass(frozen=True, slots=True)
class GitHubInstallationCredential:
    """Short-lived credential whose rendering and diagnostics are redacted."""

    _token: SecretValue
    purpose: GitHubCredentialPurpose
    repository_id: int
    repository_key: str
    expires_at: datetime
    permissions: tuple[tuple[str, str], ...]

    def github_authorization_header(self) -> str:
        """Reveal the token only at the allowlisted GitHub HTTP boundary."""

        return f"Bearer {self._token.reveal()}"

    def safe_summary(self) -> dict[str, object]:
        return {
            "credential": "[REDACTED]",
            "purpose": self.purpose.value,
            "repository_id": self.repository_id,
            "repository_key": self.repository_key,
            "expires_at": self.expires_at.isoformat(),
            "permissions": dict(self.permissions),
        }

    def __str__(self) -> str:
        return "[REDACTED]"


@dataclass(frozen=True, slots=True)
class VerifiedGitHubWebhook:
    """Proof over the exact raw body without retaining or parsing the body."""

    algorithm: str
    body_sha256: str
    body_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "algorithm": self.algorithm,
            "body_sha256": self.body_sha256,
            "body_bytes": self.body_bytes,
        }


def build_github_app_configuration(
    automation: AutomationConfiguration,
    *,
    repository_key: str,
) -> GitHubAppConfiguration:
    """Bind environment credentials to the versioned repository identity."""

    return GitHubAppConfiguration(
        app_id=automation.github_app_id,
        installation_id=automation.github_installation_id,
        repository_id=automation.github_repository_id,
        repository_key=repository_key,
        private_key_ref=automation.github_private_key_ref,
        webhook_secret_ref=automation.github_webhook_secret_ref,
    )


class GitHubAppCredentialBroker:
    """Mint purpose-scoped installation tokens after authority verification."""

    def __init__(
        self,
        configuration: GitHubAppConfiguration,
        *,
        secret_provider: SecretProvider,
        transport: GitHubHttpTransport | None = None,
        clock: Clock | None = None,
        signer: JwtSigner | None = None,
        sleeper: Sleeper | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        if timeout_seconds <= 0 or timeout_seconds > 30:
            raise ValueError("GitHub timeout must be greater than zero and at most 30 seconds")
        self._configuration = configuration
        self._secret_provider = secret_provider
        self._transport = transport or UrllibGitHubTransport()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._signer = signer or _sign_github_jwt
        self._sleeper = sleeper or time.sleep
        self._timeout_seconds = timeout_seconds

    def verify_installation(self) -> GitHubInstallationAttestation:
        """Fail closed unless the installation exactly matches the frozen manifest."""

        app_jwt = self._app_jwt()
        installations = self._request_json_array(
            method="GET",
            path="/app/installations",
            authorization=f"Bearer {app_jwt}",
            body=None,
            success_status=200,
        )
        if len(installations) != 1 or not isinstance(installations[0], dict):
            raise GitHubPermissionError(
                "github app must have exactly one installation"
            )
        installation = cast(dict[str, object], installations[0])
        if _integer(installation, "id") != self._configuration.installation_id:
            raise GitHubPermissionError("github installation identity mismatch")
        if _integer(installation, "app_id") != self._configuration.app_id:
            raise GitHubPermissionError("github app identity mismatch")
        if installation.get("suspended_at") is not None:
            raise GitHubPermissionError("github installation is suspended")
        if installation.get("repository_selection") != "selected":
            raise GitHubPermissionError(
                "github installation must select repositories explicitly"
            )

        permissions = _string_mapping(installation.get("permissions"), "permissions")
        expected_permissions = dict(GITHUB_APP_PERMISSIONS)
        if permissions != expected_permissions:
            raise GitHubPermissionError("github installation permissions do not match policy")

        events = _string_tuple(installation.get("events"), "events")
        if len(events) != len(set(events)) or set(events) != set(GITHUB_WEBHOOK_EVENTS):
            raise GitHubPermissionError("github webhook subscriptions do not match policy")

        # Mint a metadata-only audit token without repository_ids so GitHub
        # returns the installation's complete selected repository set. Revoke
        # it immediately after checking that the App-wide private key has no
        # unrelated installation or repository authority.
        audit_response = self._request_json(
            method="POST",
            path=(
                f"/app/installations/{self._configuration.installation_id}"
                "/access_tokens"
            ),
            authorization=f"Bearer {app_jwt}",
            body=_canonical_json_bytes({"permissions": {"metadata": "read"}}),
            success_status=201,
        )
        audit_token = audit_response.get("token")
        if not isinstance(audit_token, str) or _TOKEN_PATTERN.fullmatch(audit_token) is None:
            raise GitHubProtocolError("github audit token response is invalid")
        try:
            audit_expires_at = _timestamp(
                audit_response.get("expires_at"), "expires_at"
            )
            audit_lifetime = audit_expires_at - _aware_utc(self._clock())
            if not (
                _TOKEN_MINIMUM_LIFETIME
                < audit_lifetime
                <= _TOKEN_MAXIMUM_LIFETIME
            ):
                raise GitHubProtocolError("github audit token lifetime is invalid")
            if _string_mapping(
                audit_response.get("permissions"), "permissions"
            ) != {"metadata": "read"}:
                raise GitHubPermissionError(
                    "github audit token permissions exceed metadata read"
                )
            if audit_response.get("repository_selection") != "selected":
                raise GitHubPermissionError(
                    "github audit token repository selection mismatch"
                )
            self._require_exact_repository_scope(audit_response)
        finally:
            self._revoke_installation_token(audit_token)

        return GitHubInstallationAttestation(
            app_id=self._configuration.app_id,
            installation_id=self._configuration.installation_id,
            repository_id=self._configuration.repository_id,
            repository_key=self._configuration.repository_key,
            repository_selection="selected",
            permissions=tuple(sorted(permissions.items())),
            events=tuple(sorted(events)),
        )

    def _revoke_installation_token(self, token: str) -> None:
        for attempt in range(3):
            try:
                response = self._request(
                    method="DELETE",
                    path="/installation/token",
                    authorization=f"Bearer {token}",
                    body=None,
                    success_status=204,
                )
                if response.body:
                    raise GitHubProtocolError(
                        "github token revocation returned a body"
                    )
                return
            except GitHubAuthorizationError as error:
                if error.status_code == 401:
                    # An invalid installation token has no remaining authority.
                    return
                if attempt == 2:
                    raise GitHubCredentialCleanupError(
                        "github credential cleanup remains uncertain"
                    ) from None
                self._sleeper(float(2**attempt))
            except (GitHubUnavailableError, GitHubProtocolError) as error:
                if attempt == 2:
                    raise GitHubCredentialCleanupError(
                        "github credential cleanup remains uncertain"
                    ) from None
                delay = (
                    error.retry_after_seconds
                    if isinstance(error, GitHubRateLimitError)
                    else 2**attempt
                )
                if delay > 60:
                    raise GitHubCredentialCleanupError(
                        "github credential cleanup remains uncertain"
                    ) from None
                self._sleeper(float(delay))
        raise AssertionError("unreachable")

    def _require_exact_repository_scope(
        self,
        response: Mapping[str, object],
    ) -> None:
        repositories = response.get("repositories")
        if not isinstance(repositories, list) or len(repositories) != 1:
            raise GitHubPermissionError(
                "github authority is not restricted to one repository"
            )
        repository = repositories[0]
        if not isinstance(repository, dict):
            raise GitHubProtocolError("github repository response is invalid")
        typed_repository = cast(dict[str, object], repository)
        if _integer(typed_repository, "id") != self._configuration.repository_id:
            raise GitHubPermissionError("github repository id mismatch")
        full_name = typed_repository.get("full_name")
        if (
            not isinstance(full_name, str)
            or full_name.strip() != full_name
            or full_name.lower() != self._configuration.repository_key
        ):
            raise GitHubPermissionError("github repository key mismatch")

    def mint_installation_token(
        self,
        purpose: GitHubCredentialPurpose,
    ) -> GitHubInstallationCredential:
        """Mint one short-lived token for one repository and one purpose."""

        if not isinstance(purpose, GitHubCredentialPurpose):
            raise GitHubPermissionError("github credential purpose is unsupported")
        # Never mint from configuration alone: installation permissions,
        # subscriptions, suspension state, and repository ownership can change
        # independently in GitHub.
        self.verify_installation()
        requested_permissions = github_token_permissions(purpose)
        request_body = _canonical_json_bytes(
            {
                "repository_ids": [self._configuration.repository_id],
                "permissions": requested_permissions,
            }
        )
        response = self._request_json(
            method="POST",
            path=(
                f"/app/installations/{self._configuration.installation_id}"
                "/access_tokens"
            ),
            authorization=f"Bearer {self._app_jwt()}",
            body=request_body,
            success_status=201,
        )

        raw_token = response.get("token")
        if not isinstance(raw_token, str) or _TOKEN_PATTERN.fullmatch(raw_token) is None:
            raise GitHubProtocolError("github token response is invalid")
        try:
            expires_at = _timestamp(response.get("expires_at"), "expires_at")
            now = _aware_utc(self._clock())
            lifetime = expires_at - now
            if not _TOKEN_MINIMUM_LIFETIME < lifetime <= _TOKEN_MAXIMUM_LIFETIME:
                raise GitHubProtocolError("github token lifetime is invalid")

            actual_permissions = _string_mapping(
                response.get("permissions"), "permissions"
            )
            accepted_permissions = (
                requested_permissions,
                {**requested_permissions, "metadata": "read"},
            )
            if actual_permissions not in accepted_permissions:
                raise GitHubPermissionError(
                    "github token permissions exceed requested purpose"
                )

            self._require_exact_repository_scope(response)

            return GitHubInstallationCredential(
                _token=SecretValue(raw_token),
                purpose=purpose,
                repository_id=self._configuration.repository_id,
                repository_key=self._configuration.repository_key,
                expires_at=expires_at,
                permissions=tuple(sorted(actual_permissions.items())),
            )
        except Exception:
            self._revoke_installation_token(raw_token)
            raise

    def revoke_installation_token(
        self,
        credential: GitHubInstallationCredential,
    ) -> None:
        """Revoke a credential minted by this exact repository broker."""

        if (
            not isinstance(credential, GitHubInstallationCredential)
            or credential.repository_id != self._configuration.repository_id
            or credential.repository_key != self._configuration.repository_key
        ):
            raise GitHubPermissionError("github credential repository mismatch")
        self._revoke_installation_token(credential._token.reveal())

    def _app_jwt(self) -> str:
        now = _aware_utc(self._clock())
        claims: dict[str, int | str] = {
            "iat": int((now - _JWT_BACKDATE).timestamp()),
            "exp": int((now + _JWT_LIFETIME).timestamp()),
            "iss": str(self._configuration.app_id),
        }
        try:
            private_key = self._secret_provider.get(
                self._configuration.private_key_ref
            )
            encoded = self._signer(claims, private_key.reveal())
        except Exception:
            raise GitHubAuthorizationError(
                "github app private key is unavailable or invalid"
            ) from None
        if not isinstance(encoded, str) or _TOKEN_PATTERN.fullmatch(encoded) is None:
            raise GitHubAuthorizationError("github app signer returned an invalid JWT")
        return encoded

    def _request_json(
        self,
        *,
        method: str,
        path: str,
        authorization: str,
        body: bytes | None,
        success_status: int,
    ) -> dict[str, object]:
        response = self._request(
            method=method,
            path=path,
            authorization=authorization,
            body=body,
            success_status=success_status,
        )
        if response.content_type != "application/json":
            raise GitHubProtocolError("github app returned a non-JSON response")
        return _decode_json_object(response.body)

    def _request_json_array(
        self,
        *,
        method: str,
        path: str,
        authorization: str,
        body: bytes | None,
        success_status: int,
    ) -> list[object]:
        response = self._request(
            method=method,
            path=path,
            authorization=authorization,
            body=body,
            success_status=success_status,
        )
        if response.content_type != "application/json":
            raise GitHubProtocolError("github app returned a non-JSON response")
        return _decode_json_array(response.body)

    def _request(
        self,
        *,
        method: str,
        path: str,
        authorization: str,
        body: bytes | None,
        success_status: int,
    ) -> GitHubHttpResponse:
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": authorization,
            "User-Agent": "mathews-control-plane",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        response = self._transport.request(
            method=method,
            path=path,
            headers=headers,
            body=body,
            timeout_seconds=self._timeout_seconds,
        )
        retry_after = _rate_limit_retry_after(
            response,
            now=_aware_utc(self._clock()),
        )
        if retry_after is not None:
            raise GitHubRateLimitError(retry_after)
        if response.status_code in {401, 404}:
            raise GitHubAuthorizationError(
                "github app request was not authorized",
                status_code=response.status_code,
            )
        if response.status_code >= 500:
            raise GitHubUnavailableError("github app request failed")
        if response.status_code != success_status:
            raise GitHubProtocolError("github app returned an unexpected status")
        return response


class GitHubWebhookVerifier:
    """Verify HMAC-SHA256 over the unmodified raw body before any parsing."""

    def __init__(
        self,
        configuration: GitHubAppConfiguration,
        *,
        secret_provider: SecretProvider,
        maximum_body_bytes: int = MAX_GITHUB_WEBHOOK_BYTES,
    ) -> None:
        if maximum_body_bytes <= 0 or maximum_body_bytes > MAX_GITHUB_WEBHOOK_BYTES:
            raise ValueError(
                "webhook body limit must be positive and no larger than the policy maximum"
            )
        self._configuration = configuration
        self._secret_provider = secret_provider
        self._maximum_body_bytes = maximum_body_bytes

    def verify(
        self,
        *,
        signature_header: str | None,
        body: bytes,
    ) -> VerifiedGitHubWebhook:
        if not isinstance(body, bytes) or not body:
            raise GitHubWebhookVerificationError("webhook.body_invalid")
        if len(body) > self._maximum_body_bytes:
            raise GitHubWebhookVerificationError("webhook.body_too_large")
        if signature_header is None:
            raise GitHubWebhookVerificationError("webhook.signature_missing")
        if _SIGNATURE_PATTERN.fullmatch(signature_header) is None:
            raise GitHubWebhookVerificationError("webhook.signature_malformed")

        try:
            webhook_secret = self._secret_provider.get(
                self._configuration.webhook_secret_ref
            )
        except Exception:
            raise GitHubWebhookVerificationError("webhook.secret_unavailable") from None
        secret_bytes = webhook_secret.reveal().encode("utf-8")
        if not 16 <= len(secret_bytes) <= 4_096:
            raise GitHubWebhookVerificationError("webhook.secret_invalid")
        expected = "sha256=" + hmac.new(
            secret_bytes,
            body,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, signature_header):
            raise GitHubWebhookVerificationError("webhook.signature_mismatch")

        return VerifiedGitHubWebhook(
            algorithm="HMAC-SHA256",
            body_sha256=f"sha256:{hashlib.sha256(body).hexdigest()}",
            body_bytes=len(body),
        )


def _sign_github_jwt(claims: Mapping[str, int | str], private_key: str) -> str:
    encoded = jwt.encode(dict(claims), private_key, algorithm="RS256")
    if not isinstance(encoded, str):
        raise GitHubAuthorizationError("github app signer returned an invalid JWT")
    return encoded


def _read_bounded(stream: IO[bytes]) -> bytes:
    body = stream.read(MAX_GITHUB_RESPONSE_BYTES + 1)
    if len(body) > MAX_GITHUB_RESPONSE_BYTES:
        raise GitHubProtocolError("github response exceeded the byte limit")
    return body


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError):
        raise GitHubProtocolError("github request could not be encoded") from None


def _decode_json_object(body: bytes) -> dict[str, object]:
    value = _decode_json(body)
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise GitHubProtocolError("github response must be a JSON object")
    return cast(dict[str, object], value)


def _decode_json_array(body: bytes) -> list[object]:
    value = _decode_json(body)
    if not isinstance(value, list):
        raise GitHubProtocolError("github response must be a JSON array")
    return cast(list[object], value)


def _decode_json(body: bytes) -> object:
    try:
        decoded = body.decode("utf-8", errors="strict")
        value = json.loads(decoded, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise GitHubProtocolError("github response contained invalid JSON") from None
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _integer(value: Mapping[str, object], key: str) -> int:
    candidate = value.get(key)
    if isinstance(candidate, bool) or not isinstance(candidate, int) or candidate <= 0:
        raise GitHubProtocolError("github response contains an invalid integer")
    return candidate


def _string_mapping(value: object, field: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise GitHubProtocolError(f"github {field} response is invalid")
    result: dict[str, str] = {}
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not isinstance(item, str)
            or not key
            or item not in {"read", "write"}
        ):
            raise GitHubProtocolError(f"github {field} response is invalid")
        result[key] = item
    return result


def _string_tuple(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise GitHubProtocolError(f"github {field} response is invalid")
    return tuple(cast(list[str], value))


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise GitHubProtocolError(f"github {field} response is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise GitHubProtocolError(f"github {field} response is invalid") from None
    if parsed.tzinfo is None:
        raise GitHubProtocolError(f"github {field} response is invalid")
    return parsed.astimezone(UTC)


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise GitHubProtocolError("clock must return a timezone-aware timestamp")
    return value.astimezone(UTC)


def _rate_limit_retry_after(
    response: GitHubHttpResponse,
    *,
    now: datetime,
) -> int | None:
    # GitHub uses 403 for both permission denial and secondary throttling, and
    # secondary limits may omit both rate headers. Treat an ambiguous 403 as a
    # bounded retry rather than declaring credentials invalid; no effect is
    # authorized either way.
    throttled = response.status_code in {403, 429}
    if not throttled:
        return None

    if response.retry_after is not None and response.retry_after.isascii():
        try:
            retry_after = int(response.retry_after)
        except ValueError:
            retry_after = 60
        return min(max(retry_after, 1), 86_400)

    if (
        response.rate_limit_remaining == "0"
        and response.rate_limit_reset is not None
        and response.rate_limit_reset.isascii()
    ):
        try:
            reset = int(response.rate_limit_reset)
        except ValueError:
            return 60
        delay = math.ceil(reset - now.timestamp())
        return min(max(delay, 1), 86_400)

    return 60
