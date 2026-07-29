import re
from dataclasses import dataclass
from typing import Literal, Protocol
from urllib.parse import quote, unquote, urlsplit

_SERVICE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_ACCOUNT_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,127}")
_REDACTED = "[REDACTED]"


class SecretReferenceError(ValueError):
    """Raised when an opaque secret reference is malformed or unsupported."""


class SecretValueError(ValueError):
    """Raised when a secret provider returns an unusable value."""


@dataclass(frozen=True, slots=True)
class SecretReference:
    """Opaque location of a credential without containing its value."""

    provider: Literal["keychain"]
    service: str
    account: str

    def __post_init__(self) -> None:
        if self.provider != "keychain":
            raise SecretReferenceError("only keychain secret references are supported")
        if _SERVICE_PATTERN.fullmatch(self.service) is None:
            raise SecretReferenceError("secret reference contains an invalid service")
        if _ACCOUNT_PATTERN.fullmatch(self.account) is None:
            raise SecretReferenceError("secret reference contains an invalid account")

    @classmethod
    def parse(cls, value: str) -> "SecretReference":
        """Parse the canonical keychain URI used at service boundaries."""

        parsed = urlsplit(value)
        if (
            parsed.scheme != "keychain"
            or not parsed.netloc
            or not parsed.path.startswith("/")
            or parsed.path.count("/") != 1
            or parsed.query
            or parsed.fragment
        ):
            raise SecretReferenceError("secret reference must use keychain://<service>/<account>")

        return cls(
            provider="keychain",
            service=unquote(parsed.netloc),
            account=unquote(parsed.path[1:]),
        )

    @property
    def uri(self) -> str:
        """Return the canonical opaque URI; this never contains secret bytes."""

        service = quote(self.service, safe="._-")
        account = quote(self.account, safe="._@-")
        return f"keychain://{service}/{account}"

    @property
    def safe_label(self) -> str:
        """Return a log-safe indication that a provider reference is configured."""

        return "keychain://[configured]"

    def __str__(self) -> str:
        return self.uri


class SecretValue:
    """Credential bytes that render only as a redaction marker."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not value:
            raise SecretValueError("secret value cannot be empty")
        self._value = value

    def reveal(self) -> str:
        """Explicitly reveal a value only at the integration call boundary."""

        return self._value

    def __repr__(self) -> str:
        return f"SecretValue({_REDACTED!r})"

    def __str__(self) -> str:
        return _REDACTED

    def __format__(self, format_spec: str) -> str:
        return format(str(self), format_spec)


class SecretProvider(Protocol):
    """Narrow interface implemented by platform-owned credential stores."""

    def get(self, reference: SecretReference) -> SecretValue:
        """Resolve one opaque reference without logging or persisting the value."""


def redact_text(text: str, secrets: tuple[SecretValue, ...]) -> str:
    """Remove known credential values before text crosses a logging boundary."""

    redacted = text
    values = sorted({secret.reveal() for secret in secrets}, key=len, reverse=True)
    for value in values:
        redacted = redacted.replace(value, _REDACTED)
    return redacted
