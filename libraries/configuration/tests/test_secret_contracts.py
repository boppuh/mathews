import logging

import pytest
from mathews_configuration import (
    SecretReference,
    SecretReferenceError,
    SecretValue,
    SecretValueError,
    redact_text,
)


def test_secret_reference_round_trips_canonical_uri() -> None:
    reference = SecretReference.parse("keychain://com.boppuh.mathews.github-app/private-key")

    assert reference.provider == "keychain"
    assert reference.service == "com.boppuh.mathews.github-app"
    assert reference.account == "private-key"
    assert reference.uri == "keychain://com.boppuh.mathews.github-app/private-key"
    assert reference.safe_label == "keychain://[configured]"


@pytest.mark.parametrize(
    "value",
    [
        "env://github/private-key",
        "keychain://service",
        "keychain:///account",
        "keychain://service/account/extra",
        "keychain://service/account?raw=value",
        "keychain://service/account#fragment",
        "keychain://service name/account",
    ],
)
def test_secret_reference_rejects_unsafe_or_unsupported_values(value: str) -> None:
    with pytest.raises(SecretReferenceError):
        SecretReference.parse(value)


def test_secret_value_cannot_render_credential_bytes() -> None:
    secret = SecretValue("test-credential-value")

    assert str(secret) == "[REDACTED]"
    assert repr(secret) == "SecretValue('[REDACTED]')"
    assert f"credential={secret}" == "credential=[REDACTED]"
    assert secret.reveal() == "test-credential-value"


def test_secret_value_rejects_empty_credentials() -> None:
    with pytest.raises(SecretValueError):
        SecretValue("")


def test_secret_value_is_redacted_when_logged(caplog: pytest.LogCaptureFixture) -> None:
    secret = SecretValue("credential-that-must-not-be-logged")

    with caplog.at_level(logging.INFO):
        logging.getLogger("mathews.test").info("credential=%s", secret)

    assert "credential-that-must-not-be-logged" not in caplog.text
    assert "credential=[REDACTED]" in caplog.text


def test_redact_text_removes_every_known_secret() -> None:
    redacted = redact_text(
        "Authorization: Bearer longest-secret; fallback=secret",
        (SecretValue("secret"), SecretValue("longest-secret")),
    )

    assert redacted == "Authorization: Bearer [REDACTED]; fallback=[REDACTED]"
