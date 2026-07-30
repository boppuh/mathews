import subprocess

import pytest
from mathews_configuration import SecretReference
from mathews_host_agent.secrets import (
    KeychainSecretProvider,
    KeychainUnavailableError,
    SecretNotFoundError,
    check_secret,
)


def test_keychain_provider_uses_fixed_binary_and_typed_arguments() -> None:
    commands: list[tuple[list[str], float]] = []

    def runner(command: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        commands.append((command, timeout))
        return subprocess.CompletedProcess(command, 0, "credential-value\n", "")

    reference = SecretReference.parse("keychain://com.boppuh.mathews.github-app/private-key")
    value = KeychainSecretProvider(
        platform_name="darwin",
        runner=runner,
    ).get(reference)

    assert value.reveal() == "credential-value"
    assert str(value) == "[REDACTED]"
    assert commands == [
        (
            [
                "/usr/bin/security",
                "find-generic-password",
                "-w",
                "-s",
                "com.boppuh.mathews.github-app",
                "-a",
                "private-key",
            ],
            5.0,
        )
    ]


def test_keychain_provider_refuses_non_macos_hosts() -> None:
    called = False

    def runner(command: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        nonlocal called
        called = True
        return subprocess.CompletedProcess(command, 0, "credential-value", "")

    provider = KeychainSecretProvider(platform_name="linux", runner=runner)

    with pytest.raises(KeychainUnavailableError):
        provider.get(SecretReference.parse("keychain://service/account"))
    assert called is False


def test_keychain_failure_never_exposes_command_output() -> None:
    leaked_value = "credential-from-error-stream"

    def runner(command: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 44, leaked_value, leaked_value)

    provider = KeychainSecretProvider(platform_name="darwin", runner=runner)

    with pytest.raises(SecretNotFoundError) as error:
        provider.get(SecretReference.parse("keychain://service/account"))
    assert leaked_value not in str(error.value)
    assert leaked_value not in repr(error.value)


def test_keychain_access_failure_is_not_reported_as_missing() -> None:
    leaked_value = "credential-from-error-stream"

    def runner(command: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 51, leaked_value, leaked_value)

    provider = KeychainSecretProvider(platform_name="darwin", runner=runner)

    with pytest.raises(KeychainUnavailableError) as error:
        provider.get(SecretReference.parse("keychain://service/account"))
    assert leaked_value not in str(error.value)
    assert leaked_value not in repr(error.value)


def test_keychain_timeout_suppresses_low_level_output() -> None:
    leaked_value = "partial-credential-output"

    def runner(command: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(command, timeout, output=leaked_value)

    provider = KeychainSecretProvider(platform_name="darwin", runner=runner)

    with pytest.raises(KeychainUnavailableError) as error:
        provider.get(SecretReference.parse("keychain://service/account"))
    assert leaked_value not in str(error.value)
    assert error.value.__suppress_context__ is True


def test_keychain_check_returns_only_safe_metadata() -> None:
    def runner(command: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "credential-value\n", "")

    reference = SecretReference.parse("keychain://service/account")
    report = check_secret(
        reference,
        KeychainSecretProvider(platform_name="darwin", runner=runner),
    )

    assert report == {
        "available": True,
        "provider": "keychain",
        "reference": "keychain://[configured]",
    }
    assert "credential-value" not in str(report)
