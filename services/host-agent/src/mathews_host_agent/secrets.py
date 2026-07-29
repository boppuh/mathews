import argparse
import json
import platform
import subprocess
import sys
from collections.abc import Callable

from mathews_configuration import SecretProvider, SecretReference, SecretValue

SecurityRunner = Callable[[list[str], float], subprocess.CompletedProcess[str]]


class KeychainProviderError(RuntimeError):
    """Base error that never embeds command output or credential bytes."""

    code = "keychain_error"


class KeychainUnavailableError(KeychainProviderError):
    """Raised when macOS Keychain cannot be used on this host."""

    code = "keychain_unavailable"


class SecretNotFoundError(KeychainProviderError):
    """Raised when an opaque reference does not resolve to a credential."""

    code = "secret_not_found"


class KeychainSecretProvider(SecretProvider):
    """Resolve generic-password items through the fixed macOS security binary."""

    def __init__(
        self,
        *,
        platform_name: str | None = None,
        runner: SecurityRunner | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self._platform_name = platform_name or platform.system().lower()
        self._runner = runner or _run_security
        self._timeout_seconds = timeout_seconds

    def get(self, reference: SecretReference) -> SecretValue:
        if self._platform_name != "darwin":
            raise KeychainUnavailableError("macOS Keychain is unavailable on this host")

        command = [
            "/usr/bin/security",
            "find-generic-password",
            "-w",
            "-s",
            reference.service,
            "-a",
            reference.account,
        ]
        try:
            result = self._runner(command, self._timeout_seconds)
        except (OSError, subprocess.TimeoutExpired):
            raise KeychainUnavailableError("macOS Keychain could not be queried") from None

        if result.returncode != 0:
            raise SecretNotFoundError("secret reference was not found in macOS Keychain")

        value = result.stdout.rstrip("\r\n")
        if not value:
            raise SecretNotFoundError("secret reference resolved to an empty value")
        return SecretValue(value)


def _run_security(command: list[str], timeout_seconds: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        check=False,
        text=True,
        timeout=timeout_seconds,
    )


def check_secret(reference: SecretReference, provider: SecretProvider) -> dict[str, str | bool]:
    """Verify availability without returning, printing, or persisting the value."""

    provider.get(reference)
    return {
        "available": True,
        "provider": reference.provider,
        "reference": reference.safe_label,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify a Mathews Keychain reference without printing its value"
    )
    parser.add_argument("reference", type=SecretReference.parse)
    args = parser.parse_args()

    try:
        report = check_secret(args.reference, KeychainSecretProvider())
    except KeychainProviderError as error:
        print(
            json.dumps(
                {
                    "available": False,
                    "error": error.code,
                    "provider": "keychain",
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise SystemExit(2) from None

    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
