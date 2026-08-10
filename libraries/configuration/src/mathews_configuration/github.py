"""Least-privilege GitHub App configuration and capability contracts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from mathews_configuration.secrets import SecretReference

_REPOSITORY_KEY_PATTERN = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,38})/[a-z0-9](?:[a-z0-9._-]{0,99})"
)


class GitHubAppConfigurationError(ValueError):
    """Raised when GitHub App configuration is unsafe or incomplete."""


class GitHubCredentialPurpose(StrEnum):
    """The complete set of credentials the MVP may mint."""

    OBSERVE = "OBSERVE"
    PULL_REQUEST_WRITE = "PULL_REQUEST_WRITE"


# GitHub grants metadata:read implicitly. Every other permission must be
# explicitly present at exactly this level, with no additional app permission.
GITHUB_APP_PERMISSIONS: tuple[tuple[str, str], ...] = (
    ("checks", "read"),
    ("metadata", "read"),
    ("pull_requests", "write"),
)

# Task 6.3 handles CI and review state. Keeping this list exact avoids granting
# unrelated issue, deployment, release, or administration event visibility.
GITHUB_WEBHOOK_EVENTS: tuple[str, ...] = (
    "check_run",
    "pull_request",
    "pull_request_review",
    "pull_request_review_comment",
    "pull_request_review_thread",
)

_TOKEN_PERMISSION_PROFILES: dict[
    GitHubCredentialPurpose, tuple[tuple[str, str], ...]
] = {
    GitHubCredentialPurpose.OBSERVE: (
        ("checks", "read"),
        ("pull_requests", "read"),
    ),
    GitHubCredentialPurpose.PULL_REQUEST_WRITE: (("pull_requests", "write"),),
}


def github_token_permissions(
    purpose: GitHubCredentialPurpose,
) -> dict[str, str]:
    """Return a fresh exact permission request for one bounded operation."""

    return dict(_TOKEN_PERMISSION_PROFILES[purpose])


@dataclass(frozen=True, slots=True)
class GitHubRepositoryContext:
    """The only GitHub context safe to expose to Hermes."""

    repository_id: int
    repository_key: str

    def to_dict(self) -> dict[str, object]:
        return {
            "repository_id": self.repository_id,
            "repository_key": self.repository_key,
        }


@dataclass(frozen=True, slots=True)
class GitHubAppConfiguration:
    """Opaque GitHub App references bound to exactly one repository."""

    app_id: int
    installation_id: int
    repository_id: int
    repository_key: str
    private_key_ref: SecretReference
    webhook_secret_ref: SecretReference

    def __post_init__(self) -> None:
        for field, value in (
            ("GitHub App id", self.app_id),
            ("GitHub installation id", self.installation_id),
            ("GitHub repository id", self.repository_id),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise GitHubAppConfigurationError(f"{field} must be a positive integer")

        if (
            _REPOSITORY_KEY_PATTERN.fullmatch(self.repository_key) is None
            or self.repository_key.endswith(".git")
        ):
            raise GitHubAppConfigurationError(
                "GitHub repository key must use canonical lowercase owner/repository form"
            )
        if self.private_key_ref == self.webhook_secret_ref:
            raise GitHubAppConfigurationError(
                "GitHub private-key and webhook-secret references must be distinct"
            )

    @property
    def hermes_context(self) -> GitHubRepositoryContext:
        """Project configuration without credential references or values."""

        return GitHubRepositoryContext(
            repository_id=self.repository_id,
            repository_key=self.repository_key,
        )

    def safe_summary(self) -> dict[str, object]:
        """Return configuration diagnostics without credential locations."""

        return {
            "app_id": self.app_id,
            "installation_id": self.installation_id,
            "repository_id": self.repository_id,
            "repository_key": self.repository_key,
            "private_key_ref": self.private_key_ref.safe_label,
            "webhook_secret_ref": self.webhook_secret_ref.safe_label,
            "permissions": dict(GITHUB_APP_PERMISSIONS),
            "events": list(GITHUB_WEBHOOK_EVENTS),
        }
