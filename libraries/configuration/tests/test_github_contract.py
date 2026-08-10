import json

import pytest
from mathews_configuration import (
    GITHUB_APP_PERMISSIONS,
    GITHUB_WEBHOOK_EVENTS,
    GitHubAppConfiguration,
    GitHubAppConfigurationError,
    GitHubCredentialPurpose,
    SecretReference,
    github_token_permissions,
)


def _configuration(**overrides: object) -> GitHubAppConfiguration:
    values: dict[str, object] = {
        "app_id": 101,
        "installation_id": 202,
        "repository_id": 303,
        "repository_key": "boppuh/mathews",
        "private_key_ref": SecretReference.parse(
            "keychain://com.boppuh.mathews.github-app/private-key"
        ),
        "webhook_secret_ref": SecretReference.parse(
            "keychain://com.boppuh.mathews.github-app/webhook-secret"
        ),
    }
    values.update(overrides)
    return GitHubAppConfiguration(**values)  # type: ignore[arg-type]


def test_github_app_configuration_is_repository_scoped_and_hermes_safe() -> None:
    configuration = _configuration()

    assert configuration.hermes_context.to_dict() == {
        "repository_id": 303,
        "repository_key": "boppuh/mathews",
    }
    serialized_context = json.dumps(configuration.hermes_context.to_dict())
    assert "keychain" not in serialized_context
    assert "private-key" not in serialized_context
    assert "webhook-secret" not in serialized_context

    summary = configuration.safe_summary()
    assert summary["private_key_ref"] == "keychain://[configured]"
    assert summary["webhook_secret_ref"] == "keychain://[configured]"
    assert summary["permissions"] == dict(GITHUB_APP_PERMISSIONS)
    assert summary["events"] == list(GITHUB_WEBHOOK_EVENTS)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("app_id", 0),
        ("app_id", True),
        ("installation_id", -1),
        ("repository_id", "303"),
        ("repository_key", "Boppuh/mathews"),
        ("repository_key", "boppuh/mathews.git"),
        ("repository_key", "boppuh/mathews/extra"),
    ],
)
def test_github_app_configuration_rejects_unsafe_identity(
    field: str, value: object
) -> None:
    with pytest.raises(GitHubAppConfigurationError):
        _configuration(**{field: value})


def test_github_app_configuration_requires_separate_secrets() -> None:
    shared = SecretReference.parse("keychain://com.boppuh.mathews.github-app/shared")

    with pytest.raises(GitHubAppConfigurationError, match="must be distinct"):
        _configuration(private_key_ref=shared, webhook_secret_ref=shared)


def test_permission_manifest_is_exact_and_excludes_high_risk_permissions() -> None:
    assert dict(GITHUB_APP_PERMISSIONS) == {
        "checks": "read",
        "metadata": "read",
        "pull_requests": "write",
    }
    assert {
        "actions",
        "administration",
        "deployments",
        "environments",
        "secrets",
        "workflows",
    }.isdisjoint(dict(GITHUB_APP_PERMISSIONS))
    assert set(GitHubCredentialPurpose) == {
        GitHubCredentialPurpose.OBSERVE,
        GitHubCredentialPurpose.PULL_REQUEST_WRITE,
    }


def test_operation_tokens_never_receive_the_full_app_permission_union() -> None:
    assert github_token_permissions(GitHubCredentialPurpose.OBSERVE) == {
        "checks": "read",
        "pull_requests": "read",
    }
    assert github_token_permissions(GitHubCredentialPurpose.PULL_REQUEST_WRITE) == {
        "pull_requests": "write"
    }
    for purpose in GitHubCredentialPurpose:
        permissions = github_token_permissions(purpose)
        assert "administration" not in permissions
        assert "workflows" not in permissions
        assert len(permissions) < len(GITHUB_APP_PERMISSIONS)
        assert "contents" not in permissions


def test_webhook_event_manifest_is_exact() -> None:
    assert GITHUB_WEBHOOK_EVENTS == (
        "check_run",
        "pull_request",
        "pull_request_review",
        "pull_request_review_comment",
        "pull_request_review_thread",
    )
