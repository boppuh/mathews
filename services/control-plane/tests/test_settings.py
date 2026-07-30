from pathlib import Path

import pytest
from mathews_configuration import SecretReference
from pydantic import AnyHttpUrl, SecretStr, ValidationError


def test_incomplete_configuration_blocks_automation() -> None:
    from mathews_control_plane.settings import ConfigurationIncompleteError, Settings

    settings = Settings()

    assert settings.automation_ready is False
    assert settings.missing_automation_settings == (
        "target_repository_root",
        "hermes_endpoint",
        "hermes_api_key_ref",
        "github_app_id",
        "github_installation_id",
        "github_private_key_ref",
        "github_webhook_secret_ref",
    )
    with pytest.raises(ConfigurationIncompleteError) as error:
        settings.require_automation_configuration()
    assert error.value.missing == settings.missing_automation_settings


def test_complete_configuration_returns_typed_snapshot(tmp_path: Path) -> None:
    from mathews_control_plane.settings import Settings

    settings = Settings(
        target_repository_root=tmp_path,
        artifact_root=Path("/tmp/mathews-artifacts"),
        hermes_endpoint=AnyHttpUrl("https://hermes.example.test"),
        hermes_api_key_ref=SecretReference.parse("keychain://com.boppuh.mathews.hermes/api-key"),
        github_app_id=123,
        github_installation_id=456,
        github_private_key_ref=SecretReference.parse(
            "keychain://com.boppuh.mathews.github-app/private-key"
        ),
        github_webhook_secret_ref=SecretReference.parse(
            "keychain://com.boppuh.mathews.github-app/webhook-secret"
        ),
    )

    configuration = settings.require_automation_configuration()

    assert settings.automation_ready is True
    assert configuration.target_repository_root == tmp_path.resolve()
    assert configuration.artifact_root == Path("/tmp/mathews-artifacts").resolve()
    assert str(configuration.hermes_endpoint) == "https://hermes.example.test/"
    assert configuration.github_app_id == 123
    assert configuration.github_private_key_ref == SecretReference.parse(
        "keychain://com.boppuh.mathews.github-app/private-key"
    )


def test_relative_repository_root_is_rejected() -> None:
    from mathews_control_plane.settings import Settings

    with pytest.raises(ValidationError, match="absolute path"):
        Settings(target_repository_root=Path("relative/repository"))


def test_blank_optional_environment_values_are_unconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mathews_control_plane.settings import Settings

    for name in (
        "MATHEWS_TARGET_REPOSITORY_ROOT",
        "MATHEWS_HERMES_ENDPOINT",
        "MATHEWS_HERMES_API_KEY_REF",
        "MATHEWS_GITHUB_APP_ID",
        "MATHEWS_GITHUB_INSTALLATION_ID",
        "MATHEWS_GITHUB_PRIVATE_KEY_REF",
        "MATHEWS_GITHUB_WEBHOOK_SECRET_REF",
    ):
        monkeypatch.setenv(name, "")

    settings = Settings()

    assert settings.automation_ready is False
    assert settings.target_repository_root is None
    assert settings.hermes_api_key_ref is None


def test_shared_dotenv_ignores_launcher_and_legacy_fields(tmp_path: Path) -> None:
    from mathews_control_plane.settings import Settings

    env_file = tmp_path / ".env"
    env_file.write_text("MATHEWS_SKIP_POSTGRES=1\nMATHEWS_HERMES_API_KEY=unused-legacy-secret\n")

    settings = Settings(_env_file=env_file)  # type: ignore[call-arg]

    assert settings.automation_ready is False
    assert "unused-legacy-secret" not in str(settings.safe_summary())


def test_validation_errors_hide_invalid_inputs() -> None:
    from mathews_control_plane.settings import Settings

    invalid_secret = "do-not-log-this-secret"

    with pytest.raises(ValidationError) as error:
        Settings(github_app_id=invalid_secret)  # type: ignore[arg-type]

    assert invalid_secret not in str(error.value)


@pytest.mark.parametrize("field_name", ("web_origin", "hermes_endpoint"))
def test_diagnostic_urls_reject_embedded_credentials(field_name: str) -> None:
    from mathews_control_plane.settings import Settings

    credential = "do-not-log-this-secret"

    with pytest.raises(ValidationError, match="URL credentials are not allowed") as error:
        Settings.model_validate(
            {field_name: f"https://user:{credential}@example.test"}
        )

    assert credential not in str(error.value)


def test_safe_summary_redacts_url_credentials_if_validation_is_bypassed() -> None:
    from mathews_control_plane.settings import Settings

    credential = "do-not-log-this-secret"
    credential_url = AnyHttpUrl(f"https://user:{credential}@example.test")
    settings = Settings.model_construct(
        web_origin=credential_url,
        hermes_endpoint=credential_url,
    )

    summary = str(settings.safe_summary())

    assert credential not in summary
    assert summary.count("[REDACTED URL]") == 2


def test_configuration_report_redacts_database_credentials() -> None:
    from mathews_control_plane.configuration import configuration_report
    from mathews_control_plane.settings import Settings

    database_secret = "database-password-value"
    postgres_secret = "postgres-password-value"
    settings = Settings(
        database_url=SecretStr(f"postgresql+psycopg://mathews:{database_secret}@localhost/mathews"),
        postgres_password=SecretStr(postgres_secret),
    )

    report = configuration_report(settings)

    assert database_secret not in report
    assert postgres_secret not in report
    assert report.count("[REDACTED]") == 2


def test_example_environment_contains_references_not_raw_integration_secrets() -> None:
    from mathews_control_plane.settings import Settings

    workspace_root = Path(__file__).parents[3]
    example_path = workspace_root / ".env.example"
    example = example_path.read_text()
    raw_names = (
        "MATHEWS_HERMES_API_KEY",
        "MATHEWS_GITHUB_PRIVATE_KEY",
        "MATHEWS_GITHUB_WEBHOOK_SECRET",
    )

    for raw_name in raw_names:
        assert f"{raw_name}=" not in example

    settings = Settings(_env_file=example_path)  # type: ignore[call-arg]
    assert settings.hermes_endpoint is not None
    assert settings.hermes_api_key_ref is not None
    assert settings.github_private_key_ref is not None
    assert settings.github_webhook_secret_ref is not None
    assert settings.automation_ready is False
