from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal, cast
from urllib.parse import urlsplit, urlunsplit

from mathews_configuration import SecretReference
from pydantic import AnyHttpUrl, PositiveInt, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

EnvironmentName = Literal["local", "test", "staging", "production"]


class ConfigurationIncompleteError(RuntimeError):
    """Raised when an operation requires integration settings that are missing."""

    def __init__(self, missing: tuple[str, ...]) -> None:
        self.missing = missing
        super().__init__(f"automation configuration is incomplete: {', '.join(missing)}")


@dataclass(frozen=True, slots=True)
class AutomationConfiguration:
    """Complete non-secret configuration and opaque integration references."""

    target_repository_root: Path
    artifact_root: Path
    hermes_endpoint: AnyHttpUrl
    hermes_api_key_ref: SecretReference
    github_app_id: int
    github_installation_id: int
    github_private_key_ref: SecretReference
    github_webhook_secret_ref: SecretReference


class Settings(BaseSettings):
    """Environment-backed runtime settings with no raw integration credentials."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="MATHEWS_",
        # The workspace shares this file with the Node development launcher.
        # Unknown entries are ignored; required automation fields still fail closed.
        extra="ignore",
        hide_input_in_errors=True,
        validate_default=True,
    )

    environment: EnvironmentName = "local"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    web_origin: AnyHttpUrl = AnyHttpUrl("http://localhost:3000")
    database_url: SecretStr = SecretStr(
        "postgresql+psycopg://mathews:mathews@localhost:5432/mathews"
    )
    postgres_db: str = "mathews"
    postgres_user: str = "mathews"
    postgres_password: SecretStr = SecretStr("mathews")
    postgres_port: int = 5432
    artifact_root: Path = Path(".local/artifacts")

    target_repository_root: Path | None = None
    hermes_endpoint: AnyHttpUrl | None = None
    hermes_api_key_ref: SecretReference | None = None
    github_app_id: PositiveInt | None = None
    github_installation_id: PositiveInt | None = None
    github_private_key_ref: SecretReference | None = None
    github_webhook_secret_ref: SecretReference | None = None

    @field_validator(
        "target_repository_root",
        "hermes_endpoint",
        "github_app_id",
        "github_installation_id",
        mode="before",
    )
    @classmethod
    def empty_value_is_unconfigured(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator(
        "hermes_api_key_ref",
        "github_private_key_ref",
        "github_webhook_secret_ref",
        mode="before",
    )
    @classmethod
    def parse_secret_reference(cls, value: object) -> object:
        if isinstance(value, str):
            if not value.strip():
                return None
            return SecretReference.parse(value)
        return value

    @field_validator("target_repository_root")
    @classmethod
    def repository_root_is_absolute(cls, value: Path | None) -> Path | None:
        if value is None:
            return None

        expanded = value.expanduser()
        if not expanded.is_absolute():
            raise ValueError("target repository root must be an absolute path")
        return expanded.resolve(strict=False)

    @field_validator("artifact_root")
    @classmethod
    def normalize_artifact_root(cls, value: Path) -> Path:
        return value.expanduser().resolve(strict=False)

    @field_validator("web_origin", "hermes_endpoint")
    @classmethod
    def diagnostic_urls_have_no_credentials(cls, value: AnyHttpUrl | None) -> AnyHttpUrl | None:
        if value is not None and (value.username is not None or value.password is not None):
            raise ValueError(
                "URL credentials are not allowed; configure authentication "
                "through a secret reference"
            )
        return value

    @property
    def missing_automation_settings(self) -> tuple[str, ...]:
        required = (
            ("target_repository_root", self.target_repository_root),
            ("hermes_endpoint", self.hermes_endpoint),
            ("hermes_api_key_ref", self.hermes_api_key_ref),
            ("github_app_id", self.github_app_id),
            ("github_installation_id", self.github_installation_id),
            ("github_private_key_ref", self.github_private_key_ref),
            ("github_webhook_secret_ref", self.github_webhook_secret_ref),
        )
        return tuple(name for name, value in required if value is None)

    @property
    def automation_ready(self) -> bool:
        return not self.missing_automation_settings

    def require_automation_configuration(self) -> AutomationConfiguration:
        """Return a complete snapshot or block work before external effects."""

        missing = self.missing_automation_settings
        if missing:
            raise ConfigurationIncompleteError(missing)

        return AutomationConfiguration(
            target_repository_root=cast(Path, self.target_repository_root),
            artifact_root=self.artifact_root,
            hermes_endpoint=cast(AnyHttpUrl, self.hermes_endpoint),
            hermes_api_key_ref=cast(SecretReference, self.hermes_api_key_ref),
            github_app_id=cast(int, self.github_app_id),
            github_installation_id=cast(int, self.github_installation_id),
            github_private_key_ref=cast(SecretReference, self.github_private_key_ref),
            github_webhook_secret_ref=cast(SecretReference, self.github_webhook_secret_ref),
        )

    def safe_summary(self) -> dict[str, object]:
        """Return diagnostics that cannot contain credential values."""

        return {
            "environment": self.environment,
            "api_host": self.api_host,
            "api_port": self.api_port,
            "web_origin": _safe_url(self.web_origin),
            "database_url": "[REDACTED]",
            "postgres_db": self.postgres_db,
            "postgres_user": self.postgres_user,
            "postgres_password": "[REDACTED]",
            "postgres_port": self.postgres_port,
            "artifact_root": str(self.artifact_root),
            "target_repository_root": (
                str(self.target_repository_root)
                if self.target_repository_root is not None
                else None
            ),
            "hermes_endpoint": _safe_url(self.hermes_endpoint),
            "hermes_api_key_ref": _reference_status(self.hermes_api_key_ref),
            "github_app_id": self.github_app_id,
            "github_installation_id": self.github_installation_id,
            "github_private_key_ref": _reference_status(self.github_private_key_ref),
            "github_webhook_secret_ref": _reference_status(self.github_webhook_secret_ref),
            "automation_ready": self.automation_ready,
            "missing_automation_settings": list(self.missing_automation_settings),
        }


def _reference_status(reference: SecretReference | None) -> str | None:
    return reference.safe_label if reference is not None else None


def _safe_url(value: AnyHttpUrl | None) -> str | None:
    if value is None:
        return None
    if value.username is not None or value.password is not None:
        return "[REDACTED URL]"
    parsed = urlsplit(str(value))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
