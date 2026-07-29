from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="MATHEWS_",
        extra="ignore",
    )

    environment: str = "local"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    web_origin: str = "http://localhost:3000"
    database_url: str = "postgresql+psycopg://mathews:mathews@localhost:5432/mathews"
    artifact_root: Path = Path(".local/artifacts")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
