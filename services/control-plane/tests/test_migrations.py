from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


def _migration_config(database_url: str) -> Config:
    service_root = Path(__file__).parents[1]
    config = Config(str(service_root / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


def _table_names(database_url: str) -> set[str]:
    engine = create_engine(database_url)
    try:
        return set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def test_migrations_are_repeatable_from_clean_database(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)

    command.upgrade(config, "head")
    command.upgrade(config, "head")

    assert _table_names(database_url) == {"alembic_version", "tasks"}


def test_migrations_can_rebuild_schema_after_downgrade(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)

    command.upgrade(config, "head")
    command.downgrade(config, "base")
    assert _table_names(database_url) == {"alembic_version"}

    command.upgrade(config, "head")
    assert _table_names(database_url) == {"alembic_version", "tasks"}


def test_offline_postgres_migration_sql_hides_database_password(
    capsys: pytest.CaptureFixture[str],
) -> None:
    password = "database-password-that-must-not-leak"
    config = _migration_config(
        f"postgresql+psycopg://mathews:{password}@127.0.0.1:5432/mathews"
    )

    command.upgrade(config, "head", sql=True)

    captured = capsys.readouterr()
    assert "CREATE TABLE tasks" in captured.out
    assert password not in captured.out
    assert password not in captured.err
