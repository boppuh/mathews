from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from mathews_control_plane.database import Base, create_database_engine
from sqlalchemy import Connection

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _database_url() -> str:
    configured_url = config.get_main_option("sqlalchemy.url")
    if configured_url:
        return configured_url

    # Importing settings does not connect to PostgreSQL. Keeping this import
    # inside migration execution also avoids configuration work on module import.
    from mathews_control_plane.settings import get_settings

    return get_settings().database_url.get_secret_value()


def run_migrations_offline() -> None:
    """Run migrations without opening a database connection."""

    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        compare_type=True,
        dialect_opts={"paramstyle": "named"},
        literal_binds=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def _run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        render_as_batch=connection.dialect.name == "sqlite",
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against the configured database."""

    engine = create_database_engine(_database_url())
    try:
        with engine.connect() as connection:
            _run_migrations(connection)
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
