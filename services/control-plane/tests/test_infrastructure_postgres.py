import hashlib
import os
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.database import (
    create_database_engine,
    create_session_factory,
    create_task_record,
    get_task_record,
    session_scope,
)
from sqlalchemy import text
from sqlalchemy.engine import Engine, make_url

_DATABASE_URL_ENV = "POSTGRES_TEST_DATABASE_URL"


def _migration_config(database_url: str) -> Config:
    service_root = Path(__file__).parents[1]
    config = Config(str(service_root / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


def _configured_database_url() -> str:
    database_url = os.environ.get(_DATABASE_URL_ENV)
    if database_url is None:
        pytest.skip(f"{_DATABASE_URL_ENV} is required for the PostgreSQL integration test")
    return database_url


def _schema_database_url(database_url: str, schema: str) -> str:
    url = make_url(database_url).update_query_dict({"options": f"-csearch_path={schema}"})
    return url.render_as_string(hide_password=False)


def test_postgres_migrations_and_durable_storage_smoke(tmp_path: Path) -> None:
    admin_database_url = _configured_database_url()
    schema = f"mathews_test_{uuid4().hex}"
    database_url = _schema_database_url(admin_database_url, schema)
    migration_config = _migration_config(database_url)
    payload = b"\x00durable infrastructure smoke\xff"
    expected_digest = hashlib.sha256(payload).hexdigest()
    admin_engine = create_database_engine(admin_database_url)
    engine: Engine | None = None
    schema_created = False
    try:
        with admin_engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        schema_created = True

        command.upgrade(migration_config, "head")
        command.upgrade(migration_config, "head")

        engine = create_database_engine(database_url)
        factory = create_session_factory(engine)
        store = ArtifactStore(tmp_path / "artifacts")
        with engine.connect() as connection:
            current_revision = MigrationContext.configure(connection).get_current_revision()
        assert ScriptDirectory.from_config(migration_config).get_heads() == ["0001"]
        assert current_revision == "0001"

        with session_scope(factory) as session:
            created = create_task_record(
                session,
                summary="PostgreSQL and artifact durability smoke",
            )
            task_id = created.id
        artifact = store.put_bytes(payload)
        engine.dispose()
        engine = None

        recreated_engine = create_database_engine(database_url)
        engine = recreated_engine
        recreated_factory = create_session_factory(recreated_engine)
        recreated_store = ArtifactStore(store.root)
        with recreated_factory() as session:
            retrieved = get_task_record(session, task_id)

        assert retrieved is not None
        assert retrieved.summary == "PostgreSQL and artifact durability smoke"
        assert artifact.address == f"sha256:{expected_digest}"
        assert recreated_store.get_bytes(artifact.address) == payload
    finally:
        if engine is not None:
            engine.dispose()
        try:
            if schema_created:
                with admin_engine.begin() as connection:
                    connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        finally:
            admin_engine.dispose()
