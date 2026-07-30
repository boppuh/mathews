import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.authentication import (
    AuthenticationService,
    BootstrapAlreadyCompletedError,
    IssuedSession,
    generate_bootstrap_token,
)
from mathews_control_plane.database import (
    create_database_engine,
    create_session_factory,
    create_task_record,
    get_task_record,
    session_scope,
)
from mathews_control_plane.domain_models import TaskEvent
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import IntegrityError

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
        authentication_service = AuthenticationService(factory)
        with engine.connect() as connection:
            current_revision = MigrationContext.configure(connection).get_current_revision()
        assert ScriptDirectory.from_config(migration_config).get_heads() == ["0003"]
        assert current_revision == "0003"
        inspector = inspect(engine)
        validation_run_foreign_tables = {
            foreign_key["referred_table"]
            for foreign_key in inspector.get_foreign_keys("validation_runs")
        }
        assert {
            "tasks",
            "validation_contracts",
            "repository_configurations",
            "evidence_records",
        } <= validation_run_foreign_tables
        assert {
            tuple(constraint["column_names"])
            for constraint in inspector.get_unique_constraints("task_events")
        } >= {("task_id", "sequence")}
        assert {
            tuple(constraint["column_names"])
            for constraint in inspector.get_unique_constraints("background_job_leases")
        } >= {("fencing_token",), ("idempotency_key",)}
        assert {
            tuple(constraint["column_names"])
            for constraint in inspector.get_unique_constraints("webhook_deliveries")
        } >= {("provider", "provider_delivery_id")}

        with session_scope(factory) as session:
            created = create_task_record(
                session,
                repository="boppuh/mathews",
                base_revision="a" * 40,
                requester="local-user",
                raw_request="PostgreSQL and artifact durability smoke",
                summary="PostgreSQL and artifact durability smoke",
                owner_id="local-user",
                actor_id="postgres-test",
            )
            task_id = created.id
            root_correlation_id = created.root_correlation_id
            session.add(
                TaskEvent(
                    task_id=task_id,
                    sequence=1,
                    event_type="CREATED",
                    payload={},
                    occurred_at=datetime.now(UTC),
                    owner_id="local-user",
                    actor_id="postgres-test",
                    root_correlation_id=root_correlation_id,
                )
            )
        with pytest.raises(IntegrityError):
            with session_scope(factory) as session:
                session.add(
                    TaskEvent(
                        task_id=task_id,
                        sequence=1,
                        event_type="DUPLICATE",
                        payload={},
                        occurred_at=datetime.now(UTC),
                        owner_id="local-user",
                        actor_id="postgres-test",
                        root_correlation_id=root_correlation_id,
                    )
                )
        artifact = store.put_bytes(payload)
        bootstrap_token = generate_bootstrap_token(factory)

        def bootstrap_concurrently() -> IssuedSession | BootstrapAlreadyCompletedError:
            try:
                return authentication_service.bootstrap(
                    bootstrap_token=bootstrap_token,
                    password="correct horse battery staple",
                )
            except BootstrapAlreadyCompletedError as error:
                return error

        with ThreadPoolExecutor(max_workers=2) as executor:
            bootstrap_results = list(
                executor.map(lambda _attempt: bootstrap_concurrently(), range(2))
            )
        issued_sessions = [
            result for result in bootstrap_results if isinstance(result, IssuedSession)
        ]
        rejected_bootstraps = [
            result
            for result in bootstrap_results
            if isinstance(result, BootstrapAlreadyCompletedError)
        ]
        assert len(issued_sessions) == 1
        assert len(rejected_bootstraps) == 1
        issued_session = issued_sessions[0]
        engine.dispose()
        engine = None

        recreated_engine = create_database_engine(database_url)
        engine = recreated_engine
        recreated_factory = create_session_factory(recreated_engine)
        recreated_store = ArtifactStore(store.root)
        recreated_authentication_service = AuthenticationService(recreated_factory)
        with recreated_factory() as session:
            retrieved = get_task_record(session, task_id)
        authenticated = recreated_authentication_service.authenticate(issued_session.session_token)

        assert retrieved is not None
        assert retrieved.summary == "PostgreSQL and artifact durability smoke"
        assert artifact.address == f"sha256:{expected_digest}"
        assert recreated_store.get_bytes(artifact.address) == payload
        assert authenticated is not None
        assert recreated_authentication_service.bootstrap_status().bootstrap_required is False

        recreated_authentication_service.logout(authenticated)
        assert (
            AuthenticationService(recreated_factory).authenticate(issued_session.session_token)
            is None
        )
    finally:
        if engine is not None:
            engine.dispose()
        try:
            if schema_created:
                with admin_engine.begin() as connection:
                    connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        finally:
            admin_engine.dispose()
