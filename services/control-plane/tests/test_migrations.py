from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from mathews_control_plane.database import Base, create_database_engine
from sqlalchemy import create_engine, inspect, text

EXPECTED_HEAD_TABLES = {
    "alembic_version",
    "approval_requests",
    "auth_sessions",
    "authentication_state",
    "background_job_leases",
    "background_jobs",
    "brief_approval_decisions",
    "briefs",
    "evidence_records",
    "local_users",
    "policy_version_prompt_templates",
    "policy_version_review_rules",
    "policy_versions",
    "prompt_template_versions",
    "repository_configurations",
    "review_rules",
    "rule_candidates",
    "task_events",
    "tasks",
    "validation_contracts",
    "validation_runs",
    "webhook_deliveries",
}


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

    assert _table_names(database_url) == EXPECTED_HEAD_TABLES


def test_migrations_can_rebuild_schema_after_downgrade(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)

    command.upgrade(config, "head")
    command.downgrade(config, "base")
    assert _table_names(database_url) == {"alembic_version"}

    command.upgrade(config, "head")
    assert _table_names(database_url) == EXPECTED_HEAD_TABLES


def test_authentication_revision_can_downgrade_without_removing_tasks(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)

    command.upgrade(config, "head")
    command.downgrade(config, "0001")

    assert _table_names(database_url) == {"alembic_version", "tasks"}

    command.upgrade(config, "head")
    assert _table_names(database_url) == EXPECTED_HEAD_TABLES


def test_domain_revision_preserves_legacy_task_and_authentication_rows(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)
    task_id = "12345678123456781234567812345678"
    brief_id = "87654321876543218765432187654321"

    command.upgrade(config, "0002")
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("INSERT INTO tasks (id, summary) VALUES (:id, :summary)"),
                {"id": task_id, "summary": "Legacy durable task"},
            )
            connection.execute(
                text("INSERT INTO local_users (id, password_hash) VALUES (1, :password_hash)"),
                {"password_hash": "argon2id-test-hash"},
            )
    finally:
        engine.dispose()

    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO briefs ("
                    "id, task_id, version, scope, exclusions, acceptance_criteria, "
                    "risks, affected_flow, test_plan, owner_id, actor_id, "
                    "root_correlation_id"
                    ") VALUES ("
                    ":id, :task_id, 1, '{}', '[]', '[]', '[]', '{}', '[]', "
                    "'legacy-local-user', 'legacy-local-user', :task_id"
                    ")"
                ),
                {"id": brief_id, "task_id": task_id},
            )
            connection.execute(
                text("UPDATE tasks SET accepted_brief_id = :brief_id WHERE id = :task_id"),
                {"brief_id": brief_id, "task_id": task_id},
            )
            task_row = connection.execute(
                text(
                    "SELECT summary, owner_id, actor_id, state, raw_request "
                    "FROM tasks WHERE id = :id"
                ),
                {"id": task_id},
            ).one()
            local_user_count = connection.execute(
                text("SELECT count(*) FROM local_users WHERE id = 1")
            ).scalar_one()

        assert task_row == (
            "Legacy durable task",
            "legacy-local-user",
            "legacy-local-user",
            "INTAKE",
            "Legacy durable task",
        )
        assert local_user_count == 1
    finally:
        engine.dispose()

    command.downgrade(config, "0002")
    assert _table_names(database_url) == {
        "alembic_version",
        "auth_sessions",
        "authentication_state",
        "local_users",
        "tasks",
    }

    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT summary FROM tasks WHERE id = :id"),
                    {"id": task_id},
                ).scalar_one()
                == "Legacy durable task"
            )
            assert (
                connection.execute(
                    text("SELECT count(*) FROM local_users WHERE id = 1")
                ).scalar_one()
                == 1
            )
    finally:
        engine.dispose()


def test_migrations_match_declared_model_metadata(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)
    command.upgrade(config, "head")
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(
                connection,
                opts={"compare_type": True},
            )
            assert compare_metadata(context, Base.metadata) == []
    finally:
        engine.dispose()


def test_offline_postgres_migration_sql_hides_database_password(
    capsys: pytest.CaptureFixture[str],
) -> None:
    password = "database-password-that-must-not-leak"
    config = _migration_config(f"postgresql+psycopg://mathews:{password}@127.0.0.1:5432/mathews")

    command.upgrade(config, "head", sql=True)

    captured = capsys.readouterr()
    assert "CREATE TABLE tasks" in captured.out
    assert "CREATE TABLE authentication_state" in captured.out
    assert "CREATE TABLE local_users" in captured.out
    assert "CREATE TABLE auth_sessions" in captured.out
    assert "CREATE TABLE validation_contracts" in captured.out
    assert "CREATE TABLE webhook_deliveries" in captured.out
    assert password not in captured.out
    assert password not in captured.err
