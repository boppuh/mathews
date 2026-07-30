from pathlib import Path
from uuid import UUID

import pytest
from mathews_control_plane.database import (
    Base,
    create_database_engine,
    create_session_factory,
    create_task_record,
    get_task_record,
    session_scope,
)
from pydantic import SecretStr


def _task_arguments(summary: str) -> dict[str, str]:
    return {
        "repository": "boppuh/mathews",
        "base_revision": "a" * 40,
        "requester": "local-user",
        "raw_request": summary,
        "summary": summary,
        "owner_id": "local-user",
        "actor_id": "database-test",
    }


def test_database_engine_is_lazy_and_redacts_credentials(tmp_path: Path) -> None:
    database_path = tmp_path / "lazy.sqlite3"

    engine = create_database_engine(SecretStr(f"sqlite:///{database_path}"))
    try:
        assert not database_path.exists()
        assert str(engine.url) == f"sqlite:///{database_path}"
    finally:
        engine.dispose()


def test_database_engine_does_not_render_password() -> None:
    password = "database-secret-marker"
    engine = create_database_engine(
        SecretStr(f"postgresql+psycopg://mathews:{password}@127.0.0.1:5432/mathews")
    )

    try:
        assert password not in str(engine.url)
        assert password not in repr(engine)
    finally:
        engine.dispose()


def test_task_record_round_trip(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'tasks.sqlite3'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)

    try:
        with session_scope(factory) as session:
            created = create_task_record(
                session,
                **_task_arguments("  Prove durable storage  "),
            )
            task_id = created.id

        assert isinstance(task_id, UUID)

        with factory() as session:
            retrieved = get_task_record(session, task_id)

        assert retrieved is not None
        assert retrieved.id == task_id
        assert retrieved.summary == "Prove durable storage"
        assert retrieved.created_at is not None
        assert retrieved.updated_at is not None
    finally:
        engine.dispose()


def test_task_record_rejects_empty_summary(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'tasks.sqlite3'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)

    try:
        with pytest.raises(ValueError, match="must not be empty"):
            with session_scope(factory) as session:
                create_task_record(session, **_task_arguments("  "))
    finally:
        engine.dispose()


def test_task_record_rejects_summary_over_storage_limit(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'tasks.sqlite3'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)

    try:
        with pytest.raises(ValueError, match="must not exceed 500"):
            with session_scope(factory) as session:
                create_task_record(session, **_task_arguments("a" * 501))
    finally:
        engine.dispose()


def test_task_record_requires_an_exact_base_revision(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'tasks.sqlite3'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    arguments = _task_arguments("Reject a mutable base")
    arguments["base_revision"] = "HEAD"

    try:
        with pytest.raises(ValueError, match="exact 40- or 64-character"):
            with session_scope(factory) as session:
                create_task_record(session, **arguments)
    finally:
        engine.dispose()


def test_session_scope_rolls_back_failed_unit_of_work(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'tasks.sqlite3'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    task_id: UUID | None = None

    try:
        with pytest.raises(RuntimeError, match="abort"):
            with session_scope(factory) as session:
                task_id = create_task_record(
                    session,
                    **_task_arguments("Rollback me"),
                ).id
                raise RuntimeError("abort")

        assert task_id is not None
        with factory() as session:
            assert get_task_record(session, task_id) is None
    finally:
        engine.dispose()
