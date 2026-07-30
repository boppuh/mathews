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
            created = create_task_record(session, summary="  Prove durable storage  ")
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
                create_task_record(session, summary="  ")
    finally:
        engine.dispose()


def test_task_record_rejects_summary_over_storage_limit(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'tasks.sqlite3'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)

    try:
        with pytest.raises(ValueError, match="must not exceed 500"):
            with session_scope(factory) as session:
                create_task_record(session, summary="a" * 501)
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
                task_id = create_task_record(session, summary="Rollback me").id
                raise RuntimeError("abort")

        assert task_id is not None
        with factory() as session:
            assert get_task_record(session, task_id) is None
    finally:
        engine.dispose()
