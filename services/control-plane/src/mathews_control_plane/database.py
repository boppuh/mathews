from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from uuid import UUID, uuid4

from pydantic import SecretStr
from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Engine,
    ForeignKey,
    LargeBinary,
    MetaData,
    SmallInteger,
    String,
    Uuid,
    create_engine,
    func,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

_NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base shared by control-plane database models."""

    metadata = MetaData(naming_convention=_NAMING_CONVENTION)


class TaskRecord(Base):
    """Minimal durable task used by the infrastructure smoke test.

    The complete task domain belongs to MVP task 1.1. This table intentionally
    stores only the stable identity and user-supplied summary needed to prove
    that the local database can persist and retrieve a task.
    """

    __tablename__ = "tasks"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    summary: Mapped[str] = mapped_column(String(500), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class AuthenticationState(Base):
    """Singleton state for the one-time, out-of-band bootstrap ceremony."""

    __tablename__ = "authentication_state"
    __table_args__ = (
        CheckConstraint("id = 1", name="singleton"),
    )

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, default=1)
    bootstrap_token_digest: Mapped[bytes | None] = mapped_column(LargeBinary(32))
    failed_login_attempts: Mapped[int] = mapped_column(
        SmallInteger,
        nullable=False,
        default=0,
        server_default="0",
    )
    login_blocked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class LocalUser(Base):
    """The single local operator account."""

    __tablename__ = "local_users"
    __table_args__ = (
        CheckConstraint("id = 1", name="singleton"),
    )

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, default=1)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class AuthSession(Base):
    """Durable server-side session; raw credentials are never persisted."""

    __tablename__ = "auth_sessions"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[int] = mapped_column(
        SmallInteger,
        ForeignKey("local_users.id", ondelete="CASCADE"),
        nullable=False,
    )
    token_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False, unique=True)
    csrf_token_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    absolute_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    reauthenticated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


type SessionFactory = sessionmaker[Session]


def create_database_engine(database_url: str | SecretStr) -> Engine:
    """Create a lazy SQLAlchemy engine without opening a database connection."""

    url = database_url.get_secret_value() if isinstance(database_url, SecretStr) else database_url
    return create_engine(url, pool_pre_ping=True)


def create_session_factory(engine: Engine) -> SessionFactory:
    """Return the control-plane's typed, transaction-ready session factory."""

    return sessionmaker(bind=engine, class_=Session, expire_on_commit=False)


@contextmanager
def session_scope(factory: SessionFactory) -> Iterator[Session]:
    """Commit a unit of work, rolling it back if the operation fails."""

    with factory() as session, session.begin():
        yield session


def create_task_record(session: Session, *, summary: str) -> TaskRecord:
    """Stage and flush a minimal task record in the caller's transaction."""

    normalized_summary = summary.strip()
    if not normalized_summary:
        raise ValueError("task summary must not be empty")
    if len(normalized_summary) > 500:
        raise ValueError("task summary must not exceed 500 characters")

    task = TaskRecord(summary=normalized_summary)
    session.add(task)
    session.flush()
    return task


def get_task_record(session: Session, task_id: UUID) -> TaskRecord | None:
    """Retrieve a task record by its stable identifier."""

    return session.scalar(select(TaskRecord).where(TaskRecord.id == task_id))
