from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from mathews_configuration import SecretValue
from pydantic import SecretStr
from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Engine,
    ForeignKey,
    LargeBinary,
    SmallInteger,
    String,
    Uuid,
    create_engine,
    event,
    func,
    select,
)
from sqlalchemy.orm import Mapped, Session, mapped_column, sessionmaker

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.database_base import Base as Base
from mathews_control_plane.domain_models import Task


class AuthenticationState(Base):
    """Singleton state for the one-time, out-of-band bootstrap ceremony."""

    __tablename__ = "authentication_state"
    __table_args__ = (CheckConstraint("id = 1", name="singleton"),)

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
    __table_args__ = (CheckConstraint("id = 1", name="singleton"),)

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


TaskRecord = Task


type SessionFactory = sessionmaker[Session]


def _enable_sqlite_foreign_keys(
    dbapi_connection: Any,
    _connection_record: Any,
) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


def create_database_engine(database_url: str | SecretStr) -> Engine:
    """Create a lazy SQLAlchemy engine without opening a database connection."""

    url = database_url.get_secret_value() if isinstance(database_url, SecretStr) else database_url
    engine = create_engine(url, pool_pre_ping=True)
    if engine.dialect.name == "sqlite":
        event.listen(engine, "connect", _enable_sqlite_foreign_keys)
    return engine


def create_session_factory(engine: Engine) -> SessionFactory:
    """Return the control-plane's typed, transaction-ready session factory."""

    return sessionmaker(bind=engine, class_=Session, expire_on_commit=False)


@contextmanager
def session_scope(factory: SessionFactory) -> Iterator[Session]:
    """Commit a unit of work, rolling it back if the operation fails."""

    with factory() as session, session.begin():
        yield session


def create_task_record(
    session: Session,
    artifact_store: ArtifactStore,
    *,
    repository: str,
    base_revision: str,
    requester: str,
    raw_request: str,
    summary: str,
    owner_id: str,
    actor_id: str,
    secrets: Sequence[SecretValue] = (),
) -> TaskRecord:
    """Capture a redacted request, then stage its linked task record."""

    # Local import avoids a module cycle: evidence uses SessionFactory.
    from mathews_control_plane.evidence import (
        EvidenceAccessClass,
        EvidenceRetentionClass,
        EvidenceSourceKind,
        capture_evidence,
        redact_evidence_content,
    )

    redacted_summary = redact_evidence_content(
        summary,
        media_type="text/plain; charset=utf-8",
        secrets=secrets,
    )
    normalized_summary = str(redacted_summary.value).strip()
    if not normalized_summary:
        raise ValueError("task summary must not be empty")
    if len(normalized_summary) > 500:
        raise ValueError("task summary must not exceed 500 characters")

    normalized_repository = repository.strip()
    if not normalized_repository:
        raise ValueError("task repository must not be empty")
    if len(normalized_repository) > 500:
        raise ValueError("task repository must not exceed 500 characters")

    normalized_base_revision = base_revision.strip().lower()
    if len(normalized_base_revision) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in normalized_base_revision
    ):
        raise ValueError("task base revision must be an exact 40- or 64-character Git object ID")

    normalized_requester = requester.strip()
    if not normalized_requester:
        raise ValueError("task requester must not be empty")
    if not raw_request.strip():
        raise ValueError("task raw request must not be empty")
    normalized_owner_id = owner_id.strip()
    normalized_actor_id = actor_id.strip()
    if not normalized_owner_id or not normalized_actor_id:
        raise ValueError("task owner and actor must not be empty")

    task_id = uuid4()
    task = TaskRecord(
        id=task_id,
        root_correlation_id=task_id,
        repository=normalized_repository,
        base_revision=normalized_base_revision,
        requester=normalized_requester,
        # The authoritative request content exists only in its evidence
        # envelope. This placeholder is replaced with the evidence identifier
        # below and never contains a second content copy.
        raw_request="evidence://capture-pending",
        summary=normalized_summary,
        owner_id=normalized_owner_id,
        actor_id=normalized_actor_id,
    )
    session.add(task)
    session.flush()
    captured_request = capture_evidence(
        session,
        artifact_store,
        payload=raw_request,
        media_type="text/plain; charset=utf-8",
        source_kind=EvidenceSourceKind.REQUEST,
        evidence_type="task-request",
        origin="control-plane:task-intake",
        access_classification=EvidenceAccessClass.TASK_OWNER,
        retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
        owner_id=normalized_owner_id,
        actor_id=normalized_actor_id,
        root_correlation_id=task_id,
        task_id=task_id,
        secrets=secrets,
    )
    task.raw_request = f"evidence://{captured_request.record.id}"
    session.flush()
    return task


def get_task_record(session: Session, task_id: UUID) -> TaskRecord | None:
    """Retrieve a task record by its stable identifier."""

    return session.scalar(select(TaskRecord).where(TaskRecord.id == task_id))
