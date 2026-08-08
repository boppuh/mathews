"""Typed persistence models for the Mathews control-plane domain."""

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from mathews_control_plane.database_base import Base


class TaskState(StrEnum):
    """Canonical durable task states shared with the public contracts package."""

    INTAKE = "INTAKE"
    BRIEFING = "BRIEFING"
    BRIEF_PENDING_APPROVAL = "BRIEF_PENDING_APPROVAL"
    IMPLEMENTING = "IMPLEMENTING"
    VALIDATING = "VALIDATING"
    REPAIRING = "REPAIRING"
    PR_ACTIVE = "PR_ACTIVE"
    READY_FOR_HUMAN_MERGE = "READY_FOR_HUMAN_MERGE"
    HANDED_OFF = "HANDED_OFF"
    ESCALATED = "ESCALATED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


TASK_STATE_VALUES = tuple(state.value for state in TaskState)


def _hex_only_sql(column: str) -> str:
    expression = column
    for character in "0123456789abcdef":
        expression = f"replace({expression}, '{character}', '')"
    return f"length({expression}) = 0"


class TaskTerminalOutcome(StrEnum):
    """Safe terminal codes; explanatory content belongs in evidence."""

    AUTOMATION_HANDED_OFF = "AUTOMATION_HANDED_OFF"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class BriefDecisionDisposition(StrEnum):
    AUTO_ACCEPTED_BY_POLICY = "AUTO_ACCEPTED_BY_POLICY"
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"


class ValidationOutcome(StrEnum):
    PENDING = "PENDING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    ESCALATED = "ESCALATED"
    CANCELLED = "CANCELLED"


class ApprovalStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


class ApprovalRequestType(StrEnum):
    BRIEF = "BRIEF"
    UNSAFE_ACTION = "UNSAFE_ACTION"
    RETRY_LIMIT = "RETRY_LIMIT"
    REVIEW_CONFLICT = "REVIEW_CONFLICT"
    REVIEW_RULE = "REVIEW_RULE"


class ApprovalDecision(StrEnum):
    APPROVE = "APPROVE"
    REQUEST_REVISION = "REQUEST_REVISION"
    RETRY = "RETRY"
    DENY = "DENY"
    REJECT = "REJECT"
    ABANDON = "ABANDON"
    CANCEL = "CANCEL"
    EXPIRE = "EXPIRE"


class RuleCandidateStatus(StrEnum):
    PROPOSED = "PROPOSED"
    EVALUATED = "EVALUATED"
    REJECTED = "REJECTED"
    APPROVED = "APPROVED"


class BackgroundJobStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class BackgroundJobEffectStatus(StrEnum):
    PENDING = "PENDING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class DependencyService(StrEnum):
    HOST = "HOST"
    HERMES = "HERMES"
    GITHUB = "GITHUB"


class HermesRunStatus(StrEnum):
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"


class HermesToolDecisionStatus(StrEnum):
    AUTHORIZED = "AUTHORIZED"
    DENIED = "DENIED"


class HermesToolResultStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    REJECTED = "REJECTED"
    AMBIGUOUS = "AMBIGUOUS"


class OwnedHostProcessStatus(StrEnum):
    RUNNING = "RUNNING"
    TERMINATION_REQUESTED = "TERMINATION_REQUESTED"
    TERMINATED = "TERMINATED"
    GONE = "GONE"


class ReconciliationTargetKind(StrEnum):
    HERMES_RUN = "HERMES_RUN"
    HOST_PROCESS = "HOST_PROCESS"
    BRANCH_HEAD = "BRANCH_HEAD"
    PR_HEAD = "PR_HEAD"
    WEBHOOK_CURSOR = "WEBHOOK_CURSOR"


class ReconciliationStatus(StrEnum):
    PENDING = "PENDING"
    CURRENT = "CURRENT"
    UPDATED = "UPDATED"
    QUARANTINED = "QUARANTINED"
    RETRY_REQUIRED = "RETRY_REQUIRED"
    CANCELLED = "CANCELLED"


def _enum(enum_class: type[StrEnum], *, name: str, length: int = 64) -> Enum:
    return Enum(
        enum_class,
        name=name,
        native_enum=False,
        create_constraint=True,
        validate_strings=True,
        values_callable=lambda members: [member.value for member in members],
        length=length,
    )


class RecordContext:
    """Ownership, actor, correlation, lineage, and timestamp fields."""

    owner_id: Mapped[str] = mapped_column(String(255), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    root_correlation_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    causation_id: Mapped[UUID | None] = mapped_column(Uuid)
    parent_correlation_id: Mapped[UUID | None] = mapped_column(Uuid)
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


class Task(RecordContext, Base):
    """Authoritative durable task aggregate."""

    __tablename__ = "tasks"
    __table_args__ = (
        CheckConstraint("retry_count >= 0", name="retry_count_non_negative"),
        CheckConstraint("length(base_revision) IN (40, 64)", name="base_revision_length"),
        ForeignKeyConstraint(
            ["id", "accepted_brief_id"],
            ["briefs.task_id", "briefs.id"],
            ondelete="RESTRICT",
            use_alter=True,
        ),
        ForeignKeyConstraint(
            ["id", "brief_approval_decision_id"],
            ["brief_approval_decisions.task_id", "brief_approval_decisions.id"],
            ondelete="RESTRICT",
            use_alter=True,
        ),
        ForeignKeyConstraint(
            ["repository", "repository_configuration_id"],
            [
                "repository_configurations.repository_key",
                "repository_configurations.id",
            ],
            ondelete="RESTRICT",
            use_alter=True,
        ),
        ForeignKeyConstraint(
            ["id", "validation_contract_id"],
            ["validation_contracts.task_id", "validation_contracts.id"],
            ondelete="RESTRICT",
            use_alter=True,
        ),
        ForeignKeyConstraint(
            ["brief_approval_decision_id", "accepted_brief_id"],
            ["brief_approval_decisions.id", "brief_approval_decisions.brief_id"],
            ondelete="RESTRICT",
            use_alter=True,
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    repository: Mapped[str] = mapped_column(String(500), nullable=False)
    base_revision: Mapped[str] = mapped_column(String(255), nullable=False)
    requester: Mapped[str] = mapped_column(String(255), nullable=False)
    raw_request: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str] = mapped_column(String(500), nullable=False)
    state: Mapped[TaskState] = mapped_column(
        _enum(TaskState, name="task_state", length=32),
        nullable=False,
        default=TaskState.INTAKE,
        server_default=TaskState.INTAKE.value,
    )
    accepted_brief_id: Mapped[UUID | None] = mapped_column(Uuid)
    brief_approval_decision_id: Mapped[UUID | None] = mapped_column(Uuid)
    repository_configuration_id: Mapped[UUID | None] = mapped_column(Uuid)
    validation_contract_id: Mapped[UUID | None] = mapped_column(Uuid)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    escalation_resume_state: Mapped[TaskState | None] = mapped_column(
        _enum(TaskState, name="task_escalation_resume_state", length=32)
    )
    terminal_outcome: Mapped[str | None] = mapped_column(Text)


class Brief(RecordContext, Base):
    """Immutable, versioned statement of task scope and acceptance."""

    __tablename__ = "briefs"
    __table_args__ = (
        CheckConstraint("version > 0", name="version_positive"),
        CheckConstraint(
            "predecessor_id IS NULL OR predecessor_id <> id", name="predecessor_not_self"
        ),
        UniqueConstraint("task_id", "version", name="uq_briefs_task_version"),
        UniqueConstraint("task_id", "id", name="uq_briefs_task_id"),
        ForeignKeyConstraint(
            ["task_id", "predecessor_id"],
            ["briefs.task_id", "briefs.id"],
            ondelete="RESTRICT",
            use_alter=True,
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    task_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    predecessor_id: Mapped[UUID | None] = mapped_column(Uuid)
    scope: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    exclusions: Mapped[list[object]] = mapped_column(JSON, nullable=False)
    acceptance_criteria: Mapped[list[object]] = mapped_column(JSON, nullable=False)
    risks: Mapped[list[object]] = mapped_column(JSON, nullable=False)
    affected_flow: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    test_plan: Mapped[list[object]] = mapped_column(JSON, nullable=False)


class RepositoryConfiguration(RecordContext, Base):
    """Immutable version of non-secret repository execution configuration."""

    __tablename__ = "repository_configurations"
    __table_args__ = (
        CheckConstraint("version > 0", name="version_positive"),
        CheckConstraint(
            "predecessor_id IS NULL OR predecessor_id <> id", name="predecessor_not_self"
        ),
        UniqueConstraint(
            "repository_key",
            "version",
            name="uq_repository_configurations_repository_version",
        ),
        UniqueConstraint(
            "repository_key",
            "id",
            name="uq_repository_configurations_repository_id",
        ),
        ForeignKeyConstraint(
            ["repository_key", "predecessor_id"],
            ["repository_configurations.repository_key", "repository_configurations.id"],
            ondelete="RESTRICT",
            use_alter=True,
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    repository_key: Mapped[str] = mapped_column(String(500), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    predecessor_id: Mapped[UUID | None] = mapped_column(Uuid)
    repository_settings: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    git_settings: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    xcode_settings: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    operations: Mapped[list[object]] = mapped_column(JSON, nullable=False)
    e2e_assertions: Mapped[list[object]] = mapped_column(JSON, nullable=False)
    artifact_settings: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    prohibited_paths: Mapped[list[object]] = mapped_column(JSON, nullable=False)
    secret_references: Mapped[list[object]] = mapped_column(JSON, nullable=False)
    preflight_evidence_id: Mapped[UUID | None] = mapped_column(
        Uuid,
        ForeignKey(
            "evidence_records.id",
            ondelete="RESTRICT",
            use_alter=True,
        ),
    )


class TaskEvent(RecordContext, Base):
    """Append-only, ordered event in a task's activity stream."""

    __tablename__ = "task_events"
    __table_args__ = (
        CheckConstraint("sequence > 0", name="sequence_positive"),
        UniqueConstraint("task_id", "sequence", name="uq_task_events_task_sequence"),
        UniqueConstraint("task_id", "id", name="uq_task_events_task_id"),
        UniqueConstraint("transition_id", name="uq_task_events_transition_id"),
        ForeignKeyConstraint(
            ["policy_lineage_key", "policy_version_id"],
            ["policy_versions.lineage_key", "policy_versions.id"],
            ondelete="RESTRICT",
            use_alter=True,
        ),
        CheckConstraint(
            "("
            "event_type = 'TASK_STATE_TRANSITION' "
            "AND transition_id IS NOT NULL "
            "AND transition_fingerprint IS NOT NULL "
            "AND transition_kind IS NOT NULL "
            "AND transition_from_state IS NOT NULL "
            "AND transition_to_state IS NOT NULL "
            "AND transition_reason_code IS NOT NULL "
            "AND policy_lineage_key IS NOT NULL "
            "AND policy_version_id IS NOT NULL"
            ") OR ("
            "event_type <> 'TASK_STATE_TRANSITION' "
            "AND transition_id IS NULL "
            "AND transition_fingerprint IS NULL "
            "AND transition_kind IS NULL "
            "AND transition_from_state IS NULL "
            "AND transition_to_state IS NULL "
            "AND transition_reason_code IS NULL "
            "AND policy_lineage_key IS NULL "
            "AND policy_version_id IS NULL "
            "AND gate_head_sha IS NULL"
            ")",
            name="transition_shape",
        ),
        CheckConstraint(
            "transition_kind IS NULL OR transition_kind IN ("
            "'START_BRIEFING', 'AUTO_ACCEPT_BRIEF', 'REQUEST_BRIEF_APPROVAL', "
            "'REVISE_BRIEF', 'APPROVE_EXACT_BRIEF', 'BEGIN_VALIDATION', "
            "'BEGIN_REPAIR', 'REVALIDATE', 'OPEN_VERIFIED_DRAFT_PR', "
            "'MARK_MERGE_READY', 'INVALIDATE_READINESS', 'ACKNOWLEDGE_HANDOFF', "
            "'ESCALATE', 'RESUME', 'CANCEL', 'FAIL', 'SCOPE_STEER'"
            ")",
            name="transition_kind",
        ),
        CheckConstraint(
            "("
            "transition_kind IN ("
            "'OPEN_VERIFIED_DRAFT_PR', 'MARK_MERGE_READY', 'ACKNOWLEDGE_HANDOFF'"
            ") AND gate_head_sha IS NOT NULL"
            ") OR ("
            "transition_kind NOT IN ("
            "'OPEN_VERIFIED_DRAFT_PR', 'MARK_MERGE_READY', 'ACKNOWLEDGE_HANDOFF'"
            ") AND gate_head_sha IS NULL"
            ") OR transition_kind IS NULL",
            name="transition_gate_head_shape",
        ),
        CheckConstraint(
            "transition_fingerprint IS NULL OR length(transition_fingerprint) = 64",
            name="transition_fingerprint_length",
        ),
        CheckConstraint(
            "gate_head_sha IS NULL OR ("
            "length(gate_head_sha) IN (40, 64) AND "
            f"{_hex_only_sql('gate_head_sha')}"
            ")",
            name="gate_head_sha_length",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    task_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("tasks.id", ondelete="RESTRICT"), nullable=False
    )
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    transition_id: Mapped[UUID | None] = mapped_column(Uuid)
    transition_fingerprint: Mapped[str | None] = mapped_column(String(64))
    transition_kind: Mapped[str | None] = mapped_column(String(64))
    transition_from_state: Mapped[TaskState | None] = mapped_column(
        _enum(TaskState, name="task_event_transition_from_state", length=32)
    )
    transition_to_state: Mapped[TaskState | None] = mapped_column(
        _enum(TaskState, name="task_event_transition_to_state", length=32)
    )
    transition_reason_code: Mapped[str | None] = mapped_column(String(100))
    policy_lineage_key: Mapped[str | None] = mapped_column(String(255))
    policy_version_id: Mapped[UUID | None] = mapped_column(Uuid)
    gate_head_sha: Mapped[str | None] = mapped_column(String(64))


class EvidenceRecord(RecordContext, Base):
    """Immutable reference to canonical redacted evidence."""

    __tablename__ = "evidence_records"
    __table_args__ = (
        CheckConstraint(
            "correction_of_id IS NULL OR correction_of_id <> id", name="correction_not_self"
        ),
        CheckConstraint(
            "access_classification IN ('TASK_OWNER', 'OWNER', 'RECENT_PASSWORD', 'INTERNAL')",
            name="access_classification",
        ),
        CheckConstraint(
            "retention_policy IN ('TASK_LIFETIME', 'REPOSITORY_LIFETIME', 'AUDIT')",
            name="retention_policy",
        ),
        UniqueConstraint("correction_of_id", name="uq_evidence_records_correction"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    task_id: Mapped[UUID | None] = mapped_column(
        Uuid,
        ForeignKey("tasks.id", ondelete="RESTRICT"),
    )
    validation_run_id: Mapped[UUID | None] = mapped_column(
        Uuid,
        ForeignKey("validation_runs.id", ondelete="RESTRICT", use_alter=True),
    )
    evidence_type: Mapped[str] = mapped_column(String(100), nullable=False)
    origin: Mapped[str] = mapped_column(String(500), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    content_address: Mapped[str | None] = mapped_column(String(255))
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    access_classification: Mapped[str] = mapped_column(String(100), nullable=False)
    retention_policy: Mapped[str] = mapped_column(String(100), nullable=False)
    correction_of_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("evidence_records.id", ondelete="RESTRICT")
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deletion_actor_id: Mapped[str | None] = mapped_column(String(255))
    deletion_reason: Mapped[str | None] = mapped_column(Text)


class EvidenceAuditEvent(RecordContext, Base):
    """Append-only, non-content audit event for an evidence record."""

    __tablename__ = "evidence_audit_events"
    __table_args__ = (
        CheckConstraint(
            "event_type IN "
            "('CAPTURED', 'METADATA_READ', 'CONTENT_DOWNLOADED', "
            "'CORRECTION_CREATED', 'DELETION_REQUESTED', 'CONTENT_DESTROYED', "
            "'DERIVATIVE_REGISTERED')",
            name="event_type",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    evidence_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("evidence_records.id", ondelete="RESTRICT"),
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    session_id: Mapped[UUID | None] = mapped_column(Uuid)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    details: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)


class EvidenceDeletionRequest(RecordContext, Base):
    """Durable fence that makes evidence unreadable before content removal."""

    __tablename__ = "evidence_deletion_requests"
    __table_args__ = (
        UniqueConstraint("evidence_id", name="uq_evidence_deletion_requests_evidence"),
        UniqueConstraint(
            "id",
            "evidence_id",
            "reason_code",
            name="uq_evidence_deletion_requests_identity",
        ),
        CheckConstraint(
            "reason_code IN "
            "('USER_REQUEST', 'RETENTION_EXPIRED', 'SOURCE_REVOKED', "
            "'SECURITY_RESPONSE')",
            name="reason_code",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    evidence_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("evidence_records.id", ondelete="RESTRICT"),
        nullable=False,
    )
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class EvidenceTombstone(RecordContext, Base):
    """Minimal completion marker retained after evidence content is destroyed."""

    __tablename__ = "evidence_tombstones"
    __table_args__ = (
        UniqueConstraint("evidence_id", name="uq_evidence_tombstones_evidence"),
        UniqueConstraint(
            "deletion_request_id",
            name="uq_evidence_tombstones_deletion_request",
        ),
        CheckConstraint(
            "reason_code IN "
            "('USER_REQUEST', 'RETENTION_EXPIRED', 'SOURCE_REVOKED', "
            "'SECURITY_RESPONSE')",
            name="reason_code",
        ),
        CheckConstraint(
            "removed_derivative_count >= 0",
            name="removed_derivative_count_non_negative",
        ),
        ForeignKeyConstraint(
            ["deletion_request_id", "evidence_id", "reason_code"],
            [
                "evidence_deletion_requests.id",
                "evidence_deletion_requests.evidence_id",
                "evidence_deletion_requests.reason_code",
            ],
            name="fk_evidence_tombstones_deletion_request_identity",
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    evidence_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("evidence_records.id", ondelete="RESTRICT"),
        nullable=False,
    )
    deletion_request_id: Mapped[UUID] = mapped_column(
        Uuid,
        nullable=False,
    )
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    deleted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    removed_derivative_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )


class EvidenceDerivative(RecordContext, Base):
    """Registered rebuildable index/cache content derived from source evidence."""

    __tablename__ = "evidence_derivatives"
    __table_args__ = (
        CheckConstraint(
            "(deleted_at IS NULL AND content_address IS NOT NULL) OR "
            "(deleted_at IS NOT NULL AND content_address IS NULL)",
            name="deletion_state",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    evidence_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("evidence_records.id", ondelete="RESTRICT"),
        nullable=False,
    )
    derivative_type: Mapped[str] = mapped_column(String(100), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    content_address: Mapped[str | None] = mapped_column(String(255))
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TaskEventEvidenceReference(RecordContext, Base):
    """Ordered, task-bound evidence provenance for one transition event."""

    __tablename__ = "task_event_evidence_references"
    __table_args__ = (
        CheckConstraint("position > 0", name="position_positive"),
        UniqueConstraint(
            "task_event_id",
            "position",
            name="uq_task_event_evidence_position",
        ),
        UniqueConstraint(
            "task_event_id",
            "evidence_id",
            name="uq_task_event_evidence_membership",
        ),
        ForeignKeyConstraint(
            ["task_id", "task_event_id"],
            ["task_events.task_id", "task_events.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence_records.id"],
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    task_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    task_event_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    evidence_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    position: Mapped[int] = mapped_column(Integer, nullable=False)


class ValidationContract(RecordContext, Base):
    """Immutable validation definition bound to exact brief and repository versions."""

    __tablename__ = "validation_contracts"
    __table_args__ = (
        CheckConstraint("version > 0", name="version_positive"),
        CheckConstraint(
            "predecessor_id IS NULL OR predecessor_id <> id", name="predecessor_not_self"
        ),
        UniqueConstraint("task_id", "version", name="uq_validation_contracts_task_version"),
        UniqueConstraint("task_id", "id", name="uq_validation_contracts_task_id"),
        UniqueConstraint(
            "id",
            "repository_configuration_id",
            name="uq_validation_contracts_id_repository_configuration",
        ),
        ForeignKeyConstraint(
            ["task_id", "predecessor_id"],
            ["validation_contracts.task_id", "validation_contracts.id"],
            ondelete="RESTRICT",
            use_alter=True,
        ),
        ForeignKeyConstraint(
            ["task_id", "brief_id"],
            ["briefs.task_id", "briefs.id"],
            ondelete="RESTRICT",
            use_alter=True,
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    task_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    predecessor_id: Mapped[UUID | None] = mapped_column(Uuid)
    brief_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    repository_configuration_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("repository_configurations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    required_operations: Mapped[list[object]] = mapped_column(JSON, nullable=False)
    simulator_setup: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    clean_state_setup: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    e2e_flow: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    typed_assertions: Mapped[list[object]] = mapped_column(JSON, nullable=False)
    evidence_requirements: Mapped[list[object]] = mapped_column(JSON, nullable=False)
    timeouts: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    outcome_rules: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)


class ValidationRun(RecordContext, Base):
    """A validation result tied to immutable inputs and exact Git objects."""

    __tablename__ = "validation_runs"
    __table_args__ = (
        CheckConstraint("duration_ms >= 0", name="duration_non_negative"),
        CheckConstraint("length(commit_sha) IN (40, 64)", name="commit_sha_length"),
        CheckConstraint("length(tree_sha) IN (40, 64)", name="tree_sha_length"),
        ForeignKeyConstraint(
            ["task_id", "validation_contract_id"],
            ["validation_contracts.task_id", "validation_contracts.id"],
            ondelete="RESTRICT",
            use_alter=True,
        ),
        ForeignKeyConstraint(
            ["validation_contract_id", "repository_configuration_id"],
            [
                "validation_contracts.id",
                "validation_contracts.repository_configuration_id",
            ],
            ondelete="RESTRICT",
            use_alter=True,
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    task_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False
    )
    validation_contract_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    repository_configuration_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    commit_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    tree_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    configured_test_plan: Mapped[list[object]] = mapped_column(JSON, nullable=False)
    operation_results: Mapped[list[object]] = mapped_column(JSON, nullable=False)
    simulator_target: Mapped[dict[str, object] | None] = mapped_column(JSON)
    outcome: Mapped[ValidationOutcome] = mapped_column(
        _enum(ValidationOutcome, name="validation_run_outcome"),
        nullable=False,
        default=ValidationOutcome.PENDING,
        server_default=ValidationOutcome.PENDING.value,
    )
    duration_ms: Mapped[int] = mapped_column(BigInteger, nullable=False)
    log_evidence_id: Mapped[UUID | None] = mapped_column(
        Uuid,
        ForeignKey(
            "evidence_records.id",
            ondelete="RESTRICT",
            use_alter=True,
        ),
    )
    acceptance_criterion_results: Mapped[list[object]] = mapped_column(JSON, nullable=False)


class BriefApprovalDecision(RecordContext, Base):
    """Disposition for one exact immutable brief version."""

    __tablename__ = "brief_approval_decisions"
    __table_args__ = (
        UniqueConstraint("brief_id", name="uq_brief_approval_decisions_brief"),
        UniqueConstraint(
            "task_id",
            "id",
            name="uq_brief_approval_decisions_task_id",
        ),
        UniqueConstraint(
            "id",
            "brief_id",
            name="uq_brief_approval_decisions_id_brief",
        ),
        ForeignKeyConstraint(
            ["task_id", "brief_id"],
            ["briefs.task_id", "briefs.id"],
            ondelete="RESTRICT",
            use_alter=True,
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    task_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False
    )
    brief_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    disposition: Mapped[BriefDecisionDisposition] = mapped_column(
        _enum(BriefDecisionDisposition, name="brief_decision_disposition"),
        nullable=False,
    )
    evaluator_id: Mapped[str] = mapped_column(String(255), nullable=False)
    policy_version_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("policy_versions.id", ondelete="RESTRICT")
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    ambiguity_flags: Mapped[list[object]] = mapped_column(JSON, nullable=False)
    human_response: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ApprovalRequest(RecordContext, Base):
    """Durable human decision request for an exact task state."""

    __tablename__ = "approval_requests"
    __table_args__ = (
        CheckConstraint(
            f"length(request_fingerprint) = 64 AND {_hex_only_sql('request_fingerprint')}",
            name="request_fingerprint",
        ),
        CheckConstraint(
            "length(precondition_fingerprint) = 64 AND "
            f"{_hex_only_sql('precondition_fingerprint')}",
            name="precondition_fingerprint",
        ),
        CheckConstraint(
            "decision_fingerprint IS NULL OR ("
            "length(decision_fingerprint) = 64 AND "
            f"{_hex_only_sql('decision_fingerprint')}"
            ")",
            name="decision_fingerprint",
        ),
        UniqueConstraint("id", "status", name="uq_approval_requests_id_status"),
        UniqueConstraint(
            "decision_id",
            name="uq_approval_requests_decision_id",
        ),
        UniqueConstraint(
            "id",
            "status",
            "request_type",
            "subject_type",
            "subject_id",
            name="uq_approval_requests_id_status_subject",
        ),
        Index(
            "ix_approval_requests_task_status_expiry",
            "task_id",
            "status",
            "expires_at",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    task_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False
    )
    request_type: Mapped[str] = mapped_column(String(100), nullable=False)
    subject_type: Mapped[str | None] = mapped_column(String(100))
    subject_id: Mapped[UUID | None] = mapped_column(Uuid)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    options: Mapped[list[object]] = mapped_column(JSON, nullable=False)
    supporting_evidence_ids: Mapped[list[object]] = mapped_column(JSON, nullable=False)
    requesting_state: Mapped[TaskState] = mapped_column(
        _enum(TaskState, name="approval_request_task_state", length=32),
        nullable=False,
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[ApprovalStatus] = mapped_column(
        _enum(ApprovalStatus, name="approval_request_status"),
        nullable=False,
        default=ApprovalStatus.PENDING,
        server_default=ApprovalStatus.PENDING.value,
    )
    request_fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="0" * 64,
        server_default="0" * 64,
    )
    precondition_fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="0" * 64,
        server_default="0" * 64,
    )
    resume_state: Mapped[TaskState | None] = mapped_column(
        _enum(TaskState, name="approval_request_resume_state", length=32)
    )
    blocked_operation: Mapped[dict[str, object] | None] = mapped_column(JSON)
    retry_history: Mapped[list[object]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
        server_default="[]",
    )
    decision: Mapped[str | None] = mapped_column(Text)
    decision_id: Mapped[UUID | None] = mapped_column(Uuid)
    decision_fingerprint: Mapped[str | None] = mapped_column(String(64))
    decided_by: Mapped[str | None] = mapped_column(String(255))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RuleCandidate(RecordContext, Base):
    """Non-executable proposed review rule."""

    __tablename__ = "rule_candidates"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    task_id: Mapped[UUID | None] = mapped_column(Uuid, ForeignKey("tasks.id", ondelete="SET NULL"))
    proposed_rule: Mapped[str] = mapped_column(Text, nullable=False)
    cited_evidence_ids: Mapped[list[object]] = mapped_column(JSON, nullable=False)
    recurrence_assessment: Mapped[str] = mapped_column(Text, nullable=False)
    severity_assessment: Mapped[str] = mapped_column(String(100), nullable=False)
    false_positive_risks: Mapped[list[object]] = mapped_column(JSON, nullable=False)
    evaluation_result: Mapped[dict[str, object] | None] = mapped_column(JSON)
    status: Mapped[RuleCandidateStatus] = mapped_column(
        _enum(RuleCandidateStatus, name="rule_candidate_status"),
        nullable=False,
        default=RuleCandidateStatus.PROPOSED,
        server_default=RuleCandidateStatus.PROPOSED.value,
    )


class ReviewRule(RecordContext, Base):
    """Human-approved, immutable executable review rule version."""

    __tablename__ = "review_rules"
    __table_args__ = (
        CheckConstraint("version > 0", name="version_positive"),
        CheckConstraint(
            "predecessor_id IS NULL OR predecessor_id <> id", name="predecessor_not_self"
        ),
        CheckConstraint("approval_status = 'APPROVED'", name="approval_status_approved"),
        CheckConstraint(
            "approval_request_type = 'REVIEW_RULE'",
            name="approval_request_type_review_rule",
        ),
        CheckConstraint(
            "approval_subject_type = 'RULE_CANDIDATE'",
            name="approval_subject_type_rule_candidate",
        ),
        UniqueConstraint("lineage_key", "version", name="uq_review_rules_lineage_version"),
        UniqueConstraint("lineage_key", "id", name="uq_review_rules_lineage_id"),
        ForeignKeyConstraint(
            ["lineage_key", "predecessor_id"],
            ["review_rules.lineage_key", "review_rules.id"],
            ondelete="RESTRICT",
            use_alter=True,
        ),
        ForeignKeyConstraint(
            [
                "approval_request_id",
                "approval_status",
                "approval_request_type",
                "approval_subject_type",
                "candidate_id",
            ],
            [
                "approval_requests.id",
                "approval_requests.status",
                "approval_requests.request_type",
                "approval_requests.subject_type",
                "approval_requests.subject_id",
            ],
            ondelete="RESTRICT",
            use_alter=True,
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    lineage_key: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    predecessor_id: Mapped[UUID | None] = mapped_column(Uuid)
    candidate_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("rule_candidates.id", ondelete="RESTRICT"), nullable=False
    )
    approval_request_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    approval_status: Mapped[ApprovalStatus] = mapped_column(
        _enum(ApprovalStatus, name="review_rule_approval_status"),
        nullable=False,
        default=ApprovalStatus.APPROVED,
        server_default=ApprovalStatus.APPROVED.value,
    )
    approval_request_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="REVIEW_RULE",
        server_default="REVIEW_RULE",
    )
    approval_subject_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="RULE_CANDIDATE",
        server_default="RULE_CANDIDATE",
    )
    scope: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    matcher: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    permitted_action: Mapped[str] = mapped_column(String(255), nullable=False)
    risk_class: Mapped[str] = mapped_column(String(100), nullable=False)
    evidence_requirements: Mapped[list[object]] = mapped_column(JSON, nullable=False)
    provenance: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    approved_by: Mapped[str] = mapped_column(String(255), nullable=False)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class PromptTemplateVersion(RecordContext, Base):
    """Immutable structured prompt template version."""

    __tablename__ = "prompt_template_versions"
    __table_args__ = (
        CheckConstraint("version > 0", name="version_positive"),
        CheckConstraint(
            "predecessor_id IS NULL OR predecessor_id <> id", name="predecessor_not_self"
        ),
        CheckConstraint(
            "promoted = false OR "
            "(evaluation_threshold_passed = true AND regression_reviewed = true "
            "AND approved_by IS NOT NULL AND approved_at IS NOT NULL)",
            name="promotion_requirements",
        ),
        UniqueConstraint(
            "lineage_key",
            "version",
            name="uq_prompt_template_versions_lineage_version",
        ),
        UniqueConstraint(
            "lineage_key",
            "id",
            name="uq_prompt_template_versions_lineage_id",
        ),
        UniqueConstraint(
            "id",
            "promoted",
            name="uq_prompt_template_versions_id_promoted",
        ),
        ForeignKeyConstraint(
            ["lineage_key", "predecessor_id"],
            ["prompt_template_versions.lineage_key", "prompt_template_versions.id"],
            ondelete="RESTRICT",
            use_alter=True,
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    lineage_key: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    predecessor_id: Mapped[UUID | None] = mapped_column(Uuid)
    structured_template: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    evaluation_evidence_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("evidence_records.id", ondelete="RESTRICT")
    )
    evaluation_score: Mapped[float | None] = mapped_column(Float)
    evaluation_threshold_passed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    regression_reviewed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    promoted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    approved_by: Mapped[str | None] = mapped_column(String(255))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PolicyVersion(RecordContext, Base):
    """Immutable executable set of approved rules, thresholds, and prompts."""

    __tablename__ = "policy_versions"
    __table_args__ = (
        CheckConstraint("version > 0", name="version_positive"),
        CheckConstraint(
            "predecessor_id IS NULL OR predecessor_id <> id", name="predecessor_not_self"
        ),
        UniqueConstraint("lineage_key", "version", name="uq_policy_versions_lineage_version"),
        UniqueConstraint("lineage_key", "id", name="uq_policy_versions_lineage_id"),
        ForeignKeyConstraint(
            ["lineage_key", "predecessor_id"],
            ["policy_versions.lineage_key", "policy_versions.id"],
            name="fk_policy_versions_lineage_predecessor_policy_versions",
            ondelete="RESTRICT",
            use_alter=True,
        ),
        ForeignKeyConstraint(
            ["lineage_key", "rollback_policy_version_id"],
            ["policy_versions.lineage_key", "policy_versions.id"],
            name="fk_policy_versions_lineage_rollback_policy_versions",
            ondelete="RESTRICT",
            use_alter=True,
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    lineage_key: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    predecessor_id: Mapped[UUID | None] = mapped_column(Uuid)
    workflow_thresholds: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    approved_by: Mapped[str] = mapped_column(String(255), nullable=False)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    rollback_policy_version_id: Mapped[UUID | None] = mapped_column(Uuid)


class PolicyVersionReviewRule(RecordContext, Base):
    """Ordered membership of approved rules in an immutable policy version."""

    __tablename__ = "policy_version_review_rules"
    __table_args__ = (
        CheckConstraint("position > 0", name="position_positive"),
        UniqueConstraint("policy_version_id", "position", name="uq_policy_rules_position"),
        UniqueConstraint("policy_version_id", "review_rule_id", name="uq_policy_rules_membership"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    policy_version_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("policy_versions.id", ondelete="CASCADE"), nullable=False
    )
    review_rule_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("review_rules.id", ondelete="RESTRICT"), nullable=False
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False)


class PolicyVersionPromptTemplate(RecordContext, Base):
    """Ordered promoted prompt membership in an immutable policy version."""

    __tablename__ = "policy_version_prompt_templates"
    __table_args__ = (
        CheckConstraint("position > 0", name="position_positive"),
        CheckConstraint("prompt_promoted = true", name="prompt_promoted"),
        UniqueConstraint("policy_version_id", "position", name="uq_policy_prompts_position"),
        UniqueConstraint(
            "policy_version_id",
            "prompt_template_version_id",
            name="uq_policy_prompts_membership",
        ),
        ForeignKeyConstraint(
            ["prompt_template_version_id", "prompt_promoted"],
            ["prompt_template_versions.id", "prompt_template_versions.promoted"],
            ondelete="RESTRICT",
            use_alter=True,
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    policy_version_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("policy_versions.id", ondelete="CASCADE"), nullable=False
    )
    prompt_template_version_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    prompt_promoted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False)


class BackgroundJob(RecordContext, Base):
    """Durable unit of resumable control-plane work."""

    __tablename__ = "background_jobs"
    __table_args__ = (
        CheckConstraint("attempt_count >= 0", name="attempt_count_non_negative"),
        CheckConstraint(
            "max_attempts BETWEEN 1 AND 100",
            name="max_attempts_bounded",
        ),
        CheckConstraint(
            "attempt_count <= max_attempts",
            name="attempt_count_within_budget",
        ),
        CheckConstraint(
            "retry_base_seconds > 0",
            name="retry_base_seconds_positive",
        ),
        CheckConstraint(
            "retry_max_seconds >= retry_base_seconds",
            name="retry_max_seconds_not_below_base",
        ),
        CheckConstraint(
            "checkpoint_version >= 0",
            name="checkpoint_version_non_negative",
        ),
        CheckConstraint(
            "(current_lease_id IS NULL "
            "AND current_fencing_token IS NULL "
            "AND lease_owner IS NULL "
            "AND lease_expires_at IS NULL) "
            "OR (current_lease_id IS NOT NULL "
            "AND current_fencing_token IS NOT NULL "
            "AND lease_owner IS NOT NULL "
            "AND lease_expires_at IS NOT NULL)",
            name="current_lease_projection_shape",
        ),
        Index(
            "ix_background_jobs_schedule",
            "status",
            "available_at",
            "created_at",
        ),
        UniqueConstraint("idempotency_key", name="uq_background_jobs_idempotency_key"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    task_id: Mapped[UUID | None] = mapped_column(
        Uuid,
        ForeignKey("tasks.id", ondelete="CASCADE"),
    )
    job_type: Mapped[str] = mapped_column(String(100), nullable=False)
    input_payload: Mapped[dict[str, object]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
        server_default="{}",
    )
    input_fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="0" * 64,
        server_default="0" * 64,
    )
    status: Mapped[BackgroundJobStatus] = mapped_column(
        _enum(BackgroundJobStatus, name="background_job_status"),
        nullable=False,
        default=BackgroundJobStatus.QUEUED,
        server_default=BackgroundJobStatus.QUEUED.value,
    )
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    attempt_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    max_attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, default=5, server_default="5"
    )
    retry_base_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    retry_max_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=300, server_default="300"
    )
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        server_default=func.now(),
    )
    checkpoint: Mapped[dict[str, object] | None] = mapped_column(JSON)
    checkpoint_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    current_lease_id: Mapped[UUID | None] = mapped_column(Uuid)
    current_fencing_token: Mapped[int | None] = mapped_column(BigInteger)
    lease_owner: Mapped[str | None] = mapped_column(String(255))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_fencing_token: Mapped[int | None] = mapped_column(BigInteger)
    last_error_code: Mapped[str | None] = mapped_column(String(100))
    cancellation_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class BackgroundJobLease(RecordContext, Base):
    """Time-bounded job ownership with an immutable fencing token."""

    __tablename__ = "background_job_leases"
    __table_args__ = (
        CheckConstraint("attempt > 0", name="attempt_positive"),
        CheckConstraint("fencing_token > 0", name="fencing_token_positive"),
        CheckConstraint(
            "checkpoint_version >= 0",
            name="checkpoint_version_non_negative",
        ),
        CheckConstraint(
            "expires_at > heartbeat_at",
            name="expires_after_heartbeat",
        ),
        CheckConstraint(
            "(released_at IS NULL AND release_reason IS NULL) "
            "OR (released_at IS NOT NULL AND release_reason IN "
            "('SUPERSEDED', 'EXPIRED', 'RETRY', 'SUCCEEDED', 'FAILED', "
            "'CANCELLED'))",
            name="release_shape",
        ),
        Index(
            "ix_background_job_leases_expiry",
            "job_id",
            "expires_at",
        ),
        UniqueConstraint("job_id", "attempt", name="uq_background_job_leases_job_attempt"),
        UniqueConstraint(
            "job_id",
            "id",
            "fencing_token",
            name="uq_background_job_leases_job_id_token",
        ),
        UniqueConstraint("fencing_token", name="uq_background_job_leases_fencing_token"),
        UniqueConstraint(
            "idempotency_key",
            name="uq_background_job_leases_idempotency_key",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    job_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("background_jobs.id", ondelete="RESTRICT"), nullable=False
    )
    lease_owner: Mapped[str] = mapped_column(String(255), nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    fencing_token: Mapped[int] = mapped_column(BigInteger, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    lease_protocol_version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default="1",
    )
    claim_fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="0" * 64,
        server_default="0" * 64,
    )
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    checkpoint: Mapped[dict[str, object] | None] = mapped_column(JSON)
    checkpoint_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    release_reason: Mapped[str | None] = mapped_column(String(32))
    retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_code: Mapped[str | None] = mapped_column(String(100))
    cancellation_acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class BackgroundJobCheckpoint(RecordContext, Base):
    """Append-only durable progress accepted from one current lease."""

    __tablename__ = "background_job_checkpoints"
    __table_args__ = (
        CheckConstraint("sequence > 0", name="sequence_positive"),
        CheckConstraint("fencing_token > 0", name="fencing_token_positive"),
        CheckConstraint(
            "length(payload_fingerprint) = 64",
            name="payload_fingerprint_length",
        ),
        CheckConstraint(
            _hex_only_sql("payload_fingerprint"),
            name="payload_fingerprint_hex",
        ),
        UniqueConstraint(
            "job_id",
            "sequence",
            name="uq_background_job_checkpoints_job_sequence",
        ),
        UniqueConstraint(
            "idempotency_key",
            name="uq_background_job_checkpoints_idempotency_key",
        ),
        ForeignKeyConstraint(
            ["job_id", "lease_id", "fencing_token"],
            [
                "background_job_leases.job_id",
                "background_job_leases.id",
                "background_job_leases.fencing_token",
            ],
            name="fk_background_job_checkpoints_lease",
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    job_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("background_jobs.id", ondelete="RESTRICT"),
        nullable=False,
    )
    lease_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    fencing_token: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    payload_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class BackgroundJobEffect(RecordContext, Base):
    """Durable idempotent external-effect intent and reconciled outcome."""

    __tablename__ = "background_job_effects"
    __table_args__ = (
        CheckConstraint(
            "length(request_fingerprint) = 64",
            name="request_fingerprint_length",
        ),
        CheckConstraint(
            _hex_only_sql("request_fingerprint"),
            name="request_fingerprint_hex",
        ),
        CheckConstraint(
            "(status = 'PENDING' AND completed_at IS NULL "
            "AND completion_lease_id IS NULL "
            "AND completion_fencing_token IS NULL) "
            "OR (status IN ('SUCCEEDED', 'FAILED') "
            "AND completed_at IS NOT NULL "
            "AND completion_lease_id IS NOT NULL "
            "AND completion_fencing_token IS NOT NULL)",
            name="completion_shape",
        ),
        Index(
            "ix_background_job_effects_reconciliation",
            "job_id",
            "status",
            "started_at",
        ),
        UniqueConstraint(
            "idempotency_key",
            name="uq_background_job_effects_idempotency_key",
        ),
        UniqueConstraint(
            "job_id",
            "effect_type",
            "idempotency_key",
            name="uq_background_job_effects_job_effect_key",
        ),
        ForeignKeyConstraint(
            ["job_id", "started_lease_id", "started_fencing_token"],
            [
                "background_job_leases.job_id",
                "background_job_leases.id",
                "background_job_leases.fencing_token",
            ],
            name="fk_background_job_effects_started_lease",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["job_id", "completion_lease_id", "completion_fencing_token"],
            [
                "background_job_leases.job_id",
                "background_job_leases.id",
                "background_job_leases.fencing_token",
            ],
            name="fk_background_job_effects_completion_lease",
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    job_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("background_jobs.id", ondelete="RESTRICT"),
        nullable=False,
    )
    effect_type: Mapped[str] = mapped_column(String(100), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    request_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    request_payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    status: Mapped[BackgroundJobEffectStatus] = mapped_column(
        _enum(BackgroundJobEffectStatus, name="background_job_effect_status"),
        nullable=False,
        default=BackgroundJobEffectStatus.PENDING,
        server_default=BackgroundJobEffectStatus.PENDING.value,
    )
    started_lease_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    started_fencing_token: Mapped[int] = mapped_column(BigInteger, nullable=False)
    completion_lease_id: Mapped[UUID | None] = mapped_column(Uuid)
    completion_fencing_token: Mapped[int | None] = mapped_column(BigInteger)
    result_payload: Mapped[dict[str, object] | None] = mapped_column(JSON)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class BackgroundJobFencingCounter(Base):
    """Singleton allocator that prevents fencing-token reuse across jobs."""

    __tablename__ = "background_job_fencing_counter"
    __table_args__ = (
        CheckConstraint("id = 1", name="singleton"),
        CheckConstraint("next_token > 0", name="next_token_positive"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    next_token: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=1,
        server_default="1",
    )


class BackgroundJobTaskTransition(RecordContext, Base):
    """Lease provenance for a task transition initiated by a background job."""

    __tablename__ = "background_job_task_transitions"
    __table_args__ = (
        CheckConstraint("fencing_token > 0", name="fencing_token_positive"),
        UniqueConstraint(
            "task_event_id",
            name="uq_background_job_task_transitions_task_event",
        ),
        ForeignKeyConstraint(
            ["job_id", "lease_id", "fencing_token"],
            [
                "background_job_leases.job_id",
                "background_job_leases.id",
                "background_job_leases.fencing_token",
            ],
            name="fk_background_job_task_transitions_lease",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["task_id", "task_event_id"],
            ["task_events.task_id", "task_events.id"],
            name="fk_background_job_task_transitions_task_event",
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    job_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("background_jobs.id", ondelete="RESTRICT"),
        nullable=False,
    )
    lease_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    fencing_token: Mapped[int] = mapped_column(BigInteger, nullable=False)
    task_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    task_event_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class BackgroundJobToolGrant(RecordContext, Base):
    """Lease-bound Hermes capability that cancellation can durably revoke."""

    __tablename__ = "background_job_tool_grants"
    __table_args__ = (
        CheckConstraint("fencing_token > 0", name="fencing_token_positive"),
        CheckConstraint(
            "(revoked_at IS NULL AND revoke_reason IS NULL) "
            "OR (revoked_at IS NOT NULL AND revoke_reason IS NOT NULL)",
            name="revocation_shape",
        ),
        UniqueConstraint(
            "job_id",
            "grant_key",
            name="uq_background_job_tool_grants_job_key",
        ),
        ForeignKeyConstraint(
            ["job_id", "lease_id", "fencing_token"],
            [
                "background_job_leases.job_id",
                "background_job_leases.id",
                "background_job_leases.fencing_token",
            ],
            name="fk_background_job_tool_grants_lease",
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    job_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("background_jobs.id", ondelete="RESTRICT"),
        nullable=False,
    )
    lease_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    fencing_token: Mapped[int] = mapped_column(BigInteger, nullable=False)
    grant_key: Mapped[str] = mapped_column(String(255), nullable=False)
    capability_scope: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoke_reason: Mapped[str | None] = mapped_column(String(100))


class OwnedHostProcess(RecordContext, Base):
    """Exact host process-group identity created for one fenced job lease."""

    __tablename__ = "owned_host_processes"
    __table_args__ = (
        CheckConstraint("pid > 1", name="pid_safe"),
        CheckConstraint("process_group_id > 1", name="process_group_id_safe"),
        CheckConstraint("fencing_token > 0", name="fencing_token_positive"),
        CheckConstraint(
            "(status = 'RUNNING' "
            "AND termination_requested_at IS NULL "
            "AND terminated_at IS NULL) "
            "OR (status = 'TERMINATION_REQUESTED' "
            "AND termination_requested_at IS NOT NULL "
            "AND terminated_at IS NULL) "
            "OR (status IN ('TERMINATED', 'GONE') "
            "AND termination_requested_at IS NOT NULL "
            "AND terminated_at IS NOT NULL)",
            name="status_shape",
        ),
        UniqueConstraint(
            "host_id",
            "pid",
            "birth_token",
            name="uq_owned_host_processes_identity",
        ),
        UniqueConstraint(
            "ownership_nonce",
            name="uq_owned_host_processes_ownership_nonce",
        ),
        ForeignKeyConstraint(
            ["job_id", "lease_id", "fencing_token"],
            [
                "background_job_leases.job_id",
                "background_job_leases.id",
                "background_job_leases.fencing_token",
            ],
            name="fk_owned_host_processes_lease",
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    job_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("background_jobs.id", ondelete="RESTRICT"),
        nullable=False,
    )
    lease_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    fencing_token: Mapped[int] = mapped_column(BigInteger, nullable=False)
    host_id: Mapped[str] = mapped_column(String(255), nullable=False)
    pid: Mapped[int] = mapped_column(Integer, nullable=False)
    process_group_id: Mapped[int] = mapped_column(Integer, nullable=False)
    birth_token: Mapped[str] = mapped_column(String(255), nullable=False)
    ownership_nonce: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    status: Mapped[OwnedHostProcessStatus] = mapped_column(
        _enum(OwnedHostProcessStatus, name="owned_host_process_status"),
        nullable=False,
        default=OwnedHostProcessStatus.RUNNING,
        server_default=OwnedHostProcessStatus.RUNNING.value,
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    termination_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    terminated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    partial_evidence_id: Mapped[UUID | None] = mapped_column(
        Uuid,
        ForeignKey("evidence_records.id", ondelete="RESTRICT"),
    )
    cleanup_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class BackgroundJobIgnoredResult(RecordContext, Base):
    """Evidence-only result rejected by a cancellation or newer lease fence."""

    __tablename__ = "background_job_ignored_results"
    __table_args__ = (
        CheckConstraint("fencing_token > 0", name="fencing_token_positive"),
        CheckConstraint(
            "reason_code IN ('CANCELLED', 'FENCED')",
            name="reason_code",
        ),
        CheckConstraint(
            "length(result_fingerprint) = 64",
            name="result_fingerprint_length",
        ),
        CheckConstraint(
            _hex_only_sql("result_fingerprint"),
            name="result_fingerprint_hex",
        ),
        UniqueConstraint(
            "idempotency_key",
            name="uq_background_job_ignored_results_idempotency_key",
        ),
        UniqueConstraint(
            "evidence_id",
            name="uq_background_job_ignored_results_evidence",
        ),
        ForeignKeyConstraint(
            ["job_id", "lease_id", "fencing_token"],
            [
                "background_job_leases.job_id",
                "background_job_leases.id",
                "background_job_leases.fencing_token",
            ],
            name="fk_background_job_ignored_results_lease",
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    job_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("background_jobs.id", ondelete="RESTRICT"),
        nullable=False,
    )
    lease_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    fencing_token: Mapped[int] = mapped_column(BigInteger, nullable=False)
    effect_id: Mapped[UUID | None] = mapped_column(
        Uuid,
        ForeignKey("background_job_effects.id", ondelete="RESTRICT"),
    )
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    result_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("evidence_records.id", ondelete="RESTRICT"),
        nullable=False,
    )
    reason_code: Mapped[str] = mapped_column(String(32), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class DependencyOutageAttempt(RecordContext, Base):
    """One retryable dependency failure and its optional escalation resolution."""

    __tablename__ = "dependency_outage_attempts"
    __table_args__ = (
        CheckConstraint("attempt > 0", name="attempt_positive"),
        CheckConstraint("fencing_token > 0", name="fencing_token_positive"),
        CheckConstraint(
            "service IN ('HOST', 'HERMES', 'GITHUB')",
            name="service",
        ),
        CheckConstraint(
            "(exhausted = false AND approval_request_id IS NULL) OR exhausted = true",
            name="approval_only_when_exhausted",
        ),
        CheckConstraint(
            "(resolved_at IS NULL AND decision_id IS NULL "
            "AND resumed_job_id IS NULL) "
            "OR (resolved_at IS NOT NULL AND decision_id IS NOT NULL)",
            name="resolution_shape",
        ),
        UniqueConstraint(
            "job_id",
            "attempt",
            name="uq_dependency_outage_attempts_job_attempt",
        ),
        UniqueConstraint(
            "approval_request_id",
            name="uq_dependency_outage_attempts_approval_request",
        ),
        ForeignKeyConstraint(
            ["job_id", "lease_id", "fencing_token"],
            [
                "background_job_leases.job_id",
                "background_job_leases.id",
                "background_job_leases.fencing_token",
            ],
            name="fk_dependency_outage_attempts_lease",
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    job_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("background_jobs.id", ondelete="RESTRICT"),
        nullable=False,
    )
    lease_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    fencing_token: Mapped[int] = mapped_column(BigInteger, nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    service: Mapped[DependencyService] = mapped_column(
        _enum(DependencyService, name="dependency_service"),
        nullable=False,
    )
    error_code: Mapped[str] = mapped_column(String(100), nullable=False)
    checkpoint_evidence_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("evidence_records.id", ondelete="RESTRICT"),
        nullable=False,
    )
    exhausted: Mapped[bool] = mapped_column(Boolean, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    approval_request_id: Mapped[UUID | None] = mapped_column(
        Uuid,
        ForeignKey("approval_requests.id", ondelete="RESTRICT"),
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_id: Mapped[UUID | None] = mapped_column(Uuid)
    resumed_job_id: Mapped[UUID | None] = mapped_column(
        Uuid,
        ForeignKey("background_jobs.id", ondelete="RESTRICT"),
    )


class TaskCancellation(RecordContext, Base):
    """Idempotent terminal work fence and cleanup completion projection."""

    __tablename__ = "task_cancellations"
    __table_args__ = (
        CheckConstraint(
            "length(request_fingerprint) = 64",
            name="request_fingerprint_length",
        ),
        CheckConstraint(
            _hex_only_sql("request_fingerprint"),
            name="request_fingerprint_hex",
        ),
        UniqueConstraint("task_id", name="uq_task_cancellations_task"),
        UniqueConstraint(
            "transition_event_id",
            name="uq_task_cancellations_transition_event",
        ),
        ForeignKeyConstraint(
            ["task_id", "transition_event_id"],
            ["task_events.task_id", "task_events.id"],
            name="fk_task_cancellations_transition_event",
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    task_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("tasks.id", ondelete="RESTRICT"),
        nullable=False,
    )
    request_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(100), nullable=False)
    partial_evidence_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("evidence_records.id", ondelete="RESTRICT"),
        nullable=False,
    )
    transition_event_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    cleanup_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ReconciliationTarget(RecordContext, Base):
    """Durable expected state for one startup-only external observation."""

    __tablename__ = "reconciliation_targets"
    __table_args__ = (
        CheckConstraint(
            "length(expected_fingerprint) = 64",
            name="expected_fingerprint_length",
        ),
        CheckConstraint(
            _hex_only_sql("expected_fingerprint"),
            name="expected_fingerprint_hex",
        ),
        CheckConstraint(
            "reconciliation_version >= 0",
            name="reconciliation_version_non_negative",
        ),
        UniqueConstraint(
            "kind",
            "target_key",
            name="uq_reconciliation_targets_kind_key",
        ),
        Index(
            "ix_reconciliation_targets_startup",
            "status",
            "kind",
            "updated_at",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    task_id: Mapped[UUID | None] = mapped_column(
        Uuid,
        ForeignKey("tasks.id", ondelete="RESTRICT"),
    )
    job_id: Mapped[UUID | None] = mapped_column(
        Uuid,
        ForeignKey("background_jobs.id", ondelete="RESTRICT"),
    )
    kind: Mapped[ReconciliationTargetKind] = mapped_column(
        _enum(ReconciliationTargetKind, name="reconciliation_target_kind"),
        nullable=False,
    )
    target_key: Mapped[str] = mapped_column(String(255), nullable=False)
    expected_payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    expected_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_payload: Mapped[dict[str, object] | None] = mapped_column(JSON)
    status: Mapped[ReconciliationStatus] = mapped_column(
        _enum(ReconciliationStatus, name="reconciliation_status"),
        nullable=False,
        default=ReconciliationStatus.PENDING,
        server_default=ReconciliationStatus.PENDING.value,
    )
    reconciliation_version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    last_reconciled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(100))


class HermesRun(RecordContext, Base):
    """One exact Hermes attempt bound to a durable job lease fence."""

    __tablename__ = "hermes_runs"
    __table_args__ = (
        CheckConstraint("attempt > 0", name="attempt_positive"),
        CheckConstraint("fencing_token > 0", name="fencing_token_positive"),
        CheckConstraint("last_event_sequence >= 0", name="event_sequence_non_negative"),
        CheckConstraint("length(prompt_fingerprint) = 64", name="prompt_fingerprint_length"),
        UniqueConstraint("job_id", "attempt", name="uq_hermes_runs_job_attempt"),
        UniqueConstraint("external_run_id", name="uq_hermes_runs_external_run"),
        ForeignKeyConstraint(
            ["job_id", "lease_id", "fencing_token"],
            [
                "background_job_leases.job_id",
                "background_job_leases.id",
                "background_job_leases.fencing_token",
            ],
            name="fk_hermes_runs_lease",
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    task_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("tasks.id", ondelete="RESTRICT"), nullable=False
    )
    job_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("background_jobs.id", ondelete="RESTRICT"), nullable=False
    )
    lease_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    fencing_token: Mapped[int] = mapped_column(BigInteger, nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    external_run_id: Mapped[str | None] = mapped_column(String(255))
    prompt_template_version_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("prompt_template_versions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    policy_version_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("policy_versions.id", ondelete="RESTRICT"), nullable=False
    )
    evaluation_label: Mapped[str | None] = mapped_column(String(255))
    prompt_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[HermesRunStatus] = mapped_column(
        _enum(HermesRunStatus, name="hermes_run_status"),
        nullable=False,
        default=HermesRunStatus.STARTING,
        server_default=HermesRunStatus.STARTING.value,
    )
    last_event_sequence: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancellation_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_code: Mapped[str | None] = mapped_column(String(100))


class HermesRunEvent(RecordContext, Base):
    """Immutable provider delivery and its fenced normalization result."""

    __tablename__ = "hermes_run_events"
    __table_args__ = (
        CheckConstraint("provider_sequence > 0", name="provider_sequence_positive"),
        CheckConstraint("length(payload_fingerprint) = 64", name="payload_fingerprint_length"),
        CheckConstraint(
            "(accepted = true AND ignored_reason IS NULL AND task_event_id IS NOT NULL) "
            "OR (accepted = false AND ignored_reason IS NOT NULL AND task_event_id IS NULL)",
            name="acceptance_shape",
        ),
        UniqueConstraint("run_id", "provider_event_id", name="uq_hermes_run_events_delivery"),
        UniqueConstraint("run_id", "provider_sequence", name="uq_hermes_run_events_sequence"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    run_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("hermes_runs.id", ondelete="RESTRICT"), nullable=False
    )
    provider_event_id: Mapped[str] = mapped_column(String(255), nullable=False)
    provider_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    payload_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_evidence_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("evidence_records.id", ondelete="RESTRICT"), nullable=False
    )
    accepted: Mapped[bool] = mapped_column(Boolean, nullable=False)
    ignored_reason: Mapped[str | None] = mapped_column(String(100))
    task_event_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("task_events.id", ondelete="RESTRICT")
    )
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class HermesToolProposal(RecordContext, Base):
    """Immutable Hermes tool proposal bound to one exact run lease."""

    __tablename__ = "hermes_tool_proposals"
    __table_args__ = (
        CheckConstraint("fencing_token > 0", name="fencing_token_positive"),
        CheckConstraint("length(arguments_fingerprint) = 64", name="arguments_fingerprint_length"),
        UniqueConstraint(
            "run_id",
            "external_proposal_id",
            name="uq_hermes_tool_proposals_run_external",
        ),
        ForeignKeyConstraint(
            ["job_id", "lease_id", "fencing_token"],
            [
                "background_job_leases.job_id",
                "background_job_leases.id",
                "background_job_leases.fencing_token",
            ],
            name="fk_hermes_tool_proposals_lease",
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    run_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("hermes_runs.id", ondelete="RESTRICT"), nullable=False
    )
    task_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("tasks.id", ondelete="RESTRICT"), nullable=False
    )
    job_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("background_jobs.id", ondelete="RESTRICT"), nullable=False
    )
    lease_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    fencing_token: Mapped[int] = mapped_column(BigInteger, nullable=False)
    external_proposal_id: Mapped[str] = mapped_column(String(255), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    arguments_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    proposal_evidence_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("evidence_records.id", ondelete="RESTRICT"), nullable=False
    )
    proposed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class HermesToolDecision(RecordContext, Base):
    """Immutable control-plane authorization for one Hermes proposal."""

    __tablename__ = "hermes_tool_decisions"
    __table_args__ = (UniqueConstraint("proposal_id", name="uq_hermes_tool_decisions_proposal"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    proposal_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("hermes_tool_proposals.id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[HermesToolDecisionStatus] = mapped_column(
        _enum(HermesToolDecisionStatus, name="hermes_tool_decision_status"),
        nullable=False,
    )
    reason_code: Mapped[str] = mapped_column(String(100), nullable=False)
    tool_grant_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("background_job_tool_grants.id", ondelete="RESTRICT"), nullable=False
    )
    brief_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("briefs.id", ondelete="RESTRICT")
    )
    repository_configuration_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("repository_configurations.id", ondelete="RESTRICT")
    )
    policy_version_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("policy_versions.id", ondelete="RESTRICT"), nullable=False
    )
    decision_evidence_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("evidence_records.id", ondelete="RESTRICT"), nullable=False
    )
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class HermesToolResult(RecordContext, Base):
    """Append-only host outcome returned for an authorized Hermes proposal."""

    __tablename__ = "hermes_tool_results"
    __table_args__ = (
        CheckConstraint("attempt > 0", name="attempt_positive"),
        UniqueConstraint(
            "proposal_id",
            "attempt",
            name="uq_hermes_tool_results_proposal_attempt",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    proposal_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("hermes_tool_proposals.id", ondelete="RESTRICT"), nullable=False
    )
    attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[HermesToolResultStatus] = mapped_column(
        _enum(HermesToolResultStatus, name="hermes_tool_result_status"),
        nullable=False,
    )
    code: Mapped[str] = mapped_column(String(100), nullable=False)
    repository_revision: Mapped[str | None] = mapped_column(String(64))
    result_evidence_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("evidence_records.id", ondelete="RESTRICT"), nullable=False
    )
    diff_evidence_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("evidence_records.id", ondelete="RESTRICT")
    )
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class WebhookDelivery(RecordContext, Base):
    """Verified external delivery and its correlation/processing result."""

    __tablename__ = "webhook_deliveries"
    __table_args__ = (
        UniqueConstraint(
            "provider",
            "provider_delivery_id",
            name="uq_webhook_deliveries_provider_delivery",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    provider_delivery_id: Mapped[str] = mapped_column(String(255), nullable=False)
    installation_id: Mapped[str] = mapped_column(String(255), nullable=False)
    repository_id: Mapped[str] = mapped_column(String(255), nullable=False)
    pull_request_number: Mapped[int | None] = mapped_column(Integer)
    head_sha: Mapped[str | None] = mapped_column(String(64))
    signature_verified: Mapped[bool] = mapped_column(Boolean, nullable=False)
    payload_evidence_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("evidence_records.id", ondelete="RESTRICT")
    )
    processing_result: Mapped[dict[str, object] | None] = mapped_column(JSON)
    quarantine_reason: Mapped[str | None] = mapped_column(Text)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
