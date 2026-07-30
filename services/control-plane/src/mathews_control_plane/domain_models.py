"""Typed persistence models for the Mathews control-plane domain."""

from datetime import datetime
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
    root_correlation_id: Mapped[UUID] = mapped_column(Uuid, nullable=False, default=uuid4)


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
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    task_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False
    )
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class EvidenceRecord(RecordContext, Base):
    """Immutable reference to canonical redacted evidence."""

    __tablename__ = "evidence_records"
    __table_args__ = (
        CheckConstraint(
            "correction_of_id IS NULL OR correction_of_id <> id", name="correction_not_self"
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    task_id: Mapped[UUID | None] = mapped_column(Uuid, ForeignKey("tasks.id", ondelete="CASCADE"))
    validation_run_id: Mapped[UUID | None] = mapped_column(
        Uuid,
        ForeignKey("validation_runs.id", ondelete="SET NULL", use_alter=True),
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
        UniqueConstraint("id", "status", name="uq_approval_requests_id_status"),
        UniqueConstraint(
            "id",
            "status",
            "request_type",
            "subject_type",
            "subject_id",
            name="uq_approval_requests_id_status_subject",
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
    decision: Mapped[str | None] = mapped_column(Text)
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
        UniqueConstraint("idempotency_key", name="uq_background_jobs_idempotency_key"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    task_id: Mapped[UUID | None] = mapped_column(Uuid, ForeignKey("tasks.id", ondelete="CASCADE"))
    job_type: Mapped[str] = mapped_column(String(100), nullable=False)
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
    checkpoint: Mapped[dict[str, object] | None] = mapped_column(JSON)
    cancellation_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class BackgroundJobLease(RecordContext, Base):
    """Time-bounded job ownership with an immutable fencing token."""

    __tablename__ = "background_job_leases"
    __table_args__ = (
        CheckConstraint("attempt > 0", name="attempt_positive"),
        CheckConstraint("fencing_token > 0", name="fencing_token_positive"),
        UniqueConstraint("job_id", "attempt", name="uq_background_job_leases_job_attempt"),
        UniqueConstraint("fencing_token", name="uq_background_job_leases_fencing_token"),
        UniqueConstraint(
            "idempotency_key",
            name="uq_background_job_leases_idempotency_key",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    job_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("background_jobs.id", ondelete="CASCADE"), nullable=False
    )
    lease_owner: Mapped[str] = mapped_column(String(255), nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    fencing_token: Mapped[int] = mapped_column(BigInteger, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    checkpoint: Mapped[dict[str, object] | None] = mapped_column(JSON)
    cancellation_acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


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
