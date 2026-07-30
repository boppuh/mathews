"""Define the durable control-plane domain schema.

Revision ID: 0003
Revises: 0002
Create Date: 2026-07-30
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_TASK_STATES = (
    "INTAKE",
    "BRIEFING",
    "BRIEF_PENDING_APPROVAL",
    "IMPLEMENTING",
    "VALIDATING",
    "REPAIRING",
    "PR_ACTIVE",
    "READY_FOR_HUMAN_MERGE",
    "HANDED_OFF",
    "ESCALATED",
    "FAILED",
    "CANCELLED",
)
_VALIDATION_OUTCOMES = (
    "PENDING",
    "PASSED",
    "FAILED",
    "BLOCKED",
    "ESCALATED",
    "CANCELLED",
)
_APPROVAL_STATUSES = (
    "PENDING",
    "APPROVED",
    "REJECTED",
    "EXPIRED",
    "CANCELLED",
)
_RULE_CANDIDATE_STATUSES = ("PROPOSED", "EVALUATED", "REJECTED", "APPROVED")
_BACKGROUND_JOB_STATUSES = ("QUEUED", "RUNNING", "SUCCEEDED", "FAILED", "CANCELLED")
_BRIEF_DECISION_DISPOSITIONS = (
    "AUTO_ACCEPTED_BY_POLICY",
    "HUMAN_APPROVAL_REQUIRED",
)
_LEGACY_BASE_REVISION = "0" * 40


def _context_columns() -> tuple[sa.Column[Any], ...]:
    return (
        sa.Column("owner_id", sa.String(length=255), nullable=False),
        sa.Column("actor_id", sa.String(length=255), nullable=False),
        sa.Column("root_correlation_id", sa.Uuid(), nullable=False),
        sa.Column("causation_id", sa.Uuid(), nullable=True),
        sa.Column("parent_correlation_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def _create_record_table(
    table_name: str,
    *columns: sa.Column[Any] | sa.Constraint,
) -> None:
    op.create_table(
        table_name,
        sa.Column("id", sa.Uuid(), nullable=False),
        *columns,
        *_context_columns(),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{table_name}")),
    )


def _enum_check(column_name: str, values: tuple[str, ...]) -> str:
    allowed_values = ", ".join(f"'{value}'" for value in values)
    return f"{column_name} IN ({allowed_values})"


_FOREIGN_KEYS: dict[
    str,
    tuple[
        tuple[
            str,
            str | tuple[str, ...],
            str,
            str | tuple[str, ...],
            str,
        ],
        ...,
    ],
] = {
    "tasks": (
        (
            "fk_tasks_id_briefs",
            ("id", "accepted_brief_id"),
            "briefs",
            ("task_id", "id"),
            "RESTRICT",
        ),
        (
            "fk_tasks_id_brief_approval_decisions",
            ("id", "brief_approval_decision_id"),
            "brief_approval_decisions",
            ("task_id", "id"),
            "RESTRICT",
        ),
        (
            "fk_tasks_repository_repository_configurations",
            ("repository", "repository_configuration_id"),
            "repository_configurations",
            ("repository_key", "id"),
            "RESTRICT",
        ),
        (
            "fk_tasks_id_validation_contracts",
            ("id", "validation_contract_id"),
            "validation_contracts",
            ("task_id", "id"),
            "RESTRICT",
        ),
        (
            "fk_tasks_brief_approval_decision_id_brief_approval_decisions",
            ("brief_approval_decision_id", "accepted_brief_id"),
            "brief_approval_decisions",
            ("id", "brief_id"),
            "RESTRICT",
        ),
    ),
    "briefs": (
        ("fk_briefs_task_id_tasks", "task_id", "tasks", "id", "CASCADE"),
        (
            "fk_briefs_task_id_briefs",
            ("task_id", "predecessor_id"),
            "briefs",
            ("task_id", "id"),
            "RESTRICT",
        ),
    ),
    "repository_configurations": (
        (
            "fk_repository_configurations_repository_key_repository_configurations",
            ("repository_key", "predecessor_id"),
            "repository_configurations",
            ("repository_key", "id"),
            "RESTRICT",
        ),
        (
            "fk_repository_configurations_preflight_evidence_id_evidence_records",
            "preflight_evidence_id",
            "evidence_records",
            "id",
            "RESTRICT",
        ),
    ),
    "task_events": (("fk_task_events_task_id_tasks", "task_id", "tasks", "id", "CASCADE"),),
    "evidence_records": (
        (
            "fk_evidence_records_task_id_tasks",
            "task_id",
            "tasks",
            "id",
            "CASCADE",
        ),
        (
            "fk_evidence_records_validation_run_id_validation_runs",
            "validation_run_id",
            "validation_runs",
            "id",
            "SET NULL",
        ),
        (
            "fk_evidence_records_correction_of_id_evidence_records",
            "correction_of_id",
            "evidence_records",
            "id",
            "RESTRICT",
        ),
    ),
    "validation_contracts": (
        (
            "fk_validation_contracts_task_id_tasks",
            "task_id",
            "tasks",
            "id",
            "CASCADE",
        ),
        (
            "fk_validation_contracts_task_id_validation_contracts",
            ("task_id", "predecessor_id"),
            "validation_contracts",
            ("task_id", "id"),
            "RESTRICT",
        ),
        (
            "fk_validation_contracts_task_id_briefs",
            ("task_id", "brief_id"),
            "briefs",
            ("task_id", "id"),
            "RESTRICT",
        ),
        (
            "fk_validation_contracts_repository_configuration_id_repository_configurations",
            "repository_configuration_id",
            "repository_configurations",
            "id",
            "RESTRICT",
        ),
    ),
    "validation_runs": (
        (
            "fk_validation_runs_task_id_tasks",
            "task_id",
            "tasks",
            "id",
            "CASCADE",
        ),
        (
            "fk_validation_runs_task_id_validation_contracts",
            ("task_id", "validation_contract_id"),
            "validation_contracts",
            ("task_id", "id"),
            "RESTRICT",
        ),
        (
            "fk_validation_runs_validation_contract_id_validation_contracts",
            ("validation_contract_id", "repository_configuration_id"),
            "validation_contracts",
            ("id", "repository_configuration_id"),
            "RESTRICT",
        ),
        (
            "fk_validation_runs_log_evidence_id_evidence_records",
            "log_evidence_id",
            "evidence_records",
            "id",
            "RESTRICT",
        ),
    ),
    "brief_approval_decisions": (
        (
            "fk_brief_approval_decisions_task_id_tasks",
            "task_id",
            "tasks",
            "id",
            "CASCADE",
        ),
        (
            "fk_brief_approval_decisions_task_id_briefs",
            ("task_id", "brief_id"),
            "briefs",
            ("task_id", "id"),
            "RESTRICT",
        ),
        (
            "fk_brief_approval_decisions_policy_version_id_policy_versions",
            "policy_version_id",
            "policy_versions",
            "id",
            "RESTRICT",
        ),
    ),
    "approval_requests": (
        (
            "fk_approval_requests_task_id_tasks",
            "task_id",
            "tasks",
            "id",
            "CASCADE",
        ),
    ),
    "rule_candidates": (
        (
            "fk_rule_candidates_task_id_tasks",
            "task_id",
            "tasks",
            "id",
            "SET NULL",
        ),
    ),
    "review_rules": (
        (
            "fk_review_rules_lineage_key_review_rules",
            ("lineage_key", "predecessor_id"),
            "review_rules",
            ("lineage_key", "id"),
            "RESTRICT",
        ),
        (
            "fk_review_rules_candidate_id_rule_candidates",
            "candidate_id",
            "rule_candidates",
            "id",
            "RESTRICT",
        ),
        (
            "fk_review_rules_approval_request_id_approval_requests",
            (
                "approval_request_id",
                "approval_status",
                "approval_request_type",
                "approval_subject_type",
                "candidate_id",
            ),
            "approval_requests",
            (
                "id",
                "status",
                "request_type",
                "subject_type",
                "subject_id",
            ),
            "RESTRICT",
        ),
    ),
    "prompt_template_versions": (
        (
            "fk_prompt_template_versions_lineage_key_prompt_template_versions",
            ("lineage_key", "predecessor_id"),
            "prompt_template_versions",
            ("lineage_key", "id"),
            "RESTRICT",
        ),
        (
            "fk_prompt_template_versions_evaluation_evidence_id_evidence_records",
            "evaluation_evidence_id",
            "evidence_records",
            "id",
            "RESTRICT",
        ),
    ),
    "policy_versions": (
        (
            "fk_policy_versions_lineage_predecessor_policy_versions",
            ("lineage_key", "predecessor_id"),
            "policy_versions",
            ("lineage_key", "id"),
            "RESTRICT",
        ),
        (
            "fk_policy_versions_lineage_rollback_policy_versions",
            ("lineage_key", "rollback_policy_version_id"),
            "policy_versions",
            ("lineage_key", "id"),
            "RESTRICT",
        ),
    ),
    "policy_version_review_rules": (
        (
            "fk_policy_version_review_rules_policy_version_id_policy_versions",
            "policy_version_id",
            "policy_versions",
            "id",
            "CASCADE",
        ),
        (
            "fk_policy_version_review_rules_review_rule_id_review_rules",
            "review_rule_id",
            "review_rules",
            "id",
            "RESTRICT",
        ),
    ),
    "policy_version_prompt_templates": (
        (
            "fk_policy_version_prompt_templates_policy_version_id_policy_versions",
            "policy_version_id",
            "policy_versions",
            "id",
            "CASCADE",
        ),
        (
            "fk_policy_version_prompt_templates_prompt_template_version_id_prompt_template_versions",
            ("prompt_template_version_id", "prompt_promoted"),
            "prompt_template_versions",
            ("id", "promoted"),
            "RESTRICT",
        ),
    ),
    "background_jobs": (
        (
            "fk_background_jobs_task_id_tasks",
            "task_id",
            "tasks",
            "id",
            "CASCADE",
        ),
    ),
    "background_job_leases": (
        (
            "fk_background_job_leases_job_id_background_jobs",
            "job_id",
            "background_jobs",
            "id",
            "CASCADE",
        ),
    ),
    "webhook_deliveries": (
        (
            "fk_webhook_deliveries_payload_evidence_id_evidence_records",
            "payload_evidence_id",
            "evidence_records",
            "id",
            "RESTRICT",
        ),
    ),
}

_NEW_TABLES = (
    "briefs",
    "repository_configurations",
    "task_events",
    "evidence_records",
    "validation_contracts",
    "validation_runs",
    "policy_versions",
    "brief_approval_decisions",
    "approval_requests",
    "rule_candidates",
    "review_rules",
    "prompt_template_versions",
    "policy_version_review_rules",
    "policy_version_prompt_templates",
    "background_jobs",
    "background_job_leases",
    "webhook_deliveries",
)


def _add_foreign_keys() -> None:
    for table_name, foreign_keys in _FOREIGN_KEYS.items():
        with op.batch_alter_table(table_name) as batch_op:
            for name, local_columns, target_table, target_columns, ondelete in foreign_keys:
                batch_op.create_foreign_key(
                    op.f(name),
                    target_table,
                    [local_columns] if isinstance(local_columns, str) else list(local_columns),
                    [target_columns] if isinstance(target_columns, str) else list(target_columns),
                    ondelete=ondelete,
                )


def _drop_foreign_keys() -> None:
    # Drop relationships from new tables before rebuilding the legacy tasks
    # table. This keeps SQLite batch migrations safe when FK enforcement is on.
    table_names = tuple(name for name in reversed(_NEW_TABLES) if name in _FOREIGN_KEYS)
    for table_name in (*table_names, "tasks"):
        with op.batch_alter_table(table_name) as batch_op:
            for name, *_ in reversed(_FOREIGN_KEYS[table_name]):
                batch_op.drop_constraint(op.f(name), type_="foreignkey")


def _extend_tasks() -> None:
    with op.batch_alter_table("tasks") as batch_op:
        batch_op.add_column(
            sa.Column(
                "repository",
                sa.String(length=500),
                server_default="legacy-local",
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column(
                "base_revision",
                sa.String(length=255),
                server_default=_LEGACY_BASE_REVISION,
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column(
                "requester",
                sa.String(length=255),
                server_default="legacy-local-user",
                nullable=False,
            )
        )
        batch_op.add_column(sa.Column("raw_request", sa.Text(), server_default="", nullable=True))
        batch_op.add_column(
            sa.Column(
                "state",
                sa.String(length=32),
                server_default="INTAKE",
                nullable=False,
            )
        )
        batch_op.add_column(sa.Column("accepted_brief_id", sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column("brief_approval_decision_id", sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column("repository_configuration_id", sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column("validation_contract_id", sa.Uuid(), nullable=True))
        batch_op.add_column(
            sa.Column(
                "retry_count",
                sa.Integer(),
                server_default="0",
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column(
                "escalation_resume_state",
                sa.String(length=32),
                nullable=True,
            )
        )
        batch_op.add_column(sa.Column("terminal_outcome", sa.Text(), nullable=True))
        batch_op.add_column(
            sa.Column(
                "owner_id",
                sa.String(length=255),
                server_default="legacy-local-user",
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column(
                "actor_id",
                sa.String(length=255),
                server_default="legacy-local-user",
                nullable=False,
            )
        )
        batch_op.add_column(sa.Column("root_correlation_id", sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column("causation_id", sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column("parent_correlation_id", sa.Uuid(), nullable=True))

    # Preserve the original request text for legacy rows and seed a stable,
    # unique root correlation without relying on database-specific UUID
    # functions. A task's own UUID is the natural initial correlation root.
    op.execute(
        sa.text(
            "UPDATE tasks SET "
            "repository = 'legacy-local', "
            f"base_revision = '{_LEGACY_BASE_REVISION}', "
            "requester = 'legacy-local-user', "
            "raw_request = summary, "
            "owner_id = 'legacy-local-user', "
            "actor_id = 'legacy-local-user'"
        )
    )
    op.execute(
        sa.text("UPDATE tasks SET root_correlation_id = id WHERE root_correlation_id IS NULL")
    )

    with op.batch_alter_table("tasks") as batch_op:
        batch_op.alter_column(
            "repository",
            existing_type=sa.String(length=500),
            existing_server_default="legacy-local",
            server_default=None,
            nullable=False,
        )
        batch_op.alter_column(
            "base_revision",
            existing_type=sa.String(length=255),
            existing_server_default=_LEGACY_BASE_REVISION,
            server_default=None,
            nullable=False,
        )
        batch_op.alter_column(
            "requester",
            existing_type=sa.String(length=255),
            existing_server_default="legacy-local-user",
            server_default=None,
            nullable=False,
        )
        batch_op.alter_column(
            "raw_request",
            existing_type=sa.Text(),
            existing_server_default="",
            server_default=None,
            nullable=False,
        )
        batch_op.alter_column(
            "owner_id",
            existing_type=sa.String(length=255),
            existing_server_default="legacy-local-user",
            server_default=None,
            nullable=False,
        )
        batch_op.alter_column(
            "actor_id",
            existing_type=sa.String(length=255),
            existing_server_default="legacy-local-user",
            server_default=None,
            nullable=False,
        )
        batch_op.alter_column(
            "root_correlation_id",
            existing_type=sa.Uuid(),
            nullable=False,
        )
        batch_op.create_check_constraint(
            op.f("ck_tasks_task_state"),
            _enum_check("state", _TASK_STATES),
        )
        batch_op.create_check_constraint(
            op.f("ck_tasks_task_escalation_resume_state"),
            _enum_check("escalation_resume_state", _TASK_STATES),
        )
        batch_op.create_check_constraint(
            op.f("ck_tasks_retry_count_non_negative"),
            "retry_count >= 0",
        )
        batch_op.create_check_constraint(
            op.f("ck_tasks_base_revision_length"),
            "length(base_revision) IN (40, 64)",
        )


def _create_domain_tables() -> None:
    _create_record_table(
        "briefs",
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("predecessor_id", sa.Uuid(), nullable=True),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("exclusions", sa.JSON(), nullable=False),
        sa.Column("acceptance_criteria", sa.JSON(), nullable=False),
        sa.Column("risks", sa.JSON(), nullable=False),
        sa.Column("affected_flow", sa.JSON(), nullable=False),
        sa.Column("test_plan", sa.JSON(), nullable=False),
        sa.CheckConstraint(
            "version > 0",
            name=op.f("ck_briefs_version_positive"),
        ),
        sa.CheckConstraint(
            "predecessor_id IS NULL OR predecessor_id <> id",
            name=op.f("ck_briefs_predecessor_not_self"),
        ),
        sa.UniqueConstraint(
            "task_id",
            "version",
            name=op.f("uq_briefs_task_version"),
        ),
        sa.UniqueConstraint(
            "task_id",
            "id",
            name=op.f("uq_briefs_task_id"),
        ),
    )
    _create_record_table(
        "repository_configurations",
        sa.Column("repository_key", sa.String(length=500), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("predecessor_id", sa.Uuid(), nullable=True),
        sa.Column("repository_settings", sa.JSON(), nullable=False),
        sa.Column("git_settings", sa.JSON(), nullable=False),
        sa.Column("xcode_settings", sa.JSON(), nullable=False),
        sa.Column("operations", sa.JSON(), nullable=False),
        sa.Column("e2e_assertions", sa.JSON(), nullable=False),
        sa.Column("artifact_settings", sa.JSON(), nullable=False),
        sa.Column("prohibited_paths", sa.JSON(), nullable=False),
        sa.Column("secret_references", sa.JSON(), nullable=False),
        sa.Column("preflight_evidence_id", sa.Uuid(), nullable=True),
        sa.CheckConstraint(
            "version > 0",
            name=op.f("ck_repository_configurations_version_positive"),
        ),
        sa.CheckConstraint(
            "predecessor_id IS NULL OR predecessor_id <> id",
            name=op.f("ck_repository_configurations_predecessor_not_self"),
        ),
        sa.UniqueConstraint(
            "repository_key",
            "version",
            name=op.f("uq_repository_configurations_repository_version"),
        ),
        sa.UniqueConstraint(
            "repository_key",
            "id",
            name=op.f("uq_repository_configurations_repository_id"),
        ),
    )
    _create_record_table(
        "task_events",
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "sequence > 0",
            name=op.f("ck_task_events_sequence_positive"),
        ),
        sa.UniqueConstraint(
            "task_id",
            "sequence",
            name=op.f("uq_task_events_task_sequence"),
        ),
    )
    _create_record_table(
        "evidence_records",
        sa.Column("task_id", sa.Uuid(), nullable=True),
        sa.Column("validation_run_id", sa.Uuid(), nullable=True),
        sa.Column("evidence_type", sa.String(length=100), nullable=False),
        sa.Column("origin", sa.String(length=500), nullable=False),
        sa.Column("content_hash", sa.String(length=80), nullable=False),
        sa.Column("content_address", sa.String(length=255), nullable=True),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "access_classification",
            sa.String(length=100),
            nullable=False,
        ),
        sa.Column("retention_policy", sa.String(length=100), nullable=False),
        sa.Column("correction_of_id", sa.Uuid(), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deletion_actor_id", sa.String(length=255), nullable=True),
        sa.Column("deletion_reason", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "correction_of_id IS NULL OR correction_of_id <> id",
            name=op.f("ck_evidence_records_correction_not_self"),
        ),
    )
    _create_record_table(
        "validation_contracts",
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("predecessor_id", sa.Uuid(), nullable=True),
        sa.Column("brief_id", sa.Uuid(), nullable=False),
        sa.Column(
            "repository_configuration_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column("required_operations", sa.JSON(), nullable=False),
        sa.Column("simulator_setup", sa.JSON(), nullable=False),
        sa.Column("clean_state_setup", sa.JSON(), nullable=False),
        sa.Column("e2e_flow", sa.JSON(), nullable=False),
        sa.Column("typed_assertions", sa.JSON(), nullable=False),
        sa.Column("evidence_requirements", sa.JSON(), nullable=False),
        sa.Column("timeouts", sa.JSON(), nullable=False),
        sa.Column("outcome_rules", sa.JSON(), nullable=False),
        sa.CheckConstraint(
            "version > 0",
            name=op.f("ck_validation_contracts_version_positive"),
        ),
        sa.CheckConstraint(
            "predecessor_id IS NULL OR predecessor_id <> id",
            name=op.f("ck_validation_contracts_predecessor_not_self"),
        ),
        sa.UniqueConstraint(
            "task_id",
            "version",
            name=op.f("uq_validation_contracts_task_version"),
        ),
        sa.UniqueConstraint(
            "task_id",
            "id",
            name=op.f("uq_validation_contracts_task_id"),
        ),
        sa.UniqueConstraint(
            "id",
            "repository_configuration_id",
            name=op.f("uq_validation_contracts_id_repository_configuration"),
        ),
    )
    _create_record_table(
        "validation_runs",
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("validation_contract_id", sa.Uuid(), nullable=False),
        sa.Column(
            "repository_configuration_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column("commit_sha", sa.String(length=64), nullable=False),
        sa.Column("tree_sha", sa.String(length=64), nullable=False),
        sa.Column("configured_test_plan", sa.JSON(), nullable=False),
        sa.Column("operation_results", sa.JSON(), nullable=False),
        sa.Column("simulator_target", sa.JSON(), nullable=True),
        sa.Column(
            "outcome",
            sa.String(length=64),
            server_default="PENDING",
            nullable=False,
        ),
        sa.Column("duration_ms", sa.BigInteger(), nullable=False),
        sa.Column("log_evidence_id", sa.Uuid(), nullable=True),
        sa.Column(
            "acceptance_criterion_results",
            sa.JSON(),
            nullable=False,
        ),
        sa.CheckConstraint(
            _enum_check("outcome", _VALIDATION_OUTCOMES),
            name=op.f("ck_validation_runs_validation_run_outcome"),
        ),
        sa.CheckConstraint(
            "duration_ms >= 0",
            name=op.f("ck_validation_runs_duration_non_negative"),
        ),
        sa.CheckConstraint(
            "length(commit_sha) IN (40, 64)",
            name=op.f("ck_validation_runs_commit_sha_length"),
        ),
        sa.CheckConstraint(
            "length(tree_sha) IN (40, 64)",
            name=op.f("ck_validation_runs_tree_sha_length"),
        ),
    )
    _create_record_table(
        "policy_versions",
        sa.Column("lineage_key", sa.String(length=255), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("predecessor_id", sa.Uuid(), nullable=True),
        sa.Column("workflow_thresholds", sa.JSON(), nullable=False),
        sa.Column("approved_by", sa.String(length=255), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rollback_policy_version_id", sa.Uuid(), nullable=True),
        sa.CheckConstraint(
            "version > 0",
            name=op.f("ck_policy_versions_version_positive"),
        ),
        sa.CheckConstraint(
            "predecessor_id IS NULL OR predecessor_id <> id",
            name=op.f("ck_policy_versions_predecessor_not_self"),
        ),
        sa.UniqueConstraint(
            "lineage_key",
            "version",
            name=op.f("uq_policy_versions_lineage_version"),
        ),
        sa.UniqueConstraint(
            "lineage_key",
            "id",
            name=op.f("uq_policy_versions_lineage_id"),
        ),
    )
    _create_record_table(
        "brief_approval_decisions",
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("brief_id", sa.Uuid(), nullable=False),
        sa.Column(
            "disposition",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column("evaluator_id", sa.String(length=255), nullable=False),
        sa.Column("policy_version_id", sa.Uuid(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("ambiguity_flags", sa.JSON(), nullable=False),
        sa.Column("human_response", sa.Text(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            _enum_check(
                "disposition",
                _BRIEF_DECISION_DISPOSITIONS,
            ),
            name=op.f("ck_brief_approval_decisions_brief_decision_disposition"),
        ),
        sa.UniqueConstraint(
            "brief_id",
            name=op.f("uq_brief_approval_decisions_brief"),
        ),
        sa.UniqueConstraint(
            "task_id",
            "id",
            name=op.f("uq_brief_approval_decisions_task_id"),
        ),
        sa.UniqueConstraint(
            "id",
            "brief_id",
            name=op.f("uq_brief_approval_decisions_id_brief"),
        ),
    )
    _create_record_table(
        "approval_requests",
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("request_type", sa.String(length=100), nullable=False),
        sa.Column("subject_type", sa.String(length=100), nullable=True),
        sa.Column("subject_id", sa.Uuid(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("options", sa.JSON(), nullable=False),
        sa.Column("supporting_evidence_ids", sa.JSON(), nullable=False),
        sa.Column(
            "requesting_state",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "status",
            sa.String(length=64),
            server_default="PENDING",
            nullable=False,
        ),
        sa.Column("decision", sa.Text(), nullable=True),
        sa.Column("decided_by", sa.String(length=255), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            _enum_check("requesting_state", _TASK_STATES),
            name=op.f("ck_approval_requests_approval_request_task_state"),
        ),
        sa.CheckConstraint(
            _enum_check("status", _APPROVAL_STATUSES),
            name=op.f("ck_approval_requests_approval_request_status"),
        ),
        sa.UniqueConstraint(
            "id",
            "status",
            name=op.f("uq_approval_requests_id_status"),
        ),
        sa.UniqueConstraint(
            "id",
            "status",
            "request_type",
            "subject_type",
            "subject_id",
            name=op.f("uq_approval_requests_id_status_subject"),
        ),
    )
    _create_record_table(
        "rule_candidates",
        sa.Column("task_id", sa.Uuid(), nullable=True),
        sa.Column("proposed_rule", sa.Text(), nullable=False),
        sa.Column("cited_evidence_ids", sa.JSON(), nullable=False),
        sa.Column("recurrence_assessment", sa.Text(), nullable=False),
        sa.Column(
            "severity_assessment",
            sa.String(length=100),
            nullable=False,
        ),
        sa.Column("false_positive_risks", sa.JSON(), nullable=False),
        sa.Column("evaluation_result", sa.JSON(), nullable=True),
        sa.Column(
            "status",
            sa.String(length=64),
            server_default="PROPOSED",
            nullable=False,
        ),
        sa.CheckConstraint(
            _enum_check("status", _RULE_CANDIDATE_STATUSES),
            name=op.f("ck_rule_candidates_rule_candidate_status"),
        ),
    )
    _create_record_table(
        "review_rules",
        sa.Column("lineage_key", sa.String(length=255), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("predecessor_id", sa.Uuid(), nullable=True),
        sa.Column("candidate_id", sa.Uuid(), nullable=False),
        sa.Column("approval_request_id", sa.Uuid(), nullable=False),
        sa.Column(
            "approval_status",
            sa.String(length=64),
            server_default="APPROVED",
            nullable=False,
        ),
        sa.Column(
            "approval_request_type",
            sa.String(length=100),
            server_default="REVIEW_RULE",
            nullable=False,
        ),
        sa.Column(
            "approval_subject_type",
            sa.String(length=100),
            server_default="RULE_CANDIDATE",
            nullable=False,
        ),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("matcher", sa.JSON(), nullable=False),
        sa.Column("permitted_action", sa.String(length=255), nullable=False),
        sa.Column("risk_class", sa.String(length=100), nullable=False),
        sa.Column("evidence_requirements", sa.JSON(), nullable=False),
        sa.Column("provenance", sa.JSON(), nullable=False),
        sa.Column("approved_by", sa.String(length=255), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "version > 0",
            name=op.f("ck_review_rules_version_positive"),
        ),
        sa.CheckConstraint(
            "predecessor_id IS NULL OR predecessor_id <> id",
            name=op.f("ck_review_rules_predecessor_not_self"),
        ),
        sa.CheckConstraint(
            _enum_check("approval_status", _APPROVAL_STATUSES),
            name=op.f("ck_review_rules_review_rule_approval_status"),
        ),
        sa.CheckConstraint(
            "approval_status = 'APPROVED'",
            name=op.f("ck_review_rules_approval_status_approved"),
        ),
        sa.CheckConstraint(
            "approval_request_type = 'REVIEW_RULE'",
            name=op.f("ck_review_rules_approval_request_type_review_rule"),
        ),
        sa.CheckConstraint(
            "approval_subject_type = 'RULE_CANDIDATE'",
            name=op.f("ck_review_rules_approval_subject_type_rule_candidate"),
        ),
        sa.UniqueConstraint(
            "lineage_key",
            "version",
            name=op.f("uq_review_rules_lineage_version"),
        ),
        sa.UniqueConstraint(
            "lineage_key",
            "id",
            name=op.f("uq_review_rules_lineage_id"),
        ),
    )
    _create_record_table(
        "prompt_template_versions",
        sa.Column("lineage_key", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=100), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("predecessor_id", sa.Uuid(), nullable=True),
        sa.Column("structured_template", sa.JSON(), nullable=False),
        sa.Column("evaluation_evidence_id", sa.Uuid(), nullable=True),
        sa.Column("evaluation_score", sa.Float(), nullable=True),
        sa.Column(
            "evaluation_threshold_passed",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "regression_reviewed",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "promoted",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("approved_by", sa.String(length=255), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "version > 0",
            name=op.f("ck_prompt_template_versions_version_positive"),
        ),
        sa.CheckConstraint(
            "predecessor_id IS NULL OR predecessor_id <> id",
            name=op.f("ck_prompt_template_versions_predecessor_not_self"),
        ),
        sa.CheckConstraint(
            "promoted = false OR "
            "(evaluation_threshold_passed = true AND regression_reviewed = true "
            "AND approved_by IS NOT NULL AND approved_at IS NOT NULL)",
            name=op.f("ck_prompt_template_versions_promotion_requirements"),
        ),
        sa.UniqueConstraint(
            "lineage_key",
            "version",
            name=op.f("uq_prompt_template_versions_lineage_version"),
        ),
        sa.UniqueConstraint(
            "lineage_key",
            "id",
            name=op.f("uq_prompt_template_versions_lineage_id"),
        ),
        sa.UniqueConstraint(
            "id",
            "promoted",
            name=op.f("uq_prompt_template_versions_id_promoted"),
        ),
    )
    _create_record_table(
        "policy_version_review_rules",
        sa.Column("policy_version_id", sa.Uuid(), nullable=False),
        sa.Column("review_rule_id", sa.Uuid(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "position > 0",
            name=op.f("ck_policy_version_review_rules_position_positive"),
        ),
        sa.UniqueConstraint(
            "policy_version_id",
            "position",
            name=op.f("uq_policy_rules_position"),
        ),
        sa.UniqueConstraint(
            "policy_version_id",
            "review_rule_id",
            name=op.f("uq_policy_rules_membership"),
        ),
    )
    _create_record_table(
        "policy_version_prompt_templates",
        sa.Column("policy_version_id", sa.Uuid(), nullable=False),
        sa.Column(
            "prompt_template_version_id",
            sa.Uuid(),
            nullable=False,
        ),
        sa.Column(
            "prompt_promoted",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "position > 0",
            name=op.f("ck_policy_version_prompt_templates_position_positive"),
        ),
        sa.CheckConstraint(
            "prompt_promoted = true",
            name=op.f("ck_policy_version_prompt_templates_prompt_promoted"),
        ),
        sa.UniqueConstraint(
            "policy_version_id",
            "position",
            name=op.f("uq_policy_prompts_position"),
        ),
        sa.UniqueConstraint(
            "policy_version_id",
            "prompt_template_version_id",
            name=op.f("uq_policy_prompts_membership"),
        ),
    )
    _create_record_table(
        "background_jobs",
        sa.Column("task_id", sa.Uuid(), nullable=True),
        sa.Column("job_type", sa.String(length=100), nullable=False),
        sa.Column(
            "status",
            sa.String(length=64),
            server_default="QUEUED",
            nullable=False,
        ),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column(
            "attempt_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column("checkpoint", sa.JSON(), nullable=True),
        sa.Column(
            "cancellation_requested_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            _enum_check("status", _BACKGROUND_JOB_STATUSES),
            name=op.f("ck_background_jobs_background_job_status"),
        ),
        sa.CheckConstraint(
            "attempt_count >= 0",
            name=op.f("ck_background_jobs_attempt_count_non_negative"),
        ),
        sa.UniqueConstraint(
            "idempotency_key",
            name=op.f("uq_background_jobs_idempotency_key"),
        ),
    )
    _create_record_table(
        "background_job_leases",
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("lease_owner", sa.String(length=255), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("fencing_token", sa.BigInteger(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("checkpoint", sa.JSON(), nullable=True),
        sa.Column(
            "cancellation_acknowledged_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.CheckConstraint(
            "attempt > 0",
            name=op.f("ck_background_job_leases_attempt_positive"),
        ),
        sa.CheckConstraint(
            "fencing_token > 0",
            name=op.f("ck_background_job_leases_fencing_token_positive"),
        ),
        sa.UniqueConstraint(
            "job_id",
            "attempt",
            name=op.f("uq_background_job_leases_job_attempt"),
        ),
        sa.UniqueConstraint(
            "fencing_token",
            name=op.f("uq_background_job_leases_fencing_token"),
        ),
        sa.UniqueConstraint(
            "idempotency_key",
            name=op.f("uq_background_job_leases_idempotency_key"),
        ),
    )
    _create_record_table(
        "webhook_deliveries",
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column(
            "provider_delivery_id",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column("installation_id", sa.String(length=255), nullable=False),
        sa.Column("repository_id", sa.String(length=255), nullable=False),
        sa.Column("pull_request_number", sa.Integer(), nullable=True),
        sa.Column("head_sha", sa.String(length=64), nullable=True),
        sa.Column("signature_verified", sa.Boolean(), nullable=False),
        sa.Column("payload_evidence_id", sa.Uuid(), nullable=True),
        sa.Column("processing_result", sa.JSON(), nullable=True),
        sa.Column("quarantine_reason", sa.Text(), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            "provider",
            "provider_delivery_id",
            name=op.f("uq_webhook_deliveries_provider_delivery"),
        ),
    )


def upgrade() -> None:
    """Expand tasks and create all immutable domain record tables."""

    _extend_tasks()
    _create_domain_tables()
    _add_foreign_keys()


def downgrade() -> None:
    """Restore the revision-0002 task shape without losing legacy task rows."""

    sqlite = op.get_bind().dialect.name == "sqlite"
    if sqlite:
        # Cyclic domain references require SQLite to defer FK validation until
        # the teardown has removed every related constraint and table. Clear
        # nullable cycle edges as well so SQLite does not retain deferred
        # violations after their source tables have been dropped.
        op.execute(sa.text("BEGIN"))
        op.execute(sa.text("PRAGMA defer_foreign_keys = ON"))
        op.execute(
            sa.text(
                "UPDATE tasks SET "
                "accepted_brief_id = NULL, "
                "brief_approval_decision_id = NULL, "
                "repository_configuration_id = NULL, "
                "validation_contract_id = NULL"
            )
        )
        op.execute(
            sa.text(
                "UPDATE repository_configurations SET "
                "predecessor_id = NULL, preflight_evidence_id = NULL"
            )
        )
        op.execute(sa.text("UPDATE briefs SET predecessor_id = NULL"))
        op.execute(
            sa.text("UPDATE evidence_records SET validation_run_id = NULL, correction_of_id = NULL")
        )
        op.execute(sa.text("UPDATE validation_contracts SET predecessor_id = NULL"))
        op.execute(sa.text("UPDATE validation_runs SET log_evidence_id = NULL"))
        op.execute(sa.text("UPDATE review_rules SET predecessor_id = NULL"))
        op.execute(
            sa.text(
                "UPDATE prompt_template_versions SET "
                "predecessor_id = NULL, evaluation_evidence_id = NULL"
            )
        )
        op.execute(
            sa.text(
                "UPDATE policy_versions SET "
                "predecessor_id = NULL, rollback_policy_version_id = NULL"
            )
        )

    _drop_foreign_keys()
    for table_name in reversed(_NEW_TABLES):
        op.drop_table(table_name)

    with op.batch_alter_table("tasks") as batch_op:
        batch_op.drop_constraint(
            op.f("ck_tasks_task_escalation_resume_state"),
            type_="check",
        )
        batch_op.drop_constraint(
            op.f("ck_tasks_task_state"),
            type_="check",
        )
        batch_op.drop_constraint(
            op.f("ck_tasks_retry_count_non_negative"),
            type_="check",
        )
        batch_op.drop_constraint(
            op.f("ck_tasks_base_revision_length"),
            type_="check",
        )
        for column_name in (
            "parent_correlation_id",
            "causation_id",
            "root_correlation_id",
            "actor_id",
            "owner_id",
            "terminal_outcome",
            "escalation_resume_state",
            "retry_count",
            "validation_contract_id",
            "repository_configuration_id",
            "brief_approval_decision_id",
            "accepted_brief_id",
            "state",
            "raw_request",
            "requester",
            "base_revision",
            "repository",
        ):
            batch_op.drop_column(column_name)

    if sqlite:
        op.execute(sa.text("COMMIT"))
