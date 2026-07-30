"""Add canonical evidence auditing, deletion fencing, and derivatives.

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-30
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_APPEND_ONLY_TABLES = (
    "evidence_records",
    "evidence_audit_events",
    "evidence_deletion_requests",
    "evidence_tombstones",
)


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


def _create_append_only_triggers() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(
            sa.text(
                "CREATE FUNCTION reject_evidence_append_only_mutation() "
                "RETURNS trigger LANGUAGE plpgsql AS $$ "
                "BEGIN RAISE EXCEPTION 'evidence audit records are append-only'; "
                "RETURN NULL; END; $$"
            )
        )
        for table_name in _APPEND_ONLY_TABLES:
            op.execute(
                sa.text(
                    f"CREATE TRIGGER {table_name}_append_only "
                    f"BEFORE UPDATE OR DELETE ON {table_name} "
                    "FOR EACH ROW EXECUTE FUNCTION "
                    "reject_evidence_append_only_mutation()"
                )
            )
        op.execute(
            sa.text(
                "CREATE FUNCTION restrict_evidence_derivative_mutation() "
                "RETURNS trigger LANGUAGE plpgsql AS $$ "
                "BEGIN "
                "IF TG_OP = 'DELETE' THEN "
                "RAISE EXCEPTION 'evidence derivatives cannot be deleted'; "
                "END IF; "
                "IF OLD.id IS NOT DISTINCT FROM NEW.id "
                "AND OLD.evidence_id IS NOT DISTINCT FROM NEW.evidence_id "
                "AND OLD.derivative_type IS NOT DISTINCT FROM NEW.derivative_type "
                "AND OLD.content_hash IS NOT DISTINCT FROM NEW.content_hash "
                "AND OLD.captured_at IS NOT DISTINCT FROM NEW.captured_at "
                "AND OLD.owner_id IS NOT DISTINCT FROM NEW.owner_id "
                "AND OLD.actor_id IS NOT DISTINCT FROM NEW.actor_id "
                "AND OLD.root_correlation_id IS NOT DISTINCT FROM "
                "NEW.root_correlation_id "
                "AND OLD.causation_id IS NOT DISTINCT FROM NEW.causation_id "
                "AND OLD.parent_correlation_id IS NOT DISTINCT FROM "
                "NEW.parent_correlation_id "
                "AND OLD.created_at IS NOT DISTINCT FROM NEW.created_at "
                "AND OLD.content_address IS NOT NULL "
                "AND NEW.content_address IS NULL "
                "AND OLD.deleted_at IS NULL "
                "AND NEW.deleted_at IS NOT NULL THEN RETURN NEW; END IF; "
                "RAISE EXCEPTION 'invalid evidence derivative mutation'; "
                "END; $$"
            )
        )
        op.execute(
            sa.text(
                "CREATE TRIGGER evidence_derivatives_lifecycle "
                "BEFORE UPDATE OR DELETE ON evidence_derivatives "
                "FOR EACH ROW EXECUTE FUNCTION "
                "restrict_evidence_derivative_mutation()"
            )
        )
        return
    if dialect == "sqlite":
        for table_name in _APPEND_ONLY_TABLES:
            op.execute(
                sa.text(
                    f"CREATE TRIGGER {table_name}_no_update "
                    f"BEFORE UPDATE ON {table_name} BEGIN "
                    "SELECT RAISE(ABORT, 'evidence audit records are append-only'); "
                    "END"
                )
            )
            op.execute(
                sa.text(
                    f"CREATE TRIGGER {table_name}_no_delete "
                    f"BEFORE DELETE ON {table_name} BEGIN "
                    "SELECT RAISE(ABORT, 'evidence audit records are append-only'); "
                    "END"
                )
            )
        op.execute(
            sa.text(
                "CREATE TRIGGER evidence_derivatives_no_delete "
                "BEFORE DELETE ON evidence_derivatives BEGIN "
                "SELECT RAISE(ABORT, 'evidence derivatives cannot be deleted'); END"
            )
        )
        op.execute(
            sa.text(
                "CREATE TRIGGER evidence_derivatives_restrict_update "
                "BEFORE UPDATE ON evidence_derivatives WHEN NOT ("
                "OLD.id IS NEW.id AND "
                "OLD.evidence_id IS NEW.evidence_id AND "
                "OLD.derivative_type IS NEW.derivative_type AND "
                "OLD.content_hash IS NEW.content_hash AND "
                "OLD.captured_at IS NEW.captured_at AND "
                "OLD.owner_id IS NEW.owner_id AND "
                "OLD.actor_id IS NEW.actor_id AND "
                "OLD.root_correlation_id IS NEW.root_correlation_id AND "
                "OLD.causation_id IS NEW.causation_id AND "
                "OLD.parent_correlation_id IS NEW.parent_correlation_id AND "
                "OLD.created_at IS NEW.created_at AND "
                "OLD.content_address IS NOT NULL AND "
                "NEW.content_address IS NULL AND "
                "OLD.deleted_at IS NULL AND "
                "NEW.deleted_at IS NOT NULL"
                ") BEGIN "
                "SELECT RAISE(ABORT, 'invalid evidence derivative mutation'); END"
            )
        )


def _drop_append_only_triggers() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(
            sa.text(
                "DROP TRIGGER evidence_derivatives_lifecycle "
                "ON evidence_derivatives"
            )
        )
        for table_name in _APPEND_ONLY_TABLES:
            op.execute(
                sa.text(f"DROP TRIGGER {table_name}_append_only ON {table_name}")
            )
        op.execute(sa.text("DROP FUNCTION restrict_evidence_derivative_mutation()"))
        op.execute(sa.text("DROP FUNCTION reject_evidence_append_only_mutation()"))
        return
    if dialect == "sqlite":
        op.execute(sa.text("DROP TRIGGER evidence_derivatives_restrict_update"))
        op.execute(sa.text("DROP TRIGGER evidence_derivatives_no_delete"))
        for table_name in _APPEND_ONLY_TABLES:
            op.execute(sa.text(f"DROP TRIGGER {table_name}_no_update"))
            op.execute(sa.text(f"DROP TRIGGER {table_name}_no_delete"))


def upgrade() -> None:
    """Add the durable records used by the evidence safety boundary."""

    # Revision-0003 artifacts predate the canonical envelope. Fence every
    # attached preflight explicitly so callers must issue a new attempt rather
    # than silently treating legacy bytes as current authorization.
    op.execute(
        sa.text(
            "UPDATE repository_configurations "
            "SET preflight_evidence_id = NULL "
            "WHERE preflight_evidence_id IS NOT NULL"
        )
    )
    # Revision-0003 task requests and summaries were direct content copies with
    # no evidence lineage. They cannot be safely backfilled without the original
    # redaction policy, so fence them and require explicit re-intake.
    op.execute(
        sa.text(
            "UPDATE tasks SET "
            "raw_request = 'legacy-request-fenced', "
            "summary = 'Legacy task requires re-intake', "
            "state = 'ESCALATED', "
            "escalation_resume_state = 'INTAKE', "
            "terminal_outcome = NULL"
        )
    )
    # Pre-0004 metadata was unrestricted and may itself contain credentials.
    # Retain only safe lineage identifiers before append-only triggers install.
    op.execute(
        sa.text(
            "UPDATE evidence_records SET "
            "evidence_type = 'legacy-evidence', "
            "origin = 'legacy:fenced', "
            "owner_id = 'local-user', "
            "actor_id = 'legacy-fenced', "
            "deletion_actor_id = NULL, "
            "deletion_reason = NULL"
        )
    )
    op.execute(
        sa.text(
            "UPDATE evidence_records SET access_classification = CASE "
            "WHEN access_classification = 'task' THEN 'TASK_OWNER' "
            "WHEN access_classification = 'internal' THEN 'INTERNAL' "
            "WHEN access_classification IN "
            "('TASK_OWNER', 'OWNER', 'RECENT_PASSWORD', 'INTERNAL') "
            "THEN access_classification "
            "ELSE 'INTERNAL' END"
        )
    )
    op.execute(
        sa.text(
            "UPDATE evidence_records SET retention_policy = CASE "
            "WHEN retention_policy = 'mvp-default' THEN 'TASK_LIFETIME' "
            "WHEN retention_policy = 'repository-configuration' "
            "THEN 'REPOSITORY_LIFETIME' "
            "WHEN retention_policy IN "
            "('TASK_LIFETIME', 'REPOSITORY_LIFETIME', 'AUDIT') "
            "THEN retention_policy ELSE 'AUDIT' END"
        )
    )

    with op.batch_alter_table("evidence_records") as batch_op:
        batch_op.drop_constraint(
            op.f("fk_evidence_records_task_id_tasks"),
            type_="foreignkey",
        )
        batch_op.drop_constraint(
            op.f("fk_evidence_records_validation_run_id_validation_runs"),
            type_="foreignkey",
        )
        batch_op.create_foreign_key(
            op.f("fk_evidence_records_task_id_tasks"),
            "tasks",
            ["task_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch_op.create_foreign_key(
            op.f("fk_evidence_records_validation_run_id_validation_runs"),
            "validation_runs",
            ["validation_run_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch_op.create_unique_constraint(
            op.f("uq_evidence_records_correction"),
            ["correction_of_id"],
        )
        batch_op.create_check_constraint(
            op.f("ck_evidence_records_access_classification"),
            "access_classification IN "
            "('TASK_OWNER', 'OWNER', 'RECENT_PASSWORD', 'INTERNAL')",
        )
        batch_op.create_check_constraint(
            op.f("ck_evidence_records_retention_policy"),
            "retention_policy IN "
            "('TASK_LIFETIME', 'REPOSITORY_LIFETIME', 'AUDIT')",
        )

    op.create_table(
        "evidence_audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.Uuid(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        *_context_columns(),
        sa.CheckConstraint(
            "event_type IN "
            "('CAPTURED', 'METADATA_READ', 'CONTENT_DOWNLOADED', "
            "'CORRECTION_CREATED', 'DELETION_REQUESTED', 'CONTENT_DESTROYED', "
            "'DERIVATIVE_REGISTERED')",
            name=op.f("ck_evidence_audit_events_event_type"),
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence_records.id"],
            name=op.f("fk_evidence_audit_events_evidence_id_evidence_records"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_evidence_audit_events")),
    )
    op.create_table(
        "evidence_deletion_requests",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        *_context_columns(),
        sa.CheckConstraint(
            "reason_code IN "
            "('USER_REQUEST', 'RETENTION_EXPIRED', 'SOURCE_REVOKED', "
            "'SECURITY_RESPONSE')",
            name=op.f("ck_evidence_deletion_requests_reason_code"),
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence_records.id"],
            name=op.f(
                "fk_evidence_deletion_requests_evidence_id_evidence_records"
            ),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_evidence_deletion_requests")),
        sa.UniqueConstraint(
            "evidence_id",
            name=op.f("uq_evidence_deletion_requests_evidence"),
        ),
        sa.UniqueConstraint(
            "id",
            "evidence_id",
            "reason_code",
            name=op.f("uq_evidence_deletion_requests_identity"),
        ),
    )
    op.create_table(
        "evidence_derivatives",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("derivative_type", sa.String(length=100), nullable=False),
        sa.Column("content_hash", sa.String(length=80), nullable=False),
        sa.Column("content_address", sa.String(length=255), nullable=True),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        *_context_columns(),
        sa.CheckConstraint(
            "(deleted_at IS NULL AND content_address IS NOT NULL) OR "
            "(deleted_at IS NOT NULL AND content_address IS NULL)",
            name=op.f("ck_evidence_derivatives_deletion_state"),
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence_records.id"],
            name=op.f("fk_evidence_derivatives_evidence_id_evidence_records"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_evidence_derivatives")),
    )
    op.create_table(
        "evidence_tombstones",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("deletion_request_id", sa.Uuid(), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "removed_derivative_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        *_context_columns(),
        sa.CheckConstraint(
            "reason_code IN "
            "('USER_REQUEST', 'RETENTION_EXPIRED', 'SOURCE_REVOKED', "
            "'SECURITY_RESPONSE')",
            name=op.f("ck_evidence_tombstones_reason_code"),
        ),
        sa.CheckConstraint(
            "removed_derivative_count >= 0",
            name=op.f(
                "ck_evidence_tombstones_removed_derivative_count_non_negative"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["deletion_request_id", "evidence_id", "reason_code"],
            [
                "evidence_deletion_requests.id",
                "evidence_deletion_requests.evidence_id",
                "evidence_deletion_requests.reason_code",
            ],
            name=op.f("fk_evidence_tombstones_deletion_request_identity"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence_records.id"],
            name=op.f("fk_evidence_tombstones_evidence_id_evidence_records"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_evidence_tombstones")),
        sa.UniqueConstraint(
            "deletion_request_id",
            name=op.f("uq_evidence_tombstones_deletion_request"),
        ),
        sa.UniqueConstraint(
            "evidence_id",
            name=op.f("uq_evidence_tombstones_evidence"),
        ),
    )
    _create_append_only_triggers()

def downgrade() -> None:
    """Remove evidence-safety records while preserving revision-0003 data."""

    _drop_append_only_triggers()
    # Revision-0003 cannot decode canonical envelopes. Fence their pointers on
    # rollback and restore its legacy labels so the older code fails safely and
    # can issue a fresh preflight attempt.
    op.execute(
        sa.text(
            "UPDATE repository_configurations "
            "SET preflight_evidence_id = NULL "
            "WHERE preflight_evidence_id IS NOT NULL"
        )
    )
    op.drop_table("evidence_tombstones")
    op.drop_table("evidence_derivatives")
    op.drop_table("evidence_deletion_requests")
    op.drop_table("evidence_audit_events")

    with op.batch_alter_table("evidence_records") as batch_op:
        batch_op.drop_constraint(
            op.f("uq_evidence_records_correction"),
            type_="unique",
        )
        batch_op.drop_constraint(
            op.f("ck_evidence_records_access_classification"),
            type_="check",
        )
        batch_op.drop_constraint(
            op.f("ck_evidence_records_retention_policy"),
            type_="check",
        )
        batch_op.drop_constraint(
            op.f("fk_evidence_records_task_id_tasks"),
            type_="foreignkey",
        )
        batch_op.drop_constraint(
            op.f("fk_evidence_records_validation_run_id_validation_runs"),
            type_="foreignkey",
        )
        batch_op.create_foreign_key(
            op.f("fk_evidence_records_task_id_tasks"),
            "tasks",
            ["task_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_foreign_key(
            op.f("fk_evidence_records_validation_run_id_validation_runs"),
            "validation_runs",
            ["validation_run_id"],
            ["id"],
            ondelete="SET NULL",
        )

    op.execute(
        sa.text(
            "UPDATE evidence_records SET access_classification = CASE "
            "WHEN access_classification = 'INTERNAL' THEN 'internal' "
            "ELSE 'task' END"
        )
    )
    op.execute(
        sa.text(
            "UPDATE evidence_records SET retention_policy = CASE "
            "WHEN retention_policy = 'REPOSITORY_LIFETIME' "
            "THEN 'repository-configuration' ELSE 'mvp-default' END"
        )
    )
