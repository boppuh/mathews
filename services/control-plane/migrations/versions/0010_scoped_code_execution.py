"""Add durable control-plane-brokered Hermes tool execution.

Revision ID: 0010
Revises: 0009
Create Date: 2026-08-07
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _context_columns() -> tuple[sa.Column[Any], ...]:
    return (
        sa.Column("owner_id", sa.String(255), nullable=False),
        sa.Column("actor_id", sa.String(255), nullable=False),
        sa.Column("root_correlation_id", sa.Uuid(), nullable=False),
        sa.Column("causation_id", sa.Uuid()),
        sa.Column("parent_correlation_id", sa.Uuid()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )


def _append_only(table: str, label: str) -> None:
    if op.get_bind().dialect.name == "postgresql":
        function = f"reject_{label}_mutation"
        op.execute(
            sa.text(
                f"CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ "
                f"BEGIN RAISE EXCEPTION '{table} is append-only'; RETURN NULL; END; $$"
            )
        )
        op.execute(
            sa.text(
                f"CREATE TRIGGER {label}_append_only BEFORE UPDATE OR DELETE ON {table} "
                f"FOR EACH ROW EXECUTE FUNCTION {function}()"
            )
        )
        return
    for operation in ("UPDATE", "DELETE"):
        op.execute(
            sa.text(
                f"CREATE TRIGGER {label}_no_{operation.lower()} BEFORE {operation} ON {table} "
                f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END"
            )
        )


def upgrade() -> None:
    op.create_table(
        "hermes_tool_proposals",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("lease_id", sa.Uuid(), nullable=False),
        sa.Column("fencing_token", sa.BigInteger(), nullable=False),
        sa.Column("external_proposal_id", sa.String(255), nullable=False),
        sa.Column("tool_name", sa.String(100), nullable=False),
        sa.Column("arguments_fingerprint", sa.String(64), nullable=False),
        sa.Column("proposal_evidence_id", sa.Uuid(), nullable=False),
        sa.Column("proposed_at", sa.DateTime(timezone=True), nullable=False),
        *_context_columns(),
        sa.CheckConstraint(
            "fencing_token > 0",
            name=op.f("ck_hermes_tool_proposals_fencing_token_positive"),
        ),
        sa.CheckConstraint(
            "length(arguments_fingerprint) = 64",
            name=op.f("ck_hermes_tool_proposals_arguments_fingerprint_length"),
        ),
        sa.UniqueConstraint(
            "run_id",
            "external_proposal_id",
            name=op.f("uq_hermes_tool_proposals_run_external"),
        ),
        sa.ForeignKeyConstraint(["run_id"], ["hermes_runs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["job_id"], ["background_jobs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["job_id", "lease_id", "fencing_token"],
            [
                "background_job_leases.job_id",
                "background_job_leases.id",
                "background_job_leases.fencing_token",
            ],
            name="fk_hermes_tool_proposals_lease",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["proposal_evidence_id"], ["evidence_records.id"], ondelete="RESTRICT"
        ),
    )
    op.create_table(
        "hermes_tool_decisions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("proposal_id", sa.Uuid(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "AUTHORIZED",
                "DENIED",
                name="hermes_tool_decision_status",
                native_enum=False,
                create_constraint=True,
                length=64,
            ),
            nullable=False,
        ),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("tool_grant_id", sa.Uuid(), nullable=False),
        sa.Column("brief_id", sa.Uuid()),
        sa.Column("repository_configuration_id", sa.Uuid()),
        sa.Column("policy_version_id", sa.Uuid(), nullable=False),
        sa.Column("decision_evidence_id", sa.Uuid(), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        *_context_columns(),
        sa.UniqueConstraint("proposal_id", name=op.f("uq_hermes_tool_decisions_proposal")),
        sa.ForeignKeyConstraint(["proposal_id"], ["hermes_tool_proposals.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["tool_grant_id"], ["background_job_tool_grants.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["brief_id"], ["briefs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["repository_configuration_id"],
            ["repository_configurations.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["policy_version_id"], ["policy_versions.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["decision_evidence_id"], ["evidence_records.id"], ondelete="RESTRICT"
        ),
    )
    op.create_table(
        "hermes_tool_results",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("proposal_id", sa.Uuid(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "SUCCEEDED",
                "REJECTED",
                "AMBIGUOUS",
                name="hermes_tool_result_status",
                native_enum=False,
                create_constraint=True,
                length=64,
            ),
            nullable=False,
        ),
        sa.Column("code", sa.String(100), nullable=False),
        sa.Column("repository_revision", sa.String(64)),
        sa.Column("result_evidence_id", sa.Uuid(), nullable=False),
        sa.Column("diff_evidence_id", sa.Uuid()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        *_context_columns(),
        sa.CheckConstraint("attempt > 0", name=op.f("ck_hermes_tool_results_attempt_positive")),
        sa.UniqueConstraint(
            "proposal_id",
            "attempt",
            name=op.f("uq_hermes_tool_results_proposal_attempt"),
        ),
        sa.ForeignKeyConstraint(["proposal_id"], ["hermes_tool_proposals.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["result_evidence_id"], ["evidence_records.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["diff_evidence_id"], ["evidence_records.id"], ondelete="RESTRICT"),
    )
    for table, label in (
        ("hermes_tool_proposals", "hermes_tool_proposals"),
        ("hermes_tool_decisions", "hermes_tool_decisions"),
        ("hermes_tool_results", "hermes_tool_results"),
    ):
        _append_only(table, label)


def downgrade() -> None:
    connection = op.get_bind()
    has_provenance = connection.execute(
        sa.text(
            "SELECT CASE WHEN EXISTS (SELECT 1 FROM hermes_tool_proposals) "
            "OR EXISTS (SELECT 1 FROM hermes_tool_decisions) "
            "OR EXISTS (SELECT 1 FROM hermes_tool_results) THEN 1 ELSE 0 END"
        )
    ).scalar_one()
    if has_provenance:
        raise RuntimeError("cannot downgrade while durable Hermes tool provenance exists")
    if connection.dialect.name == "postgresql":
        for label in (
            "hermes_tool_results",
            "hermes_tool_decisions",
            "hermes_tool_proposals",
        ):
            op.execute(sa.text(f"DROP TRIGGER {label}_append_only ON {label}"))
            op.execute(sa.text(f"DROP FUNCTION reject_{label}_mutation()"))
    else:
        for label in (
            "hermes_tool_results",
            "hermes_tool_decisions",
            "hermes_tool_proposals",
        ):
            op.execute(sa.text(f"DROP TRIGGER {label}_no_update"))
            op.execute(sa.text(f"DROP TRIGGER {label}_no_delete"))
    op.drop_table("hermes_tool_results")
    op.drop_table("hermes_tool_decisions")
    op.drop_table("hermes_tool_proposals")
