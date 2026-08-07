"""Add durable lease-fenced Hermes runs and deliveries.

Revision ID: 0009
Revises: 0008
Create Date: 2026-08-07
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
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


def _create_event_immutability_trigger() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            sa.text(
                "CREATE FUNCTION reject_hermes_event_mutation() "
                "RETURNS trigger LANGUAGE plpgsql AS $$ "
                "BEGIN RAISE EXCEPTION 'Hermes run events are append-only'; "
                "RETURN NULL; END; $$"
            )
        )
        op.execute(
            sa.text(
                "CREATE TRIGGER hermes_run_events_append_only "
                "BEFORE UPDATE OR DELETE ON hermes_run_events "
                "FOR EACH ROW EXECUTE FUNCTION reject_hermes_event_mutation()"
            )
        )
        return
    op.execute(
        sa.text(
            "CREATE TRIGGER hermes_run_events_no_update "
            "BEFORE UPDATE ON hermes_run_events BEGIN "
            "SELECT RAISE(ABORT, 'Hermes run events are append-only'); END"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER hermes_run_events_no_delete "
            "BEFORE DELETE ON hermes_run_events BEGIN "
            "SELECT RAISE(ABORT, 'Hermes run events are append-only'); END"
        )
    )


def upgrade() -> None:
    op.create_table(
        "hermes_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("lease_id", sa.Uuid(), nullable=False),
        sa.Column("fencing_token", sa.BigInteger(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("external_run_id", sa.String(255)),
        sa.Column("prompt_template_version_id", sa.Uuid(), nullable=False),
        sa.Column("policy_version_id", sa.Uuid(), nullable=False),
        sa.Column("evaluation_label", sa.String(255)),
        sa.Column("prompt_fingerprint", sa.String(64), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "STARTING",
                "RUNNING",
                "SUCCEEDED",
                "FAILED",
                "CANCELLED",
                "TIMED_OUT",
                name="hermes_run_status",
                native_enum=False,
                create_constraint=True,
                length=64,
            ),
            server_default="STARTING",
            nullable=False,
        ),
        sa.Column("last_event_sequence", sa.Integer(), server_default="0", nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_event_at", sa.DateTime(timezone=True)),
        sa.Column("cancellation_requested_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("failure_code", sa.String(100)),
        *_context_columns(),
        sa.CheckConstraint("attempt > 0", name=op.f("ck_hermes_runs_attempt_positive")),
        sa.CheckConstraint("fencing_token > 0", name=op.f("ck_hermes_runs_fencing_token_positive")),
        sa.CheckConstraint(
            "last_event_sequence >= 0",
            name=op.f("ck_hermes_runs_event_sequence_non_negative"),
        ),
        sa.CheckConstraint(
            "length(prompt_fingerprint) = 64",
            name=op.f("ck_hermes_runs_prompt_fingerprint_length"),
        ),
        sa.UniqueConstraint("job_id", "attempt", name=op.f("uq_hermes_runs_job_attempt")),
        sa.UniqueConstraint("external_run_id", name=op.f("uq_hermes_runs_external_run")),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["job_id"], ["background_jobs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["job_id", "lease_id", "fencing_token"],
            [
                "background_job_leases.job_id",
                "background_job_leases.id",
                "background_job_leases.fencing_token",
            ],
            name="fk_hermes_runs_lease",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["prompt_template_version_id"],
            ["prompt_template_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["policy_version_id"], ["policy_versions.id"], ondelete="RESTRICT"),
    )
    op.create_table(
        "hermes_run_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("provider_event_id", sa.String(255), nullable=False),
        sa.Column("provider_sequence", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("payload_fingerprint", sa.String(64), nullable=False),
        sa.Column("payload_evidence_id", sa.Uuid(), nullable=False),
        sa.Column("accepted", sa.Boolean(), nullable=False),
        sa.Column("ignored_reason", sa.String(100)),
        sa.Column("task_event_id", sa.Uuid()),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        *_context_columns(),
        sa.CheckConstraint(
            "provider_sequence > 0",
            name=op.f("ck_hermes_run_events_provider_sequence_positive"),
        ),
        sa.CheckConstraint(
            "length(payload_fingerprint) = 64",
            name=op.f("ck_hermes_run_events_payload_fingerprint_length"),
        ),
        sa.CheckConstraint(
            "(accepted = true AND ignored_reason IS NULL AND task_event_id IS NOT NULL) OR "
            "(accepted = false AND ignored_reason IS NOT NULL AND task_event_id IS NULL)",
            name=op.f("ck_hermes_run_events_acceptance_shape"),
        ),
        sa.UniqueConstraint(
            "run_id", "provider_event_id", name=op.f("uq_hermes_run_events_delivery")
        ),
        sa.UniqueConstraint(
            "run_id", "provider_sequence", name=op.f("uq_hermes_run_events_sequence")
        ),
        sa.ForeignKeyConstraint(["run_id"], ["hermes_runs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["payload_evidence_id"], ["evidence_records.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["task_event_id"], ["task_events.id"], ondelete="RESTRICT"),
    )
    _create_event_immutability_trigger()


def downgrade() -> None:
    connection = op.get_bind()
    has_provenance = connection.execute(
        sa.text(
            "SELECT CASE WHEN EXISTS (SELECT 1 FROM hermes_runs) "
            "OR EXISTS (SELECT 1 FROM hermes_run_events) THEN 1 ELSE 0 END"
        )
    ).scalar_one()
    if has_provenance:
        raise RuntimeError(
            "cannot downgrade while durable Hermes run provenance exists"
        )
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text("DROP TRIGGER hermes_run_events_append_only ON hermes_run_events"))
        op.execute(sa.text("DROP FUNCTION reject_hermes_event_mutation()"))
    op.drop_table("hermes_run_events")
    op.drop_table("hermes_runs")
