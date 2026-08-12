"""Add immutable controlled policy activation audit records.

Revision ID: 0015
Revises: 0014
Create Date: 2026-08-11
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
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


def _create_append_only_guards() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            sa.text(
                "CREATE FUNCTION policy_activations_append_only_guard() "
                "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
                "RAISE EXCEPTION 'policy activations are append-only'; "
                "RETURN NULL; END; $$"
            )
        )
        op.execute(
            sa.text(
                "CREATE TRIGGER policy_activations_append_only "
                "BEFORE UPDATE OR DELETE ON policy_activations "
                "FOR EACH ROW EXECUTE FUNCTION policy_activations_append_only_guard()"
            )
        )
        return
    op.execute(
        sa.text(
            "CREATE TRIGGER policy_activations_no_update "
            "BEFORE UPDATE ON policy_activations BEGIN "
            "SELECT RAISE(ABORT, 'policy activations are append-only'); END"
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER policy_activations_no_delete "
            "BEFORE DELETE ON policy_activations BEGIN "
            "SELECT RAISE(ABORT, 'policy activations are append-only'); END"
        )
    )


def upgrade() -> None:
    op.create_table(
        "policy_activations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("policy_version_id", sa.Uuid(), nullable=False),
        sa.Column("source_policy_version_id", sa.Uuid(), nullable=False),
        sa.Column("rollback_policy_version_id", sa.Uuid(), nullable=False),
        sa.Column("activation_kind", sa.String(64), nullable=False),
        sa.Column("subject_type", sa.String(100), nullable=False),
        sa.Column("subject_id", sa.Uuid(), nullable=False),
        sa.Column("subject_version", sa.Integer()),
        sa.Column("subject_fingerprint", sa.String(64), nullable=False),
        sa.Column("evaluation_contract_version_id", sa.Uuid()),
        sa.Column("threshold_evidence", sa.JSON(), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("regression_reviewed", sa.Boolean(), nullable=False),
        sa.Column("approved_by", sa.String(255), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activation_fingerprint", sa.String(64), nullable=False),
        *_context_columns(),
        sa.CheckConstraint(
            "source_policy_version_id <> policy_version_id",
            name=op.f("ck_policy_activations_source_not_active"),
        ),
        sa.CheckConstraint(
            "rollback_policy_version_id <> policy_version_id",
            name=op.f("ck_policy_activations_rollback_not_active"),
        ),
        sa.CheckConstraint(
            "subject_version IS NULL OR subject_version > 0",
            name=op.f("ck_policy_activations_subject_version_positive"),
        ),
        sa.CheckConstraint(
            "regression_reviewed = true",
            name=op.f("ck_policy_activations_regression_review_required"),
        ),
        sa.CheckConstraint(
            "length(subject_fingerprint) = 64",
            name=op.f("ck_policy_activations_subject_fingerprint_length"),
        ),
        sa.CheckConstraint(
            "length(activation_fingerprint) = 64",
            name=op.f("ck_policy_activations_activation_fingerprint_length"),
        ),
        sa.CheckConstraint(
            "activation_kind IN ('PROMPT_PROMOTION', 'RULE_PROMOTION', 'ROLLBACK')",
            name=op.f("ck_policy_activations_policy_activation_kind"),
        ),
        sa.ForeignKeyConstraint(["policy_version_id"], ["policy_versions.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["source_policy_version_id"], ["policy_versions.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["rollback_policy_version_id"], ["policy_versions.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["evaluation_contract_version_id"],
            ["evaluation_contract_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_policy_activations")),
        sa.UniqueConstraint("policy_version_id", name=op.f("uq_policy_activation_version")),
    )
    _create_append_only_guards()


def downgrade() -> None:
    """Remove activation structures only before they contain audit provenance."""

    if op.get_context().as_sql:
        raise RuntimeError("Policy activation provenance requires an online guarded downgrade")
    if op.get_bind().scalar(sa.text("SELECT 1 FROM policy_activations LIMIT 1")):
        raise RuntimeError("Cannot downgrade while policy activation provenance exists")
    op.drop_table("policy_activations")
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text("DROP FUNCTION policy_activations_append_only_guard()"))
