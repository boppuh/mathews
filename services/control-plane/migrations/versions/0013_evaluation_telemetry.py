"""Add version-bound agent-run evaluation telemetry.

Revision ID: 0013
Revises: 0012
Create Date: 2026-08-11
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
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


def upgrade() -> None:
    op.create_table(
        "evaluation_contract_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("lineage_key", sa.String(255), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("predecessor_id", sa.Uuid()),
        sa.Column("promotion_thresholds", sa.JSON(), nullable=False),
        sa.Column("regression_cases", sa.JSON(), nullable=False),
        sa.Column("contract_fingerprint", sa.String(64), nullable=False),
        sa.Column("active", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True)),
        *_context_columns(),
        sa.CheckConstraint(
            "version > 0", name=op.f("ck_evaluation_contract_versions_version_positive")
        ),
        sa.CheckConstraint(
            "predecessor_id IS NULL OR predecessor_id <> id",
            name=op.f("ck_evaluation_contract_versions_predecessor_not_self"),
        ),
        sa.CheckConstraint(
            "active = false OR activated_at IS NOT NULL",
            name=op.f("ck_evaluation_contract_versions_active_requires_timestamp"),
        ),
        sa.CheckConstraint(
            "length(contract_fingerprint) = 64",
            name=op.f("ck_evaluation_contract_versions_fingerprint_length"),
        ),
        sa.ForeignKeyConstraint(
            ["lineage_key", "predecessor_id"],
            ["evaluation_contract_versions.lineage_key", "evaluation_contract_versions.id"],
            name=op.f(
                "fk_evaluation_contract_versions_lineage_key_predecessor_id_evaluation_contract_versions"
            ),
            ondelete="RESTRICT",
            use_alter=True,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_evaluation_contract_versions")),
        sa.UniqueConstraint(
            "lineage_key", "version", name=op.f("uq_evaluation_contract_lineage_version")
        ),
        sa.UniqueConstraint("lineage_key", "id", name=op.f("uq_evaluation_contract_lineage_id")),
    )
    op.create_index(
        "uq_evaluation_contract_active_lineage",
        "evaluation_contract_versions",
        ["lineage_key"],
        unique=True,
        sqlite_where=sa.text("active = true"),
        postgresql_where=sa.text("active = true"),
    )
    op.create_table(
        "agent_run_evaluations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("evaluation_contract_version_id", sa.Uuid(), nullable=False),
        sa.Column("retrieval_generation_id", sa.Uuid(), nullable=False),
        sa.Column("retrieval_index_version", sa.String(100), nullable=False),
        sa.Column("retrieval_chunker_version", sa.String(100), nullable=False),
        sa.Column("retrieval_verifier_version", sa.String(100), nullable=False),
        sa.Column("retrieval_set", sa.JSON(), nullable=False),
        sa.Column("prompt_template_version_id", sa.Uuid(), nullable=False),
        sa.Column("prompt_template_version", sa.Integer(), nullable=False),
        sa.Column("policy_version_id", sa.Uuid(), nullable=False),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("model_provider", sa.String(100), nullable=False),
        sa.Column("model_name", sa.String(255), nullable=False),
        sa.Column("model_version", sa.String(255), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=False),
        sa.Column("output_tokens", sa.Integer(), nullable=False),
        sa.Column("cached_tokens", sa.Integer(), nullable=False),
        sa.Column("total_tokens", sa.Integer(), nullable=False),
        sa.Column("cost_microusd", sa.BigInteger(), nullable=False),
        sa.Column("quality_outcome", sa.String(32), nullable=False),
        sa.Column("quality_score", sa.Float(), nullable=False),
        sa.Column("regression_results", sa.JSON(), nullable=False),
        sa.Column("evaluation_fingerprint", sa.String(64), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        *_context_columns(),
        sa.CheckConstraint(
            "input_tokens >= 0", name=op.f("ck_agent_run_evaluations_input_tokens_non_negative")
        ),
        sa.CheckConstraint(
            "output_tokens >= 0", name=op.f("ck_agent_run_evaluations_output_tokens_non_negative")
        ),
        sa.CheckConstraint(
            "cached_tokens >= 0", name=op.f("ck_agent_run_evaluations_cached_tokens_non_negative")
        ),
        sa.CheckConstraint(
            "cached_tokens <= input_tokens",
            name=op.f("ck_agent_run_evaluations_cached_tokens_bounded"),
        ),
        sa.CheckConstraint(
            "total_tokens >= 0", name=op.f("ck_agent_run_evaluations_total_tokens_non_negative")
        ),
        sa.CheckConstraint(
            "total_tokens = input_tokens + output_tokens",
            name=op.f("ck_agent_run_evaluations_total_tokens_consistent"),
        ),
        sa.CheckConstraint(
            "cost_microusd >= 0", name=op.f("ck_agent_run_evaluations_cost_non_negative")
        ),
        sa.CheckConstraint(
            "quality_score >= 0 AND quality_score <= 1",
            name=op.f("ck_agent_run_evaluations_quality_score_bounded"),
        ),
        sa.CheckConstraint(
            "length(evaluation_fingerprint) = 64",
            name=op.f("ck_agent_run_evaluations_fingerprint_length"),
        ),
        sa.ForeignKeyConstraint(["run_id"], ["hermes_runs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["evaluation_contract_version_id"],
            ["evaluation_contract_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["retrieval_generation_id"], ["retrieval_index_generations.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["prompt_template_version_id"], ["prompt_template_versions.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["policy_version_id"], ["policy_versions.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_run_evaluations")),
        sa.UniqueConstraint("run_id", name=op.f("uq_agent_run_evaluations_run")),
    )


def downgrade() -> None:
    op.drop_table("agent_run_evaluations")
    op.drop_index(
        "uq_evaluation_contract_active_lineage", table_name="evaluation_contract_versions"
    )
    op.drop_table("evaluation_contract_versions")
