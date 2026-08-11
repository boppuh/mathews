"""Add multi-source lineage for candidate-learning derivatives.

Revision ID: 0014
Revises: 0013
Create Date: 2026-08-11
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
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


def upgrade() -> None:
    op.create_table(
        "evidence_derivative_citations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("derivative_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("source_hash", sa.String(71), nullable=False),
        *_context_columns(),
        sa.CheckConstraint(
            "length(source_hash) = 71",
            name=op.f("ck_evidence_derivative_citations_source_hash_length"),
        ),
        sa.ForeignKeyConstraint(
            ["derivative_id"],
            ["evidence_derivatives.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence_records.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_evidence_derivative_citations")),
        sa.UniqueConstraint(
            "derivative_id",
            "evidence_id",
            name=op.f("uq_evidence_derivative_citation_source"),
        ),
    )
    op.create_table(
        "rule_candidate_citations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("candidate_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("source_hash", sa.String(71), nullable=False),
        *_context_columns(),
        sa.CheckConstraint(
            "length(source_hash) = 71",
            name=op.f("ck_rule_candidate_citations_source_hash_length"),
        ),
        sa.ForeignKeyConstraint(
            ["candidate_id"],
            ["rule_candidates.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence_records.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_rule_candidate_citations")),
        sa.UniqueConstraint(
            "candidate_id",
            "evidence_id",
            name=op.f("uq_rule_candidate_citation_source"),
        ),
    )


def downgrade() -> None:
    op.drop_table("rule_candidate_citations")
    op.drop_table("evidence_derivative_citations")
