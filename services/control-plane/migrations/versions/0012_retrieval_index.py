"""Add disposable retrieval-index generations and lexical projections.

Revision ID: 0012
Revises: 0011
Create Date: 2026-08-11
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


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


def upgrade() -> None:
    op.create_table(
        "retrieval_index_generations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("index_version", sa.String(length=100), nullable=False),
        sa.Column("chunker_version", sa.String(length=100), nullable=False),
        sa.Column("verifier_version", sa.String(length=100), nullable=False),
        sa.Column("indexed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_count", sa.Integer(), nullable=False),
        sa.Column("chunk_count", sa.Integer(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        *_context_columns(),
        sa.CheckConstraint(
            "source_count >= 0",
            name=op.f("ck_retrieval_index_generations_source_count_non_negative"),
        ),
        sa.CheckConstraint(
            "chunk_count >= 0",
            name=op.f("ck_retrieval_index_generations_chunk_count_non_negative"),
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["tasks.id"],
            name=op.f("fk_retrieval_index_generations_task_id_tasks"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_retrieval_index_generations")),
        sa.UniqueConstraint(
            "id",
            "task_id",
            name=op.f("uq_retrieval_generations_id_task"),
        ),
    )
    op.create_index(
        "uq_retrieval_generations_active_task",
        "retrieval_index_generations",
        ["task_id"],
        unique=True,
        sqlite_where=sa.text("deleted_at IS NULL"),
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_table(
        "retrieval_index_chunks",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("generation_id", sa.Uuid(), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("derivative_id", sa.Uuid(), nullable=False),
        sa.Column("projection_class", sa.String(length=64), nullable=False),
        sa.Column("access_classification", sa.String(length=100), nullable=False),
        sa.Column("source_hash", sa.String(length=80), nullable=False),
        sa.Column("source_envelope_hash", sa.String(length=80), nullable=False),
        sa.Column("chunk_hash", sa.String(length=80), nullable=False),
        sa.Column("index_version", sa.String(length=100), nullable=False),
        sa.Column("chunker_version", sa.String(length=100), nullable=False),
        sa.Column("verifier_version", sa.String(length=100), nullable=False),
        sa.Column("source_captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("indexed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("start_offset", sa.Integer(), nullable=False),
        sa.Column("end_offset", sa.Integer(), nullable=False),
        sa.Column("lexical_term_frequencies", sa.JSON(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        *_context_columns(),
        sa.CheckConstraint("ordinal > 0", name=op.f("ck_retrieval_index_chunks_ordinal_positive")),
        sa.CheckConstraint(
            "start_offset >= 0",
            name=op.f("ck_retrieval_index_chunks_start_offset_non_negative"),
        ),
        sa.CheckConstraint(
            "end_offset > start_offset",
            name=op.f("ck_retrieval_index_chunks_span_positive"),
        ),
        sa.ForeignKeyConstraint(
            ["derivative_id"],
            ["evidence_derivatives.id"],
            name=op.f("fk_retrieval_index_chunks_derivative_id_evidence_derivatives"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence_records.id"],
            name=op.f("fk_retrieval_index_chunks_evidence_id_evidence_records"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["generation_id", "task_id"],
            ["retrieval_index_generations.id", "retrieval_index_generations.task_id"],
            name=op.f(
                "fk_retrieval_index_chunks_generation_id_task_id_retrieval_index_generations"
            ),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_retrieval_index_chunks")),
        sa.UniqueConstraint("derivative_id", name=op.f("uq_retrieval_chunks_derivative")),
        sa.UniqueConstraint(
            "generation_id",
            "evidence_id",
            "ordinal",
            name=op.f("uq_retrieval_chunks_source_ordinal"),
        ),
    )
    op.create_index(
        "ix_retrieval_chunks_evidence",
        "retrieval_index_chunks",
        ["evidence_id"],
        unique=False,
    )
    op.create_index(
        "ix_retrieval_chunks_generation_live",
        "retrieval_index_chunks",
        ["generation_id", "deleted_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_retrieval_chunks_generation_live",
        table_name="retrieval_index_chunks",
    )
    op.drop_index("ix_retrieval_chunks_evidence", table_name="retrieval_index_chunks")
    op.drop_table("retrieval_index_chunks")
    op.drop_index(
        "uq_retrieval_generations_active_task",
        table_name="retrieval_index_generations",
    )
    op.drop_table("retrieval_index_generations")
