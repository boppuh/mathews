"""Persist run-level validation assertion results.

Revision ID: 0011
Revises: 0010
Create Date: 2026-08-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "validation_runs",
        sa.Column(
            "assertion_results",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
    )
def downgrade() -> None:
    op.drop_column("validation_runs", "assertion_results")
