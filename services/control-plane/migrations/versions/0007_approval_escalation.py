"""Add durable approval and resumable-escalation identity.

Revision ID: 0007
Revises: 0006
Create Date: 2026-07-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ZERO_FINGERPRINT = "0" * 64
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


def _hex_only_sql(column: str) -> str:
    expression = column
    for character in "0123456789abcdef":
        expression = f"replace({expression}, '{character}', '')"
    return f"length({expression}) = 0"


def _create_sqlite_triggers() -> None:
    op.execute(
        """
        CREATE TRIGGER approval_requests_validate_insert
        BEFORE INSERT ON approval_requests
        BEGIN
            SELECT CASE WHEN
                (
                    NEW.status = 'PENDING'
                    AND (
                        NEW.decision IS NOT NULL
                        OR NEW.decision_id IS NOT NULL
                        OR NEW.decision_fingerprint IS NOT NULL
                        OR NEW.decided_by IS NOT NULL
                        OR NEW.decided_at IS NOT NULL
                    )
                )
                OR (
                    NEW.status <> 'PENDING'
                    AND (
                        NEW.decision IS NULL
                        OR NEW.decision_id IS NULL
                        OR NEW.decision_fingerprint IS NULL
                        OR NEW.decided_by IS NULL
                        OR NEW.decided_at IS NULL
                    )
                )
                OR (
                    NEW.request_type = 'BRIEF'
                    AND (
                        NEW.resume_state IS NOT NULL
                        OR NEW.blocked_operation IS NOT NULL
                    )
                )
                OR (
                    NEW.request_type <> 'BRIEF'
                    AND (
                        NEW.resume_state IS NULL
                        OR NEW.blocked_operation IS NULL
                    )
                )
            THEN RAISE(ABORT, 'invalid approval request projection') END;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER approval_requests_validate_update
        BEFORE UPDATE ON approval_requests
        BEGIN
            SELECT CASE WHEN
                NEW.id <> OLD.id
                OR NEW.task_id <> OLD.task_id
                OR NEW.request_type <> OLD.request_type
                OR NEW.subject_type IS NOT OLD.subject_type
                OR NEW.subject_id IS NOT OLD.subject_id
                OR NEW.reason <> OLD.reason
                OR NEW.options <> OLD.options
                OR NEW.supporting_evidence_ids <> OLD.supporting_evidence_ids
                OR NEW.requesting_state <> OLD.requesting_state
                OR NEW.expires_at IS NOT OLD.expires_at
                OR NEW.request_fingerprint <> OLD.request_fingerprint
                OR NEW.precondition_fingerprint <> OLD.precondition_fingerprint
                OR NEW.resume_state IS NOT OLD.resume_state
                OR NEW.blocked_operation IS NOT OLD.blocked_operation
                OR NEW.retry_history <> OLD.retry_history
                OR NEW.owner_id <> OLD.owner_id
                OR NEW.root_correlation_id <> OLD.root_correlation_id
                OR NEW.causation_id IS NOT OLD.causation_id
                OR NEW.parent_correlation_id IS NOT OLD.parent_correlation_id
                OR NEW.created_at <> OLD.created_at
                OR OLD.status <> 'PENDING'
                OR NEW.status = 'PENDING'
                OR NEW.decision IS NULL
                OR NEW.decision_id IS NULL
                OR NEW.decision_fingerprint IS NULL
                OR NEW.decided_by IS NULL
                OR NEW.decided_at IS NULL
            THEN RAISE(ABORT, 'invalid approval request update') END;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER approval_requests_no_delete
        BEFORE DELETE ON approval_requests
        BEGIN
            SELECT RAISE(ABORT, 'approval requests are append-only');
        END
        """
    )


def _create_postgresql_triggers() -> None:
    op.execute(
        """
        CREATE FUNCTION validate_approval_request()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF (
                (
                    NEW.status = 'PENDING'
                    AND (
                        NEW.decision IS NOT NULL
                        OR NEW.decision_id IS NOT NULL
                        OR NEW.decision_fingerprint IS NOT NULL
                        OR NEW.decided_by IS NOT NULL
                        OR NEW.decided_at IS NOT NULL
                    )
                )
                OR (
                    NEW.status <> 'PENDING'
                    AND (
                        NEW.decision IS NULL
                        OR NEW.decision_id IS NULL
                        OR NEW.decision_fingerprint IS NULL
                        OR NEW.decided_by IS NULL
                        OR NEW.decided_at IS NULL
                    )
                )
                OR (
                    NEW.request_type = 'BRIEF'
                    AND (
                        NEW.resume_state IS NOT NULL
                        OR NEW.blocked_operation IS NOT NULL
                    )
                )
                OR (
                    NEW.request_type <> 'BRIEF'
                    AND (
                        NEW.resume_state IS NULL
                        OR NEW.blocked_operation IS NULL
                    )
                )
            ) THEN
                RAISE EXCEPTION 'invalid approval request projection';
            END IF;
            IF TG_OP = 'UPDATE' AND (
                NEW.id IS DISTINCT FROM OLD.id
                OR NEW.task_id IS DISTINCT FROM OLD.task_id
                OR NEW.request_type IS DISTINCT FROM OLD.request_type
                OR NEW.subject_type IS DISTINCT FROM OLD.subject_type
                OR NEW.subject_id IS DISTINCT FROM OLD.subject_id
                OR NEW.reason IS DISTINCT FROM OLD.reason
                OR NEW.options::text IS DISTINCT FROM OLD.options::text
                OR NEW.supporting_evidence_ids::text
                    IS DISTINCT FROM OLD.supporting_evidence_ids::text
                OR NEW.requesting_state IS DISTINCT FROM OLD.requesting_state
                OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
                OR NEW.request_fingerprint
                    IS DISTINCT FROM OLD.request_fingerprint
                OR NEW.precondition_fingerprint
                    IS DISTINCT FROM OLD.precondition_fingerprint
                OR NEW.resume_state IS DISTINCT FROM OLD.resume_state
                OR NEW.blocked_operation::text
                    IS DISTINCT FROM OLD.blocked_operation::text
                OR NEW.retry_history::text IS DISTINCT FROM OLD.retry_history::text
                OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
                OR NEW.root_correlation_id IS DISTINCT FROM OLD.root_correlation_id
                OR NEW.causation_id IS DISTINCT FROM OLD.causation_id
                OR NEW.parent_correlation_id
                    IS DISTINCT FROM OLD.parent_correlation_id
                OR NEW.created_at IS DISTINCT FROM OLD.created_at
                OR OLD.status <> 'PENDING'
                OR NEW.status = 'PENDING'
                OR NEW.decision IS NULL
                OR NEW.decision_id IS NULL
                OR NEW.decision_fingerprint IS NULL
                OR NEW.decided_by IS NULL
                OR NEW.decided_at IS NULL
            ) THEN
                RAISE EXCEPTION 'invalid approval request update';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER approval_requests_validate_insert
        BEFORE INSERT ON approval_requests
        FOR EACH ROW EXECUTE FUNCTION validate_approval_request()
        """
    )
    op.execute(
        """
        CREATE TRIGGER approval_requests_validate_update
        BEFORE UPDATE ON approval_requests
        FOR EACH ROW EXECUTE FUNCTION validate_approval_request()
        """
    )
    op.execute(
        """
        CREATE FUNCTION reject_approval_request_delete()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'approval requests are append-only';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER approval_requests_no_delete
        BEFORE DELETE ON approval_requests
        FOR EACH ROW EXECUTE FUNCTION reject_approval_request_delete()
        """
    )


def _drop_triggers() -> None:
    dialect = op.get_bind().dialect.name
    for name in (
        "approval_requests_no_delete",
        "approval_requests_validate_update",
        "approval_requests_validate_insert",
    ):
        if dialect == "sqlite":
            op.execute(f"DROP TRIGGER IF EXISTS {name}")
        else:
            op.execute(
                f"DROP TRIGGER IF EXISTS {name} ON approval_requests"
            )
    if dialect != "sqlite":
        op.execute(
            "DROP FUNCTION IF EXISTS reject_approval_request_delete()"
        )
        op.execute("DROP FUNCTION IF EXISTS validate_approval_request()")


def upgrade() -> None:
    """Add bounded replay, decision, and escalation context to approvals."""

    with op.batch_alter_table("approval_requests") as batch_op:
        batch_op.add_column(
            sa.Column(
                "request_fingerprint",
                sa.String(length=64),
                server_default=_ZERO_FINGERPRINT,
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column(
                "precondition_fingerprint",
                sa.String(length=64),
                server_default=_ZERO_FINGERPRINT,
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column("resume_state", sa.String(length=32), nullable=True)
        )
        batch_op.add_column(
            sa.Column("blocked_operation", sa.JSON(), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "retry_history",
                sa.JSON(),
                server_default=sa.text("'[]'"),
                nullable=False,
            )
        )
        batch_op.add_column(sa.Column("decision_id", sa.Uuid(), nullable=True))
        batch_op.add_column(
            sa.Column(
                "decision_fingerprint",
                sa.String(length=64),
                nullable=True,
            )
        )
        batch_op.create_check_constraint(
            op.f("ck_approval_requests_approval_request_resume_state"),
            "resume_state IS NULL OR resume_state IN "
            f"({', '.join(repr(state) for state in _TASK_STATES)})",
        )
        batch_op.create_check_constraint(
            op.f("ck_approval_requests_request_fingerprint"),
            "length(request_fingerprint) = 64 AND "
            f"{_hex_only_sql('request_fingerprint')}",
        )
        batch_op.create_check_constraint(
            op.f("ck_approval_requests_precondition_fingerprint"),
            "length(precondition_fingerprint) = 64 AND "
            f"{_hex_only_sql('precondition_fingerprint')}",
        )
        batch_op.create_check_constraint(
            op.f("ck_approval_requests_decision_fingerprint"),
            "decision_fingerprint IS NULL OR ("
            "length(decision_fingerprint) = 64 AND "
            f"{_hex_only_sql('decision_fingerprint')}"
            ")",
        )
        batch_op.create_unique_constraint(
            op.f("uq_approval_requests_decision_id"),
            ["decision_id"],
        )
        batch_op.create_index(
            op.f("ix_approval_requests_task_status_expiry"),
            ["task_id", "status", "expires_at"],
            unique=False,
        )
    if op.get_bind().dialect.name == "sqlite":
        _create_sqlite_triggers()
    else:
        _create_postgresql_triggers()


def downgrade() -> None:
    """Remove approval extensions only when no durable provenance uses them."""

    if op.get_context().as_sql:
        raise RuntimeError(
            "Approval provenance requires an online guarded downgrade"
        )
    if op.get_bind().scalar(
        sa.text(
            "SELECT 1 FROM approval_requests "
            "WHERE request_fingerprint <> :zero "
            "OR precondition_fingerprint <> :zero "
            "OR resume_state IS NOT NULL "
            "OR blocked_operation IS NOT NULL "
            "OR CAST(retry_history AS TEXT) <> '[]' "
            "OR decision_id IS NOT NULL "
            "OR decision_fingerprint IS NOT NULL "
            "LIMIT 1"
        ),
        {"zero": _ZERO_FINGERPRINT},
    ):
        raise RuntimeError(
            "Cannot downgrade while durable approval provenance exists"
        )

    _drop_triggers()
    with op.batch_alter_table("approval_requests") as batch_op:
        batch_op.drop_index(
            op.f("ix_approval_requests_task_status_expiry")
        )
        batch_op.drop_constraint(
            op.f("uq_approval_requests_decision_id"),
            type_="unique",
        )
        batch_op.drop_constraint(
            op.f("ck_approval_requests_approval_request_resume_state"),
            type_="check",
        )
        batch_op.drop_constraint(
            op.f("ck_approval_requests_decision_fingerprint"),
            type_="check",
        )
        batch_op.drop_constraint(
            op.f("ck_approval_requests_precondition_fingerprint"),
            type_="check",
        )
        batch_op.drop_constraint(
            op.f("ck_approval_requests_request_fingerprint"),
            type_="check",
        )
        batch_op.drop_column("decision_fingerprint")
        batch_op.drop_column("decision_id")
        batch_op.drop_column("retry_history")
        batch_op.drop_column("blocked_operation")
        batch_op.drop_column("resume_state")
        batch_op.drop_column("precondition_fingerprint")
        batch_op.drop_column("request_fingerprint")
