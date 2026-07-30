"""Add audited task-transition integrity and idempotency.

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-30
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_POLICY_TABLES = (
    "policy_versions",
    "policy_version_review_rules",
    "policy_version_prompt_templates",
    "review_rules",
    "prompt_template_versions",
)


def _hex_only_sql(column: str) -> str:
    expression = column
    for character in "0123456789abcdef":
        expression = f"replace({expression}, '{character}', '')"
    return f"length({expression}) = 0"


_LIFECYCLE_PROJECTION_SQL = (
    "("
    "NEW.state = 'ESCALATED' AND NEW.escalation_resume_state IS NOT NULL "
    "AND NEW.escalation_resume_state NOT IN "
    "('ESCALATED', 'HANDED_OFF', 'FAILED', 'CANCELLED') "
    "AND NEW.terminal_outcome IS NULL"
    ") OR ("
    "NEW.state = 'HANDED_OFF' AND NEW.escalation_resume_state IS NULL "
    "AND NEW.terminal_outcome = 'AUTOMATION_HANDED_OFF'"
    ") OR ("
    "NEW.state = 'FAILED' AND NEW.escalation_resume_state IS NULL "
    "AND NEW.terminal_outcome = 'FAILED'"
    ") OR ("
    "NEW.state = 'CANCELLED' AND NEW.escalation_resume_state IS NULL "
    "AND NEW.terminal_outcome = 'CANCELLED'"
    ") OR ("
    "NEW.state NOT IN ('ESCALATED', 'HANDED_OFF', 'FAILED', 'CANCELLED') "
    "AND NEW.escalation_resume_state IS NULL AND NEW.terminal_outcome IS NULL"
    ")"
)

_LEGAL_LIFECYCLE_EDGE_SQL = (
    "("
    "OLD.state NOT IN ('HANDED_OFF', 'FAILED', 'CANCELLED') "
    "AND NEW.state IN ('FAILED', 'CANCELLED')"
    ") OR ("
    "OLD.state NOT IN ('ESCALATED', 'HANDED_OFF', 'FAILED', 'CANCELLED') "
    "AND NEW.state = 'ESCALATED' "
    "AND NEW.escalation_resume_state = OLD.state"
    ") OR ("
    "OLD.state = 'ESCALATED' "
    "AND NEW.state = OLD.escalation_resume_state"
    ") OR ("
    "OLD.state NOT IN ('ESCALATED', 'HANDED_OFF', 'FAILED', 'CANCELLED') "
    "AND NEW.state = 'BRIEFING'"
    ") OR ("
    "OLD.state = 'BRIEFING' AND NEW.state IN "
    "('BRIEF_PENDING_APPROVAL', 'IMPLEMENTING')"
    ") OR ("
    "OLD.state = 'BRIEF_PENDING_APPROVAL' "
    "AND NEW.state IN ('BRIEFING', 'IMPLEMENTING')"
    ") OR ("
    "OLD.state = 'IMPLEMENTING' AND NEW.state = 'VALIDATING'"
    ") OR ("
    "OLD.state IN ('VALIDATING', 'PR_ACTIVE') AND NEW.state = 'REPAIRING'"
    ") OR ("
    "OLD.state = 'REPAIRING' AND NEW.state = 'VALIDATING'"
    ") OR ("
    "OLD.state = 'VALIDATING' AND NEW.state = 'PR_ACTIVE'"
    ") OR ("
    "OLD.state = 'PR_ACTIVE' AND NEW.state = 'READY_FOR_HUMAN_MERGE'"
    ") OR ("
    "OLD.state = 'READY_FOR_HUMAN_MERGE' "
    "AND NEW.state IN ('PR_ACTIVE', 'HANDED_OFF')"
    ")"
)

_TRANSITION_EVENT_EDGE_SQL = (
    "("
    "event.transition_kind = 'START_BRIEFING' "
    "AND OLD.state = 'INTAKE' AND NEW.state = 'BRIEFING'"
    ") OR ("
    "event.transition_kind = 'AUTO_ACCEPT_BRIEF' "
    "AND OLD.state = 'BRIEFING' AND NEW.state = 'IMPLEMENTING'"
    ") OR ("
    "event.transition_kind = 'REQUEST_BRIEF_APPROVAL' "
    "AND OLD.state = 'BRIEFING' AND NEW.state = 'BRIEF_PENDING_APPROVAL'"
    ") OR ("
    "event.transition_kind = 'REVISE_BRIEF' "
    "AND OLD.state = 'BRIEF_PENDING_APPROVAL' AND NEW.state = 'BRIEFING'"
    ") OR ("
    "event.transition_kind = 'APPROVE_EXACT_BRIEF' "
    "AND OLD.state = 'BRIEF_PENDING_APPROVAL' AND NEW.state = 'IMPLEMENTING'"
    ") OR ("
    "event.transition_kind = 'BEGIN_VALIDATION' "
    "AND OLD.state = 'IMPLEMENTING' AND NEW.state = 'VALIDATING'"
    ") OR ("
    "event.transition_kind = 'BEGIN_REPAIR' "
    "AND OLD.state IN ('VALIDATING', 'PR_ACTIVE') AND NEW.state = 'REPAIRING'"
    ") OR ("
    "event.transition_kind = 'REVALIDATE' "
    "AND OLD.state = 'REPAIRING' AND NEW.state = 'VALIDATING'"
    ") OR ("
    "event.transition_kind = 'OPEN_VERIFIED_DRAFT_PR' "
    "AND OLD.state = 'VALIDATING' AND NEW.state = 'PR_ACTIVE'"
    ") OR ("
    "event.transition_kind = 'MARK_MERGE_READY' "
    "AND OLD.state = 'PR_ACTIVE' AND NEW.state = 'READY_FOR_HUMAN_MERGE'"
    ") OR ("
    "event.transition_kind = 'INVALIDATE_READINESS' "
    "AND OLD.state = 'READY_FOR_HUMAN_MERGE' AND NEW.state = 'PR_ACTIVE'"
    ") OR ("
    "event.transition_kind = 'ACKNOWLEDGE_HANDOFF' "
    "AND OLD.state = 'READY_FOR_HUMAN_MERGE' AND NEW.state = 'HANDED_OFF'"
    ") OR ("
    "event.transition_kind = 'ESCALATE' "
    "AND OLD.state NOT IN ('ESCALATED', 'HANDED_OFF', 'FAILED', 'CANCELLED') "
    "AND NEW.state = 'ESCALATED' "
    "AND NEW.escalation_resume_state = OLD.state"
    ") OR ("
    "event.transition_kind = 'RESUME' "
    "AND OLD.state = 'ESCALATED' "
    "AND NEW.state = OLD.escalation_resume_state"
    ") OR ("
    "event.transition_kind = 'CANCEL' "
    "AND OLD.state NOT IN ('HANDED_OFF', 'FAILED', 'CANCELLED') "
    "AND NEW.state = 'CANCELLED'"
    ") OR ("
    "event.transition_kind = 'FAIL' "
    "AND OLD.state NOT IN ('HANDED_OFF', 'FAILED', 'CANCELLED') "
    "AND NEW.state = 'FAILED'"
    ") OR ("
    "event.transition_kind = 'SCOPE_STEER' "
    "AND OLD.state NOT IN ('ESCALATED', 'HANDED_OFF', 'FAILED', 'CANCELLED') "
    "AND NEW.state = 'BRIEFING'"
    ")"
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


def _create_integrity_triggers() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(
            sa.text(
                "CREATE FUNCTION reject_task_audit_mutation() "
                "RETURNS trigger LANGUAGE plpgsql AS $$ "
                "BEGIN RAISE EXCEPTION 'task audit records are append-only'; "
                "RETURN NULL; END; $$"
            )
        )
        for table_name in ("task_events", "task_event_evidence_references", *_POLICY_TABLES):
            op.execute(
                sa.text(
                    f"CREATE TRIGGER {table_name}_append_only "
                    f"BEFORE UPDATE OR DELETE ON {table_name} "
                    "FOR EACH ROW EXECUTE FUNCTION reject_task_audit_mutation()"
                )
            )
        op.execute(
            sa.text(
                "CREATE FUNCTION enforce_unsealed_policy_membership() "
                "RETURNS trigger LANGUAGE plpgsql AS $$ "
                "BEGIN "
                "PERFORM 1 FROM policy_versions policy "
                "WHERE policy.id = NEW.policy_version_id FOR UPDATE; "
                "IF EXISTS ("
                "SELECT 1 FROM task_events event "
                "WHERE event.policy_version_id = NEW.policy_version_id"
                ") THEN "
                "RAISE EXCEPTION 'audited policy version membership is sealed'; "
                "END IF; "
                "RETURN NEW; "
                "END; $$"
            )
        )
        for table_name in (
            "policy_version_review_rules",
            "policy_version_prompt_templates",
        ):
            op.execute(
                sa.text(
                    f"CREATE TRIGGER {table_name}_sealed_insert "
                    f"BEFORE INSERT ON {table_name} "
                    "FOR EACH ROW EXECUTE FUNCTION "
                    "enforce_unsealed_policy_membership()"
                )
            )
        op.execute(
            sa.text(
                "CREATE FUNCTION enforce_audited_task_lifecycle() "
                "RETURNS trigger LANGUAGE plpgsql AS $$ "
                "BEGIN "
                "IF TG_OP = 'DELETE' THEN "
                "RAISE EXCEPTION 'tasks cannot be deleted'; "
                "END IF; "
                "IF TG_OP = 'INSERT' THEN "
                "IF NEW.state <> 'INTAKE' "
                "OR NEW.escalation_resume_state IS NOT NULL "
                "OR NEW.terminal_outcome IS NOT NULL THEN "
                "RAISE EXCEPTION 'tasks must begin in INTAKE'; "
                "END IF; "
                "RETURN NEW; "
                "END IF; "
                f"IF NOT ({_LIFECYCLE_PROJECTION_SQL}) THEN "
                "RAISE EXCEPTION 'invalid task lifecycle projection'; "
                "END IF; "
                "IF OLD.state IS DISTINCT FROM NEW.state "
                "OR OLD.escalation_resume_state IS DISTINCT FROM "
                "NEW.escalation_resume_state "
                "OR OLD.terminal_outcome IS DISTINCT FROM NEW.terminal_outcome THEN "
                f"IF NOT ({_LEGAL_LIFECYCLE_EDGE_SQL}) THEN "
                "RAISE EXCEPTION 'illegal task lifecycle edge'; "
                "END IF; "
                "IF NOT EXISTS ("
                "SELECT 1 FROM task_events event "
                "WHERE event.task_id = NEW.id "
                "AND event.event_type = 'TASK_STATE_TRANSITION' "
                "AND event.sequence = ("
                "SELECT max(latest.sequence) FROM task_events latest "
                "WHERE latest.task_id = NEW.id"
                ") "
                "AND event.transition_from_state = OLD.state "
                "AND event.transition_to_state = NEW.state "
                f"AND ({_TRANSITION_EVENT_EDGE_SQL}) "
                "AND EXISTS ("
                "SELECT 1 FROM policy_versions policy "
                "WHERE policy.id = event.policy_version_id "
                "AND policy.lineage_key = event.policy_lineage_key "
                "AND policy.owner_id = NEW.owner_id "
                "AND policy.approved_at <= event.occurred_at "
                "AND policy.version = ("
                "SELECT max(active_policy.version) "
                "FROM policy_versions active_policy "
                "WHERE active_policy.lineage_key = event.policy_lineage_key "
                "AND active_policy.owner_id = NEW.owner_id "
                "AND active_policy.approved_at <= event.occurred_at"
                ")"
                ") "
                "AND EXISTS ("
                "SELECT 1 FROM task_event_evidence_references evidence_ref "
                "WHERE evidence_ref.task_event_id = event.id"
                ") "
                "AND NOT EXISTS ("
                "SELECT 1 FROM task_event_evidence_references evidence_ref "
                "JOIN evidence_records evidence "
                "ON evidence.id = evidence_ref.evidence_id "
                "WHERE evidence_ref.task_event_id = event.id "
                "AND (evidence.task_id <> NEW.id "
                "OR evidence.owner_id <> NEW.owner_id "
                "OR evidence.root_correlation_id <> NEW.root_correlation_id "
                "OR evidence.deleted_at IS NOT NULL "
                "OR EXISTS ("
                "SELECT 1 FROM evidence_deletion_requests deletion_request "
                "WHERE deletion_request.evidence_id = evidence.id"
                ") OR EXISTS ("
                "SELECT 1 FROM evidence_records correction "
                "WHERE correction.correction_of_id = evidence.id"
                "))"
                ")"
                ") THEN "
                "RAISE EXCEPTION 'task lifecycle change lacks matching audit'; "
                "END IF; "
                "END IF; "
                "RETURN NEW; "
                "END; $$"
            )
        )
        op.execute(
            sa.text(
                "CREATE TRIGGER tasks_audited_lifecycle "
                "BEFORE INSERT OR UPDATE OR DELETE ON tasks "
                "FOR EACH ROW EXECUTE FUNCTION enforce_audited_task_lifecycle()"
            )
        )
        op.execute(
            sa.text(
                "CREATE FUNCTION enforce_task_event_evidence_same_task() "
                "RETURNS trigger LANGUAGE plpgsql AS $$ "
                "BEGIN "
                "IF NOT EXISTS ("
                "SELECT 1 FROM evidence_records evidence "
                "WHERE evidence.id = NEW.evidence_id "
                "AND evidence.task_id = NEW.task_id"
                ") THEN "
                "RAISE EXCEPTION 'transition evidence must belong to task'; "
                "END IF; "
                "RETURN NEW; "
                "END; $$"
            )
        )
        op.execute(
            sa.text(
                "CREATE TRIGGER task_event_evidence_same_task "
                "BEFORE INSERT ON task_event_evidence_references "
                "FOR EACH ROW EXECUTE FUNCTION "
                "enforce_task_event_evidence_same_task()"
            )
        )
        return
    if dialect == "sqlite":
        for table_name in ("task_events", "task_event_evidence_references", *_POLICY_TABLES):
            op.execute(
                sa.text(
                    f"CREATE TRIGGER {table_name}_no_update "
                    f"BEFORE UPDATE ON {table_name} BEGIN "
                    "SELECT RAISE(ABORT, 'task audit records are append-only'); END"
                )
            )
            op.execute(
                sa.text(
                    f"CREATE TRIGGER {table_name}_no_delete "
                    f"BEFORE DELETE ON {table_name} BEGIN "
                    "SELECT RAISE(ABORT, 'task audit records are append-only'); END"
                )
            )
        for table_name in (
            "policy_version_review_rules",
            "policy_version_prompt_templates",
        ):
            op.execute(
                sa.text(
                    f"CREATE TRIGGER {table_name}_sealed_insert "
                    f"BEFORE INSERT ON {table_name} WHEN EXISTS ("
                    "SELECT 1 FROM task_events event "
                    "WHERE event.policy_version_id = NEW.policy_version_id"
                    ") BEGIN SELECT RAISE(ABORT, "
                    "'audited policy version membership is sealed'); END"
                )
            )
        op.execute(
            sa.text(
                "CREATE TRIGGER tasks_intake_insert "
                "BEFORE INSERT ON tasks WHEN "
                "NEW.state <> 'INTAKE' "
                "OR NEW.escalation_resume_state IS NOT NULL "
                "OR NEW.terminal_outcome IS NOT NULL "
                "BEGIN SELECT RAISE(ABORT, 'tasks must begin in INTAKE'); END"
            )
        )
        op.execute(
            sa.text(
                "CREATE TRIGGER tasks_lifecycle_projection "
                "BEFORE UPDATE OF state, escalation_resume_state, terminal_outcome "
                f"ON tasks WHEN NOT ({_LIFECYCLE_PROJECTION_SQL}) "
                "BEGIN SELECT RAISE(ABORT, "
                "'invalid task lifecycle projection'); END"
            )
        )
        op.execute(
            sa.text(
                "CREATE TRIGGER tasks_legal_lifecycle_edge "
                "BEFORE UPDATE OF state, escalation_resume_state, terminal_outcome "
                "ON tasks WHEN NOT ("
                "OLD.state IS NEW.state "
                "AND OLD.escalation_resume_state IS NEW.escalation_resume_state "
                "AND OLD.terminal_outcome IS NEW.terminal_outcome"
                f") AND NOT ({_LEGAL_LIFECYCLE_EDGE_SQL}) "
                "BEGIN SELECT RAISE(ABORT, "
                "'illegal task lifecycle edge'); END"
            )
        )
        op.execute(
            sa.text(
                "CREATE TRIGGER tasks_audited_lifecycle "
                "BEFORE UPDATE OF state, escalation_resume_state, terminal_outcome "
                "ON tasks WHEN NOT ("
                "OLD.state IS NEW.state "
                "AND OLD.escalation_resume_state IS NEW.escalation_resume_state "
                "AND OLD.terminal_outcome IS NEW.terminal_outcome"
                ") AND NOT EXISTS ("
                "SELECT 1 FROM task_events event "
                "WHERE event.task_id = NEW.id "
                "AND event.event_type = 'TASK_STATE_TRANSITION' "
                "AND event.sequence = ("
                "SELECT max(latest.sequence) FROM task_events latest "
                "WHERE latest.task_id = NEW.id"
                ") "
                "AND event.transition_from_state = OLD.state "
                "AND event.transition_to_state = NEW.state "
                f"AND ({_TRANSITION_EVENT_EDGE_SQL}) "
                "AND EXISTS ("
                "SELECT 1 FROM policy_versions policy "
                "WHERE policy.id = event.policy_version_id "
                "AND policy.lineage_key = event.policy_lineage_key "
                "AND policy.owner_id = NEW.owner_id "
                "AND policy.approved_at <= event.occurred_at "
                "AND policy.version = ("
                "SELECT max(active_policy.version) "
                "FROM policy_versions active_policy "
                "WHERE active_policy.lineage_key = event.policy_lineage_key "
                "AND active_policy.owner_id = NEW.owner_id "
                "AND active_policy.approved_at <= event.occurred_at"
                ")"
                ") "
                "AND EXISTS ("
                "SELECT 1 FROM task_event_evidence_references evidence_ref "
                "WHERE evidence_ref.task_event_id = event.id"
                ") "
                "AND NOT EXISTS ("
                "SELECT 1 FROM task_event_evidence_references evidence_ref "
                "JOIN evidence_records evidence "
                "ON evidence.id = evidence_ref.evidence_id "
                "WHERE evidence_ref.task_event_id = event.id "
                "AND (evidence.task_id <> NEW.id "
                "OR evidence.owner_id <> NEW.owner_id "
                "OR evidence.root_correlation_id <> NEW.root_correlation_id "
                "OR evidence.deleted_at IS NOT NULL "
                "OR EXISTS ("
                "SELECT 1 FROM evidence_deletion_requests deletion_request "
                "WHERE deletion_request.evidence_id = evidence.id"
                ") OR EXISTS ("
                "SELECT 1 FROM evidence_records correction "
                "WHERE correction.correction_of_id = evidence.id"
                "))"
                ")"
                ") BEGIN "
                "SELECT RAISE(ABORT, "
                "'task lifecycle change lacks matching audit'); END"
            )
        )
        op.execute(
            sa.text(
                "CREATE TRIGGER tasks_no_delete BEFORE DELETE ON tasks BEGIN "
                "SELECT RAISE(ABORT, 'tasks cannot be deleted'); END"
            )
        )
        op.execute(
            sa.text(
                "CREATE TRIGGER task_event_evidence_same_task "
                "BEFORE INSERT ON task_event_evidence_references "
                "WHEN NOT EXISTS ("
                "SELECT 1 FROM evidence_records evidence "
                "WHERE evidence.id = NEW.evidence_id "
                "AND evidence.task_id = NEW.task_id"
                ") BEGIN SELECT RAISE(ABORT, "
                "'transition evidence must belong to task'); END"
            )
        )


def _drop_integrity_triggers() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(
            sa.text(
                "DROP TRIGGER task_event_evidence_same_task "
                "ON task_event_evidence_references"
            )
        )
        op.execute(sa.text("DROP FUNCTION enforce_task_event_evidence_same_task()"))
        op.execute(sa.text("DROP TRIGGER tasks_audited_lifecycle ON tasks"))
        op.execute(sa.text("DROP FUNCTION enforce_audited_task_lifecycle()"))
        for table_name in (
            "policy_version_review_rules",
            "policy_version_prompt_templates",
        ):
            op.execute(
                sa.text(
                    f"DROP TRIGGER {table_name}_sealed_insert ON {table_name}"
                )
            )
        op.execute(sa.text("DROP FUNCTION enforce_unsealed_policy_membership()"))
        for table_name in ("task_events", "task_event_evidence_references", *_POLICY_TABLES):
            op.execute(
                sa.text(f"DROP TRIGGER {table_name}_append_only ON {table_name}")
            )
        op.execute(sa.text("DROP FUNCTION reject_task_audit_mutation()"))
        return
    if dialect == "sqlite":
        op.execute(sa.text("DROP TRIGGER task_event_evidence_same_task"))
        op.execute(sa.text("DROP TRIGGER tasks_no_delete"))
        op.execute(sa.text("DROP TRIGGER tasks_audited_lifecycle"))
        op.execute(sa.text("DROP TRIGGER tasks_legal_lifecycle_edge"))
        op.execute(sa.text("DROP TRIGGER tasks_lifecycle_projection"))
        op.execute(sa.text("DROP TRIGGER tasks_intake_insert"))
        for table_name in (
            "policy_version_review_rules",
            "policy_version_prompt_templates",
        ):
            op.execute(sa.text(f"DROP TRIGGER {table_name}_sealed_insert"))
        for table_name in ("task_events", "task_event_evidence_references", *_POLICY_TABLES):
            op.execute(sa.text(f"DROP TRIGGER {table_name}_no_delete"))
            op.execute(sa.text(f"DROP TRIGGER {table_name}_no_update"))


def upgrade() -> None:
    """Install typed transition provenance and database backstops."""

    # Legacy generic events may contain unrestricted prose or identities. They
    # cannot satisfy a transition guard and must be scrubbed before append-only
    # protection is installed.
    op.execute(
        sa.text(
            "UPDATE task_events SET "
            "event_type = 'LEGACY_EVENT_FENCED', "
            "payload = '{\"legacy_event_fenced\"\\:true}', "
            "owner_id = 'local-user', actor_id = 'legacy-fenced'"
        )
    )
    # Bring every existing task into the explicit lifecycle projection before
    # the mutation guards are enabled.
    op.execute(
        sa.text(
            "UPDATE tasks SET "
            "escalation_resume_state = CASE "
            "WHEN state = 'ESCALATED' AND escalation_resume_state NOT IN "
            "('ESCALATED', 'HANDED_OFF', 'FAILED', 'CANCELLED') "
            "THEN escalation_resume_state "
            "WHEN state = 'ESCALATED' THEN 'INTAKE' "
            "ELSE NULL END, "
            "terminal_outcome = CASE "
            "WHEN state = 'HANDED_OFF' THEN 'AUTOMATION_HANDED_OFF' "
            "WHEN state = 'FAILED' THEN 'FAILED' "
            "WHEN state = 'CANCELLED' THEN 'CANCELLED' "
            "ELSE NULL END"
        )
    )

    with op.batch_alter_table("task_events") as batch_op:
        batch_op.drop_constraint(
            op.f("fk_task_events_task_id_tasks"),
            type_="foreignkey",
        )
        batch_op.add_column(sa.Column("transition_id", sa.Uuid(), nullable=True))
        batch_op.add_column(
            sa.Column("transition_fingerprint", sa.String(length=64), nullable=True)
        )
        batch_op.add_column(
            sa.Column("transition_kind", sa.String(length=64), nullable=True)
        )
        batch_op.add_column(
            sa.Column("transition_from_state", sa.String(length=32), nullable=True)
        )
        batch_op.add_column(
            sa.Column("transition_to_state", sa.String(length=32), nullable=True)
        )
        batch_op.add_column(
            sa.Column("transition_reason_code", sa.String(length=100), nullable=True)
        )
        batch_op.add_column(
            sa.Column("policy_lineage_key", sa.String(length=255), nullable=True)
        )
        batch_op.add_column(sa.Column("policy_version_id", sa.Uuid(), nullable=True))
        batch_op.add_column(
            sa.Column("gate_head_sha", sa.String(length=64), nullable=True)
        )
        batch_op.create_unique_constraint(
            op.f("uq_task_events_task_id"),
            ["task_id", "id"],
        )
        batch_op.create_unique_constraint(
            op.f("uq_task_events_transition_id"),
            ["transition_id"],
        )
        batch_op.create_check_constraint(
            op.f("ck_task_events_transition_shape"),
            "("
            "event_type = 'TASK_STATE_TRANSITION' "
            "AND transition_id IS NOT NULL "
            "AND transition_fingerprint IS NOT NULL "
            "AND transition_kind IS NOT NULL "
            "AND transition_from_state IS NOT NULL "
            "AND transition_to_state IS NOT NULL "
            "AND transition_reason_code IS NOT NULL "
            "AND policy_lineage_key IS NOT NULL "
            "AND policy_version_id IS NOT NULL"
            ") OR ("
            "event_type <> 'TASK_STATE_TRANSITION' "
            "AND transition_id IS NULL "
            "AND transition_fingerprint IS NULL "
            "AND transition_kind IS NULL "
            "AND transition_from_state IS NULL "
            "AND transition_to_state IS NULL "
            "AND transition_reason_code IS NULL "
            "AND policy_lineage_key IS NULL "
            "AND policy_version_id IS NULL "
            "AND gate_head_sha IS NULL"
            ")",
        )
        batch_op.create_check_constraint(
            op.f("ck_task_events_transition_kind"),
            "transition_kind IS NULL OR transition_kind IN ("
            "'START_BRIEFING', 'AUTO_ACCEPT_BRIEF', 'REQUEST_BRIEF_APPROVAL', "
            "'REVISE_BRIEF', 'APPROVE_EXACT_BRIEF', 'BEGIN_VALIDATION', "
            "'BEGIN_REPAIR', 'REVALIDATE', 'OPEN_VERIFIED_DRAFT_PR', "
            "'MARK_MERGE_READY', 'INVALIDATE_READINESS', 'ACKNOWLEDGE_HANDOFF', "
            "'ESCALATE', 'RESUME', 'CANCEL', 'FAIL', 'SCOPE_STEER'"
            ")",
        )
        batch_op.create_check_constraint(
            op.f("ck_task_events_transition_gate_head_shape"),
            "("
            "transition_kind IN ("
            "'OPEN_VERIFIED_DRAFT_PR', 'MARK_MERGE_READY', 'ACKNOWLEDGE_HANDOFF'"
            ") AND gate_head_sha IS NOT NULL"
            ") OR ("
            "transition_kind NOT IN ("
            "'OPEN_VERIFIED_DRAFT_PR', 'MARK_MERGE_READY', 'ACKNOWLEDGE_HANDOFF'"
            ") AND gate_head_sha IS NULL"
            ") OR transition_kind IS NULL",
        )
        batch_op.create_check_constraint(
            op.f("ck_task_events_transition_fingerprint_length"),
            "transition_fingerprint IS NULL OR length(transition_fingerprint) = 64",
        )
        batch_op.create_check_constraint(
            op.f("ck_task_events_gate_head_sha_length"),
            "gate_head_sha IS NULL OR ("
            "length(gate_head_sha) IN (40, 64) AND "
            f"{_hex_only_sql('gate_head_sha')}"
            ")",
        )
        batch_op.create_foreign_key(
            op.f("fk_task_events_task_id_tasks"),
            "tasks",
            ["task_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch_op.create_foreign_key(
            op.f("fk_task_events_policy_lineage_key_policy_versions"),
            "policy_versions",
            ["policy_lineage_key", "policy_version_id"],
            ["lineage_key", "id"],
            ondelete="RESTRICT",
        )

    op.create_table(
        "task_event_evidence_references",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("task_event_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        *_context_columns(),
        sa.CheckConstraint(
            "position > 0",
            name=op.f("ck_task_event_evidence_references_position_positive"),
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence_records.id"],
            name=op.f(
                "fk_task_event_evidence_references_evidence_id_evidence_records"
            ),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["task_id", "task_event_id"],
            ["task_events.task_id", "task_events.id"],
            name=op.f(
                "fk_task_event_evidence_references_task_id_task_events"
            ),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f("pk_task_event_evidence_references"),
        ),
        sa.UniqueConstraint(
            "task_event_id",
            "evidence_id",
            name=op.f("uq_task_event_evidence_membership"),
        ),
        sa.UniqueConstraint(
            "task_event_id",
            "position",
            name=op.f("uq_task_event_evidence_position"),
        ),
    )
    _create_integrity_triggers()


def downgrade() -> None:
    """Remove transition integrity while preserving compatible task data."""

    if op.get_context().as_sql:
        raise RuntimeError(
            "Task transition provenance requires an online guarded downgrade"
        )
    if op.get_bind().scalar(
        sa.text(
            "SELECT 1 FROM task_events "
            "WHERE event_type = 'TASK_STATE_TRANSITION' LIMIT 1"
        )
    ):
        raise RuntimeError(
            "Cannot downgrade while audited task transitions exist"
        )

    _drop_integrity_triggers()
    op.drop_table("task_event_evidence_references")

    with op.batch_alter_table("task_events") as batch_op:
        batch_op.drop_constraint(
            op.f("fk_task_events_policy_lineage_key_policy_versions"),
            type_="foreignkey",
        )
        batch_op.drop_constraint(
            op.f("fk_task_events_task_id_tasks"),
            type_="foreignkey",
        )
        batch_op.drop_constraint(
            op.f("ck_task_events_gate_head_sha_length"),
            type_="check",
        )
        batch_op.drop_constraint(
            op.f("ck_task_events_transition_fingerprint_length"),
            type_="check",
        )
        batch_op.drop_constraint(
            op.f("ck_task_events_transition_shape"),
            type_="check",
        )
        batch_op.drop_constraint(
            op.f("ck_task_events_transition_gate_head_shape"),
            type_="check",
        )
        batch_op.drop_constraint(
            op.f("ck_task_events_transition_kind"),
            type_="check",
        )
        batch_op.drop_constraint(
            op.f("uq_task_events_transition_id"),
            type_="unique",
        )
        batch_op.drop_constraint(
            op.f("uq_task_events_task_id"),
            type_="unique",
        )
        batch_op.drop_column("gate_head_sha")
        batch_op.drop_column("policy_version_id")
        batch_op.drop_column("policy_lineage_key")
        batch_op.drop_column("transition_reason_code")
        batch_op.drop_column("transition_to_state")
        batch_op.drop_column("transition_from_state")
        batch_op.drop_column("transition_fingerprint")
        batch_op.drop_column("transition_kind")
        batch_op.drop_column("transition_id")
        batch_op.create_foreign_key(
            op.f("fk_task_events_task_id_tasks"),
            "tasks",
            ["task_id"],
            ["id"],
            ondelete="CASCADE",
        )
