"""Add durable cancellation, outage, and restart-recovery records.

Revision ID: 0008
Revises: 0007
Create Date: 2026-07-30
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _hex_only_sql(column: str) -> str:
    expression = column
    for character in "0123456789abcdef":
        expression = f"replace({expression}, '{character}', '')"
    return f"length({expression}) = 0"


def _context_columns() -> tuple[sa.Column[Any], ...]:
    return (
        sa.Column("owner_id", sa.String(length=255), nullable=False),
        sa.Column("actor_id", sa.String(length=255), nullable=False),
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


def _replace_sqlite_background_job_guard(
    *,
    allow_cancellation: bool,
) -> None:
    queued_cancellation = (
        """
                OR (
                    OLD.status = 'QUEUED'
                    AND OLD.current_lease_id IS NULL
                    AND NEW.status = 'CANCELLED'
                    AND NEW.attempt_count = OLD.attempt_count
                    AND NEW.current_lease_id IS NULL
                    AND NEW.cancellation_requested_at IS NOT NULL
                    AND NEW.last_fencing_token IS OLD.last_fencing_token
                )
        """
        if allow_cancellation
        else ""
    )
    cancelled_lease_guard = (
        "NEW.cancellation_requested_at IS NOT NULL"
        if allow_cancellation
        else "julianday(lease.expires_at) > julianday('now')"
    )
    expired_recovery = (
        """
                              OR (
                                  NEW.status = 'QUEUED'
                                  AND lease.release_reason = 'EXPIRED'
                                  AND julianday(lease.expires_at)
                                      <= julianday('now')
                                  AND NEW.cancellation_requested_at IS NULL
                              )
        """
        if allow_cancellation
        else ""
    )
    op.execute("DROP TRIGGER IF EXISTS background_jobs_validate_update")
    op.execute(
        f"""
        CREATE TRIGGER background_jobs_validate_update
        BEFORE UPDATE ON background_jobs
        BEGIN
            SELECT CASE WHEN
                NEW.id <> OLD.id
                OR NEW.task_id IS NOT OLD.task_id
                OR NEW.job_type <> OLD.job_type
                OR NEW.idempotency_key <> OLD.idempotency_key
                OR NEW.input_payload <> OLD.input_payload
                OR NEW.input_fingerprint <> OLD.input_fingerprint
                OR NEW.max_attempts <> OLD.max_attempts
                OR NEW.retry_base_seconds <> OLD.retry_base_seconds
                OR NEW.retry_max_seconds <> OLD.retry_max_seconds
                OR NEW.owner_id <> OLD.owner_id
                OR NEW.root_correlation_id <> OLD.root_correlation_id
            THEN RAISE(ABORT, 'background job identity is immutable') END;
            SELECT CASE WHEN
                NEW.attempt_count < 0
                OR NEW.attempt_count > NEW.max_attempts
                OR NEW.checkpoint_version < OLD.checkpoint_version
                OR (
                    (NEW.current_lease_id IS NULL
                     AND NEW.current_fencing_token IS NULL
                     AND NEW.lease_owner IS NULL
                     AND NEW.lease_expires_at IS NULL)
                    = 0
                    AND
                    (NEW.current_lease_id IS NOT NULL
                     AND NEW.current_fencing_token IS NOT NULL
                     AND NEW.lease_owner IS NOT NULL
                     AND NEW.lease_expires_at IS NOT NULL)
                    = 0
                )
                OR (
                    NEW.status = 'QUEUED'
                    AND (
                        NEW.current_lease_id IS NOT NULL
                        OR NEW.completed_at IS NOT NULL
                    )
                )
                OR (
                    NEW.status = 'RUNNING'
                    AND (
                        NEW.current_lease_id IS NULL
                        OR NEW.completed_at IS NOT NULL
                    )
                )
                OR (
                    NEW.status IN ('SUCCEEDED', 'FAILED', 'CANCELLED')
                    AND (
                        NEW.current_lease_id IS NOT NULL
                        OR NEW.completed_at IS NULL
                    )
                )
            THEN RAISE(ABORT, 'invalid background job projection') END;
            SELECT CASE WHEN NEW.current_lease_id IS NOT NULL AND NOT EXISTS (
                SELECT 1
                FROM background_job_leases AS lease
                WHERE lease.job_id = NEW.id
                  AND lease.id = NEW.current_lease_id
                  AND lease.fencing_token = NEW.current_fencing_token
                  AND lease.lease_owner = NEW.lease_owner
                  AND lease.expires_at = NEW.lease_expires_at
                  AND lease.released_at IS NULL
            ) THEN RAISE(ABORT, 'background job lease projection is invalid') END;
            SELECT CASE WHEN NOT (
                (
                    OLD.status = 'QUEUED'
                    AND OLD.current_lease_id IS NULL
                    AND NEW.status = 'RUNNING'
                    AND NEW.attempt_count = OLD.attempt_count + 1
                    AND NEW.last_fencing_token = NEW.current_fencing_token
                )
                {queued_cancellation}
                OR (
                    OLD.status = 'RUNNING'
                    AND OLD.current_lease_id IS NOT NULL
                    AND julianday(OLD.lease_expires_at) <= julianday('now')
                    AND NEW.status = 'RUNNING'
                    AND NEW.attempt_count = OLD.attempt_count + 1
                    AND NEW.current_fencing_token > OLD.current_fencing_token
                    AND NEW.last_fencing_token = NEW.current_fencing_token
                )
                OR (
                    OLD.status = 'RUNNING'
                    AND OLD.current_lease_id IS NOT NULL
                    AND NEW.attempt_count = OLD.attempt_count
                    AND NEW.last_fencing_token = OLD.current_fencing_token
                    AND EXISTS (
                        SELECT 1
                        FROM background_job_leases AS lease
                        WHERE lease.job_id = OLD.id
                          AND lease.id = OLD.current_lease_id
                          AND lease.fencing_token = OLD.current_fencing_token
                          AND (
                              (
                                  NEW.status = 'RUNNING'
                                  AND NEW.current_lease_id = OLD.current_lease_id
                                  AND lease.released_at IS NULL
                                  AND julianday(lease.expires_at) > julianday('now')
                              )
                              OR (
                                  NEW.status = 'QUEUED'
                                  AND lease.release_reason = 'RETRY'
                                  AND julianday(lease.expires_at) > julianday('now')
                              )
                              {expired_recovery}
                              OR (
                                  NEW.status = 'SUCCEEDED'
                                  AND lease.release_reason = 'SUCCEEDED'
                                  AND julianday(lease.expires_at) > julianday('now')
                              )
                              OR (
                                  NEW.status = 'FAILED'
                                  AND (
                                      (
                                          lease.release_reason = 'FAILED'
                                          AND julianday(lease.expires_at)
                                              > julianday('now')
                                      )
                                      OR (
                                          lease.release_reason = 'EXPIRED'
                                          AND julianday(lease.expires_at)
                                              <= julianday('now')
                                      )
                                  )
                              )
                              OR (
                                  NEW.status = 'CANCELLED'
                                  AND lease.release_reason = 'CANCELLED'
                                  AND {cancelled_lease_guard}
                              )
                          )
                    )
                )
            ) THEN RAISE(ABORT, 'background job mutation is not fenced') END;
        END
        """
    )


def _replace_postgresql_background_job_guard(
    *,
    allow_cancellation: bool,
) -> None:
    queued_cancellation = (
        """
                OR
                (OLD.status = 'QUEUED' AND OLD.current_lease_id IS NULL
                 AND NEW.status = 'CANCELLED'
                 AND NEW.attempt_count = OLD.attempt_count
                 AND NEW.current_lease_id IS NULL
                 AND NEW.cancellation_requested_at IS NOT NULL
                 AND NEW.last_fencing_token IS NOT DISTINCT FROM OLD.last_fencing_token)
        """
        if allow_cancellation
        else ""
    )
    cancelled_lease_guard = (
        "NEW.cancellation_requested_at IS NOT NULL"
        if allow_cancellation
        else "lease.expires_at > clock_timestamp()"
    )
    expired_recovery = (
        """
                           OR
                           (NEW.status = 'QUEUED'
                            AND lease.release_reason = 'EXPIRED'
                            AND lease.expires_at <= clock_timestamp()
                            AND NEW.cancellation_requested_at IS NULL)
        """
        if allow_cancellation
        else ""
    )
    op.execute(
        f"""
        CREATE OR REPLACE FUNCTION enforce_background_job_write()
        RETURNS trigger AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'background jobs cannot be deleted';
            END IF;
            IF NEW.max_attempts NOT BETWEEN 1 AND 100
               OR NEW.attempt_count < 0
               OR NEW.attempt_count > NEW.max_attempts
               OR NEW.retry_base_seconds <= 0
               OR NEW.retry_max_seconds < NEW.retry_base_seconds
               OR NEW.checkpoint_version < 0
               OR NEW.input_fingerprint !~ '^[0-9a-f]{{64}}$' THEN
                RAISE EXCEPTION 'invalid background job projection';
            END IF;
            IF (NEW.current_lease_id IS NULL)
               <> (NEW.current_fencing_token IS NULL)
               OR (NEW.current_lease_id IS NULL) <> (NEW.lease_owner IS NULL)
               OR (NEW.current_lease_id IS NULL) <> (NEW.lease_expires_at IS NULL) THEN
                RAISE EXCEPTION 'invalid background job lease projection';
            END IF;
            IF (NEW.status = 'QUEUED'
                AND (NEW.current_lease_id IS NOT NULL OR NEW.completed_at IS NOT NULL))
               OR (NEW.status = 'RUNNING'
                   AND (NEW.current_lease_id IS NULL OR NEW.completed_at IS NOT NULL))
               OR (NEW.status IN ('SUCCEEDED', 'FAILED', 'CANCELLED')
                   AND (NEW.current_lease_id IS NOT NULL OR NEW.completed_at IS NULL)) THEN
                RAISE EXCEPTION 'invalid background job projection';
            END IF;
            IF TG_OP = 'INSERT' THEN
                RETURN NEW;
            END IF;
            IF NEW.checkpoint_version < OLD.checkpoint_version THEN
                RAISE EXCEPTION 'invalid background job projection';
            END IF;
            IF NEW.id <> OLD.id
               OR NEW.task_id IS DISTINCT FROM OLD.task_id
               OR NEW.job_type <> OLD.job_type
               OR NEW.idempotency_key <> OLD.idempotency_key
               OR NEW.input_payload::jsonb
                  IS DISTINCT FROM OLD.input_payload::jsonb
               OR NEW.input_fingerprint <> OLD.input_fingerprint
               OR NEW.max_attempts <> OLD.max_attempts
               OR NEW.retry_base_seconds <> OLD.retry_base_seconds
               OR NEW.retry_max_seconds <> OLD.retry_max_seconds
               OR NEW.owner_id <> OLD.owner_id
               OR NEW.root_correlation_id <> OLD.root_correlation_id THEN
                RAISE EXCEPTION 'background job identity is immutable';
            END IF;
            IF NEW.current_lease_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM background_job_leases lease
                WHERE lease.job_id = NEW.id
                  AND lease.id = NEW.current_lease_id
                  AND lease.fencing_token = NEW.current_fencing_token
                  AND lease.lease_owner = NEW.lease_owner
                  AND lease.expires_at = NEW.lease_expires_at
                  AND lease.released_at IS NULL
            ) THEN
                RAISE EXCEPTION 'background job lease projection is invalid';
            END IF;
            IF NOT (
                (OLD.status = 'QUEUED' AND OLD.current_lease_id IS NULL
                 AND NEW.status = 'RUNNING'
                 AND NEW.attempt_count = OLD.attempt_count + 1
                 AND NEW.last_fencing_token = NEW.current_fencing_token)
                {queued_cancellation}
                OR
                (OLD.status = 'RUNNING' AND OLD.current_lease_id IS NOT NULL
                 AND OLD.lease_expires_at <= clock_timestamp()
                 AND NEW.status = 'RUNNING'
                 AND NEW.attempt_count = OLD.attempt_count + 1
                 AND NEW.current_fencing_token > OLD.current_fencing_token
                 AND NEW.last_fencing_token = NEW.current_fencing_token)
                OR
                (OLD.status = 'RUNNING' AND OLD.current_lease_id IS NOT NULL
                 AND NEW.attempt_count = OLD.attempt_count
                 AND NEW.last_fencing_token = OLD.current_fencing_token
                 AND EXISTS (
                     SELECT 1
                     FROM background_job_leases lease
                     WHERE lease.job_id = OLD.id
                       AND lease.id = OLD.current_lease_id
                       AND lease.fencing_token = OLD.current_fencing_token
                       AND (
                           (NEW.status = 'RUNNING'
                            AND NEW.current_lease_id = OLD.current_lease_id
                            AND lease.released_at IS NULL
                            AND lease.expires_at > clock_timestamp())
                           OR
                           (NEW.status = 'QUEUED'
                            AND lease.release_reason = 'RETRY'
                            AND lease.expires_at > clock_timestamp())
                           {expired_recovery}
                           OR
                           (NEW.status = 'SUCCEEDED'
                            AND lease.release_reason = 'SUCCEEDED'
                            AND lease.expires_at > clock_timestamp())
                           OR
                           (NEW.status = 'FAILED'
                            AND (
                                (lease.release_reason = 'FAILED'
                                 AND lease.expires_at > clock_timestamp())
                                OR
                                (lease.release_reason = 'EXPIRED'
                                 AND lease.expires_at <= clock_timestamp())
                            ))
                           OR
                           (NEW.status = 'CANCELLED'
                            AND lease.release_reason = 'CANCELLED'
                            AND {cancelled_lease_guard})
                       )
                 ))
            ) THEN
                RAISE EXCEPTION 'background job mutation is not fenced';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )


def _replace_background_job_guard(*, allow_cancellation: bool) -> None:
    if op.get_bind().dialect.name == "sqlite":
        _replace_sqlite_background_job_guard(
            allow_cancellation=allow_cancellation
        )
    else:
        _replace_postgresql_background_job_guard(
            allow_cancellation=allow_cancellation
        )


def _create_sqlite_reliability_guards() -> None:
    for table in (
        "background_job_tool_grants",
        "owned_host_processes",
    ):
        op.execute(
            f"""
            CREATE TRIGGER {table}_validate_insert
            BEFORE INSERT ON {table}
            BEGIN
                SELECT CASE WHEN NOT EXISTS (
                    SELECT 1
                    FROM background_jobs AS job
                    JOIN background_job_leases AS lease
                      ON lease.id = NEW.lease_id
                     AND lease.job_id = NEW.job_id
                     AND lease.fencing_token = NEW.fencing_token
                    WHERE job.id = NEW.job_id
                      AND job.status = 'RUNNING'
                      AND job.current_lease_id = NEW.lease_id
                      AND job.current_fencing_token = NEW.fencing_token
                      AND job.cancellation_requested_at IS NULL
                      AND lease.released_at IS NULL
                      AND job.owner_id = NEW.owner_id
                      AND job.root_correlation_id
                          = NEW.root_correlation_id
                ) THEN RAISE(
                    ABORT,
                    'reliability record is not currently fenced'
                ) END;
            END
            """
        )
    op.execute(
        """
        CREATE TRIGGER background_job_ignored_results_validate_insert
        BEFORE INSERT ON background_job_ignored_results
        BEGIN
            SELECT CASE WHEN NOT EXISTS (
                SELECT 1
                FROM background_jobs AS job
                JOIN background_job_leases AS lease
                  ON lease.id = NEW.lease_id
                 AND lease.job_id = NEW.job_id
                 AND lease.fencing_token = NEW.fencing_token
                JOIN evidence_records AS evidence
                  ON evidence.id = NEW.evidence_id
                 AND evidence.task_id = job.task_id
                WHERE job.id = NEW.job_id
                  AND (
                      job.cancellation_requested_at IS NOT NULL
                      OR job.status <> 'RUNNING'
                      OR job.current_lease_id <> NEW.lease_id
                      OR job.current_fencing_token <> NEW.fencing_token
                      OR lease.released_at IS NOT NULL
                  )
            ) THEN RAISE(
                ABORT,
                'ignored result is not historically fenced'
            ) END;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER dependency_outage_attempts_validate_insert
        BEFORE INSERT ON dependency_outage_attempts
        BEGIN
            SELECT CASE WHEN NOT EXISTS (
                SELECT 1
                FROM background_jobs AS job
                JOIN background_job_leases AS lease
                  ON lease.id = NEW.lease_id
                 AND lease.job_id = NEW.job_id
                 AND lease.fencing_token = NEW.fencing_token
                JOIN evidence_records AS evidence
                  ON evidence.id = NEW.checkpoint_evidence_id
                 AND evidence.task_id = job.task_id
                WHERE job.id = NEW.job_id
                  AND lease.attempt = NEW.attempt
                  AND lease.failure_code = NEW.error_code
                  AND lease.release_reason IN ('RETRY', 'FAILED')
                  AND (
                      (
                          NEW.exhausted = false
                          AND lease.release_reason = 'RETRY'
                          AND job.status = 'QUEUED'
                      )
                      OR (
                          NEW.exhausted = true
                          AND lease.release_reason = 'FAILED'
                          AND job.status = 'FAILED'
                      )
                  )
            ) THEN RAISE(
                ABORT,
                'outage attempt is not fenced'
            ) END;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER task_cancellations_validate_insert
        BEFORE INSERT ON task_cancellations
        BEGIN
            SELECT CASE WHEN NOT EXISTS (
                SELECT 1
                FROM tasks AS task
                JOIN task_events AS event
                  ON event.id = NEW.transition_event_id
                 AND event.task_id = NEW.task_id
                 AND event.transition_id = NEW.id
                JOIN evidence_records AS evidence
                  ON evidence.id = NEW.partial_evidence_id
                 AND evidence.task_id = NEW.task_id
                WHERE task.id = NEW.task_id
                  AND event.transition_kind IN ('CANCEL', 'FAIL')
                  AND event.transition_to_state = task.state
                  AND task.state IN ('CANCELLED', 'FAILED')
            ) THEN RAISE(
                ABORT,
                'terminal work fence lacks transition provenance'
            ) END;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER reconciliation_targets_validate_insert
        BEFORE INSERT ON reconciliation_targets
        BEGIN
            SELECT CASE WHEN
                NEW.job_id IS NOT NULL
                AND NOT EXISTS (
                    SELECT 1
                    FROM background_jobs AS job
                    WHERE job.id = NEW.job_id
                      AND job.task_id = NEW.task_id
                      AND job.status = 'RUNNING'
                      AND job.cancellation_requested_at IS NULL
                )
            THEN RAISE(
                ABORT,
                'reconciliation target is not currently fenced'
            ) END;
        END
        """
    )
    immutable_tables = (
        "background_job_ignored_results",
    )
    for table in immutable_tables:
        op.execute(
            f"""
            CREATE TRIGGER {table}_no_change
            BEFORE UPDATE ON {table}
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'reliability provenance is append-only'
                );
            END
            """
        )
    op.execute(
        """
        CREATE TRIGGER background_job_tool_grants_validate_update
        BEFORE UPDATE ON background_job_tool_grants
        BEGIN
            SELECT CASE WHEN
                NEW.id <> OLD.id
                OR NEW.job_id <> OLD.job_id
                OR NEW.lease_id <> OLD.lease_id
                OR NEW.fencing_token <> OLD.fencing_token
                OR NEW.grant_key <> OLD.grant_key
                OR NEW.capability_scope <> OLD.capability_scope
                OR NEW.issued_at <> OLD.issued_at
                OR NEW.owner_id <> OLD.owner_id
                OR NEW.root_correlation_id <> OLD.root_correlation_id
                OR NEW.causation_id IS NOT OLD.causation_id
                OR NEW.parent_correlation_id IS NOT OLD.parent_correlation_id
                OR NEW.created_at <> OLD.created_at
                OR OLD.revoked_at IS NOT NULL
                OR NEW.revoked_at IS NULL
                OR NEW.revoke_reason IS NULL
            THEN RAISE(
                ABORT,
                'invalid tool grant revocation'
            ) END;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER owned_host_processes_validate_update
        BEFORE UPDATE ON owned_host_processes
        BEGIN
            SELECT CASE WHEN
                NEW.id <> OLD.id
                OR NEW.job_id <> OLD.job_id
                OR NEW.lease_id <> OLD.lease_id
                OR NEW.fencing_token <> OLD.fencing_token
                OR NEW.host_id <> OLD.host_id
                OR NEW.pid <> OLD.pid
                OR NEW.process_group_id <> OLD.process_group_id
                OR NEW.birth_token <> OLD.birth_token
                OR NEW.ownership_nonce <> OLD.ownership_nonce
                OR NEW.started_at <> OLD.started_at
                OR NEW.owner_id <> OLD.owner_id
                OR NEW.root_correlation_id <> OLD.root_correlation_id
                OR NEW.causation_id IS NOT OLD.causation_id
                OR NEW.parent_correlation_id IS NOT OLD.parent_correlation_id
                OR NEW.created_at <> OLD.created_at
                OR NOT (
                    (
                        OLD.status = 'RUNNING'
                        AND NEW.status = 'TERMINATION_REQUESTED'
                        AND NEW.termination_requested_at IS NOT NULL
                        AND NEW.terminated_at IS NULL
                        AND NEW.partial_evidence_id IS NULL
                        AND NEW.cleanup_completed_at IS NULL
                    )
                    OR (
                        OLD.status = 'TERMINATION_REQUESTED'
                        AND NEW.status IN ('TERMINATED', 'GONE')
                        AND NEW.termination_requested_at
                            = OLD.termination_requested_at
                        AND NEW.terminated_at IS NOT NULL
                        AND NEW.partial_evidence_id IS NOT NULL
                        AND NEW.cleanup_completed_at IS NOT NULL
                    )
                )
            THEN RAISE(
                ABORT,
                'invalid owned process progression'
            ) END;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER dependency_outage_attempts_validate_update
        BEFORE UPDATE ON dependency_outage_attempts
        BEGIN
            SELECT CASE WHEN
                NEW.id <> OLD.id
                OR NEW.job_id <> OLD.job_id
                OR NEW.lease_id <> OLD.lease_id
                OR NEW.fencing_token <> OLD.fencing_token
                OR NEW.attempt <> OLD.attempt
                OR NEW.service <> OLD.service
                OR NEW.error_code <> OLD.error_code
                OR NEW.checkpoint_evidence_id
                    <> OLD.checkpoint_evidence_id
                OR NEW.exhausted <> OLD.exhausted
                OR NEW.occurred_at <> OLD.occurred_at
                OR NEW.owner_id <> OLD.owner_id
                OR NEW.root_correlation_id <> OLD.root_correlation_id
                OR NEW.causation_id IS NOT OLD.causation_id
                OR NEW.parent_correlation_id IS NOT OLD.parent_correlation_id
                OR NEW.created_at <> OLD.created_at
                OR NOT (
                    (
                        OLD.approval_request_id IS NULL
                        AND OLD.resolved_at IS NULL
                        AND OLD.decision_id IS NULL
                        AND OLD.resumed_job_id IS NULL
                        AND NEW.approval_request_id IS NOT NULL
                        AND NEW.resolved_at IS NULL
                        AND NEW.decision_id IS NULL
                        AND NEW.resumed_job_id IS NULL
                    )
                    OR (
                        OLD.approval_request_id IS NOT NULL
                        AND NEW.approval_request_id
                            = OLD.approval_request_id
                        AND OLD.resolved_at IS NULL
                        AND OLD.decision_id IS NULL
                        AND OLD.resumed_job_id IS NULL
                        AND NEW.resolved_at IS NOT NULL
                        AND NEW.decision_id IS NOT NULL
                    )
                )
            THEN RAISE(
                ABORT,
                'invalid outage progression'
            ) END;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER task_cancellations_validate_update
        BEFORE UPDATE ON task_cancellations
        BEGIN
            SELECT CASE WHEN
                NEW.id <> OLD.id
                OR NEW.task_id <> OLD.task_id
                OR NEW.request_fingerprint <> OLD.request_fingerprint
                OR NEW.reason_code <> OLD.reason_code
                OR NEW.partial_evidence_id <> OLD.partial_evidence_id
                OR NEW.transition_event_id <> OLD.transition_event_id
                OR NEW.requested_at <> OLD.requested_at
                OR NEW.owner_id <> OLD.owner_id
                OR NEW.root_correlation_id <> OLD.root_correlation_id
                OR NEW.causation_id IS NOT OLD.causation_id
                OR NEW.parent_correlation_id IS NOT OLD.parent_correlation_id
                OR NEW.created_at <> OLD.created_at
                OR OLD.cleanup_completed_at IS NOT NULL
                OR NEW.cleanup_completed_at IS NULL
            THEN RAISE(
                ABORT,
                'invalid task cancellation completion'
            ) END;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER reconciliation_targets_validate_update
        BEFORE UPDATE ON reconciliation_targets
        BEGIN
            SELECT CASE WHEN
                NEW.id <> OLD.id
                OR NEW.task_id IS NOT OLD.task_id
                OR NEW.job_id IS NOT OLD.job_id
                OR NEW.kind <> OLD.kind
                OR NEW.target_key <> OLD.target_key
                OR NEW.expected_payload <> OLD.expected_payload
                OR NEW.expected_fingerprint <> OLD.expected_fingerprint
                OR NEW.owner_id <> OLD.owner_id
                OR NEW.root_correlation_id <> OLD.root_correlation_id
                OR NEW.causation_id IS NOT OLD.causation_id
                OR NEW.parent_correlation_id IS NOT OLD.parent_correlation_id
                OR NEW.created_at <> OLD.created_at
                OR NEW.reconciliation_version
                    <> OLD.reconciliation_version + 1
                OR NEW.last_reconciled_at IS NULL
                OR NEW.observed_payload IS NULL
                OR NEW.status = 'PENDING'
                OR (
                    NEW.status = 'RETRY_REQUIRED'
                    AND NEW.last_error_code IS NULL
                )
                OR (
                    NEW.status <> 'RETRY_REQUIRED'
                    AND NEW.last_error_code IS NOT NULL
                )
            THEN RAISE(
                ABORT,
                'invalid reconciliation progression'
            ) END;
        END
        """
    )
    for table in (
        "background_job_tool_grants",
        "owned_host_processes",
        "background_job_ignored_results",
        "dependency_outage_attempts",
        "task_cancellations",
        "reconciliation_targets",
    ):
        op.execute(
            f"""
            CREATE TRIGGER {table}_no_delete
            BEFORE DELETE ON {table}
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'reliability provenance cannot be deleted'
                );
            END
            """
        )


def _create_postgresql_reliability_guards() -> None:
    op.execute(
        """
        CREATE FUNCTION enforce_reliability_provenance_write()
        RETURNS trigger AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'reliability provenance cannot be deleted';
            END IF;
            IF TG_OP = 'INSERT' THEN
                IF TG_TABLE_NAME IN (
                    'background_job_tool_grants',
                    'owned_host_processes'
                ) THEN
                    IF NOT EXISTS (
                        SELECT 1
                        FROM background_jobs job
                        JOIN background_job_leases lease
                          ON lease.id = NEW.lease_id
                         AND lease.job_id = NEW.job_id
                         AND lease.fencing_token = NEW.fencing_token
                        WHERE job.id = NEW.job_id
                          AND job.status = 'RUNNING'
                          AND job.current_lease_id = NEW.lease_id
                          AND job.current_fencing_token = NEW.fencing_token
                          AND job.cancellation_requested_at IS NULL
                          AND lease.released_at IS NULL
                          AND job.owner_id = NEW.owner_id
                          AND job.root_correlation_id
                              = NEW.root_correlation_id
                    ) THEN
                        RAISE EXCEPTION
                            'reliability record is not currently fenced';
                    END IF;
                ELSIF TG_TABLE_NAME
                    = 'background_job_ignored_results' THEN
                    IF NOT EXISTS (
                            SELECT 1
                            FROM background_jobs job
                            JOIN background_job_leases lease
                              ON lease.id = NEW.lease_id
                             AND lease.job_id = NEW.job_id
                             AND lease.fencing_token = NEW.fencing_token
                            JOIN evidence_records evidence
                              ON evidence.id = NEW.evidence_id
                             AND evidence.task_id = job.task_id
                            WHERE job.id = NEW.job_id
                              AND (
                                  job.cancellation_requested_at IS NOT NULL
                                  OR job.status <> 'RUNNING'
                                  OR job.current_lease_id <> NEW.lease_id
                                  OR job.current_fencing_token
                                      <> NEW.fencing_token
                                  OR lease.released_at IS NOT NULL
                              )
                        ) THEN
                        RAISE EXCEPTION
                            'ignored result is not historically fenced';
                    END IF;
                ELSIF TG_TABLE_NAME = 'dependency_outage_attempts' THEN
                    IF NOT EXISTS (
                            SELECT 1
                            FROM background_jobs job
                            JOIN background_job_leases lease
                              ON lease.id = NEW.lease_id
                             AND lease.job_id = NEW.job_id
                             AND lease.fencing_token = NEW.fencing_token
                            JOIN evidence_records evidence
                              ON evidence.id = NEW.checkpoint_evidence_id
                             AND evidence.task_id = job.task_id
                            WHERE job.id = NEW.job_id
                              AND lease.attempt = NEW.attempt
                              AND lease.failure_code = NEW.error_code
                              AND lease.release_reason IN ('RETRY', 'FAILED')
                              AND (
                                  (
                                      NEW.exhausted = false
                                      AND lease.release_reason = 'RETRY'
                                      AND job.status = 'QUEUED'
                                  )
                                  OR (
                                      NEW.exhausted = true
                                      AND lease.release_reason = 'FAILED'
                                      AND job.status = 'FAILED'
                                  )
                              )
                        ) THEN
                        RAISE EXCEPTION 'outage attempt is not fenced';
                    END IF;
                ELSIF TG_TABLE_NAME = 'task_cancellations' THEN
                    IF NOT EXISTS (
                            SELECT 1
                            FROM tasks task
                            JOIN task_events event
                              ON event.id = NEW.transition_event_id
                             AND event.task_id = NEW.task_id
                             AND event.transition_id = NEW.id
                            JOIN evidence_records evidence
                              ON evidence.id = NEW.partial_evidence_id
                             AND evidence.task_id = NEW.task_id
                            WHERE task.id = NEW.task_id
                              AND event.transition_kind IN ('CANCEL', 'FAIL')
                              AND event.transition_to_state = task.state
                              AND task.state IN ('CANCELLED', 'FAILED')
                        ) THEN
                        RAISE EXCEPTION
                            'terminal work fence lacks transition provenance';
                    END IF;
                ELSIF TG_TABLE_NAME = 'reconciliation_targets' THEN
                    IF NEW.job_id IS NOT NULL
                       AND NOT EXISTS (
                           SELECT 1
                           FROM background_jobs job
                           WHERE job.id = NEW.job_id
                             AND job.task_id = NEW.task_id
                             AND job.status = 'RUNNING'
                             AND job.cancellation_requested_at IS NULL
                       ) THEN
                        RAISE EXCEPTION
                            'reconciliation target is not currently fenced';
                    END IF;
                END IF;
                RETURN NEW;
            END IF;
            IF TG_TABLE_NAME = 'background_job_ignored_results' THEN
                RAISE EXCEPTION 'reliability provenance is append-only';
            ELSIF TG_TABLE_NAME = 'background_job_tool_grants' THEN
                IF to_jsonb(NEW) - ARRAY[
                       'revoked_at', 'revoke_reason', 'actor_id', 'updated_at'
                   ] IS DISTINCT FROM
                   to_jsonb(OLD) - ARRAY[
                       'revoked_at', 'revoke_reason', 'actor_id', 'updated_at'
                   ]
                   OR OLD.revoked_at IS NOT NULL
                   OR NEW.revoked_at IS NULL
                   OR NEW.revoke_reason IS NULL THEN
                    RAISE EXCEPTION 'invalid tool grant revocation';
                END IF;
            ELSIF TG_TABLE_NAME = 'owned_host_processes' THEN
                IF to_jsonb(NEW) - ARRAY[
                       'status', 'termination_requested_at', 'terminated_at',
                       'partial_evidence_id', 'cleanup_completed_at',
                       'actor_id', 'updated_at'
                   ] IS DISTINCT FROM
                   to_jsonb(OLD) - ARRAY[
                       'status', 'termination_requested_at', 'terminated_at',
                       'partial_evidence_id', 'cleanup_completed_at',
                       'actor_id', 'updated_at'
                   ]
                   OR NOT (
                       (
                           OLD.status = 'RUNNING'
                           AND NEW.status = 'TERMINATION_REQUESTED'
                           AND NEW.termination_requested_at IS NOT NULL
                           AND NEW.terminated_at IS NULL
                           AND NEW.partial_evidence_id IS NULL
                           AND NEW.cleanup_completed_at IS NULL
                       )
                       OR (
                           OLD.status = 'TERMINATION_REQUESTED'
                           AND NEW.status IN ('TERMINATED', 'GONE')
                           AND NEW.termination_requested_at
                               = OLD.termination_requested_at
                           AND NEW.terminated_at IS NOT NULL
                           AND NEW.partial_evidence_id IS NOT NULL
                           AND NEW.cleanup_completed_at IS NOT NULL
                       )
                   ) THEN
                    RAISE EXCEPTION 'invalid owned process progression';
                END IF;
            ELSIF TG_TABLE_NAME = 'dependency_outage_attempts' THEN
                IF to_jsonb(NEW) - ARRAY[
                       'approval_request_id', 'resolved_at', 'decision_id',
                       'resumed_job_id', 'actor_id', 'updated_at'
                   ] IS DISTINCT FROM
                   to_jsonb(OLD) - ARRAY[
                       'approval_request_id', 'resolved_at', 'decision_id',
                       'resumed_job_id', 'actor_id', 'updated_at'
                   ]
                   OR NOT (
                       (
                           OLD.approval_request_id IS NULL
                           AND OLD.resolved_at IS NULL
                           AND OLD.decision_id IS NULL
                           AND OLD.resumed_job_id IS NULL
                           AND NEW.approval_request_id IS NOT NULL
                           AND NEW.resolved_at IS NULL
                           AND NEW.decision_id IS NULL
                           AND NEW.resumed_job_id IS NULL
                       )
                       OR (
                           OLD.approval_request_id IS NOT NULL
                           AND NEW.approval_request_id
                               = OLD.approval_request_id
                           AND OLD.resolved_at IS NULL
                           AND OLD.decision_id IS NULL
                           AND OLD.resumed_job_id IS NULL
                           AND NEW.resolved_at IS NOT NULL
                           AND NEW.decision_id IS NOT NULL
                       )
                   ) THEN
                    RAISE EXCEPTION 'invalid outage progression';
                END IF;
            ELSIF TG_TABLE_NAME = 'task_cancellations' THEN
                IF to_jsonb(NEW) - ARRAY[
                       'cleanup_completed_at', 'actor_id', 'updated_at'
                   ] IS DISTINCT FROM
                   to_jsonb(OLD) - ARRAY[
                       'cleanup_completed_at', 'actor_id', 'updated_at'
                   ]
                   OR OLD.cleanup_completed_at IS NOT NULL
                   OR NEW.cleanup_completed_at IS NULL THEN
                    RAISE EXCEPTION 'invalid task cancellation completion';
                END IF;
            ELSIF TG_TABLE_NAME = 'reconciliation_targets' THEN
                IF to_jsonb(NEW) - ARRAY[
                       'observed_payload', 'status',
                       'reconciliation_version', 'last_reconciled_at',
                       'last_error_code', 'actor_id', 'updated_at'
                   ] IS DISTINCT FROM
                   to_jsonb(OLD) - ARRAY[
                       'observed_payload', 'status',
                       'reconciliation_version', 'last_reconciled_at',
                       'last_error_code', 'actor_id', 'updated_at'
                   ]
                   OR NEW.reconciliation_version
                       <> OLD.reconciliation_version + 1
                   OR NEW.last_reconciled_at IS NULL
                   OR NEW.observed_payload IS NULL
                   OR NEW.status = 'PENDING'
                   OR (
                       NEW.status = 'RETRY_REQUIRED'
                       AND NEW.last_error_code IS NULL
                   )
                   OR (
                       NEW.status <> 'RETRY_REQUIRED'
                       AND NEW.last_error_code IS NOT NULL
                   ) THEN
                    RAISE EXCEPTION 'invalid reconciliation progression';
                END IF;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    for table in (
        "background_job_tool_grants",
        "owned_host_processes",
        "background_job_ignored_results",
        "dependency_outage_attempts",
        "task_cancellations",
        "reconciliation_targets",
    ):
        op.execute(
            f"""
            CREATE TRIGGER {table}_enforce_write
            BEFORE INSERT OR UPDATE OR DELETE ON {table}
            FOR EACH ROW
            EXECUTE FUNCTION enforce_reliability_provenance_write()
            """
        )


def _create_reliability_guards() -> None:
    if op.get_bind().dialect.name == "sqlite":
        _create_sqlite_reliability_guards()
    else:
        _create_postgresql_reliability_guards()


def _drop_reliability_guards() -> None:
    tables = (
        "background_job_tool_grants",
        "owned_host_processes",
        "background_job_ignored_results",
        "dependency_outage_attempts",
        "task_cancellations",
        "reconciliation_targets",
    )
    if op.get_bind().dialect.name == "sqlite":
        for table in tables:
            op.execute(f"DROP TRIGGER IF EXISTS {table}_no_delete")
            op.execute(f"DROP TRIGGER IF EXISTS {table}_validate_insert")
        op.execute(
            "DROP TRIGGER IF EXISTS "
            "background_job_ignored_results_no_change"
        )
        for trigger in (
            "background_job_tool_grants_validate_update",
            "owned_host_processes_validate_update",
            "dependency_outage_attempts_validate_update",
            "task_cancellations_validate_update",
            "reconciliation_targets_validate_update",
        ):
            op.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        return
    for table in tables:
        op.execute(
            f"DROP TRIGGER IF EXISTS {table}_enforce_write ON {table}"
        )
    op.execute(
        "DROP FUNCTION IF EXISTS enforce_reliability_provenance_write"
    )


def upgrade() -> None:
    """Create append-only reliability provenance and recovery projections."""

    op.create_table(
        "background_job_tool_grants",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("lease_id", sa.Uuid(), nullable=False),
        sa.Column("fencing_token", sa.BigInteger(), nullable=False),
        sa.Column("grant_key", sa.String(length=255), nullable=False),
        sa.Column("capability_scope", sa.JSON(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revoke_reason", sa.String(length=100)),
        *_context_columns(),
        sa.CheckConstraint(
            "fencing_token > 0",
            name=op.f("ck_background_job_tool_grants_fencing_token_positive"),
        ),
        sa.CheckConstraint(
            "(revoked_at IS NULL AND revoke_reason IS NULL) "
            "OR (revoked_at IS NOT NULL AND revoke_reason IS NOT NULL)",
            name=op.f("ck_background_job_tool_grants_revocation_shape"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["background_jobs.id"],
            name=op.f("fk_background_job_tool_grants_job_id_background_jobs"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["job_id", "lease_id", "fencing_token"],
            [
                "background_job_leases.job_id",
                "background_job_leases.id",
                "background_job_leases.fencing_token",
            ],
            name=op.f("fk_background_job_tool_grants_lease"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f("pk_background_job_tool_grants"),
        ),
        sa.UniqueConstraint(
            "job_id",
            "grant_key",
            name=op.f("uq_background_job_tool_grants_job_key"),
        ),
    )

    op.create_table(
        "owned_host_processes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("lease_id", sa.Uuid(), nullable=False),
        sa.Column("fencing_token", sa.BigInteger(), nullable=False),
        sa.Column("host_id", sa.String(length=255), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=False),
        sa.Column("process_group_id", sa.Integer(), nullable=False),
        sa.Column("birth_token", sa.String(length=255), nullable=False),
        sa.Column("ownership_nonce", sa.Uuid(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "RUNNING",
                "TERMINATION_REQUESTED",
                "TERMINATED",
                "GONE",
                name="owned_host_process_status",
                native_enum=False,
                create_constraint=True,
                length=64,
            ),
            server_default="RUNNING",
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("termination_requested_at", sa.DateTime(timezone=True)),
        sa.Column("terminated_at", sa.DateTime(timezone=True)),
        sa.Column("partial_evidence_id", sa.Uuid()),
        sa.Column("cleanup_completed_at", sa.DateTime(timezone=True)),
        *_context_columns(),
        sa.CheckConstraint(
            "pid > 1",
            name=op.f("ck_owned_host_processes_pid_safe"),
        ),
        sa.CheckConstraint(
            "process_group_id > 1",
            name=op.f("ck_owned_host_processes_process_group_id_safe"),
        ),
        sa.CheckConstraint(
            "fencing_token > 0",
            name=op.f("ck_owned_host_processes_fencing_token_positive"),
        ),
        sa.CheckConstraint(
            "(status = 'RUNNING' "
            "AND termination_requested_at IS NULL "
            "AND terminated_at IS NULL) "
            "OR (status = 'TERMINATION_REQUESTED' "
            "AND termination_requested_at IS NOT NULL "
            "AND terminated_at IS NULL) "
            "OR (status IN ('TERMINATED', 'GONE') "
            "AND termination_requested_at IS NOT NULL "
            "AND terminated_at IS NOT NULL)",
            name=op.f("ck_owned_host_processes_status_shape"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["background_jobs.id"],
            name=op.f("fk_owned_host_processes_job_id_background_jobs"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["job_id", "lease_id", "fencing_token"],
            [
                "background_job_leases.job_id",
                "background_job_leases.id",
                "background_job_leases.fencing_token",
            ],
            name=op.f("fk_owned_host_processes_lease"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["partial_evidence_id"],
            ["evidence_records.id"],
            name=op.f("fk_owned_host_processes_partial_evidence_id_evidence_records"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f("pk_owned_host_processes"),
        ),
        sa.UniqueConstraint(
            "host_id",
            "pid",
            "birth_token",
            name=op.f("uq_owned_host_processes_identity"),
        ),
        sa.UniqueConstraint(
            "ownership_nonce",
            name=op.f("uq_owned_host_processes_ownership_nonce"),
        ),
    )

    op.create_table(
        "background_job_ignored_results",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("lease_id", sa.Uuid(), nullable=False),
        sa.Column("fencing_token", sa.BigInteger(), nullable=False),
        sa.Column("effect_id", sa.Uuid()),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("result_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("reason_code", sa.String(length=32), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        *_context_columns(),
        sa.CheckConstraint(
            "fencing_token > 0",
            name=op.f("ck_background_job_ignored_results_fencing_token_positive"),
        ),
        sa.CheckConstraint(
            "reason_code IN ('CANCELLED', 'FENCED')",
            name=op.f("ck_background_job_ignored_results_reason_code"),
        ),
        sa.CheckConstraint(
            "length(result_fingerprint) = 64",
            name=op.f("ck_background_job_ignored_results_result_fingerprint_length"),
        ),
        sa.CheckConstraint(
            _hex_only_sql("result_fingerprint"),
            name=op.f("ck_background_job_ignored_results_result_fingerprint_hex"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["background_jobs.id"],
            name=op.f("fk_background_job_ignored_results_job_id_background_jobs"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["effect_id"],
            ["background_job_effects.id"],
            name=op.f("fk_background_job_ignored_results_effect_id_background_job_effects"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence_records.id"],
            name=op.f("fk_background_job_ignored_results_evidence_id_evidence_records"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["job_id", "lease_id", "fencing_token"],
            [
                "background_job_leases.job_id",
                "background_job_leases.id",
                "background_job_leases.fencing_token",
            ],
            name=op.f("fk_background_job_ignored_results_lease"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f("pk_background_job_ignored_results"),
        ),
        sa.UniqueConstraint(
            "idempotency_key",
            name=op.f("uq_background_job_ignored_results_idempotency_key"),
        ),
        sa.UniqueConstraint(
            "evidence_id",
            name=op.f("uq_background_job_ignored_results_evidence"),
        ),
    )

    op.create_table(
        "dependency_outage_attempts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("lease_id", sa.Uuid(), nullable=False),
        sa.Column("fencing_token", sa.BigInteger(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column(
            "service",
            sa.Enum(
                "HOST",
                "HERMES",
                "GITHUB",
                name="dependency_service",
                native_enum=False,
                create_constraint=True,
                length=64,
            ),
            nullable=False,
        ),
        sa.Column("error_code", sa.String(length=100), nullable=False),
        sa.Column("checkpoint_evidence_id", sa.Uuid(), nullable=False),
        sa.Column("exhausted", sa.Boolean(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approval_request_id", sa.Uuid()),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.Column("decision_id", sa.Uuid()),
        sa.Column("resumed_job_id", sa.Uuid()),
        *_context_columns(),
        sa.CheckConstraint(
            "attempt > 0",
            name=op.f("ck_dependency_outage_attempts_attempt_positive"),
        ),
        sa.CheckConstraint(
            "fencing_token > 0",
            name=op.f("ck_dependency_outage_attempts_fencing_token_positive"),
        ),
        sa.CheckConstraint(
            "service IN ('HOST', 'HERMES', 'GITHUB')",
            name=op.f("ck_dependency_outage_attempts_service"),
        ),
        sa.CheckConstraint(
            "(exhausted = false AND approval_request_id IS NULL) "
            "OR exhausted = true",
            name=op.f("ck_dependency_outage_attempts_approval_only_when_exhausted"),
        ),
        sa.CheckConstraint(
            "(resolved_at IS NULL AND decision_id IS NULL "
            "AND resumed_job_id IS NULL) "
            "OR (resolved_at IS NOT NULL AND decision_id IS NOT NULL)",
            name=op.f("ck_dependency_outage_attempts_resolution_shape"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["background_jobs.id"],
            name=op.f("fk_dependency_outage_attempts_job_id_background_jobs"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["checkpoint_evidence_id"],
            ["evidence_records.id"],
            name=op.f(
                "fk_dependency_outage_attempts_checkpoint_evidence_id_evidence_records"
            ),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["approval_request_id"],
            ["approval_requests.id"],
            name=op.f(
                "fk_dependency_outage_attempts_approval_request_id_approval_requests"
            ),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["resumed_job_id"],
            ["background_jobs.id"],
            name=op.f(
                "fk_dependency_outage_attempts_resumed_job_id_background_jobs"
            ),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["job_id", "lease_id", "fencing_token"],
            [
                "background_job_leases.job_id",
                "background_job_leases.id",
                "background_job_leases.fencing_token",
            ],
            name=op.f("fk_dependency_outage_attempts_lease"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f("pk_dependency_outage_attempts"),
        ),
        sa.UniqueConstraint(
            "job_id",
            "attempt",
            name=op.f("uq_dependency_outage_attempts_job_attempt"),
        ),
        sa.UniqueConstraint(
            "approval_request_id",
            name=op.f("uq_dependency_outage_attempts_approval_request"),
        ),
    )

    op.create_table(
        "task_cancellations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("request_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("reason_code", sa.String(length=100), nullable=False),
        sa.Column("partial_evidence_id", sa.Uuid(), nullable=False),
        sa.Column("transition_event_id", sa.Uuid(), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cleanup_completed_at", sa.DateTime(timezone=True)),
        *_context_columns(),
        sa.CheckConstraint(
            "length(request_fingerprint) = 64",
            name=op.f("ck_task_cancellations_request_fingerprint_length"),
        ),
        sa.CheckConstraint(
            _hex_only_sql("request_fingerprint"),
            name=op.f("ck_task_cancellations_request_fingerprint_hex"),
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["tasks.id"],
            name=op.f("fk_task_cancellations_task_id_tasks"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["partial_evidence_id"],
            ["evidence_records.id"],
            name=op.f("fk_task_cancellations_partial_evidence_id_evidence_records"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["task_id", "transition_event_id"],
            ["task_events.task_id", "task_events.id"],
            name=op.f("fk_task_cancellations_transition_event"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f("pk_task_cancellations"),
        ),
        sa.UniqueConstraint(
            "task_id",
            name=op.f("uq_task_cancellations_task"),
        ),
        sa.UniqueConstraint(
            "transition_event_id",
            name=op.f("uq_task_cancellations_transition_event"),
        ),
    )

    op.create_table(
        "reconciliation_targets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("task_id", sa.Uuid()),
        sa.Column("job_id", sa.Uuid()),
        sa.Column(
            "kind",
            sa.Enum(
                "HERMES_RUN",
                "HOST_PROCESS",
                "BRANCH_HEAD",
                "PR_HEAD",
                "WEBHOOK_CURSOR",
                name="reconciliation_target_kind",
                native_enum=False,
                create_constraint=True,
                length=64,
            ),
            nullable=False,
        ),
        sa.Column("target_key", sa.String(length=255), nullable=False),
        sa.Column("expected_payload", sa.JSON(), nullable=False),
        sa.Column("expected_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("observed_payload", sa.JSON()),
        sa.Column(
            "status",
            sa.Enum(
                "PENDING",
                "CURRENT",
                "UPDATED",
                "QUARANTINED",
                "RETRY_REQUIRED",
                "CANCELLED",
                name="reconciliation_status",
                native_enum=False,
                create_constraint=True,
                length=64,
            ),
            server_default="PENDING",
            nullable=False,
        ),
        sa.Column(
            "reconciliation_version",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column("last_reconciled_at", sa.DateTime(timezone=True)),
        sa.Column("last_error_code", sa.String(length=100)),
        *_context_columns(),
        sa.CheckConstraint(
            "length(expected_fingerprint) = 64",
            name=op.f("ck_reconciliation_targets_expected_fingerprint_length"),
        ),
        sa.CheckConstraint(
            _hex_only_sql("expected_fingerprint"),
            name=op.f("ck_reconciliation_targets_expected_fingerprint_hex"),
        ),
        sa.CheckConstraint(
            "reconciliation_version >= 0",
            name=op.f(
                "ck_reconciliation_targets_reconciliation_version_non_negative"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["tasks.id"],
            name=op.f("fk_reconciliation_targets_task_id_tasks"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["background_jobs.id"],
            name=op.f("fk_reconciliation_targets_job_id_background_jobs"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f("pk_reconciliation_targets"),
        ),
        sa.UniqueConstraint(
            "kind",
            "target_key",
            name=op.f("uq_reconciliation_targets_kind_key"),
        ),
    )
    op.create_index(
        op.f("ix_reconciliation_targets_startup"),
        "reconciliation_targets",
        ["status", "kind", "updated_at"],
    )
    _replace_background_job_guard(allow_cancellation=True)
    _create_reliability_guards()


def downgrade() -> None:
    """Remove reliability tables only before they contain durable provenance."""

    if op.get_context().as_sql:
        raise RuntimeError(
            "Cancellation and outage provenance requires an online guarded downgrade"
        )
    tables = (
        "background_job_tool_grants",
        "owned_host_processes",
        "background_job_ignored_results",
        "dependency_outage_attempts",
        "task_cancellations",
        "reconciliation_targets",
    )
    for table in tables:
        if op.get_bind().scalar(sa.text(f"SELECT 1 FROM {table} LIMIT 1")):
            raise RuntimeError(
                "Cannot downgrade while cancellation or outage provenance exists"
            )

    _drop_reliability_guards()
    _replace_background_job_guard(allow_cancellation=False)
    op.drop_index(
        op.f("ix_reconciliation_targets_startup"),
        table_name="reconciliation_targets",
    )
    op.drop_table("reconciliation_targets")
    op.drop_table("task_cancellations")
    op.drop_table("dependency_outage_attempts")
    op.drop_table("background_job_ignored_results")
    op.drop_table("owned_host_processes")
    op.drop_table("background_job_tool_grants")
