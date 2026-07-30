"""Add fenced durable background-job execution.

Revision ID: 0006
Revises: 0005
Create Date: 2026-07-30
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ZERO_FINGERPRINT = "0" * 64


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


def _hex_only_sql(column: str) -> str:
    expression = column
    for character in "0123456789abcdef":
        expression = f"replace({expression}, '{character}', '')"
    return f"length({expression}) = 0"


def _create_sqlite_triggers() -> None:
    op.execute(
        """
        CREATE TRIGGER background_jobs_validate_insert
        BEFORE INSERT ON background_jobs
        BEGIN
            SELECT CASE WHEN
                NEW.max_attempts NOT BETWEEN 1 AND 100
                OR NEW.attempt_count < 0
                OR NEW.attempt_count > NEW.max_attempts
                OR NEW.retry_base_seconds <= 0
                OR NEW.retry_max_seconds < NEW.retry_base_seconds
                OR NEW.checkpoint_version < 0
                OR length(NEW.input_fingerprint) <> 64
                OR length(
                    replace(replace(replace(replace(replace(replace(
                    replace(replace(replace(replace(replace(replace(
                    replace(replace(replace(replace(
                    NEW.input_fingerprint,
                    '0', ''), '1', ''), '2', ''), '3', ''),
                    '4', ''), '5', ''), '6', ''), '7', ''),
                    '8', ''), '9', ''), 'a', ''), 'b', ''),
                    'c', ''), 'd', ''), 'e', ''), 'f', '')
                ) <> 0
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
        END
        """
    )
    op.execute(
        """
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
                                  AND julianday(lease.expires_at) > julianday('now')
                              )
                          )
                    )
                )
            ) THEN RAISE(ABORT, 'background job mutation is not fenced') END;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER background_jobs_no_delete
        BEFORE DELETE ON background_jobs
        BEGIN
            SELECT RAISE(ABORT, 'background jobs cannot be deleted');
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER background_job_leases_validate_insert
        BEFORE INSERT ON background_job_leases
        BEGIN
            SELECT CASE WHEN
                NEW.lease_protocol_version <> 1
                OR NEW.attempt <= 0
                OR NEW.fencing_token <= 0
                OR NEW.checkpoint_version < 0
                OR NEW.expires_at <= NEW.heartbeat_at
                OR julianday(NEW.expires_at) <= julianday('now')
                OR length(NEW.claim_fingerprint) <> 64
                OR NOT EXISTS (
                    SELECT 1
                    FROM background_jobs AS job
                    WHERE job.id = NEW.job_id
                      AND job.task_id IS NOT NULL
                      AND job.owner_id = NEW.owner_id
                      AND job.root_correlation_id = NEW.root_correlation_id
                      AND job.cancellation_requested_at IS NULL
                      AND job.attempt_count < job.max_attempts
                      AND NEW.attempt = job.attempt_count + 1
                      AND (
                          (
                              job.status = 'QUEUED'
                              AND julianday(job.available_at) <= julianday('now')
                          )
                          OR (
                              job.status = 'RUNNING'
                              AND julianday(job.lease_expires_at) <= julianday('now')
                          )
                      )
                )
            THEN RAISE(ABORT, 'invalid background job lease claim') END;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER background_job_leases_validate_update
        BEFORE UPDATE ON background_job_leases
        BEGIN
            SELECT CASE WHEN
                NEW.id <> OLD.id
                OR NEW.job_id <> OLD.job_id
                OR NEW.lease_owner <> OLD.lease_owner
                OR NEW.attempt <> OLD.attempt
                OR NEW.fencing_token <> OLD.fencing_token
                OR NEW.idempotency_key <> OLD.idempotency_key
                OR NEW.lease_protocol_version <> OLD.lease_protocol_version
                OR NEW.claim_fingerprint <> OLD.claim_fingerprint
                OR NEW.owner_id <> OLD.owner_id
                OR NEW.root_correlation_id <> OLD.root_correlation_id
            THEN RAISE(ABORT, 'background job lease identity is immutable') END;
            SELECT CASE WHEN NOT EXISTS (
                SELECT 1
                FROM background_jobs AS job
                WHERE job.id = OLD.job_id
                  AND job.status = 'RUNNING'
                  AND job.current_lease_id = OLD.id
                  AND job.current_fencing_token = OLD.fencing_token
                  AND job.lease_owner = OLD.lease_owner
            ) THEN RAISE(ABORT, 'background job lease is stale') END;
            SELECT CASE WHEN
                (
                    NEW.expires_at <> OLD.expires_at
                    AND NEW.heartbeat_at = OLD.heartbeat_at
                )
                OR (
                    NEW.heartbeat_at <> OLD.heartbeat_at
                    AND (
                        OLD.released_at IS NOT NULL
                        OR julianday(OLD.expires_at) <= julianday('now')
                        OR NEW.heartbeat_at < OLD.heartbeat_at
                        OR NEW.expires_at <= NEW.heartbeat_at
                        OR julianday(NEW.expires_at)
                            < julianday(OLD.expires_at)
                    )
                )
            THEN RAISE(ABORT, 'expired background job lease cannot heartbeat') END;
            SELECT CASE WHEN
                OLD.released_at IS NOT NULL
                AND (
                    NEW.released_at IS NOT OLD.released_at
                    OR NEW.release_reason IS NOT OLD.release_reason
                )
            THEN RAISE(ABORT, 'background job lease release is immutable') END;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER background_job_leases_no_delete
        BEFORE DELETE ON background_job_leases
        BEGIN
            SELECT RAISE(ABORT, 'background job leases cannot be deleted');
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER background_job_checkpoints_validate_insert
        BEFORE INSERT ON background_job_checkpoints
        BEGIN
            SELECT CASE WHEN NOT EXISTS (
                SELECT 1
                FROM background_jobs AS job
                JOIN background_job_leases AS lease
                  ON lease.job_id = job.id
                 AND lease.id = NEW.lease_id
                 AND lease.fencing_token = NEW.fencing_token
                WHERE job.id = NEW.job_id
                  AND job.status = 'RUNNING'
                  AND job.current_lease_id = NEW.lease_id
                  AND job.current_fencing_token = NEW.fencing_token
                  AND job.cancellation_requested_at IS NULL
                  AND job.owner_id = NEW.owner_id
                  AND job.root_correlation_id = NEW.root_correlation_id
                  AND lease.released_at IS NULL
                  AND julianday(lease.expires_at) > julianday('now')
                  AND NEW.sequence = job.checkpoint_version + 1
            ) THEN RAISE(ABORT, 'background job checkpoint is not current') END;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER background_job_checkpoints_no_change
        BEFORE UPDATE ON background_job_checkpoints
        BEGIN
            SELECT RAISE(ABORT, 'background job checkpoints are append-only');
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER background_job_checkpoints_no_delete
        BEFORE DELETE ON background_job_checkpoints
        BEGIN
            SELECT RAISE(ABORT, 'background job checkpoints are append-only');
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER background_job_effects_validate_insert
        BEFORE INSERT ON background_job_effects
        BEGIN
            SELECT CASE WHEN NOT EXISTS (
                SELECT 1
                FROM background_jobs AS job
                JOIN background_job_leases AS lease
                  ON lease.job_id = job.id
                 AND lease.id = NEW.started_lease_id
                 AND lease.fencing_token = NEW.started_fencing_token
                WHERE job.id = NEW.job_id
                  AND job.status = 'RUNNING'
                  AND job.current_lease_id = NEW.started_lease_id
                  AND job.current_fencing_token = NEW.started_fencing_token
                  AND job.cancellation_requested_at IS NULL
                  AND job.owner_id = NEW.owner_id
                  AND job.root_correlation_id = NEW.root_correlation_id
                  AND lease.released_at IS NULL
                  AND julianday(lease.expires_at) > julianday('now')
            ) THEN RAISE(ABORT, 'background job effect is not current') END;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER background_job_effects_validate_update
        BEFORE UPDATE ON background_job_effects
        BEGIN
            SELECT CASE WHEN
                NEW.id <> OLD.id
                OR NEW.job_id <> OLD.job_id
                OR NEW.effect_type <> OLD.effect_type
                OR NEW.idempotency_key <> OLD.idempotency_key
                OR NEW.request_fingerprint <> OLD.request_fingerprint
                OR NEW.request_payload <> OLD.request_payload
                OR NEW.started_lease_id <> OLD.started_lease_id
                OR NEW.started_fencing_token <> OLD.started_fencing_token
                OR NEW.owner_id <> OLD.owner_id
                OR NEW.root_correlation_id <> OLD.root_correlation_id
                OR OLD.status <> 'PENDING'
                OR NEW.status NOT IN ('SUCCEEDED', 'FAILED')
                OR NOT EXISTS (
                    SELECT 1
                    FROM background_jobs AS job
                    JOIN background_job_leases AS lease
                      ON lease.job_id = job.id
                     AND lease.id = NEW.completion_lease_id
                     AND lease.fencing_token = NEW.completion_fencing_token
                    WHERE job.id = NEW.job_id
                      AND job.status = 'RUNNING'
                      AND job.current_lease_id = NEW.completion_lease_id
                      AND job.current_fencing_token = NEW.completion_fencing_token
                      AND job.cancellation_requested_at IS NULL
                      AND lease.released_at IS NULL
                      AND julianday(lease.expires_at) > julianday('now')
                )
            THEN RAISE(ABORT, 'background job effect result is not current') END;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER background_job_effects_no_delete
        BEFORE DELETE ON background_job_effects
        BEGIN
            SELECT RAISE(ABORT, 'background job effects cannot be deleted');
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER background_job_task_transitions_validate_insert
        BEFORE INSERT ON background_job_task_transitions
        BEGIN
            SELECT CASE WHEN NOT EXISTS (
                SELECT 1
                FROM background_jobs AS job
                JOIN background_job_leases AS lease
                  ON lease.job_id = job.id
                 AND lease.id = NEW.lease_id
                 AND lease.fencing_token = NEW.fencing_token
                JOIN task_events AS event
                  ON event.task_id = NEW.task_id
                 AND event.id = NEW.task_event_id
                WHERE job.id = NEW.job_id
                  AND job.task_id = NEW.task_id
                  AND job.status = 'RUNNING'
                  AND job.current_lease_id = NEW.lease_id
                  AND job.current_fencing_token = NEW.fencing_token
                  AND job.cancellation_requested_at IS NULL
                  AND job.owner_id = NEW.owner_id
                  AND job.root_correlation_id = NEW.root_correlation_id
                  AND event.owner_id = NEW.owner_id
                  AND event.root_correlation_id = NEW.root_correlation_id
                  AND lease.released_at IS NULL
                  AND julianday(lease.expires_at) > julianday('now')
            ) THEN RAISE(ABORT, 'background job task transition is not current') END;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER background_job_task_transitions_no_change
        BEFORE UPDATE ON background_job_task_transitions
        BEGIN
            SELECT RAISE(ABORT, 'background job task transitions are append-only');
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER background_job_task_transitions_no_delete
        BEFORE DELETE ON background_job_task_transitions
        BEGIN
            SELECT RAISE(ABORT, 'background job task transitions are append-only');
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER background_job_fencing_counter_validate_update
        BEFORE UPDATE ON background_job_fencing_counter
        BEGIN
            SELECT CASE WHEN
                NEW.id <> 1
                OR OLD.id <> 1
                OR NEW.next_token <> OLD.next_token + 1
            THEN RAISE(ABORT, 'invalid background job fencing allocation') END;
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER background_job_fencing_counter_no_delete
        BEFORE DELETE ON background_job_fencing_counter
        BEGIN
            SELECT RAISE(ABORT, 'background job fencing counter cannot be deleted');
        END
        """
    )


def _create_postgresql_triggers() -> None:
    op.execute(
        """
        CREATE FUNCTION enforce_background_job_write() RETURNS trigger AS $$
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
               OR NEW.input_fingerprint !~ '^[0-9a-f]{64}$' THEN
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
                            AND lease.expires_at > clock_timestamp())
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
    op.execute(
        """
        CREATE TRIGGER background_jobs_enforce_write
        BEFORE INSERT OR UPDATE OR DELETE ON background_jobs
        FOR EACH ROW EXECUTE FUNCTION enforce_background_job_write()
        """
    )
    op.execute(
        """
        CREATE FUNCTION enforce_background_job_lease_write() RETURNS trigger AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'background job leases cannot be deleted';
            END IF;
            IF TG_OP = 'INSERT' THEN
                IF NEW.lease_protocol_version <> 1
                   OR NEW.attempt <= 0
                   OR NEW.fencing_token <= 0
                   OR NEW.checkpoint_version < 0
                   OR NEW.expires_at <= NEW.heartbeat_at
                   OR NEW.expires_at <= clock_timestamp()
                   OR NEW.claim_fingerprint !~ '^[0-9a-f]{64}$'
                   OR NOT EXISTS (
                       SELECT 1 FROM background_jobs job
                       WHERE job.id = NEW.job_id
                         AND job.task_id IS NOT NULL
                         AND job.owner_id = NEW.owner_id
                         AND job.root_correlation_id = NEW.root_correlation_id
                         AND job.cancellation_requested_at IS NULL
                         AND job.attempt_count < job.max_attempts
                         AND NEW.attempt = job.attempt_count + 1
                         AND (
                             (job.status = 'QUEUED'
                              AND job.available_at <= clock_timestamp())
                             OR
                             (job.status = 'RUNNING'
                              AND job.lease_expires_at <= clock_timestamp())
                         )
                   ) THEN
                    RAISE EXCEPTION 'invalid background job lease claim';
                END IF;
                RETURN NEW;
            END IF;
            IF NEW.id <> OLD.id
               OR NEW.job_id <> OLD.job_id
               OR NEW.lease_owner <> OLD.lease_owner
               OR NEW.attempt <> OLD.attempt
               OR NEW.fencing_token <> OLD.fencing_token
               OR NEW.idempotency_key <> OLD.idempotency_key
               OR NEW.lease_protocol_version <> OLD.lease_protocol_version
               OR NEW.claim_fingerprint <> OLD.claim_fingerprint
               OR NEW.owner_id <> OLD.owner_id
               OR NEW.root_correlation_id <> OLD.root_correlation_id THEN
                RAISE EXCEPTION 'background job lease identity is immutable';
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM background_jobs job
                WHERE job.id = OLD.job_id
                  AND job.status = 'RUNNING'
                  AND job.current_lease_id = OLD.id
                  AND job.current_fencing_token = OLD.fencing_token
                  AND job.lease_owner = OLD.lease_owner
            ) THEN
                RAISE EXCEPTION 'background job lease is stale';
            END IF;
            IF (NEW.expires_at <> OLD.expires_at
                AND NEW.heartbeat_at = OLD.heartbeat_at)
               OR
               (NEW.heartbeat_at <> OLD.heartbeat_at
                AND (OLD.released_at IS NOT NULL
                     OR OLD.expires_at <= clock_timestamp()
                     OR NEW.heartbeat_at < OLD.heartbeat_at
                     OR NEW.expires_at <= NEW.heartbeat_at
                     OR NEW.expires_at < OLD.expires_at)) THEN
                RAISE EXCEPTION 'expired background job lease cannot heartbeat';
            END IF;
            IF OLD.released_at IS NOT NULL
               AND (NEW.released_at IS DISTINCT FROM OLD.released_at
                    OR NEW.release_reason IS DISTINCT FROM OLD.release_reason) THEN
                RAISE EXCEPTION 'background job lease release is immutable';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER background_job_leases_enforce_write
        BEFORE INSERT OR UPDATE OR DELETE ON background_job_leases
        FOR EACH ROW EXECUTE FUNCTION enforce_background_job_lease_write()
        """
    )
    op.execute(
        """
        CREATE FUNCTION enforce_background_job_checkpoint_write() RETURNS trigger AS $$
        BEGIN
            IF TG_OP <> 'INSERT' THEN
                RAISE EXCEPTION 'background job checkpoints are append-only';
            END IF;
            IF NOT EXISTS (
                SELECT 1
                FROM background_jobs job
                JOIN background_job_leases lease
                  ON lease.job_id = job.id
                 AND lease.id = NEW.lease_id
                 AND lease.fencing_token = NEW.fencing_token
                WHERE job.id = NEW.job_id
                  AND job.status = 'RUNNING'
                  AND job.current_lease_id = NEW.lease_id
                  AND job.current_fencing_token = NEW.fencing_token
                  AND job.cancellation_requested_at IS NULL
                  AND job.owner_id = NEW.owner_id
                  AND job.root_correlation_id = NEW.root_correlation_id
                  AND lease.released_at IS NULL
                  AND lease.expires_at > clock_timestamp()
                  AND NEW.sequence = job.checkpoint_version + 1
            ) THEN
                RAISE EXCEPTION 'background job checkpoint is not current';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER background_job_checkpoints_enforce_write
        BEFORE INSERT OR UPDATE OR DELETE ON background_job_checkpoints
        FOR EACH ROW EXECUTE FUNCTION enforce_background_job_checkpoint_write()
        """
    )
    op.execute(
        """
        CREATE FUNCTION enforce_background_job_effect_write() RETURNS trigger AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'background job effects cannot be deleted';
            END IF;
            IF TG_OP = 'INSERT' THEN
                IF NOT EXISTS (
                    SELECT 1
                    FROM background_jobs job
                    JOIN background_job_leases lease
                      ON lease.job_id = job.id
                     AND lease.id = NEW.started_lease_id
                     AND lease.fencing_token = NEW.started_fencing_token
                    WHERE job.id = NEW.job_id
                      AND job.status = 'RUNNING'
                      AND job.current_lease_id = NEW.started_lease_id
                      AND job.current_fencing_token = NEW.started_fencing_token
                      AND job.cancellation_requested_at IS NULL
                      AND job.owner_id = NEW.owner_id
                      AND job.root_correlation_id = NEW.root_correlation_id
                      AND lease.released_at IS NULL
                      AND lease.expires_at > clock_timestamp()
                ) THEN
                    RAISE EXCEPTION 'background job effect is not current';
                END IF;
                RETURN NEW;
            END IF;
            IF NEW.id <> OLD.id
               OR NEW.job_id <> OLD.job_id
               OR NEW.effect_type <> OLD.effect_type
               OR NEW.idempotency_key <> OLD.idempotency_key
               OR NEW.request_fingerprint <> OLD.request_fingerprint
               OR NEW.request_payload::jsonb
                  IS DISTINCT FROM OLD.request_payload::jsonb
               OR NEW.started_lease_id <> OLD.started_lease_id
               OR NEW.started_fencing_token <> OLD.started_fencing_token
               OR NEW.owner_id <> OLD.owner_id
               OR NEW.root_correlation_id <> OLD.root_correlation_id
               OR OLD.status <> 'PENDING'
               OR NEW.status NOT IN ('SUCCEEDED', 'FAILED')
               OR NOT EXISTS (
                   SELECT 1
                   FROM background_jobs job
                   JOIN background_job_leases lease
                     ON lease.job_id = job.id
                    AND lease.id = NEW.completion_lease_id
                    AND lease.fencing_token = NEW.completion_fencing_token
                   WHERE job.id = NEW.job_id
                     AND job.status = 'RUNNING'
                     AND job.current_lease_id = NEW.completion_lease_id
                     AND job.current_fencing_token = NEW.completion_fencing_token
                     AND job.cancellation_requested_at IS NULL
                     AND lease.released_at IS NULL
                     AND lease.expires_at > clock_timestamp()
               ) THEN
                RAISE EXCEPTION 'background job effect result is not current';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER background_job_effects_enforce_write
        BEFORE INSERT OR UPDATE OR DELETE ON background_job_effects
        FOR EACH ROW EXECUTE FUNCTION enforce_background_job_effect_write()
        """
    )
    op.execute(
        """
        CREATE FUNCTION enforce_background_job_task_transition_write()
        RETURNS trigger AS $$
        BEGIN
            IF TG_OP <> 'INSERT' THEN
                RAISE EXCEPTION 'background job task transitions are append-only';
            END IF;
            IF NOT EXISTS (
                SELECT 1
                FROM background_jobs job
                JOIN background_job_leases lease
                  ON lease.job_id = job.id
                 AND lease.id = NEW.lease_id
                 AND lease.fencing_token = NEW.fencing_token
                JOIN task_events event
                  ON event.task_id = NEW.task_id
                 AND event.id = NEW.task_event_id
                WHERE job.id = NEW.job_id
                  AND job.task_id = NEW.task_id
                  AND job.status = 'RUNNING'
                  AND job.current_lease_id = NEW.lease_id
                  AND job.current_fencing_token = NEW.fencing_token
                  AND job.cancellation_requested_at IS NULL
                  AND job.owner_id = NEW.owner_id
                  AND job.root_correlation_id = NEW.root_correlation_id
                  AND event.owner_id = NEW.owner_id
                  AND event.root_correlation_id = NEW.root_correlation_id
                  AND lease.released_at IS NULL
                  AND lease.expires_at > clock_timestamp()
            ) THEN
                RAISE EXCEPTION 'background job task transition is not current';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER background_job_task_transitions_enforce_write
        BEFORE INSERT OR UPDATE OR DELETE ON background_job_task_transitions
        FOR EACH ROW EXECUTE FUNCTION enforce_background_job_task_transition_write()
        """
    )
    op.execute(
        """
        CREATE FUNCTION enforce_background_job_fencing_counter_write()
        RETURNS trigger AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'background job fencing counter cannot be deleted';
            END IF;
            IF NEW.id <> 1 OR OLD.id <> 1
               OR NEW.next_token <> OLD.next_token + 1 THEN
                RAISE EXCEPTION 'invalid background job fencing allocation';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER background_job_fencing_counter_enforce_write
        BEFORE UPDATE OR DELETE ON background_job_fencing_counter
        FOR EACH ROW EXECUTE FUNCTION enforce_background_job_fencing_counter_write()
        """
    )


def _drop_triggers() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        for trigger in (
            "background_job_fencing_counter_no_delete",
            "background_job_fencing_counter_validate_update",
            "background_job_task_transitions_no_delete",
            "background_job_task_transitions_no_change",
            "background_job_task_transitions_validate_insert",
            "background_job_effects_no_delete",
            "background_job_effects_validate_update",
            "background_job_effects_validate_insert",
            "background_job_checkpoints_no_delete",
            "background_job_checkpoints_no_change",
            "background_job_checkpoints_validate_insert",
            "background_job_leases_no_delete",
            "background_job_leases_validate_update",
            "background_job_leases_validate_insert",
            "background_jobs_no_delete",
            "background_jobs_validate_update",
            "background_jobs_validate_insert",
        ):
            op.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        return
    for trigger, table in (
        ("background_job_fencing_counter_enforce_write", "background_job_fencing_counter"),
        (
            "background_job_task_transitions_enforce_write",
            "background_job_task_transitions",
        ),
        ("background_job_effects_enforce_write", "background_job_effects"),
        ("background_job_checkpoints_enforce_write", "background_job_checkpoints"),
        ("background_job_leases_enforce_write", "background_job_leases"),
        ("background_jobs_enforce_write", "background_jobs"),
    ):
        op.execute(f"DROP TRIGGER IF EXISTS {trigger} ON {table}")
    for function in (
        "enforce_background_job_fencing_counter_write",
        "enforce_background_job_task_transition_write",
        "enforce_background_job_effect_write",
        "enforce_background_job_checkpoint_write",
        "enforce_background_job_lease_write",
        "enforce_background_job_write",
    ):
        op.execute(f"DROP FUNCTION IF EXISTS {function}()")


def upgrade() -> None:
    """Install durable leasing, effect, checkpoint, and recovery state."""

    dialect = op.get_bind().dialect.name
    op.add_column(
        "background_jobs",
        sa.Column(
            "input_payload",
            sa.JSON(),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
    )
    op.add_column(
        "background_jobs",
        sa.Column(
            "input_fingerprint",
            sa.String(length=64),
            server_default=_ZERO_FINGERPRINT,
            nullable=False,
        ),
    )
    op.add_column(
        "background_jobs",
        sa.Column("max_attempts", sa.Integer(), server_default="5", nullable=False),
    )
    op.add_column(
        "background_jobs",
        sa.Column(
            "retry_base_seconds",
            sa.Integer(),
            server_default="1",
            nullable=False,
        ),
    )
    op.add_column(
        "background_jobs",
        sa.Column(
            "retry_max_seconds",
            sa.Integer(),
            server_default="300",
            nullable=False,
        ),
    )
    if dialect == "sqlite":
        op.add_column(
            "background_jobs",
            sa.Column(
                "available_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("'1970-01-01 00:00:00'"),
                nullable=False,
            ),
        )
    else:
        op.add_column(
            "background_jobs",
            sa.Column(
                "available_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
        )
    op.add_column(
        "background_jobs",
        sa.Column(
            "checkpoint_version",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
    )
    op.add_column("background_jobs", sa.Column("current_lease_id", sa.Uuid()))
    op.add_column(
        "background_jobs",
        sa.Column("current_fencing_token", sa.BigInteger()),
    )
    op.add_column(
        "background_jobs",
        sa.Column("lease_owner", sa.String(length=255)),
    )
    op.add_column(
        "background_jobs",
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
    )
    op.add_column(
        "background_jobs",
        sa.Column("last_fencing_token", sa.BigInteger()),
    )
    op.add_column(
        "background_jobs",
        sa.Column("last_error_code", sa.String(length=100)),
    )
    op.execute(
        """
        UPDATE background_jobs
        SET attempt_count = CASE
                WHEN attempt_count > 100 THEN 100
                ELSE attempt_count
            END,
            max_attempts = CASE
                WHEN attempt_count >= 100 THEN 100
                WHEN status IN ('SUCCEEDED', 'FAILED', 'CANCELLED')
                    THEN CASE WHEN attempt_count > 5 THEN attempt_count ELSE 5 END
                WHEN task_id IS NULL
                    THEN CASE WHEN attempt_count > 5 THEN attempt_count ELSE 5 END
                WHEN attempt_count >= 5 THEN attempt_count + 1
                ELSE 5
            END,
            available_at = created_at,
            status = CASE
                WHEN status NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED')
                     AND task_id IS NULL THEN 'FAILED'
                WHEN status NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED')
                     AND attempt_count >= 100 THEN 'FAILED'
                WHEN status = 'RUNNING' THEN 'QUEUED'
                ELSE status
            END,
            completed_at = CASE
                WHEN status IN ('SUCCEEDED', 'FAILED', 'CANCELLED')
                     OR task_id IS NULL
                     OR attempt_count >= 100
                    THEN COALESCE(completed_at, updated_at)
                ELSE NULL
            END,
            last_error_code = CASE
                WHEN status NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED')
                     AND task_id IS NULL THEN 'LEGACY_TASK_BINDING_MISSING'
                WHEN status NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED')
                     AND attempt_count >= 100
                    THEN 'LEGACY_ATTEMPT_BUDGET_EXCEEDED'
                ELSE NULL
            END
        """
    )
    if dialect != "sqlite":
        with op.batch_alter_table("background_jobs") as batch_op:
            batch_op.create_check_constraint(
                op.f("ck_background_jobs_max_attempts_bounded"),
                "max_attempts BETWEEN 1 AND 100",
            )
            batch_op.create_check_constraint(
                op.f("ck_background_jobs_attempt_count_within_budget"),
                "attempt_count <= max_attempts",
            )
            batch_op.create_check_constraint(
                op.f("ck_background_jobs_retry_base_seconds_positive"),
                "retry_base_seconds > 0",
            )
            batch_op.create_check_constraint(
                op.f("ck_background_jobs_retry_max_seconds_not_below_base"),
                "retry_max_seconds >= retry_base_seconds",
            )
            batch_op.create_check_constraint(
                op.f("ck_background_jobs_checkpoint_version_non_negative"),
                "checkpoint_version >= 0",
            )
            batch_op.create_check_constraint(
                op.f("ck_background_jobs_current_lease_projection_shape"),
                "(current_lease_id IS NULL "
                "AND current_fencing_token IS NULL "
                "AND lease_owner IS NULL "
                "AND lease_expires_at IS NULL) "
                "OR (current_lease_id IS NOT NULL "
                "AND current_fencing_token IS NOT NULL "
                "AND lease_owner IS NOT NULL "
                "AND lease_expires_at IS NOT NULL)",
            )
    op.create_index(
        op.f("ix_background_jobs_schedule"),
        "background_jobs",
        ["status", "available_at", "created_at"],
    )

    with op.batch_alter_table("background_job_leases") as batch_op:
        batch_op.add_column(
            sa.Column(
                "lease_protocol_version",
                sa.Integer(),
                server_default="0",
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column(
                "claim_fingerprint",
                sa.String(length=64),
                server_default=_ZERO_FINGERPRINT,
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column(
                "checkpoint_version",
                sa.Integer(),
                server_default="0",
                nullable=False,
            )
        )
        batch_op.add_column(sa.Column("released_at", sa.DateTime(timezone=True)))
        batch_op.add_column(sa.Column("release_reason", sa.String(length=32)))
        batch_op.add_column(sa.Column("retry_at", sa.DateTime(timezone=True)))
        batch_op.add_column(sa.Column("failure_code", sa.String(length=100)))
        batch_op.create_unique_constraint(
            op.f("uq_background_job_leases_job_id_token"),
            ["job_id", "id", "fencing_token"],
        )
        batch_op.drop_constraint(
            op.f("fk_background_job_leases_job_id_background_jobs"),
            type_="foreignkey",
        )
        batch_op.create_foreign_key(
            op.f("fk_background_job_leases_job_id_background_jobs"),
            "background_jobs",
            ["job_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch_op.create_check_constraint(
            op.f("ck_background_job_leases_checkpoint_version_non_negative"),
            "checkpoint_version >= 0",
        )
        batch_op.create_check_constraint(
            op.f("ck_background_job_leases_expires_after_heartbeat"),
            "expires_at > heartbeat_at",
        )
        batch_op.create_check_constraint(
            op.f("ck_background_job_leases_release_shape"),
            "(released_at IS NULL AND release_reason IS NULL) "
            "OR (released_at IS NOT NULL AND release_reason IN "
            "('SUPERSEDED', 'EXPIRED', 'RETRY', 'SUCCEEDED', 'FAILED', "
            "'CANCELLED'))",
        )
    with op.batch_alter_table("background_job_leases") as batch_op:
        batch_op.alter_column(
            "lease_protocol_version",
            existing_type=sa.Integer(),
            nullable=False,
            server_default="1",
        )
    op.create_index(
        op.f("ix_background_job_leases_expiry"),
        "background_job_leases",
        ["job_id", "expires_at"],
    )

    op.create_table(
        "background_job_fencing_counter",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column(
            "next_token",
            sa.BigInteger(),
            server_default="1",
            nullable=False,
        ),
        sa.CheckConstraint("id = 1", name=op.f("ck_background_job_fencing_counter_singleton")),
        sa.CheckConstraint(
            "next_token > 0",
            name=op.f("ck_background_job_fencing_counter_next_token_positive"),
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f("pk_background_job_fencing_counter"),
        ),
    )
    op.execute(
        """
        INSERT INTO background_job_fencing_counter (id, next_token)
        SELECT 1, COALESCE(MAX(fencing_token), 0) + 1
        FROM background_job_leases
        """
    )

    op.create_table(
        "background_job_checkpoints",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("lease_id", sa.Uuid(), nullable=False),
        sa.Column("fencing_token", sa.BigInteger(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("payload_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        *_context_columns(),
        sa.CheckConstraint(
            "sequence > 0",
            name=op.f("ck_background_job_checkpoints_sequence_positive"),
        ),
        sa.CheckConstraint(
            "fencing_token > 0",
            name=op.f("ck_background_job_checkpoints_fencing_token_positive"),
        ),
        sa.CheckConstraint(
            "length(payload_fingerprint) = 64",
            name=op.f("ck_background_job_checkpoints_payload_fingerprint_length"),
        ),
        sa.CheckConstraint(
            _hex_only_sql("payload_fingerprint"),
            name=op.f("ck_background_job_checkpoints_payload_fingerprint_hex"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["background_jobs.id"],
            name=op.f("fk_background_job_checkpoints_job_id_background_jobs"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["job_id", "lease_id", "fencing_token"],
            [
                "background_job_leases.job_id",
                "background_job_leases.id",
                "background_job_leases.fencing_token",
            ],
            name=op.f("fk_background_job_checkpoints_lease"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f("pk_background_job_checkpoints"),
        ),
        sa.UniqueConstraint(
            "job_id",
            "sequence",
            name=op.f("uq_background_job_checkpoints_job_sequence"),
        ),
        sa.UniqueConstraint(
            "idempotency_key",
            name=op.f("uq_background_job_checkpoints_idempotency_key"),
        ),
    )

    op.create_table(
        "background_job_effects",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("effect_type", sa.String(length=100), nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("request_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("request_payload", sa.JSON(), nullable=False),
        sa.Column(
            "status",
            sa.String(length=64),
            server_default="PENDING",
            nullable=False,
        ),
        sa.Column("started_lease_id", sa.Uuid(), nullable=False),
        sa.Column("started_fencing_token", sa.BigInteger(), nullable=False),
        sa.Column("completion_lease_id", sa.Uuid()),
        sa.Column("completion_fencing_token", sa.BigInteger()),
        sa.Column("result_payload", sa.JSON()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        *_context_columns(),
        sa.CheckConstraint(
            "status IN ('PENDING', 'SUCCEEDED', 'FAILED')",
            name=op.f("ck_background_job_effects_background_job_effect_status"),
        ),
        sa.CheckConstraint(
            "length(request_fingerprint) = 64",
            name=op.f("ck_background_job_effects_request_fingerprint_length"),
        ),
        sa.CheckConstraint(
            _hex_only_sql("request_fingerprint"),
            name=op.f("ck_background_job_effects_request_fingerprint_hex"),
        ),
        sa.CheckConstraint(
            "(status = 'PENDING' AND completed_at IS NULL "
            "AND completion_lease_id IS NULL "
            "AND completion_fencing_token IS NULL) "
            "OR (status IN ('SUCCEEDED', 'FAILED') "
            "AND completed_at IS NOT NULL "
            "AND completion_lease_id IS NOT NULL "
            "AND completion_fencing_token IS NOT NULL)",
            name=op.f("ck_background_job_effects_completion_shape"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["background_jobs.id"],
            name=op.f("fk_background_job_effects_job_id_background_jobs"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["job_id", "started_lease_id", "started_fencing_token"],
            [
                "background_job_leases.job_id",
                "background_job_leases.id",
                "background_job_leases.fencing_token",
            ],
            name=op.f("fk_background_job_effects_started_lease"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["job_id", "completion_lease_id", "completion_fencing_token"],
            [
                "background_job_leases.job_id",
                "background_job_leases.id",
                "background_job_leases.fencing_token",
            ],
            name=op.f("fk_background_job_effects_completion_lease"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_background_job_effects")),
        sa.UniqueConstraint(
            "idempotency_key",
            name=op.f("uq_background_job_effects_idempotency_key"),
        ),
        sa.UniqueConstraint(
            "job_id",
            "effect_type",
            "idempotency_key",
            name=op.f("uq_background_job_effects_job_effect_key"),
        ),
    )
    op.create_index(
        op.f("ix_background_job_effects_reconciliation"),
        "background_job_effects",
        ["job_id", "status", "started_at"],
    )

    op.create_table(
        "background_job_task_transitions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("lease_id", sa.Uuid(), nullable=False),
        sa.Column("fencing_token", sa.BigInteger(), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("task_event_id", sa.Uuid(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        *_context_columns(),
        sa.CheckConstraint(
            "fencing_token > 0",
            name=op.f("ck_background_job_task_transitions_fencing_token_positive"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["background_jobs.id"],
            name=op.f("fk_background_job_task_transitions_job_id_background_jobs"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["job_id", "lease_id", "fencing_token"],
            [
                "background_job_leases.job_id",
                "background_job_leases.id",
                "background_job_leases.fencing_token",
            ],
            name=op.f("fk_background_job_task_transitions_lease"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["task_id", "task_event_id"],
            ["task_events.task_id", "task_events.id"],
            name=op.f("fk_background_job_task_transitions_task_event"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f("pk_background_job_task_transitions"),
        ),
        sa.UniqueConstraint(
            "task_event_id",
            name=op.f("uq_background_job_task_transitions_task_event"),
        ),
    )
    if dialect == "sqlite":
        _create_sqlite_triggers()
    else:
        _create_postgresql_triggers()


def downgrade() -> None:
    """Remove job-loop structures only when no version-one provenance exists."""

    if op.get_context().as_sql:
        raise RuntimeError("Background job provenance requires an online guarded downgrade")
    dialect = op.get_bind().dialect.name
    if op.get_bind().scalar(
        sa.text(
            "SELECT 1 WHERE "
            "EXISTS (SELECT 1 FROM background_job_leases "
            "WHERE lease_protocol_version = 1) "
            "OR EXISTS (SELECT 1 FROM background_job_checkpoints) "
            "OR EXISTS (SELECT 1 FROM background_job_effects) "
            "OR EXISTS (SELECT 1 FROM background_job_task_transitions) "
            "OR EXISTS (SELECT 1 FROM background_jobs "
            f"WHERE input_fingerprint <> '{'0' * 64}')"
        )
    ):
        raise RuntimeError("Cannot downgrade while fenced background job provenance exists")

    _drop_triggers()
    op.drop_table("background_job_task_transitions")
    op.drop_index(
        op.f("ix_background_job_effects_reconciliation"),
        table_name="background_job_effects",
    )
    op.drop_table("background_job_effects")
    op.drop_table("background_job_checkpoints")
    op.drop_table("background_job_fencing_counter")
    op.drop_index(
        op.f("ix_background_job_leases_expiry"),
        table_name="background_job_leases",
    )
    with op.batch_alter_table("background_job_leases") as batch_op:
        for constraint_name in (
            "ck_background_job_leases_release_shape",
            "ck_background_job_leases_expires_after_heartbeat",
            "ck_background_job_leases_checkpoint_version_non_negative",
        ):
            batch_op.drop_constraint(
                op.f(constraint_name),
                type_="check",
            )
        batch_op.drop_constraint(
            op.f("uq_background_job_leases_job_id_token"),
            type_="unique",
        )
        batch_op.drop_constraint(
            op.f("fk_background_job_leases_job_id_background_jobs"),
            type_="foreignkey",
        )
        batch_op.drop_column("failure_code")
        batch_op.drop_column("retry_at")
        batch_op.drop_column("release_reason")
        batch_op.drop_column("released_at")
        batch_op.drop_column("checkpoint_version")
        batch_op.drop_column("claim_fingerprint")
        batch_op.drop_column("lease_protocol_version")
        batch_op.create_foreign_key(
            op.f("fk_background_job_leases_job_id_background_jobs"),
            "background_jobs",
            ["job_id"],
            ["id"],
            ondelete="CASCADE",
        )
    op.drop_index(
        op.f("ix_background_jobs_schedule"),
        table_name="background_jobs",
    )
    job_loop_columns = (
        "last_error_code",
        "last_fencing_token",
        "lease_expires_at",
        "lease_owner",
        "current_fencing_token",
        "current_lease_id",
        "checkpoint_version",
        "available_at",
        "retry_max_seconds",
        "retry_base_seconds",
        "max_attempts",
        "input_fingerprint",
        "input_payload",
    )
    if dialect == "sqlite":
        for column in job_loop_columns:
            op.drop_column("background_jobs", column)
    else:
        with op.batch_alter_table("background_jobs") as batch_op:
            for constraint_name in (
                "ck_background_jobs_current_lease_projection_shape",
                "ck_background_jobs_checkpoint_version_non_negative",
                "ck_background_jobs_retry_max_seconds_not_below_base",
                "ck_background_jobs_retry_base_seconds_positive",
                "ck_background_jobs_attempt_count_within_budget",
                "ck_background_jobs_max_attempts_bounded",
            ):
                batch_op.drop_constraint(
                    op.f(constraint_name),
                    type_="check",
                )
            for column in job_loop_columns:
                batch_op.drop_column(column)
