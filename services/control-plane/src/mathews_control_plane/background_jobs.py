"""Durable leased background jobs with fencing and effect reconciliation."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, cast
from uuid import UUID, uuid4

from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    BackgroundJob,
    BackgroundJobCheckpoint,
    BackgroundJobEffect,
    BackgroundJobEffectStatus,
    BackgroundJobFencingCounter,
    BackgroundJobLease,
    BackgroundJobStatus,
    BackgroundJobTaskTransition,
    Task,
    TaskState,
)
from mathews_control_plane.evidence import redact_evidence_content
from mathews_control_plane.task_state_machine import (
    ClosedTaskTransitionGateEvaluator,
    TaskTransitionGateEvaluator,
    TaskTransitionKind,
    TaskTransitionResult,
    _transition_task,
)

MAX_LEASE_SECONDS = 300
MAX_RETRY_SECONDS = 86_400
MAX_JOB_IDENTIFIER_LENGTH = 100
MAX_IDEMPOTENCY_KEY_LENGTH = 255

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]*\Z")
_ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,99}\Z")


class BackgroundJobError(RuntimeError):
    """Base class for safe durable-job failures."""


class InvalidBackgroundJobError(BackgroundJobError):
    """The requested job command is invalid."""


class BackgroundJobNotFoundError(BackgroundJobError):
    """The requested job is unavailable to this operation."""


class BackgroundJobConflictError(BackgroundJobError):
    """A durable idempotency key or expected version conflicts."""


class BackgroundJobLeaseLostError(BackgroundJobError):
    """The supplied lease is no longer the current live fence."""


class AmbiguousBackgroundJobEffectError(BackgroundJobError):
    """An old prepared effect cannot safely be replayed without reconciliation."""


class RetryableBackgroundJobError(BackgroundJobError):
    """A handler failure that may consume another bounded attempt."""

    def __init__(self, error_code: str) -> None:
        self.error_code = _required_error_code(error_code)
        super().__init__(self.error_code)


class TerminalBackgroundJobError(BackgroundJobError):
    """A handler failure that must not be retried."""

    def __init__(self, error_code: str) -> None:
        self.error_code = _required_error_code(error_code)
        super().__init__(self.error_code)


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Immutable retry budget captured when a job is scheduled."""

    max_attempts: int = 5
    base_delay_seconds: int = 1
    max_delay_seconds: int = 300

    def __post_init__(self) -> None:
        if not 1 <= self.max_attempts <= 100:
            raise InvalidBackgroundJobError("background job max attempts must be between 1 and 100")
        if not 1 <= self.base_delay_seconds <= MAX_RETRY_SECONDS:
            raise InvalidBackgroundJobError("background job base retry delay is invalid")
        if not self.base_delay_seconds <= self.max_delay_seconds <= MAX_RETRY_SECONDS:
            raise InvalidBackgroundJobError("background job maximum retry delay is invalid")


@dataclass(frozen=True, slots=True)
class ScheduledJob:
    """Stable result of one idempotent schedule command."""

    job_id: UUID
    replayed: bool


@dataclass(frozen=True, slots=True)
class JobLeaseGrant:
    """Complete lease identity required by every fenced mutation."""

    job_id: UUID
    task_id: UUID
    lease_id: UUID
    worker_id: str
    attempt: int
    fencing_token: int
    expires_at: datetime
    job_type: str
    input_payload: dict[str, object]
    checkpoint: dict[str, object] | None
    checkpoint_version: int
    recovered: bool


@dataclass(frozen=True, slots=True)
class JobCheckpointResult:
    """Accepted append-only checkpoint and current projection version."""

    checkpoint_id: UUID
    sequence: int
    replayed: bool


@dataclass(frozen=True, slots=True)
class PreparedJobEffect:
    """Durable effect intent safe to execute or reconcile outside the database."""

    effect_id: UUID
    idempotency_key: str
    effect_type: str
    request_payload: dict[str, object]
    status: BackgroundJobEffectStatus
    result_payload: dict[str, object] | None
    created: bool
    needs_reconciliation: bool


@dataclass(frozen=True, slots=True)
class EffectExecutionResult:
    """Normalized external-effect observation returned by an adapter."""

    succeeded: bool
    payload: dict[str, object]


@dataclass(frozen=True, slots=True)
class JobFailureDisposition:
    """Durable result of releasing a failed attempt."""

    status: BackgroundJobStatus
    next_attempt_at: datetime | None
    exhausted: bool
    retry_delay: timedelta | None


class WorkerRunOutcome(StrEnum):
    """One bounded worker poll result."""

    IDLE = "IDLE"
    SUCCEEDED = "SUCCEEDED"
    RETRY_SCHEDULED = "RETRY_SCHEDULED"
    FAILED = "FAILED"
    LEASE_LOST = "LEASE_LOST"


class BackgroundJobEffectExecutor(Protocol):
    """Adapter that executes new effects and reconciles prepared ones."""

    def execute(
        self,
        *,
        idempotency_key: str,
        effect_type: str,
        request_payload: Mapping[str, object],
    ) -> EffectExecutionResult: ...

    def reconcile(
        self,
        *,
        idempotency_key: str,
        effect_type: str,
        request_payload: Mapping[str, object],
    ) -> EffectExecutionResult | None: ...


class BackgroundJobHandler(Protocol):
    """Allowlisted job implementation invoked with a fenced context."""

    def __call__(
        self,
        context: LeasedJobContext,
    ) -> Mapping[str, object] | None: ...


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return _as_utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _required_identifier(
    value: str,
    *,
    field: str,
    maximum: int,
) -> str:
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > maximum
        or _IDENTIFIER.fullmatch(normalized) is None
        or "://" in normalized
        or "//" in normalized
        or ".." in normalized
        or normalized.startswith("/")
    ):
        raise InvalidBackgroundJobError(f"background job {field} is invalid")
    return normalized


def _required_error_code(value: str) -> str:
    normalized = value.strip().upper()
    if _ERROR_CODE.fullmatch(normalized) is None:
        raise InvalidBackgroundJobError("background job error code is invalid")
    return normalized


def _safe_payload(value: Mapping[str, object], *, field: str) -> dict[str, object]:
    prepared = redact_evidence_content(
        dict(value),
        media_type="application/json",
    )
    if prepared.manifest:
        raise InvalidBackgroundJobError(f"background job {field} contains sensitive values")
    normalized = prepared.value
    if not isinstance(normalized, dict):
        raise InvalidBackgroundJobError(f"background job {field} is invalid")
    try:
        encoded = json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
    except (TypeError, ValueError):
        raise InvalidBackgroundJobError(
            f"background job {field} is not JSON serializable"
        ) from None
    if len(encoded) > 1024 * 1024:
        raise InvalidBackgroundJobError(f"background job {field} exceeds the size limit")
    return cast(dict[str, object], normalized)


def _fingerprint(value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _schedule_fingerprint(
    *,
    task_id: UUID,
    job_type: str,
    payload: Mapping[str, object],
    policy: RetryPolicy,
    requested_available_at: datetime | None,
) -> str:
    return _fingerprint(
        {
            "task_id": str(task_id),
            "job_type": job_type,
            "payload": dict(payload),
            "retry_policy": {
                "max_attempts": policy.max_attempts,
                "base_delay_seconds": policy.base_delay_seconds,
                "max_delay_seconds": policy.max_delay_seconds,
            },
            "available_at": (
                None if requested_available_at is None else _timestamp(requested_available_at)
            ),
        }
    )


def deterministic_retry_delay(
    job_id: UUID,
    failed_attempt: int,
    policy: RetryPolicy,
) -> timedelta:
    """Return persisted full jitter bounded by the scheduled retry policy."""

    if failed_attempt < 1:
        raise InvalidBackgroundJobError("background job attempt is invalid")
    exponent = min(failed_attempt - 1, 63)
    cap_seconds = min(
        policy.max_delay_seconds,
        policy.base_delay_seconds * (2**exponent),
    )
    cap_milliseconds = cap_seconds * 1000
    digest = hashlib.sha256(
        (
            f"{job_id}:{failed_attempt}:{policy.max_attempts}:"
            f"{policy.base_delay_seconds}:{policy.max_delay_seconds}"
        ).encode()
    ).digest()
    delay_milliseconds = int.from_bytes(digest[:8], "big") % (cap_milliseconds + 1)
    return timedelta(milliseconds=delay_milliseconds)


def _begin_serialized(session: Session) -> None:
    if session.get_bind().dialect.name == "sqlite":
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")


def _ensure_fencing_counter(session: Session) -> BackgroundJobFencingCounter:
    query = (
        select(BackgroundJobFencingCounter)
        .where(BackgroundJobFencingCounter.id == 1)
        .with_for_update()
    )
    counter = session.scalar(query)
    if counter is None:
        try:
            with session.begin_nested():
                counter = BackgroundJobFencingCounter(id=1, next_token=1)
                session.add(counter)
                session.flush()
        except IntegrityError:
            counter = session.scalar(query)
            if counter is None:
                raise
    return counter


def _lease_fingerprint(
    job: BackgroundJob,
    *,
    lease_id: UUID,
    worker_id: str,
    attempt: int,
    token: int,
) -> str:
    return _fingerprint(
        {
            "job_id": str(job.id),
            "lease_id": str(lease_id),
            "worker_id": worker_id,
            "attempt": attempt,
            "fencing_token": token,
            "input_fingerprint": job.input_fingerprint,
        }
    )


def _grant(job: BackgroundJob, lease: BackgroundJobLease, *, recovered: bool) -> JobLeaseGrant:
    if job.task_id is None:
        raise BackgroundJobConflictError("background job has no task binding")
    return JobLeaseGrant(
        job_id=job.id,
        task_id=job.task_id,
        lease_id=lease.id,
        worker_id=lease.lease_owner,
        attempt=lease.attempt,
        fencing_token=lease.fencing_token,
        expires_at=_as_utc(lease.expires_at),
        job_type=job.job_type,
        input_payload=dict(job.input_payload),
        checkpoint=None if job.checkpoint is None else dict(job.checkpoint),
        checkpoint_version=job.checkpoint_version,
        recovered=recovered,
    )


def _matching_schedule(
    job: BackgroundJob,
    *,
    task_id: UUID,
    job_type: str,
    fingerprint: str,
) -> ScheduledJob:
    if job.task_id != task_id or job.job_type != job_type or job.input_fingerprint != fingerprint:
        raise BackgroundJobConflictError(
            "background job idempotency key was used for a different command"
        )
    return ScheduledJob(job_id=job.id, replayed=True)


class BackgroundJobService:
    """Transactional scheduler, lease coordinator, and provenance boundary."""

    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        *,
        principal_id: str = "control-plane",
        gate_evaluator: TaskTransitionGateEvaluator | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._factory = factory
        self._artifact_store = artifact_store
        self._principal_id = _required_identifier(
            principal_id,
            field="principal",
            maximum=255,
        )
        self._gate_evaluator = gate_evaluator or ClosedTaskTransitionGateEvaluator()
        self._clock = clock

    def schedule(
        self,
        *,
        task_id: UUID,
        job_type: str,
        idempotency_key: str,
        input_payload: Mapping[str, object],
        retry_policy: RetryPolicy | None = None,
        available_at: datetime | None = None,
    ) -> ScheduledJob:
        policy = retry_policy or RetryPolicy()
        normalized_type = _required_identifier(
            job_type,
            field="type",
            maximum=MAX_JOB_IDENTIFIER_LENGTH,
        )
        normalized_key = _required_identifier(
            idempotency_key,
            field="idempotency key",
            maximum=MAX_IDEMPOTENCY_KEY_LENGTH,
        )
        payload = _safe_payload(input_payload, field="input")
        requested_available = None if available_at is None else _as_utc(available_at)
        fingerprint = _schedule_fingerprint(
            task_id=task_id,
            job_type=normalized_type,
            payload=payload,
            policy=policy,
            requested_available_at=requested_available,
        )
        now = _as_utc(self._clock())
        due_at = requested_available or now
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            task = session.scalar(select(Task).where(Task.id == task_id).with_for_update())
            if task is None:
                raise BackgroundJobNotFoundError("background job task is unavailable")
            existing = session.scalar(
                select(BackgroundJob).where(BackgroundJob.idempotency_key == normalized_key)
            )
            if existing is not None:
                return _matching_schedule(
                    existing,
                    task_id=task_id,
                    job_type=normalized_type,
                    fingerprint=fingerprint,
                )
            _ensure_fencing_counter(session)
            job = BackgroundJob(
                task_id=task.id,
                job_type=normalized_type,
                input_payload=payload,
                input_fingerprint=fingerprint,
                status=BackgroundJobStatus.QUEUED,
                idempotency_key=normalized_key,
                attempt_count=0,
                max_attempts=policy.max_attempts,
                retry_base_seconds=policy.base_delay_seconds,
                retry_max_seconds=policy.max_delay_seconds,
                available_at=due_at,
                checkpoint=None,
                checkpoint_version=0,
                owner_id=task.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=task.root_correlation_id,
            )
            try:
                with session.begin_nested():
                    session.add(job)
                    session.flush()
            except IntegrityError:
                existing = session.scalar(
                    select(BackgroundJob).where(BackgroundJob.idempotency_key == normalized_key)
                )
                if existing is None:
                    raise
                return _matching_schedule(
                    existing,
                    task_id=task_id,
                    job_type=normalized_type,
                    fingerprint=fingerprint,
                )
            return ScheduledJob(job_id=job.id, replayed=False)

    def claim_next(
        self,
        *,
        worker_id: str,
        lease_duration: timedelta,
        job_types: Sequence[str] = (),
    ) -> JobLeaseGrant | None:
        normalized_worker = _required_identifier(
            worker_id,
            field="worker",
            maximum=255,
        )
        duration = _lease_duration(lease_duration)
        normalized_types = tuple(
            _required_identifier(
                job_type,
                field="type",
                maximum=MAX_JOB_IDENTIFIER_LENGTH,
            )
            for job_type in job_types
        )
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            while True:
                scan_time = _as_utc(self._clock())
                eligible = and_(
                    BackgroundJob.task_id.is_not(None),
                    BackgroundJob.cancellation_requested_at.is_(None),
                    or_(
                        and_(
                            BackgroundJob.status == BackgroundJobStatus.QUEUED,
                            BackgroundJob.attempt_count < BackgroundJob.max_attempts,
                            BackgroundJob.available_at <= scan_time,
                        ),
                        and_(
                            BackgroundJob.status == BackgroundJobStatus.RUNNING,
                            BackgroundJob.lease_expires_at.is_not(None),
                            BackgroundJob.lease_expires_at <= scan_time,
                        ),
                    ),
                )
                query = (
                    select(BackgroundJob)
                    .where(eligible)
                    .order_by(
                        BackgroundJob.available_at,
                        BackgroundJob.created_at,
                        BackgroundJob.id,
                    )
                    .limit(1)
                )
                if normalized_types:
                    query = query.where(BackgroundJob.job_type.in_(normalized_types))
                if session.get_bind().dialect.name == "postgresql":
                    query = query.with_for_update(skip_locked=True)
                else:
                    query = query.with_for_update()
                job = session.scalar(query)
                if job is None:
                    return None

                recovered = job.status == BackgroundJobStatus.RUNNING
                previous: BackgroundJobLease | None = None
                if recovered:
                    previous = session.scalar(
                        select(BackgroundJobLease)
                        .where(
                            BackgroundJobLease.id == job.current_lease_id,
                            BackgroundJobLease.job_id == job.id,
                            BackgroundJobLease.fencing_token == job.current_fencing_token,
                        )
                        .with_for_update()
                    )
                    if previous is None:
                        raise BackgroundJobConflictError(
                            "background job active lease projection is corrupt"
                        )
                now = _as_utc(self._clock())
                if (
                    recovered
                    and job.lease_expires_at is not None
                    and _as_utc(job.lease_expires_at) > now
                ):
                    return None
                if previous is not None:
                    previous.released_at = now
                    previous.actor_id = self._principal_id
                    previous.updated_at = now
                    if job.attempt_count >= job.max_attempts:
                        previous.release_reason = "EXPIRED"
                        previous.failure_code = "LEASE_EXPIRED_ATTEMPTS_EXHAUSTED"
                        session.flush((previous,))
                        _finish_job(
                            job,
                            status=BackgroundJobStatus.FAILED,
                            error_code="LEASE_EXPIRED_ATTEMPTS_EXHAUSTED",
                            token=previous.fencing_token,
                            completed_at=now,
                            principal_id=self._principal_id,
                        )
                        session.flush()
                        continue
                    previous.release_reason = "SUPERSEDED"
                    session.flush()

                counter = _ensure_fencing_counter(session)
                now = _as_utc(self._clock())
                token = counter.next_token
                counter.next_token = token + 1
                attempt = job.attempt_count + 1
                lease_id = uuid4()
                expires_at = now + duration
                lease = BackgroundJobLease(
                    id=lease_id,
                    job_id=job.id,
                    lease_owner=normalized_worker,
                    attempt=attempt,
                    fencing_token=token,
                    idempotency_key=f"{job.id}:lease:{attempt}",
                    lease_protocol_version=1,
                    claim_fingerprint=_lease_fingerprint(
                        job,
                        lease_id=lease_id,
                        worker_id=normalized_worker,
                        attempt=attempt,
                        token=token,
                    ),
                    heartbeat_at=now,
                    expires_at=expires_at,
                    checkpoint=None if job.checkpoint is None else dict(job.checkpoint),
                    checkpoint_version=job.checkpoint_version,
                    owner_id=job.owner_id,
                    actor_id=self._principal_id,
                    root_correlation_id=job.root_correlation_id,
                )
                session.add(lease)
                session.flush()
                job.status = BackgroundJobStatus.RUNNING
                job.attempt_count = attempt
                job.current_lease_id = lease.id
                job.current_fencing_token = token
                job.lease_owner = normalized_worker
                job.lease_expires_at = expires_at
                job.last_fencing_token = token
                job.last_error_code = None
                job.actor_id = self._principal_id
                job.updated_at = now
                session.flush()
                return _grant(job, lease, recovered=recovered)

    def heartbeat(
        self,
        grant: JobLeaseGrant,
        *,
        lease_duration: timedelta,
    ) -> JobLeaseGrant:
        duration = _lease_duration(lease_duration)
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            job, lease, now = _current_lease(
                session,
                grant,
                clock=self._clock,
            )
            expires_at = max(_as_utc(lease.expires_at), now + duration)
            lease.heartbeat_at = now
            lease.expires_at = expires_at
            lease.actor_id = self._principal_id
            lease.updated_at = now
            session.flush()
            job.lease_expires_at = expires_at
            job.last_fencing_token = grant.fencing_token
            job.actor_id = self._principal_id
            job.updated_at = now
            session.flush()
            return _grant(job, lease, recovered=grant.recovered)

    def checkpoint(
        self,
        grant: JobLeaseGrant,
        *,
        expected_version: int,
        idempotency_key: str,
        payload: Mapping[str, object],
    ) -> JobCheckpointResult:
        normalized_key = _required_identifier(
            idempotency_key,
            field="checkpoint idempotency key",
            maximum=MAX_IDEMPOTENCY_KEY_LENGTH,
        )
        normalized_payload = _safe_payload(payload, field="checkpoint")
        fingerprint = _fingerprint(normalized_payload)
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            job, lease, now = _current_lease(
                session,
                grant,
                clock=self._clock,
            )
            return _append_checkpoint(
                session,
                job,
                lease,
                expected_version=expected_version,
                idempotency_key=normalized_key,
                payload=normalized_payload,
                fingerprint=fingerprint,
                principal_id=self._principal_id,
                now=now,
            )

    def prepare_effect(
        self,
        grant: JobLeaseGrant,
        *,
        effect_key: str,
        effect_type: str,
        request_payload: Mapping[str, object],
    ) -> PreparedJobEffect:
        normalized_effect_key = _required_identifier(
            effect_key,
            field="effect key",
            maximum=MAX_JOB_IDENTIFIER_LENGTH,
        )
        normalized_type = _required_identifier(
            effect_type,
            field="effect type",
            maximum=MAX_JOB_IDENTIFIER_LENGTH,
        )
        payload = _safe_payload(request_payload, field="effect request")
        request_fingerprint = _fingerprint(
            {
                "effect_type": normalized_type,
                "effect_key": normalized_effect_key,
                "request_payload": payload,
            }
        )
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            job, lease, now = _current_lease(
                session,
                grant,
                clock=self._clock,
            )
            provider_key = f"{job.id}:{normalized_effect_key}"
            pending = session.scalar(
                select(BackgroundJobEffect)
                .where(
                    BackgroundJobEffect.job_id == job.id,
                    BackgroundJobEffect.status == BackgroundJobEffectStatus.PENDING,
                )
                .order_by(BackgroundJobEffect.started_at, BackgroundJobEffect.id)
                .with_for_update()
            )
            if pending is not None and pending.idempotency_key != provider_key:
                raise AmbiguousBackgroundJobEffectError(
                    "a prepared background job effect must be reconciled first"
                )
            existing = pending or session.scalar(
                select(BackgroundJobEffect)
                .where(BackgroundJobEffect.idempotency_key == provider_key)
                .with_for_update()
            )
            if existing is not None:
                if (
                    existing.job_id != job.id
                    or existing.effect_type != normalized_type
                    or existing.request_fingerprint != request_fingerprint
                    or existing.request_payload != payload
                ):
                    raise BackgroundJobConflictError(
                        "background job effect key was used for a different request"
                    )
                return _prepared_effect(
                    existing,
                    created=False,
                    needs_reconciliation=(existing.status == BackgroundJobEffectStatus.PENDING),
                )
            effect = BackgroundJobEffect(
                job_id=job.id,
                effect_type=normalized_type,
                idempotency_key=provider_key,
                request_fingerprint=request_fingerprint,
                request_payload=payload,
                status=BackgroundJobEffectStatus.PENDING,
                started_lease_id=lease.id,
                started_fencing_token=lease.fencing_token,
                started_at=now,
                owner_id=job.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=job.root_correlation_id,
            )
            session.add(effect)
            session.flush()
            return _prepared_effect(
                effect,
                created=True,
                needs_reconciliation=False,
            )

    def record_effect_result(
        self,
        grant: JobLeaseGrant,
        *,
        effect_id: UUID,
        result: EffectExecutionResult,
        expected_checkpoint_version: int,
        checkpoint_idempotency_key: str,
        checkpoint_payload: Mapping[str, object],
    ) -> JobCheckpointResult:
        normalized_checkpoint_key = _required_identifier(
            checkpoint_idempotency_key,
            field="checkpoint idempotency key",
            maximum=MAX_IDEMPOTENCY_KEY_LENGTH,
        )
        normalized_result = _safe_payload(result.payload, field="effect result")
        normalized_checkpoint = _safe_payload(
            checkpoint_payload,
            field="checkpoint",
        )
        checkpoint_fingerprint = _fingerprint(normalized_checkpoint)
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            job, lease, now = _current_lease(
                session,
                grant,
                clock=self._clock,
            )
            effect = session.scalar(
                select(BackgroundJobEffect)
                .where(
                    BackgroundJobEffect.id == effect_id,
                    BackgroundJobEffect.job_id == job.id,
                )
                .with_for_update()
            )
            if effect is None:
                raise BackgroundJobNotFoundError("background job effect is unavailable")
            target_status = (
                BackgroundJobEffectStatus.SUCCEEDED
                if result.succeeded
                else BackgroundJobEffectStatus.FAILED
            )
            if effect.status != BackgroundJobEffectStatus.PENDING:
                if effect.status != target_status or effect.result_payload != normalized_result:
                    raise BackgroundJobConflictError("background job effect result conflicts")
            else:
                effect.status = target_status
                effect.completion_lease_id = lease.id
                effect.completion_fencing_token = lease.fencing_token
                effect.result_payload = normalized_result
                effect.completed_at = now
                effect.actor_id = self._principal_id
                effect.updated_at = now
                session.flush()
            return _append_checkpoint(
                session,
                job,
                lease,
                expected_version=expected_checkpoint_version,
                idempotency_key=normalized_checkpoint_key,
                payload=normalized_checkpoint,
                fingerprint=checkpoint_fingerprint,
                principal_id=self._principal_id,
                now=now,
            )

    def complete(
        self,
        grant: JobLeaseGrant,
        *,
        expected_checkpoint_version: int,
        final_checkpoint_key: str | None = None,
        final_checkpoint: Mapping[str, object] | None = None,
    ) -> None:
        if (final_checkpoint_key is None) != (final_checkpoint is None):
            raise InvalidBackgroundJobError("background job final checkpoint is incomplete")
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            job, lease, now = _current_lease(
                session,
                grant,
                clock=self._clock,
            )
            _require_no_pending_effects(session, job.id)
            if final_checkpoint is not None and final_checkpoint_key is not None:
                normalized_key = _required_identifier(
                    final_checkpoint_key,
                    field="checkpoint idempotency key",
                    maximum=MAX_IDEMPOTENCY_KEY_LENGTH,
                )
                payload = _safe_payload(final_checkpoint, field="checkpoint")
                _append_checkpoint(
                    session,
                    job,
                    lease,
                    expected_version=expected_checkpoint_version,
                    idempotency_key=normalized_key,
                    payload=payload,
                    fingerprint=_fingerprint(payload),
                    principal_id=self._principal_id,
                    now=now,
                )
                session.flush()
            elif job.checkpoint_version != expected_checkpoint_version:
                raise BackgroundJobConflictError("background job checkpoint version changed")
            lease.released_at = now
            lease.release_reason = "SUCCEEDED"
            lease.actor_id = self._principal_id
            lease.updated_at = now
            session.flush()
            _finish_job(
                job,
                status=BackgroundJobStatus.SUCCEEDED,
                error_code=None,
                token=grant.fencing_token,
                completed_at=now,
                principal_id=self._principal_id,
            )
            session.flush()

    def fail_attempt(
        self,
        grant: JobLeaseGrant,
        *,
        error_code: str,
        retryable: bool,
    ) -> JobFailureDisposition:
        normalized_code = _required_error_code(error_code)
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            job, lease, now = _current_lease(
                session,
                grant,
                clock=self._clock,
            )
            policy = RetryPolicy(
                max_attempts=job.max_attempts,
                base_delay_seconds=job.retry_base_seconds,
                max_delay_seconds=job.retry_max_seconds,
            )
            can_retry = retryable and job.attempt_count < job.max_attempts
            delay = (
                deterministic_retry_delay(job.id, job.attempt_count, policy) if can_retry else None
            )
            retry_at = None if delay is None else now + delay
            lease.released_at = now
            lease.release_reason = "RETRY" if can_retry else "FAILED"
            lease.retry_at = retry_at
            lease.failure_code = normalized_code
            lease.actor_id = self._principal_id
            lease.updated_at = now
            session.flush()
            if can_retry:
                if retry_at is None:
                    raise BackgroundJobConflictError("background job retry schedule is unavailable")
                job.status = BackgroundJobStatus.QUEUED
                job.available_at = retry_at
                job.completed_at = None
            else:
                job.status = BackgroundJobStatus.FAILED
                job.completed_at = now
            job.current_lease_id = None
            job.current_fencing_token = None
            job.lease_owner = None
            job.lease_expires_at = None
            job.last_fencing_token = grant.fencing_token
            job.last_error_code = normalized_code
            job.actor_id = self._principal_id
            job.updated_at = now
            session.flush()
            return JobFailureDisposition(
                status=BackgroundJobStatus.QUEUED if can_retry else BackgroundJobStatus.FAILED,
                next_attempt_at=retry_at,
                exhausted=retryable and not can_retry,
                retry_delay=delay,
            )

    def pending_effects(
        self,
        grant: JobLeaseGrant,
    ) -> tuple[PreparedJobEffect, ...]:
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            job, _lease, _now = _current_lease(
                session,
                grant,
                clock=self._clock,
            )
            effects = tuple(
                session.scalars(
                    select(BackgroundJobEffect)
                    .where(
                        BackgroundJobEffect.job_id == job.id,
                        BackgroundJobEffect.status == BackgroundJobEffectStatus.PENDING,
                    )
                    .order_by(BackgroundJobEffect.started_at, BackgroundJobEffect.id)
                )
            )
            return tuple(
                _prepared_effect(
                    effect,
                    created=False,
                    needs_reconciliation=True,
                )
                for effect in effects
            )

    def transition_task(
        self,
        grant: JobLeaseGrant,
        *,
        transition_id: UUID,
        expected_state: TaskState,
        kind: TaskTransitionKind,
        reason_code: str,
        evidence_ids: Sequence[UUID],
        active_policy_lineage: str = "mvp",
    ) -> TaskTransitionResult:
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            job, lease, now = _current_lease(
                session,
                grant,
                clock=self._clock,
            )
            if job.task_id is None or job.task_id != grant.task_id:
                raise BackgroundJobConflictError("background job task binding changed")
            _require_no_pending_effects(session, job.id)
            result = _transition_task(
                session,
                self._artifact_store,
                task_id=grant.task_id,
                transition_id=transition_id,
                expected_state=expected_state,
                kind=kind,
                reason_code=reason_code,
                actor_id=self._principal_id,
                evidence_ids=evidence_ids,
                gate_evaluator=self._gate_evaluator,
                active_policy_lineage=active_policy_lineage,
                occurred_at=now,
            )
            if result.replayed:
                provenance = session.scalar(
                    select(BackgroundJobTaskTransition).where(
                        BackgroundJobTaskTransition.task_event_id == result.event_id
                    )
                )
                if (
                    provenance is None
                    or provenance.job_id != job.id
                    or provenance.task_id != grant.task_id
                ):
                    raise BackgroundJobConflictError(
                        "background job transition id belongs to another source"
                    )
            else:
                session.add(
                    BackgroundJobTaskTransition(
                        job_id=job.id,
                        lease_id=lease.id,
                        fencing_token=lease.fencing_token,
                        task_id=grant.task_id,
                        task_event_id=result.event_id,
                        recorded_at=now,
                        owner_id=job.owner_id,
                        actor_id=self._principal_id,
                        root_correlation_id=job.root_correlation_id,
                    )
                )
                session.flush()
            return result


def _lease_duration(value: timedelta) -> timedelta:
    seconds = value.total_seconds()
    if seconds < 1 or seconds > MAX_LEASE_SECONDS:
        raise InvalidBackgroundJobError(
            "background job lease duration must be between 1 and 300 seconds"
        )
    return timedelta(microseconds=int(seconds * 1_000_000))


def _current_lease(
    session: Session,
    grant: JobLeaseGrant,
    *,
    clock: Callable[[], datetime],
) -> tuple[BackgroundJob, BackgroundJobLease, datetime]:
    job = session.scalar(
        select(BackgroundJob).where(BackgroundJob.id == grant.job_id).with_for_update()
    )
    if (
        job is None
        or job.status != BackgroundJobStatus.RUNNING
        or job.task_id != grant.task_id
        or job.current_lease_id != grant.lease_id
        or job.current_fencing_token != grant.fencing_token
        or job.lease_owner != grant.worker_id
        or job.lease_expires_at is None
        or job.cancellation_requested_at is not None
    ):
        raise BackgroundJobLeaseLostError("background job lease is no longer current")
    lease = session.scalar(
        select(BackgroundJobLease)
        .where(
            BackgroundJobLease.id == grant.lease_id,
            BackgroundJobLease.job_id == grant.job_id,
            BackgroundJobLease.lease_owner == grant.worker_id,
            BackgroundJobLease.attempt == grant.attempt,
            BackgroundJobLease.fencing_token == grant.fencing_token,
        )
        .with_for_update()
    )
    now = _as_utc(clock())
    if (
        lease is None
        or lease.released_at is not None
        or _as_utc(job.lease_expires_at) <= now
        or _as_utc(lease.expires_at) <= now
    ):
        raise BackgroundJobLeaseLostError("background job lease is no longer current")
    return job, lease, now


def _append_checkpoint(
    session: Session,
    job: BackgroundJob,
    lease: BackgroundJobLease,
    *,
    expected_version: int,
    idempotency_key: str,
    payload: dict[str, object],
    fingerprint: str,
    principal_id: str,
    now: datetime,
) -> JobCheckpointResult:
    existing = session.scalar(
        select(BackgroundJobCheckpoint)
        .where(BackgroundJobCheckpoint.idempotency_key == idempotency_key)
        .with_for_update()
    )
    target_sequence = expected_version + 1
    if existing is not None:
        if (
            existing.job_id != job.id
            or existing.sequence != target_sequence
            or existing.payload_fingerprint != fingerprint
            or existing.payload != payload
        ):
            raise BackgroundJobConflictError(
                "background job checkpoint key was used for different progress"
            )
        return JobCheckpointResult(
            checkpoint_id=existing.id,
            sequence=existing.sequence,
            replayed=True,
        )
    if job.checkpoint_version != expected_version:
        raise BackgroundJobConflictError("background job checkpoint version changed")
    checkpoint = BackgroundJobCheckpoint(
        job_id=job.id,
        lease_id=lease.id,
        fencing_token=lease.fencing_token,
        sequence=target_sequence,
        idempotency_key=idempotency_key,
        payload_fingerprint=fingerprint,
        payload=payload,
        recorded_at=now,
        owner_id=job.owner_id,
        actor_id=principal_id,
        root_correlation_id=job.root_correlation_id,
    )
    session.add(checkpoint)
    session.flush()
    job.checkpoint = payload
    job.checkpoint_version = target_sequence
    job.last_fencing_token = lease.fencing_token
    job.actor_id = principal_id
    job.updated_at = now
    lease.checkpoint = payload
    lease.checkpoint_version = target_sequence
    lease.actor_id = principal_id
    lease.updated_at = now
    session.flush()
    return JobCheckpointResult(
        checkpoint_id=checkpoint.id,
        sequence=checkpoint.sequence,
        replayed=False,
    )


def _require_no_pending_effects(session: Session, job_id: UUID) -> None:
    pending = session.scalar(
        select(BackgroundJobEffect.id)
        .where(
            BackgroundJobEffect.job_id == job_id,
            BackgroundJobEffect.status == BackgroundJobEffectStatus.PENDING,
        )
        .limit(1)
        .with_for_update()
    )
    if pending is not None:
        raise AmbiguousBackgroundJobEffectError(
            "a prepared background job effect must be reconciled first"
        )


def _prepared_effect(
    effect: BackgroundJobEffect,
    *,
    created: bool,
    needs_reconciliation: bool,
) -> PreparedJobEffect:
    return PreparedJobEffect(
        effect_id=effect.id,
        idempotency_key=effect.idempotency_key,
        effect_type=effect.effect_type,
        request_payload=dict(effect.request_payload),
        status=BackgroundJobEffectStatus(effect.status),
        result_payload=(None if effect.result_payload is None else dict(effect.result_payload)),
        created=created,
        needs_reconciliation=needs_reconciliation,
    )


def _finish_job(
    job: BackgroundJob,
    *,
    status: BackgroundJobStatus,
    error_code: str | None,
    token: int,
    completed_at: datetime,
    principal_id: str,
) -> None:
    job.status = status
    job.current_lease_id = None
    job.current_fencing_token = None
    job.lease_owner = None
    job.lease_expires_at = None
    job.last_fencing_token = token
    job.last_error_code = error_code
    job.completed_at = completed_at
    job.actor_id = principal_id
    job.updated_at = completed_at


@dataclass(slots=True)
class LeasedJobContext:
    """Handler-facing facade that exposes only fenced durable operations."""

    service: BackgroundJobService
    grant: JobLeaseGrant

    def heartbeat(self, lease_duration: timedelta) -> JobLeaseGrant:
        self.grant = self.service.heartbeat(
            self.grant,
            lease_duration=lease_duration,
        )
        return self.grant

    def checkpoint(
        self,
        *,
        idempotency_key: str,
        payload: Mapping[str, object],
    ) -> JobCheckpointResult:
        result = self.service.checkpoint(
            self.grant,
            expected_version=self.grant.checkpoint_version,
            idempotency_key=idempotency_key,
            payload=payload,
        )
        self.grant = replace(
            self.grant,
            checkpoint=dict(payload),
            checkpoint_version=result.sequence,
        )
        return result

    def perform_effect(
        self,
        *,
        effect_key: str,
        effect_type: str,
        request_payload: Mapping[str, object],
        executor: BackgroundJobEffectExecutor,
        checkpoint_idempotency_key: str,
        checkpoint_payload: Mapping[str, object],
    ) -> EffectExecutionResult:
        prepared = self.service.prepare_effect(
            self.grant,
            effect_key=effect_key,
            effect_type=effect_type,
            request_payload=request_payload,
        )
        if prepared.status != BackgroundJobEffectStatus.PENDING:
            return EffectExecutionResult(
                succeeded=prepared.status == BackgroundJobEffectStatus.SUCCEEDED,
                payload=prepared.result_payload or {},
            )
        if prepared.created:
            observation = executor.execute(
                idempotency_key=prepared.idempotency_key,
                effect_type=prepared.effect_type,
                request_payload=prepared.request_payload,
            )
        else:
            reconciled = executor.reconcile(
                idempotency_key=prepared.idempotency_key,
                effect_type=prepared.effect_type,
                request_payload=prepared.request_payload,
            )
            if reconciled is None:
                raise AmbiguousBackgroundJobEffectError(
                    "prepared background job effect requires reconciliation"
                )
            observation = reconciled
        checkpoint = self.service.record_effect_result(
            self.grant,
            effect_id=prepared.effect_id,
            result=observation,
            expected_checkpoint_version=self.grant.checkpoint_version,
            checkpoint_idempotency_key=checkpoint_idempotency_key,
            checkpoint_payload=checkpoint_payload,
        )
        self.grant = replace(
            self.grant,
            checkpoint=dict(checkpoint_payload),
            checkpoint_version=checkpoint.sequence,
        )
        return observation


class DurableJobWorker:
    """One-poll worker that dispatches only explicitly registered job types."""

    def __init__(
        self,
        service: BackgroundJobService,
        handlers: Mapping[str, BackgroundJobHandler],
        *,
        worker_id: str,
        lease_duration: timedelta = timedelta(seconds=30),
    ) -> None:
        self._service = service
        self._handlers = dict(handlers)
        self._worker_id = _required_identifier(
            worker_id,
            field="worker",
            maximum=255,
        )
        self._lease_duration = _lease_duration(lease_duration)

    def run_once(self) -> WorkerRunOutcome:
        if not self._handlers:
            return WorkerRunOutcome.IDLE
        grant = self._service.claim_next(
            worker_id=self._worker_id,
            lease_duration=self._lease_duration,
            job_types=tuple(self._handlers),
        )
        if grant is None:
            return WorkerRunOutcome.IDLE
        handler = self._handlers.get(grant.job_type)
        if handler is None:
            self._service.fail_attempt(
                grant,
                error_code="UNSUPPORTED_JOB_TYPE",
                retryable=False,
            )
            return WorkerRunOutcome.FAILED
        context = LeasedJobContext(self._service, grant)
        try:
            final_checkpoint = handler(context)
            self._service.complete(
                context.grant,
                expected_checkpoint_version=context.grant.checkpoint_version,
                final_checkpoint_key=(
                    None if final_checkpoint is None else f"{context.grant.job_id}:complete"
                ),
                final_checkpoint=final_checkpoint,
            )
        except BackgroundJobLeaseLostError:
            return WorkerRunOutcome.LEASE_LOST
        except AmbiguousBackgroundJobEffectError:
            disposition = self._record_failure(
                context.grant,
                error_code="AMBIGUOUS_EXTERNAL_EFFECT",
                retryable=True,
            )
            if disposition is None:
                return WorkerRunOutcome.LEASE_LOST
            return (
                WorkerRunOutcome.RETRY_SCHEDULED
                if disposition.status == BackgroundJobStatus.QUEUED
                else WorkerRunOutcome.FAILED
            )
        except RetryableBackgroundJobError as error:
            disposition = self._record_failure(
                context.grant,
                error_code=error.error_code,
                retryable=True,
            )
            if disposition is None:
                return WorkerRunOutcome.LEASE_LOST
            return (
                WorkerRunOutcome.RETRY_SCHEDULED
                if disposition.status == BackgroundJobStatus.QUEUED
                else WorkerRunOutcome.FAILED
            )
        except TerminalBackgroundJobError as error:
            disposition = self._record_failure(
                context.grant,
                error_code=error.error_code,
                retryable=False,
            )
            return (
                WorkerRunOutcome.FAILED if disposition is not None else WorkerRunOutcome.LEASE_LOST
            )
        except Exception:
            disposition = self._record_failure(
                context.grant,
                error_code="UNEXPECTED_HANDLER_FAILURE",
                retryable=True,
            )
            if disposition is None:
                return WorkerRunOutcome.LEASE_LOST
            return (
                WorkerRunOutcome.RETRY_SCHEDULED
                if disposition.status == BackgroundJobStatus.QUEUED
                else WorkerRunOutcome.FAILED
            )
        return WorkerRunOutcome.SUCCEEDED

    def _record_failure(
        self,
        grant: JobLeaseGrant,
        *,
        error_code: str,
        retryable: bool,
    ) -> JobFailureDisposition | None:
        try:
            return self._service.fail_attempt(
                grant,
                error_code=error_code,
                retryable=retryable,
            )
        except BackgroundJobLeaseLostError:
            return None
