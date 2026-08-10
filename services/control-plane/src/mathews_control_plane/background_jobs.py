"""Durable leased background jobs with fencing and effect reconciliation."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, cast
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, aliased

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    ApprovalRequest,
    BackgroundJob,
    BackgroundJobCheckpoint,
    BackgroundJobEffect,
    BackgroundJobEffectStatus,
    BackgroundJobFencingCounter,
    BackgroundJobIgnoredResult,
    BackgroundJobLease,
    BackgroundJobStatus,
    BackgroundJobTaskTransition,
    BackgroundJobToolGrant,
    DependencyOutageAttempt,
    DependencyService,
    OwnedHostProcess,
    OwnedHostProcessStatus,
    ReconciliationStatus,
    ReconciliationTarget,
    ReconciliationTargetKind,
    Task,
    TaskState,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
    redact_evidence_content,
)
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
MAX_RECOVERY_BATCH_SIZE = 1000

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]*\Z")
_ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,99}\Z")
_LOGGER = logging.getLogger(__name__)


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


class PausedBackgroundJobError(BackgroundJobError):
    """A handler pause that releases its lease without consuming an attempt."""

    def __init__(self, error_code: str) -> None:
        self.error_code = _required_error_code(error_code)
        super().__init__(self.error_code)


class TerminalBackgroundJobError(BackgroundJobError):
    """A handler failure that must not be retried."""

    def __init__(self, error_code: str) -> None:
        self.error_code = _required_error_code(error_code)
        super().__init__(self.error_code)


class DependencyOutageError(BackgroundJobError):
    """A host, Hermes, or GitHub failure governed by bounded outage retry."""

    def __init__(self, service: DependencyService, error_code: str) -> None:
        self.service = service
        self.error_code = _required_error_code(error_code)
        super().__init__(f"{service.value}:{self.error_code}")


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
    escalation_request_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class ToolGrantResult:
    """Stable identity for one lease-bound Hermes capability."""

    grant_id: UUID
    replayed: bool


@dataclass(frozen=True, slots=True)
class OwnedProcessResult:
    """Stable identity for one host-owned process group."""

    process_id: UUID
    ownership_nonce: UUID
    replayed: bool


@dataclass(frozen=True, slots=True)
class IgnoredResult:
    """Evidence reference for a late result that could not mutate job truth."""

    ignored_result_id: UUID
    evidence_id: UUID
    reason_code: str
    replayed: bool


@dataclass(frozen=True, slots=True)
class ReconciliationTargetResult:
    """Stable identity for an external state startup must observe."""

    target_id: UUID
    replayed: bool


class WorkerRunOutcome(StrEnum):
    """One bounded worker poll result."""

    IDLE = "IDLE"
    SUCCEEDED = "SUCCEEDED"
    RETRY_SCHEDULED = "RETRY_SCHEDULED"
    ESCALATED = "ESCALATED"
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


def _bounded_evidence_payload(
    value: Mapping[str, object],
    *,
    maximum_bytes: int = 256 * 1024,
) -> dict[str, object]:
    """Keep operational evidence below the envelope limit without losing identity."""

    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError):
        raise InvalidBackgroundJobError(
            "background job evidence is not JSON serializable"
        ) from None
    if len(encoded) <= maximum_bytes:
        return dict(value)
    bounded: dict[str, object] = {}
    for key in sorted(value)[:64]:
        child = value[key]
        if child is None or isinstance(child, bool | int | float):
            bounded[key] = child
        elif isinstance(child, str):
            bounded[key] = child[:2048]
        else:
            bounded[key] = {
                "truncated": True,
                "value_type": type(child).__name__,
            }
    bounded["_truncation"] = {
        "byte_count": len(encoded),
        "field_count": len(value),
        "truncated": True,
    }
    return bounded


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
        task_validator: Callable[[Session, Task], None] | None = None,
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
            if task_validator is not None:
                task_validator(session, task)
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
            if TaskState(task.state) in {
                TaskState.BRIEF_PENDING_APPROVAL,
                TaskState.ESCALATED,
                TaskState.HANDED_OFF,
                TaskState.FAILED,
                TaskState.CANCELLED,
            }:
                raise BackgroundJobConflictError(
                    "background job task is not runnable"
                )
            unresolved_outage = session.scalar(
                select(DependencyOutageAttempt.id)
                .join(
                    BackgroundJob,
                    BackgroundJob.id
                    == DependencyOutageAttempt.job_id,
                )
                .where(
                    BackgroundJob.task_id == task.id,
                    DependencyOutageAttempt.exhausted.is_(True),
                    DependencyOutageAttempt.resolved_at.is_(None),
                )
                .limit(1)
            )
            if unresolved_outage is not None:
                raise BackgroundJobConflictError(
                    "background job task has an unresolved outage"
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
            outage_job = aliased(BackgroundJob)
            reconciliation_job = aliased(BackgroundJob)
            while True:
                scan_time = _as_utc(self._clock())
                eligible = and_(
                    BackgroundJob.task_id.is_not(None),
                    BackgroundJob.cancellation_requested_at.is_(None),
                    exists().where(
                        Task.id == BackgroundJob.task_id,
                        Task.state.not_in(
                            (
                                TaskState.BRIEF_PENDING_APPROVAL,
                                TaskState.ESCALATED,
                                TaskState.HANDED_OFF,
                                TaskState.FAILED,
                                TaskState.CANCELLED,
                            )
                        ),
                    ),
                    ~exists().where(
                        DependencyOutageAttempt.exhausted.is_(True),
                        DependencyOutageAttempt.resolved_at.is_(None),
                        outage_job.id
                        == DependencyOutageAttempt.job_id,
                        outage_job.task_id == BackgroundJob.task_id,
                    ),
                    ~exists().where(
                        or_(
                            ReconciliationTarget.job_id
                            == BackgroundJob.id,
                            ReconciliationTarget.task_id
                            == BackgroundJob.task_id,
                        ),
                        # PENDING is the normal live registration state.
                        # Startup observes it before polling and promotes any
                        # unresolved target to a blocking status below.
                        ReconciliationTarget.status.in_(
                            (
                                ReconciliationStatus.UPDATED,
                                ReconciliationStatus.RETRY_REQUIRED,
                                ReconciliationStatus.QUARANTINED,
                            )
                        ),
                    ),
                    # A PENDING target becomes a restart fence only after its
                    # owning lease expires; live registrations must not stall
                    # unrelated queued work on the same task.
                    ~exists().where(
                        ReconciliationTarget.status
                        == ReconciliationStatus.PENDING,
                        reconciliation_job.id
                        == ReconciliationTarget.job_id,
                        reconciliation_job.task_id
                        == BackgroundJob.task_id,
                        reconciliation_job.status
                        == BackgroundJobStatus.RUNNING,
                        reconciliation_job.lease_expires_at.is_not(None),
                        reconciliation_job.lease_expires_at <= scan_time,
                    ),
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
                attempt_count = job.attempt_count + 1
                lease_attempt = (
                    session.scalar(
                        select(func.max(BackgroundJobLease.attempt)).where(
                            BackgroundJobLease.job_id == job.id
                        )
                    )
                    or 0
                ) + 1
                lease_id = uuid4()
                expires_at = now + duration
                lease = BackgroundJobLease(
                    id=lease_id,
                    job_id=job.id,
                    lease_owner=normalized_worker,
                    attempt=lease_attempt,
                    fencing_token=token,
                    idempotency_key=f"{job.id}:lease:{lease_attempt}",
                    lease_protocol_version=1,
                    claim_fingerprint=_lease_fingerprint(
                        job,
                        lease_id=lease_id,
                        worker_id=normalized_worker,
                        attempt=lease_attempt,
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
                job.attempt_count = attempt_count
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

    def reconcile_expired_leases(
        self,
        *,
        limit: int = 100,
    ) -> tuple[UUID, ...]:
        """Release expired ownership without issuing any replacement effect."""

        if not 1 <= limit <= MAX_RECOVERY_BATCH_SIZE:
            raise InvalidBackgroundJobError(
                "background job recovery limit must be between 1 and 1000"
            )
        recovered: list[UUID] = []
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            now = _as_utc(self._clock())
            query = (
                select(BackgroundJob)
                .where(
                    BackgroundJob.status == BackgroundJobStatus.RUNNING,
                    BackgroundJob.lease_expires_at.is_not(None),
                    BackgroundJob.lease_expires_at <= now,
                )
                .order_by(
                    BackgroundJob.lease_expires_at,
                    BackgroundJob.created_at,
                    BackgroundJob.id,
                )
                .limit(limit)
            )
            if session.get_bind().dialect.name == "postgresql":
                query = query.with_for_update(skip_locked=True)
            else:
                query = query.with_for_update()
            for job in session.scalars(query):
                lease = session.scalar(
                    select(BackgroundJobLease)
                    .where(
                        BackgroundJobLease.id == job.current_lease_id,
                        BackgroundJobLease.job_id == job.id,
                        BackgroundJobLease.fencing_token
                        == job.current_fencing_token,
                    )
                    .with_for_update()
                )
                if lease is None or lease.released_at is not None:
                    raise BackgroundJobConflictError(
                        "background job active lease projection is corrupt"
                    )
                cancelled = job.cancellation_requested_at is not None
                exhausted = job.attempt_count >= job.max_attempts
                lease.released_at = now
                lease.release_reason = "CANCELLED" if cancelled else "EXPIRED"
                lease.failure_code = (
                    "CANCELLATION_REQUESTED"
                    if cancelled
                    else (
                        "LEASE_EXPIRED_ATTEMPTS_EXHAUSTED"
                        if exhausted
                        else "LEASE_EXPIRED"
                    )
                )
                lease.cancellation_acknowledged_at = now if cancelled else None
                lease.actor_id = self._principal_id
                lease.updated_at = now
                session.flush((lease,))
                if cancelled:
                    target_status = BackgroundJobStatus.CANCELLED
                    completed_at = now
                elif exhausted:
                    target_status = BackgroundJobStatus.FAILED
                    completed_at = now
                else:
                    target_status = BackgroundJobStatus.QUEUED
                    completed_at = None
                    job.available_at = now
                _finish_job(
                    job,
                    status=target_status,
                    error_code=lease.failure_code,
                    token=lease.fencing_token,
                    completed_at=completed_at or now,
                    principal_id=self._principal_id,
                )
                if target_status is BackgroundJobStatus.QUEUED:
                    job.completed_at = None
                session.flush((job,))
                recovered.append(job.id)
        return tuple(recovered)

    def issue_tool_grant(
        self,
        grant: JobLeaseGrant,
        *,
        grant_key: str,
        capability_scope: Mapping[str, object],
    ) -> ToolGrantResult:
        """Persist a Hermes capability only while its lease fence is current."""

        normalized_key = _required_identifier(
            grant_key,
            field="tool grant key",
            maximum=MAX_IDEMPOTENCY_KEY_LENGTH,
        )
        normalized_scope = _safe_payload(
            capability_scope,
            field="tool grant scope",
        )
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            job, lease, now = _current_lease(
                session,
                grant,
                clock=self._clock,
            )
            existing = session.scalar(
                select(BackgroundJobToolGrant)
                .where(
                    BackgroundJobToolGrant.job_id == job.id,
                    BackgroundJobToolGrant.grant_key == normalized_key,
                )
                .with_for_update()
            )
            if existing is not None:
                if (
                    existing.lease_id != lease.id
                    or existing.fencing_token != lease.fencing_token
                    or existing.capability_scope != normalized_scope
                ):
                    raise BackgroundJobConflictError(
                        "background job tool grant key conflicts"
                    )
                return ToolGrantResult(grant_id=existing.id, replayed=True)
            tool_grant = BackgroundJobToolGrant(
                job_id=job.id,
                lease_id=lease.id,
                fencing_token=lease.fencing_token,
                grant_key=normalized_key,
                capability_scope=normalized_scope,
                issued_at=now,
                owner_id=job.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=job.root_correlation_id,
                causation_id=lease.id,
                parent_correlation_id=job.id,
            )
            session.add(tool_grant)
            session.flush()
            return ToolGrantResult(grant_id=tool_grant.id, replayed=False)

    def register_owned_process(
        self,
        grant: JobLeaseGrant,
        *,
        host_id: str,
        pid: int,
        process_group_id: int,
        birth_token: str,
        ownership_nonce: UUID,
    ) -> OwnedProcessResult:
        """Bind an exact host process identity to the current lease fence."""

        normalized_host = _required_identifier(
            host_id,
            field="host",
            maximum=255,
        )
        normalized_birth = _required_identifier(
            birth_token,
            field="process birth token",
            maximum=255,
        )
        if pid <= 1 or process_group_id <= 1:
            raise InvalidBackgroundJobError(
                "background job process identity is unsafe"
            )
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            job, lease, now = _current_lease(
                session,
                grant,
                clock=self._clock,
            )
            existing = session.scalar(
                select(OwnedHostProcess)
                .where(OwnedHostProcess.ownership_nonce == ownership_nonce)
                .with_for_update()
            )
            if existing is not None:
                if (
                    existing.job_id != job.id
                    or existing.lease_id != lease.id
                    or existing.fencing_token != lease.fencing_token
                    or existing.host_id != normalized_host
                    or existing.pid != pid
                    or existing.process_group_id != process_group_id
                    or existing.birth_token != normalized_birth
                ):
                    raise BackgroundJobConflictError(
                        "background job process ownership conflicts"
                    )
                return OwnedProcessResult(
                    process_id=existing.id,
                    ownership_nonce=existing.ownership_nonce,
                    replayed=True,
                )
            process = OwnedHostProcess(
                job_id=job.id,
                lease_id=lease.id,
                fencing_token=lease.fencing_token,
                host_id=normalized_host,
                pid=pid,
                process_group_id=process_group_id,
                birth_token=normalized_birth,
                ownership_nonce=ownership_nonce,
                status=OwnedHostProcessStatus.RUNNING,
                started_at=now,
                owner_id=job.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=job.root_correlation_id,
                causation_id=lease.id,
                parent_correlation_id=job.id,
            )
            session.add(process)
            session.flush()
            expected_payload = {
                "birth_token": process.birth_token,
                "host_id": process.host_id,
                "job_id": str(process.job_id),
                "ownership_nonce": str(process.ownership_nonce),
                "pid": process.pid,
                "process_group_id": process.process_group_id,
            }
            session.add(
                ReconciliationTarget(
                    task_id=job.task_id,
                    job_id=job.id,
                    kind=ReconciliationTargetKind.HOST_PROCESS,
                    target_key=f"process:{process.id}",
                    expected_payload=expected_payload,
                    expected_fingerprint=_fingerprint(expected_payload),
                    status=ReconciliationStatus.PENDING,
                    reconciliation_version=0,
                    owner_id=job.owner_id,
                    actor_id=self._principal_id,
                    root_correlation_id=job.root_correlation_id,
                    causation_id=process.id,
                    parent_correlation_id=job.id,
                )
            )
            session.flush()
            return OwnedProcessResult(
                process_id=process.id,
                ownership_nonce=process.ownership_nonce,
                replayed=False,
            )

    def register_reconciliation_target(
        self,
        grant: JobLeaseGrant,
        *,
        kind: ReconciliationTargetKind,
        target_key: str,
        expected_payload: Mapping[str, object],
    ) -> ReconciliationTargetResult:
        """Register exact external state before relying on it after restart."""

        normalized_key = _required_identifier(
            target_key,
            field="reconciliation target key",
            maximum=MAX_IDEMPOTENCY_KEY_LENGTH,
        )
        payload = _safe_payload(
            expected_payload,
            field="reconciliation expected state",
        )
        fingerprint = _fingerprint(payload)
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            job, lease, _now = _current_lease(
                session,
                grant,
                clock=self._clock,
            )
            existing = session.scalar(
                select(ReconciliationTarget)
                .where(
                    ReconciliationTarget.kind == kind,
                    ReconciliationTarget.target_key == normalized_key,
                )
                .with_for_update()
            )
            if existing is not None:
                if (
                    existing.task_id != job.task_id
                    or existing.job_id != job.id
                    or existing.expected_fingerprint != fingerprint
                    or existing.expected_payload != payload
                ):
                    raise BackgroundJobConflictError(
                        "background job reconciliation target conflicts"
                    )
                return ReconciliationTargetResult(
                    target_id=existing.id,
                    replayed=True,
                )
            target = ReconciliationTarget(
                task_id=job.task_id,
                job_id=job.id,
                kind=kind,
                target_key=normalized_key,
                expected_payload=payload,
                expected_fingerprint=fingerprint,
                status=ReconciliationStatus.PENDING,
                reconciliation_version=0,
                owner_id=job.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=job.root_correlation_id,
                causation_id=lease.id,
                parent_correlation_id=job.id,
            )
            session.add(target)
            session.flush()
            return ReconciliationTargetResult(
                target_id=target.id,
                replayed=False,
            )

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

    def record_ignored_result(
        self,
        grant: JobLeaseGrant,
        *,
        idempotency_key: str,
        effect_id: UUID | None,
        result: EffectExecutionResult,
    ) -> IgnoredResult:
        """Store a fenced late result as evidence without changing job state."""

        normalized_key = _required_identifier(
            idempotency_key,
            field="ignored result idempotency key",
            maximum=MAX_IDEMPOTENCY_KEY_LENGTH,
        )
        bounded_result = _bounded_evidence_payload(result.payload)
        prepared_result = redact_evidence_content(
            bounded_result,
            media_type="application/json",
        )
        normalized_result = prepared_result.value
        if not isinstance(normalized_result, dict):
            raise InvalidBackgroundJobError(
                "background job ignored effect result is invalid"
            )
        fingerprint = _fingerprint(
            {
                "effect_id": None if effect_id is None else str(effect_id),
                "lease_id": str(grant.lease_id),
                "result_fingerprint": _fingerprint(result.payload),
                "succeeded": result.succeeded,
            }
        )
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            job = session.scalar(
                select(BackgroundJob)
                .where(BackgroundJob.id == grant.job_id)
                .with_for_update()
            )
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
            if (
                job is None
                or lease is None
                or job.task_id != grant.task_id
            ):
                raise BackgroundJobNotFoundError(
                    "background job historical lease is unavailable"
                )
            now = _as_utc(self._clock())
            still_current = (
                job.status is BackgroundJobStatus.RUNNING
                and job.current_lease_id == grant.lease_id
                and job.current_fencing_token == grant.fencing_token
                and job.cancellation_requested_at is None
                and lease.released_at is None
                and job.lease_expires_at is not None
                and _as_utc(job.lease_expires_at) > now
                and _as_utc(lease.expires_at) > now
            )
            if still_current:
                raise BackgroundJobConflictError(
                    "background job result is not fenced"
                )
            if effect_id is not None:
                effect = session.scalar(
                    select(BackgroundJobEffect.id).where(
                        BackgroundJobEffect.id == effect_id,
                        BackgroundJobEffect.job_id == job.id,
                    )
                )
                if effect is None:
                    raise BackgroundJobNotFoundError(
                        "background job effect is unavailable"
                    )
            existing = session.scalar(
                select(BackgroundJobIgnoredResult)
                .where(
                    BackgroundJobIgnoredResult.idempotency_key
                    == normalized_key
                )
                .with_for_update()
            )
            reason_code = (
                "CANCELLED"
                if job.cancellation_requested_at is not None
                else "FENCED"
            )
            if existing is not None:
                if (
                    existing.job_id != job.id
                    or existing.lease_id != lease.id
                    or existing.fencing_token != lease.fencing_token
                    or existing.effect_id != effect_id
                    or existing.result_fingerprint != fingerprint
                    or existing.reason_code != reason_code
                ):
                    raise BackgroundJobConflictError(
                        "background job ignored result key conflicts"
                    )
                return IgnoredResult(
                    ignored_result_id=existing.id,
                    evidence_id=existing.evidence_id,
                    reason_code=existing.reason_code,
                    replayed=True,
                )
            ignored_id = uuid5(
                NAMESPACE_URL,
                f"mathews:ignored-result:{normalized_key}",
            )
            evidence_id = uuid5(
                NAMESPACE_URL,
                f"mathews:ignored-result-evidence:{normalized_key}",
            )
            captured = capture_evidence(
                session,
                self._artifact_store,
                payload={
                    "effect_id": (
                        None if effect_id is None else str(effect_id)
                    ),
                    "fencing_token": grant.fencing_token,
                    "job_id": str(job.id),
                    "lease_id": str(lease.id),
                    "reason_code": reason_code,
                    "result": _bounded_evidence_payload(
                        normalized_result
                    ),
                    "succeeded": result.succeeded,
                },
                media_type="application/json",
                source_kind=EvidenceSourceKind.RESULT,
                evidence_type="ignored-job-result",
                origin=f"background-job:{job.id}:late-result",
                access_classification=EvidenceAccessClass.TASK_OWNER,
                retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
                owner_id=job.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=job.root_correlation_id,
                task_id=job.task_id,
                causation_id=lease.id,
                parent_correlation_id=job.id,
                evidence_id=evidence_id,
                captured_at=now,
            )
            ignored = BackgroundJobIgnoredResult(
                id=ignored_id,
                job_id=job.id,
                lease_id=lease.id,
                fencing_token=lease.fencing_token,
                effect_id=effect_id,
                idempotency_key=normalized_key,
                result_fingerprint=fingerprint,
                evidence_id=captured.record.id,
                reason_code=reason_code,
                received_at=now,
                owner_id=job.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=job.root_correlation_id,
                causation_id=lease.id,
                parent_correlation_id=job.id,
            )
            session.add(ignored)
            session.flush()
            return IgnoredResult(
                ignored_result_id=ignored.id,
                evidence_id=ignored.evidence_id,
                reason_code=ignored.reason_code,
                replayed=False,
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
            return _release_failed_attempt(
                session,
                job,
                lease,
                grant=grant,
                error_code=normalized_code,
                retryable=retryable,
                principal_id=self._principal_id,
                now=now,
            )

    def pause_attempt(
        self,
        grant: JobLeaseGrant,
        *,
        error_code: str,
    ) -> None:
        """Release a temporarily blocked lease without spending retry budget."""

        normalized_code = _required_error_code(error_code)
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            job, lease, now = _current_lease(
                session,
                grant,
                clock=self._clock,
            )
            lease.released_at = now
            lease.release_reason = "RETRY"
            lease.actor_id = self._principal_id
            lease.updated_at = now
            job.status = BackgroundJobStatus.QUEUED
            job.attempt_count = max(0, job.attempt_count - 1)
            job.available_at = now
            job.current_lease_id = None
            job.current_fencing_token = None
            job.lease_owner = None
            job.lease_expires_at = None
            job.last_fencing_token = grant.fencing_token
            job.last_error_code = normalized_code
            job.actor_id = self._principal_id
            job.updated_at = now
            session.flush()

    def fail_dependency_attempt(
        self,
        grant: JobLeaseGrant,
        *,
        service: DependencyService,
        error_code: str,
    ) -> JobFailureDisposition:
        """Persist a dependency retry and escalate exact exhausted state."""

        normalized_code = _required_error_code(error_code)
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            job, lease, now = _current_lease(
                session,
                grant,
                clock=self._clock,
            )
            outage_id = uuid5(
                NAMESPACE_URL,
                f"mathews:outage:{job.id}:{job.attempt_count}",
            )
            evidence_id = uuid5(
                NAMESPACE_URL,
                f"mathews:outage-evidence:{job.id}:{job.attempt_count}",
            )
            captured = capture_evidence(
                session,
                self._artifact_store,
                payload={
                    "attempt": job.attempt_count,
                    "checkpoint_fingerprint": (
                        None
                        if job.checkpoint is None
                        else _fingerprint(job.checkpoint)
                    ),
                    "checkpoint_version": job.checkpoint_version,
                    "error_code": normalized_code,
                    "job_id": str(job.id),
                    "service": service.value,
                },
                media_type="application/json",
                source_kind=EvidenceSourceKind.EXTERNAL_EVENT,
                evidence_type="dependency-outage",
                origin=f"background-job:{job.id}:outage:{job.attempt_count}",
                access_classification=EvidenceAccessClass.TASK_OWNER,
                retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
                owner_id=job.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=job.root_correlation_id,
                task_id=job.task_id,
                causation_id=lease.id,
                parent_correlation_id=job.id,
                evidence_id=evidence_id,
                captured_at=now,
            )
            disposition = _release_failed_attempt(
                session,
                job,
                lease,
                grant=grant,
                error_code=normalized_code,
                retryable=True,
                principal_id=self._principal_id,
                now=now,
            )
            session.add(
                DependencyOutageAttempt(
                    id=outage_id,
                    job_id=job.id,
                    lease_id=lease.id,
                    fencing_token=lease.fencing_token,
                    attempt=lease.attempt,
                    service=service,
                    error_code=normalized_code,
                    checkpoint_evidence_id=captured.record.id,
                    exhausted=disposition.exhausted,
                    occurred_at=now,
                    owner_id=job.owner_id,
                    actor_id=self._principal_id,
                    root_correlation_id=job.root_correlation_id,
                    causation_id=lease.id,
                    parent_correlation_id=job.id,
                )
            )
            session.flush()
            job_id = job.id
        if not disposition.exhausted:
            return disposition
        request_id = self.reconcile_outage_escalation(job_id)
        return replace(
            disposition,
            escalation_request_id=request_id,
        )

    def reconcile_outage_escalation(self, job_id: UUID) -> UUID | None:
        """Idempotently create the retry-limit approval for an exhausted outage."""

        from mathews_control_plane.approvals import (
            ApprovalError,
            ApprovalRetryAttempt,
            ApprovalService,
            BlockedOperation,
        )
        from mathews_control_plane.domain_models import ApprovalRequestType

        with self._factory() as session:
            job = session.get(BackgroundJob, job_id)
            if job is None or job.task_id is None:
                raise BackgroundJobNotFoundError(
                    "background job outage is unavailable"
                )
            task = session.get(Task, job.task_id)
            attempts = tuple(
                session.scalars(
                    select(DependencyOutageAttempt)
                    .where(DependencyOutageAttempt.job_id == job.id)
                    .order_by(
                        DependencyOutageAttempt.attempt,
                        DependencyOutageAttempt.id,
                    )
                )
            )
            if task is None or not attempts or not attempts[-1].exhausted:
                raise BackgroundJobConflictError(
                    "background job outage is not exhausted"
                )
            latest = attempts[-1]
            if latest.approval_request_id is not None:
                return latest.approval_request_id
            if TaskState(task.state) in {
                TaskState.HANDED_OFF,
                TaskState.FAILED,
                TaskState.CANCELLED,
            }:
                return None
            expected_state = TaskState(task.state)
            request_id = uuid5(
                NAMESPACE_URL,
                f"mathews:outage-approval:{latest.id}",
            )
            existing_request = session.get(ApprovalRequest, request_id)
            expires_at = (
                _as_utc(existing_request.expires_at)
                if (
                    existing_request is not None
                    and existing_request.expires_at is not None
                )
                else _as_utc(self._clock()) + timedelta(days=30)
            )
            evidence_ids = tuple(
                attempt.checkpoint_evidence_id for attempt in attempts
            )
            retry_history = tuple(
                ApprovalRetryAttempt(
                    attempt=attempt.attempt,
                    error_code=attempt.error_code,
                    occurred_at=attempt.occurred_at,
                    checkpoint_evidence_id=attempt.checkpoint_evidence_id,
                )
                for attempt in attempts
            )
            blocked_operation = BlockedOperation(
                operation_name=(
                    f"dependency.{DependencyService(latest.service).value.lower()}.resume"
                ),
                idempotency_key=f"outage:{job.id}:{latest.attempt}",
                input_fingerprint=job.input_fingerprint,
                checkpoint_evidence_id=latest.checkpoint_evidence_id,
            )
            task_id = task.id
            reason_code = (
                f"{DependencyService(latest.service).value}_RETRY_LIMIT"
            )
        try:
            ApprovalService(
                self._factory,
                self._artifact_store,
                principal_id=self._principal_id,
                clock=self._clock,
            ).request(
                task_id,
                request_id=request_id,
                expected_state=expected_state,
                request_type=ApprovalRequestType.RETRY_LIMIT,
                reason_code=reason_code,
                subject_type="BLOCKED_OPERATION",
                subject_id=None,
                blocked_operation=blocked_operation,
                retry_history=retry_history,
                evidence_ids=evidence_ids,
                expires_at=expires_at,
            )
        except ApprovalError as error:
            _LOGGER.warning(
                "outage escalation remains pending",
                extra={
                    "error_type": type(error).__name__,
                    "job_id": str(job_id),
                },
            )
            return None
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            latest_row = session.scalar(
                select(DependencyOutageAttempt)
                .where(DependencyOutageAttempt.id == latest.id)
                .with_for_update()
            )
            if latest_row is None:
                raise BackgroundJobConflictError(
                    "background job outage disappeared"
                )
            if latest_row.approval_request_id not in {None, request_id}:
                raise BackgroundJobConflictError(
                    "background job outage approval conflicts"
                )
            latest_row.approval_request_id = request_id
            latest_row.actor_id = self._principal_id
            latest_row.updated_at = _as_utc(self._clock())
            session.flush()
        return request_id

    def reconcile_pending_outage_escalations(
        self,
        *,
        limit: int = 100,
    ) -> tuple[UUID, ...]:
        """Retry durable exhausted escalations left incomplete by a restart."""

        if not 1 <= limit <= MAX_RECOVERY_BATCH_SIZE:
            raise InvalidBackgroundJobError(
                "background job recovery limit must be between 1 and 1000"
            )
        with self._factory() as session:
            job_ids = tuple(
                session.scalars(
                    select(DependencyOutageAttempt.job_id)
                    .where(
                        DependencyOutageAttempt.exhausted.is_(True),
                        DependencyOutageAttempt.approval_request_id.is_(None),
                    )
                    .order_by(DependencyOutageAttempt.occurred_at)
                    .limit(limit)
                )
            )
        reconciled: list[UUID] = []
        for candidate in dict.fromkeys(job_ids):
            if self.reconcile_outage_escalation(candidate) is not None:
                reconciled.append(candidate)
        return tuple(reconciled)

    def reconcile_outage_decisions(
        self,
        *,
        limit: int = 100,
    ) -> tuple[UUID, ...]:
        """Resume an approved outage as a new immutable job generation."""

        from mathews_control_plane.domain_models import (
            ApprovalDecision,
            ApprovalRequest,
            ApprovalStatus,
        )

        if not 1 <= limit <= MAX_RECOVERY_BATCH_SIZE:
            raise InvalidBackgroundJobError(
                "background job recovery limit must be between 1 and 1000"
            )
        reconciled: list[UUID] = []
        terminal_decided = False
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            query = (
                select(DependencyOutageAttempt)
                .join(
                    ApprovalRequest,
                    ApprovalRequest.id
                    == DependencyOutageAttempt.approval_request_id,
                )
                .where(
                    DependencyOutageAttempt.exhausted.is_(True),
                    DependencyOutageAttempt.resolved_at.is_(None),
                    ApprovalRequest.status != ApprovalStatus.PENDING,
                )
                .order_by(DependencyOutageAttempt.occurred_at)
                .limit(limit)
            )
            if session.get_bind().dialect.name == "postgresql":
                query = query.with_for_update(skip_locked=True)
            else:
                query = query.with_for_update()
            for outage in session.scalars(query):
                request = session.get(
                    ApprovalRequest,
                    outage.approval_request_id,
                )
                job = session.scalar(
                    select(BackgroundJob)
                    .where(BackgroundJob.id == outage.job_id)
                    .with_for_update()
                )
                if (
                    request is None
                    or request.decision_id is None
                    or request.decision is None
                    or job is None
                    or job.task_id is None
                ):
                    raise BackgroundJobConflictError(
                        "background job outage decision is corrupt"
                    )
                now = _as_utc(self._clock())
                decision = ApprovalDecision(request.decision)
                resumed_job: BackgroundJob | None = None
                if decision is ApprovalDecision.RETRY:
                    resume_key = f"outage-resume:{request.decision_id}"
                    resumed_job = session.scalar(
                        select(BackgroundJob).where(
                            BackgroundJob.idempotency_key == resume_key
                        )
                    )
                    if resumed_job is None:
                        policy = RetryPolicy(
                            max_attempts=job.max_attempts,
                            base_delay_seconds=job.retry_base_seconds,
                            max_delay_seconds=job.retry_max_seconds,
                        )
                        resumed_job = BackgroundJob(
                            task_id=job.task_id,
                            job_type=job.job_type,
                            input_payload=dict(job.input_payload),
                            input_fingerprint=_schedule_fingerprint(
                                task_id=job.task_id,
                                job_type=job.job_type,
                                payload=job.input_payload,
                                policy=policy,
                                requested_available_at=None,
                            ),
                            status=BackgroundJobStatus.QUEUED,
                            idempotency_key=resume_key,
                            attempt_count=0,
                            max_attempts=policy.max_attempts,
                            retry_base_seconds=policy.base_delay_seconds,
                            retry_max_seconds=policy.max_delay_seconds,
                            available_at=now,
                            checkpoint=(
                                None
                                if job.checkpoint is None
                                else dict(job.checkpoint)
                            ),
                            checkpoint_version=job.checkpoint_version,
                            owner_id=job.owner_id,
                            actor_id=self._principal_id,
                            root_correlation_id=job.root_correlation_id,
                            causation_id=request.decision_id,
                            parent_correlation_id=job.id,
                        )
                        session.add(resumed_job)
                        session.flush()
                    elif (
                        resumed_job.task_id != job.task_id
                        or resumed_job.parent_correlation_id != job.id
                    ):
                        raise BackgroundJobConflictError(
                            "background job outage resume key conflicts"
                        )
                elif decision in {
                    ApprovalDecision.ABANDON,
                    ApprovalDecision.CANCEL,
                }:
                    terminal_decided = True
                outage.resolved_at = now
                outage.decision_id = request.decision_id
                outage.resumed_job_id = (
                    None if resumed_job is None else resumed_job.id
                )
                outage.actor_id = self._principal_id
                outage.updated_at = now
                session.flush()
                reconciled.append(outage.id)
        if terminal_decided:
            from mathews_control_plane.reliability import CancellationService

            CancellationService(
                self._factory,
                self._artifact_store,
                principal_id=self._principal_id,
                clock=self._clock,
            ).reconcile_unfenced_terminal_tasks(limit=limit)
        return tuple(reconciled)

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
            task = session.scalar(
                select(Task)
                .where(Task.id == grant.task_id)
                .with_for_update()
            )
            if task is None:
                raise BackgroundJobNotFoundError(
                    "background job task is unavailable"
                )
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
                validation_candidate=None,
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


def _release_failed_attempt(
    session: Session,
    job: BackgroundJob,
    lease: BackgroundJobLease,
    *,
    grant: JobLeaseGrant,
    error_code: str,
    retryable: bool,
    principal_id: str,
    now: datetime,
) -> JobFailureDisposition:
    policy = RetryPolicy(
        max_attempts=job.max_attempts,
        base_delay_seconds=job.retry_base_seconds,
        max_delay_seconds=job.retry_max_seconds,
    )
    can_retry = retryable and job.attempt_count < job.max_attempts
    delay = (
        deterministic_retry_delay(job.id, job.attempt_count, policy)
        if can_retry
        else None
    )
    retry_at = None if delay is None else now + delay
    lease.released_at = now
    lease.release_reason = "RETRY" if can_retry else "FAILED"
    lease.retry_at = retry_at
    lease.failure_code = error_code
    lease.actor_id = principal_id
    lease.updated_at = now
    session.flush((lease,))
    if can_retry:
        if retry_at is None:
            raise BackgroundJobConflictError(
                "background job retry schedule is unavailable"
            )
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
    job.last_error_code = error_code
    job.actor_id = principal_id
    job.updated_at = now
    session.flush((job,))
    return JobFailureDisposition(
        status=(
            BackgroundJobStatus.QUEUED
            if can_retry
            else BackgroundJobStatus.FAILED
        ),
        next_attempt_at=retry_at,
        exhausted=retryable and not can_retry,
        retry_delay=delay,
    )


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


def require_current_job_lease(
    session: Session,
    grant: JobLeaseGrant,
    *,
    now: datetime,
) -> None:
    """Fence a caller's mutation inside its existing database transaction."""

    _current_lease(session, grant, clock=lambda: now)


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
        try:
            checkpoint = self.service.record_effect_result(
                self.grant,
                effect_id=prepared.effect_id,
                result=observation,
                expected_checkpoint_version=self.grant.checkpoint_version,
                checkpoint_idempotency_key=checkpoint_idempotency_key,
                checkpoint_payload=checkpoint_payload,
            )
        except BackgroundJobLeaseLostError:
            self.service.record_ignored_result(
                self.grant,
                idempotency_key=(
                    f"{self.grant.job_id}:ignored:{prepared.effect_id}"
                ),
                effect_id=prepared.effect_id,
                result=observation,
            )
            raise
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
        except DependencyOutageError as error:
            try:
                disposition = self._service.fail_dependency_attempt(
                    context.grant,
                    service=error.service,
                    error_code=error.error_code,
                )
            except BackgroundJobLeaseLostError:
                return WorkerRunOutcome.LEASE_LOST
            if disposition.status is BackgroundJobStatus.QUEUED:
                return WorkerRunOutcome.RETRY_SCHEDULED
            return (
                WorkerRunOutcome.ESCALATED
                if disposition.escalation_request_id is not None
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
        except PausedBackgroundJobError as error:
            try:
                self._service.pause_attempt(
                    context.grant,
                    error_code=error.error_code,
                )
            except BackgroundJobLeaseLostError:
                return WorkerRunOutcome.LEASE_LOST
            return WorkerRunOutcome.RETRY_SCHEDULED
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
