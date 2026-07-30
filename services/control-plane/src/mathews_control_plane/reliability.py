"""Durable cancellation cleanup and read-only startup reconciliation."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, cast
from uuid import NAMESPACE_URL, UUID, uuid5

from sqlalchemy import exists, func, select
from sqlalchemy.orm import Session

from mathews_control_plane.approvals import ApprovalService
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.background_jobs import (
    MAX_RECOVERY_BATCH_SIZE,
    BackgroundJobConflictError,
    BackgroundJobNotFoundError,
    BackgroundJobService,
    InvalidBackgroundJobError,
    _begin_serialized,
    _bounded_evidence_payload,
    _required_identifier,
)
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    BackgroundJob,
    BackgroundJobEffect,
    BackgroundJobEffectStatus,
    BackgroundJobLease,
    BackgroundJobStatus,
    BackgroundJobToolGrant,
    DependencyOutageAttempt,
    EvidenceRecord,
    OwnedHostProcess,
    OwnedHostProcessStatus,
    ReconciliationStatus,
    ReconciliationTarget,
    ReconciliationTargetKind,
    Task,
    TaskCancellation,
    TaskEvent,
    TaskState,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
)
from mathews_control_plane.task_state_machine import (
    ClosedTaskTransitionGateEvaluator,
    TaskTransitionKind,
    _transition_task,
)

_REASON_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,99}\Z")
_ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,99}\Z")


class ReliabilityError(RuntimeError):
    """Base class for cancellation and recovery failures."""


class InvalidReliabilityCommandError(ReliabilityError):
    """A cancellation or reconciliation command is malformed."""


class ReliabilityConflictError(ReliabilityError):
    """Durable reliability state no longer matches the command."""


@dataclass(frozen=True, slots=True)
class OwnedProcessIdentity:
    process_id: UUID
    job_id: UUID
    host_id: str
    pid: int
    process_group_id: int
    birth_token: str
    ownership_nonce: UUID


@dataclass(frozen=True, slots=True)
class ProcessTerminationObservation:
    """Host assertion after matching the exact registered process identity."""

    status: OwnedHostProcessStatus
    partial_output: dict[str, object]

    def __post_init__(self) -> None:
        if self.status not in {
            OwnedHostProcessStatus.TERMINATED,
            OwnedHostProcessStatus.GONE,
        }:
            raise InvalidReliabilityCommandError(
                "host process termination status is invalid"
            )


class OwnedProcessTerminator(Protocol):
    """Narrow host boundary that must verify identity before killpg."""

    def terminate_owned(
        self,
        process: OwnedProcessIdentity,
        *,
        idempotency_key: str,
    ) -> ProcessTerminationObservation: ...


class OwnedWorkspaceCleaner(Protocol):
    """Policy-gated idempotent cleanup for one task-owned workspace."""

    def cleanup_owned(
        self,
        *,
        task_id: UUID,
        job_id: UUID,
        idempotency_key: str,
    ) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class CancellationResult:
    task_id: UUID
    cancellation_id: UUID
    task_state: TaskState
    partial_evidence_id: UUID
    revoked_lease_count: int
    revoked_tool_grant_count: int
    cleanup_complete: bool
    replayed: bool


@dataclass(frozen=True, slots=True)
class ReconciliationObservation:
    """One adapter's read-only comparison with durable expected state."""

    status: ReconciliationStatus
    observed_payload: dict[str, object]
    error_code: str | None = None

    def __post_init__(self) -> None:
        if self.status in {
            ReconciliationStatus.PENDING,
            ReconciliationStatus.CANCELLED,
        }:
            raise InvalidReliabilityCommandError(
                "startup reconciliation observation status is invalid"
            )
        if (self.status is ReconciliationStatus.RETRY_REQUIRED) != (
            self.error_code is not None
        ):
            raise InvalidReliabilityCommandError(
                "startup reconciliation error shape is invalid"
            )
        if self.error_code is not None and _ERROR_CODE.fullmatch(
            self.error_code
        ) is None:
            raise InvalidReliabilityCommandError(
                "startup reconciliation error code is invalid"
            )


class ReconciliationAdapter(Protocol):
    """Read-only adapter used before any post-restart effect may run."""

    def reconcile(
        self,
        *,
        kind: ReconciliationTargetKind,
        target_key: str,
        expected_payload: Mapping[str, object],
    ) -> ReconciliationObservation: ...


@dataclass(frozen=True, slots=True)
class StartupRecoveryResult:
    recovered_job_ids: tuple[UUID, ...]
    escalated_job_ids: tuple[UUID, ...]
    resolved_outage_ids: tuple[UUID, ...]
    completed_cancellation_ids: tuple[UUID, ...]
    reconciled_target_ids: tuple[UUID, ...]


def _drain_recovery_batches(
    operation: Callable[[], tuple[UUID, ...]],
    *,
    batch_size: int,
) -> tuple[UUID, ...]:
    """Drain a recovery query whose successful rows leave its result set."""

    recovered: list[UUID] = []
    while True:
        batch = operation()
        recovered.extend(batch)
        if len(batch) < batch_size:
            return tuple(dict.fromkeys(recovered))


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _fingerprint(value: Mapping[str, object]) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError):
        raise InvalidReliabilityCommandError(
            "reliability command is not JSON serializable"
        ) from None
    return hashlib.sha256(encoded).hexdigest()


def _reason_code(value: str) -> str:
    normalized = value.strip().upper()
    if _REASON_CODE.fullmatch(normalized) is None:
        raise InvalidReliabilityCommandError(
            "cancellation reason code is invalid"
        )
    return normalized


def _pending_approval(
    session: Session,
    task_id: UUID,
) -> ApprovalRequest | None:
    return session.scalar(
        select(ApprovalRequest)
        .where(
            ApprovalRequest.task_id == task_id,
            ApprovalRequest.status == ApprovalStatus.PENDING,
        )
        .order_by(ApprovalRequest.created_at, ApprovalRequest.id)
    )


def _capture_cancellation_evidence(
    session: Session,
    artifact_store: ArtifactStore,
    *,
    task: Task,
    cancellation_id: UUID,
    reason_code: str,
    actor_id: str,
    now: datetime,
) -> EvidenceRecord:
    evidence_id = uuid5(
        NAMESPACE_URL,
        f"mathews:cancellation-evidence:{cancellation_id}",
    )
    existing = session.get(EvidenceRecord, evidence_id)
    if existing is not None:
        if existing.task_id != task.id or existing.owner_id != task.owner_id:
            raise ReliabilityConflictError(
                "cancellation evidence identity conflicts"
            )
        return existing
    job_count = int(
        session.scalar(
            select(func.count())
            .select_from(BackgroundJob)
            .where(BackgroundJob.task_id == task.id)
        )
        or 0
    )
    jobs = tuple(
        session.scalars(
            select(BackgroundJob)
            .where(BackgroundJob.task_id == task.id)
            .order_by(BackgroundJob.created_at, BackgroundJob.id)
            .limit(100)
        )
    )
    pending_effect_count = int(
        session.scalar(
            select(func.count())
            .select_from(BackgroundJobEffect)
            .join(
                BackgroundJob,
                BackgroundJob.id == BackgroundJobEffect.job_id,
            )
            .where(
                BackgroundJob.task_id == task.id,
                BackgroundJobEffect.status
                == BackgroundJobEffectStatus.PENDING,
            )
        )
        or 0
    )
    pending_effect_ids = tuple(
        session.scalars(
            select(BackgroundJobEffect.id)
            .join(
                BackgroundJob,
                BackgroundJob.id == BackgroundJobEffect.job_id,
            )
            .where(
                BackgroundJob.task_id == task.id,
                BackgroundJobEffect.status
                == BackgroundJobEffectStatus.PENDING,
            )
            .order_by(
                BackgroundJobEffect.started_at,
                BackgroundJobEffect.id,
            )
            .limit(100)
        )
    )
    captured = capture_evidence(
        session,
        artifact_store,
        payload={
            "jobs": [
                {
                    "attempt_count": job.attempt_count,
                    "checkpoint_fingerprint": (
                        None
                        if job.checkpoint is None
                        else _fingerprint(job.checkpoint)
                    ),
                    "checkpoint_version": job.checkpoint_version,
                    "job_id": str(job.id),
                    "last_error_code": job.last_error_code,
                    "status": BackgroundJobStatus(job.status).value,
                }
                for job in jobs
            ],
            "job_count": job_count,
            "jobs_truncated": job_count > len(jobs),
            "pending_effect_count": pending_effect_count,
            "pending_effect_ids": [
                str(effect_id) for effect_id in pending_effect_ids
            ],
            "pending_effects_truncated": (
                pending_effect_count > len(pending_effect_ids)
            ),
            "reason_code": reason_code,
            "task_id": str(task.id),
            "task_state": TaskState(task.state).value,
        },
        media_type="application/json",
        source_kind=EvidenceSourceKind.RESULT,
        evidence_type="cancellation-partial-state",
        origin=f"task:{task.id}:cancellation",
        access_classification=EvidenceAccessClass.TASK_OWNER,
        retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
        owner_id=task.owner_id,
        actor_id=actor_id,
        root_correlation_id=task.root_correlation_id,
        task_id=task.id,
        causation_id=cancellation_id,
        parent_correlation_id=task.id,
        evidence_id=evidence_id,
        captured_at=now,
    )
    return captured.record


class CancellationService:
    """Fence task work first, then replay only exact owned cleanup."""

    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        *,
        principal_id: str = "control-plane",
        active_policy_lineage: str = "mvp",
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._factory = factory
        self._artifact_store = artifact_store
        self._principal_id = _required_identifier(
            principal_id,
            field="reliability principal",
            maximum=255,
        )
        self._active_policy_lineage = _required_identifier(
            active_policy_lineage,
            field="reliability policy lineage",
            maximum=255,
        )
        self._clock = clock

    def cancel_task(
        self,
        task_id: UUID,
        *,
        cancellation_id: UUID,
        expected_state: TaskState,
        reason_code: str,
        terminator: OwnedProcessTerminator | None = None,
        cleaner: OwnedWorkspaceCleaner | None = None,
    ) -> CancellationResult:
        normalized_reason = _reason_code(reason_code)
        fingerprint = _fingerprint(
            {
                "cancellation_id": str(cancellation_id),
                "expected_state": expected_state.value,
                "reason_code": normalized_reason,
                "task_id": str(task_id),
            }
        )
        transition_event_id: UUID | None = None
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            task = session.scalar(
                select(Task).where(Task.id == task_id).with_for_update()
            )
            if task is None:
                raise BackgroundJobNotFoundError(
                    "cancellation task is unavailable"
                )
            existing = session.scalar(
                select(TaskCancellation)
                .where(TaskCancellation.task_id == task.id)
                .with_for_update()
            )
            if existing is not None:
                if (
                    existing.id != cancellation_id
                    or existing.request_fingerprint != fingerprint
                ):
                    raise ReliabilityConflictError(
                        "task cancellation conflicts"
                    )
                partial_evidence_id = existing.partial_evidence_id
                replayed = True
                pending_request_id = None
            else:
                if TaskState(task.state) is not expected_state:
                    recovered_transition = session.scalar(
                        select(TaskEvent).where(
                            TaskEvent.task_id == task.id,
                            TaskEvent.transition_id == cancellation_id,
                            TaskEvent.transition_kind.in_(
                                (
                                    TaskTransitionKind.CANCEL.value,
                                    TaskTransitionKind.FAIL.value,
                                )
                            ),
                            TaskEvent.transition_to_state.in_(
                                (
                                    TaskState.CANCELLED,
                                    TaskState.FAILED,
                                )
                            ),
                        )
                    )
                    evidence = session.get(
                        EvidenceRecord,
                        uuid5(
                            NAMESPACE_URL,
                            f"mathews:cancellation-evidence:{cancellation_id}",
                        ),
                    )
                    if (
                        recovered_transition is None
                    ):
                        raise ReliabilityConflictError(
                            "task state no longer matches cancellation"
                        )
                    if evidence is None:
                        evidence = _capture_cancellation_evidence(
                            session,
                            self._artifact_store,
                            task=task,
                            cancellation_id=cancellation_id,
                            reason_code=normalized_reason,
                            actor_id=self._principal_id,
                            now=_as_utc(self._clock()),
                        )
                    if evidence.task_id != task.id:
                        raise ReliabilityConflictError(
                            "cancellation evidence identity conflicts"
                        )
                    transition_event_id = recovered_transition.id
                    partial_evidence_id = evidence.id
                    replayed = False
                    pending_request_id = None
                else:
                    evidence = _capture_cancellation_evidence(
                        session,
                        self._artifact_store,
                        task=task,
                        cancellation_id=cancellation_id,
                        reason_code=normalized_reason,
                        actor_id=self._principal_id,
                        now=_as_utc(self._clock()),
                    )
                    partial_evidence_id = evidence.id
                    replayed = False
                    pending = _pending_approval(session, task.id)
                    pending_request_id = (
                        None if pending is None else pending.id
                    )
        if not replayed and pending_request_id is not None:
            decision = ApprovalService(
                self._factory,
                self._artifact_store,
                principal_id=self._principal_id,
                clock=self._clock,
            ).decide(
                pending_request_id,
                decision_id=cancellation_id,
                decision=ApprovalDecision.CANCEL,
                actor_id=self._principal_id,
                evidence_ids=(partial_evidence_id,),
            )
            transition_event_id = decision.transition_event_id

        revoked_leases = 0
        revoked_grants = 0
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            task = session.scalar(
                select(Task).where(Task.id == task_id).with_for_update()
            )
            if task is None:
                raise BackgroundJobNotFoundError(
                    "cancellation task is unavailable"
                )
            cancellation = session.scalar(
                select(TaskCancellation)
                .where(TaskCancellation.task_id == task.id)
                .with_for_update()
            )
            if cancellation is None:
                now = _as_utc(self._clock())
                if transition_event_id is None:
                    transition = _transition_task(
                        session,
                        self._artifact_store,
                        task_id=task.id,
                        transition_id=cancellation_id,
                        expected_state=expected_state,
                        kind=TaskTransitionKind.CANCEL,
                        reason_code=normalized_reason,
                        actor_id=self._principal_id,
                        evidence_ids=(partial_evidence_id,),
                        gate_evaluator=ClosedTaskTransitionGateEvaluator(),
                        active_policy_lineage=self._active_policy_lineage,
                        occurred_at=now,
                    )
                    transition_event_id = transition.event_id
                elif TaskState(task.state) not in {
                    TaskState.CANCELLED,
                    TaskState.FAILED,
                }:
                    raise ReliabilityConflictError(
                        "terminal transition did not fence the task"
                    )
                cancellation = TaskCancellation(
                    id=cancellation_id,
                    task_id=task.id,
                    request_fingerprint=fingerprint,
                    reason_code=normalized_reason,
                    partial_evidence_id=partial_evidence_id,
                    transition_event_id=transition_event_id,
                    requested_at=now,
                    owner_id=task.owner_id,
                    actor_id=self._principal_id,
                    root_correlation_id=task.root_correlation_id,
                    causation_id=cancellation_id,
                    parent_correlation_id=task.id,
                )
                session.add(cancellation)
                session.flush()
            elif (
                cancellation.id != cancellation_id
                or cancellation.request_fingerprint != fingerprint
            ):
                raise ReliabilityConflictError("task cancellation conflicts")

            now = _as_utc(self._clock())
            jobs = tuple(
                session.scalars(
                    select(BackgroundJob)
                    .where(BackgroundJob.task_id == task.id)
                    .order_by(BackgroundJob.created_at, BackgroundJob.id)
                    .with_for_update()
                )
            )
            for job in jobs:
                active = job.status in {
                    BackgroundJobStatus.QUEUED,
                    BackgroundJobStatus.RUNNING,
                }
                if active:
                    job.cancellation_requested_at = (
                        job.cancellation_requested_at or now
                    )
                if job.status is BackgroundJobStatus.RUNNING and (
                    job.current_lease_id is not None
                ):
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
                            "cancellation lease projection is corrupt"
                        )
                    lease.released_at = now
                    lease.release_reason = "CANCELLED"
                    lease.failure_code = "CANCELLATION_REQUESTED"
                    lease.cancellation_acknowledged_at = now
                    lease.actor_id = self._principal_id
                    lease.updated_at = now
                    session.flush((lease,))
                    revoked_leases += 1
                if active:
                    job.status = BackgroundJobStatus.CANCELLED
                    job.current_lease_id = None
                    job.current_fencing_token = None
                    job.lease_owner = None
                    job.lease_expires_at = None
                    job.last_error_code = "CANCELLATION_REQUESTED"
                    job.completed_at = now
                    job.actor_id = self._principal_id
                    job.updated_at = now
                    session.flush((job,))
            job_ids = tuple(job.id for job in jobs)
            if job_ids:
                grants = tuple(
                    session.scalars(
                        select(BackgroundJobToolGrant)
                        .where(
                            BackgroundJobToolGrant.job_id.in_(job_ids),
                            BackgroundJobToolGrant.revoked_at.is_(None),
                        )
                        .with_for_update()
                    )
                )
                for grant in grants:
                    grant.revoked_at = now
                    grant.revoke_reason = "TASK_CANCELLED"
                    grant.actor_id = self._principal_id
                    grant.updated_at = now
                revoked_grants = len(grants)
                processes = tuple(
                    session.scalars(
                        select(OwnedHostProcess)
                        .where(
                            OwnedHostProcess.job_id.in_(job_ids),
                            OwnedHostProcess.status
                            == OwnedHostProcessStatus.RUNNING,
                        )
                        .with_for_update()
                    )
                )
                for process in processes:
                    process.status = (
                        OwnedHostProcessStatus.TERMINATION_REQUESTED
                    )
                    process.termination_requested_at = now
                    process.actor_id = self._principal_id
                    process.updated_at = now
                targets = tuple(
                    session.scalars(
                        select(ReconciliationTarget)
                        .where(
                            ReconciliationTarget.task_id == task.id,
                            ReconciliationTarget.kind
                            != ReconciliationTargetKind.HOST_PROCESS,
                            ReconciliationTarget.status
                            != ReconciliationStatus.CANCELLED,
                        )
                        .with_for_update()
                    )
                )
                for target in targets:
                    target.observed_payload = {
                        "reason_code": "TASK_TERMINAL",
                    }
                    target.status = ReconciliationStatus.CANCELLED
                    target.reconciliation_version += 1
                    target.last_reconciled_at = now
                    target.last_error_code = None
                    target.actor_id = self._principal_id
                    target.updated_at = now
            session.flush()

        self.resume_cleanup(
            cancellation_id,
            terminator=terminator,
            cleaner=cleaner,
        )
        with self._factory() as session:
            cancellation = session.get(TaskCancellation, cancellation_id)
            task = session.get(Task, task_id)
            if cancellation is None or task is None:
                raise ReliabilityConflictError(
                    "task cancellation is unavailable after commit"
                )
            return CancellationResult(
                task_id=task.id,
                cancellation_id=cancellation.id,
                task_state=TaskState(task.state),
                partial_evidence_id=cancellation.partial_evidence_id,
                revoked_lease_count=revoked_leases,
                revoked_tool_grant_count=revoked_grants,
                cleanup_complete=(
                    cancellation.cleanup_completed_at is not None
                ),
                replayed=replayed,
            )

    def resume_cleanup(
        self,
        cancellation_id: UUID,
        *,
        terminator: OwnedProcessTerminator | None = None,
        cleaner: OwnedWorkspaceCleaner | None = None,
    ) -> bool:
        """Replay incomplete exact-identity termination and workspace cleanup."""

        with self._factory() as session:
            cancellation = session.get(TaskCancellation, cancellation_id)
            if cancellation is None:
                raise BackgroundJobNotFoundError(
                    "task cancellation is unavailable"
                )
            task_id = cancellation.task_id
            processes = tuple(
                session.scalars(
                    select(OwnedHostProcess)
                    .join(
                        BackgroundJob,
                        BackgroundJob.id == OwnedHostProcess.job_id,
                    )
                    .where(
                        BackgroundJob.task_id == task_id,
                        OwnedHostProcess.status
                        == OwnedHostProcessStatus.TERMINATION_REQUESTED,
                    )
                    .order_by(
                        OwnedHostProcess.started_at,
                        OwnedHostProcess.id,
                    )
                )
            )
            identities = tuple(
                OwnedProcessIdentity(
                    process_id=process.id,
                    job_id=process.job_id,
                    host_id=process.host_id,
                    pid=process.pid,
                    process_group_id=process.process_group_id,
                    birth_token=process.birth_token,
                    ownership_nonce=process.ownership_nonce,
                )
                for process in processes
            )
        if identities and terminator is None:
            return False
        for identity in identities:
            observation = cast(OwnedProcessTerminator, terminator).terminate_owned(
                identity,
                idempotency_key=f"cancel:{cancellation_id}:process:{identity.process_id}",
            )
            cleanup_payload: Mapping[str, object] = {}
            if cleaner is not None:
                cleanup_payload = cleaner.cleanup_owned(
                    task_id=task_id,
                    job_id=identity.job_id,
                    idempotency_key=(
                        f"cancel:{cancellation_id}:workspace:{identity.job_id}"
                    ),
                )
            self._complete_process_cleanup(
                cancellation_id,
                identity,
                observation=observation,
                cleanup_payload=cleanup_payload,
            )
        return self._finish_cancellation_if_clean(cancellation_id)

    def _complete_process_cleanup(
        self,
        cancellation_id: UUID,
        identity: OwnedProcessIdentity,
        *,
        observation: ProcessTerminationObservation,
        cleanup_payload: Mapping[str, object],
    ) -> None:
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            cancellation = session.scalar(
                select(TaskCancellation)
                .where(TaskCancellation.id == cancellation_id)
                .with_for_update()
            )
            process = session.scalar(
                select(OwnedHostProcess)
                .where(OwnedHostProcess.id == identity.process_id)
                .with_for_update()
            )
            if cancellation is None or process is None:
                raise ReliabilityConflictError(
                    "owned process cleanup state is unavailable"
                )
            if (
                process.job_id != identity.job_id
                or process.host_id != identity.host_id
                or process.pid != identity.pid
                or process.process_group_id != identity.process_group_id
                or process.birth_token != identity.birth_token
                or process.ownership_nonce != identity.ownership_nonce
            ):
                raise ReliabilityConflictError(
                    "owned process identity changed"
                )
            now = _as_utc(self._clock())
            evidence_id = uuid5(
                NAMESPACE_URL,
                f"mathews:process-cleanup-evidence:{cancellation_id}:{process.id}",
            )
            evidence = session.get(EvidenceRecord, evidence_id)
            if evidence is None:
                job = session.get(BackgroundJob, process.job_id)
                if job is None:
                    raise ReliabilityConflictError(
                        "owned process job is unavailable"
                    )
                evidence = capture_evidence(
                    session,
                    self._artifact_store,
                    payload={
                        "cleanup": _bounded_evidence_payload(
                            cleanup_payload
                        ),
                        "host_id": process.host_id,
                        "job_id": str(process.job_id),
                        "partial_output": _bounded_evidence_payload(
                            observation.partial_output
                        ),
                        "process_id": str(process.id),
                        "status": observation.status.value,
                    },
                    media_type="application/json",
                    source_kind=EvidenceSourceKind.RESULT,
                    evidence_type="host-cancellation-result",
                    origin=f"task:{cancellation.task_id}:host-cleanup",
                    access_classification=EvidenceAccessClass.TASK_OWNER,
                    retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
                    owner_id=process.owner_id,
                    actor_id=self._principal_id,
                    root_correlation_id=process.root_correlation_id,
                    task_id=cancellation.task_id,
                    causation_id=cancellation.id,
                    parent_correlation_id=process.job_id,
                    evidence_id=evidence_id,
                    captured_at=now,
                ).record
            if process.status not in {
                OwnedHostProcessStatus.TERMINATION_REQUESTED,
                observation.status,
            }:
                raise ReliabilityConflictError(
                    "owned process cleanup already conflicts"
                )
            process.status = observation.status
            process.terminated_at = process.terminated_at or now
            process.partial_evidence_id = evidence.id
            process.cleanup_completed_at = process.cleanup_completed_at or now
            process.actor_id = self._principal_id
            process.updated_at = now
            target = session.scalar(
                select(ReconciliationTarget)
                .where(
                    ReconciliationTarget.kind
                    == ReconciliationTargetKind.HOST_PROCESS,
                    ReconciliationTarget.target_key
                    == f"process:{process.id}",
                )
                .with_for_update()
            )
            if target is not None:
                target.observed_payload = {
                    "status": observation.status.value,
                }
                target.status = ReconciliationStatus.CANCELLED
                target.reconciliation_version += 1
                target.last_reconciled_at = now
                target.last_error_code = None
                target.actor_id = self._principal_id
                target.updated_at = now
            session.flush()

    def _finish_cancellation_if_clean(self, cancellation_id: UUID) -> bool:
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            cancellation = session.scalar(
                select(TaskCancellation)
                .where(TaskCancellation.id == cancellation_id)
                .with_for_update()
            )
            if cancellation is None:
                raise BackgroundJobNotFoundError(
                    "task cancellation is unavailable"
                )
            pending = session.scalar(
                select(OwnedHostProcess.id)
                .join(
                    BackgroundJob,
                    BackgroundJob.id == OwnedHostProcess.job_id,
                )
                .where(
                    BackgroundJob.task_id == cancellation.task_id,
                    OwnedHostProcess.status.in_(
                        (
                            OwnedHostProcessStatus.RUNNING,
                            OwnedHostProcessStatus.TERMINATION_REQUESTED,
                        )
                    ),
                )
                .limit(1)
            )
            if pending is not None:
                return False
            if cancellation.cleanup_completed_at is not None:
                return True
            now = _as_utc(self._clock())
            cancellation.cleanup_completed_at = now
            cancellation.actor_id = self._principal_id
            cancellation.updated_at = now
            session.flush()
            return True

    def resume_pending_cleanups(
        self,
        *,
        limit: int = 100,
        terminator: OwnedProcessTerminator | None = None,
        cleaner: OwnedWorkspaceCleaner | None = None,
    ) -> tuple[UUID, ...]:
        if not 1 <= limit <= MAX_RECOVERY_BATCH_SIZE:
            raise InvalidBackgroundJobError(
                "cancellation recovery limit must be between 1 and 1000"
            )
        with self._factory() as session:
            cancellation_ids = tuple(
                session.scalars(
                    select(TaskCancellation.id)
                    .where(TaskCancellation.cleanup_completed_at.is_(None))
                    .order_by(TaskCancellation.requested_at)
                    .limit(limit)
                )
            )
        completed = [
            cancellation_id
            for cancellation_id in cancellation_ids
            if self.resume_cleanup(
                cancellation_id,
                terminator=terminator,
                cleaner=cleaner,
            )
        ]
        return tuple(completed)

    def has_unfenced_terminal_tasks(self) -> bool:
        """Return whether a terminal task transition still lacks its fence."""

        with self._factory() as session:
            return bool(
                session.scalar(
                    select(
                        exists().where(
                            TaskEvent.task_id == Task.id,
                            Task.state.in_(
                                (TaskState.CANCELLED, TaskState.FAILED)
                            ),
                            TaskEvent.transition_kind.in_(
                                (
                                    TaskTransitionKind.CANCEL.value,
                                    TaskTransitionKind.FAIL.value,
                                )
                            ),
                            TaskEvent.transition_id.is_not(None),
                            ~exists().where(
                                TaskCancellation.task_id
                                == TaskEvent.task_id
                            ),
                        )
                    )
                )
            )

    def reconcile_unfenced_terminal_tasks(
        self,
        *,
        limit: int = 100,
        terminator: OwnedProcessTerminator | None = None,
        cleaner: OwnedWorkspaceCleaner | None = None,
    ) -> tuple[UUID, ...]:
        """Fence work after a cancellation or failure transition committed."""

        if not 1 <= limit <= MAX_RECOVERY_BATCH_SIZE:
            raise InvalidBackgroundJobError(
                "cancellation recovery limit must be between 1 and 1000"
            )
        with self._factory() as session:
            events = tuple(
                session.scalars(
                    select(TaskEvent)
                    .join(Task, Task.id == TaskEvent.task_id)
                    .where(
                        Task.state.in_(
                            (TaskState.CANCELLED, TaskState.FAILED)
                        ),
                        TaskEvent.transition_kind.in_(
                            (
                                TaskTransitionKind.CANCEL.value,
                                TaskTransitionKind.FAIL.value,
                            )
                        ),
                        TaskEvent.transition_id.is_not(None),
                        ~exists().where(
                            TaskCancellation.task_id == TaskEvent.task_id
                        ),
                    )
                    .order_by(TaskEvent.occurred_at, TaskEvent.id)
                    .limit(limit)
                )
            )
            snapshots = tuple(
                (
                    event.task_id,
                    event.transition_id,
                    TaskState(event.transition_from_state),
                    event.transition_reason_code,
                )
                for event in events
                if event.transition_id is not None
                and event.transition_from_state is not None
                and event.transition_reason_code is not None
            )
        recovered: list[UUID] = []
        for task_id, cancellation_id, expected_state, reason_code in snapshots:
            result = self.cancel_task(
                task_id,
                cancellation_id=cancellation_id,
                expected_state=expected_state,
                reason_code=reason_code,
                terminator=terminator,
                cleaner=cleaner,
            )
            if result.cleanup_complete:
                recovered.append(cancellation_id)
        return tuple(recovered)


class StartupRecoveryService:
    """Reconcile every durable boundary before workers may issue new effects."""

    _KIND_ORDER = (
        ReconciliationTargetKind.HERMES_RUN,
        ReconciliationTargetKind.HOST_PROCESS,
        ReconciliationTargetKind.BRANCH_HEAD,
        ReconciliationTargetKind.PR_HEAD,
        ReconciliationTargetKind.WEBHOOK_CURSOR,
    )

    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        *,
        principal_id: str = "control-plane",
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._factory = factory
        self._artifact_store = artifact_store
        self._principal_id = _required_identifier(
            principal_id,
            field="reliability principal",
            maximum=255,
        )
        self._clock = clock
        self._jobs = BackgroundJobService(
            factory,
            artifact_store,
            principal_id=principal_id,
            clock=clock,
        )
        self._cancellations = CancellationService(
            factory,
            artifact_store,
            principal_id=principal_id,
            clock=clock,
        )

    def recover(
        self,
        *,
        adapters: Mapping[
            ReconciliationTargetKind,
            ReconciliationAdapter,
        ]
        | None = None,
        terminator: OwnedProcessTerminator | None = None,
        cleaner: OwnedWorkspaceCleaner | None = None,
        limit: int = MAX_RECOVERY_BATCH_SIZE,
    ) -> StartupRecoveryResult:
        if not 1 <= limit <= MAX_RECOVERY_BATCH_SIZE:
            raise InvalidBackgroundJobError(
                "startup recovery limit must be between 1 and 1000"
            )
        recovered_jobs = _drain_recovery_batches(
            lambda: self._jobs.reconcile_expired_leases(limit=limit),
            batch_size=limit,
        )
        escalated_jobs = self._reconcile_pending_outage_pages(
            limit=limit,
        )
        resolved_outages = _drain_recovery_batches(
            lambda: self._jobs.reconcile_outage_decisions(limit=limit),
            batch_size=limit,
        )
        recovered_cancellations: list[UUID] = []
        while self._cancellations.has_unfenced_terminal_tasks():
            recovered_cancellations.extend(
                self._cancellations.reconcile_unfenced_terminal_tasks(
                    limit=limit,
                    terminator=terminator,
                    cleaner=cleaner,
                )
            )
        resumed_cancellations = self._resume_pending_cleanup_pages(
            limit=limit,
            terminator=terminator,
            cleaner=cleaner,
        )
        completed_cancellations = tuple(
            dict.fromkeys(
                (*recovered_cancellations, *resumed_cancellations)
            )
        )
        reconciled_targets = self._reconcile_targets(
            adapters={} if adapters is None else adapters,
            limit=limit,
        )
        return StartupRecoveryResult(
            recovered_job_ids=recovered_jobs,
            escalated_job_ids=escalated_jobs,
            resolved_outage_ids=resolved_outages,
            completed_cancellation_ids=completed_cancellations,
            reconciled_target_ids=reconciled_targets,
        )

    def _reconcile_pending_outage_pages(
        self,
        *,
        limit: int,
    ) -> tuple[UUID, ...]:
        reconciled: list[UUID] = []
        seen_jobs: set[UUID] = set()
        after_id: UUID | None = None
        while True:
            with self._factory() as session:
                query = (
                    select(
                        DependencyOutageAttempt.id,
                        DependencyOutageAttempt.job_id,
                    )
                    .where(
                        DependencyOutageAttempt.exhausted.is_(True),
                        DependencyOutageAttempt.approval_request_id.is_(None),
                    )
                    .order_by(DependencyOutageAttempt.id)
                    .limit(limit)
                )
                if after_id is not None:
                    query = query.where(
                        DependencyOutageAttempt.id > after_id
                    )
                candidates = tuple(session.execute(query).tuples())
            if not candidates:
                return tuple(reconciled)
            after_id = candidates[-1][0]
            for _attempt_id, job_id in candidates:
                if job_id in seen_jobs:
                    continue
                seen_jobs.add(job_id)
                if self._jobs.reconcile_outage_escalation(job_id) is not None:
                    reconciled.append(job_id)
            if len(candidates) < limit:
                return tuple(reconciled)

    def _resume_pending_cleanup_pages(
        self,
        *,
        limit: int,
        terminator: OwnedProcessTerminator | None,
        cleaner: OwnedWorkspaceCleaner | None,
    ) -> tuple[UUID, ...]:
        completed: list[UUID] = []
        after_id: UUID | None = None
        while True:
            with self._factory() as session:
                query = (
                    select(TaskCancellation.id)
                    .where(
                        TaskCancellation.cleanup_completed_at.is_(None)
                    )
                    .order_by(TaskCancellation.id)
                    .limit(limit)
                )
                if after_id is not None:
                    query = query.where(TaskCancellation.id > after_id)
                cancellation_ids = tuple(session.scalars(query))
            if not cancellation_ids:
                return tuple(completed)
            after_id = cancellation_ids[-1]
            completed.extend(
                cancellation_id
                for cancellation_id in cancellation_ids
                if self._cancellations.resume_cleanup(
                    cancellation_id,
                    terminator=terminator,
                    cleaner=cleaner,
                )
            )
            if len(cancellation_ids) < limit:
                return tuple(completed)

    def _reconcile_targets(
        self,
        *,
        adapters: Mapping[
            ReconciliationTargetKind,
            ReconciliationAdapter,
        ],
        limit: int,
    ) -> tuple[UUID, ...]:
        reconciled: list[UUID] = []
        for kind in self._KIND_ORDER:
            after_id: UUID | None = None
            while True:
                with self._factory() as session:
                    query = (
                        select(ReconciliationTarget)
                        .where(
                            ReconciliationTarget.status
                            != ReconciliationStatus.CANCELLED,
                            ReconciliationTarget.kind == kind,
                        )
                        .order_by(ReconciliationTarget.id)
                        .limit(limit)
                    )
                    if after_id is not None:
                        query = query.where(
                            ReconciliationTarget.id > after_id
                        )
                    targets = tuple(session.scalars(query))
                    snapshots = tuple(
                        (
                            target.id,
                            target.target_key,
                            dict(target.expected_payload),
                            target.expected_fingerprint,
                            target.reconciliation_version,
                        )
                        for target in targets
                    )
                if not snapshots:
                    break
                after_id = snapshots[-1][0]
                for (
                    target_id,
                    target_key,
                    expected_payload,
                    expected_fingerprint,
                    expected_version,
                ) in snapshots:
                    adapter = adapters.get(kind)
                    if adapter is None:
                        observation = ReconciliationObservation(
                            status=ReconciliationStatus.RETRY_REQUIRED,
                            observed_payload={},
                            error_code="ADAPTER_UNAVAILABLE",
                        )
                    else:
                        observation = adapter.reconcile(
                            kind=kind,
                            target_key=target_key,
                            expected_payload=expected_payload,
                        )
                    with self._factory() as session, session.begin():
                        _begin_serialized(session)
                        target = session.scalar(
                            select(ReconciliationTarget)
                            .where(
                                ReconciliationTarget.id == target_id
                            )
                            .with_for_update()
                        )
                        if target is None:
                            raise ReliabilityConflictError(
                                "reconciliation target disappeared"
                            )
                        if (
                            target.expected_fingerprint
                            != expected_fingerprint
                            or target.reconciliation_version
                            != expected_version
                        ):
                            continue
                        now = _as_utc(self._clock())
                        target.observed_payload = dict(
                            observation.observed_payload
                        )
                        target.status = observation.status
                        target.reconciliation_version += 1
                        target.last_reconciled_at = now
                        target.last_error_code = observation.error_code
                        target.actor_id = self._principal_id
                        target.updated_at = now
                        session.flush()
                        reconciled.append(target.id)
                if len(snapshots) < limit:
                    break
        return tuple(reconciled)
