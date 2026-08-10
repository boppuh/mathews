"""Durable task steering with explicit scope classification and work fencing."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import NAMESPACE_URL, UUID, uuid5

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    BackgroundJob,
    BackgroundJobLease,
    BackgroundJobStatus,
    BackgroundJobToolGrant,
    DependencyOutageAttempt,
    EvidenceRecord,
    HermesRun,
    HermesRunStatus,
    OwnedHostProcess,
    OwnedHostProcessStatus,
    PolicyVersion,
    ReconciliationStatus,
    ReconciliationTarget,
    ReconciliationTargetKind,
    Task,
    TaskEvent,
    TaskEventEvidenceReference,
    TaskState,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
    load_evidence,
)
from mathews_control_plane.task_state_machine import (
    TaskTransitionGateEvaluator,
    TaskTransitionGuards,
    TaskTransitionKind,
    _transition_task,
)

STEERING_EVENT_TYPE = "TASK_STEERING_RECORDED"
STEERING_EVENT_SCHEMA_VERSION = 1
STEERING_EVIDENCE_TYPE = "task-steering-message"


class SteeringImpact(StrEnum):
    ACCEPTANCE_CRITERIA = "ACCEPTANCE_CRITERIA"
    PATHS = "PATHS"
    RISK = "RISK"
    TESTS = "TESTS"


class SteeringClassification(StrEnum):
    CLARIFICATION = "CLARIFICATION"
    SCOPE_CHANGE = "SCOPE_CHANGE"


class SteeringError(RuntimeError):
    """Base class for safe steering failures."""


class SteeringNotFoundError(SteeringError):
    """The task is unavailable to the steering principal."""


class SteeringConflictError(SteeringError):
    """The task or idempotent steering command changed."""


@dataclass(frozen=True, slots=True)
class SteeringResult:
    steering_id: UUID
    task_id: UUID
    classification: SteeringClassification
    impacts: tuple[SteeringImpact, ...]
    task_state: TaskState
    evidence_id: UUID
    request_evidence_id: UUID
    event_id: UUID
    invalidated_brief_id: UUID | None
    invalidated_validation_contract_id: UUID | None
    revoked_lease_count: int
    revoked_tool_grant_count: int
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class _ScopeSteeringGates(TaskTransitionGateEvaluator):
    def evaluate(
        self,
        session: Session,
        task: Task,
        kind: TaskTransitionKind,
        *,
        policy: PolicyVersion,
        now: datetime,
    ) -> TaskTransitionGuards:
        del session, task, kind, policy, now
        return TaskTransitionGuards(
            work_fence_verified=True,
            scope_decisions_invalidated=True,
        )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _fingerprint(value: dict[str, object]) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _derived_id(steering_id: UUID, label: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"mathews:steering:{steering_id}:{label}")


def _next_event_sequence(session: Session, task_id: UUID) -> int:
    current = session.scalar(
        select(func.max(TaskEvent.sequence)).where(TaskEvent.task_id == task_id)
    )
    return int(current or 0) + 1


def _stored_result(event: TaskEvent, *, replayed: bool) -> SteeringResult:
    payload = event.payload
    try:
        impacts_value = payload["impacts"]
        revoked_lease_count = payload["revoked_lease_count"]
        revoked_tool_grant_count = payload["revoked_tool_grant_count"]
        if not isinstance(impacts_value, list) or not all(
            isinstance(value, str) for value in impacts_value
        ):
            raise TypeError
        if (
            not isinstance(revoked_lease_count, int)
            or isinstance(revoked_lease_count, bool)
            or revoked_lease_count < 0
            or not isinstance(revoked_tool_grant_count, int)
            or isinstance(revoked_tool_grant_count, bool)
            or revoked_tool_grant_count < 0
        ):
            raise TypeError
        return SteeringResult(
            steering_id=UUID(str(payload["steering_id"])),
            task_id=event.task_id,
            classification=SteeringClassification(str(payload["classification"])),
            impacts=tuple(
                SteeringImpact(str(value))
                for value in impacts_value
            ),
            task_state=TaskState(str(payload["resulting_state"])),
            evidence_id=UUID(str(payload["evidence_id"])),
            request_evidence_id=UUID(str(payload["request_evidence_id"])),
            event_id=event.id,
            invalidated_brief_id=(
                None
                if payload["invalidated_brief_id"] is None
                else UUID(str(payload["invalidated_brief_id"]))
            ),
            invalidated_validation_contract_id=(
                None
                if payload["invalidated_validation_contract_id"] is None
                else UUID(str(payload["invalidated_validation_contract_id"]))
            ),
            revoked_lease_count=revoked_lease_count,
            revoked_tool_grant_count=revoked_tool_grant_count,
            replayed=replayed,
        )
    except (KeyError, TypeError, ValueError):
        raise SteeringConflictError("stored steering event is invalid") from None


def _current_request_evidence(session: Session, task: Task) -> EvidenceRecord:
    prefix = "evidence://"
    if not task.raw_request.startswith(prefix):
        raise SteeringConflictError("current task request evidence is unavailable")
    try:
        evidence_id = UUID(task.raw_request.removeprefix(prefix))
    except ValueError:
        raise SteeringConflictError("current task request evidence is invalid") from None
    record = session.get(EvidenceRecord, evidence_id)
    if (
        record is None
        or record.task_id != task.id
        or record.evidence_type != "task-request"
        or record.deleted_at is not None
    ):
        raise SteeringConflictError("current task request evidence is unavailable")
    return record


def _revise_task_request(
    session: Session,
    artifact_store: ArtifactStore,
    task: Task,
    *,
    steering_id: UUID,
    message: str,
    classification: SteeringClassification,
    impacts: tuple[SteeringImpact, ...],
    actor_id: str,
    now: datetime,
) -> EvidenceRecord:
    current = _current_request_evidence(session, task)
    loaded = load_evidence(session, artifact_store, current)
    if not isinstance(loaded.content, str):
        raise SteeringConflictError("current task request evidence is invalid")
    impact_label = (
        "cosmetic in-scope clarification"
        if classification is SteeringClassification.CLARIFICATION
        else ", ".join(value.value.lower().replace("_", " ") for value in impacts)
    )
    revised = (
        f"{loaded.content.rstrip()}\n\n"
        f"User steering ({impact_label}):\n{message}"
    )
    summary = task.summary
    captured = capture_evidence(
        session,
        artifact_store,
        payload=revised,
        media_type="text/plain; charset=utf-8",
        source_kind=EvidenceSourceKind.REQUEST,
        evidence_type="task-request",
        origin=f"task:{task.id}:steering-revision",
        access_classification=EvidenceAccessClass.TASK_OWNER,
        retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
        owner_id=task.owner_id,
        actor_id=actor_id,
        root_correlation_id=task.root_correlation_id,
        task_id=task.id,
        causation_id=steering_id,
        parent_correlation_id=current.id,
        correction_of_id=current.id,
        evidence_id=_derived_id(steering_id, "request-revision"),
        captured_at=now,
    )
    task.summary = summary
    return captured.record


def _fence_scope_work(
    session: Session,
    task: Task,
    *,
    steering_id: UUID,
    actor_id: str,
    now: datetime,
) -> tuple[int, int, tuple[UUID, ...]]:
    jobs = tuple(
        session.scalars(
            select(BackgroundJob)
            .where(BackgroundJob.task_id == task.id)
            .order_by(BackgroundJob.created_at, BackgroundJob.id)
            .with_for_update()
        )
    )
    revoked_leases = 0
    for job in jobs:
        if job.status not in {BackgroundJobStatus.QUEUED, BackgroundJobStatus.RUNNING}:
            continue
        job.cancellation_requested_at = job.cancellation_requested_at or now
        if job.status is BackgroundJobStatus.RUNNING and job.current_lease_id is not None:
            lease = session.scalar(
                select(BackgroundJobLease)
                .where(
                    BackgroundJobLease.id == job.current_lease_id,
                    BackgroundJobLease.job_id == job.id,
                    BackgroundJobLease.fencing_token == job.current_fencing_token,
                    BackgroundJobLease.released_at.is_(None),
                )
                .with_for_update()
            )
            if lease is None:
                raise SteeringConflictError("active task lease is unavailable")
            lease.released_at = now
            lease.release_reason = "CANCELLED"
            lease.failure_code = "SCOPE_STEERED"
            lease.cancellation_acknowledged_at = now
            lease.actor_id = actor_id
            lease.updated_at = now
            revoked_leases += 1
        job.status = BackgroundJobStatus.CANCELLED
        job.current_lease_id = None
        job.current_fencing_token = None
        job.lease_owner = None
        job.lease_expires_at = None
        job.last_error_code = "SCOPE_STEERED"
        job.completed_at = now
        job.actor_id = actor_id
        job.updated_at = now

    job_ids = tuple(job.id for job in jobs)
    grants: tuple[BackgroundJobToolGrant, ...] = ()
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
            grant.revoke_reason = "SCOPE_STEERED"
            grant.actor_id = actor_id
            grant.updated_at = now
        processes = tuple(
            session.scalars(
                select(OwnedHostProcess)
                .where(
                    OwnedHostProcess.job_id.in_(job_ids),
                    OwnedHostProcess.status == OwnedHostProcessStatus.RUNNING,
                )
                .with_for_update()
            )
        )
        for process in processes:
            process.status = OwnedHostProcessStatus.TERMINATION_REQUESTED
            process.termination_requested_at = now
            process.actor_id = actor_id
            process.updated_at = now

    runs = tuple(
        session.scalars(
            select(HermesRun)
            .where(
                HermesRun.task_id == task.id,
                HermesRun.status.in_((HermesRunStatus.STARTING, HermesRunStatus.RUNNING)),
            )
            .with_for_update()
        )
    )
    for run in runs:
        run.cancellation_requested_at = run.cancellation_requested_at or now
        run.actor_id = actor_id
        run.updated_at = now

    targets = tuple(
        session.scalars(
            select(ReconciliationTarget)
            .where(
                ReconciliationTarget.task_id == task.id,
                ReconciliationTarget.kind != ReconciliationTargetKind.HOST_PROCESS,
                ReconciliationTarget.status != ReconciliationStatus.CANCELLED,
            )
            .with_for_update()
        )
    )
    for target in targets:
        target.observed_payload = {"reason_code": "SCOPE_STEERED"}
        target.status = ReconciliationStatus.CANCELLED
        target.reconciliation_version += 1
        target.last_reconciled_at = now
        target.last_error_code = None
        target.actor_id = actor_id
        target.updated_at = now

    pending = tuple(
        session.scalars(
            select(ApprovalRequest)
            .where(
                ApprovalRequest.task_id == task.id,
                ApprovalRequest.status == ApprovalStatus.PENDING,
            )
            .with_for_update()
        )
    )
    for request in pending:
        decision_id = _derived_id(steering_id, f"approval:{request.id}")
        request.status = ApprovalStatus.CANCELLED
        request.decision = ApprovalDecision.CANCEL.value
        request.decision_id = decision_id
        request.decision_fingerprint = _fingerprint(
            {
                "actor_id": actor_id,
                "decision": ApprovalDecision.CANCEL.value,
                "decision_id": str(decision_id),
                "request_id": str(request.id),
                "steering_id": str(steering_id),
            }
        )
        request.decided_by = actor_id
        request.decided_at = now
        request.actor_id = actor_id
        request.updated_at = now

    outages = tuple(
        session.scalars(
            select(DependencyOutageAttempt)
            .join(BackgroundJob, BackgroundJob.id == DependencyOutageAttempt.job_id)
            .where(
                BackgroundJob.task_id == task.id,
                DependencyOutageAttempt.exhausted.is_(True),
                DependencyOutageAttempt.resolved_at.is_(None),
            )
            .with_for_update()
        )
    )
    for outage in outages:
        outage.resolved_at = now
        outage.decision_id = _derived_id(steering_id, f"outage:{outage.id}")
        outage.actor_id = actor_id
        outage.updated_at = now

    session.flush()
    return revoked_leases, len(grants), tuple(request.id for request in pending)


class SteeringService:
    """Record user steering and enforce the scope-change boundary atomically."""

    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        *,
        active_policy_lineage: str = "mvp",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._factory = factory
        self._artifact_store = artifact_store
        self._active_policy_lineage = active_policy_lineage
        self._clock = clock or (lambda: datetime.now(UTC))

    def steer(
        self,
        task_id: UUID,
        *,
        steering_id: UUID,
        expected_state: TaskState,
        message: str,
        impacts: Sequence[SteeringImpact],
        owner_id: str,
    ) -> SteeringResult:
        normalized_message = message.strip()
        if not normalized_message:
            raise SteeringConflictError("steering message is empty")
        normalized_impacts = tuple(sorted(set(impacts), key=lambda value: value.value))
        classification = (
            SteeringClassification.SCOPE_CHANGE
            if normalized_impacts
            else SteeringClassification.CLARIFICATION
        )
        fingerprint = _fingerprint(
            {
                "expected_state": expected_state.value,
                "impacts": [value.value for value in normalized_impacts],
                "message": normalized_message,
                "owner_id": owner_id,
                "steering_id": str(steering_id),
                "task_id": str(task_id),
            }
        )
        event_id = _derived_id(steering_id, "event")
        evidence_id = _derived_id(steering_id, "evidence")
        now = _as_utc(self._clock())

        with self._factory() as session, session.begin():
            if session.get_bind().dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            task = session.scalar(select(Task).where(Task.id == task_id).with_for_update())
            if task is None or task.owner_id != owner_id:
                raise SteeringNotFoundError("task is unavailable")
            existing = session.get(TaskEvent, event_id)
            if existing is not None:
                if (
                    existing.task_id != task.id
                    or existing.owner_id != task.owner_id
                    or existing.event_type != STEERING_EVENT_TYPE
                    or existing.payload.get("request_fingerprint") != fingerprint
                ):
                    raise SteeringConflictError("steering id conflicts")
                return _stored_result(existing, replayed=True)
            current_state = TaskState(task.state)
            if current_state is not expected_state:
                raise SteeringConflictError("task state changed before steering")
            if current_state in {TaskState.HANDED_OFF, TaskState.FAILED, TaskState.CANCELLED}:
                raise SteeringConflictError("terminal task cannot be steered")
            if (
                classification is SteeringClassification.SCOPE_CHANGE
                and current_state is TaskState.ESCALATED
            ):
                raise SteeringConflictError("resolve the escalation before changing scope")

            captured = capture_evidence(
                session,
                self._artifact_store,
                payload=normalized_message,
                media_type="text/plain; charset=utf-8",
                source_kind=EvidenceSourceKind.REQUEST,
                evidence_type=STEERING_EVIDENCE_TYPE,
                origin=f"task:{task.id}:steering",
                access_classification=EvidenceAccessClass.TASK_OWNER,
                retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
                owner_id=task.owner_id,
                actor_id=owner_id,
                root_correlation_id=task.root_correlation_id,
                task_id=task.id,
                causation_id=steering_id,
                parent_correlation_id=task.id,
                evidence_id=evidence_id,
                captured_at=now,
            )
            request_evidence = _revise_task_request(
                session,
                self._artifact_store,
                task,
                steering_id=steering_id,
                message=normalized_message,
                classification=classification,
                impacts=normalized_impacts,
                actor_id=owner_id,
                now=now,
            )
            invalidated_brief_id = task.accepted_brief_id
            invalidated_contract_id = task.validation_contract_id
            revoked_leases = 0
            revoked_grants = 0
            invalidated_approval_ids: tuple[UUID, ...] = ()
            resulting_state = current_state
            if classification is SteeringClassification.SCOPE_CHANGE:
                revoked_leases, revoked_grants, invalidated_approval_ids = _fence_scope_work(
                    session,
                    task,
                    steering_id=steering_id,
                    actor_id=owner_id,
                    now=now,
                )
                resulting_state = TaskState.BRIEFING

            event = TaskEvent(
                id=event_id,
                task_id=task.id,
                sequence=_next_event_sequence(session, task.id),
                event_type=STEERING_EVENT_TYPE,
                payload={
                    "schema_version": STEERING_EVENT_SCHEMA_VERSION,
                    "steering_id": str(steering_id),
                    "request_fingerprint": fingerprint,
                    "classification": classification.value,
                    "impacts": [value.value for value in normalized_impacts],
                    "evidence_id": str(captured.record.id),
                    "request_evidence_id": str(request_evidence.id),
                    "expected_state": expected_state.value,
                    "resulting_state": resulting_state.value,
                    "invalidated_brief_id": (
                        None if invalidated_brief_id is None else str(invalidated_brief_id)
                    ),
                    "invalidated_validation_contract_id": (
                        None if invalidated_contract_id is None else str(invalidated_contract_id)
                    ),
                    "invalidated_approval_ids": [
                        str(value) for value in invalidated_approval_ids
                    ],
                    "revoked_lease_count": revoked_leases,
                    "revoked_tool_grant_count": revoked_grants,
                },
                occurred_at=now,
                owner_id=task.owner_id,
                actor_id=owner_id,
                root_correlation_id=task.root_correlation_id,
                causation_id=steering_id,
                parent_correlation_id=task.id,
            )
            session.add(event)
            session.flush()
            session.add(
                TaskEventEvidenceReference(
                    task_id=task.id,
                    task_event_id=event.id,
                    evidence_id=captured.record.id,
                    position=1,
                    owner_id=task.owner_id,
                    actor_id=owner_id,
                    root_correlation_id=task.root_correlation_id,
                    causation_id=event.id,
                    parent_correlation_id=steering_id,
                )
            )
            session.flush()
            if classification is SteeringClassification.SCOPE_CHANGE:
                _transition_task(
                    session,
                    self._artifact_store,
                    task_id=task.id,
                    transition_id=steering_id,
                    expected_state=expected_state,
                    kind=TaskTransitionKind.SCOPE_STEER,
                    reason_code="USER_SCOPE_STEERING",
                    actor_id=owner_id,
                    evidence_ids=(captured.record.id,),
                    validation_candidate=None,
                    gate_evaluator=_ScopeSteeringGates(),
                    active_policy_lineage=self._active_policy_lineage,
                    occurred_at=now,
                )
            return SteeringResult(
                steering_id=steering_id,
                task_id=task.id,
                classification=classification,
                impacts=normalized_impacts,
                task_state=resulting_state,
                evidence_id=captured.record.id,
                request_evidence_id=request_evidence.id,
                event_id=event.id,
                invalidated_brief_id=invalidated_brief_id,
                invalidated_validation_contract_id=invalidated_contract_id,
                revoked_lease_count=revoked_leases,
                revoked_tool_grant_count=revoked_grants,
            )
