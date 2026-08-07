"""Durable, lease-fenced Hermes run integration."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import cast
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.background_jobs import (
    BackgroundJobLeaseLostError,
    BackgroundJobService,
    JobFailureDisposition,
    JobLeaseGrant,
)
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    BackgroundJob,
    BackgroundJobLease,
    BackgroundJobStatus,
    BackgroundJobToolGrant,
    DependencyOutageAttempt,
    DependencyService,
    EvidenceRecord,
    HermesRun,
    HermesRunEvent,
    HermesRunStatus,
    PolicyVersion,
    PolicyVersionPromptTemplate,
    PromptTemplateVersion,
    ReconciliationStatus,
    ReconciliationTarget,
    ReconciliationTargetKind,
    Task,
    TaskEvent,
    TaskEventEvidenceReference,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
    load_evidence,
)
from mathews_control_plane.prompt_compiler import CompiledPrompt

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}\Z")


class HermesError(RuntimeError):
    pass


class HermesNotFoundError(HermesError):
    pass


class HermesConflictError(HermesError):
    pass


class HermesEventType(StrEnum):
    RUNNING = "RUNNING"
    OUTPUT = "OUTPUT"
    TOOL_PROPOSAL = "TOOL_PROPOSAL"
    HEARTBEAT = "HEARTBEAT"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class HermesProviderEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    provider_event_id: str = Field(min_length=1, max_length=255)
    external_run_id: str = Field(min_length=1, max_length=255)
    sequence: int = Field(gt=0)
    event_type: HermesEventType
    payload: dict[str, object]


@dataclass(frozen=True, slots=True)
class HermesRunResult:
    run_id: UUID
    status: HermesRunStatus
    tool_grant_id: UUID
    replayed: bool


@dataclass(frozen=True, slots=True)
class HermesEventResult:
    run_id: UUID
    event_id: UUID
    accepted: bool
    ignored_reason: str | None
    task_event_id: UUID | None
    evidence_id: UUID
    replayed: bool


@dataclass(frozen=True, slots=True)
class HermesCancellationResult:
    run_id: UUID
    revoked_tool_grants: int
    replayed: bool


class HermesRunService:
    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        *,
        principal_id: str = "control-plane",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._factory = factory
        self._store = artifact_store
        self._principal_id = _identifier(principal_id, "principal")
        self._clock = clock or (lambda: datetime.now(UTC))

    def prepare(
        self,
        grant: JobLeaseGrant,
        *,
        run_id: UUID,
        prompt: CompiledPrompt,
    ) -> HermesRunResult:
        if prompt.task_id != grant.task_id:
            raise HermesConflictError("compiled prompt belongs to another task")
        with self._factory() as session:
            job = session.get(BackgroundJob, grant.job_id)
            if job is None or job.task_id != grant.task_id:
                raise HermesConflictError("Hermes job correlation conflicts")
            _validate_prompt(session, prompt, owner_id=job.owner_id)
            existing_attempt = session.scalar(
                select(HermesRun).where(
                    HermesRun.job_id == grant.job_id,
                    HermesRun.attempt == grant.attempt,
                )
            )
            if existing_attempt is not None and existing_attempt.id != run_id:
                raise HermesConflictError("Hermes job attempt already has a run")
        now = _as_utc(self._clock())
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            job, lease = _current_lease(session, grant, now)
            existing = session.get(HermesRun, run_id)
            if existing is not None:
                if not _run_matches(existing, grant, prompt):
                    raise HermesConflictError("Hermes run id conflicts")
                status = HermesRunStatus(existing.status)
                replayed = True
            else:
                _validate_prompt(session, prompt, owner_id=job.owner_id)
                run = HermesRun(
                    id=run_id,
                    task_id=job.task_id,
                    job_id=job.id,
                    lease_id=lease.id,
                    fencing_token=lease.fencing_token,
                    attempt=grant.attempt,
                    prompt_template_version_id=prompt.template_id,
                    policy_version_id=prompt.policy_version_id,
                    evaluation_label=prompt.evaluation_label,
                    prompt_fingerprint=_prompt_fingerprint(prompt),
                    status=HermesRunStatus.STARTING,
                    last_event_sequence=0,
                    started_at=now,
                    owner_id=job.owner_id,
                    actor_id=self._principal_id,
                    root_correlation_id=job.root_correlation_id,
                    causation_id=lease.id,
                    parent_correlation_id=job.id,
                )
                session.add(run)
                session.flush()
                status = HermesRunStatus.STARTING
                replayed = False
        tool = BackgroundJobService(
            self._factory,
            self._store,
            principal_id=self._principal_id,
            clock=self._clock,
        ).issue_tool_grant(
            grant,
            grant_key=f"hermes:{run_id}",
            capability_scope={"run_id": str(run_id), "task_id": str(grant.task_id)},
        )
        return HermesRunResult(run_id, status, tool.grant_id, replayed)

    def record_started(
        self,
        grant: JobLeaseGrant,
        *,
        run_id: UUID,
        external_run_id: str,
    ) -> HermesRunResult:
        external = _identifier(external_run_id, "external run")
        now = _as_utc(self._clock())
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            _current_lease(session, grant, now)
            run = _run_for_grant(session, run_id, grant)
            tool = _run_tool_grant(session, run)
            if run.external_run_id is not None:
                if run.external_run_id != external:
                    raise HermesConflictError("external Hermes run id conflicts")
                return HermesRunResult(run.id, run.status, tool.id, True)
            if run.status is not HermesRunStatus.STARTING:
                raise HermesConflictError("Hermes run cannot be started")
            run.external_run_id = external
            run.status = HermesRunStatus.RUNNING
            run.actor_id = self._principal_id
            run.updated_at = now
            expected = {
                "external_run_id": external,
                "fencing_token": run.fencing_token,
                "job_id": str(run.job_id),
                "lease_id": str(run.lease_id),
                "run_id": str(run.id),
            }
            target_key = f"hermes:{run.id}"
            target = session.scalar(
                select(ReconciliationTarget).where(
                    ReconciliationTarget.kind == ReconciliationTargetKind.HERMES_RUN,
                    ReconciliationTarget.target_key == target_key,
                )
            )
            fingerprint = sha256(_canonical_json(expected).encode()).hexdigest()
            if target is None:
                session.add(
                    ReconciliationTarget(
                        task_id=run.task_id,
                        job_id=run.job_id,
                        kind=ReconciliationTargetKind.HERMES_RUN,
                        target_key=target_key,
                        expected_payload=expected,
                        expected_fingerprint=fingerprint,
                        status=ReconciliationStatus.PENDING,
                        reconciliation_version=0,
                        owner_id=run.owner_id,
                        actor_id=self._principal_id,
                        root_correlation_id=run.root_correlation_id,
                        causation_id=run.id,
                        parent_correlation_id=run.job_id,
                    )
                )
            elif target.expected_fingerprint != fingerprint:
                raise HermesConflictError("Hermes reconciliation target conflicts")
            session.flush()
            return HermesRunResult(run.id, run.status, tool.id, False)

    def ingest(
        self,
        run_id: UUID,
        event: HermesProviderEvent,
    ) -> HermesEventResult:
        payload = _bounded_payload(event.payload)
        payload_fingerprint = _event_fingerprint(event, payload)
        now = _as_utc(self._clock())
        event_id = uuid5(NAMESPACE_URL, f"mathews:hermes:{run_id}:{event.provider_event_id}")
        evidence_id = uuid5(NAMESPACE_URL, f"mathews:hermes-evidence:{event_id}")
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            run = session.scalar(select(HermesRun).where(HermesRun.id == run_id).with_for_update())
            if run is None:
                raise HermesNotFoundError("Hermes run is unavailable")
            existing = session.scalar(
                select(HermesRunEvent).where(
                    HermesRunEvent.run_id == run.id,
                    HermesRunEvent.provider_event_id == event.provider_event_id,
                )
            )
            if existing is not None:
                if (
                    existing.provider_sequence != event.sequence
                    or existing.event_type != event.event_type.value
                    or existing.payload_fingerprint != payload_fingerprint
                ):
                    raise HermesConflictError("Hermes provider event id conflicts")
                return _event_result(existing, replayed=True)
            sequence_delivery = session.scalar(
                select(HermesRunEvent).where(
                    HermesRunEvent.run_id == run.id,
                    HermesRunEvent.provider_sequence == event.sequence,
                )
            )
            if sequence_delivery is not None:
                raise HermesConflictError("Hermes provider sequence conflicts")
            evidence_payload = {
                "run_id": str(run.id),
                "external_run_id": event.external_run_id,
                "provider_event_id": event.provider_event_id,
                "sequence": event.sequence,
                "event_type": event.event_type.value,
                "payload": payload,
                "payload_fingerprint": payload_fingerprint,
            }
            evidence = session.get(EvidenceRecord, evidence_id)
            if evidence is None:
                evidence = capture_evidence(
                    session,
                    self._store,
                    payload=evidence_payload,
                    media_type="application/json",
                    source_kind=EvidenceSourceKind.RESULT,
                    evidence_type="hermes-event",
                    origin="hermes:provider-event",
                    access_classification=EvidenceAccessClass.TASK_OWNER,
                    retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
                    owner_id=run.owner_id,
                    actor_id=self._principal_id,
                    root_correlation_id=run.root_correlation_id,
                    task_id=run.task_id,
                    causation_id=run.id,
                    parent_correlation_id=run.job_id,
                    evidence_id=evidence_id,
                    captured_at=now,
                ).record
            else:
                loaded_content = load_evidence(session, self._store, evidence).content
                if (
                    not isinstance(loaded_content, dict)
                    or loaded_content.get("payload_fingerprint") != payload_fingerprint
                ):
                    raise HermesConflictError("Hermes provider event evidence conflicts")
            ignored = _ignored_reason(session, run, event, now)
            if ignored == "OUT_OF_ORDER":
                return HermesEventResult(
                    run_id=run.id,
                    event_id=event_id,
                    accepted=False,
                    ignored_reason=ignored,
                    task_event_id=None,
                    evidence_id=evidence.id,
                    replayed=False,
                )
            task_event: TaskEvent | None = None
            if ignored is None:
                task_event = TaskEvent(
                    task_id=run.task_id,
                    sequence=_next_task_sequence(session, run.task_id),
                    event_type="HERMES_EVENT",
                    payload={
                        "schema_version": 1,
                        "run_id": str(run.id),
                        "attempt": run.attempt,
                        "fencing_token": run.fencing_token,
                        "provider_sequence": event.sequence,
                        "event_type": event.event_type.value,
                        "evidence_id": str(evidence.id),
                        "agent_prose_is_authoritative": False,
                    },
                    occurred_at=now,
                    owner_id=run.owner_id,
                    actor_id=self._principal_id,
                    root_correlation_id=run.root_correlation_id,
                    causation_id=run.id,
                    parent_correlation_id=run.job_id,
                )
                session.add(task_event)
                session.flush()
                session.add(
                    TaskEventEvidenceReference(
                        task_id=run.task_id,
                        task_event_id=task_event.id,
                        evidence_id=evidence.id,
                        position=1,
                        owner_id=run.owner_id,
                        actor_id=self._principal_id,
                        root_correlation_id=run.root_correlation_id,
                        causation_id=task_event.id,
                        parent_correlation_id=run.id,
                    )
                )
                run.last_event_sequence = event.sequence
                run.last_event_at = now
                if event.event_type is HermesEventType.COMPLETED:
                    run.status = HermesRunStatus.SUCCEEDED
                    run.completed_at = now
                elif event.event_type is HermesEventType.FAILED:
                    run.status = HermesRunStatus.FAILED
                    run.failure_code = _payload_error_code(payload)
                    run.completed_at = now
                else:
                    run.status = HermesRunStatus.RUNNING
                run.actor_id = self._principal_id
                run.updated_at = now
            delivery = HermesRunEvent(
                id=event_id,
                run_id=run.id,
                provider_event_id=event.provider_event_id,
                provider_sequence=event.sequence,
                event_type=event.event_type.value,
                payload_fingerprint=payload_fingerprint,
                payload_evidence_id=evidence.id,
                accepted=ignored is None,
                ignored_reason=ignored,
                task_event_id=None if task_event is None else task_event.id,
                received_at=now,
                owner_id=run.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=run.root_correlation_id,
                causation_id=run.id,
                parent_correlation_id=run.job_id,
            )
            session.add(delivery)
            session.flush()
            return _event_result(delivery, replayed=False)

    def cancel(self, run_id: UUID) -> HermesCancellationResult:
        now = _as_utc(self._clock())
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            run = session.scalar(select(HermesRun).where(HermesRun.id == run_id).with_for_update())
            if run is None:
                raise HermesNotFoundError("Hermes run is unavailable")
            if run.cancellation_requested_at is not None:
                revoked = session.scalar(
                    select(func.count())
                    .select_from(BackgroundJobToolGrant)
                    .where(
                        BackgroundJobToolGrant.job_id == run.job_id,
                        BackgroundJobToolGrant.revoke_reason == "HERMES_RUN_CANCELLED",
                    )
                )
                return HermesCancellationResult(run.id, int(revoked or 0), True)
            if run.status in {HermesRunStatus.SUCCEEDED, HermesRunStatus.FAILED}:
                raise HermesConflictError("completed Hermes run cannot be cancelled")
            grants = tuple(
                session.scalars(
                    select(BackgroundJobToolGrant)
                    .where(
                        BackgroundJobToolGrant.job_id == run.job_id,
                        BackgroundJobToolGrant.revoked_at.is_(None),
                    )
                    .with_for_update()
                )
            )
            for grant in grants:
                grant.revoked_at = now
                grant.revoke_reason = "HERMES_RUN_CANCELLED"
                grant.actor_id = self._principal_id
                grant.updated_at = now
            run.cancellation_requested_at = now
            run.status = HermesRunStatus.CANCELLED
            run.completed_at = now
            run.actor_id = self._principal_id
            run.updated_at = now
            session.flush()
            return HermesCancellationResult(run.id, len(grants), False)

    def fail_dependency(
        self,
        grant: JobLeaseGrant,
        *,
        run_id: UUID,
        error_code: str,
        timed_out: bool = False,
    ) -> JobFailureDisposition:
        code = _error_code(error_code)
        now = _as_utc(self._clock())
        target_status = HermesRunStatus.TIMED_OUT if timed_out else HermesRunStatus.FAILED
        jobs = BackgroundJobService(
            self._factory,
            self._store,
            principal_id=self._principal_id,
            clock=self._clock,
        )
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            run = _run_for_grant(session, run_id, grant)
            recovered = _outage_disposition(session, grant, code)
            if recovered is None:
                if run.status not in {HermesRunStatus.STARTING, HermesRunStatus.RUNNING}:
                    raise HermesConflictError("terminal Hermes run cannot fail its dependency")
                _current_lease(session, grant, now)
        if recovered is None:
            try:
                disposition = jobs.fail_dependency_attempt(
                    grant,
                    service=DependencyService.HERMES,
                    error_code=code,
                )
            except BackgroundJobLeaseLostError:
                with self._factory() as session:
                    recovered = _outage_disposition(session, grant, code)
                if recovered is None:
                    raise HermesConflictError("Hermes job lease is no longer current") from None
                disposition = recovered
        else:
            disposition = recovered
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            run = _run_for_grant(session, run_id, grant)
            _project_dependency_failure(
                run,
                target_status=target_status,
                error_code=code,
                principal_id=self._principal_id,
                now=now,
            )
            session.flush()
        if disposition.exhausted and disposition.escalation_request_id is None:
            escalation_id = jobs.reconcile_outage_escalation(grant.job_id)
            return JobFailureDisposition(
                status=disposition.status,
                next_attempt_at=disposition.next_attempt_at,
                exhausted=True,
                retry_delay=disposition.retry_delay,
                escalation_request_id=escalation_id,
            )
        return disposition


def _current_lease(
    session: Session,
    grant: JobLeaseGrant,
    now: datetime,
) -> tuple[BackgroundJob, BackgroundJobLease]:
    job = session.scalar(
        select(BackgroundJob).where(BackgroundJob.id == grant.job_id).with_for_update()
    )
    lease = session.scalar(
        select(BackgroundJobLease)
        .where(
            BackgroundJobLease.id == grant.lease_id,
            BackgroundJobLease.job_id == grant.job_id,
            BackgroundJobLease.fencing_token == grant.fencing_token,
        )
        .with_for_update()
    )
    if (
        job is None
        or lease is None
        or job.task_id != grant.task_id
        or job.status is not BackgroundJobStatus.RUNNING
        or job.current_lease_id != lease.id
        or job.current_fencing_token != lease.fencing_token
        or job.lease_owner != grant.worker_id
        or job.lease_expires_at is None
        or job.cancellation_requested_at is not None
        or lease.lease_owner != grant.worker_id
        or lease.attempt != grant.attempt
        or lease.released_at is not None
        or _as_utc(job.lease_expires_at) <= now
        or _as_utc(lease.expires_at) <= now
    ):
        raise HermesConflictError("Hermes job lease is no longer current")
    return job, lease


def _run_for_grant(session: Session, run_id: UUID, grant: JobLeaseGrant) -> HermesRun:
    run = session.scalar(select(HermesRun).where(HermesRun.id == run_id).with_for_update())
    if run is None:
        raise HermesNotFoundError("Hermes run is unavailable")
    if (
        run.task_id != grant.task_id
        or run.job_id != grant.job_id
        or run.lease_id != grant.lease_id
        or run.fencing_token != grant.fencing_token
        or run.attempt != grant.attempt
    ):
        raise HermesConflictError("Hermes run lease correlation conflicts")
    return run


def _outage_disposition(
    session: Session,
    grant: JobLeaseGrant,
    error_code: str,
) -> JobFailureDisposition | None:
    outage = session.scalar(
        select(DependencyOutageAttempt).where(
            DependencyOutageAttempt.job_id == grant.job_id,
            DependencyOutageAttempt.attempt == grant.attempt,
        )
    )
    if outage is None:
        return None
    if (
        outage.lease_id != grant.lease_id
        or outage.fencing_token != grant.fencing_token
        or outage.service != DependencyService.HERMES
        or outage.error_code != error_code
    ):
        raise HermesConflictError("Hermes outage attempt conflicts")
    job = session.get(BackgroundJob, grant.job_id)
    lease = session.get(BackgroundJobLease, grant.lease_id)
    if job is None or lease is None:
        raise HermesConflictError("Hermes outage disposition is unavailable")
    retry_at = (
        None
        if outage.exhausted or lease.retry_at is None
        else _as_utc(lease.retry_at)
    )
    retry_delay = (
        None
        if retry_at is None
        else retry_at - _as_utc(outage.occurred_at)
    )
    return JobFailureDisposition(
        status=BackgroundJobStatus(job.status),
        next_attempt_at=retry_at,
        exhausted=outage.exhausted,
        retry_delay=retry_delay,
        escalation_request_id=outage.approval_request_id,
    )


def _project_dependency_failure(
    run: HermesRun,
    *,
    target_status: HermesRunStatus,
    error_code: str,
    principal_id: str,
    now: datetime,
) -> None:
    if run.status in {HermesRunStatus.STARTING, HermesRunStatus.RUNNING}:
        run.status = target_status
        run.failure_code = error_code
        run.completed_at = now
        run.actor_id = principal_id
        run.updated_at = now
        return
    if run.status is target_status and run.failure_code == error_code:
        return
    raise HermesConflictError("terminal Hermes run cannot fail its dependency")


def _run_tool_grant(session: Session, run: HermesRun) -> BackgroundJobToolGrant:
    grant = session.scalar(
        select(BackgroundJobToolGrant).where(
            BackgroundJobToolGrant.job_id == run.job_id,
            BackgroundJobToolGrant.grant_key == f"hermes:{run.id}",
        )
    )
    if grant is None:
        raise HermesConflictError("Hermes run tool grant is unavailable")
    return grant


def _run_matches(run: HermesRun, grant: JobLeaseGrant, prompt: CompiledPrompt) -> bool:
    return bool(
        run.task_id == grant.task_id
        and run.job_id == grant.job_id
        and run.lease_id == grant.lease_id
        and run.fencing_token == grant.fencing_token
        and run.attempt == grant.attempt
        and run.prompt_template_version_id == prompt.template_id
        and run.policy_version_id == prompt.policy_version_id
        and run.evaluation_label == prompt.evaluation_label
        and run.prompt_fingerprint == _prompt_fingerprint(prompt)
    )


def _validate_prompt(session: Session, prompt: CompiledPrompt, *, owner_id: str) -> None:
    template = session.get(PromptTemplateVersion, prompt.template_id)
    policy = session.get(PolicyVersion, prompt.policy_version_id)
    if (
        template is None
        or policy is None
        or template.owner_id != owner_id
        or policy.owner_id != owner_id
        or template.role != prompt.role.value
        or template.version != prompt.template_version
    ):
        raise HermesConflictError("compiled prompt provenance is unavailable")
    if prompt.evaluation_label is not None:
        _identifier(prompt.evaluation_label, "evaluation label")
        return
    membership = session.scalar(
        select(PolicyVersionPromptTemplate).where(
            PolicyVersionPromptTemplate.policy_version_id == policy.id,
            PolicyVersionPromptTemplate.prompt_template_version_id == template.id,
        )
    )
    if membership is None:
        raise HermesConflictError("compiled prompt is not active in its policy")


def _prompt_fingerprint(prompt: CompiledPrompt) -> str:
    value = {
        "content": prompt.content,
        "evaluation_label": prompt.evaluation_label,
        "evidence_ids": [str(value) for value in prompt.evidence_ids],
        "policy_version_id": str(prompt.policy_version_id),
        "role": prompt.role.value,
        "task_id": str(prompt.task_id),
        "template_id": str(prompt.template_id),
        "template_version": prompt.template_version,
    }
    return sha256(_canonical_json(value).encode()).hexdigest()


def _event_fingerprint(
    event: HermesProviderEvent,
    payload: Mapping[str, object],
) -> str:
    value = {
        "event_type": event.event_type.value,
        "external_run_id": event.external_run_id,
        "payload": payload,
        "provider_event_id": event.provider_event_id,
        "sequence": event.sequence,
    }
    return sha256(_canonical_json(value).encode()).hexdigest()


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _ignored_reason(
    session: Session,
    run: HermesRun,
    event: HermesProviderEvent,
    now: datetime,
) -> str | None:
    if run.external_run_id != event.external_run_id:
        return "EXTERNAL_RUN_MISMATCH"
    if run.cancellation_requested_at is not None or run.status in {
        HermesRunStatus.CANCELLED,
        HermesRunStatus.SUCCEEDED,
        HermesRunStatus.FAILED,
        HermesRunStatus.TIMED_OUT,
    }:
        return "RUN_TERMINAL"
    job = session.get(BackgroundJob, run.job_id)
    lease = session.get(BackgroundJobLease, run.lease_id)
    if (
        job is None
        or lease is None
        or job.status is not BackgroundJobStatus.RUNNING
        or job.current_lease_id != run.lease_id
        or job.current_fencing_token != run.fencing_token
        or lease.released_at is not None
        or _as_utc(lease.expires_at) <= now
    ):
        return "STALE_LEASE"
    if event.sequence != run.last_event_sequence + 1:
        return "OUT_OF_ORDER"
    return None


def _bounded_payload(value: Mapping[str, object]) -> dict[str, object]:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        raise HermesConflictError("Hermes event payload is not JSON safe") from None
    if len(encoded) > 64_000:
        raise HermesConflictError("Hermes event payload exceeds its size limit")
    return cast(dict[str, object], json.loads(encoded))


def _payload_error_code(payload: Mapping[str, object]) -> str:
    value = payload.get("error_code", "HERMES_RUN_FAILED")
    if not isinstance(value, str):
        return "HERMES_RUN_FAILED"
    try:
        return _error_code(value)
    except HermesConflictError:
        return "HERMES_RUN_FAILED"


def _event_result(event: HermesRunEvent, *, replayed: bool) -> HermesEventResult:
    return HermesEventResult(
        run_id=event.run_id,
        event_id=event.id,
        accepted=event.accepted,
        ignored_reason=event.ignored_reason,
        task_event_id=event.task_event_id,
        evidence_id=event.payload_evidence_id,
        replayed=replayed,
    )


def _next_task_sequence(session: Session, task_id: UUID) -> int:
    task = session.scalar(select(Task.id).where(Task.id == task_id).with_for_update())
    if task is None:
        raise HermesConflictError("Hermes task is unavailable")
    value = session.scalar(select(func.max(TaskEvent.sequence)).where(TaskEvent.task_id == task_id))
    return int(value or 0) + 1


def _identifier(value: str, field: str) -> str:
    normalized = value.strip()
    if _IDENTIFIER.fullmatch(normalized) is None:
        raise HermesConflictError(f"{field} is invalid")
    return normalized


def _error_code(value: str) -> str:
    normalized = value.strip().upper()
    if re.fullmatch(r"[A-Z][A-Z0-9_]{0,99}", normalized) is None:
        raise HermesConflictError("Hermes error code is invalid")
    return normalized


def _begin_serialized(session: Session) -> None:
    if session.get_bind().dialect.name == "sqlite":
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
