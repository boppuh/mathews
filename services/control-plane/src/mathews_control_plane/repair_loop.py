"""Bounded, evidence-backed validation repair orchestration."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol, cast
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from mathews_configuration import (
    HostOperation,
    HostRequestMessage,
    HostResponseMessage,
    HostResponseStatus,
    JsonValue,
)
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from mathews_control_plane.approvals import (
    ApprovalRequestResult,
    ApprovalRetryAttempt,
    ApprovalService,
    BlockedOperation,
)
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.background_jobs import (
    BackgroundJobService,
    DependencyOutageError,
    JobLeaseGrant,
    LeasedJobContext,
    TerminalBackgroundJobError,
    require_current_job_lease,
)
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalRequestType,
    ApprovalStatus,
    BackgroundJob,
    DependencyService,
    EvidenceRecord,
    PolicyVersion,
    RepositoryConfiguration,
    Task,
    TaskEvent,
    TaskEventEvidenceReference,
    TaskState,
    ValidationContract,
    ValidationOutcome,
    ValidationRun,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceError,
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
    load_evidence,
    redact_evidence_content,
)
from mathews_control_plane.hermes_adapter import HermesJobInput, HermesJobPrompt
from mathews_control_plane.host_gateway import (
    HostGatewayError,
    authority_for_job_lease,
)
from mathews_control_plane.prompt_compiler import PromptCompilerService, PromptRole
from mathews_control_plane.repository_configuration import (
    validated_repository_configuration,
)
from mathews_control_plane.task_state_machine import (
    TaskTransitionGateEvaluator,
    TaskTransitionGuards,
    TaskTransitionKind,
    ValidationCandidate,
)
from mathews_control_plane.validation_decisioning import (
    VALIDATION_DECIDED_EVENT_TYPE,
    ValidationDecisionError,
    ValidationDecisionResult,
    ValidationDecisionService,
)

VALIDATION_REPAIR_JOB_TYPE = "validation-repair"
VALIDATION_RERUN_REQUESTED_EVENT_TYPE = "VALIDATION_RERUN_REQUESTED"
REPAIR_SCHEMA_VERSION = 1
DEFAULT_MAX_REPAIR_ATTEMPTS = 2
DEFAULT_APPROVAL_LIFETIME_SECONDS = 86_400
MAX_REPAIR_ATTEMPTS = 10
_GIT_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


class RepairLoopError(RuntimeError):
    """A stable repair refusal without evidence contents."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RepairScheduleStatus(StrEnum):
    SCHEDULED = "SCHEDULED"
    ESCALATED = "ESCALATED"


@dataclass(frozen=True, slots=True)
class RepairScheduleResult:
    validation_run_id: UUID
    task_id: UUID
    status: RepairScheduleStatus
    failure_fingerprint: str
    job_id: UUID | None = None
    approval_request_id: UUID | None = None
    replayed: bool = False


class RepairJobInput(BaseModel):
    """Exact failed-run and prompt bindings carried by one durable repair job."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = REPAIR_SCHEMA_VERSION
    validation_run_id: UUID
    task_id: UUID
    failure_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    failed_commit_sha: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    failed_tree_sha: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    validation_contract_id: UUID
    validation_contract_version: int = Field(gt=0)
    repository_configuration_id: UUID
    repository_configuration_version: int = Field(gt=0)
    decision_evidence_id: UUID
    manifest_evidence_id: UUID
    prompt: HermesJobPrompt
    retry_approval_decision_id: UUID | None = None


class RepairHermesHandler(Protocol):
    def __call__(self, context: LeasedJobContext) -> Mapping[str, object] | None: ...


class RepairHostGateway(Protocol):
    def execute(self, request: HostRequestMessage) -> HostResponseMessage: ...


@dataclass(frozen=True, slots=True)
class _RepairContext:
    task_id: UUID
    task_retry_count: int
    validation_run_id: UUID
    failed_commit_sha: str
    failed_tree_sha: str
    validation_contract_id: UUID
    validation_contract_version: int
    repository_configuration_id: UUID
    repository_configuration_version: int
    decision_evidence_id: UUID
    manifest_evidence_id: UUID
    failure_fingerprint: str
    max_attempts: int
    approval_lifetime_seconds: int


class ValidationRepairService:
    """Schedule one scoped repair or create the smallest retry decision."""

    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        *,
        principal_id: str = "control-plane",
        clock: Callable[[], datetime] | None = None,
        prompt_compiler: PromptCompilerService | None = None,
        approvals: ApprovalService | None = None,
    ) -> None:
        self._factory = factory
        self._store = artifact_store
        self._principal_id = principal_id
        self._clock = clock or (lambda: datetime.now(UTC))
        self._prompts = prompt_compiler or PromptCompilerService(
            factory,
            artifact_store,
            principal_id=principal_id,
            clock=self._clock,
        )
        self._approvals = approvals or ApprovalService(
            factory,
            artifact_store,
            principal_id=principal_id,
            clock=self._clock,
        )
        self._jobs = BackgroundJobService(
            factory,
            artifact_store,
            principal_id=principal_id,
            clock=self._clock,
        )
        self._decisions = ValidationDecisionService(
            factory,
            artifact_store,
            principal_id="local-user",
            clock=self._clock,
        )

    def schedule(
        self,
        validation_run_id: UUID,
        *,
        decision: ValidationDecisionResult | None = None,
    ) -> RepairScheduleResult:
        if decision is None:
            try:
                decision = self._decisions.decide(validation_run_id)
            except ValidationDecisionError as error:
                raise RepairLoopError(error.code) from None
        elif decision.validation_run_id != validation_run_id:
            raise RepairLoopError("VALIDATION_DECISION_RUN_MISMATCH")
        if decision.outcome is not ValidationOutcome.FAILED or not decision.is_current:
            raise RepairLoopError("VALIDATION_FAILURE_NOT_REPAIRABLE")
        now = _as_utc(self._clock())
        with self._factory() as session:
            context = _repair_context(
                session,
                self._store,
                validation_run_id,
                principal_id="local-user",
                now=now,
            )
            task = session.get(Task, context.task_id)
            if task is None:
                raise RepairLoopError("TASK_UNAVAILABLE")
            prior_jobs = _repair_jobs(session, context.task_id)
            same_run = next(
                (
                    job
                    for job in prior_jobs
                    if job.input_payload.get("validation_run_id")
                    == str(validation_run_id)
                ),
                None,
            )
            equivalent = any(
                job.input_payload.get("validation_run_id") != str(validation_run_id)
                and job.input_payload.get("failure_fingerprint")
                == context.failure_fingerprint
                for job in prior_jobs
            )
            retry_approval_id = _human_retry_authorization(
                session,
                task,
                context.failure_fingerprint,
            )
            exhausted = context.task_retry_count >= context.max_attempts
        if same_run is None and (equivalent or exhausted) and retry_approval_id is None:
            return self._escalate(
                context,
                prior_jobs,
                reason_code=(
                    "EQUIVALENT_VALIDATION_FAILURE"
                    if equivalent
                    else "REPAIR_BUDGET_EXHAUSTED"
                ),
                now=now,
            )
        prompt = self._prompts.compile(
            context.task_id,
            role=PromptRole.IMPLEMENTER,
            evidence_ids=(
                context.decision_evidence_id,
                context.manifest_evidence_id,
            ),
        )
        job_input = RepairJobInput(
            validation_run_id=context.validation_run_id,
            task_id=context.task_id,
            failure_fingerprint=context.failure_fingerprint,
            failed_commit_sha=context.failed_commit_sha,
            failed_tree_sha=context.failed_tree_sha,
            validation_contract_id=context.validation_contract_id,
            validation_contract_version=context.validation_contract_version,
            repository_configuration_id=context.repository_configuration_id,
            repository_configuration_version=context.repository_configuration_version,
            decision_evidence_id=context.decision_evidence_id,
            manifest_evidence_id=context.manifest_evidence_id,
            retry_approval_decision_id=retry_approval_id,
            prompt=HermesJobPrompt(
                task_id=prompt.task_id,
                role=prompt.role,
                template_id=prompt.template_id,
                template_version=prompt.template_version,
                policy_version_id=prompt.policy_version_id,
                evaluation_label=prompt.evaluation_label,
                content=prompt.content,
                evidence_ids=prompt.evidence_ids,
            ),
        )
        scheduled = self._jobs.schedule(
            task_id=context.task_id,
            job_type=VALIDATION_REPAIR_JOB_TYPE,
            idempotency_key=f"validation-repair:{context.validation_run_id}",
            input_payload=job_input.model_dump(mode="json"),
            task_validator=lambda session, task: _validate_repair_schedule(
                session,
                task,
                validation_run_id=context.validation_run_id,
                failure_fingerprint=context.failure_fingerprint,
                max_attempts=context.max_attempts,
                retry_approval_decision_id=retry_approval_id,
            ),
        )
        return RepairScheduleResult(
            validation_run_id=context.validation_run_id,
            task_id=context.task_id,
            status=RepairScheduleStatus.SCHEDULED,
            failure_fingerprint=context.failure_fingerprint,
            job_id=scheduled.job_id,
            replayed=scheduled.replayed,
        )

    def _escalate(
        self,
        context: _RepairContext,
        prior_jobs: Sequence[BackgroundJob],
        *,
        reason_code: str,
        now: datetime,
    ) -> RepairScheduleResult:
        history = tuple(
            ApprovalRetryAttempt(
                attempt=index,
                error_code=(
                    "VALIDATION_FAILURE"
                    if job.input_payload.get("failure_fingerprint")
                    != context.failure_fingerprint
                    else "EQUIVALENT_VALIDATION_FAILURE"
                ),
                occurred_at=_as_utc(job.created_at),
                checkpoint_evidence_id=_mapping_uuid(
                    job.input_payload,
                    "decision_evidence_id",
                ),
            )
            for index, job in enumerate(prior_jobs[-20:], start=1)
        )
        if not history:
            history = (
                ApprovalRetryAttempt(
                    attempt=1,
                    error_code=reason_code,
                    occurred_at=now,
                    checkpoint_evidence_id=context.decision_evidence_id,
                ),
            )
        evidence_ids = tuple(
            dict.fromkeys(
                (
                    context.decision_evidence_id,
                    context.manifest_evidence_id,
                    *(
                        attempt.checkpoint_evidence_id
                        for attempt in history
                        if attempt.checkpoint_evidence_id is not None
                    ),
                )
            )
        )
        request_id = uuid5(
            NAMESPACE_URL,
            f"mathews:validation-repair-approval:{context.validation_run_id}:{reason_code}",
        )
        result: ApprovalRequestResult = self._approvals.request(
            context.task_id,
            request_id=request_id,
            expected_state=TaskState.VALIDATING,
            request_type=ApprovalRequestType.RETRY_LIMIT,
            reason_code=reason_code,
            subject_type="BLOCKED_OPERATION",
            subject_id=None,
            blocked_operation=BlockedOperation(
                operation_name="validation.repair",
                idempotency_key=f"validation-repair:{context.validation_run_id}",
                input_fingerprint=context.failure_fingerprint,
                checkpoint_evidence_id=context.decision_evidence_id,
            ),
            retry_history=history,
            evidence_ids=evidence_ids,
            expires_at=now + timedelta(seconds=context.approval_lifetime_seconds),
        )
        return RepairScheduleResult(
            validation_run_id=context.validation_run_id,
            task_id=context.task_id,
            status=RepairScheduleStatus.ESCALATED,
            failure_fingerprint=context.failure_fingerprint,
            approval_request_id=result.request_id,
            replayed=result.replayed,
        )


class RepairJobHandler:
    """Run Hermes, commit a replacement candidate, and request full revalidation."""

    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        host_gateway: RepairHostGateway,
        hermes_handler: RepairHermesHandler,
        *,
        principal_id: str = "control-plane",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._factory = factory
        self._store = artifact_store
        self._host = host_gateway
        self._hermes = hermes_handler
        self._principal_id = principal_id
        self._clock = clock or (lambda: datetime.now(UTC))

    def __call__(self, context: LeasedJobContext) -> Mapping[str, object]:
        job_input = RepairJobInput.model_validate(context.grant.input_payload)
        if job_input.task_id != context.grant.task_id:
            raise TerminalBackgroundJobError("REPAIR_JOB_TASK_MISMATCH")
        transitions = BackgroundJobService(
            self._factory,
            self._store,
            principal_id=self._principal_id,
            gate_evaluator=_RepairTransitionGates(job_input),
            clock=self._clock,
        )
        repair_transition_id = uuid5(
            NAMESPACE_URL,
            f"mathews:validation-repair-start:{context.grant.job_id}",
        )
        transitions.transition_task(
            context.grant,
            transition_id=repair_transition_id,
            expected_state=TaskState.VALIDATING,
            kind=TaskTransitionKind.BEGIN_REPAIR,
            reason_code="VALIDATION_REPAIR_STARTED",
            evidence_ids=(
                job_input.decision_evidence_id,
                job_input.manifest_evidence_id,
            ),
        )
        try:
            hermes_result = self._run_hermes(context, job_input)
            candidate = self._commit_candidate(context, job_input)
            candidate_evidence_id = self._record_candidate(
                context.grant,
                job_input,
                candidate,
                hermes_result,
            )
            revalidate_transition_id = uuid5(
                NAMESPACE_URL,
                f"mathews:validation-repair-revalidate:{context.grant.job_id}",
            )
            transition = transitions.transition_task(
                context.grant,
                transition_id=revalidate_transition_id,
                expected_state=TaskState.REPAIRING,
                kind=TaskTransitionKind.REVALIDATE,
                reason_code="VALIDATION_REPAIR_COMMITTED",
                evidence_ids=(
                    job_input.decision_evidence_id,
                    candidate_evidence_id,
                ),
                validation_candidate=ValidationCandidate(
                    commit_sha=cast(str, candidate["head_sha"]),
                    tree_sha=cast(str, candidate["tree_sha"]),
                ),
            )
            rerun_evidence_id = self._record_rerun_request(
                context.grant,
                job_input,
                candidate,
                candidate_evidence_id,
                validation_attempt_id=transition.transition_id,
            )
        except TerminalBackgroundJobError as error:
            self._fail_task(context.grant, transitions, job_input, error.error_code)
            raise
        except RepairLoopError as error:
            self._fail_task(context.grant, transitions, job_input, error.code)
            raise TerminalBackgroundJobError(error.code) from None
        except HostGatewayError as error:
            raise DependencyOutageError(DependencyService.HOST, error.code) from None
        except (ValueError, KeyError, TypeError):
            self._fail_task(
                context.grant,
                transitions,
                job_input,
                "VALIDATION_REPAIR_UNRECOVERABLE",
            )
            raise TerminalBackgroundJobError(
                "VALIDATION_REPAIR_UNRECOVERABLE"
            ) from None
        return {
            "validation_run_id": str(job_input.validation_run_id),
            "repair_attempt": _task_retry_count(self._factory, job_input.task_id),
            "candidate_commit_sha": candidate["head_sha"],
            "candidate_tree_sha": candidate["tree_sha"],
            "candidate_evidence_id": str(candidate_evidence_id),
            "rerun_request_evidence_id": str(rerun_evidence_id),
            "status": "REVALIDATION_REQUESTED",
        }

    def _run_hermes(
        self,
        context: LeasedJobContext,
        job_input: RepairJobInput,
    ) -> Mapping[str, object]:
        original_payload = context.grant.input_payload
        hermes_context = LeasedJobContext(
            context.service,
            replace(
                context.grant,
                input_payload=HermesJobInput(prompt=job_input.prompt).model_dump(
                    mode="json"
                ),
            ),
        )
        result = self._hermes(hermes_context) or {}
        context.grant = replace(
            hermes_context.grant,
            input_payload=original_payload,
        )
        if result.get("status") != "SUCCEEDED":
            raise TerminalBackgroundJobError("HERMES_REPAIR_INCOMPLETE")
        return result

    def _commit_candidate(
        self,
        context: LeasedJobContext,
        job_input: RepairJobInput,
    ) -> Mapping[str, JsonValue]:
        context.heartbeat(timedelta(seconds=30))
        with self._factory() as session:
            configuration = session.get(
                RepositoryConfiguration,
                job_input.repository_configuration_id,
            )
            if (
                configuration is None
                or configuration.version
                != job_input.repository_configuration_version
            ):
                raise RepairLoopError("REPAIR_CONFIGURATION_STALE")
            validated = validated_repository_configuration(configuration)
        request = HostRequestMessage(
            request_id=uuid4(),
            issued_at_ms=int(_as_utc(self._clock()).timestamp() * 1_000),
            expires_at_ms=int(
                (_as_utc(self._clock()) + timedelta(seconds=30)).timestamp()
                * 1_000
            ),
            authority=authority_for_job_lease(
                context.grant,
                configuration=validated,
            ),
            operation=HostOperation(
                name="git.commit",
                idempotency_key=f"validation-repair-commit:{context.grant.job_id}",
                arguments=cast(
                    dict[str, JsonValue],
                    {
                        "configuration": validated.to_dict(),
                        "expected_head_sha": job_input.failed_commit_sha,
                        "message": (
                            "Repair validation failure "
                            f"{job_input.failure_fingerprint[:12]}"
                        ),
                    },
                ),
            ),
        )
        response = self._host.execute(request)
        result = response.result
        changed_paths = result.get("changed_paths")
        head_sha = result.get("head_sha")
        tree_sha = result.get("tree_sha")
        if (
            response.status is not HostResponseStatus.OK
            or response.execution_fencing_token != context.grant.fencing_token
            or result.get("committed") is not True
            or result.get("clean") is not True
            or not isinstance(changed_paths, list)
            or not changed_paths
            or not all(isinstance(value, str) and value for value in changed_paths)
            or not isinstance(head_sha, str)
            or _GIT_OBJECT.fullmatch(head_sha) is None
            or head_sha == job_input.failed_commit_sha
            or not isinstance(tree_sha, str)
            or _GIT_OBJECT.fullmatch(tree_sha) is None
        ):
            raise RepairLoopError("REPAIR_CANDIDATE_INVALID")
        return result

    def _record_candidate(
        self,
        grant: JobLeaseGrant,
        job_input: RepairJobInput,
        candidate: Mapping[str, JsonValue],
        hermes_result: Mapping[str, object],
    ) -> UUID:
        evidence_id = uuid5(
            NAMESPACE_URL,
            f"mathews:validation-repair-candidate:{grant.job_id}",
        )
        payload = {
            "schema_version": REPAIR_SCHEMA_VERSION,
            "validation_run_id": str(job_input.validation_run_id),
            "failure_fingerprint": job_input.failure_fingerprint,
            "failed_commit_sha": job_input.failed_commit_sha,
            "candidate_commit_sha": candidate["head_sha"],
            "candidate_tree_sha": candidate["tree_sha"],
            "changed_paths": candidate["changed_paths"],
            "hermes_run_id": hermes_result.get("hermes_run_id"),
            "repository_configuration_id": str(
                job_input.repository_configuration_id
            ),
            "repository_configuration_version": (
                job_input.repository_configuration_version
            ),
            "validation_contract_id": str(job_input.validation_contract_id),
            "validation_contract_version": job_input.validation_contract_version,
        }
        with self._factory.begin() as session:
            require_current_job_lease(
                session,
                grant,
                now=_as_utc(self._clock()),
            )
            existing = session.get(EvidenceRecord, evidence_id)
            if existing is not None:
                _require_evidence_payload(
                    session,
                    self._store,
                    existing,
                    payload,
                    task_id=job_input.task_id,
                    evidence_type="validation-repair-candidate",
                )
                return existing.id
            task = session.get(Task, job_input.task_id)
            if task is None or TaskState(task.state) is not TaskState.REPAIRING:
                raise RepairLoopError("REPAIR_TASK_STALE")
            captured = capture_evidence(
                session,
                self._store,
                payload=payload,
                media_type="application/json",
                source_kind=EvidenceSourceKind.RESULT,
                evidence_type="validation-repair-candidate",
                origin="control-plane:validation-repair",
                access_classification=EvidenceAccessClass.TASK_OWNER,
                retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
                owner_id=task.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=task.root_correlation_id,
                task_id=task.id,
                causation_id=grant.job_id,
                parent_correlation_id=job_input.validation_run_id,
                evidence_id=evidence_id,
                captured_at=_as_utc(self._clock()),
            )
            return captured.record.id

    def _record_rerun_request(
        self,
        grant: JobLeaseGrant,
        job_input: RepairJobInput,
        candidate: Mapping[str, JsonValue],
        candidate_evidence_id: UUID,
        *,
        validation_attempt_id: UUID,
    ) -> UUID:
        evidence_id = uuid5(
            NAMESPACE_URL,
            f"mathews:validation-rerun-request:{grant.job_id}",
        )
        now = _as_utc(self._clock())
        with self._factory.begin() as session:
            require_current_job_lease(session, grant, now=now)
            task = session.scalar(
                select(Task).where(Task.id == job_input.task_id).with_for_update()
            )
            contract = session.get(ValidationContract, job_input.validation_contract_id)
            configuration = session.get(
                RepositoryConfiguration,
                job_input.repository_configuration_id,
            )
            attempt = session.scalar(
                select(TaskEvent).where(
                    TaskEvent.transition_id == validation_attempt_id,
                    TaskEvent.task_id == job_input.task_id,
                )
            )
            if (
                task is None
                or contract is None
                or configuration is None
                or attempt is None
                or TaskState(task.state) is not TaskState.VALIDATING
                or task.validation_contract_id != contract.id
                or task.repository_configuration_id != configuration.id
                or contract.version != job_input.validation_contract_version
                or configuration.version
                != job_input.repository_configuration_version
            ):
                raise RepairLoopError("REVALIDATION_BINDING_STALE")
            payload = {
                "schema_version": REPAIR_SCHEMA_VERSION,
                "validation_attempt_id": str(validation_attempt_id),
                "repair_job_id": str(grant.job_id),
                "previous_validation_run_id": str(job_input.validation_run_id),
                "commit_sha": candidate["head_sha"],
                "tree_sha": candidate["tree_sha"],
                "validation_contract_id": str(contract.id),
                "validation_contract_version": contract.version,
                "repository_configuration_id": str(configuration.id),
                "repository_configuration_version": configuration.version,
                "required_operations": contract.required_operations,
                "typed_assertions": contract.typed_assertions,
                "evidence_requirements": contract.evidence_requirements,
                "simulator_setup": contract.simulator_setup,
                "clean_state_setup": contract.clean_state_setup,
                "e2e_flow": contract.e2e_flow,
                "timeouts": contract.timeouts,
                "outcome_rules": contract.outcome_rules,
            }
            existing = session.get(EvidenceRecord, evidence_id)
            if existing is None:
                captured = capture_evidence(
                    session,
                    self._store,
                    payload=payload,
                    media_type="application/json",
                    source_kind=EvidenceSourceKind.RESULT,
                    evidence_type="validation-rerun-request",
                    origin="control-plane:validation-repair",
                    access_classification=EvidenceAccessClass.TASK_OWNER,
                    retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
                    owner_id=task.owner_id,
                    actor_id=self._principal_id,
                    root_correlation_id=task.root_correlation_id,
                    task_id=task.id,
                    causation_id=grant.job_id,
                    parent_correlation_id=validation_attempt_id,
                    evidence_id=evidence_id,
                    captured_at=now,
                )
                existing = captured.record
            else:
                _require_evidence_payload(
                    session,
                    self._store,
                    existing,
                    payload,
                    task_id=task.id,
                    evidence_type="validation-rerun-request",
                )
            event = session.scalar(
                select(TaskEvent).where(
                    TaskEvent.task_id == task.id,
                    TaskEvent.event_type == VALIDATION_RERUN_REQUESTED_EVENT_TYPE,
                    TaskEvent.causation_id == grant.job_id,
                )
            )
            if event is None:
                event = TaskEvent(
                    task_id=task.id,
                    sequence=(
                        session.scalar(
                            select(func.max(TaskEvent.sequence)).where(
                                TaskEvent.task_id == task.id
                            )
                        )
                        or 0
                    )
                    + 1,
                    event_type=VALIDATION_RERUN_REQUESTED_EVENT_TYPE,
                    payload={
                        **payload,
                        "request_evidence_id": str(existing.id),
                        "candidate_evidence_id": str(candidate_evidence_id),
                    },
                    occurred_at=now,
                    owner_id=task.owner_id,
                    actor_id=self._principal_id,
                    root_correlation_id=task.root_correlation_id,
                    causation_id=grant.job_id,
                    parent_correlation_id=validation_attempt_id,
                )
                session.add(event)
                session.flush()
                for position, reference_id in enumerate(
                    (candidate_evidence_id, existing.id),
                    start=1,
                ):
                    session.add(
                        TaskEventEvidenceReference(
                            task_id=task.id,
                            task_event_id=event.id,
                            evidence_id=reference_id,
                            position=position,
                            owner_id=task.owner_id,
                            actor_id=self._principal_id,
                            root_correlation_id=task.root_correlation_id,
                            causation_id=event.id,
                            parent_correlation_id=grant.job_id,
                        )
                    )
            return existing.id

    def _fail_task(
        self,
        grant: JobLeaseGrant,
        transitions: BackgroundJobService,
        job_input: RepairJobInput,
        error_code: str,
    ) -> None:
        with self._factory() as session:
            task = session.get(Task, job_input.task_id)
            state = None if task is None else TaskState(task.state)
        if state in {
            TaskState.HANDED_OFF,
            TaskState.FAILED,
            TaskState.CANCELLED,
        }:
            return
        if state not in {TaskState.VALIDATING, TaskState.REPAIRING}:
            return
        transitions.transition_task(
            grant,
            transition_id=uuid5(
                NAMESPACE_URL,
                f"mathews:validation-repair-failed:{grant.job_id}:{error_code}",
            ),
            expected_state=state,
            kind=TaskTransitionKind.FAIL,
            reason_code=error_code,
            evidence_ids=(job_input.decision_evidence_id,),
        )


@dataclass(frozen=True, slots=True)
class _RepairTransitionGates(TaskTransitionGateEvaluator):
    job_input: RepairJobInput

    def evaluate(
        self,
        session: Session,
        task: Task,
        kind: TaskTransitionKind,
        *,
        policy: PolicyVersion,
        now: datetime,
    ) -> TaskTransitionGuards:
        del now
        if kind is not TaskTransitionKind.BEGIN_REPAIR:
            return TaskTransitionGuards()
        run = session.get(ValidationRun, self.job_input.validation_run_id)
        max_attempts, _lifetime = _repair_policy(policy)
        return TaskTransitionGuards(
            repair_authorized=bool(
                run is not None
                and run.task_id == task.id
                and ValidationOutcome(run.outcome) is ValidationOutcome.FAILED
                and run.commit_sha == self.job_input.failed_commit_sha
                and run.tree_sha == self.job_input.failed_tree_sha
                and run.validation_contract_id
                == self.job_input.validation_contract_id
                and run.repository_configuration_id
                == self.job_input.repository_configuration_id
                and task.validation_contract_id
                == self.job_input.validation_contract_id
                and task.repository_configuration_id
                == self.job_input.repository_configuration_id
                and (
                    task.retry_count < max_attempts
                    or _retry_approval_is_current(
                        session,
                        task,
                        self.job_input.failure_fingerprint,
                        self.job_input.retry_approval_decision_id,
                    )
                )
                and _failure_fingerprint(run) == self.job_input.failure_fingerprint
                and _run_is_current(session, task, run)
            )
        )


def _repair_context(
    session: Session,
    store: ArtifactStore,
    validation_run_id: UUID,
    *,
    principal_id: str,
    now: datetime,
) -> _RepairContext:
    run = session.get(ValidationRun, validation_run_id)
    if run is None or run.owner_id != principal_id:
        raise RepairLoopError("VALIDATION_RUN_UNAVAILABLE")
    task = session.get(Task, run.task_id)
    contract = session.get(ValidationContract, run.validation_contract_id)
    configuration = session.get(
        RepositoryConfiguration,
        run.repository_configuration_id,
    )
    policy = session.scalar(
        select(PolicyVersion)
        .where(
            PolicyVersion.owner_id == run.owner_id,
            PolicyVersion.lineage_key == "mvp",
            PolicyVersion.approved_at <= now,
        )
        .order_by(PolicyVersion.version.desc())
        .limit(1)
    )
    decision = session.scalar(
        select(TaskEvent)
        .where(
            TaskEvent.task_id == run.task_id,
            TaskEvent.event_type == VALIDATION_DECIDED_EVENT_TYPE,
            TaskEvent.causation_id == run.id,
        )
        .order_by(TaskEvent.sequence.desc())
        .limit(1)
    )
    decision_evidence_id = (
        None
        if decision is None
        else _mapping_uuid(decision.payload, "decision_evidence_id")
    )
    manifest = session.scalar(
        select(EvidenceRecord).where(
            EvidenceRecord.validation_run_id == run.id,
            EvidenceRecord.evidence_type == "validation-evidence-manifest",
            EvidenceRecord.correction_of_id.is_(None),
        )
    )
    if (
        task is None
        or contract is None
        or configuration is None
        or policy is None
        or decision_evidence_id is None
        or manifest is None
        or TaskState(task.state) is not TaskState.VALIDATING
        or ValidationOutcome(run.outcome) is not ValidationOutcome.FAILED
        or task.validation_contract_id != contract.id
        or task.repository_configuration_id != configuration.id
        or not _run_is_current(session, task, run)
    ):
        raise RepairLoopError("VALIDATION_FAILURE_NOT_REPAIRABLE")
    for record_id in (decision_evidence_id, manifest.id):
        record = session.get(EvidenceRecord, record_id)
        try:
            if (
                record is None
                or record.owner_id != task.owner_id
                or record.task_id != task.id
            ):
                raise EvidenceError("unavailable")
            load_evidence(session, store, record)
        except EvidenceError:
            raise RepairLoopError("REPAIR_EVIDENCE_UNAVAILABLE") from None
    max_attempts, approval_lifetime = _repair_policy(policy)
    return _RepairContext(
        task_id=task.id,
        task_retry_count=task.retry_count,
        validation_run_id=run.id,
        failed_commit_sha=run.commit_sha,
        failed_tree_sha=run.tree_sha,
        validation_contract_id=contract.id,
        validation_contract_version=contract.version,
        repository_configuration_id=configuration.id,
        repository_configuration_version=configuration.version,
        decision_evidence_id=decision_evidence_id,
        manifest_evidence_id=manifest.id,
        failure_fingerprint=_failure_fingerprint(run),
        max_attempts=max_attempts,
        approval_lifetime_seconds=approval_lifetime,
    )


def _repair_policy(policy: PolicyVersion) -> tuple[int, int]:
    raw = policy.workflow_thresholds.get("validation_repair_policy")
    if raw is None:
        return DEFAULT_MAX_REPAIR_ATTEMPTS, DEFAULT_APPROVAL_LIFETIME_SECONDS
    if not isinstance(raw, Mapping) or set(raw) != {
        "max_attempts",
        "approval_lifetime_seconds",
    }:
        raise RepairLoopError("REPAIR_POLICY_INVALID")
    max_attempts = raw.get("max_attempts")
    lifetime = raw.get("approval_lifetime_seconds")
    if (
        isinstance(max_attempts, bool)
        or not isinstance(max_attempts, int)
        or not 1 <= max_attempts <= MAX_REPAIR_ATTEMPTS
        or isinstance(lifetime, bool)
        or not isinstance(lifetime, int)
        or not 60 <= lifetime <= 7 * 86_400
    ):
        raise RepairLoopError("REPAIR_POLICY_INVALID")
    return max_attempts, lifetime


def _failure_fingerprint(run: ValidationRun) -> str:
    operations = sorted(
        (
            str(value.get("operation_id")),
            bool(value.get("passed")),
            bool(value.get("repository_state_valid")),
            str(value.get("exit_status")),
            str(value.get("cancellation_status")),
        )
        for value in run.operation_results
        if isinstance(value, Mapping) and value.get("passed") is not True
    )
    assertions = sorted(
        (
            str(value.get("assertion_id")),
            str(value.get("status")),
            str(value.get("result_code")),
        )
        for value in run.assertion_results
        if isinstance(value, Mapping) and value.get("status") != "PASSED"
    )
    criteria = sorted(
        (str(value.get("criterion_id")), str(value.get("status")))
        for value in run.acceptance_criterion_results
        if isinstance(value, Mapping) and value.get("status") != "PASSED"
    )
    payload = {
        "schema_version": REPAIR_SCHEMA_VERSION,
        "validation_contract_id": str(run.validation_contract_id),
        "operation_failures": operations,
        "assertion_failures": assertions,
        "criterion_failures": criteria,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _human_retry_authorization(
    session: Session,
    task: Task,
    failure_fingerprint: str,
) -> UUID | None:
    requests = session.scalars(
        select(ApprovalRequest)
        .where(
            ApprovalRequest.task_id == task.id,
            ApprovalRequest.request_type == ApprovalRequestType.RETRY_LIMIT.value,
            ApprovalRequest.status == ApprovalStatus.APPROVED,
            ApprovalRequest.decision == ApprovalDecision.RETRY.value,
            ApprovalRequest.decision_id.is_not(None),
        )
        .order_by(ApprovalRequest.decided_at.desc(), ApprovalRequest.id.desc())
    )
    for request in requests:
        decision_id = request.decision_id
        if (
            decision_id is None
            or not _retry_approval_is_current(
                session,
                task,
                failure_fingerprint,
                decision_id,
            )
        ):
            continue
        consumed = session.scalar(
            select(BackgroundJob.id).where(
                BackgroundJob.task_id == task.id,
                BackgroundJob.job_type == VALIDATION_REPAIR_JOB_TYPE,
                BackgroundJob.input_payload["retry_approval_decision_id"].as_string()
                == str(decision_id),
            )
        )
        if consumed is None:
            return decision_id
    return None


def _retry_approval_is_current(
    session: Session,
    task: Task,
    failure_fingerprint: str,
    decision_id: UUID | None,
) -> bool:
    if decision_id is None:
        return False
    request = session.scalar(
        select(ApprovalRequest).where(
            ApprovalRequest.task_id == task.id,
            ApprovalRequest.request_type == ApprovalRequestType.RETRY_LIMIT.value,
            ApprovalRequest.status == ApprovalStatus.APPROVED,
            ApprovalRequest.decision == ApprovalDecision.RETRY.value,
            ApprovalRequest.decision_id == decision_id,
        )
    )
    blocked = None if request is None else request.blocked_operation
    return bool(
        request is not None
        and isinstance(blocked, Mapping)
        and blocked.get("operation_name") == "validation.repair"
        and blocked.get("input_fingerprint") == failure_fingerprint
        and request.resume_state is TaskState.VALIDATING
    )


def _validate_repair_schedule(
    session: Session,
    task: Task,
    *,
    validation_run_id: UUID,
    failure_fingerprint: str,
    max_attempts: int,
    retry_approval_decision_id: UUID | None,
) -> None:
    run = session.get(ValidationRun, validation_run_id)
    existing = session.scalar(
        select(BackgroundJob).where(
            BackgroundJob.task_id == task.id,
            BackgroundJob.job_type == VALIDATION_REPAIR_JOB_TYPE,
            BackgroundJob.idempotency_key == f"validation-repair:{validation_run_id}",
        )
    )
    if existing is not None:
        return
    human_retry = _retry_approval_is_current(
        session,
        task,
        failure_fingerprint,
        retry_approval_decision_id,
    )
    if (
        TaskState(task.state) is not TaskState.VALIDATING
        or run is None
        or run.task_id != task.id
        or ValidationOutcome(run.outcome) is not ValidationOutcome.FAILED
        or (task.retry_count >= max_attempts and not human_retry)
        or _failure_fingerprint(run) != failure_fingerprint
        or not _run_is_current(session, task, run)
        or (
            not human_retry
            and session.scalar(
                select(BackgroundJob.id).where(
                    BackgroundJob.task_id == task.id,
                    BackgroundJob.job_type == VALIDATION_REPAIR_JOB_TYPE,
                    BackgroundJob.input_payload["failure_fingerprint"].as_string()
                    == failure_fingerprint,
                )
            )
            is not None
        )
    ):
        raise RepairLoopError("VALIDATION_FAILURE_NOT_REPAIRABLE")


def _run_is_current(session: Session, task: Task, run: ValidationRun) -> bool:
    attempt = session.scalar(
        select(TaskEvent)
        .where(
            TaskEvent.task_id == task.id,
            TaskEvent.transition_to_state == TaskState.VALIDATING,
            TaskEvent.transition_kind.in_(("BEGIN_VALIDATION", "REVALIDATE")),
        )
        .order_by(TaskEvent.sequence.desc())
        .limit(1)
    )
    candidate = None if attempt is None else attempt.payload.get("validation_candidate")
    return bool(
        attempt is not None
        and isinstance(candidate, Mapping)
        and candidate.get("commit_sha") == run.commit_sha
        and candidate.get("tree_sha") == run.tree_sha
    )


def _repair_jobs(session: Session, task_id: UUID) -> tuple[BackgroundJob, ...]:
    return tuple(
        session.scalars(
            select(BackgroundJob)
            .where(
                BackgroundJob.task_id == task_id,
                BackgroundJob.job_type == VALIDATION_REPAIR_JOB_TYPE,
            )
            .order_by(BackgroundJob.created_at, BackgroundJob.id)
        )
    )


def _require_evidence_payload(
    session: Session,
    store: ArtifactStore,
    record: EvidenceRecord,
    payload: Mapping[str, object],
    *,
    task_id: UUID,
    evidence_type: str,
) -> None:
    try:
        content_bytes = load_evidence(session, store, record).content_bytes
    except EvidenceError:
        raise RepairLoopError("REPAIR_EVIDENCE_UNAVAILABLE") from None
    expected_bytes = redact_evidence_content(
        payload,
        media_type="application/json",
    ).canonical_bytes
    if (
        record.task_id != task_id
        or record.evidence_type != evidence_type
        or content_bytes != expected_bytes
    ):
        raise RepairLoopError("REPAIR_EVIDENCE_CONFLICT")


def _mapping_uuid(value: Mapping[str, object], key: str) -> UUID | None:
    raw = value.get(key)
    try:
        return UUID(raw) if isinstance(raw, str) else None
    except ValueError:
        return None


def _task_retry_count(factory: SessionFactory, task_id: UUID) -> int:
    with factory() as session:
        task = session.get(Task, task_id)
        if task is None:
            raise RepairLoopError("TASK_UNAVAILABLE")
        return task.retry_count


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
