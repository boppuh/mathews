"""Fail-closed validation decisions bound to one exact candidate and attempt."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Literal, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.authentication import (
    AuthenticatedSession,
    require_authenticated_session,
)
from mathews_control_plane.background_jobs import JobLeaseGrant, require_current_job_lease
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    Brief,
    EvidenceRecord,
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
)

VALIDATION_DECIDED_EVENT_TYPE = "VALIDATION_DECIDED"
VALIDATION_DECISION_SCHEMA_VERSION = 1
_GIT_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_DECIDED_OUTCOMES = frozenset(
    {
        ValidationOutcome.PASSED,
        ValidationOutcome.FAILED,
        ValidationOutcome.BLOCKED,
        ValidationOutcome.ESCALATED,
        ValidationOutcome.CANCELLED,
    }
)
AuthenticatedValidationDecisionSession = Annotated[
    AuthenticatedSession,
    Depends(require_authenticated_session),
]


class ValidationDecisionError(RuntimeError):
    """A stable validation-decision refusal without source artifact contents."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ValidationDecisionResult:
    validation_run_id: UUID
    task_id: UUID
    validation_attempt_id: UUID
    validation_contract_id: UUID
    validation_contract_version: int
    repository_configuration_id: UUID
    repository_configuration_version: int
    commit_sha: str
    tree_sha: str
    outcome: ValidationOutcome
    reason_code: str
    decision_evidence_id: UUID
    decided_at: datetime
    is_current: bool
    replayed: bool


@dataclass(frozen=True, slots=True)
class _Assessment:
    attempt_id: UUID
    contract: ValidationContract
    configuration: RepositoryConfiguration
    outcome: ValidationOutcome
    reason_code: str
    source_evidence_ids: tuple[UUID, ...]


class ValidationDecisionService:
    """Decide and query immutable validation results for exact Git objects."""

    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        *,
        principal_id: str = "local-user",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._factory = factory
        self._store = artifact_store
        self._principal_id = principal_id
        self._clock = clock or (lambda: datetime.now(UTC))

    def decide(
        self,
        validation_run_id: UUID,
        *,
        lease_grant_supplier: Callable[[], JobLeaseGrant] | None = None,
    ) -> ValidationDecisionResult:
        now = _as_utc(self._clock())
        with self._factory.begin() as session:
            run = session.scalar(
                select(ValidationRun)
                .where(ValidationRun.id == validation_run_id)
                .with_for_update()
            )
            if run is None or run.owner_id != self._principal_id:
                raise ValidationDecisionError("VALIDATION_RUN_UNAVAILABLE")
            task = session.scalar(
                select(Task).where(Task.id == run.task_id).with_for_update()
            )
            if task is None or task.owner_id != self._principal_id:
                raise ValidationDecisionError("TASK_UNAVAILABLE")
            existing = _decision_event(session, task.id, run.id)
            if existing is not None:
                return _stored_result(
                    session,
                    self._store,
                    task,
                    run,
                    existing,
                    replayed=True,
                )
            if ValidationOutcome(run.outcome) is not ValidationOutcome.PENDING:
                raise ValidationDecisionError("VALIDATION_DECISION_INCOMPLETE")
            assessment = self._assess(session, task, run)
            if lease_grant_supplier is not None:
                require_current_job_lease(
                    session,
                    lease_grant_supplier(),
                    now=_as_utc(self._clock()),
                )
            payload = _decision_payload(run, assessment, now)
            decision = capture_evidence(
                session,
                self._store,
                payload=payload,
                media_type="application/json",
                source_kind=EvidenceSourceKind.RESULT,
                evidence_type="validation-decision",
                origin="control-plane:validation-decision",
                access_classification=EvidenceAccessClass.TASK_OWNER,
                retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
                owner_id=task.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=task.root_correlation_id,
                task_id=task.id,
                validation_run_id=run.id,
                causation_id=run.id,
                parent_correlation_id=assessment.contract.id,
                captured_at=now,
            )
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
                event_type=VALIDATION_DECIDED_EVENT_TYPE,
                payload={
                    **payload,
                    "decision_evidence_id": str(decision.record.id),
                },
                occurred_at=now,
                owner_id=task.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=task.root_correlation_id,
                causation_id=run.id,
                parent_correlation_id=assessment.contract.id,
            )
            session.add(event)
            session.flush()
            session.add(
                TaskEventEvidenceReference(
                    task_id=task.id,
                    task_event_id=event.id,
                    evidence_id=decision.record.id,
                    position=1,
                    owner_id=task.owner_id,
                    actor_id=self._principal_id,
                    root_correlation_id=task.root_correlation_id,
                    causation_id=event.id,
                    parent_correlation_id=run.id,
                )
            )
            run.outcome = assessment.outcome
            run.actor_id = self._principal_id
            run.causation_id = event.id
            run.updated_at = now
            session.flush()
            return ValidationDecisionResult(
                validation_run_id=run.id,
                task_id=task.id,
                validation_attempt_id=assessment.attempt_id,
                validation_contract_id=assessment.contract.id,
                validation_contract_version=assessment.contract.version,
                repository_configuration_id=assessment.configuration.id,
                repository_configuration_version=assessment.configuration.version,
                commit_sha=run.commit_sha,
                tree_sha=run.tree_sha,
                outcome=assessment.outcome,
                reason_code=assessment.reason_code,
                decision_evidence_id=decision.record.id,
                decided_at=now,
                is_current=_is_current(session, task, run, assessment.attempt_id),
                replayed=False,
            )

    def get_exact(
        self,
        task_id: UUID,
        *,
        commit_sha: str,
        tree_sha: str,
    ) -> ValidationDecisionResult:
        commit = _git_object(commit_sha, "VALIDATION_COMMIT_INVALID")
        tree = _git_object(tree_sha, "VALIDATION_TREE_INVALID")
        with self._factory() as session:
            task = session.get(Task, task_id)
            if task is None or task.owner_id != self._principal_id:
                raise ValidationDecisionError("VALIDATION_DECISION_UNAVAILABLE")
            runs = tuple(
                session.scalars(
                    select(ValidationRun)
                    .where(
                        ValidationRun.task_id == task.id,
                        ValidationRun.commit_sha == commit,
                        ValidationRun.tree_sha == tree,
                        ValidationRun.outcome != ValidationOutcome.PENDING,
                    )
                    .order_by(ValidationRun.created_at.desc(), ValidationRun.id.desc())
                )
            )
            for run in runs:
                event = _decision_event(session, task.id, run.id)
                if event is not None:
                    return _stored_result(
                        session,
                        self._store,
                        task,
                        run,
                        event,
                        replayed=False,
                    )
        raise ValidationDecisionError("VALIDATION_DECISION_UNAVAILABLE")

    def _assess(self, session: Session, task: Task, run: ValidationRun) -> _Assessment:
        attempt = _latest_validation_attempt(session, task.id)
        if attempt is None or attempt.transition_id is None:
            raise ValidationDecisionError("VALIDATION_ATTEMPT_UNAVAILABLE")
        if (
            TaskState(task.state) is TaskState.ESCALATED
            and task.escalation_resume_state is TaskState.VALIDATING
        ):
            raise ValidationDecisionError("TASK_VALIDATION_PAUSED")
        contract = session.get(ValidationContract, run.validation_contract_id)
        configuration = session.get(
            RepositoryConfiguration,
            run.repository_configuration_id,
        )
        if contract is None or configuration is None:
            raise ValidationDecisionError("VALIDATION_BINDING_UNAVAILABLE")
        candidate = attempt.payload.get("validation_candidate")
        if TaskState(task.state) is TaskState.CANCELLED:
            return _Assessment(
                attempt.transition_id,
                contract,
                configuration,
                ValidationOutcome.CANCELLED,
                "TASK_CANCELLED",
                (),
            )
        if (
            TaskState(task.state) is not TaskState.VALIDATING
            or task.validation_contract_id != run.validation_contract_id
            or task.repository_configuration_id != run.repository_configuration_id
            or contract.task_id != task.id
            or contract.repository_configuration_id != configuration.id
            or not isinstance(candidate, Mapping)
            or set(candidate) != {"commit_sha", "tree_sha"}
            or candidate.get("commit_sha") != run.commit_sha
            or candidate.get("tree_sha") != run.tree_sha
        ):
            return _Assessment(
                attempt.transition_id,
                contract,
                configuration,
                ValidationOutcome.BLOCKED,
                "VALIDATION_BINDING_STALE",
                (),
            )
        if contract.outcome_rules != {"all_required": True}:
            return _Assessment(
                attempt.transition_id,
                contract,
                configuration,
                ValidationOutcome.ESCALATED,
                "OUTCOME_RULES_UNSUPPORTED",
                (),
            )
        outcome, reason, evidence_ids = self._assess_complete_run(
            session,
            task,
            run,
            contract,
            configuration,
        )
        return _Assessment(
            attempt.transition_id,
            contract,
            configuration,
            outcome,
            reason,
            evidence_ids,
        )

    def _assess_complete_run(
        self,
        session: Session,
        task: Task,
        run: ValidationRun,
        contract: ValidationContract,
        configuration: RepositoryConfiguration,
    ) -> tuple[ValidationOutcome, str, tuple[UUID, ...]]:
        records = tuple(
            session.scalars(
                select(EvidenceRecord)
                .where(
                    EvidenceRecord.validation_run_id == run.id,
                    EvidenceRecord.correction_of_id.is_(None),
                )
                .order_by(EvidenceRecord.captured_at, EvidenceRecord.id)
            )
        )
        source_ids = {record.id for record in records}
        correction = session.scalar(
            select(EvidenceRecord.id)
            .where(EvidenceRecord.correction_of_id.in_(source_ids))
            .limit(1)
        )
        loaded: dict[UUID, object] = {}
        try:
            for record in records:
                loaded[record.id] = load_evidence(session, self._store, record).content
        except EvidenceError:
            return ValidationOutcome.ESCALATED, "EVIDENCE_UNAVAILABLE", tuple(source_ids)
        if correction is not None:
            return ValidationOutcome.ESCALATED, "EVIDENCE_CORRECTED", tuple(source_ids)
        manifests = [
            record for record in records if record.evidence_type == "validation-evidence-manifest"
        ]
        source_records = [
            record for record in records if record.evidence_type != "validation-evidence-manifest"
        ]
        required_types = _required_evidence_types(contract.evidence_requirements)
        present_types = {record.evidence_type for record in source_records}
        if (
            required_types is None
            or len(manifests) != 1
            or present_types != required_types
            or len(source_records) != len(required_types)
            or any(
                record.owner_id != task.owner_id or record.task_id != task.id
                for record in records
            )
        ):
            return ValidationOutcome.ESCALATED, "REQUIRED_EVIDENCE_MISSING", tuple(source_ids)
        manifest = loaded[manifests[0].id]
        if not _valid_manifest(
            manifest,
            run=run,
            contract=contract,
            configuration=configuration,
            evidence_ids={record.id for record in source_records},
        ):
            return ValidationOutcome.ESCALATED, "EVIDENCE_MANIFEST_INVALID", tuple(source_ids)
        referenced_ids = _result_evidence_ids(
            (*run.operation_results, *run.assertion_results, *run.acceptance_criterion_results)
        )
        if referenced_ids is None or not referenced_ids.issubset(
            {record.id for record in source_records}
        ):
            return ValidationOutcome.ESCALATED, "RESULT_EVIDENCE_INVALID", tuple(source_ids)
        operation_status = _operation_status(run, contract, configuration)
        assertion_status = _assertion_status(run, contract)
        criterion_status = _criterion_status(run, contract, task, session)
        statuses = (operation_status, assertion_status, criterion_status)
        if "INVALID" in statuses:
            return ValidationOutcome.ESCALATED, "VALIDATION_RESULTS_INVALID", tuple(source_ids)
        if "FAILED" in statuses:
            return ValidationOutcome.FAILED, "REQUIRED_VALIDATION_FAILED", tuple(source_ids)
        if any(value in {"BLOCKED", "PENDING"} for value in statuses):
            return ValidationOutcome.ESCALATED, "VALIDATION_REQUIRES_DECISION", tuple(source_ids)
        return ValidationOutcome.PASSED, "ALL_REQUIRED_VALIDATION_PASSED", tuple(source_ids)


class ValidationDecisionResponse(BaseModel):
    """Safe exact-candidate validation decision projection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    validation_run_id: UUID
    task_id: UUID
    validation_attempt_id: UUID
    validation_contract_id: UUID
    validation_contract_version: int
    repository_configuration_id: UUID
    repository_configuration_version: int
    commit_sha: str
    tree_sha: str
    outcome: Literal["PASSED", "FAILED", "BLOCKED", "ESCALATED", "CANCELLED"]
    reason_code: str
    decision_evidence_id: UUID
    decided_at: datetime
    is_current: bool


def create_validation_decision_router(service: ValidationDecisionService) -> APIRouter:
    router = APIRouter(prefix="/api/validation-decisions", tags=["validation"])

    @router.get(
        "/{task_id}/{commit_sha}/{tree_sha}",
        response_model=ValidationDecisionResponse,
    )
    def exact_decision(
        task_id: UUID,
        commit_sha: str,
        tree_sha: str,
        _authentication: AuthenticatedValidationDecisionSession,
        response: Response,
    ) -> ValidationDecisionResponse:
        response.headers["Cache-Control"] = "no-store"
        try:
            result = service.get_exact(
                task_id,
                commit_sha=commit_sha,
                tree_sha=tree_sha,
            )
        except ValidationDecisionError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="validation decision unavailable",
            ) from None
        return _response(result)

    return router


def _response(result: ValidationDecisionResult) -> ValidationDecisionResponse:
    return ValidationDecisionResponse(
        validation_run_id=result.validation_run_id,
        task_id=result.task_id,
        validation_attempt_id=result.validation_attempt_id,
        validation_contract_id=result.validation_contract_id,
        validation_contract_version=result.validation_contract_version,
        repository_configuration_id=result.repository_configuration_id,
        repository_configuration_version=result.repository_configuration_version,
        commit_sha=result.commit_sha,
        tree_sha=result.tree_sha,
        outcome=cast(
            Literal["PASSED", "FAILED", "BLOCKED", "ESCALATED", "CANCELLED"],
            result.outcome.value,
        ),
        reason_code=result.reason_code,
        decision_evidence_id=result.decision_evidence_id,
        decided_at=result.decided_at,
        is_current=result.is_current,
    )


def _decision_payload(
    run: ValidationRun,
    assessment: _Assessment,
    decided_at: datetime,
) -> dict[str, object]:
    core: dict[str, object] = {
        "schema_version": VALIDATION_DECISION_SCHEMA_VERSION,
        "validation_run_id": str(run.id),
        "task_id": str(run.task_id),
        "validation_attempt_id": str(assessment.attempt_id),
        "validation_contract_id": str(assessment.contract.id),
        "validation_contract_version": assessment.contract.version,
        "repository_configuration_id": str(assessment.configuration.id),
        "repository_configuration_version": assessment.configuration.version,
        "commit_sha": run.commit_sha,
        "tree_sha": run.tree_sha,
        "outcome": assessment.outcome.value,
        "reason_code": assessment.reason_code,
        "source_evidence_ids": sorted(str(value) for value in assessment.source_evidence_ids),
        "decided_at": _timestamp(decided_at),
    }
    encoded = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
    return {**core, "decision_fingerprint": hashlib.sha256(encoded).hexdigest()}


def _decision_event(session: Session, task_id: UUID, run_id: UUID) -> TaskEvent | None:
    for event in session.scalars(
        select(TaskEvent)
        .where(
            TaskEvent.task_id == task_id,
            TaskEvent.event_type == VALIDATION_DECIDED_EVENT_TYPE,
        )
        .order_by(TaskEvent.sequence.desc())
    ):
        if event.payload.get("validation_run_id") == str(run_id):
            return event
    return None


def _stored_result(
    session: Session,
    artifact_store: ArtifactStore,
    task: Task,
    run: ValidationRun,
    event: TaskEvent,
    *,
    replayed: bool,
) -> ValidationDecisionResult:
    payload = event.payload
    try:
        outcome = ValidationOutcome(str(payload["outcome"]))
        result = ValidationDecisionResult(
            validation_run_id=UUID(str(payload["validation_run_id"])),
            task_id=UUID(str(payload["task_id"])),
            validation_attempt_id=UUID(str(payload["validation_attempt_id"])),
            validation_contract_id=UUID(str(payload["validation_contract_id"])),
            validation_contract_version=_integer(payload["validation_contract_version"]),
            repository_configuration_id=UUID(
                str(payload["repository_configuration_id"])
            ),
            repository_configuration_version=_integer(
                payload["repository_configuration_version"]
            ),
            commit_sha=str(payload["commit_sha"]),
            tree_sha=str(payload["tree_sha"]),
            outcome=outcome,
            reason_code=str(payload["reason_code"]),
            decision_evidence_id=UUID(str(payload["decision_evidence_id"])),
            decided_at=_parse_timestamp(payload["decided_at"]),
            is_current=_is_current(
                session,
                task,
                run,
                UUID(str(payload["validation_attempt_id"])),
            ),
            replayed=replayed,
        )
    except (KeyError, TypeError, ValueError):
        raise ValidationDecisionError("VALIDATION_DECISION_INCOMPLETE") from None
    decision_record = session.get(EvidenceRecord, result.decision_evidence_id)
    contract = session.get(ValidationContract, result.validation_contract_id)
    configuration = session.get(
        RepositoryConfiguration,
        result.repository_configuration_id,
    )
    reference = session.scalar(
        select(TaskEventEvidenceReference.id).where(
            TaskEventEvidenceReference.task_event_id == event.id,
            TaskEventEvidenceReference.evidence_id == result.decision_evidence_id,
        )
    )
    try:
        decision_content = (
            None
            if decision_record is None
            else load_evidence(session, artifact_store, decision_record).content
        )
    except EvidenceError:
        decision_content = None
    if (
        outcome not in _DECIDED_OUTCOMES
        or result.validation_run_id != run.id
        or result.task_id != task.id
        or result.validation_contract_id != run.validation_contract_id
        or result.repository_configuration_id != run.repository_configuration_id
        or contract is None
        or contract.version != result.validation_contract_version
        or configuration is None
        or configuration.version != result.repository_configuration_version
        or result.commit_sha != run.commit_sha
        or result.tree_sha != run.tree_sha
        or ValidationOutcome(run.outcome) is not outcome
        or decision_record is None
        or decision_record.owner_id != task.owner_id
        or decision_record.task_id != task.id
        or decision_record.validation_run_id != run.id
        or decision_record.evidence_type != "validation-decision"
        or reference is None
        or not isinstance(decision_content, Mapping)
        or dict(decision_content)
        != {
            key: value
            for key, value in payload.items()
            if key != "decision_evidence_id"
        }
        or not _valid_decision_fingerprint(payload)
    ):
        raise ValidationDecisionError("VALIDATION_DECISION_INCOMPLETE")
    return result


def _valid_decision_fingerprint(payload: Mapping[str, object]) -> bool:
    fingerprint = payload.get("decision_fingerprint")
    core = {
        key: value
        for key, value in payload.items()
        if key not in {"decision_evidence_id", "decision_fingerprint"}
    }
    encoded = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
    return bool(
        isinstance(fingerprint, str)
        and fingerprint == hashlib.sha256(encoded).hexdigest()
    )


def _latest_validation_attempt(session: Session, task_id: UUID) -> TaskEvent | None:
    return session.scalar(
        select(TaskEvent)
        .where(
            TaskEvent.task_id == task_id,
            TaskEvent.transition_to_state == TaskState.VALIDATING,
            TaskEvent.transition_kind.in_(("BEGIN_VALIDATION", "REVALIDATE")),
        )
        .order_by(TaskEvent.sequence.desc())
        .limit(1)
    )


def _is_current(
    session: Session,
    task: Task,
    run: ValidationRun,
    attempt_id: UUID,
) -> bool:
    attempt = _latest_validation_attempt(session, task.id)
    candidate = None if attempt is None else attempt.payload.get("validation_candidate")
    return bool(
        attempt is not None
        and attempt.transition_id == attempt_id
        and task.validation_contract_id == run.validation_contract_id
        and task.repository_configuration_id == run.repository_configuration_id
        and isinstance(candidate, Mapping)
        and candidate.get("commit_sha") == run.commit_sha
        and candidate.get("tree_sha") == run.tree_sha
    )


def _operation_status(
    run: ValidationRun,
    contract: ValidationContract,
    configuration: RepositoryConfiguration,
) -> str:
    configured: dict[str, object] = {}
    for value in configuration.operations:
        if not isinstance(value, Mapping):
            return "INVALID"
        operation_id = value.get("operation_id")
        operation_kind = value.get("kind")
        if not isinstance(operation_id, str) or operation_id in configured:
            return "INVALID"
        configured[operation_id] = operation_kind
    required: set[str] = set()
    for value in contract.required_operations:
        operation_id = value.get("operation_id") if isinstance(value, Mapping) else None
        if not isinstance(operation_id, str) or operation_id in required:
            return "INVALID"
        required.add(operation_id)
    seen: set[str] = set()
    failed = False
    for value in run.operation_results:
        if not isinstance(value, Mapping):
            return "INVALID"
        operation_id = value.get("operation_id")
        if (
            not isinstance(operation_id, str)
            or operation_id in seen
            or operation_id not in required
            or value.get("schema_version") != 1
            or value.get("operation_kind") != configured.get(operation_id)
            or value.get("head_sha") != run.commit_sha
            or value.get("tree_sha") != run.tree_sha
            or value.get("configuration_id") != str(configuration.id)
            or value.get("configuration_version") != configuration.version
            or value.get("validation_contract_version") != contract.version
            or not isinstance(value.get("passed"), bool)
            or not isinstance(value.get("repository_state_valid"), bool)
            or not isinstance(value.get("exit_status"), int)
            or isinstance(value.get("exit_status"), bool)
            or not isinstance(value.get("output_limited"), bool)
        ):
            return "INVALID"
        seen.add(operation_id)
        passed = cast(bool, value["passed"])
        repository_state_valid = cast(bool, value["repository_state_valid"])
        expected_passed = bool(
            value["exit_status"] == 0
            and value.get("cancellation_status") == "NOT_REQUESTED"
            and not cast(bool, value["output_limited"])
            and repository_state_valid
        )
        if passed is not expected_passed:
            return "INVALID"
        failed = failed or not passed
    if seen != required:
        return "INVALID"
    return "FAILED" if failed else "PASSED"


def _assertion_status(run: ValidationRun, contract: ValidationContract) -> str:
    required: dict[str, tuple[object, object]] = {}
    for value in contract.typed_assertions:
        if not isinstance(value, Mapping):
            return "INVALID"
        assertion_id = value.get("assertion_id")
        if not isinstance(assertion_id, str) or assertion_id in required:
            return "INVALID"
        required[assertion_id] = (value.get("kind"), value.get("verifier_catalog_key"))
    statuses: list[str] = []
    seen: set[str] = set()
    for value in run.assertion_results:
        if not isinstance(value, Mapping):
            return "INVALID"
        assertion_id = value.get("assertion_id")
        status = value.get("status")
        expected = required.get(assertion_id) if isinstance(assertion_id, str) else None
        if (
            expected is None
            or assertion_id in seen
            or (value.get("kind"), value.get("verifier_catalog_key")) != expected
            or status not in {"PENDING", "PASSED", "FAILED", "BLOCKED"}
        ):
            return "INVALID"
        seen.add(cast(str, assertion_id))
        statuses.append(cast(str, status))
    if seen != set(required):
        return "INVALID"
    return _combined_status(statuses)


def _criterion_status(
    run: ValidationRun,
    contract: ValidationContract,
    task: Task,
    session: Session,
) -> str:
    brief = session.get(Brief, contract.brief_id)
    if brief is None or brief.task_id != task.id:
        return "INVALID"
    required: set[str] = set()
    for value in brief.acceptance_criteria:
        criterion_id = value.get("criterion_id") if isinstance(value, Mapping) else None
        if not isinstance(criterion_id, str) or criterion_id in required:
            return "INVALID"
        required.add(criterion_id)
    statuses: list[str] = []
    seen: set[str] = set()
    for value in run.acceptance_criterion_results:
        if not isinstance(value, Mapping):
            return "INVALID"
        criterion_id = value.get("criterion_id")
        criterion_status = value.get("status")
        if (
            not isinstance(criterion_id, str)
            or criterion_id in seen
            or value.get("validation_contract_version") != contract.version
            or value.get("commit_sha") != run.commit_sha
            or value.get("tree_sha") != run.tree_sha
            or criterion_status not in {"PENDING", "PASSED", "FAILED", "BLOCKED"}
        ):
            return "INVALID"
        seen.add(criterion_id)
        statuses.append(cast(str, criterion_status))
    if seen != required:
        return "INVALID"
    return _combined_status(statuses)


def _combined_status(statuses: Sequence[str]) -> str:
    if "FAILED" in statuses:
        return "FAILED"
    if "BLOCKED" in statuses:
        return "BLOCKED"
    if "PENDING" in statuses:
        return "PENDING"
    return "PASSED" if statuses and all(value == "PASSED" for value in statuses) else "INVALID"


def _required_evidence_types(values: Sequence[object]) -> set[str] | None:
    result: set[str] = set()
    for value in values:
        evidence_type = value.get("evidence_type") if isinstance(value, Mapping) else None
        normalized = (
            None
            if not isinstance(evidence_type, str)
            else f"validation-{evidence_type.casefold().replace('_', '-')}"
        )
        if normalized is None or normalized in result:
            return None
        result.add(normalized)
    return result if result else None


def _valid_manifest(
    value: object,
    *,
    run: ValidationRun,
    contract: ValidationContract,
    configuration: RepositoryConfiguration,
    evidence_ids: set[UUID],
) -> bool:
    if not isinstance(value, Mapping):
        return False
    raw_ids = value.get("evidence_ids")
    try:
        parsed_ids = (
            [UUID(item) for item in raw_ids if isinstance(item, str)]
            if isinstance(raw_ids, list)
            else []
        )
    except ValueError:
        return False
    if not isinstance(raw_ids, list) or len(parsed_ids) != len(raw_ids):
        return False
    manifest_ids = set(parsed_ids)
    return bool(
        value.get("validation_run_id") == str(run.id)
        and value.get("validation_contract_id") == str(contract.id)
        and value.get("validation_contract_version") == contract.version
        and value.get("repository_configuration_id") == str(configuration.id)
        and value.get("repository_configuration_version") == configuration.version
        and value.get("commit_sha") == run.commit_sha
        and value.get("tree_sha") == run.tree_sha
        and manifest_ids == evidence_ids
    )


def _result_evidence_ids(values: Sequence[object]) -> set[UUID] | None:
    result: set[UUID] = set()
    try:
        for value in values:
            if not isinstance(value, Mapping):
                return None
            raw_ids = value.get("evidence_ids")
            if not isinstance(raw_ids, list):
                return None
            parsed = [UUID(item) for item in raw_ids if isinstance(item, str)]
            if len(parsed) != len(raw_ids):
                return None
            result.update(parsed)
    except ValueError:
        return None
    return result


def _git_object(value: str, code: str) -> str:
    normalized = value.strip().lower()
    if _GIT_OBJECT.fullmatch(normalized) is None:
        raise ValidationDecisionError(code)
    return normalized


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return _as_utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("invalid timestamp")
    return _as_utc(datetime.fromisoformat(value[:-1] + "+00:00"))


def _integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("invalid integer")
    return value
