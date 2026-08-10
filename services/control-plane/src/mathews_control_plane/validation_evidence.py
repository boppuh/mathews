"""Strict, transactional collection of evidence for one validation candidate."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import cast
from uuid import UUID

from mathews_configuration import AssertionKind, OperationKind
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    Brief,
    BriefApprovalDecision,
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
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
)

VALIDATION_EVIDENCE_EVENT_TYPE = "VALIDATION_EVIDENCE_COLLECTED"
VALIDATION_EVIDENCE_SCHEMA_VERSION = 1
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,254}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GIT_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_MAX_EVIDENCE_ITEMS = 256
_MAX_ASSERTION_RESULTS = 256
_MAX_OPERATION_RESULTS = 32


class ValidationEvidenceError(RuntimeError):
    """A stable validation-evidence refusal without source artifact contents."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class AssertionResultStatus(StrEnum):
    PENDING = "PENDING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class ValidationEvidenceType(StrEnum):
    UNIT_TEST_OUTPUT = "UNIT_TEST_OUTPUT"
    INTEGRATION_TEST_OUTPUT = "INTEGRATION_TEST_OUTPUT"
    SIMULATOR_ARTIFACT = "SIMULATOR_ARTIFACT"
    APPLICATION_LOG = "APPLICATION_LOG"
    CRASH_SIGNAL = "CRASH_SIGNAL"
    ERROR_SIGNAL = "ERROR_SIGNAL"
    NETWORK_SIGNAL = "NETWORK_SIGNAL"
    PERFORMANCE_SIGNAL = "PERFORMANCE_SIGNAL"


@dataclass(frozen=True, slots=True)
class ValidationEvidenceItem:
    """One immutable host artifact reference to register in the evidence ledger."""

    evidence_id: UUID
    evidence_key: str
    evidence_type: ValidationEvidenceType
    origin: str
    content_address: str
    size_bytes: int
    role: str
    source_path: str | None = None

    def __post_init__(self) -> None:
        _require_identifier(self.evidence_key, "evidence key")
        _require_identifier(self.origin, "evidence origin", maximum=500)
        _require_identifier(self.role, "evidence role")
        if not isinstance(self.evidence_id, UUID):
            raise ValidationEvidenceError("EVIDENCE_ID_INVALID")
        if not isinstance(self.evidence_type, ValidationEvidenceType):
            raise ValidationEvidenceError("EVIDENCE_TYPE_INVALID")
        if _DIGEST.fullmatch(self.content_address) is None:
            raise ValidationEvidenceError("EVIDENCE_ADDRESS_INVALID")
        if (
            isinstance(self.size_bytes, bool)
            or not isinstance(self.size_bytes, int)
            or self.size_bytes < 0
            or self.size_bytes > 128 * 1024 * 1024
        ):
            raise ValidationEvidenceError("EVIDENCE_SIZE_INVALID")
        if self.source_path is not None:
            if (
                not isinstance(self.source_path, str)
                or not self.source_path
                or len(self.source_path) > 1_000
                or "\x00" in self.source_path
            ):
                raise ValidationEvidenceError("EVIDENCE_SOURCE_PATH_INVALID")

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": VALIDATION_EVIDENCE_SCHEMA_VERSION,
            "evidence_key": self.evidence_key,
            "evidence_type": self.evidence_type.value,
            "host_content_address": self.content_address,
            "size_bytes": self.size_bytes,
            "role": self.role,
            "source_path": self.source_path,
        }


@dataclass(frozen=True, slots=True)
class ValidationOperationResult:
    """Bounded projection of one configured host operation result."""

    operation_id: str
    operation_kind: OperationKind
    exit_status: int
    duration_ms: int
    passed: bool
    cancellation_status: str
    output_limited: bool
    repository_state_valid: bool
    head_sha: str
    tree_sha: str
    configuration_id: UUID
    configuration_version: int
    configuration_digest: str
    validation_contract_version: int
    evidence_keys: tuple[str, ...]
    simulator_target: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        _require_identifier(self.operation_id, "operation id")
        if not isinstance(self.operation_kind, OperationKind):
            raise ValidationEvidenceError("OPERATION_KIND_INVALID")
        if isinstance(self.exit_status, bool) or not isinstance(self.exit_status, int):
            raise ValidationEvidenceError("OPERATION_EXIT_STATUS_INVALID")
        _require_non_negative(self.duration_ms, "OPERATION_DURATION_INVALID")
        if not all(
            isinstance(value, bool)
            for value in (
                self.passed,
                self.output_limited,
                self.repository_state_valid,
            )
        ):
            raise ValidationEvidenceError("OPERATION_RESULT_INVALID")
        _require_identifier(self.cancellation_status, "cancellation status")
        _require_git_object(self.head_sha, "OPERATION_HEAD_INVALID")
        _require_git_object(self.tree_sha, "OPERATION_TREE_INVALID")
        if not isinstance(self.configuration_id, UUID):
            raise ValidationEvidenceError("OPERATION_CONFIGURATION_INVALID")
        _require_positive(
            self.configuration_version,
            "OPERATION_CONFIGURATION_VERSION_INVALID",
        )
        if _DIGEST.fullmatch(self.configuration_digest) is None:
            raise ValidationEvidenceError("OPERATION_CONFIGURATION_DIGEST_INVALID")
        _require_positive(
            self.validation_contract_version,
            "OPERATION_CONTRACT_VERSION_INVALID",
        )
        _require_identifier_tuple(self.evidence_keys, "operation evidence keys")
        if not self.evidence_keys:
            raise ValidationEvidenceError("OPERATION_EVIDENCE_MISSING")
        if self.operation_kind is OperationKind.SIMULATOR_E2E:
            _validate_simulator_target(self.simulator_target)
        elif self.simulator_target is not None:
            raise ValidationEvidenceError("OPERATION_SIMULATOR_TARGET_UNEXPECTED")

    def to_dict(self, evidence_ids: Mapping[str, UUID]) -> dict[str, object]:
        return {
            "schema_version": VALIDATION_EVIDENCE_SCHEMA_VERSION,
            "operation_id": self.operation_id,
            "operation_kind": self.operation_kind.value,
            "exit_status": self.exit_status,
            "duration_ms": self.duration_ms,
            "passed": self.passed,
            "cancellation_status": self.cancellation_status,
            "output_limited": self.output_limited,
            "repository_state_valid": self.repository_state_valid,
            "head_sha": self.head_sha,
            "tree_sha": self.tree_sha,
            "configuration_id": str(self.configuration_id),
            "configuration_version": self.configuration_version,
            "configuration_digest": self.configuration_digest,
            "validation_contract_version": self.validation_contract_version,
            "evidence_ids": [str(evidence_ids[key]) for key in self.evidence_keys],
            "simulator_target": (
                None if self.simulator_target is None else dict(self.simulator_target)
            ),
        }


@dataclass(frozen=True, slots=True)
class TypedAssertionResult:
    """Authoritative deterministic verifier result; prose cannot mint this type."""

    assertion_id: str
    kind: AssertionKind
    verifier_catalog_key: str
    status: AssertionResultStatus
    evidence_keys: tuple[str, ...]
    result_code: str

    def __post_init__(self) -> None:
        _require_identifier(self.assertion_id, "assertion id")
        if not isinstance(self.kind, AssertionKind):
            raise ValidationEvidenceError("ASSERTION_KIND_INVALID")
        _require_identifier(self.verifier_catalog_key, "verifier catalog key")
        if not isinstance(self.status, AssertionResultStatus):
            raise ValidationEvidenceError("ASSERTION_STATUS_INVALID")
        _require_identifier_tuple(self.evidence_keys, "assertion evidence keys")
        _require_identifier(self.result_code, "assertion result code")
        if self.status is AssertionResultStatus.PENDING:
            if self.evidence_keys:
                raise ValidationEvidenceError("PENDING_ASSERTION_HAS_EVIDENCE")
        elif not self.evidence_keys:
            raise ValidationEvidenceError("ASSERTION_EVIDENCE_MISSING")

    def to_dict(self, evidence_ids: Mapping[str, UUID]) -> dict[str, object]:
        return {
            "assertion_id": self.assertion_id,
            "kind": self.kind.value,
            "verifier_catalog_key": self.verifier_catalog_key,
            "status": self.status.value,
            "result_code": self.result_code,
            "evidence_ids": [str(evidence_ids[key]) for key in self.evidence_keys],
        }


@dataclass(frozen=True, slots=True)
class ValidationEvidenceCollection:
    run_id: UUID
    task_id: UUID
    validation_contract_id: UUID
    repository_configuration_id: UUID
    commit_sha: str
    tree_sha: str
    duration_ms: int
    evidence: tuple[ValidationEvidenceItem, ...]
    operation_results: tuple[ValidationOperationResult, ...]
    assertion_results: tuple[TypedAssertionResult, ...]

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, UUID)
            for value in (
                self.run_id,
                self.task_id,
                self.validation_contract_id,
                self.repository_configuration_id,
            )
        ):
            raise ValidationEvidenceError("COLLECTION_ID_INVALID")
        _require_git_object(self.commit_sha, "COLLECTION_COMMIT_INVALID")
        _require_git_object(self.tree_sha, "COLLECTION_TREE_INVALID")
        _require_non_negative(self.duration_ms, "COLLECTION_DURATION_INVALID")
        _bounded_typed_tuple(
            self.evidence,
            ValidationEvidenceItem,
            maximum=_MAX_EVIDENCE_ITEMS,
            code="EVIDENCE_COLLECTION_INVALID",
        )
        _bounded_typed_tuple(
            self.operation_results,
            ValidationOperationResult,
            maximum=_MAX_OPERATION_RESULTS,
            code="OPERATION_RESULTS_INVALID",
        )
        _bounded_typed_tuple(
            self.assertion_results,
            TypedAssertionResult,
            maximum=_MAX_ASSERTION_RESULTS,
            code="ASSERTION_RESULTS_INVALID",
        )
        _require_unique(
            (item.evidence_id for item in self.evidence),
            "EVIDENCE_ID_DUPLICATE",
        )
        _require_unique(
            (item.evidence_key for item in self.evidence),
            "EVIDENCE_KEY_DUPLICATE",
        )
        _require_unique(
            (item.operation_id for item in self.operation_results),
            "OPERATION_RESULT_DUPLICATE",
        )
        _require_unique(
            (item.assertion_id for item in self.assertion_results),
            "ASSERTION_RESULT_DUPLICATE",
        )


@dataclass(frozen=True, slots=True)
class ValidationEvidenceResult:
    validation_run_id: UUID
    task_id: UUID
    contract_version: int
    commit_sha: str
    tree_sha: str
    evidence_ids: tuple[UUID, ...]
    criterion_results: tuple[Mapping[str, object], ...]
    replayed: bool


class ValidationEvidenceService:
    """Validate all immutable bindings and atomically persist one run's evidence."""

    def __init__(
        self,
        session_factory: SessionFactory,
        artifact_store: ArtifactStore,
        *,
        principal_id: str = "local-user",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._factory = session_factory
        self._store = artifact_store
        self._principal_id = principal_id
        self._clock = clock or (lambda: datetime.now(UTC))

    def collect(self, collection: ValidationEvidenceCollection) -> ValidationEvidenceResult:
        now = _as_utc(self._clock())
        with self._factory.begin() as session:
            replay = session.get(ValidationRun, collection.run_id)
            if replay is not None:
                return _replayed_result(session, replay, collection)

            task = session.scalar(
                select(Task).where(Task.id == collection.task_id).with_for_update()
            )
            if task is None or task.owner_id != self._principal_id:
                raise ValidationEvidenceError("TASK_UNAVAILABLE")
            if TaskState(task.state) is not TaskState.VALIDATING:
                raise ValidationEvidenceError("TASK_NOT_VALIDATING")
            contract = session.get(ValidationContract, collection.validation_contract_id)
            configuration = session.get(
                RepositoryConfiguration,
                collection.repository_configuration_id,
            )
            brief = (
                None
                if task.accepted_brief_id is None
                else session.get(Brief, task.accepted_brief_id)
            )
            decision = (
                None
                if task.brief_approval_decision_id is None
                else session.get(BriefApprovalDecision, task.brief_approval_decision_id)
            )
            if (
                contract is None
                or configuration is None
                or brief is None
                or decision is None
                or task.validation_contract_id != contract.id
                or task.repository_configuration_id != configuration.id
                or contract.task_id != task.id
                or contract.brief_id != brief.id
                or contract.repository_configuration_id != configuration.id
                or decision.task_id != task.id
                or decision.brief_id != brief.id
                or task.accepted_brief_id != brief.id
            ):
                raise ValidationEvidenceError("VALIDATION_BINDING_MISMATCH")

            evidence_by_key = {item.evidence_key: item for item in collection.evidence}
            evidence_types = {item.evidence_type.value for item in collection.evidence}
            required_evidence_types = _required_evidence_types(
                contract.evidence_requirements
            )
            if not required_evidence_types.issubset(evidence_types):
                raise ValidationEvidenceError("REQUIRED_EVIDENCE_MISSING")

            operation_ids = _required_operation_ids(contract.required_operations)
            if {result.operation_id for result in collection.operation_results} != operation_ids:
                raise ValidationEvidenceError("OPERATION_RESULTS_INCOMPLETE")
            for operation in collection.operation_results:
                _validate_operation_binding(
                    operation,
                    collection=collection,
                    contract=contract,
                    configuration=configuration,
                    evidence_by_key=evidence_by_key,
                )

            requirements = _assertion_requirements(contract.typed_assertions)
            results_by_id = {
                result.assertion_id: result for result in collection.assertion_results
            }
            if set(results_by_id) != set(requirements):
                raise ValidationEvidenceError("ASSERTION_RESULTS_INCOMPLETE")
            for assertion_id, (kind, catalog_key, _criterion_id) in requirements.items():
                result = results_by_id[assertion_id]
                if result.kind is not kind or result.verifier_catalog_key != catalog_key:
                    raise ValidationEvidenceError("ASSERTION_RESULT_MISMATCH")
                _require_evidence_keys(result.evidence_keys, evidence_by_key)

            criterion_ids = _brief_criterion_ids(brief)
            criteria_by_assertion: dict[str, list[str]] = defaultdict(list)
            for assertion_id, (_kind, _catalog_key, criterion_id) in requirements.items():
                if criterion_id is not None:
                    criteria_by_assertion[criterion_id].append(assertion_id)
            if set(criteria_by_assertion) != criterion_ids:
                raise ValidationEvidenceError("CRITERION_BINDINGS_INCOMPLETE")

            run = ValidationRun(
                id=collection.run_id,
                task_id=task.id,
                validation_contract_id=contract.id,
                repository_configuration_id=configuration.id,
                commit_sha=collection.commit_sha,
                tree_sha=collection.tree_sha,
                configured_test_plan=list(contract.required_operations),
                operation_results=[],
                simulator_target=_simulator_target(collection.operation_results),
                outcome=ValidationOutcome.PENDING,
                duration_ms=collection.duration_ms,
                acceptance_criterion_results=[],
                owner_id=task.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=task.root_correlation_id,
                causation_id=collection.run_id,
                parent_correlation_id=contract.id,
                created_at=now,
                updated_at=now,
            )
            session.add(run)
            session.flush()

            evidence_ids: dict[str, UUID] = {}
            for item in collection.evidence:
                captured = capture_evidence(
                    session,
                    self._store,
                    payload=item.payload(),
                    media_type="application/json",
                    source_kind=EvidenceSourceKind.RESULT,
                    evidence_type=(
                        "validation-"
                        f"{item.evidence_type.value.casefold().replace('_', '-')}"
                    ),
                    origin=item.origin,
                    access_classification=EvidenceAccessClass.TASK_OWNER,
                    retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
                    owner_id=task.owner_id,
                    actor_id=self._principal_id,
                    root_correlation_id=task.root_correlation_id,
                    task_id=task.id,
                    validation_run_id=run.id,
                    causation_id=item.evidence_id,
                    parent_correlation_id=run.id,
                    evidence_id=item.evidence_id,
                    captured_at=now,
                )
                evidence_ids[item.evidence_key] = captured.record.id

            assertion_payloads = {
                result.assertion_id: result.to_dict(evidence_ids)
                for result in collection.assertion_results
            }
            criterion_results = tuple(
                _criterion_result(
                    criterion_id,
                    criteria_by_assertion[criterion_id],
                    assertion_payloads,
                    contract_version=contract.version,
                    commit_sha=collection.commit_sha,
                    tree_sha=collection.tree_sha,
                )
                for criterion_id in sorted(criterion_ids)
            )
            run.operation_results = [
                operation.to_dict(evidence_ids)
                for operation in collection.operation_results
            ]
            run.acceptance_criterion_results = list(criterion_results)
            application_logs = [
                evidence_ids[item.evidence_key]
                for item in collection.evidence
                if item.evidence_type is ValidationEvidenceType.APPLICATION_LOG
            ]
            run.log_evidence_id = application_logs[0] if application_logs else None

            manifest = capture_evidence(
                session,
                self._store,
                payload={
                    "schema_version": VALIDATION_EVIDENCE_SCHEMA_VERSION,
                    "validation_run_id": str(run.id),
                    "validation_contract_id": str(contract.id),
                    "validation_contract_version": contract.version,
                    "repository_configuration_id": str(configuration.id),
                    "repository_configuration_version": configuration.version,
                    "commit_sha": collection.commit_sha,
                    "tree_sha": collection.tree_sha,
                    "collection_fingerprint": _collection_fingerprint(collection),
                    "evidence_ids": [str(value) for value in evidence_ids.values()],
                    "operation_results": run.operation_results,
                    "acceptance_criterion_results": run.acceptance_criterion_results,
                },
                media_type="application/json",
                source_kind=EvidenceSourceKind.RESULT,
                evidence_type="validation-evidence-manifest",
                origin="control-plane:validation-evidence",
                access_classification=EvidenceAccessClass.TASK_OWNER,
                retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
                owner_id=task.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=task.root_correlation_id,
                task_id=task.id,
                validation_run_id=run.id,
                causation_id=run.id,
                parent_correlation_id=contract.id,
                captured_at=now,
            )
            event = TaskEvent(
                task_id=task.id,
                sequence=(
                    session.scalar(
                        select(func.max(TaskEvent.sequence)).where(TaskEvent.task_id == task.id)
                    )
                    or 0
                )
                + 1,
                event_type=VALIDATION_EVIDENCE_EVENT_TYPE,
                payload={
                    "schema_version": VALIDATION_EVIDENCE_SCHEMA_VERSION,
                    "validation_run_id": str(run.id),
                    "validation_contract_id": str(contract.id),
                    "validation_contract_version": contract.version,
                    "commit_sha": collection.commit_sha,
                    "tree_sha": collection.tree_sha,
                    "manifest_evidence_id": str(manifest.record.id),
                    "evidence_ids": [
                        *(str(value) for value in evidence_ids.values()),
                        str(manifest.record.id),
                    ],
                    "collection_fingerprint": _collection_fingerprint(collection),
                },
                occurred_at=now,
                owner_id=task.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=task.root_correlation_id,
                causation_id=run.id,
                parent_correlation_id=contract.id,
            )
            session.add(event)
            session.flush()
            session.add(
                TaskEventEvidenceReference(
                    task_id=task.id,
                    task_event_id=event.id,
                    evidence_id=manifest.record.id,
                    position=1,
                    owner_id=task.owner_id,
                    actor_id=self._principal_id,
                    root_correlation_id=task.root_correlation_id,
                    causation_id=event.id,
                    parent_correlation_id=run.id,
                )
            )
            session.flush()
            return ValidationEvidenceResult(
                validation_run_id=run.id,
                task_id=task.id,
                contract_version=contract.version,
                commit_sha=run.commit_sha,
                tree_sha=run.tree_sha,
                evidence_ids=tuple((*evidence_ids.values(), manifest.record.id)),
                criterion_results=criterion_results,
                replayed=False,
            )


def _required_evidence_types(values: Sequence[object]) -> set[str]:
    result: set[str] = set()
    for value in values:
        raw_type = value if isinstance(value, str) else None
        if isinstance(value, Mapping) and set(value) == {"evidence_type"}:
            raw_type = value.get("evidence_type")
        if not isinstance(raw_type, str):
            raise ValidationEvidenceError("EVIDENCE_REQUIREMENT_INVALID")
        try:
            normalized = ValidationEvidenceType(raw_type).value
        except ValueError:
            raise ValidationEvidenceError("EVIDENCE_REQUIREMENT_INVALID") from None
        if normalized in result:
            raise ValidationEvidenceError("EVIDENCE_REQUIREMENT_DUPLICATE")
        result.add(normalized)
    if not result:
        raise ValidationEvidenceError("EVIDENCE_REQUIREMENTS_EMPTY")
    return result


def _required_operation_ids(values: Sequence[object]) -> set[str]:
    result: set[str] = set()
    for value in values:
        if not isinstance(value, Mapping) or set(value) != {"operation_id"}:
            raise ValidationEvidenceError("OPERATION_REQUIREMENT_INVALID")
        operation_id = value.get("operation_id")
        if not isinstance(operation_id, str):
            raise ValidationEvidenceError("OPERATION_REQUIREMENT_INVALID")
        _require_identifier(operation_id, "operation id")
        if operation_id in result:
            raise ValidationEvidenceError("OPERATION_REQUIREMENT_DUPLICATE")
        result.add(operation_id)
    if not result:
        raise ValidationEvidenceError("OPERATION_REQUIREMENTS_EMPTY")
    return result


def _assertion_requirements(
    values: Sequence[object],
) -> dict[str, tuple[AssertionKind, str, str | None]]:
    result: dict[str, tuple[AssertionKind, str, str | None]] = {}
    expected_fields = {
        "assertion_id",
        "kind",
        "verifier_catalog_key",
        "acceptance_criterion_id",
    }
    for value in values:
        if not isinstance(value, Mapping) or set(value) != expected_fields:
            raise ValidationEvidenceError("ASSERTION_REQUIREMENT_INVALID")
        assertion_id = value.get("assertion_id")
        raw_kind = value.get("kind")
        catalog_key = value.get("verifier_catalog_key")
        criterion_id = value.get("acceptance_criterion_id")
        if (
            not isinstance(assertion_id, str)
            or not isinstance(raw_kind, str)
            or not isinstance(catalog_key, str)
            or (criterion_id is not None and not isinstance(criterion_id, str))
        ):
            raise ValidationEvidenceError("ASSERTION_REQUIREMENT_INVALID")
        _require_identifier(assertion_id, "assertion id")
        _require_identifier(catalog_key, "verifier catalog key")
        if criterion_id is not None:
            _require_identifier(criterion_id, "acceptance criterion id")
        try:
            kind = AssertionKind(raw_kind)
        except ValueError:
            raise ValidationEvidenceError("ASSERTION_REQUIREMENT_INVALID") from None
        if assertion_id in result:
            raise ValidationEvidenceError("ASSERTION_REQUIREMENT_DUPLICATE")
        result[assertion_id] = (kind, catalog_key, criterion_id)
    if not result:
        raise ValidationEvidenceError("ASSERTION_REQUIREMENTS_EMPTY")
    return result


def _brief_criterion_ids(brief: Brief) -> set[str]:
    result: set[str] = set()
    for value in brief.acceptance_criteria:
        if not isinstance(value, Mapping) or not isinstance(value.get("criterion_id"), str):
            raise ValidationEvidenceError("BRIEF_CRITERIA_INVALID")
        criterion_id = cast(str, value["criterion_id"])
        _require_identifier(criterion_id, "acceptance criterion id")
        if criterion_id in result:
            raise ValidationEvidenceError("BRIEF_CRITERIA_INVALID")
        result.add(criterion_id)
    if not result:
        raise ValidationEvidenceError("BRIEF_CRITERIA_INVALID")
    return result


def _validate_operation_binding(
    result: ValidationOperationResult,
    *,
    collection: ValidationEvidenceCollection,
    contract: ValidationContract,
    configuration: RepositoryConfiguration,
    evidence_by_key: Mapping[str, ValidationEvidenceItem],
) -> None:
    if (
        result.head_sha != collection.commit_sha
        or result.tree_sha != collection.tree_sha
        or result.configuration_id != configuration.id
        or result.configuration_version != configuration.version
        or result.configuration_digest != _bound_configuration_digest(configuration)
        or result.validation_contract_version != contract.version
    ):
        raise ValidationEvidenceError("OPERATION_BINDING_MISMATCH")
    _require_evidence_keys(result.evidence_keys, evidence_by_key)
    if result.operation_kind is OperationKind.SIMULATOR_E2E:
        _validate_simulator_binding(result, configuration, contract)


def _require_evidence_keys(
    keys: Sequence[str],
    evidence_by_key: Mapping[str, ValidationEvidenceItem],
) -> None:
    if not set(keys).issubset(evidence_by_key):
        raise ValidationEvidenceError("EVIDENCE_REFERENCE_UNKNOWN")


def _criterion_result(
    criterion_id: str,
    assertion_ids: Sequence[str],
    assertion_payloads: Mapping[str, Mapping[str, object]],
    *,
    contract_version: int,
    commit_sha: str,
    tree_sha: str,
) -> Mapping[str, object]:
    assertions = [assertion_payloads[assertion_id] for assertion_id in assertion_ids]
    statuses = {
        AssertionResultStatus(cast(str, assertion["status"])) for assertion in assertions
    }
    if AssertionResultStatus.FAILED in statuses:
        status = AssertionResultStatus.FAILED
    elif AssertionResultStatus.BLOCKED in statuses:
        status = AssertionResultStatus.BLOCKED
    elif AssertionResultStatus.PENDING in statuses:
        status = AssertionResultStatus.PENDING
    else:
        status = AssertionResultStatus.PASSED
    evidence_ids = sorted(
        {
            cast(str, evidence_id)
            for assertion in assertions
            for evidence_id in cast(Sequence[object], assertion["evidence_ids"])
        }
    )
    return {
        "schema_version": VALIDATION_EVIDENCE_SCHEMA_VERSION,
        "criterion_id": criterion_id,
        "status": status.value,
        "assertions": assertions,
        "evidence_ids": evidence_ids,
        "validation_contract_version": contract_version,
        "commit_sha": commit_sha,
        "tree_sha": tree_sha,
    }


def _simulator_target(
    results: Sequence[ValidationOperationResult],
) -> dict[str, object] | None:
    targets = [
        dict(result.simulator_target)
        for result in results
        if result.simulator_target is not None
    ]
    if len(targets) > 1:
        raise ValidationEvidenceError("SIMULATOR_TARGET_AMBIGUOUS")
    return targets[0] if targets else None


def _bound_configuration_digest(configuration: RepositoryConfiguration) -> str:
    payload = {
        "repository_key": configuration.repository_key,
        "version": configuration.version,
        "repository_settings": configuration.repository_settings,
        "git_settings": configuration.git_settings,
        "xcode_settings": configuration.xcode_settings,
        "operations": configuration.operations,
        "e2e_assertions": configuration.e2e_assertions,
        "artifact_settings": configuration.artifact_settings,
        "prohibited_paths": configuration.prohibited_paths,
        "secret_references": configuration.secret_references,
    }
    try:
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
    except (TypeError, ValueError):
        raise ValidationEvidenceError("CONFIGURATION_BINDING_INVALID") from None
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def _validate_simulator_target(value: Mapping[str, object] | None) -> None:
    expected = {
        "device_id",
        "device_type_identifier",
        "runtime_identifier",
        "locale_identifier",
        "time_zone_identifier",
    }
    if value is None or set(value) != expected:
        raise ValidationEvidenceError("SIMULATOR_TARGET_INVALID")
    for field in expected:
        raw = value.get(field)
        if not isinstance(raw, str) or not raw or len(raw) > 255 or "\x00" in raw:
            raise ValidationEvidenceError("SIMULATOR_TARGET_INVALID")


def _validate_simulator_binding(
    result: ValidationOperationResult,
    configuration: RepositoryConfiguration,
    contract: ValidationContract,
) -> None:
    target = result.simulator_target
    xcode = configuration.xcode_settings
    simulator = xcode.get("simulator") if isinstance(xcode, Mapping) else None
    flow = contract.e2e_flow
    if (
        target is None
        or not isinstance(simulator, Mapping)
        or target.get("device_type_identifier")
        != simulator.get("device_type_identifier")
        or target.get("runtime_identifier") != simulator.get("runtime_identifier")
        or target.get("locale_identifier") != flow.get("locale_identifier")
        or target.get("time_zone_identifier") != flow.get("time_zone_identifier")
    ):
        raise ValidationEvidenceError("SIMULATOR_BINDING_MISMATCH")


def _replayed_result(
    session: Session,
    run: ValidationRun,
    collection: ValidationEvidenceCollection,
) -> ValidationEvidenceResult:
    if (
        run.task_id != collection.task_id
        or run.validation_contract_id != collection.validation_contract_id
        or run.repository_configuration_id != collection.repository_configuration_id
        or run.commit_sha != collection.commit_sha
        or run.tree_sha != collection.tree_sha
        or run.duration_ms != collection.duration_ms
    ):
        raise ValidationEvidenceError("VALIDATION_RUN_ID_CONFLICT")
    event = session.scalar(
        select(TaskEvent).where(
            TaskEvent.task_id == run.task_id,
            TaskEvent.event_type == VALIDATION_EVIDENCE_EVENT_TYPE,
            TaskEvent.causation_id == run.id,
        )
    )
    if (
        event is None
        or event.payload.get("collection_fingerprint")
        != _collection_fingerprint(collection)
    ):
        raise ValidationEvidenceError("VALIDATION_RUN_ID_CONFLICT")
    raw_evidence_ids = event.payload.get("evidence_ids")
    if not isinstance(raw_evidence_ids, list):
        raise ValidationEvidenceError("VALIDATION_RUN_INCOMPLETE")
    try:
        evidence_ids = tuple(
            UUID(value) for value in raw_evidence_ids if isinstance(value, str)
        )
    except ValueError:
        raise ValidationEvidenceError("VALIDATION_RUN_INCOMPLETE") from None
    if len(evidence_ids) != len(raw_evidence_ids) or len(set(evidence_ids)) != len(
        evidence_ids
    ):
        raise ValidationEvidenceError("VALIDATION_RUN_INCOMPLETE")
    stored_evidence_ids = set(
        session.scalars(
            select(EvidenceRecord.id).where(EvidenceRecord.validation_run_id == run.id)
        )
    )
    if stored_evidence_ids != set(evidence_ids):
        raise ValidationEvidenceError("VALIDATION_RUN_INCOMPLETE")
    contract = session.get(ValidationContract, run.validation_contract_id)
    if contract is None:
        raise ValidationEvidenceError("VALIDATION_RUN_INCOMPLETE")
    return ValidationEvidenceResult(
        validation_run_id=run.id,
        task_id=run.task_id,
        contract_version=contract.version,
        commit_sha=run.commit_sha,
        tree_sha=run.tree_sha,
        evidence_ids=evidence_ids,
        criterion_results=tuple(
            cast(Mapping[str, object], value)
            for value in run.acceptance_criterion_results
        ),
        replayed=True,
    )


def _require_identifier(value: object, field: str, *, maximum: int = 255) -> None:
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or _IDENTIFIER.fullmatch(value) is None
    ):
        raise ValidationEvidenceError(f"{field.upper().replace(' ', '_')}_INVALID")


def _require_identifier_tuple(values: object, field: str) -> None:
    if not isinstance(values, tuple):
        raise ValidationEvidenceError(f"{field.upper().replace(' ', '_')}_INVALID")
    for value in values:
        _require_identifier(value, field)
    if len(values) != len(set(values)):
        raise ValidationEvidenceError(f"{field.upper().replace(' ', '_')}_INVALID")


def _require_git_object(value: str, code: str) -> None:
    if _GIT_OBJECT.fullmatch(value) is None:
        raise ValidationEvidenceError(code)


def _require_positive(value: object, code: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValidationEvidenceError(code)


def _require_non_negative(value: object, code: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValidationEvidenceError(code)


def _bounded_typed_tuple(
    values: object,
    expected_type: type[object],
    *,
    maximum: int,
    code: str,
) -> None:
    if (
        not isinstance(values, tuple)
        or not values
        or len(values) > maximum
        or any(not isinstance(value, expected_type) for value in values)
    ):
        raise ValidationEvidenceError(code)


def _require_unique(values: Sequence[object] | object, code: str) -> None:
    materialized = tuple(cast(Sequence[object], values))
    if len(materialized) != len(set(materialized)):
        raise ValidationEvidenceError(code)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _collection_fingerprint(collection: ValidationEvidenceCollection) -> str:
    evidence_ids = {
        item.evidence_key: item.evidence_id for item in collection.evidence
    }
    payload = {
        "schema_version": VALIDATION_EVIDENCE_SCHEMA_VERSION,
        "run_id": str(collection.run_id),
        "task_id": str(collection.task_id),
        "validation_contract_id": str(collection.validation_contract_id),
        "repository_configuration_id": str(collection.repository_configuration_id),
        "commit_sha": collection.commit_sha,
        "tree_sha": collection.tree_sha,
        "duration_ms": collection.duration_ms,
        "evidence": [
            {
                "evidence_id": str(item.evidence_id),
                "origin": item.origin,
                **item.payload(),
            }
            for item in collection.evidence
        ],
        "operation_results": [
            item.to_dict(evidence_ids) for item in collection.operation_results
        ],
        "assertion_results": [
            item.to_dict(evidence_ids) for item in collection.assertion_results
        ],
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()
