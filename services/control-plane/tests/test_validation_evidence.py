from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from mathews_configuration import AssertionKind, OperationKind
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.database import (
    Base,
    SessionFactory,
    create_database_engine,
    create_session_factory,
)
from mathews_control_plane.domain_models import (
    Brief,
    BriefApprovalDecision,
    BriefDecisionDisposition,
    EvidenceRecord,
    RepositoryConfiguration,
    Task,
    TaskEvent,
    TaskState,
    ValidationContract,
    ValidationOutcome,
    ValidationRun,
)
from mathews_control_plane.tasks import _acceptance_criteria_response
from mathews_control_plane.validation_evidence import (
    AssertionResultStatus,
    TypedAssertionResult,
    ValidationEvidenceCollection,
    ValidationEvidenceError,
    ValidationEvidenceItem,
    ValidationEvidenceService,
    ValidationEvidenceType,
    ValidationOperationResult,
)
from sqlalchemy import func, select

_NOW = datetime(2026, 8, 10, 12, tzinfo=UTC)
_COMMIT_SHA = "a" * 40
_TREE_SHA = "b" * 40
_CONFIGURATION_DIGEST = f"sha256:{'c' * 64}"


def _context(root_id: UUID) -> dict[str, object]:
    return {
        "owner_id": "local-user",
        "actor_id": "local-user",
        "root_correlation_id": root_id,
        "causation_id": root_id,
        "parent_correlation_id": root_id,
        "created_at": _NOW,
        "updated_at": _NOW,
    }


def _seed(factory: SessionFactory) -> tuple[UUID, UUID, UUID]:
    root_id = uuid4()
    task_id = uuid4()
    with factory.begin() as session:
        task = Task(
            id=task_id,
            repository="boppuh/mathews",
            base_revision="d" * 40,
            requester="local-user",
            raw_request=f"evidence://{uuid4()}",
            summary="Collect validation evidence",
            state=TaskState.VALIDATING,
            retry_count=0,
            **_context(root_id),
        )
        configuration = RepositoryConfiguration(
            repository_key="boppuh/mathews",
            version=3,
            repository_settings={"root": "/tmp/mathews"},
            git_settings={"remote": "origin"},
            xcode_settings={
                "scheme": "Mathews",
                "simulator": {
                    "runtime_identifier": "com.apple.iOS-18-5",
                    "device_type_identifier": "com.apple.iPhone-16-Pro",
                },
            },
            operations=[],
            e2e_assertions=[],
            artifact_settings={"collection_paths": ["artifacts"]},
            prohibited_paths=[],
            secret_references=[],
            **_context(root_id),
        )
        brief = Brief(
            task_id=task.id,
            version=1,
            scope={"summary": "Validate the candidate"},
            exclusions=[],
            acceptance_criteria=[
                {
                    "criterion_id": "criterion.ui",
                    "requirement": "The expected value is visible.",
                    "verification": "SIMULATOR_ASSERTION",
                },
                {
                    "criterion_id": "criterion.network",
                    "requirement": "The expected response is observed.",
                    "verification": "SIMULATOR_ASSERTION",
                },
            ],
            risks=[],
            affected_flow={"name": "primary"},
            test_plan=[],
            **_context(root_id),
        )
        session.add_all((task, configuration))
        session.flush()
        session.add(brief)
        session.flush()
        decision = BriefApprovalDecision(
            task_id=task.id,
            brief_id=brief.id,
            disposition=BriefDecisionDisposition.AUTO_ACCEPTED_BY_POLICY,
            evaluator_id="brief-policy-v1",
            reason="unambiguous",
            ambiguity_flags=[],
            decided_at=_NOW,
            **_context(root_id),
        )
        contract = ValidationContract(
            task_id=task.id,
            version=4,
            brief_id=brief.id,
            repository_configuration_id=configuration.id,
            required_operations=[
                {"operation_id": "unit-tests"},
                {"operation_id": "integration-tests"},
                {"operation_id": "simulator-e2e"},
            ],
            simulator_setup={"clean": True},
            clean_state_setup={"reset": True},
            e2e_flow={
                "flow_id": "primary",
                "locale_identifier": "en_US_POSIX",
                "time_zone_identifier": "UTC",
            },
            typed_assertions=[
                {
                    "assertion_id": "no-crash",
                    "kind": "NO_CRASH",
                    "verifier_catalog_key": "app.no-crash",
                    "acceptance_criterion_id": None,
                },
                {
                    "assertion_id": "visible-title",
                    "kind": "ELEMENT_VALUE_PRESENT",
                    "verifier_catalog_key": "ui.visible-title",
                    "acceptance_criterion_id": "criterion.ui",
                },
                {
                    "assertion_id": "created-response",
                    "kind": "EXPECTED_NETWORK_RESPONSE",
                    "verifier_catalog_key": "network.created-response",
                    "acceptance_criterion_id": "criterion.network",
                },
            ],
            evidence_requirements=[
                {"evidence_type": evidence_type.value}
                for evidence_type in ValidationEvidenceType
            ],
            timeouts={"total_seconds": 3600},
            outcome_rules={"all_required": True},
            **_context(root_id),
        )
        session.add_all((decision, contract))
        session.flush()
        task.accepted_brief_id = brief.id
        task.brief_approval_decision_id = decision.id
        task.repository_configuration_id = configuration.id
        task.validation_contract_id = contract.id
        session.flush()
        return task.id, configuration.id, contract.id


def _evidence() -> tuple[ValidationEvidenceItem, ...]:
    return tuple(
        ValidationEvidenceItem(
            evidence_id=uuid4(),
            evidence_key=f"evidence.{index}",
            evidence_type=evidence_type,
            origin="host-agent:validation",
            content_address=f"sha256:{index:064x}",
            size_bytes=index + 1,
            role=evidence_type.value,
            source_path=f"artifacts/{evidence_type.value.casefold()}.json",
        )
        for index, evidence_type in enumerate(ValidationEvidenceType, start=1)
    )


def _collection(
    task_id: UUID,
    configuration_id: UUID,
    contract_id: UUID,
    *,
    run_id: UUID | None = None,
    head_sha: str = _COMMIT_SHA,
    configuration_digest: str,
) -> ValidationEvidenceCollection:
    evidence = _evidence()
    keys = {item.evidence_type: item.evidence_key for item in evidence}
    def operation(
        operation_id: str,
        operation_kind: OperationKind,
        evidence_keys: tuple[str, ...],
        *,
        simulator_target: Mapping[str, object] | None = None,
    ) -> ValidationOperationResult:
        return ValidationOperationResult(
            operation_id=operation_id,
            operation_kind=operation_kind,
            exit_status=0,
            duration_ms=100,
            passed=True,
            cancellation_status="NOT_REQUESTED",
            output_limited=False,
            repository_state_valid=True,
            head_sha=head_sha,
            tree_sha=_TREE_SHA,
            configuration_id=configuration_id,
            configuration_version=3,
            configuration_digest=configuration_digest,
            validation_contract_version=4,
            evidence_keys=evidence_keys,
            simulator_target=simulator_target,
        )

    operations = (
        operation(
            "unit-tests",
            OperationKind.UNIT_TEST,
            (keys[ValidationEvidenceType.UNIT_TEST_OUTPUT],),
        ),
        operation(
            "integration-tests",
            OperationKind.INTEGRATION_TEST,
            (keys[ValidationEvidenceType.INTEGRATION_TEST_OUTPUT],),
        ),
        operation(
            "simulator-e2e",
            OperationKind.SIMULATOR_E2E,
            tuple(item.evidence_key for item in evidence[2:]),
            simulator_target={
                "device_id": "SIMULATOR-1",
                "device_type_identifier": "com.apple.iPhone-16-Pro",
                "runtime_identifier": "com.apple.iOS-18-5",
                "locale_identifier": "en_US_POSIX",
                "time_zone_identifier": "UTC",
            },
        ),
    )
    assertions = (
        TypedAssertionResult(
            assertion_id="no-crash",
            kind=AssertionKind.NO_CRASH,
            verifier_catalog_key="app.no-crash",
            status=AssertionResultStatus.PASSED,
            evidence_keys=(keys[ValidationEvidenceType.CRASH_SIGNAL],),
            result_code="ZERO_CRASHES_OBSERVED",
        ),
        TypedAssertionResult(
            assertion_id="visible-title",
            kind=AssertionKind.ELEMENT_VALUE_PRESENT,
            verifier_catalog_key="ui.visible-title",
            status=AssertionResultStatus.PASSED,
            evidence_keys=(keys[ValidationEvidenceType.SIMULATOR_ARTIFACT],),
            result_code="EXPECTED_VALUE_PRESENT",
        ),
        TypedAssertionResult(
            assertion_id="created-response",
            kind=AssertionKind.EXPECTED_NETWORK_RESPONSE,
            verifier_catalog_key="network.created-response",
            status=AssertionResultStatus.BLOCKED,
            evidence_keys=(keys[ValidationEvidenceType.ERROR_SIGNAL],),
            result_code="DEPENDENCY_UNAVAILABLE",
        ),
    )
    return ValidationEvidenceCollection(
        run_id=run_id or uuid4(),
        task_id=task_id,
        validation_contract_id=contract_id,
        repository_configuration_id=configuration_id,
        commit_sha=_COMMIT_SHA,
        tree_sha=_TREE_SHA,
        duration_ms=300,
        evidence=evidence,
        operation_results=operations,
        assertion_results=assertions,
    )


@pytest.fixture
def validation_harness(
    tmp_path: Path,
) -> Iterator[tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID]]:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'validation.sqlite3'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    store = ArtifactStore(tmp_path / "artifacts")
    task_id, configuration_id, contract_id = _seed(factory)
    try:
        yield factory, store, task_id, configuration_id, contract_id
    finally:
        engine.dispose()


def test_collects_typed_direct_evidence_and_projects_each_criterion(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    factory, store, task_id, configuration_id, contract_id = validation_harness
    collection = _collection(
        task_id,
        configuration_id,
        contract_id,
        configuration_digest=_CONFIGURATION_DIGEST,
    )
    service = ValidationEvidenceService(
        factory,
        store,
        clock=lambda: _NOW,
        configuration_digest=lambda _configuration: _CONFIGURATION_DIGEST,
    )

    result = service.collect(collection)

    assert result.replayed is False
    assert result.contract_version == 4
    assert result.commit_sha == _COMMIT_SHA
    assert result.tree_sha == _TREE_SHA
    assert len(result.evidence_ids) == len(ValidationEvidenceType) + 1
    statuses = {
        value["criterion_id"]: value["status"] for value in result.criterion_results
    }
    assert statuses == {
        "criterion.network": "BLOCKED",
        "criterion.ui": "PASSED",
    }

    with factory() as session:
        run = session.get(ValidationRun, result.validation_run_id)
        assert run is not None
        assert run.outcome is ValidationOutcome.PENDING
        assert run.log_evidence_id is not None
        assert run.simulator_target == {
            "device_id": "SIMULATOR-1",
            "device_type_identifier": "com.apple.iPhone-16-Pro",
            "runtime_identifier": "com.apple.iOS-18-5",
            "locale_identifier": "en_US_POSIX",
            "time_zone_identifier": "UTC",
        }
        assert session.scalar(
            select(func.count(EvidenceRecord.id)).where(
                EvidenceRecord.validation_run_id == run.id
            )
        ) == len(ValidationEvidenceType) + 1
        assert session.scalar(
            select(func.count(TaskEvent.id)).where(
                TaskEvent.task_id == task_id,
                TaskEvent.event_type == "VALIDATION_EVIDENCE_COLLECTED",
            )
        ) == 1
        task = session.get(Task, task_id)
        assert task is not None
        brief = session.get(Brief, task.accepted_brief_id)
        contract = session.get(ValidationContract, contract_id)
        assert brief is not None
        assert contract is not None
        cockpit = _acceptance_criteria_response(brief, run, contract)
        assert [criterion.status for criterion in cockpit] == ["PASSED", "BLOCKED"]
        assert all(criterion.validation_contract_version == 4 for criterion in cockpit)
        assert all(criterion.commit_sha == _COMMIT_SHA for criterion in cockpit)
        assert all(criterion.tree_sha == _TREE_SHA for criterion in cockpit)
        assert all(criterion.evidence_ids for criterion in cockpit)
        assert all(criterion.assertions for criterion in cockpit)


def test_rejects_mismatched_host_head_without_partial_records(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    factory, store, task_id, configuration_id, contract_id = validation_harness
    collection = _collection(
        task_id,
        configuration_id,
        contract_id,
        head_sha="e" * 40,
        configuration_digest=_CONFIGURATION_DIGEST,
    )
    service = ValidationEvidenceService(
        factory,
        store,
        clock=lambda: _NOW,
        configuration_digest=lambda _configuration: _CONFIGURATION_DIGEST,
    )

    with pytest.raises(ValidationEvidenceError, match="OPERATION_BINDING_MISMATCH"):
        service.collect(collection)

    with factory() as session:
        assert session.scalar(select(func.count(ValidationRun.id))) == 0
        assert session.scalar(select(func.count(EvidenceRecord.id))) == 0


def test_rejects_digest_that_differs_from_authoritative_configuration(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    factory, store, task_id, configuration_id, contract_id = validation_harness
    collection = _collection(
        task_id,
        configuration_id,
        contract_id,
        configuration_digest=_CONFIGURATION_DIGEST,
    )
    service = ValidationEvidenceService(
        factory,
        store,
        clock=lambda: _NOW,
        configuration_digest=lambda _configuration: f"sha256:{'d' * 64}",
    )

    with pytest.raises(ValidationEvidenceError, match="OPERATION_BINDING_MISMATCH"):
        service.collect(collection)

    with factory() as session:
        assert session.scalar(select(func.count(ValidationRun.id))) == 0
        assert session.scalar(select(func.count(EvidenceRecord.id))) == 0


def test_same_run_id_replays_without_duplicate_evidence(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    factory, store, task_id, configuration_id, contract_id = validation_harness
    collection = _collection(
        task_id,
        configuration_id,
        contract_id,
        configuration_digest=_CONFIGURATION_DIGEST,
    )
    service = ValidationEvidenceService(
        factory,
        store,
        clock=lambda: _NOW,
        configuration_digest=lambda _configuration: _CONFIGURATION_DIGEST,
    )

    first = service.collect(collection)
    replay = service.collect(collection)

    assert first.validation_run_id == replay.validation_run_id
    assert replay.replayed is True
    with factory() as session:
        assert session.scalar(select(func.count(ValidationRun.id))) == 1
        assert session.scalar(
            select(func.count(EvidenceRecord.id)).where(
                EvidenceRecord.validation_run_id == first.validation_run_id
            )
        ) == len(ValidationEvidenceType) + 1


def test_same_run_id_rejects_changed_evidence_metadata(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    factory, store, task_id, configuration_id, contract_id = validation_harness
    collection = _collection(
        task_id,
        configuration_id,
        contract_id,
        configuration_digest=_CONFIGURATION_DIGEST,
    )
    service = ValidationEvidenceService(
        factory,
        store,
        clock=lambda: _NOW,
        configuration_digest=lambda _configuration: _CONFIGURATION_DIGEST,
    )
    service.collect(collection)
    changed_item = replace(
        collection.evidence[0],
        content_address=f"sha256:{'f' * 64}",
    )
    changed = replace(
        collection,
        evidence=(changed_item, *collection.evidence[1:]),
    )

    with pytest.raises(ValidationEvidenceError, match="VALIDATION_RUN_ID_CONFLICT"):
        service.collect(changed)
