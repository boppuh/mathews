from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
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


def _accept_artifact(_item: ValidationEvidenceItem) -> None:
    pass


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
            operations=[
                {"operation_id": "unit-tests", "kind": "UNIT_TEST"},
                {"operation_id": "integration-tests", "kind": "INTEGRATION_TEST"},
                {"operation_id": "simulator-e2e", "kind": "SIMULATOR_E2E"},
            ],
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

    verified_artifacts: list[UUID] = []
    result = service.collect(
        collection,
        artifact_verifier=lambda item: verified_artifacts.append(item.evidence_id),
    )

    assert result.replayed is False
    assert result.contract_version == 4
    assert result.commit_sha == _COMMIT_SHA
    assert result.tree_sha == _TREE_SHA
    assert len(result.evidence_ids) == len(ValidationEvidenceType) + 1
    assert verified_artifacts == [item.evidence_id for item in collection.evidence]
    assert ValidationEvidenceCollection.from_dict(collection.to_dict()) == collection
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
        service.collect(collection, artifact_verifier=_accept_artifact)

    with factory() as session:
        assert session.scalar(select(func.count(ValidationRun.id))) == 0
        assert session.scalar(select(func.count(EvidenceRecord.id))) == 0


def test_rejects_unverified_host_artifact_without_partial_records(
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

    def reject_artifact(_item: ValidationEvidenceItem) -> None:
        raise ValidationEvidenceError("HOST_ARTIFACT_UNVERIFIED")

    with pytest.raises(ValidationEvidenceError, match="HOST_ARTIFACT_UNVERIFIED"):
        service.collect(collection, artifact_verifier=reject_artifact)

    with factory() as session:
        assert session.scalar(select(func.count(ValidationRun.id))) == 0
        assert session.scalar(select(func.count(EvidenceRecord.id))) == 0


def test_rejects_contradictory_pass_and_unknown_evidence_reference(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    _factory, _store, task_id, configuration_id, contract_id = validation_harness
    collection = _collection(
        task_id,
        configuration_id,
        contract_id,
        configuration_digest=_CONFIGURATION_DIGEST,
    )
    with pytest.raises(
        ValidationEvidenceError,
        match="OPERATION_PASS_RESULT_CONTRADICTORY",
    ):
        replace(collection.operation_results[0], exit_status=1)
    changed_assertion = replace(
        collection.assertion_results[0],
        evidence_keys=("evidence.missing",),
    )
    with pytest.raises(ValidationEvidenceError, match="EVIDENCE_REFERENCE_UNKNOWN"):
        replace(
            collection,
            assertion_results=(changed_assertion, *collection.assertion_results[1:]),
        )


def test_rejects_operation_kind_and_simulator_lineage_mismatches(
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
    wrong_kind = replace(
        collection.operation_results[0],
        operation_kind=OperationKind.BUILD,
    )
    with pytest.raises(ValidationEvidenceError, match="OPERATION_BINDING_MISMATCH"):
        service.collect(
            replace(
                collection,
                operation_results=(wrong_kind, *collection.operation_results[1:]),
            ),
            artifact_verifier=_accept_artifact,
        )
    e2e = collection.operation_results[2]
    assert e2e.simulator_target is not None
    wrong_target = replace(
        e2e,
        simulator_target={
            **e2e.simulator_target,
            "runtime_identifier": "com.apple.iOS-17-0",
        },
    )
    with pytest.raises(ValidationEvidenceError, match="SIMULATOR_BINDING_MISMATCH"):
        service.collect(
            replace(
                collection,
                operation_results=(*collection.operation_results[:2], wrong_target),
            ),
            artifact_verifier=_accept_artifact,
        )
    with pytest.raises(
        ValidationEvidenceError,
        match="OPERATION_SIMULATOR_TARGET_UNEXPECTED",
    ):
        replace(
            collection.operation_results[0],
            simulator_target=e2e.simulator_target,
        )


def test_rejects_ambiguous_simulator_targets(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    factory, store, task_id, configuration_id, contract_id = validation_harness
    collection = _collection(
        task_id,
        configuration_id,
        contract_id,
        configuration_digest=_CONFIGURATION_DIGEST,
    )
    second_e2e = replace(
        collection.operation_results[2],
        operation_id="simulator-e2e-secondary",
    )
    with factory.begin() as session:
        configuration = session.get(RepositoryConfiguration, configuration_id)
        contract = session.get(ValidationContract, contract_id)
        assert configuration is not None
        assert contract is not None
        configuration.operations = [
            *configuration.operations,
            {
                "operation_id": "simulator-e2e-secondary",
                "kind": "SIMULATOR_E2E",
            },
        ]
        contract.required_operations = [
            *contract.required_operations,
            {"operation_id": "simulator-e2e-secondary"},
        ]
    service = ValidationEvidenceService(
        factory,
        store,
        clock=lambda: _NOW,
        configuration_digest=lambda _configuration: _CONFIGURATION_DIGEST,
    )

    with pytest.raises(ValidationEvidenceError, match="SIMULATOR_TARGET_AMBIGUOUS"):
        service.collect(
            replace(
                collection,
                operation_results=(*collection.operation_results, second_e2e),
            ),
            artifact_verifier=_accept_artifact,
        )


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
        service.collect(collection, artifact_verifier=_accept_artifact)

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

    first = service.collect(collection, artifact_verifier=_accept_artifact)
    replay = service.collect(collection, artifact_verifier=_accept_artifact)

    assert first.validation_run_id == replay.validation_run_id
    assert replay.replayed is True
    with factory() as session:
        assert session.scalar(select(func.count(ValidationRun.id))) == 1
        assert session.scalar(
            select(func.count(EvidenceRecord.id)).where(
                EvidenceRecord.validation_run_id == first.validation_run_id
            )
        ) == len(ValidationEvidenceType) + 1


def test_replay_ignores_later_evidence_correction_records(
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
    first = service.collect(collection, artifact_verifier=_accept_artifact)
    with factory.begin() as session:
        original = session.get(EvidenceRecord, collection.evidence[0].evidence_id)
        assert original is not None
        session.add(
            EvidenceRecord(
                task_id=original.task_id,
                validation_run_id=original.validation_run_id,
                evidence_type=original.evidence_type,
                origin="local-user:correction",
                content_hash=f"sha256:{'e' * 64}",
                content_address=f"sha256:{'e' * 64}",
                captured_at=_NOW + timedelta(seconds=1),
                access_classification=original.access_classification,
                retention_policy=original.retention_policy,
                correction_of_id=original.id,
                owner_id=original.owner_id,
                actor_id="local-user",
                root_correlation_id=original.root_correlation_id,
                causation_id=original.id,
                parent_correlation_id=original.root_correlation_id,
                created_at=_NOW + timedelta(seconds=1),
                updated_at=_NOW + timedelta(seconds=1),
            )
        )
    replay = service.collect(collection, artifact_verifier=_accept_artifact)

    assert replay.validation_run_id == first.validation_run_id
    assert replay.replayed is True


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
    service.collect(collection, artifact_verifier=_accept_artifact)
    changed_item = replace(
        collection.evidence[0],
        content_address=f"sha256:{'f' * 64}",
    )
    changed = replace(
        collection,
        evidence=(changed_item, *collection.evidence[1:]),
    )

    with pytest.raises(ValidationEvidenceError, match="VALIDATION_RUN_ID_CONFLICT"):
        service.collect(changed, artifact_verifier=_accept_artifact)
