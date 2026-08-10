from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from uuid import UUID, uuid4

import mathews_control_plane.repair_loop as repair_loop_module
import mathews_control_plane.validation_evidence as validation_evidence_module
import pytest
from mathews_configuration import (
    AssertionKind,
    HostRequestMessage,
    HostResponseMessage,
    HostResponseStatus,
    OperationKind,
    TaskLeaseHostAuthority,
)
from mathews_control_plane.approvals import ApprovalConflictError, ApprovalService
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.background_jobs import (
    BackgroundJobConflictError,
    BackgroundJobLeaseLostError,
    BackgroundJobService,
    JobLeaseGrant,
    LeasedJobContext,
    PausedBackgroundJobError,
    TerminalBackgroundJobError,
)
from mathews_control_plane.database import (
    Base,
    SessionFactory,
    create_database_engine,
    create_session_factory,
)
from mathews_control_plane.domain_models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    BackgroundJob,
    Brief,
    BriefApprovalDecision,
    BriefDecisionDisposition,
    EvidenceRecord,
    PolicyVersion,
    PolicyVersionPromptTemplate,
    PromptTemplateVersion,
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
from mathews_control_plane.repair_loop import (
    VALIDATION_REPAIR_JOB_TYPE,
    VALIDATION_RERUN_REQUESTED_EVENT_TYPE,
    RepairJobHandler,
    RepairLoopError,
    RepairScheduleResult,
    RepairScheduleStatus,
    ValidationRepairService,
)
from mathews_control_plane.tasks import _acceptance_criteria_response
from mathews_control_plane.validation_decisioning import (
    VALIDATION_DECIDED_EVENT_TYPE,
    ValidationDecisionResult,
    ValidationDecisionService,
)
from mathews_control_plane.validation_evidence import (
    LEGACY_VALIDATION_EVIDENCE_JOB_TYPE,
    VALIDATION_EVIDENCE_JOB_TYPE,
    AssertionResultStatus,
    TypedAssertionResult,
    ValidationEvidenceCollection,
    ValidationEvidenceError,
    ValidationEvidenceItem,
    ValidationEvidenceJobHandler,
    ValidationEvidenceJobScheduler,
    ValidationEvidenceResult,
    ValidationEvidenceService,
    ValidationEvidenceType,
    ValidationOperationResult,
)
from sqlalchemy import func, select

_NOW = datetime(2026, 8, 10, 12, tzinfo=UTC)
_COMMIT_SHA = "a" * 40
_TREE_SHA = "b" * 40
_CONFIGURATION_DIGEST = f"sha256:{'c' * 64}"
_VALIDATION_ATTEMPT_ID = UUID("77777777-7777-4777-8777-777777777777")


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
        policy = PolicyVersion(
            lineage_key="mvp",
            version=1,
            workflow_thresholds={},
            approved_by="local-user",
            approved_at=_NOW,
            **_context(root_id),
        )
        session.add(policy)
        session.flush()
        prompt = PromptTemplateVersion(
            lineage_key="mvp-implementer",
            role="implementer",
            version=1,
            predecessor_id=None,
            structured_template={
                "schema_version": 1,
                "role": "implementer",
                "instructions": [
                    "Repair only the cited validation failure within the accepted scope.",
                    "Use the smallest change and leave validation decisions to the control plane.",
                ],
                "evidence_limit": 4,
                "max_prompt_characters": 16000,
            },
            evaluation_threshold_passed=True,
            regression_reviewed=True,
            promoted=True,
            approved_by="local-user",
            approved_at=_NOW,
            **_context(root_id),
        )
        session.add(prompt)
        session.flush()
        session.add(
            PolicyVersionPromptTemplate(
                policy_version_id=policy.id,
                prompt_template_version_id=prompt.id,
                prompt_promoted=True,
                position=1,
                **_context(root_id),
            )
        )
        session.add(
            TaskEvent(
                task_id=task.id,
                sequence=1,
                event_type="TASK_STATE_TRANSITION",
                payload={
                    "schema_version": 1,
                    "kind": "BEGIN_VALIDATION",
                    "validation_candidate": {
                        "commit_sha": _COMMIT_SHA,
                        "tree_sha": _TREE_SHA,
                    },
                },
                occurred_at=_NOW,
                transition_id=_VALIDATION_ATTEMPT_ID,
                transition_fingerprint="f" * 64,
                transition_kind="BEGIN_VALIDATION",
                transition_from_state=TaskState.IMPLEMENTING,
                transition_to_state=TaskState.VALIDATING,
                transition_reason_code="BEGIN_VALIDATION",
                policy_lineage_key=policy.lineage_key,
                policy_version_id=policy.id,
                **_context(root_id),
            )
        )
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
        validation_attempt_id=_VALIDATION_ATTEMPT_ID,
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


def _with_final_assertion_status(
    collection: ValidationEvidenceCollection,
    assertion_status: AssertionResultStatus,
) -> ValidationEvidenceCollection:
    final = collection.assertion_results[-1]
    return replace(
        collection,
        assertion_results=(
            *collection.assertion_results[:-1],
            replace(
                final,
                status=assertion_status,
                result_code=f"NETWORK_ASSERTION_{assertion_status.value}",
            ),
        ),
    )


def _collect_for_decision(
    factory: SessionFactory,
    store: ArtifactStore,
    task_id: UUID,
    configuration_id: UUID,
    contract_id: UUID,
    *,
    assertion_status: AssertionResultStatus,
) -> ValidationEvidenceResult:
    collection = _with_final_assertion_status(
        _collection(
            task_id,
            configuration_id,
            contract_id,
            configuration_digest=_CONFIGURATION_DIGEST,
        ),
        assertion_status,
    )
    return ValidationEvidenceService(
        factory,
        store,
        clock=lambda: _NOW,
        configuration_digest=lambda _configuration: _CONFIGURATION_DIGEST,
    ).collect(collection, artifact_verifier=_accept_artifact)


def test_decides_pass_once_and_queries_the_exact_candidate(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    factory, store, task_id, configuration_id, contract_id = validation_harness
    collected = _collect_for_decision(
        factory,
        store,
        task_id,
        configuration_id,
        contract_id,
        assertion_status=AssertionResultStatus.PASSED,
    )
    service = ValidationDecisionService(factory, store, clock=lambda: _NOW)

    decided = service.decide(collected.validation_run_id)
    replayed = service.decide(collected.validation_run_id)
    exact = service.get_exact(
        task_id,
        commit_sha=_COMMIT_SHA,
        tree_sha=_TREE_SHA,
    )

    assert decided.outcome is ValidationOutcome.PASSED
    assert decided.reason_code == "ALL_REQUIRED_VALIDATION_PASSED"
    assert decided.is_current is True
    assert decided.replayed is False
    assert replayed.decision_evidence_id == decided.decision_evidence_id
    assert replayed.replayed is True
    assert exact.validation_run_id == decided.validation_run_id
    assert exact.is_current is True
    assert exact.replayed is False
    with factory() as session:
        run = session.get(ValidationRun, collected.validation_run_id)
        assert run is not None
        assert run.outcome is ValidationOutcome.PASSED
        events = tuple(
            session.scalars(
                select(TaskEvent).where(
                    TaskEvent.task_id == task_id,
                    TaskEvent.event_type == VALIDATION_DECIDED_EVENT_TYPE,
                )
            )
        )
        assert len(events) == 1
        assert (
            session.scalar(
                select(func.count(TaskEventEvidenceReference.id)).where(
                    TaskEventEvidenceReference.task_event_id == events[0].id
                )
            )
            == 1
        )


@pytest.mark.parametrize(
    ("assertion_status", "expected_outcome", "expected_reason"),
    (
        (
            AssertionResultStatus.FAILED,
            ValidationOutcome.FAILED,
            "REQUIRED_VALIDATION_FAILED",
        ),
        (
            AssertionResultStatus.BLOCKED,
            ValidationOutcome.ESCALATED,
            "VALIDATION_REQUIRES_DECISION",
        ),
    ),
)
def test_decides_failure_and_escalation_from_stored_results(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
    assertion_status: AssertionResultStatus,
    expected_outcome: ValidationOutcome,
    expected_reason: str,
) -> None:
    factory, store, task_id, configuration_id, contract_id = validation_harness
    collected = _collect_for_decision(
        factory,
        store,
        task_id,
        configuration_id,
        contract_id,
        assertion_status=assertion_status,
    )

    decided = ValidationDecisionService(factory, store, clock=lambda: _NOW).decide(
        collected.validation_run_id
    )

    assert decided.outcome is expected_outcome
    assert decided.reason_code == expected_reason


def test_missing_required_evidence_escalates_instead_of_passing(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    factory, store, task_id, configuration_id, contract_id = validation_harness
    collected = _collect_for_decision(
        factory,
        store,
        task_id,
        configuration_id,
        contract_id,
        assertion_status=AssertionResultStatus.PASSED,
    )
    with factory() as session:
        record = session.scalar(
            select(EvidenceRecord).where(
                EvidenceRecord.validation_run_id == collected.validation_run_id,
                EvidenceRecord.evidence_type == "validation-unit-test-output",
            )
        )
        assert record is not None
        address = record.content_address
        assert address is not None
    assert store.delete_bytes(address) is True

    decided = ValidationDecisionService(factory, store, clock=lambda: _NOW).decide(
        collected.validation_run_id
    )

    assert decided.outcome is ValidationOutcome.ESCALATED
    assert decided.reason_code == "EVIDENCE_UNAVAILABLE"


def test_candidate_change_invalidates_a_pending_pass_decision(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    factory, store, task_id, configuration_id, contract_id = validation_harness
    collected = _collect_for_decision(
        factory,
        store,
        task_id,
        configuration_id,
        contract_id,
        assertion_status=AssertionResultStatus.PASSED,
    )
    with factory.begin() as session:
        attempt = session.scalar(
            select(TaskEvent).where(
                TaskEvent.task_id == task_id,
                TaskEvent.transition_id == _VALIDATION_ATTEMPT_ID,
            )
        )
        assert attempt is not None
        attempt.payload = {
            **attempt.payload,
            "validation_candidate": {
                "commit_sha": "e" * 40,
                "tree_sha": "f" * 40,
            },
        }

    service = ValidationDecisionService(factory, store, clock=lambda: _NOW)
    decided = service.decide(collected.validation_run_id)
    exact = service.get_exact(
        task_id,
        commit_sha=_COMMIT_SHA,
        tree_sha=_TREE_SHA,
    )

    assert decided.outcome is ValidationOutcome.BLOCKED
    assert decided.reason_code == "VALIDATION_BINDING_STALE"
    assert exact.is_current is False


def test_failed_decision_schedules_one_evidence_backed_repair_job(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    factory, store, task_id, configuration_id, contract_id = validation_harness
    collected = _collect_for_decision(
        factory,
        store,
        task_id,
        configuration_id,
        contract_id,
        assertion_status=AssertionResultStatus.FAILED,
    )
    ValidationDecisionService(factory, store, clock=lambda: _NOW).decide(
        collected.validation_run_id
    )
    service = ValidationRepairService(factory, store, clock=lambda: _NOW)

    scheduled = service.schedule(collected.validation_run_id)
    replayed = service.schedule(collected.validation_run_id)

    assert scheduled.status is RepairScheduleStatus.SCHEDULED
    assert scheduled.job_id is not None
    assert scheduled.replayed is False
    assert replayed.job_id == scheduled.job_id
    assert replayed.replayed is True
    with factory() as session:
        task = session.get(Task, task_id)
        job = session.get(BackgroundJob, scheduled.job_id)
        assert task is not None
        assert task.state is TaskState.VALIDATING
        assert task.retry_count == 0
        assert job is not None
        assert job.job_type == VALIDATION_REPAIR_JOB_TYPE
        assert job.input_payload["validation_run_id"] == str(collected.validation_run_id)
        prompt = cast(dict[str, object], job.input_payload["prompt"])
        content = json.loads(cast(str, prompt["content"]))
        assert content["role"] == "implementer"
        assert len(content["verified_evidence"]) == 2


def test_repair_budget_exhaustion_creates_resumable_retry_decision(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    factory, store, task_id, configuration_id, contract_id = validation_harness
    collected = _collect_for_decision(
        factory,
        store,
        task_id,
        configuration_id,
        contract_id,
        assertion_status=AssertionResultStatus.FAILED,
    )
    ValidationDecisionService(factory, store, clock=lambda: _NOW).decide(
        collected.validation_run_id
    )
    with factory.begin() as session:
        task = session.get(Task, task_id)
        assert task is not None
        task.retry_count = 2

    result = ValidationRepairService(factory, store, clock=lambda: _NOW).schedule(
        collected.validation_run_id
    )

    assert result.status is RepairScheduleStatus.ESCALATED
    assert result.approval_request_id is not None
    with factory() as session:
        task = session.get(Task, task_id)
        request = session.get(ApprovalRequest, result.approval_request_id)
        assert task is not None
        assert task.state is TaskState.ESCALATED
        assert task.escalation_resume_state is TaskState.VALIDATING
        assert request is not None
        assert request.status is ApprovalStatus.PENDING
        assert request.reason == "REPAIR_BUDGET_EXHAUSTED"
        assert request.options == ["RETRY", "ABANDON", "CANCEL"]
        retry = cast(dict[str, object], request.retry_history[0])
        assert retry["error_code"] == "REPAIR_BUDGET_EXHAUSTED"

    retry_decision_id = uuid4()
    resumed = ApprovalService(factory, store, clock=lambda: _NOW).decide(
        result.approval_request_id,
        decision_id=retry_decision_id,
        decision=ApprovalDecision.RETRY,
        actor_id="local-user",
    )
    scheduled = ValidationRepairService(factory, store, clock=lambda: _NOW).schedule(
        collected.validation_run_id
    )

    assert resumed.task_state is TaskState.VALIDATING
    assert scheduled.status is RepairScheduleStatus.SCHEDULED
    assert scheduled.job_id is not None
    with factory() as session:
        job = session.get(BackgroundJob, scheduled.job_id)
        assert job is not None
        assert job.input_payload["retry_approval_decision_id"] == str(
            retry_decision_id
        )

    jobs = BackgroundJobService(factory, store, clock=lambda: _NOW)
    grant = jobs.claim_next(
        worker_id="approved-repair-worker",
        lease_duration=timedelta(seconds=30),
        job_types=(VALIDATION_REPAIR_JOB_TYPE,),
    )
    assert grant is not None

    class ApprovedRetryHermes:
        def __call__(
            self,
            context: LeasedJobContext,
        ) -> Mapping[str, object] | None:
            del context
            raise TerminalBackgroundJobError("APPROVED_RETRY_TEST_STOP")

    class UnusedHost:
        def execute(self, _request: HostRequestMessage) -> HostResponseMessage:
            raise AssertionError("the test stops before the Git boundary")

    with pytest.raises(TerminalBackgroundJobError, match="APPROVED_RETRY_TEST_STOP"):
        RepairJobHandler(
            factory,
            store,
            UnusedHost(),
            ApprovedRetryHermes(),
            clock=lambda: _NOW,
        )(LeasedJobContext(jobs, grant))
    with factory() as session:
        task = session.get(Task, task_id)
        assert task is not None
        assert task.retry_count == 3
        assert task.state is TaskState.FAILED


def test_consumed_retry_decision_does_not_authorize_an_equivalent_failure(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    factory, store, task_id, configuration_id, contract_id = validation_harness
    first_run = _collect_for_decision(
        factory,
        store,
        task_id,
        configuration_id,
        contract_id,
        assertion_status=AssertionResultStatus.FAILED,
    )
    ValidationDecisionService(factory, store, clock=lambda: _NOW).decide(
        first_run.validation_run_id
    )
    with factory.begin() as session:
        task = session.get(Task, task_id)
        assert task is not None
        task.retry_count = 2

    service = ValidationRepairService(factory, store, clock=lambda: _NOW)
    first_escalation = service.schedule(first_run.validation_run_id)
    assert first_escalation.approval_request_id is not None
    retry_decision_id = uuid4()
    ApprovalService(factory, store, clock=lambda: _NOW).decide(
        first_escalation.approval_request_id,
        decision_id=retry_decision_id,
        decision=ApprovalDecision.RETRY,
        actor_id="local-user",
    )
    approved_retry = service.schedule(first_run.validation_run_id)
    assert approved_retry.job_id is not None

    next_run = _collect_for_decision(
        factory,
        store,
        task_id,
        configuration_id,
        contract_id,
        assertion_status=AssertionResultStatus.FAILED,
    )
    ValidationDecisionService(factory, store, clock=lambda: _NOW).decide(
        next_run.validation_run_id
    )
    next_escalation = service.schedule(next_run.validation_run_id)

    assert next_escalation.status is RepairScheduleStatus.ESCALATED
    assert next_escalation.approval_request_id is not None
    assert next_escalation.approval_request_id != first_escalation.approval_request_id
    with factory() as session:
        repair_jobs = tuple(
            session.scalars(
                select(BackgroundJob).where(
                    BackgroundJob.task_id == task_id,
                    BackgroundJob.job_type == VALIDATION_REPAIR_JOB_TYPE,
                )
            )
        )
        assert len(repair_jobs) == 1
        assert repair_jobs[0].input_payload["retry_approval_decision_id"] == str(
            retry_decision_id
        )


def test_equivalent_failure_escalates_instead_of_looping(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    factory, store, task_id, configuration_id, contract_id = validation_harness
    collected = _collect_for_decision(
        factory,
        store,
        task_id,
        configuration_id,
        contract_id,
        assertion_status=AssertionResultStatus.FAILED,
    )
    ValidationDecisionService(factory, store, clock=lambda: _NOW).decide(
        collected.validation_run_id
    )
    service = ValidationRepairService(factory, store, clock=lambda: _NOW)
    first = service.schedule(collected.validation_run_id)
    assert first.job_id is not None
    with factory.begin() as session:
        prior = session.get(BackgroundJob, first.job_id)
        assert prior is not None
        prior_decision_id = UUID(cast(str, prior.input_payload["decision_evidence_id"]))
        prior_manifest_id = UUID(cast(str, prior.input_payload["manifest_evidence_id"]))
        checkpoint = session.scalar(
            select(EvidenceRecord)
            .where(
                EvidenceRecord.task_id == task_id,
                EvidenceRecord.id.not_in((prior_decision_id, prior_manifest_id)),
            )
            .order_by(EvidenceRecord.created_at, EvidenceRecord.id)
            .limit(1)
        )
        assert checkpoint is not None
        prior.input_payload = {
            **prior.input_payload,
            "validation_run_id": str(uuid4()),
            "decision_evidence_id": str(checkpoint.id),
        }

    repeated = service.schedule(collected.validation_run_id)

    assert repeated.status is RepairScheduleStatus.ESCALATED
    assert repeated.approval_request_id is not None
    with factory() as session:
        request = session.get(ApprovalRequest, repeated.approval_request_id)
        task = session.get(Task, task_id)
        assert request is not None
        assert request.reason == "EQUIVALENT_VALIDATION_FAILURE"
        assert str(checkpoint.id) in request.supporting_evidence_ids
        assert task is not None
        assert task.state is TaskState.ESCALATED
        assert task.escalation_resume_state is TaskState.VALIDATING


@pytest.mark.parametrize(
    ("error", "expected_status", "expected_reason"),
    (
        (RepairLoopError("REPAIR_CONTEXT_STALE"), "UNSCHEDULED", "REPAIR_CONTEXT_STALE"),
        (
            ApprovalConflictError("pending approval"),
            "ESCALATED",
            "REPAIR_APPROVAL_CONFLICT",
        ),
        (
            BackgroundJobConflictError("job conflict"),
            "UNSCHEDULED",
            "REPAIR_JOB_CONFLICT",
        ),
    ),
)
def test_repair_scheduling_failure_preserves_the_validation_checkpoint(
    error: Exception,
    expected_status: str,
    expected_reason: str,
) -> None:
    decision = cast(ValidationDecisionResult, SimpleNamespace())

    class FailingScheduler:
        def schedule(
            self,
            validation_run_id: UUID,
            *,
            decision: ValidationDecisionResult | None = None,
        ) -> RepairScheduleResult:
            assert validation_run_id == _VALIDATION_ATTEMPT_ID
            assert decision is not None
            raise error

    checkpoint = validation_evidence_module._repair_schedule_checkpoint(
        FailingScheduler(),
        _VALIDATION_ATTEMPT_ID,
        decision,
    )

    assert checkpoint == {
        "repair_status": expected_status,
        "repair_reason_code": expected_reason,
    }


def test_repair_evidence_replay_compares_redacted_canonical_content(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    factory, store, task_id, _configuration_id, _contract_id = validation_harness
    payload = {"password": "sensitive", "status": "recorded"}
    with factory.begin() as session:
        captured = capture_evidence(
            session,
            store,
            payload=payload,
            media_type="application/json",
            source_kind=EvidenceSourceKind.RESULT,
            evidence_type="validation-repair-test",
            origin="test:repair-loop",
            access_classification=EvidenceAccessClass.INTERNAL,
            retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
            owner_id="local-user",
            actor_id="control-plane",
            root_correlation_id=uuid4(),
            task_id=task_id,
            captured_at=_NOW,
        )
        record_id = captured.record.id

    with factory() as session:
        record = session.get(EvidenceRecord, record_id)
        assert record is not None
        repair_loop_module._require_evidence_payload(
            session,
            store,
            record,
            payload,
            task_id=task_id,
            evidence_type="validation-repair-test",
        )


def test_repair_job_commits_new_candidate_and_requests_the_complete_contract(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory, store, task_id, configuration_id, contract_id = validation_harness
    collected = _collect_for_decision(
        factory,
        store,
        task_id,
        configuration_id,
        contract_id,
        assertion_status=AssertionResultStatus.FAILED,
    )
    ValidationDecisionService(factory, store, clock=lambda: _NOW).decide(
        collected.validation_run_id
    )
    scheduled = ValidationRepairService(factory, store, clock=lambda: _NOW).schedule(
        collected.validation_run_id
    )
    assert scheduled.job_id is not None
    jobs = BackgroundJobService(factory, store, clock=lambda: _NOW)
    grant = jobs.claim_next(
        worker_id="repair-worker",
        lease_duration=timedelta(seconds=30),
        job_types=(VALIDATION_REPAIR_JOB_TYPE,),
    )
    assert grant is not None
    fencing_token = grant.fencing_token

    class ValidatedConfiguration:
        repository_key = "boppuh/mathews"
        digest = _CONFIGURATION_DIGEST

        def __init__(self, bound_configuration_id: UUID) -> None:
            self.configuration_id = bound_configuration_id

        @staticmethod
        def to_dict() -> dict[str, object]:
            return {"repository_key": "boppuh/mathews"}

    monkeypatch.setattr(
        repair_loop_module,
        "validated_repository_configuration",
        lambda _configuration: ValidatedConfiguration(configuration_id),
    )

    class SuccessfulHermes:
        def __call__(
            self,
            context: LeasedJobContext,
        ) -> Mapping[str, object] | None:
            del context
            return {"hermes_run_id": str(uuid4()), "status": "SUCCEEDED"}

    class SuccessfulHost:
        def execute(self, request: HostRequestMessage) -> HostResponseMessage:
            assert request.operation.name == "git.commit"
            assert request.operation.arguments["expected_head_sha"] == _COMMIT_SHA
            return HostResponseMessage(
                request_id=request.request_id,
                operation_name=request.operation.name,
                idempotency_key=request.operation.idempotency_key,
                host_id="host-1",
                host_version="0.1.0",
                status=HostResponseStatus.OK,
                code="OK",
                replayed=False,
                completed_at_ms=1_800_000_000_000,
                execution_fencing_token=fencing_token,
                result={
                    "committed": True,
                    "clean": True,
                    "head_sha": "c" * 40,
                    "tree_sha": "d" * 40,
                    "changed_paths": ["Sources/Feature.swift"],
                },
            )

    checkpoint = RepairJobHandler(
        factory,
        store,
        SuccessfulHost(),
        SuccessfulHermes(),
        clock=lambda: _NOW,
    )(LeasedJobContext(jobs, grant))

    assert checkpoint["status"] == "REVALIDATION_REQUESTED"
    assert checkpoint["candidate_commit_sha"] == "c" * 40
    assert checkpoint["candidate_tree_sha"] == "d" * 40
    with factory() as session:
        task = session.get(Task, task_id)
        assert task is not None
        assert task.state is TaskState.VALIDATING
        assert task.retry_count == 1
        transitions = tuple(
            session.scalars(
                select(TaskEvent)
                .where(
                    TaskEvent.task_id == task_id,
                    TaskEvent.transition_kind.in_(("BEGIN_REPAIR", "REVALIDATE")),
                )
                .order_by(TaskEvent.sequence)
            )
        )
        assert [event.transition_kind for event in transitions] == [
            "BEGIN_REPAIR",
            "REVALIDATE",
        ]
        assert transitions[-1].payload["validation_candidate"] == {
            "commit_sha": "c" * 40,
            "tree_sha": "d" * 40,
        }
        rerun = session.scalar(
            select(TaskEvent).where(
                TaskEvent.task_id == task_id,
                TaskEvent.event_type == VALIDATION_RERUN_REQUESTED_EVENT_TYPE,
            )
        )
        assert rerun is not None
        assert rerun.payload["required_operations"] == [
            {"operation_id": "unit-tests"},
            {"operation_id": "integration-tests"},
            {"operation_id": "simulator-e2e"},
        ]
        assert len(cast(list[object], rerun.payload["typed_assertions"])) == 3
        assert len(cast(list[object], rerun.payload["evidence_requirements"])) == len(
            ValidationEvidenceType
        )


def test_unrecoverable_repair_failure_moves_task_to_explicit_failed_state(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    factory, store, task_id, configuration_id, contract_id = validation_harness
    collected = _collect_for_decision(
        factory,
        store,
        task_id,
        configuration_id,
        contract_id,
        assertion_status=AssertionResultStatus.FAILED,
    )
    ValidationDecisionService(factory, store, clock=lambda: _NOW).decide(
        collected.validation_run_id
    )
    scheduled = ValidationRepairService(factory, store, clock=lambda: _NOW).schedule(
        collected.validation_run_id
    )
    assert scheduled.job_id is not None
    jobs = BackgroundJobService(factory, store, clock=lambda: _NOW)
    grant = jobs.claim_next(
        worker_id="repair-worker",
        lease_duration=timedelta(seconds=30),
        job_types=(VALIDATION_REPAIR_JOB_TYPE,),
    )
    assert grant is not None

    class FailedHermes:
        def __call__(
            self,
            context: LeasedJobContext,
        ) -> Mapping[str, object] | None:
            del context
            raise TerminalBackgroundJobError("HERMES_RUN_FAILED")

    class UnusedHost:
        def execute(self, _request: HostRequestMessage) -> HostResponseMessage:
            raise AssertionError("terminal Hermes failure must not reach Git")

    with pytest.raises(TerminalBackgroundJobError, match="HERMES_RUN_FAILED"):
        RepairJobHandler(
            factory,
            store,
            UnusedHost(),
            FailedHermes(),
            clock=lambda: _NOW,
        )(LeasedJobContext(jobs, grant))

    with factory() as session:
        task = session.get(Task, task_id)
        assert task is not None
        assert task.state is TaskState.FAILED
        assert task.terminal_outcome == "FAILED"


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
        stored_assertions = [
            cast(Mapping[str, object], value) for value in run.assertion_results
        ]
        assert {value["assertion_id"] for value in stored_assertions} == {
            "no-crash",
            "visible-title",
            "created-response",
        }
        assert next(
            value
            for value in stored_assertions
            if value["assertion_id"] == "no-crash"
        )["result_code"] == "ZERO_CRASHES_OBSERVED"
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


def test_rejects_collection_from_stale_validation_attempt(
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

    verified: list[UUID] = []

    with pytest.raises(ValidationEvidenceError, match="VALIDATION_ATTEMPT_STALE"):
        service.collect(
            replace(collection, validation_attempt_id=uuid4()),
            artifact_verifier=lambda item: verified.append(item.evidence_id),
        )

    assert verified == []
    with factory() as session:
        assert session.scalar(select(func.count(ValidationRun.id))) == 0


def test_scheduler_binds_pre_upgrade_validation_attempt_candidate(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    factory, store, task_id, configuration_id, contract_id = validation_harness
    collection = _collection(
        task_id,
        configuration_id,
        contract_id,
        configuration_digest=_CONFIGURATION_DIGEST,
    )
    with factory.begin() as session:
        attempt = session.scalar(
            select(TaskEvent).where(TaskEvent.transition_id == _VALIDATION_ATTEMPT_ID)
        )
        assert attempt is not None
        attempt.payload = {"schema_version": 1, "kind": "BEGIN_VALIDATION"}

    ValidationEvidenceJobScheduler(factory, store, clock=lambda: _NOW).schedule(collection)

    with factory() as session:
        attempt = session.scalar(
            select(TaskEvent).where(TaskEvent.transition_id == _VALIDATION_ATTEMPT_ID)
        )
        assert attempt is not None
        assert attempt.payload["validation_candidate"] == {
            "commit_sha": collection.commit_sha,
            "tree_sha": collection.tree_sha,
        }


def test_scheduler_enqueues_one_exact_attempt_bound_collection(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    factory, store, task_id, configuration_id, contract_id = validation_harness
    collection = _collection(
        task_id,
        configuration_id,
        contract_id,
        configuration_digest=_CONFIGURATION_DIGEST,
    )
    scheduler = ValidationEvidenceJobScheduler(
        factory,
        store,
        clock=lambda: _NOW,
    )

    first = scheduler.schedule(collection)
    replay = scheduler.schedule(collection)

    assert replay == replace(first, replayed=True)
    with factory() as session:
        job = session.get(BackgroundJob, first.job_id)
        assert job is not None
        assert job.job_type == VALIDATION_EVIDENCE_JOB_TYPE
        assert job.input_payload == collection.to_dict()


def test_legacy_job_payload_resolves_current_attempt(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    factory, _store, task_id, configuration_id, contract_id = validation_harness
    collection = _collection(
        task_id,
        configuration_id,
        contract_id,
        configuration_digest=_CONFIGURATION_DIGEST,
    )
    payload = collection.to_dict()
    payload.pop("validation_attempt_id")
    grant = JobLeaseGrant(
        job_id=uuid4(),
        task_id=task_id,
        lease_id=uuid4(),
        worker_id="validation-worker",
        attempt=1,
        fencing_token=1,
        expires_at=_NOW + timedelta(seconds=30),
        job_type=LEGACY_VALIDATION_EVIDENCE_JOB_TYPE,
        input_payload=payload,
        checkpoint=None,
        checkpoint_version=0,
        recovered=False,
    )

    restored = validation_evidence_module._collection_from_job_payload(factory, grant)

    assert restored == collection


def test_handler_classifies_malformed_collection_as_terminal(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    factory, store, task_id, _configuration_id, _contract_id = validation_harness
    jobs = BackgroundJobService(factory, store, clock=lambda: _NOW)
    jobs.schedule(
        task_id=task_id,
        job_type=LEGACY_VALIDATION_EVIDENCE_JOB_TYPE,
        idempotency_key=f"validation-evidence:malformed:{uuid4()}",
        input_payload={},
    )
    grant = jobs.claim_next(
        worker_id="validation-worker",
        lease_duration=timedelta(seconds=30),
        job_types=(LEGACY_VALIDATION_EVIDENCE_JOB_TYPE,),
    )
    assert grant is not None

    class UnusedHost:
        def execute(self, _request: HostRequestMessage) -> HostResponseMessage:
            raise AssertionError("malformed input must fail before host access")

    handler = ValidationEvidenceJobHandler(factory, store, UnusedHost())
    with pytest.raises(
        TerminalBackgroundJobError,
        match="VALIDATION_EVIDENCE_COLLECTION_INVALID",
    ):
        handler(LeasedJobContext(jobs, grant))


def test_handler_pauses_escalated_validation_attempt_before_host_access(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    factory, store, task_id, configuration_id, contract_id = validation_harness
    collection = _collection(
        task_id,
        configuration_id,
        contract_id,
        configuration_digest=_CONFIGURATION_DIGEST,
    )
    with factory.begin() as session:
        task = session.get(Task, task_id)
        assert task is not None
        task.state = TaskState.ESCALATED
        task.escalation_resume_state = TaskState.VALIDATING

    class UnusedHost:
        def execute(self, _request: HostRequestMessage) -> HostResponseMessage:
            raise AssertionError("paused validation must not access the host")

    grant = JobLeaseGrant(
        job_id=uuid4(),
        task_id=task_id,
        lease_id=uuid4(),
        worker_id="validation-worker",
        attempt=1,
        fencing_token=1,
        expires_at=_NOW + timedelta(seconds=30),
        job_type=VALIDATION_EVIDENCE_JOB_TYPE,
        input_payload=collection.to_dict(),
        checkpoint=None,
        checkpoint_version=0,
        recovered=False,
    )

    handler = ValidationEvidenceJobHandler(factory, store, UnusedHost())
    with pytest.raises(PausedBackgroundJobError, match="TASK_VALIDATION_PAUSED"):
        handler(LeasedJobContext(BackgroundJobService(factory, store), grant))


def test_collection_persistence_is_fenced_by_current_job_lease(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
) -> None:
    factory, store, task_id, configuration_id, contract_id = validation_harness
    collection = _collection(
        task_id,
        configuration_id,
        contract_id,
        configuration_digest=_CONFIGURATION_DIGEST,
    )
    current_time = [_NOW]
    jobs = BackgroundJobService(factory, store, clock=lambda: current_time[0])
    jobs.schedule(
        task_id=task_id,
        job_type=VALIDATION_EVIDENCE_JOB_TYPE,
        idempotency_key=f"validation-evidence-v2:{collection.run_id}",
        input_payload=collection.to_dict(),
    )
    grant = jobs.claim_next(
        worker_id="validation-worker",
        lease_duration=timedelta(seconds=30),
        job_types=(VALIDATION_EVIDENCE_JOB_TYPE,),
    )
    assert grant is not None
    service = ValidationEvidenceService(
        factory,
        store,
        clock=lambda: current_time[0],
        configuration_digest=lambda _configuration: _CONFIGURATION_DIGEST,
    )

    def expire_after_host_response(_item: ValidationEvidenceItem) -> None:
        current_time[0] = _NOW + timedelta(seconds=31)

    with pytest.raises(BackgroundJobLeaseLostError):
        service.collect(
            collection,
            artifact_verifier=expire_after_host_response,
            lease_grant_supplier=lambda: grant,
        )

    with factory() as session:
        assert session.get(ValidationRun, collection.run_id) is None


def test_handler_renews_lease_before_each_artifact_verification(
    validation_harness: tuple[SessionFactory, ArtifactStore, UUID, UUID, UUID],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory, store, task_id, configuration_id, contract_id = validation_harness
    collection = _collection(
        task_id,
        configuration_id,
        contract_id,
        configuration_digest=_CONFIGURATION_DIGEST,
    )
    monkeypatch.setattr(
        validation_evidence_module,
        "validated_repository_configuration",
        lambda _record: SimpleNamespace(
            repository_key="boppuh/mathews",
            configuration_id=configuration_id,
            digest=_CONFIGURATION_DIGEST,
        ),
    )

    class RecordingHost:
        def __init__(self) -> None:
            self.expires_at_ms: list[int] = []

        def execute(self, request: HostRequestMessage) -> HostResponseMessage:
            authority = cast(TaskLeaseHostAuthority, request.authority)
            self.expires_at_ms.append(authority.lease_expires_at_ms)
            return HostResponseMessage(
                request_id=request.request_id,
                operation_name=request.operation.name,
                idempotency_key=request.operation.idempotency_key,
                host_id="host-1",
                host_version="0.1.0",
                status=HostResponseStatus.OK,
                code="OK",
                replayed=False,
                completed_at_ms=1_800_000_000_000,
                execution_fencing_token=authority.fencing_token,
                result={
                    "address": cast(str, request.operation.arguments["address"]),
                    "size_bytes": cast(
                        int,
                        request.operation.arguments["expected_size_bytes"],
                    ),
                    "verified": True,
                },
            )

    class RecordingCollector:
        def precheck(self, _submitted: ValidationEvidenceCollection) -> None:
            pass

        def collect(
            self,
            submitted: ValidationEvidenceCollection,
            *,
            artifact_verifier: Callable[[ValidationEvidenceItem], None],
            lease_grant_supplier: Callable[[], JobLeaseGrant] | None = None,
        ) -> ValidationEvidenceResult:
            assert lease_grant_supplier is not None
            for artifact in submitted.evidence:
                artifact_verifier(artifact)
            return ValidationEvidenceResult(
                validation_run_id=submitted.run_id,
                task_id=submitted.task_id,
                contract_version=4,
                commit_sha=submitted.commit_sha,
                tree_sha=submitted.tree_sha,
                evidence_ids=(),
                criterion_results=(),
                replayed=False,
            )

    class RecordingDecisioner:
        def decide(
            self,
            validation_run_id: UUID,
            *,
            lease_grant_supplier: Callable[[], JobLeaseGrant] | None = None,
        ) -> ValidationDecisionResult:
            assert lease_grant_supplier is not None
            assert lease_grant_supplier() is context.grant
            return ValidationDecisionResult(
                validation_run_id=validation_run_id,
                task_id=task_id,
                validation_attempt_id=_VALIDATION_ATTEMPT_ID,
                validation_contract_id=contract_id,
                validation_contract_version=4,
                repository_configuration_id=configuration_id,
                repository_configuration_version=3,
                commit_sha=_COMMIT_SHA,
                tree_sha=_TREE_SHA,
                outcome=ValidationOutcome.PASSED,
                reason_code="ALL_REQUIRED_VALIDATION_PASSED",
                decision_evidence_id=uuid4(),
                decided_at=_NOW,
                is_current=True,
                replayed=False,
            )

    class RecordingContext:
        def __init__(self) -> None:
            self.grant = JobLeaseGrant(
                job_id=uuid4(),
                task_id=task_id,
                lease_id=uuid4(),
                worker_id="validation-worker",
                attempt=1,
                fencing_token=1,
                expires_at=_NOW + timedelta(seconds=1),
                job_type=LEGACY_VALIDATION_EVIDENCE_JOB_TYPE,
                input_payload=collection.to_dict(),
                checkpoint=None,
                checkpoint_version=0,
                recovered=False,
            )
            self.heartbeats: list[timedelta] = []

        def heartbeat(self, duration: timedelta) -> JobLeaseGrant:
            self.heartbeats.append(duration)
            self.grant = replace(
                self.grant,
                expires_at=self.grant.expires_at + duration,
            )
            return self.grant

    host = RecordingHost()
    context = RecordingContext()
    handler = ValidationEvidenceJobHandler(
        factory,
        store,
        host,
        collector=RecordingCollector(),
        decision_service=RecordingDecisioner(),
    )

    checkpoint = handler(cast(LeasedJobContext, context))

    assert context.heartbeats == [
        timedelta(seconds=30)
        for _ in range(len(collection.evidence) + 1)
    ]
    assert host.expires_at_ms == sorted(host.expires_at_ms)
    assert checkpoint["outcome"] == "PASSED"


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


def test_rechecks_replay_after_artifact_verification_and_task_lock(
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
    competing_result = None

    def verify_with_competing_commit(_item: ValidationEvidenceItem) -> None:
        nonlocal competing_result
        if competing_result is None:
            competing_result = service.collect(
                collection,
                artifact_verifier=_accept_artifact,
            )

    result = service.collect(
        collection,
        artifact_verifier=verify_with_competing_commit,
    )

    assert competing_result is not None
    assert competing_result.replayed is False
    assert result.replayed is True
    assert result.validation_run_id == competing_result.validation_run_id


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
