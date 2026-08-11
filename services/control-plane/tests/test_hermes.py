from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.background_jobs import (
    BackgroundJobService,
    JobLeaseGrant,
    LeasedJobContext,
    RetryPolicy,
    TerminalBackgroundJobError,
)
from mathews_control_plane.code_change_execution import (
    ScopedCodeExecutionService,
    ScopedToolAmbiguousError,
    ScopedToolExecutionResult,
)
from mathews_control_plane.database import (
    Base,
    SessionFactory,
    create_database_engine,
    create_session_factory,
    create_task_record,
)
from mathews_control_plane.domain_models import (
    BackgroundJob,
    BackgroundJobStatus,
    BackgroundJobToolGrant,
    DependencyOutageAttempt,
    DependencyService,
    EvidenceRecord,
    HermesRun,
    HermesRunEvent,
    HermesRunStatus,
    HermesToolResultStatus,
    PolicyVersion,
    PolicyVersionPromptTemplate,
    PromptTemplateVersion,
    ReconciliationTarget,
    ReconciliationTargetKind,
    RetrievalIndexGeneration,
    Task,
    TaskEvent,
    TaskState,
)
from mathews_control_plane.evaluation_telemetry import (
    AgentRunMetrics,
    EvaluationTelemetryService,
    EvaluationTelemetryValidationError,
    QualityOutcome,
)
from mathews_control_plane.evidence import load_evidence
from mathews_control_plane.hermes import (
    HermesConflictError,
    HermesEventType,
    HermesProviderEvent,
    HermesRunService,
    _bounded_payload,
)
from mathews_control_plane.hermes_adapter import (
    HermesJobInput,
    HermesJobPrompt,
    HermesObservation,
    HermesObservedStatus,
    HermesRunJobHandler,
    HermesRuntime,
    HermesRuntimeError,
    _observation_payload,
    _provider_events,
)
from mathews_control_plane.prompt_compiler import (
    CompiledPrompt,
    PromptRole,
    StructuredPromptTemplate,
)
from mathews_control_plane.retrieval_index import RetrievalSearchResult
from sqlalchemy import Engine, func, select

_NOW = datetime(2026, 8, 7, 17, 0, tzinfo=UTC)


@dataclass(slots=True)
class HermesHarness:
    engine: Engine
    factory: SessionFactory
    store: ArtifactStore
    task_id: UUID
    job_id: UUID
    grant: JobLeaseGrant
    prompt: CompiledPrompt


@pytest.fixture
def hermes_harness(tmp_path: Path) -> Iterator[HermesHarness]:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'hermes.sqlite3'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    store = ArtifactStore(tmp_path / "artifacts")
    with factory.begin() as session:
        task = create_task_record(
            session,
            store,
            repository="boppuh/mathews",
            base_revision="a" * 40,
            requester="local-user",
            raw_request="Run Hermes safely",
            summary="Run Hermes",
            owner_id="local-user",
            actor_id="local-user",
        )
        task.state = TaskState.IMPLEMENTING
        template = PromptTemplateVersion(
            lineage_key="implementer",
            role=PromptRole.IMPLEMENTER.value,
            version=1,
            structured_template=StructuredPromptTemplate(
                role=PromptRole.IMPLEMENTER,
                instructions=("Implement the exact brief.",),
            ).model_dump(mode="json"),
            evaluation_score=1.0,
            evaluation_threshold_passed=True,
            regression_reviewed=True,
            promoted=True,
            approved_by="local-user",
            approved_at=_NOW - timedelta(minutes=1),
            owner_id=task.owner_id,
            actor_id="local-user",
            root_correlation_id=task.root_correlation_id,
        )
        policy = PolicyVersion(
            lineage_key="mvp",
            version=1,
            workflow_thresholds={},
            approved_by="local-user",
            approved_at=_NOW - timedelta(minutes=1),
            owner_id=task.owner_id,
            actor_id="local-user",
            root_correlation_id=task.root_correlation_id,
        )
        session.add_all([template, policy])
        session.flush()
        session.add(
            PolicyVersionPromptTemplate(
                policy_version_id=policy.id,
                prompt_template_version_id=template.id,
                prompt_promoted=True,
                position=1,
                owner_id=task.owner_id,
                actor_id="local-user",
                root_correlation_id=task.root_correlation_id,
            )
        )
        task_id = task.id
        prompt = CompiledPrompt(
            task_id=task.id,
            role=PromptRole.IMPLEMENTER,
            template_id=template.id,
            template_version=template.version,
            policy_version_id=policy.id,
            evaluation_label=None,
            content="{}",
            evidence_ids=(),
        )
    jobs = BackgroundJobService(factory, store, clock=lambda: _NOW)
    job_id = jobs.schedule(
        task_id=task_id,
        job_type="hermes-run",
        idempotency_key=f"hermes:{task_id}",
        input_payload={"task_id": str(task_id)},
        retry_policy=RetryPolicy(max_attempts=2, base_delay_seconds=1, max_delay_seconds=2),
    ).job_id
    grant = jobs.claim_next(worker_id="worker-1", lease_duration=timedelta(minutes=5))
    assert grant is not None
    yield HermesHarness(engine, factory, store, task_id, job_id, grant, prompt)
    engine.dispose()


def _service(harness: HermesHarness) -> HermesRunService:
    return HermesRunService(harness.factory, harness.store, clock=lambda: _NOW)


def _started(harness: HermesHarness) -> tuple[HermesRunService, UUID]:
    service = _service(harness)
    run_id = uuid4()
    prepared = service.prepare(harness.grant, run_id=run_id, prompt=harness.prompt)
    assert prepared.status is HermesRunStatus.STARTING
    started = service.record_started(harness.grant, run_id=run_id, external_run_id="run-1")
    assert started.status is HermesRunStatus.RUNNING
    return service, run_id


def test_version_bound_run_evaluation_is_idempotent_and_comparable(
    hermes_harness: HermesHarness,
) -> None:
    runs, run_id = _started(hermes_harness)
    runs.ingest(
        run_id,
        event=HermesProviderEvent(
            provider_event_id="completed-evaluation",
            external_run_id="run-1",
            sequence=1,
            event_type=HermesEventType.COMPLETED,
            payload={"usage": {"input_tokens": 100, "output_tokens": 20}},
        ),
    )
    with hermes_harness.factory.begin() as session:
        task = session.get(Task, hermes_harness.task_id)
        assert task is not None
        generation = RetrievalIndexGeneration(
            task_id=task.id,
            index_version="retrieval-v1",
            chunker_version="mvp-char-v1",
            verifier_version="evidence-envelope-v1",
            indexed_at=_NOW,
            source_count=0,
            chunk_count=0,
            owner_id=task.owner_id,
            actor_id="retrieval-indexer",
            root_correlation_id=task.root_correlation_id,
        )
        session.add(generation)
        session.flush()
        generation_id = generation.id

    telemetry = EvaluationTelemetryService(
        hermes_harness.factory,
        clock=lambda: _NOW,
    )
    contract = telemetry.create_contract_version(
        lineage_key="mvp-agent-evaluation",
        promotion_thresholds={
            "minimum_run_count": 1,
            "minimum_quality_score": 0.8,
            "maximum_average_cost_microusd": 2_000,
            "minimum_regression_pass_rate": 1.0,
        },
        regression_cases=("baseline-task",),
        actor_id="evaluation-worker",
        activate=True,
    )
    retrieval = RetrievalSearchResult(
        task_id=hermes_harness.task_id,
        generation_id=generation_id,
        index_version="retrieval-v1",
        hits=(),
    )
    metrics = AgentRunMetrics(
        model_provider="openai",
        model_name="gpt-5",
        model_version="2026-08-01",
        input_tokens=100,
        output_tokens=20,
        cached_tokens=40,
        cost_microusd=1_500,
        quality_outcome=QualityOutcome.PASSED,
        quality_score=0.95,
        regression_results={"baseline-task": True},
    )
    recorded = telemetry.record(
        run_id=run_id,
        contract_id=contract.id,
        retrieval=retrieval,
        metrics=metrics,
        actor_id="evaluation-worker",
    )
    replayed = telemetry.record(
        run_id=run_id,
        contract_id=contract.id,
        retrieval=retrieval,
        metrics=metrics,
        actor_id="evaluation-worker",
    )
    assert replayed.id == recorded.id
    comparison = telemetry.compare(contract.id)
    assert len(comparison) == 1
    assert comparison[0].promotion_eligible is True
    assert comparison[0].average_quality_score == 0.95
    assert comparison[0].regression_pass_rate == 1.0
    with pytest.raises(
        EvaluationTelemetryValidationError,
        match="agent run evaluation conflicts",
    ):
        telemetry.record(
            run_id=run_id,
            contract_id=contract.id,
            retrieval=retrieval,
            metrics=replace(metrics, quality_score=0.5),
            actor_id="evaluation-worker",
        )


def test_run_correlation_and_prose_safe_event_normalization(
    hermes_harness: HermesHarness,
) -> None:
    service, run_id = _started(hermes_harness)
    event = HermesProviderEvent(
        provider_event_id="event-1",
        external_run_id="run-1",
        sequence=1,
        event_type=HermesEventType.OUTPUT,
        payload={"message": "I declare the task complete", "raw_log": "lots of prose"},
    )

    first = service.ingest(run_id, event)
    replay = service.ingest(run_id, event)

    assert first.accepted is True and replay.replayed is True
    with hermes_harness.factory() as session:
        run = session.get(HermesRun, run_id)
        task = session.get(Task, hermes_harness.task_id)
        task_event = session.get(TaskEvent, first.task_event_id)
        evidence = session.get(EvidenceRecord, first.evidence_id)
        target = session.scalar(
            select(ReconciliationTarget).where(
                ReconciliationTarget.kind == ReconciliationTargetKind.HERMES_RUN
            )
        )
        assert run is not None
        assert run.job_id == hermes_harness.job_id
        assert run.lease_id == hermes_harness.grant.lease_id
        assert run.fencing_token == hermes_harness.grant.fencing_token
        assert run.attempt == hermes_harness.grant.attempt
        assert task is not None and task.state is TaskState.IMPLEMENTING
        assert task_event is not None and task_event.event_type == "HERMES_EVENT"
        assert "declare the task complete" not in str(task_event.payload)
        assert task_event.payload["agent_prose_is_authoritative"] is False
        assert evidence is not None
        assert target is not None
        assert target.expected_payload["external_run_id"] == "run-1"
        loaded = load_evidence(session, hermes_harness.store, evidence)
        assert "declare the task complete" in str(loaded.content)


def test_out_of_order_and_cancelled_events_are_durably_fenced(
    hermes_harness: HermesHarness,
) -> None:
    service, run_id = _started(hermes_harness)
    out_of_order = service.ingest(
        run_id,
        HermesProviderEvent(
            provider_event_id="event-2",
            external_run_id="run-1",
            sequence=2,
            event_type=HermesEventType.HEARTBEAT,
            payload={},
        ),
    )
    cancelled = service.cancel(run_id)
    late = service.ingest(
        run_id,
        HermesProviderEvent(
            provider_event_id="event-3",
            external_run_id="run-1",
            sequence=1,
            event_type=HermesEventType.COMPLETED,
            payload={"message": "done"},
        ),
    )

    assert out_of_order.accepted is False
    assert out_of_order.ignored_reason == "OUT_OF_ORDER"
    assert cancelled.revoked_tool_grants == 1
    assert late.accepted is False and late.ignored_reason == "RUN_TERMINAL"
    with hermes_harness.factory() as session:
        run = session.get(HermesRun, run_id)
        grant = session.scalar(
            select(BackgroundJobToolGrant).where(
                BackgroundJobToolGrant.job_id == hermes_harness.job_id
            )
        )
        assert run is not None and run.status is HermesRunStatus.CANCELLED
        assert grant is not None and grant.revoked_at is not None
        assert grant.revoked_at.replace(tzinfo=UTC) == _NOW
        task = session.get(Task, hermes_harness.task_id)
        assert task is not None and task.state is TaskState.IMPLEMENTING


def test_out_of_order_event_can_be_replayed_after_the_gap_closes(
    hermes_harness: HermesHarness,
) -> None:
    service, run_id = _started(hermes_harness)
    second = HermesProviderEvent(
        provider_event_id="event-2",
        external_run_id="run-1",
        sequence=2,
        event_type=HermesEventType.HEARTBEAT,
        payload={"state": "two"},
    )

    early = service.ingest(run_id, second)
    first = service.ingest(
        run_id,
        HermesProviderEvent(
            provider_event_id="event-1",
            external_run_id="run-1",
            sequence=1,
            event_type=HermesEventType.HEARTBEAT,
            payload={"state": "one"},
        ),
    )
    recovered = service.ingest(run_id, second)

    assert early.accepted is False and early.ignored_reason == "OUT_OF_ORDER"
    assert first.accepted is True
    assert recovered.accepted is True
    with hermes_harness.factory() as session:
        events = tuple(
            session.scalars(select(HermesRunEvent).order_by(HermesRunEvent.provider_sequence))
        )
        assert [event.provider_sequence for event in events] == [1, 2]


def test_completion_updates_run_but_never_task_state(
    hermes_harness: HermesHarness,
) -> None:
    service, run_id = _started(hermes_harness)
    result = service.ingest(
        run_id,
        HermesProviderEvent(
            provider_event_id="complete-1",
            external_run_id="run-1",
            sequence=1,
            event_type=HermesEventType.COMPLETED,
            payload={"summary": "completed"},
        ),
    )

    assert result.accepted is True
    with hermes_harness.factory() as session:
        run = session.get(HermesRun, run_id)
        task = session.get(Task, hermes_harness.task_id)
        assert run is not None and run.status is HermesRunStatus.SUCCEEDED
        assert task is not None and task.state is TaskState.IMPLEMENTING


def test_unsafe_provider_failure_code_uses_the_durable_fallback(
    hermes_harness: HermesHarness,
) -> None:
    service, run_id = _started(hermes_harness)
    result = service.ingest(
        run_id,
        HermesProviderEvent(
            provider_event_id="failure-1",
            external_run_id="run-1",
            sequence=1,
            event_type=HermesEventType.FAILED,
            payload={"error_code": "model.rate-limit"},
        ),
    )

    assert result.accepted is True
    with hermes_harness.factory() as session:
        run = session.get(HermesRun, run_id)
        assert run is not None and run.failure_code == "HERMES_RUN_FAILED"


def test_runtime_observation_preserves_a_bounded_provider_error_code() -> None:
    payload = _observation_payload(
        {
            "run_id": "run-1",
            "status": "failed",
            "error": "provider rejected the request",
            "error_code": "RATE_LIMITED",
        }
    )

    assert payload["error_code"] == "RATE_LIMITED"


def test_runtime_projects_typed_tool_proposals_without_mixing_them_into_prose() -> None:
    events = _provider_events(
        {
            "events": [
                {
                    "event_id": "proposal-event-1",
                    "sequence": 1,
                    "type": "TOOL_PROPOSAL",
                    "payload": {
                        "proposal_id": "proposal-1",
                        "tool_name": "workspace.read_file",
                        "arguments": {"path": "Sources/App.swift"},
                    },
                }
            ]
        },
        "run-1",
    )

    assert len(events) == 1
    assert events[0].event_type is HermesEventType.TOOL_PROPOSAL
    assert events[0].payload["proposal_id"] == "proposal-1"


def test_runtime_orders_provider_events_and_rejects_duplicate_sequences() -> None:
    events = _provider_events(
        {
            "events": [
                {
                    "event_id": "event-2",
                    "sequence": 2,
                    "type": "OUTPUT",
                    "payload": {"text": "second"},
                },
                {
                    "event_id": "event-1",
                    "sequence": 1,
                    "type": "OUTPUT",
                    "payload": {"text": "first"},
                },
            ]
        },
        "run-1",
    )

    assert [event.sequence for event in events] == [1, 2]
    with pytest.raises(HermesRuntimeError, match="HERMES_RESPONSE_INVALID"):
        _provider_events(
            {
                "events": [
                    {
                        "event_id": "event-a",
                        "sequence": 1,
                        "type": "OUTPUT",
                        "payload": {},
                    },
                    {
                        "event_id": "event-b",
                        "sequence": 1,
                        "type": "HEARTBEAT",
                        "payload": {},
                    },
                ]
            },
            "run-1",
        )


def test_hermes_event_bound_accepts_the_scoped_patch_transport_limit() -> None:
    payload = _bounded_payload({"content": "x" * (256 * 1024)})

    assert len(cast(str, payload["content"])) == 256 * 1024
    with pytest.raises(HermesConflictError, match="size limit"):
        _bounded_payload({"content": "x" * (513 * 1024)})


def test_hermes_outage_uses_bounded_background_job_retry(
    hermes_harness: HermesHarness,
) -> None:
    service, run_id = _started(hermes_harness)

    disposition = service.fail_dependency(
        hermes_harness.grant,
        run_id=run_id,
        error_code="HERMES_UNAVAILABLE",
    )

    assert disposition.status is BackgroundJobStatus.QUEUED
    assert disposition.retry_delay is not None
    with hermes_harness.factory() as session:
        run = session.get(HermesRun, run_id)
        job = session.get(BackgroundJob, hermes_harness.job_id)
        outage = session.scalar(
            select(DependencyOutageAttempt).where(
                DependencyOutageAttempt.job_id == hermes_harness.job_id
            )
        )
        assert run is not None and run.status is HermesRunStatus.FAILED
        assert job is not None and job.status is BackgroundJobStatus.QUEUED
        assert outage is not None and outage.service is DependencyService.HERMES


def test_hermes_outage_projection_resumes_after_a_committed_job_failure(
    hermes_harness: HermesHarness,
) -> None:
    service, run_id = _started(hermes_harness)
    durable = BackgroundJobService(
        hermes_harness.factory,
        hermes_harness.store,
        clock=lambda: _NOW,
    ).fail_dependency_attempt(
        hermes_harness.grant,
        service=DependencyService.HERMES,
        error_code="HERMES_UNAVAILABLE",
    )

    recovered = service.fail_dependency(
        hermes_harness.grant,
        run_id=run_id,
        error_code="HERMES_UNAVAILABLE",
    )
    replayed = service.fail_dependency(
        hermes_harness.grant,
        run_id=run_id,
        error_code="HERMES_UNAVAILABLE",
    )

    assert recovered == durable
    assert replayed == durable
    with hermes_harness.factory() as session:
        run = session.get(HermesRun, run_id)
        assert run is not None and run.status is HermesRunStatus.FAILED
        assert session.scalar(select(func.count()).select_from(DependencyOutageAttempt)) == 1


def test_dependency_failure_cannot_overwrite_a_successful_run(
    hermes_harness: HermesHarness,
) -> None:
    service, run_id = _started(hermes_harness)
    service.ingest(
        run_id,
        HermesProviderEvent(
            provider_event_id="complete-1",
            external_run_id="run-1",
            sequence=1,
            event_type=HermesEventType.COMPLETED,
            payload={},
        ),
    )

    with pytest.raises(HermesConflictError, match="terminal"):
        service.fail_dependency(
            hermes_harness.grant,
            run_id=run_id,
            error_code="HERMES_UNAVAILABLE",
        )

    with hermes_harness.factory() as session:
        run = session.get(HermesRun, run_id)
        job = session.get(BackgroundJob, hermes_harness.job_id)
        assert run is not None and run.status is HermesRunStatus.SUCCEEDED
        assert job is not None and job.status is BackgroundJobStatus.RUNNING
        assert session.scalar(select(func.count()).select_from(DependencyOutageAttempt)) == 0


def test_cancellation_cannot_overwrite_a_timed_out_run(
    hermes_harness: HermesHarness,
) -> None:
    service, run_id = _started(hermes_harness)
    service.fail_dependency(
        hermes_harness.grant,
        run_id=run_id,
        error_code="HERMES_TIMEOUT",
        timed_out=True,
    )

    with pytest.raises(HermesConflictError, match="completed"):
        service.cancel(run_id)

    with hermes_harness.factory() as session:
        run = session.get(HermesRun, run_id)
        assert run is not None and run.status is HermesRunStatus.TIMED_OUT


def test_stale_run_cancellation_does_not_revoke_the_replacement_attempt(
    hermes_harness: HermesHarness,
) -> None:
    service, stale_run_id = _started(hermes_harness)
    jobs = BackgroundJobService(hermes_harness.factory, hermes_harness.store, clock=lambda: _NOW)
    disposition = jobs.fail_attempt(
        hermes_harness.grant,
        error_code="RETRY_TEST",
        retryable=True,
    )
    assert disposition.next_attempt_at is not None
    later = disposition.next_attempt_at + timedelta(seconds=1)
    retry_jobs = BackgroundJobService(
        hermes_harness.factory,
        hermes_harness.store,
        clock=lambda: later,
    )
    replacement_grant = retry_jobs.claim_next(
        worker_id="worker-2",
        lease_duration=timedelta(minutes=5),
    )
    assert replacement_grant is not None
    replacement_run_id = uuid4()
    HermesRunService(
        hermes_harness.factory,
        hermes_harness.store,
        clock=lambda: later,
    ).prepare(
        replacement_grant,
        run_id=replacement_run_id,
        prompt=hermes_harness.prompt,
    )

    cancelled = service.cancel(stale_run_id)

    assert cancelled.revoked_tool_grants == 1
    with hermes_harness.factory() as session:
        grants = {
            grant.grant_key: grant for grant in session.scalars(select(BackgroundJobToolGrant))
        }
        assert grants[f"hermes:{stale_run_id}"].revoked_at is not None
        assert grants[f"hermes:{replacement_run_id}"].revoked_at is None


def test_run_commands_require_the_exact_lease_owner(
    hermes_harness: HermesHarness,
) -> None:
    service = _service(hermes_harness)
    run_id = uuid4()
    service.prepare(hermes_harness.grant, run_id=run_id, prompt=hermes_harness.prompt)

    with pytest.raises(HermesConflictError, match="no longer current"):
        service.record_started(
            replace(hermes_harness.grant, worker_id="other-worker"),
            run_id=run_id,
            external_run_id="run-1",
        )

    with hermes_harness.factory() as session:
        run = session.get(HermesRun, run_id)
        assert run is not None and run.status is HermesRunStatus.STARTING


def test_provider_event_ids_cannot_be_reused_with_other_content(
    hermes_harness: HermesHarness,
) -> None:
    service, run_id = _started(hermes_harness)
    service.ingest(
        run_id,
        HermesProviderEvent(
            provider_event_id="same-id",
            external_run_id="run-1",
            sequence=1,
            event_type=HermesEventType.HEARTBEAT,
            payload={},
        ),
    )
    with pytest.raises(HermesConflictError, match="conflicts"):
        service.ingest(
            run_id,
            HermesProviderEvent(
                provider_event_id="same-id",
                external_run_id="run-1",
                sequence=1,
                event_type=HermesEventType.HEARTBEAT,
                payload={"altered": True},
            ),
        )

    with hermes_harness.factory() as session:
        assert len(session.scalars(select(HermesRunEvent)).all()) == 1


def test_unapproved_prompt_cannot_obtain_a_tool_grant(
    hermes_harness: HermesHarness,
) -> None:
    with hermes_harness.factory.begin() as session:
        membership = session.scalar(select(PolicyVersionPromptTemplate))
        assert membership is not None
        session.delete(membership)

    with pytest.raises(HermesConflictError, match="not active"):
        _service(hermes_harness).prepare(
            hermes_harness.grant,
            run_id=uuid4(),
            prompt=hermes_harness.prompt,
        )

    with hermes_harness.factory() as session:
        assert session.scalar(select(func.count()).select_from(BackgroundJobToolGrant)) == 0


class _CompletingRuntime:
    def start(self, **_kwargs: object) -> str:
        return "worker-run-1"

    def observe(self, external_run_id: str) -> HermesObservation:
        return HermesObservation(
            external_run_id,
            HermesObservedStatus.COMPLETED,
            {"run_id": external_run_id, "status": "completed", "output": "done"},
        )

    def stop(self, _external_run_id: str) -> None:
        raise AssertionError("completed run must not be stopped")

    def reconcile(self, **_kwargs: object) -> object:
        raise AssertionError("startup reconciliation is not used by the handler")


class _ToolRuntime(_CompletingRuntime):
    def __init__(self) -> None:
        self.observations = 0
        self.results: list[ScopedToolExecutionResult] = []

    def observe(self, external_run_id: str) -> HermesObservation:
        self.observations += 1
        if self.observations == 1:
            return HermesObservation(
                external_run_id,
                HermesObservedStatus.RUNNING,
                {"run_id": external_run_id, "status": "running"},
                (
                    HermesProviderEvent(
                        provider_event_id="proposal-event-1",
                        external_run_id=external_run_id,
                        sequence=1,
                        event_type=HermesEventType.TOOL_PROPOSAL,
                        payload={
                            "proposal_id": "proposal-1",
                            "tool_name": "workspace.read_file",
                            "arguments": {"path": "Sources/App.swift"},
                        },
                    ),
                ),
            )
        return super().observe(external_run_id)

    def submit_tool_result(
        self,
        _external_run_id: str,
        result: ScopedToolExecutionResult,
    ) -> None:
        self.results.append(result)


class _ToolExecution:
    def execute(self, *_args: object, **_kwargs: object) -> ScopedToolExecutionResult:
        return ScopedToolExecutionResult(
            proposal_id="proposal-1",
            status=HermesToolResultStatus.SUCCEEDED,
            code="OK",
            result={"head_sha": "a" * 40, "content": "let enabled = true\n"},
            decision_evidence_id=uuid4(),
            result_evidence_id=uuid4(),
            diff_evidence_id=None,
            replayed=False,
        )


class _AmbiguousThenSuccessfulToolExecution(_ToolExecution):
    def __init__(self) -> None:
        self.grants: list[JobLeaseGrant] = []

    def execute(self, *args: object, **kwargs: object) -> ScopedToolExecutionResult:
        grant = cast(JobLeaseGrant, args[0])
        self.grants.append(grant)
        if len(self.grants) == 1:
            raise ScopedToolAmbiguousError("host response was ambiguous")
        return super().execute(*args, **kwargs)


class _MalformedToolRuntime(_ToolRuntime):
    def __init__(self) -> None:
        super().__init__()
        self.stopped: list[str] = []

    def observe(self, external_run_id: str) -> HermesObservation:
        self.observations += 1
        return HermesObservation(
            external_run_id,
            HermesObservedStatus.RUNNING,
            {"run_id": external_run_id, "status": "running"},
            (
                HermesProviderEvent(
                    provider_event_id="proposal-event-invalid",
                    external_run_id=external_run_id,
                    sequence=1,
                    event_type=HermesEventType.TOOL_PROPOSAL,
                    payload={"proposal_id": "missing-tool-fields"},
                ),
            ),
        )

    def stop(self, external_run_id: str) -> None:
        self.stopped.append(external_run_id)


def test_registered_worker_handler_executes_a_hermes_run(
    hermes_harness: HermesHarness,
) -> None:
    prompt = HermesJobPrompt(
        task_id=hermes_harness.prompt.task_id,
        role=hermes_harness.prompt.role,
        template_id=hermes_harness.prompt.template_id,
        template_version=hermes_harness.prompt.template_version,
        policy_version_id=hermes_harness.prompt.policy_version_id,
        evaluation_label=hermes_harness.prompt.evaluation_label,
        content=hermes_harness.prompt.content,
        evidence_ids=hermes_harness.prompt.evidence_ids,
    )
    grant = replace(
        hermes_harness.grant,
        input_payload=HermesJobInput(prompt=prompt).model_dump(mode="json"),
    )
    context = LeasedJobContext(
        BackgroundJobService(hermes_harness.factory, hermes_harness.store, clock=lambda: _NOW),
        grant,
    )
    result = HermesRunJobHandler(
        hermes_harness.factory,
        hermes_harness.store,
        cast(HermesRuntime, _CompletingRuntime()),
        sleeper=lambda _seconds: None,
        clock=lambda: _NOW,
    )(context)
    replay_context = LeasedJobContext(context.service, grant)
    replayed = HermesRunJobHandler(
        hermes_harness.factory,
        hermes_harness.store,
        cast(HermesRuntime, _CompletingRuntime()),
        sleeper=lambda _seconds: None,
        clock=lambda: _NOW,
    )(replay_context)

    assert result["status"] == "SUCCEEDED"
    assert replayed == result
    with hermes_harness.factory() as session:
        run = session.scalar(select(HermesRun))
        assert run is not None and run.status is HermesRunStatus.SUCCEEDED


def test_worker_brokers_tool_proposal_before_returning_result_to_hermes(
    hermes_harness: HermesHarness,
) -> None:
    prompt = HermesJobPrompt(
        task_id=hermes_harness.prompt.task_id,
        role=hermes_harness.prompt.role,
        template_id=hermes_harness.prompt.template_id,
        template_version=hermes_harness.prompt.template_version,
        policy_version_id=hermes_harness.prompt.policy_version_id,
        evaluation_label=hermes_harness.prompt.evaluation_label,
        content=hermes_harness.prompt.content,
        evidence_ids=hermes_harness.prompt.evidence_ids,
    )
    grant = replace(
        hermes_harness.grant,
        input_payload=HermesJobInput(
            prompt=prompt,
            poll_interval_seconds=0.001,
        ).model_dump(mode="json"),
    )
    context = LeasedJobContext(
        BackgroundJobService(
            hermes_harness.factory,
            hermes_harness.store,
            clock=lambda: _NOW,
        ),
        grant,
    )
    runtime = _ToolRuntime()

    result = HermesRunJobHandler(
        hermes_harness.factory,
        hermes_harness.store,
        cast(HermesRuntime, runtime),
        cast(ScopedCodeExecutionService, _ToolExecution()),
        sleeper=lambda _seconds: None,
        clock=lambda: _NOW,
    )(context)

    assert result["status"] == "SUCCEEDED"
    assert len(runtime.results) == 1
    assert runtime.results[0].proposal_id == "proposal-1"
    with hermes_harness.factory() as session:
        event = session.scalar(
            select(HermesRunEvent).where(
                HermesRunEvent.event_type == HermesEventType.TOOL_PROPOSAL.value
            )
        )
        assert event is not None and event.accepted is True


def test_worker_reconciles_an_ambiguous_host_effect_under_the_same_lease(
    hermes_harness: HermesHarness,
) -> None:
    prompt = HermesJobPrompt(
        task_id=hermes_harness.prompt.task_id,
        role=hermes_harness.prompt.role,
        template_id=hermes_harness.prompt.template_id,
        template_version=hermes_harness.prompt.template_version,
        policy_version_id=hermes_harness.prompt.policy_version_id,
        content=hermes_harness.prompt.content,
    )
    grant = replace(
        hermes_harness.grant,
        input_payload=HermesJobInput(
            prompt=prompt,
            poll_interval_seconds=0.001,
        ).model_dump(mode="json"),
    )
    context = LeasedJobContext(
        BackgroundJobService(hermes_harness.factory, hermes_harness.store, clock=lambda: _NOW),
        grant,
    )
    runtime = _ToolRuntime()
    execution = _AmbiguousThenSuccessfulToolExecution()

    result = HermesRunJobHandler(
        hermes_harness.factory,
        hermes_harness.store,
        cast(HermesRuntime, runtime),
        cast(ScopedCodeExecutionService, execution),
        sleeper=lambda _seconds: None,
        clock=lambda: _NOW,
    )(context)

    assert result["status"] == "SUCCEEDED"
    assert len(execution.grants) == 2
    assert {item.lease_id for item in execution.grants} == {grant.lease_id}
    assert {item.fencing_token for item in execution.grants} == {grant.fencing_token}
    assert len(runtime.results) == 1


def test_worker_stops_and_cancels_a_run_with_a_malformed_tool_proposal(
    hermes_harness: HermesHarness,
) -> None:
    prompt = HermesJobPrompt(
        task_id=hermes_harness.prompt.task_id,
        role=hermes_harness.prompt.role,
        template_id=hermes_harness.prompt.template_id,
        template_version=hermes_harness.prompt.template_version,
        policy_version_id=hermes_harness.prompt.policy_version_id,
        content=hermes_harness.prompt.content,
    )
    grant = replace(
        hermes_harness.grant,
        input_payload=HermesJobInput(prompt=prompt).model_dump(mode="json"),
    )
    context = LeasedJobContext(
        BackgroundJobService(hermes_harness.factory, hermes_harness.store, clock=lambda: _NOW),
        grant,
    )
    runtime = _MalformedToolRuntime()

    with pytest.raises(TerminalBackgroundJobError, match="HERMES_TOOL_PROPOSAL_INVALID"):
        HermesRunJobHandler(
            hermes_harness.factory,
            hermes_harness.store,
            cast(HermesRuntime, runtime),
            cast(ScopedCodeExecutionService, _ToolExecution()),
            sleeper=lambda _seconds: None,
            clock=lambda: _NOW,
        )(context)

    assert runtime.stopped == ["worker-run-1"]
    with hermes_harness.factory() as session:
        run = session.scalar(select(HermesRun))
        assert run is not None and run.status is HermesRunStatus.CANCELLED
