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
    PolicyVersion,
    PolicyVersionPromptTemplate,
    PromptTemplateVersion,
    ReconciliationTarget,
    ReconciliationTargetKind,
    Task,
    TaskEvent,
    TaskState,
)
from mathews_control_plane.evidence import load_evidence
from mathews_control_plane.hermes import (
    HermesConflictError,
    HermesEventType,
    HermesProviderEvent,
    HermesRunService,
)
from mathews_control_plane.hermes_adapter import (
    HermesJobInput,
    HermesJobPrompt,
    HermesObservation,
    HermesObservedStatus,
    HermesRunJobHandler,
    HermesRuntime,
)
from mathews_control_plane.prompt_compiler import (
    CompiledPrompt,
    PromptRole,
    StructuredPromptTemplate,
)
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
            session.scalars(
                select(HermesRunEvent).order_by(HermesRunEvent.provider_sequence)
            )
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

    assert result["status"] == "SUCCEEDED"
    with hermes_harness.factory() as session:
        run = session.scalar(select(HermesRun))
        assert run is not None and run.status is HermesRunStatus.SUCCEEDED
