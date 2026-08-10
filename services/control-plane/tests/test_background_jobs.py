from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.background_jobs import (
    AmbiguousBackgroundJobEffectError,
    BackgroundJobConflictError,
    BackgroundJobError,
    BackgroundJobHandler,
    BackgroundJobLeaseLostError,
    BackgroundJobService,
    DependencyOutageError,
    DurableJobWorker,
    EffectExecutionResult,
    InvalidBackgroundJobError,
    JobLeaseGrant,
    LeasedJobContext,
    PausedBackgroundJobError,
    RetryableBackgroundJobError,
    RetryPolicy,
    TerminalBackgroundJobError,
    WorkerRunOutcome,
    deterministic_retry_delay,
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
    BackgroundJobCheckpoint,
    BackgroundJobEffect,
    BackgroundJobEffectStatus,
    BackgroundJobFencingCounter,
    BackgroundJobLease,
    BackgroundJobStatus,
    BackgroundJobTaskTransition,
    DependencyService,
    EvidenceRecord,
    PolicyVersion,
    Task,
    TaskEvent,
    TaskState,
)
from mathews_control_plane.task_state_machine import TaskTransitionKind
from sqlalchemy import Engine, func, select

_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


@dataclass(slots=True)
class MutableClock:
    now: datetime = _NOW

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **changes: float) -> None:
        self.now += timedelta(**changes)


@dataclass(slots=True)
class JobHarness:
    engine: Engine
    factory: SessionFactory
    store: ArtifactStore
    clock: MutableClock

    def service(self) -> BackgroundJobService:
        return BackgroundJobService(
            self.factory,
            self.store,
            clock=self.clock,
        )


@pytest.fixture
def job_harness(tmp_path: Path) -> Any:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'jobs.sqlite3'}")
    Base.metadata.create_all(engine)
    harness = JobHarness(
        engine=engine,
        factory=create_session_factory(engine),
        store=ArtifactStore(tmp_path / "artifacts"),
        clock=MutableClock(),
    )
    yield harness
    engine.dispose()


def _create_task(job_harness: JobHarness) -> tuple[UUID, UUID]:
    with job_harness.factory.begin() as session:
        task = create_task_record(
            session,
            job_harness.store,
            repository="boppuh/mathews",
            base_revision="1" * 40,
            requester="local-user",
            raw_request="Run a durable task action",
            summary="Run durable job",
            owner_id="local-user",
            actor_id="local-user",
        )
        session.add(
            PolicyVersion(
                lineage_key="mvp",
                version=1,
                predecessor_id=None,
                workflow_thresholds={},
                approved_by="local-user",
                approved_at=job_harness.clock.now,
                owner_id=task.owner_id,
                actor_id="local-user",
                root_correlation_id=task.root_correlation_id,
            )
        )
        session.flush()
        evidence_id = session.scalar(
            select(EvidenceRecord.id).where(EvidenceRecord.task_id == task.id)
        )
        assert evidence_id is not None
        return task.id, evidence_id


def _schedule(
    job_harness: JobHarness,
    *,
    key: str = "task-action:1",
    policy: RetryPolicy | None = None,
) -> UUID:
    task_id, _evidence_id = _create_task(job_harness)
    scheduled = job_harness.service().schedule(
        task_id=task_id,
        job_type="task-action",
        idempotency_key=key,
        input_payload={"operation": "validate"},
        retry_policy=policy,
    )
    return scheduled.job_id


def _claim(
    job_harness: JobHarness,
    *,
    worker: str = "worker-1",
    duration: int = 30,
) -> JobLeaseGrant:
    grant = job_harness.service().claim_next(
        worker_id=worker,
        lease_duration=timedelta(seconds=duration),
    )
    assert grant is not None
    return grant


@pytest.mark.parametrize(
    "arguments",
    [
        {"max_attempts": 0},
        {"max_attempts": 101},
        {"base_delay_seconds": 0},
        {"max_delay_seconds": 0},
        {"base_delay_seconds": 5, "max_delay_seconds": 4},
        {"max_delay_seconds": 86_401},
    ],
)
def test_retry_policy_rejects_unsafe_bounds(arguments: dict[str, int]) -> None:
    with pytest.raises(InvalidBackgroundJobError):
        RetryPolicy(**arguments)


def test_retry_jitter_is_deterministic_and_bounded() -> None:
    policy = RetryPolicy(
        max_attempts=10,
        base_delay_seconds=2,
        max_delay_seconds=9,
    )
    job_id = UUID("11111111-1111-1111-1111-111111111111")

    first = deterministic_retry_delay(job_id, 3, policy)
    second = deterministic_retry_delay(job_id, 3, policy)
    capped = deterministic_retry_delay(job_id, 50, policy)

    assert first == second
    assert timedelta(0) <= first <= timedelta(seconds=8)
    assert timedelta(0) <= capped <= timedelta(seconds=9)


def test_schedule_is_idempotent_and_compares_the_full_command(
    job_harness: JobHarness,
) -> None:
    task_id, _evidence_id = _create_task(job_harness)
    service = job_harness.service()
    first = service.schedule(
        task_id=task_id,
        job_type="task-action",
        idempotency_key="task-action:stable",
        input_payload={"b": 2, "a": 1},
    )
    replay = service.schedule(
        task_id=task_id,
        job_type="task-action",
        idempotency_key="task-action:stable",
        input_payload={"a": 1, "b": 2},
    )

    assert replay.job_id == first.job_id
    assert replay.replayed is True
    with pytest.raises(BackgroundJobConflictError, match="different command"):
        service.schedule(
            task_id=task_id,
            job_type="task-action",
            idempotency_key="task-action:stable",
            input_payload={"a": 1, "b": 3},
        )
    with job_harness.factory() as session:
        count = session.scalar(select(func.count()).select_from(BackgroundJob))
    assert count == 1


def test_schedule_rejects_sensitive_payloads(job_harness: JobHarness) -> None:
    task_id, _evidence_id = _create_task(job_harness)
    with pytest.raises(InvalidBackgroundJobError, match="sensitive"):
        job_harness.service().schedule(
            task_id=task_id,
            job_type="task-action",
            idempotency_key="task-action:sensitive",
            input_payload={"api_token": "secret-value"},
        )


def test_concurrent_cold_start_schedules_share_one_fencing_counter(
    job_harness: JobHarness,
) -> None:
    task_id, _evidence_id = _create_task(job_harness)
    service = job_harness.service()

    def schedule(position: int) -> UUID:
        return service.schedule(
            task_id=task_id,
            job_type="task-action",
            idempotency_key=f"cold-start:{position}",
            input_payload={"position": position},
        ).job_id

    with ThreadPoolExecutor(max_workers=2) as executor:
        job_ids = tuple(executor.map(schedule, (1, 2)))

    assert len(set(job_ids)) == 2
    with job_harness.factory() as session:
        counters = tuple(session.scalars(select(BackgroundJobFencingCounter)))
    assert len(counters) == 1
    assert counters[0].next_token == 1


def test_claim_is_exclusive_and_heartbeat_cannot_revive_expiry(
    job_harness: JobHarness,
) -> None:
    job_id = _schedule(job_harness)
    service = job_harness.service()
    first = _claim(job_harness, duration=10)

    assert first.job_id == job_id
    assert first.attempt == 1
    assert first.recovered is False
    assert (
        service.claim_next(
            worker_id="worker-2",
            lease_duration=timedelta(seconds=10),
        )
        is None
    )
    job_harness.clock.advance(seconds=5)
    heartbeat = service.heartbeat(
        first,
        lease_duration=timedelta(seconds=10),
    )
    assert heartbeat.fencing_token == first.fencing_token
    assert heartbeat.expires_at == job_harness.clock.now + timedelta(seconds=10)
    job_harness.clock.now = heartbeat.expires_at
    with pytest.raises(BackgroundJobLeaseLostError):
        service.heartbeat(
            heartbeat,
            lease_duration=timedelta(seconds=10),
        )


def test_claim_lease_window_starts_after_fencing_counter_lock(
    job_harness: JobHarness,
) -> None:
    _schedule(job_harness)
    timestamps = iter(
        (
            _NOW,
            _NOW + timedelta(seconds=1),
            _NOW + timedelta(seconds=20),
        )
    )
    service = BackgroundJobService(
        job_harness.factory,
        job_harness.store,
        clock=lambda: next(timestamps),
    )

    grant = service.claim_next(
        worker_id="contended-worker",
        lease_duration=timedelta(seconds=10),
    )

    assert grant is not None
    assert grant.expires_at == _NOW + timedelta(seconds=30)


def test_checkpoint_is_append_only_ordered_and_idempotent(
    job_harness: JobHarness,
) -> None:
    _schedule(job_harness)
    service = job_harness.service()
    grant = _claim(job_harness)
    first = service.checkpoint(
        grant,
        expected_version=0,
        idempotency_key="checkpoint:one",
        payload={"step": 1},
    )
    replay = service.checkpoint(
        grant,
        expected_version=0,
        idempotency_key="checkpoint:one",
        payload={"step": 1},
    )

    assert first.sequence == 1
    assert replay == type(replay)(
        checkpoint_id=first.checkpoint_id,
        sequence=1,
        replayed=True,
    )
    with pytest.raises(BackgroundJobConflictError, match="different progress"):
        service.checkpoint(
            grant,
            expected_version=0,
            idempotency_key="checkpoint:one",
            payload={"step": 2},
        )
    with pytest.raises(BackgroundJobConflictError, match="version changed"):
        service.checkpoint(
            grant,
            expected_version=0,
            idempotency_key="checkpoint:two",
            payload={"step": 2},
        )
    with job_harness.factory() as session:
        job = session.get(BackgroundJob, grant.job_id)
        checkpoints = tuple(
            session.scalars(
                select(BackgroundJobCheckpoint).where(
                    BackgroundJobCheckpoint.job_id == grant.job_id
                )
            )
        )
    assert job is not None and job.checkpoint == {"step": 1}
    assert job.checkpoint_version == 1
    assert len(checkpoints) == 1


def test_expired_takeover_recovers_checkpoint_and_fences_old_worker(
    job_harness: JobHarness,
) -> None:
    _schedule(job_harness)
    service = job_harness.service()
    old = _claim(job_harness, duration=5)
    service.checkpoint(
        old,
        expected_version=0,
        idempotency_key="checkpoint:durable",
        payload={"step": "prepared"},
    )
    job_harness.clock.advance(seconds=5)
    current = _claim(job_harness, worker="worker-2")

    assert current.recovered is True
    assert current.attempt == 2
    assert current.fencing_token > old.fencing_token
    assert current.checkpoint == {"step": "prepared"}
    assert current.checkpoint_version == 1
    for operation in (
        lambda: service.heartbeat(old, lease_duration=timedelta(seconds=10)),
        lambda: service.checkpoint(
            old,
            expected_version=1,
            idempotency_key="checkpoint:stale",
            payload={"step": "stale"},
        ),
        lambda: service.prepare_effect(
            old,
            effect_key="push",
            effect_type="git.push",
            request_payload={"branch": "task"},
        ),
        lambda: service.complete(old, expected_checkpoint_version=1),
    ):
        with pytest.raises(BackgroundJobLeaseLostError):
            operation()

    with job_harness.factory() as session:
        leases = tuple(
            session.scalars(
                select(BackgroundJobLease)
                .where(BackgroundJobLease.job_id == old.job_id)
                .order_by(BackgroundJobLease.attempt)
            )
        )
    assert [lease.attempt for lease in leases] == [1, 2]
    assert leases[0].release_reason == "SUPERSEDED"


def test_effect_intent_result_and_checkpoint_are_fenced_and_idempotent(
    job_harness: JobHarness,
) -> None:
    _schedule(job_harness)
    service = job_harness.service()
    grant = _claim(job_harness)
    prepared = service.prepare_effect(
        grant,
        effect_key="push",
        effect_type="git.push",
        request_payload={"branch": "task"},
    )
    replay = service.prepare_effect(
        grant,
        effect_key="push",
        effect_type="git.push",
        request_payload={"branch": "task"},
    )

    assert prepared.created is True
    assert replay.effect_id == prepared.effect_id
    assert replay.created is False
    assert replay.needs_reconciliation is True
    with pytest.raises(BackgroundJobConflictError, match="different request"):
        service.prepare_effect(
            grant,
            effect_key="push",
            effect_type="git.push",
            request_payload={"branch": "other"},
        )
    checkpoint = service.record_effect_result(
        grant,
        effect_id=prepared.effect_id,
        result=EffectExecutionResult(
            succeeded=True,
            payload={"remote_sha": "a" * 40},
        ),
        expected_checkpoint_version=0,
        checkpoint_idempotency_key="checkpoint:push",
        checkpoint_payload={"push": "complete"},
    )
    assert checkpoint.sequence == 1

    with job_harness.factory() as session:
        effect = session.get(BackgroundJobEffect, prepared.effect_id)
        job = session.get(BackgroundJob, grant.job_id)
    assert effect is not None and job is not None
    assert effect.status is BackgroundJobEffectStatus.SUCCEEDED
    assert effect.completion_fencing_token == grant.fencing_token
    assert job.checkpoint == {"push": "complete"}
    assert job.checkpoint_version == 1


def test_effect_provider_keys_do_not_collide_across_command_key_boundaries(
    job_harness: JobHarness,
) -> None:
    service = job_harness.service()
    task_id, _evidence_id = _create_task(job_harness)
    first_job = service.schedule(
        task_id=task_id,
        job_type="task-action",
        idempotency_key="a:b",
        input_payload={"operation": "first"},
    ).job_id
    second_job = service.schedule(
        task_id=task_id,
        job_type="task-action",
        idempotency_key="a",
        input_payload={"operation": "second"},
    ).job_id
    first = _claim(job_harness, worker="worker-1")
    second = _claim(job_harness, worker="worker-2")
    grants = {first.job_id: first, second.job_id: second}

    first_effect = service.prepare_effect(
        grants[first_job],
        effect_key="c",
        effect_type="git.push",
        request_payload={"branch": "first"},
    )
    second_effect = service.prepare_effect(
        grants[second_job],
        effect_key="b:c",
        effect_type="git.push",
        request_payload={"branch": "second"},
    )

    assert first_effect.idempotency_key != second_effect.idempotency_key


@dataclass(slots=True)
class FakeEffectExecutor:
    applied: dict[str, EffectExecutionResult]
    execute_calls: int = 0
    reconcile_calls: int = 0

    def execute(
        self,
        *,
        idempotency_key: str,
        effect_type: str,
        request_payload: Any,
    ) -> EffectExecutionResult:
        del effect_type, request_payload
        self.execute_calls += 1
        result = self.applied.get(idempotency_key)
        if result is None:
            result = EffectExecutionResult(
                succeeded=True,
                payload={"external": "applied"},
            )
            self.applied[idempotency_key] = result
        return result

    def reconcile(
        self,
        *,
        idempotency_key: str,
        effect_type: str,
        request_payload: Any,
    ) -> EffectExecutionResult | None:
        del effect_type, request_payload
        self.reconcile_calls += 1
        return self.applied.get(idempotency_key)


def test_restart_reconciles_prepared_effect_without_duplicate_execution(
    job_harness: JobHarness,
) -> None:
    _schedule(job_harness)
    service = job_harness.service()
    first = _claim(job_harness, duration=5)
    prepared = service.prepare_effect(
        first,
        effect_key="publish",
        effect_type="git.push",
        request_payload={"branch": "task"},
    )
    executor = FakeEffectExecutor(applied={})
    executor.execute(
        idempotency_key=prepared.idempotency_key,
        effect_type="git.push",
        request_payload={"branch": "task"},
    )

    job_harness.clock.advance(seconds=5)
    recovered = _claim(job_harness, worker="worker-restarted")
    context = LeasedJobContext(service, recovered)
    observed = context.perform_effect(
        effect_key="publish",
        effect_type="git.push",
        request_payload={"branch": "task"},
        executor=executor,
        checkpoint_idempotency_key="checkpoint:publish",
        checkpoint_payload={"publish": "complete"},
    )

    assert observed.succeeded is True
    assert executor.execute_calls == 1
    assert executor.reconcile_calls == 1
    assert context.grant.checkpoint == {"publish": "complete"}
    assert context.grant.checkpoint_version == 1


def test_ambiguous_prepared_effect_is_never_reissued(
    job_harness: JobHarness,
) -> None:
    _schedule(job_harness)
    service = job_harness.service()
    first = _claim(job_harness, duration=5)
    service.prepare_effect(
        first,
        effect_key="publish",
        effect_type="git.push",
        request_payload={"branch": "task"},
    )
    with pytest.raises(AmbiguousBackgroundJobEffectError, match="reconciled first"):
        service.prepare_effect(
            first,
            effect_key="next-effect",
            effect_type="artifact.upload",
            request_payload={"artifact": "result"},
        )
    with pytest.raises(AmbiguousBackgroundJobEffectError, match="reconciled first"):
        service.complete(first, expected_checkpoint_version=0)
    job_harness.clock.advance(seconds=5)
    recovered = _claim(job_harness, worker="worker-restarted")
    executor = FakeEffectExecutor(applied={})

    with pytest.raises(AmbiguousBackgroundJobEffectError):
        LeasedJobContext(service, recovered).perform_effect(
            effect_key="publish",
            effect_type="git.push",
            request_payload={"branch": "task"},
            executor=executor,
            checkpoint_idempotency_key="checkpoint:publish",
            checkpoint_payload={"publish": "complete"},
        )
    assert executor.execute_calls == 0
    assert executor.reconcile_calls == 1


@dataclass(slots=True)
class CapturingEffectExecutor:
    effect_type: str | None = None
    request_payload: dict[str, object] | None = None

    def execute(
        self,
        *,
        idempotency_key: str,
        effect_type: str,
        request_payload: Any,
    ) -> EffectExecutionResult:
        del idempotency_key
        self.effect_type = effect_type
        self.request_payload = dict(request_payload)
        return EffectExecutionResult(succeeded=True, payload={"applied": True})

    def reconcile(
        self,
        *,
        idempotency_key: str,
        effect_type: str,
        request_payload: Any,
    ) -> EffectExecutionResult | None:
        raise AssertionError(
            (idempotency_key, effect_type, request_payload),
        )


def test_effect_execution_uses_canonical_immutable_intent(
    job_harness: JobHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _schedule(job_harness)
    service = job_harness.service()
    context = LeasedJobContext(service, _claim(job_harness))
    request = {"branch": "task"}
    prepare = service.prepare_effect

    def prepare_then_mutate(*args: Any, **kwargs: Any) -> Any:
        prepared = prepare(*args, **kwargs)
        request["branch"] = "mutated-after-intent"
        return prepared

    monkeypatch.setattr(service, "prepare_effect", prepare_then_mutate)
    executor = CapturingEffectExecutor()
    context.perform_effect(
        effect_key="push",
        effect_type=" git.push ",
        request_payload=request,
        executor=executor,
        checkpoint_idempotency_key="checkpoint:canonical-effect",
        checkpoint_payload={"push": "complete"},
    )

    assert executor.effect_type == "git.push"
    assert executor.request_payload == {"branch": "task"}


def test_retry_is_persisted_bounded_and_exhausts(
    job_harness: JobHarness,
) -> None:
    _schedule(
        job_harness,
        policy=RetryPolicy(
            max_attempts=2,
            base_delay_seconds=2,
            max_delay_seconds=3,
        ),
    )
    service = job_harness.service()
    first = _claim(job_harness)
    retry = service.fail_attempt(
        first,
        error_code="DEPENDENCY_UNAVAILABLE",
        retryable=True,
    )

    assert retry.status is BackgroundJobStatus.QUEUED
    assert retry.next_attempt_at is not None
    assert retry.retry_delay is not None
    assert timedelta(0) <= retry.retry_delay <= timedelta(seconds=2)
    assert (
        service.claim_next(
            worker_id="worker-early",
            lease_duration=timedelta(seconds=30),
        )
        is None
    )
    job_harness.clock.now = retry.next_attempt_at
    second = _claim(job_harness, worker="worker-2")
    exhausted = service.fail_attempt(
        second,
        error_code="DEPENDENCY_UNAVAILABLE",
        retryable=True,
    )

    assert exhausted.status is BackgroundJobStatus.FAILED
    assert exhausted.exhausted is True
    assert (
        service.claim_next(
            worker_id="worker-3",
            lease_duration=timedelta(seconds=30),
        )
        is None
    )


def test_expired_final_attempt_is_terminalized_instead_of_stranded(
    job_harness: JobHarness,
) -> None:
    job_id = _schedule(
        job_harness,
        policy=RetryPolicy(max_attempts=1),
    )
    grant = _claim(job_harness, duration=5)
    job_harness.clock.advance(seconds=5)

    assert (
        job_harness.service().claim_next(
            worker_id="recovery-worker",
            lease_duration=timedelta(seconds=30),
        )
        is None
    )
    with job_harness.factory() as session:
        job = session.get(BackgroundJob, job_id)
        lease = session.get(BackgroundJobLease, grant.lease_id)
    assert job is not None and lease is not None
    assert job.status is BackgroundJobStatus.FAILED
    assert job.last_error_code == "LEASE_EXPIRED_ATTEMPTS_EXHAUSTED"
    assert lease.release_reason == "EXPIRED"
    assert lease.failure_code == "LEASE_EXPIRED_ATTEMPTS_EXHAUSTED"


def test_current_lease_can_transition_task_in_the_same_transaction(
    job_harness: JobHarness,
) -> None:
    task_id, evidence_id = _create_task(job_harness)
    service = job_harness.service()
    scheduled = service.schedule(
        task_id=task_id,
        job_type="task-action",
        idempotency_key="task-transition:1",
        input_payload={"transition": "briefing"},
    )
    grant = _claim(job_harness)
    assert grant.job_id == scheduled.job_id

    transitioned = service.transition_task(
        grant,
        transition_id=uuid4(),
        expected_state=TaskState.INTAKE,
        kind=TaskTransitionKind.START_BRIEFING,
        reason_code="JOB_STARTED_BRIEFING",
        evidence_ids=(evidence_id,),
    )

    assert transitioned.to_state is TaskState.BRIEFING
    with job_harness.factory() as session:
        task = session.get(Task, task_id)
        event = session.get(TaskEvent, transitioned.event_id)
        provenance = session.scalar(
            select(BackgroundJobTaskTransition).where(
                BackgroundJobTaskTransition.task_event_id == transitioned.event_id
            )
        )
    assert task is not None and task.state is TaskState.BRIEFING
    assert event is not None and provenance is not None
    assert provenance.job_id == grant.job_id
    assert provenance.lease_id == grant.lease_id
    assert provenance.fencing_token == grant.fencing_token


def test_sqlite_concurrent_claims_yield_exactly_one_lease(
    job_harness: JobHarness,
) -> None:
    _schedule(job_harness)
    service = job_harness.service()

    def claim(worker: str) -> JobLeaseGrant | None:
        return service.claim_next(
            worker_id=worker,
            lease_duration=timedelta(seconds=30),
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(claim, ("worker-1", "worker-2")))

    grants = [result for result in results if result is not None]
    assert len(grants) == 1
    with job_harness.factory() as session:
        lease_count = session.scalar(select(func.count()).select_from(BackgroundJobLease))
    assert lease_count == 1


def test_worker_dispatches_allowlisted_handler_and_completes(
    job_harness: JobHarness,
) -> None:
    job_id = _schedule(job_harness)
    handled: list[UUID] = []

    def handler(context: LeasedJobContext) -> dict[str, object]:
        handled.append(context.grant.job_id)
        return {"done": True}

    worker = DurableJobWorker(
        job_harness.service(),
        {"task-action": cast(BackgroundJobHandler, handler)},
        worker_id="worker-1",
    )

    assert worker.run_once() is WorkerRunOutcome.SUCCEEDED
    assert worker.run_once() is WorkerRunOutcome.IDLE
    assert handled == [job_id]
    with job_harness.factory() as session:
        job = session.get(BackgroundJob, job_id)
    assert job is not None and job.status is BackgroundJobStatus.SUCCEEDED
    assert job.checkpoint == {"done": True}


def test_worker_with_empty_handler_registry_does_not_claim_jobs(
    job_harness: JobHarness,
) -> None:
    job_id = _schedule(job_harness)
    worker = DurableJobWorker(
        job_harness.service(),
        {},
        worker_id="worker-unconfigured",
    )

    assert worker.run_once() is WorkerRunOutcome.IDLE
    with job_harness.factory() as session:
        job = session.get(BackgroundJob, job_id)
        lease_count = session.scalar(select(func.count()).select_from(BackgroundJobLease))
    assert job is not None and job.status is BackgroundJobStatus.QUEUED
    assert lease_count == 0


def test_worker_treats_lease_loss_while_recording_failure_as_fenced(
    job_harness: JobHarness,
) -> None:
    _schedule(job_harness)

    def handler(_context: LeasedJobContext) -> None:
        job_harness.clock.advance(seconds=30)
        raise RetryableBackgroundJobError("TEMPORARY_FAILURE")

    worker = DurableJobWorker(
        job_harness.service(),
        {"task-action": cast(BackgroundJobHandler, handler)},
        worker_id="worker-1",
        lease_duration=timedelta(seconds=30),
    )

    assert worker.run_once() is WorkerRunOutcome.LEASE_LOST


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (RetryableBackgroundJobError("TEMPORARY_FAILURE"), WorkerRunOutcome.RETRY_SCHEDULED),
        (TerminalBackgroundJobError("UNSAFE_REQUEST"), WorkerRunOutcome.FAILED),
    ],
)
def test_worker_classifies_handler_failures(
    job_harness: JobHarness,
    error: BackgroundJobError,
    expected: WorkerRunOutcome,
) -> None:
    _schedule(job_harness)

    def handler(_context: LeasedJobContext) -> None:
        raise error

    worker = DurableJobWorker(
        job_harness.service(),
        {"task-action": cast(BackgroundJobHandler, handler)},
        worker_id="worker-1",
    )
    assert worker.run_once() is expected


def test_worker_pause_requeues_without_consuming_attempt(
    job_harness: JobHarness,
) -> None:
    job_id = _schedule(job_harness, policy=RetryPolicy(max_attempts=1))
    calls = 0

    def handler(_context: LeasedJobContext) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise PausedBackgroundJobError("TASK_VALIDATION_PAUSED")

    worker = DurableJobWorker(
        job_harness.service(),
        {"task-action": cast(BackgroundJobHandler, handler)},
        worker_id="worker-1",
    )

    assert worker.run_once() is WorkerRunOutcome.RETRY_SCHEDULED
    with job_harness.factory() as session:
        job = session.get(BackgroundJob, job_id)
    assert job is not None
    assert job.status is BackgroundJobStatus.QUEUED
    assert job.attempt_count == 0
    assert job.last_error_code == "TASK_VALIDATION_PAUSED"

    assert worker.run_once() is WorkerRunOutcome.SUCCEEDED
    with job_harness.factory() as session:
        job = session.get(BackgroundJob, job_id)
        lease_attempts = tuple(
            session.scalars(
                select(BackgroundJobLease.attempt)
                .where(BackgroundJobLease.job_id == job_id)
                .order_by(BackgroundJobLease.attempt)
            )
        )
    assert job is not None
    assert job.status is BackgroundJobStatus.SUCCEEDED
    assert job.attempt_count == 1
    assert lease_attempts == (1, 2)


def test_worker_escalates_exhausted_dependency_outage(
    job_harness: JobHarness,
) -> None:
    job_id = _schedule(
        job_harness,
        policy=RetryPolicy(max_attempts=1),
    )

    def handler(_context: LeasedJobContext) -> None:
        raise DependencyOutageError(
            DependencyService.HOST,
            "HOST_UNAVAILABLE",
        )

    worker = DurableJobWorker(
        job_harness.service(),
        {"task-action": cast(BackgroundJobHandler, handler)},
        worker_id="worker-1",
    )

    assert worker.run_once() is WorkerRunOutcome.ESCALATED
    with job_harness.factory() as session:
        job = session.get(BackgroundJob, job_id)
        task = (
            None if job is None else session.get(Task, job.task_id)
        )
    assert job is not None and job.status is BackgroundJobStatus.FAILED
    assert task is not None and task.state is TaskState.ESCALATED
