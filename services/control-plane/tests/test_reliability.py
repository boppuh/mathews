from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from mathews_control_plane.approvals import (
    ApprovalService,
    BlockedOperation,
)
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.background_jobs import (
    BackgroundJobConflictError,
    BackgroundJobLeaseLostError,
    BackgroundJobService,
    EffectExecutionResult,
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
    ApprovalDecision,
    ApprovalRequest,
    ApprovalRequestType,
    ApprovalStatus,
    BackgroundJob,
    BackgroundJobEffect,
    BackgroundJobEffectStatus,
    BackgroundJobIgnoredResult,
    BackgroundJobLease,
    BackgroundJobStatus,
    BackgroundJobToolGrant,
    DependencyOutageAttempt,
    DependencyService,
    EvidenceRecord,
    OwnedHostProcess,
    OwnedHostProcessStatus,
    PolicyVersion,
    ReconciliationStatus,
    ReconciliationTarget,
    ReconciliationTargetKind,
    Task,
    TaskCancellation,
    TaskState,
)
from mathews_control_plane.reliability import (
    CancellationService,
    OwnedProcessIdentity,
    ProcessTerminationObservation,
    ReconciliationObservation,
    StartupRecoveryService,
)
from sqlalchemy import Engine, select

_NOW = datetime(2026, 7, 30, 14, 0, tzinfo=UTC)


@dataclass(slots=True)
class MutableClock:
    now: datetime = _NOW

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **changes: float) -> None:
        self.now += timedelta(**changes)


@dataclass(slots=True)
class ReliabilityHarness:
    engine: Engine
    factory: SessionFactory
    store: ArtifactStore
    clock: MutableClock

    def jobs(self) -> BackgroundJobService:
        return BackgroundJobService(
            self.factory,
            self.store,
            clock=self.clock,
        )

    def cancellations(self) -> CancellationService:
        return CancellationService(
            self.factory,
            self.store,
            clock=self.clock,
        )


@pytest.fixture
def reliability_harness(tmp_path: Path) -> Any:
    engine = create_database_engine(
        f"sqlite:///{tmp_path / 'reliability.sqlite3'}"
    )
    Base.metadata.create_all(engine)
    harness = ReliabilityHarness(
        engine=engine,
        factory=create_session_factory(engine),
        store=ArtifactStore(tmp_path / "artifacts"),
        clock=MutableClock(),
    )
    yield harness
    engine.dispose()


def _task(
    harness: ReliabilityHarness,
    *,
    state: TaskState = TaskState.INTAKE,
) -> UUID:
    with harness.factory.begin() as session:
        task = create_task_record(
            session,
            harness.store,
            repository="boppuh/mathews",
            base_revision="1" * 40,
            requester="local-user",
            raw_request="Exercise reliability semantics",
            summary="Exercise reliability",
            owner_id="local-user",
            actor_id="local-user",
        )
        task.state = state
        policy = session.scalar(
            select(PolicyVersion).where(
                PolicyVersion.lineage_key == "mvp",
                PolicyVersion.version == 1,
            )
        )
        if policy is None:
            session.add(
                PolicyVersion(
                    lineage_key="mvp",
                    version=1,
                    predecessor_id=None,
                    workflow_thresholds={},
                    approved_by="local-user",
                    approved_at=harness.clock.now,
                    owner_id=task.owner_id,
                    actor_id="local-user",
                    root_correlation_id=task.root_correlation_id,
                )
            )
        session.flush()
        return task.id


@dataclass(slots=True)
class FakeTerminator:
    calls: list[OwnedProcessIdentity] = field(default_factory=list)

    def terminate_owned(
        self,
        process: OwnedProcessIdentity,
        *,
        idempotency_key: str,
    ) -> ProcessTerminationObservation:
        assert idempotency_key.endswith(str(process.process_id))
        self.calls.append(process)
        return ProcessTerminationObservation(
            status=OwnedHostProcessStatus.TERMINATED,
            partial_output={"stderr": "cancelled", "stdout": "partial"},
        )


@dataclass(slots=True)
class FakeCleaner:
    calls: list[tuple[UUID, UUID, str]] = field(default_factory=list)

    def cleanup_owned(
        self,
        *,
        task_id: UUID,
        job_id: UUID,
        idempotency_key: str,
    ) -> dict[str, object]:
        self.calls.append((task_id, job_id, idempotency_key))
        return {"removed": ["derived-data"]}


def test_cancellation_fences_jobs_grants_and_late_results(
    reliability_harness: ReliabilityHarness,
) -> None:
    task_id = _task(reliability_harness, state=TaskState.IMPLEMENTING)
    jobs = reliability_harness.jobs()
    scheduled = jobs.schedule(
        task_id=task_id,
        job_type="implementation",
        idempotency_key="implementation:cancel",
        input_payload={"step": "edit"},
    )
    grant = jobs.claim_next(
        worker_id="worker-1",
        lease_duration=timedelta(seconds=30),
    )
    assert grant is not None
    tool_grant = jobs.issue_tool_grant(
        grant,
        grant_key="hermes:edit",
        capability_scope={"operations": ["edit"]},
    )
    process = jobs.register_owned_process(
        grant,
        host_id="local-host",
        pid=501,
        process_group_id=501,
        birth_token="birth:501",
        ownership_nonce=uuid4(),
    )
    effect = jobs.prepare_effect(
        grant,
        effect_key="write",
        effect_type="host.write",
        request_payload={"path": "Sources/App.swift"},
    )
    terminator = FakeTerminator()
    cleaner = FakeCleaner()
    cancellation_id = uuid4()

    result = reliability_harness.cancellations().cancel_task(
        task_id,
        cancellation_id=cancellation_id,
        expected_state=TaskState.IMPLEMENTING,
        reason_code="USER_CANCELLED",
        terminator=terminator,
        cleaner=cleaner,
    )

    assert result.task_state is TaskState.CANCELLED
    assert result.revoked_lease_count == 1
    assert result.revoked_tool_grant_count == 1
    assert result.cleanup_complete is True
    assert len(terminator.calls) == 1
    assert len(cleaner.calls) == 1
    with reliability_harness.factory() as session:
        task = session.get(Task, task_id)
        job = session.get(BackgroundJob, scheduled.job_id)
        lease = session.get(BackgroundJobLease, grant.lease_id)
        stored_grant = session.get(BackgroundJobToolGrant, tool_grant.grant_id)
        stored_process = session.get(OwnedHostProcess, process.process_id)
        cancellation = session.get(TaskCancellation, cancellation_id)
        target = session.scalar(
            select(ReconciliationTarget).where(
                ReconciliationTarget.target_key
                == f"process:{process.process_id}"
            )
        )
    assert task is not None and task.state is TaskState.CANCELLED
    assert job is not None and job.status is BackgroundJobStatus.CANCELLED
    assert job.cancellation_requested_at is not None
    assert job.cancellation_requested_at.replace(
        tzinfo=UTC
    ) == reliability_harness.clock.now
    assert lease is not None and lease.release_reason == "CANCELLED"
    assert lease.cancellation_acknowledged_at is not None
    assert lease.cancellation_acknowledged_at.replace(
        tzinfo=UTC
    ) == reliability_harness.clock.now
    assert stored_grant is not None and stored_grant.revoked_at is not None
    assert stored_process is not None
    assert stored_process.status is OwnedHostProcessStatus.TERMINATED
    assert stored_process.partial_evidence_id is not None
    assert cancellation is not None
    assert cancellation.cleanup_completed_at is not None
    assert target is not None
    assert target.status is ReconciliationStatus.CANCELLED

    with pytest.raises(BackgroundJobLeaseLostError):
        jobs.complete(grant, expected_checkpoint_version=0)
    ignored = jobs.record_ignored_result(
        grant,
        idempotency_key="implementation:cancel:late-result",
        effect_id=effect.effect_id,
        result=EffectExecutionResult(
            succeeded=True,
            payload={
                "api_token": "sensitive-value",
                "bytes_written": 10,
            },
        ),
    )
    assert ignored.reason_code == "CANCELLED"
    with reliability_harness.factory() as session:
        stored_ignored = session.get(
            BackgroundJobIgnoredResult,
            ignored.ignored_result_id,
        )
        unchanged_effect = session.get(BackgroundJobEffect, effect.effect_id)
    assert stored_ignored is not None
    assert unchanged_effect is not None
    assert unchanged_effect.status is BackgroundJobEffectStatus.PENDING

    replay = reliability_harness.cancellations().cancel_task(
        task_id,
        cancellation_id=cancellation_id,
        expected_state=TaskState.IMPLEMENTING,
        reason_code="USER_CANCELLED",
    )
    assert replay.replayed is True
    assert replay.cleanup_complete is True
    schedule_replay = jobs.schedule(
        task_id=task_id,
        job_type="implementation",
        idempotency_key="implementation:cancel",
        input_payload={"step": "edit"},
    )
    assert schedule_replay.replayed is True
    with pytest.raises(BackgroundJobConflictError, match="not runnable"):
        jobs.schedule(
            task_id=task_id,
            job_type="implementation",
            idempotency_key="implementation:after-cancel",
            input_payload={"step": "edit"},
        )


def test_outage_exhaustion_escalates_and_retry_creates_new_job_generation(
    reliability_harness: ReliabilityHarness,
) -> None:
    task_id = _task(reliability_harness, state=TaskState.IMPLEMENTING)
    jobs = reliability_harness.jobs()
    scheduled = jobs.schedule(
        task_id=task_id,
        job_type="github-publish",
        idempotency_key="github-publish:1",
        input_payload={"branch": "task"},
        retry_policy=RetryPolicy(
            max_attempts=2,
            base_delay_seconds=1,
            max_delay_seconds=2,
        ),
    )
    first = jobs.claim_next(
        worker_id="worker-1",
        lease_duration=timedelta(seconds=30),
    )
    assert first is not None
    jobs.checkpoint(
        first,
        expected_version=0,
        idempotency_key="github-publish:checkpoint",
        payload={"local_head": "a" * 40},
    )
    retry = jobs.fail_dependency_attempt(
        first,
        service=DependencyService.GITHUB,
        error_code="GITHUB_UNAVAILABLE",
    )
    assert retry.status is BackgroundJobStatus.QUEUED
    assert retry.next_attempt_at is not None
    reliability_harness.clock.now = retry.next_attempt_at
    second = jobs.claim_next(
        worker_id="worker-2",
        lease_duration=timedelta(seconds=30),
    )
    assert second is not None

    exhausted = jobs.fail_dependency_attempt(
        second,
        service=DependencyService.GITHUB,
        error_code="GITHUB_UNAVAILABLE",
    )

    assert exhausted.status is BackgroundJobStatus.FAILED
    assert exhausted.exhausted is True
    assert exhausted.escalation_request_id is not None
    with reliability_harness.factory() as session:
        task = session.get(Task, task_id)
        request = session.get(
            ApprovalRequest,
            exhausted.escalation_request_id,
        )
        attempts = tuple(
            session.scalars(
                select(DependencyOutageAttempt)
                .where(DependencyOutageAttempt.job_id == scheduled.job_id)
                .order_by(DependencyOutageAttempt.attempt)
            )
        )
    assert task is not None and task.state is TaskState.ESCALATED
    assert request is not None
    assert request.status is ApprovalStatus.PENDING
    assert request.options == ["RETRY", "ABANDON", "CANCEL"]
    assert [
        cast(dict[str, object], entry)["attempt"]
        for entry in request.retry_history
    ] == [1, 2]
    assert len(attempts) == 2
    assert attempts[-1].approval_request_id == request.id

    decision_id = uuid4()
    decision = ApprovalService(
        reliability_harness.factory,
        reliability_harness.store,
        clock=reliability_harness.clock,
    ).decide(
        request.id,
        decision_id=decision_id,
        decision=ApprovalDecision.RETRY,
        actor_id="local-user",
    )
    assert decision.task_state is TaskState.IMPLEMENTING
    resolved = jobs.reconcile_outage_decisions()
    assert resolved == (attempts[-1].id,)
    with reliability_harness.factory() as session:
        outage = session.get(DependencyOutageAttempt, attempts[-1].id)
        resumed = (
            None
            if outage is None or outage.resumed_job_id is None
            else session.get(BackgroundJob, outage.resumed_job_id)
        )
    assert outage is not None
    assert outage.decision_id == decision_id
    assert resumed is not None
    assert resumed.id != scheduled.job_id
    assert resumed.status is BackgroundJobStatus.QUEUED
    assert resumed.checkpoint == {"local_head": "a" * 40}
    assert resumed.parent_correlation_id == scheduled.job_id
    assert jobs.reconcile_outage_decisions() == ()


def test_stale_outage_recovery_gets_a_fresh_deterministic_expiry(
    reliability_harness: ReliabilityHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task_id = _task(reliability_harness, state=TaskState.IMPLEMENTING)
    jobs = reliability_harness.jobs()
    scheduled = jobs.schedule(
        task_id=task_id,
        job_type="stale-outage",
        idempotency_key="stale-outage:1",
        input_payload={"service": "github"},
        retry_policy=RetryPolicy(max_attempts=1),
    )
    grant = jobs.claim_next(
        worker_id="worker-1",
        lease_duration=timedelta(seconds=30),
    )
    assert grant is not None
    original_reconcile = jobs.reconcile_outage_escalation
    monkeypatch.setattr(
        jobs,
        "reconcile_outage_escalation",
        lambda _job_id: None,
    )
    jobs.fail_dependency_attempt(
        grant,
        service=DependencyService.GITHUB,
        error_code="GITHUB_UNAVAILABLE",
    )
    monkeypatch.setattr(
        jobs,
        "reconcile_outage_escalation",
        original_reconcile,
    )
    reliability_harness.clock.advance(days=31)

    request_id = jobs.reconcile_outage_escalation(scheduled.job_id)
    replay_id = jobs.reconcile_outage_escalation(scheduled.job_id)

    assert request_id is not None
    assert replay_id == request_id
    with reliability_harness.factory() as session:
        request = session.get(ApprovalRequest, request_id)
    assert request is not None
    assert request.expires_at is not None
    assert request.expires_at.replace(tzinfo=UTC) == (
        reliability_harness.clock.now + timedelta(days=30)
    )


def test_cancellation_closes_pending_approval_before_resource_fence(
    reliability_harness: ReliabilityHarness,
) -> None:
    task_id = _task(reliability_harness, state=TaskState.IMPLEMENTING)
    with reliability_harness.factory() as session:
        evidence_id = session.scalar(
            select(EvidenceRecord.id).where(
                EvidenceRecord.task_id == task_id
            )
        )
    assert evidence_id is not None
    request_id = uuid4()
    ApprovalService(
        reliability_harness.factory,
        reliability_harness.store,
        clock=reliability_harness.clock,
    ).request(
        task_id,
        request_id=request_id,
        expected_state=TaskState.IMPLEMENTING,
        request_type=ApprovalRequestType.UNSAFE_ACTION,
        reason_code="UNSAFE_ACTION",
        subject_type="BLOCKED_OPERATION",
        subject_id=None,
        blocked_operation=BlockedOperation(
            operation_name="host.workspace.delete",
            idempotency_key="workspace-delete:1",
            input_fingerprint="a" * 64,
            checkpoint_evidence_id=evidence_id,
        ),
        evidence_ids=(evidence_id,),
        expires_at=reliability_harness.clock.now + timedelta(days=1),
    )

    cancellation = reliability_harness.cancellations().cancel_task(
        task_id,
        cancellation_id=uuid4(),
        expected_state=TaskState.ESCALATED,
        reason_code="USER_CANCELLED",
    )

    assert cancellation.task_state is TaskState.CANCELLED
    with reliability_harness.factory() as session:
        request = session.get(ApprovalRequest, request_id)
    assert request is not None
    assert request.status is ApprovalStatus.CANCELLED
    assert request.decision == ApprovalDecision.CANCEL.value


@pytest.mark.parametrize(
    ("decision", "expected_task_state"),
    [
        (ApprovalDecision.CANCEL, TaskState.CANCELLED),
        (ApprovalDecision.ABANDON, TaskState.FAILED),
    ],
)
def test_outage_terminal_decision_fences_sibling_work(
    reliability_harness: ReliabilityHarness,
    decision: ApprovalDecision,
    expected_task_state: TaskState,
) -> None:
    task_id = _task(reliability_harness, state=TaskState.IMPLEMENTING)
    jobs = reliability_harness.jobs()
    outage_job = jobs.schedule(
        task_id=task_id,
        job_type="github-outage",
        idempotency_key="github-outage:cancel",
        input_payload={"operation": "publish"},
        retry_policy=RetryPolicy(max_attempts=1),
    )
    grant = jobs.claim_next(
        worker_id="worker-1",
        lease_duration=timedelta(seconds=30),
        job_types=("github-outage",),
    )
    assert grant is not None and grant.job_id == outage_job.job_id
    sibling = jobs.schedule(
        task_id=task_id,
        job_type="sibling-work",
        idempotency_key="sibling-work:1",
        input_payload={"operation": "continue"},
    )
    exhausted = jobs.fail_dependency_attempt(
        grant,
        service=DependencyService.GITHUB,
        error_code="GITHUB_UNAVAILABLE",
    )
    assert exhausted.escalation_request_id is not None
    assert (
        jobs.claim_next(
            worker_id="worker-during-escalation",
            lease_duration=timedelta(seconds=30),
            job_types=("sibling-work",),
        )
        is None
    )
    decision_id = uuid4()
    ApprovalService(
        reliability_harness.factory,
        reliability_harness.store,
        clock=reliability_harness.clock,
    ).decide(
        exhausted.escalation_request_id,
        decision_id=decision_id,
        decision=decision,
        actor_id="local-user",
    )

    assert len(jobs.reconcile_outage_decisions()) == 1
    with reliability_harness.factory() as session:
        sibling_job = session.get(BackgroundJob, sibling.job_id)
        cancellation = session.scalar(
            select(TaskCancellation).where(
                TaskCancellation.task_id == task_id
            )
        )
        task = session.get(Task, task_id)
    assert sibling_job is not None
    assert sibling_job.status is BackgroundJobStatus.CANCELLED
    assert cancellation is not None
    assert cancellation.id == decision_id
    assert task is not None and task.state is expected_task_state


@dataclass(slots=True)
class CurrentAdapter:
    calls: list[tuple[ReconciliationTargetKind, str]] = field(
        default_factory=list
    )

    def reconcile(
        self,
        *,
        kind: ReconciliationTargetKind,
        target_key: str,
        expected_payload: Mapping[str, object],
    ) -> ReconciliationObservation:
        self.calls.append((kind, target_key))
        return ReconciliationObservation(
            status=ReconciliationStatus.CURRENT,
            observed_payload=dict(expected_payload),
        )


def test_live_pending_target_does_not_block_sibling_job(
    reliability_harness: ReliabilityHarness,
) -> None:
    task_id = _task(reliability_harness)
    jobs = reliability_harness.jobs()
    first = jobs.schedule(
        task_id=task_id,
        job_type="live-target",
        idempotency_key="live-target:1",
        input_payload={"step": 1},
    )
    first_grant = jobs.claim_next(
        worker_id="worker-1",
        lease_duration=timedelta(seconds=30),
    )
    assert first_grant is not None
    assert first_grant.job_id == first.job_id
    jobs.register_reconciliation_target(
        first_grant,
        kind=ReconciliationTargetKind.HERMES_RUN,
        target_key="hermes:live",
        expected_payload={"run_id": "live"},
    )
    second = jobs.schedule(
        task_id=task_id,
        job_type="sibling",
        idempotency_key="live-target:2",
        input_payload={"step": 2},
    )

    second_grant = jobs.claim_next(
        worker_id="worker-2",
        lease_duration=timedelta(seconds=30),
    )

    assert second_grant is not None
    assert second_grant.job_id == second.job_id


def test_startup_recovers_expired_lease_and_all_external_target_kinds(
    reliability_harness: ReliabilityHarness,
) -> None:
    task_id = _task(reliability_harness)
    jobs = reliability_harness.jobs()
    scheduled = jobs.schedule(
        task_id=task_id,
        job_type="restart",
        idempotency_key="restart:1",
        input_payload={"step": "external"},
        retry_policy=RetryPolicy(max_attempts=2),
    )
    grant = jobs.claim_next(
        worker_id="worker-1",
        lease_duration=timedelta(seconds=5),
    )
    assert grant is not None
    for kind in ReconciliationTargetKind:
        jobs.register_reconciliation_target(
            grant,
            kind=kind,
            target_key=f"{kind.value.lower()}:1",
            expected_payload={"cursor": kind.value},
        )
    reliability_harness.clock.advance(seconds=5)
    assert (
        jobs.claim_next(
            worker_id="premature-worker",
            lease_duration=timedelta(seconds=5),
        )
        is None
    )
    adapter = CurrentAdapter()
    adapters = {kind: adapter for kind in ReconciliationTargetKind}

    recovery = StartupRecoveryService(
        reliability_harness.factory,
        reliability_harness.store,
        clock=reliability_harness.clock,
    ).recover(adapters=adapters)

    assert recovery.recovered_job_ids == (scheduled.job_id,)
    assert len(recovery.reconciled_target_ids) == len(
        ReconciliationTargetKind
    )
    assert [kind for kind, _key in adapter.calls] == list(
        ReconciliationTargetKind
    )
    with reliability_harness.factory() as session:
        job = session.get(BackgroundJob, scheduled.job_id)
        lease = session.get(BackgroundJobLease, grant.lease_id)
        targets = tuple(
            session.scalars(
                select(ReconciliationTarget).order_by(
                    ReconciliationTarget.kind
                )
            )
        )
    assert job is not None and job.status is BackgroundJobStatus.QUEUED
    assert job.completed_at is None
    assert lease is not None and lease.release_reason == "EXPIRED"
    assert all(
        target.status is ReconciliationStatus.CURRENT
        and target.reconciliation_version == 1
        for target in targets
    )


def test_startup_recovery_drains_every_bounded_page(
    reliability_harness: ReliabilityHarness,
) -> None:
    jobs = reliability_harness.jobs()
    scheduled_ids: list[UUID] = []
    for index in range(2):
        task_id = _task(reliability_harness)
        scheduled = jobs.schedule(
            task_id=task_id,
            job_type="paged-restart",
            idempotency_key=f"paged-restart:{index}",
            input_payload={"index": index},
            retry_policy=RetryPolicy(max_attempts=2),
        )
        grant = jobs.claim_next(
            worker_id=f"worker-{index}",
            lease_duration=timedelta(seconds=5),
        )
        assert grant is not None
        jobs.register_reconciliation_target(
            grant,
            kind=ReconciliationTargetKind.HERMES_RUN,
            target_key=f"hermes:paged:{index}",
            expected_payload={"index": index},
        )
        scheduled_ids.append(scheduled.job_id)
    reliability_harness.clock.advance(seconds=5)
    adapter = CurrentAdapter()

    recovery = StartupRecoveryService(
        reliability_harness.factory,
        reliability_harness.store,
        clock=reliability_harness.clock,
    ).recover(
        adapters={ReconciliationTargetKind.HERMES_RUN: adapter},
        limit=1,
    )

    assert set(recovery.recovered_job_ids) == set(scheduled_ids)
    assert len(recovery.reconciled_target_ids) == 2
    assert len(adapter.calls) == 2


def test_adapterless_startup_fails_closed_without_reclaiming_job(
    reliability_harness: ReliabilityHarness,
) -> None:
    task_id = _task(reliability_harness)
    jobs = reliability_harness.jobs()
    scheduled = jobs.schedule(
        task_id=task_id,
        job_type="adapterless-restart",
        idempotency_key="adapterless-restart:1",
        input_payload={"step": "external"},
        retry_policy=RetryPolicy(max_attempts=2),
    )
    grant = jobs.claim_next(
        worker_id="worker-1",
        lease_duration=timedelta(seconds=5),
    )
    assert grant is not None
    jobs.register_reconciliation_target(
        grant,
        kind=ReconciliationTargetKind.HERMES_RUN,
        target_key="hermes:adapterless",
        expected_payload={"run_id": "run-1"},
    )
    reliability_harness.clock.advance(seconds=5)

    recovery = StartupRecoveryService(
        reliability_harness.factory,
        reliability_harness.store,
        clock=reliability_harness.clock,
    ).recover()

    assert recovery.recovered_job_ids == (scheduled.job_id,)
    with reliability_harness.factory() as session:
        target = session.scalar(select(ReconciliationTarget))
    assert target is not None
    assert target.status is ReconciliationStatus.RETRY_REQUIRED
    assert (
        jobs.claim_next(
            worker_id="worker-2",
            lease_duration=timedelta(seconds=5),
        )
        is None
    )
