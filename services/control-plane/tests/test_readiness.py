from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import mathews_control_plane.readiness as readiness_module
import pytest
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.database import (
    Base,
    SessionFactory,
    create_database_engine,
    create_session_factory,
)
from mathews_control_plane.domain_models import (
    PolicyVersion,
    Task,
    TaskEvent,
    TaskState,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
)
from mathews_control_plane.github_webhooks import (
    GITHUB_CHECK_UPDATED_EVENT,
    GITHUB_PR_BOUND_EVENT,
    GITHUB_PR_HEAD_CHANGED_EVENT,
    GITHUB_REVIEW_UPDATED_EVENT,
)
from mathews_control_plane.readiness import (
    HANDOFF_ACKNOWLEDGEMENT,
    ReadinessReconcileStatus,
    ReadinessService,
    _fingerprint,
    _github_facts,
    _GitHubFacts,
    _ReadinessAssessment,
    _repairs_authorized,
)
from mathews_control_plane.review_resolution import (
    REVIEW_RESOLUTION_SCHEMA_VERSION,
    ReviewClassification,
    ReviewDisposition,
    ReviewRisk,
)
from mathews_control_plane.task_state_machine import (
    DraftPrGateFacts,
    TaskTransitionError,
    TaskTransitionKind,
)
from sqlalchemy import Engine, select

_NOW = datetime(2026, 8, 11, 14, 0, tzinfo=UTC)
_HEAD = "a" * 40
_TREE = "b" * 40


@dataclass(slots=True)
class ReadinessHarness:
    engine: Engine
    factory: SessionFactory
    store: ArtifactStore
    task_id: UUID
    trigger_id: UUID


@pytest.fixture
def readiness_harness(tmp_path: Path) -> Iterator[ReadinessHarness]:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'readiness.sqlite3'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    store = ArtifactStore(tmp_path / "artifacts")
    task_id = uuid4()
    trigger_id = uuid4()
    with factory.begin() as session:
        task = Task(
            id=task_id,
            repository="boppuh/mathews",
            base_revision="0" * 40,
            requester="local-user",
            raw_request="evidence://test",
            summary="Readiness handoff",
            state=TaskState.PR_ACTIVE,
            retry_count=0,
            owner_id="local-user",
            actor_id="control-plane",
            root_correlation_id=task_id,
            causation_id=task_id,
        )
        policy = PolicyVersion(
            lineage_key="mvp",
            version=1,
            predecessor_id=None,
            workflow_thresholds={},
            approved_by="local-user",
            approved_at=_NOW,
            rollback_policy_version_id=None,
            owner_id="local-user",
            actor_id="control-plane",
            root_correlation_id=task_id,
        )
        session.add_all((task, policy))
        session.flush()
        session.add(
            TaskEvent(
                task_id=task_id,
                sequence=1,
                event_type="TASK_STATE_TRANSITION",
                payload={"schema_version": 1, "kind": "OPEN_VERIFIED_DRAFT_PR"},
                occurred_at=_NOW,
                transition_id=uuid4(),
                transition_fingerprint="f" * 64,
                transition_kind=TaskTransitionKind.OPEN_VERIFIED_DRAFT_PR.value,
                transition_from_state=TaskState.VALIDATING,
                transition_to_state=TaskState.PR_ACTIVE,
                transition_reason_code="VERIFIED_DRAFT_PR_OPENED",
                policy_lineage_key=policy.lineage_key,
                policy_version_id=policy.id,
                gate_head_sha=_HEAD,
                owner_id=task.owner_id,
                actor_id="control-plane",
                root_correlation_id=task.root_correlation_id,
                causation_id=task.id,
            )
        )
        session.add(
            TaskEvent(
                id=trigger_id,
                task_id=task_id,
                sequence=2,
                event_type=GITHUB_CHECK_UPDATED_EVENT,
                payload={"schema_version": 1, "head_sha": _HEAD},
                occurred_at=_NOW,
                owner_id=task.owner_id,
                actor_id="github-webhook",
                root_correlation_id=task.root_correlation_id,
                causation_id=task.id,
            )
        )
    try:
        yield ReadinessHarness(engine, factory, store, task_id, trigger_id)
    finally:
        engine.dispose()


def _draft_facts() -> DraftPrGateFacts:
    return DraftPrGateFacts(
        current_head_sha=_HEAD,
        validation_commit_sha=_HEAD,
        local_branch_sha=_HEAD,
        remote_branch_sha=_HEAD,
        pull_request_head_sha=_HEAD,
        validation_passed=True,
        required_artifacts_present=True,
        branch_clean=True,
        pull_request_is_draft=True,
        no_unresolved_approval=True,
        cancellation_clear=True,
    )


def _github(*, ci: bool = True, reviews: bool = True) -> _GitHubFacts:
    return _GitHubFacts(
        uuid4(),
        42,
        "codex/task",
        _HEAD,
        ("verify",),
        ci,
        reviews,
        True,
        (),
        (("verify", "PASSED" if ci else "FAILED"),),
        0 if reviews else 1,
        0,
    )


def _assessment(task_id: UUID, *, ready: bool = True) -> _ReadinessAssessment:
    return _ReadinessAssessment(
        task_id,
        uuid4(),
        _draft_facts(),
        _github(ci=ready),
        True,
        () if ready else ("REQUIRED_CI_NOT_GREEN",),
    )


def _event(
    sequence: int,
    event_type: str,
    payload: dict[str, object],
) -> TaskEvent:
    return TaskEvent(
        id=uuid4(),
        task_id=uuid4(),
        sequence=sequence,
        event_type=event_type,
        payload=payload,
        occurred_at=_NOW,
        owner_id="local-user",
        actor_id="github-webhook",
        root_correlation_id=uuid4(),
    )


def _github_event_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "pull_request_number": 42,
        "task_branch": "codex/task",
        "head_sha": _HEAD,
        "source_updated_at": _NOW.isoformat(),
    }
    payload.update(overrides)
    return payload


def test_github_facts_require_every_exact_head_check_and_no_blocking_review() -> None:
    events = (
        _event(
            1,
            GITHUB_PR_BOUND_EVENT,
            {
                **_github_event_payload(),
                "required_checks": ["lint", "test"],
            },
        ),
        _event(
            2,
            GITHUB_CHECK_UPDATED_EVENT,
            _github_event_payload(
                resource_type="check_run",
                resource_id="1:lint",
                resource_label="lint",
                state="PASSED",
            ),
        ),
        _event(
            3,
            GITHUB_CHECK_UPDATED_EVENT,
            _github_event_payload(
                resource_type="check_run",
                resource_id="1:test",
                resource_label="test",
                state="NEUTRAL",
            ),
        ),
    )

    ready = _github_facts(events)
    blocked = _github_facts(
        (*events, _event(4, GITHUB_REVIEW_UPDATED_EVENT, _github_event_payload(
            resource_type="review", resource_id="reviewer", state="CHANGES_REQUESTED"
        )))
    )

    assert ready.required_ci_green
    assert ready.no_blocking_review
    assert not blocked.no_blocking_review
    assert blocked.blocking_reviews == 1


def test_head_change_discards_prior_check_success() -> None:
    changed = "c" * 40
    facts = _github_facts(
        (
            _event(
                1,
                GITHUB_PR_BOUND_EVENT,
                {**_github_event_payload(), "required_checks": ["verify"]},
            ),
            _event(
                2,
                GITHUB_CHECK_UPDATED_EVENT,
                _github_event_payload(
                    resource_type="check_run",
                    resource_id="verify",
                    resource_label="verify",
                    state="PASSED",
                ),
            ),
            _event(
                3,
                GITHUB_PR_HEAD_CHANGED_EVENT,
                _github_event_payload(
                    head_sha=changed,
                    resource_type="pull_request_head",
                    resource_id="42",
                ),
            ),
        )
    )

    assert facts.head_sha == changed
    assert not facts.required_ci_green


def test_check_projection_uses_authoritative_update_time_across_runs() -> None:
    earlier = datetime(2026, 8, 11, 13, 0, tzinfo=UTC).isoformat()
    later = datetime(2026, 8, 11, 14, 0, tzinfo=UTC).isoformat()
    facts = _github_facts(
        (
            _event(
                1,
                GITHUB_PR_BOUND_EVENT,
                {**_github_event_payload(), "required_checks": ["verify"]},
            ),
            _event(
                2,
                GITHUB_CHECK_UPDATED_EVENT,
                _github_event_payload(
                    resource_type="check_run",
                    resource_id="new-suite:verify",
                    resource_label="verify",
                    state="QUEUED",
                    source_updated_at=later,
                ),
            ),
            _event(
                3,
                GITHUB_CHECK_UPDATED_EVENT,
                _github_event_payload(
                    resource_type="check_run",
                    resource_id="old-suite:verify",
                    resource_label="verify",
                    state="PASSED",
                    source_updated_at=earlier,
                ),
            ),
        )
    )

    assert facts.check_states == (("verify", "QUEUED"),)
    assert not facts.required_ci_green


def test_commented_review_does_not_clear_an_outstanding_change_request() -> None:
    facts = _github_facts(
        (
            _event(
                1,
                GITHUB_PR_BOUND_EVENT,
                {**_github_event_payload(), "required_checks": ["verify"]},
            ),
            _event(
                2,
                GITHUB_REVIEW_UPDATED_EVENT,
                _github_event_payload(
                    resource_type="review",
                    resource_id="reviewer-1",
                    state="CHANGES_REQUESTED",
                ),
            ),
            _event(
                3,
                GITHUB_REVIEW_UPDATED_EVENT,
                _github_event_payload(
                    resource_type="review",
                    resource_id="reviewer-1",
                    state="COMMENTED",
                ),
            ),
        )
    )

    assert facts.blocking_reviews == 1
    assert not facts.no_blocking_review


@pytest.mark.parametrize(
    ("source_disposition", "correction_disposition"),
    [
        (ReviewDisposition.INFORMATIONAL, ReviewDisposition.ACTIONABLE),
        (ReviewDisposition.ACTIONABLE, ReviewDisposition.INFORMATIONAL),
    ],
)
def test_corrected_review_assessments_never_satisfy_readiness(
    readiness_harness: ReadinessHarness,
    source_disposition: ReviewDisposition,
    correction_disposition: ReviewDisposition,
) -> None:
    review_event_id = uuid4()
    classification = ReviewClassification(
        disposition=source_disposition,
        category="review",
        action="code.edit",
        risk=ReviewRisk.LOW,
        proposed_paths=("service.py",),
        rationale="Test classification",
    )
    unsigned: dict[str, object] = {
        "schema_version": REVIEW_RESOLUTION_SCHEMA_VERSION,
        "task_id": str(readiness_harness.task_id),
        "task_event_id": str(review_event_id),
        "original_head_sha": _HEAD,
        "classification": classification.model_dump(mode="json"),
    }
    fingerprint = _fingerprint(unsigned)
    payload = {**unsigned, "assessment_fingerprint": fingerprint}
    assessment_id = uuid5(
        NAMESPACE_URL,
        f"mathews:review-assessment:{review_event_id}:{fingerprint}",
    )
    with readiness_harness.factory.begin() as session:
        task = session.get_one(Task, readiness_harness.task_id)
        source = capture_evidence(
            session,
            readiness_harness.store,
            payload=payload,
            media_type="application/json",
            source_kind=EvidenceSourceKind.RESULT,
            evidence_type="review-resolution-assessment",
            origin="control-plane:review-resolution",
            access_classification=EvidenceAccessClass.TASK_OWNER,
            retention_policy=EvidenceRetentionClass.AUDIT,
            owner_id=task.owner_id,
            actor_id="control-plane",
            root_correlation_id=task.root_correlation_id,
            task_id=task.id,
            causation_id=review_event_id,
            evidence_id=assessment_id,
            captured_at=_NOW,
        )
        source_id = source.record.id

    with readiness_harness.factory() as session:
        initially_authorized = _repairs_authorized(
            session,
            readiness_harness.store,
            session.get_one(Task, readiness_harness.task_id),
            current_head=_HEAD,
            open_review_event_ids=(review_event_id,),
        )
    assert initially_authorized is (
        source_disposition is ReviewDisposition.INFORMATIONAL
    )

    with readiness_harness.factory.begin() as session:
        task = session.get_one(Task, readiness_harness.task_id)
        corrected = {
            **payload,
            "classification": {
                **classification.model_dump(mode="json"),
                "disposition": correction_disposition.value,
            },
        }
        capture_evidence(
            session,
            readiness_harness.store,
            payload=corrected,
            media_type="application/json",
            source_kind=EvidenceSourceKind.RESULT,
            evidence_type="review-resolution-assessment",
            origin="local-user:correction",
            access_classification=EvidenceAccessClass.TASK_OWNER,
            retention_policy=EvidenceRetentionClass.AUDIT,
            owner_id=task.owner_id,
            actor_id=task.owner_id,
            root_correlation_id=task.root_correlation_id,
            task_id=task.id,
            causation_id=source_id,
            correction_of_id=source_id,
            captured_at=_NOW,
        )

    with readiness_harness.factory() as session:
        assert not _repairs_authorized(
            session,
            readiness_harness.store,
            session.get_one(Task, readiness_harness.task_id),
            current_head=_HEAD,
            open_review_event_ids=(review_event_id,),
        )


def test_reconcile_marks_ready_then_invalidates_on_current_failure(
    readiness_harness: ReadinessHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = [_assessment(readiness_harness.task_id)]
    monkeypatch.setattr(
        readiness_module,
        "_assess",
        lambda *_args, **_kwargs: current[0],
    )
    service = ReadinessService(
        readiness_harness.factory,
        readiness_harness.store,
        clock=lambda: _NOW,
    )

    ready = service.reconcile(
        readiness_harness.task_id,
        trigger_event_id=readiness_harness.trigger_id,
    )
    assert ready.status is ReadinessReconcileStatus.READY
    current[0] = _assessment(readiness_harness.task_id, ready=False)
    invalidating_trigger = uuid4()
    with readiness_harness.factory.begin() as session:
        task = session.get_one(Task, readiness_harness.task_id)
        session.add(
            TaskEvent(
                id=invalidating_trigger,
                task_id=task.id,
                sequence=4,
                event_type=GITHUB_CHECK_UPDATED_EVENT,
                payload={"schema_version": 1, "head_sha": _HEAD},
                occurred_at=_NOW,
                owner_id=task.owner_id,
                actor_id="github-webhook",
                root_correlation_id=task.root_correlation_id,
                causation_id=task.id,
            )
        )
    invalidated = service.reconcile(
        readiness_harness.task_id,
        trigger_event_id=invalidating_trigger,
    )

    assert invalidated.status is ReadinessReconcileStatus.INVALIDATED
    with readiness_harness.factory() as session:
        assert session.get_one(Task, readiness_harness.task_id).state is TaskState.PR_ACTIVE


def test_handoff_is_explicit_idempotent_and_never_means_merged(
    readiness_harness: ReadinessHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = _assessment(readiness_harness.task_id)
    monkeypatch.setattr(
        readiness_module,
        "_assess",
        lambda *_args, **_kwargs: current,
    )
    service = ReadinessService(
        readiness_harness.factory,
        readiness_harness.store,
        clock=lambda: _NOW,
    )
    service.reconcile(
        readiness_harness.task_id,
        trigger_event_id=readiness_harness.trigger_id,
    )
    handoff_id = uuid4()

    with pytest.raises(TaskTransitionError):
        service.acknowledge_handoff(
            readiness_harness.task_id,
            handoff_id=uuid4(),
            expected_head_sha="c" * 40,
            acknowledgement=HANDOFF_ACKNOWLEDGEMENT,
            actor_id="local-user",
        )

    first = service.acknowledge_handoff(
        readiness_harness.task_id,
        handoff_id=handoff_id,
        expected_head_sha=_HEAD,
        acknowledgement=HANDOFF_ACKNOWLEDGEMENT,
        actor_id="local-user",
    )
    replay = service.acknowledge_handoff(
        readiness_harness.task_id,
        handoff_id=handoff_id,
        expected_head_sha=_HEAD,
        acknowledgement=HANDOFF_ACKNOWLEDGEMENT,
        actor_id="local-user",
    )

    assert first.transition.to_state is TaskState.HANDED_OFF
    assert replay.transition.replayed
    assert "does not mean merged" in first.meaning
    with readiness_harness.factory() as session:
        task = session.get_one(Task, readiness_harness.task_id)
        event = session.scalar(
            select(TaskEvent).where(
                TaskEvent.transition_kind
                == TaskTransitionKind.ACKNOWLEDGE_HANDOFF.value
            )
        )
    assert task.state is TaskState.HANDED_OFF
    assert event is not None
    assert event.payload["meaning"] == (
        "automation responsibility handed off; not merged, deployed, or released"
    )
