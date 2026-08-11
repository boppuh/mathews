from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TypedDict, cast
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from mathews_control_plane.app import create_app
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.authentication import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
    AuthenticatedSession,
    AuthenticationService,
    generate_bootstrap_token,
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
    Brief,
    EvidenceDeletionRequest,
    EvidenceRecord,
    EvidenceTombstone,
    PolicyVersion,
    ReconciliationStatus,
    ReconciliationTarget,
    ReconciliationTargetKind,
    RepositoryConfiguration,
    Task,
    TaskCancellation,
    TaskEvent,
    TaskEventEvidenceReference,
    TaskState,
    ValidationContract,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
    load_evidence,
)
from mathews_control_plane.readiness import (
    HANDOFF_ACKNOWLEDGEMENT,
    HANDOFF_MEANING,
    HandoffResult,
    ReadinessService,
)
from mathews_control_plane.settings import Settings
from mathews_control_plane.task_state_machine import TaskTransitionResult
from mathews_control_plane.tasks import (
    MAX_TASK_EVENT_SEQUENCE,
    MAX_TASK_REQUEST_BYTES,
    TASK_INTAKE_EVENT_TYPE,
    InvalidTaskEventCursorError,
    TaskAccessError,
    TaskService,
    _format_sse_event,
    _last_event_sequence,
)
from pydantic import SecretStr
from sqlalchemy import Engine, func, select

_ORIGIN = "http://localhost:3000"
_PASSWORD = "correct horse battery staple"
_BASE_SHA = "A" * 40


class _RecordContext(TypedDict):
    owner_id: str
    actor_id: str
    root_correlation_id: UUID
    causation_id: UUID
    parent_correlation_id: UUID


@dataclass(slots=True)
class MutableClock:
    now: datetime

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


@dataclass(slots=True)
class TaskHarness:
    client: TestClient
    engine: Engine
    factory: SessionFactory
    store: ArtifactStore
    clock: MutableClock
    task_service: TaskService
    authentication_service: AuthenticationService
    bootstrap_token: str


@pytest.fixture
def task_harness(tmp_path: Path) -> Iterator[TaskHarness]:
    database_url = f"sqlite:///{tmp_path / 'tasks.sqlite3'}"
    engine = create_database_engine(database_url)
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    store = ArtifactStore(tmp_path / "artifacts")
    # HTTPX's cookie jar evaluates Expires against the real wall clock, so keep
    # the service clock aligned rather than letting this fixture age into expiry.
    clock = MutableClock(datetime.now(UTC).replace(microsecond=0))
    authentication_service = AuthenticationService(factory, clock=clock)
    task_service = TaskService(factory, store, clock=clock)
    app = create_app(
        Settings(
            database_url=SecretStr(database_url),
            artifact_root=store.root,
        ),
        session_factory=factory,
        authentication_service=authentication_service,
        task_service=task_service,
    )
    client = TestClient(app, base_url="https://localhost")
    harness = TaskHarness(
        client=client,
        engine=engine,
        factory=factory,
        store=store,
        clock=clock,
        task_service=task_service,
        authentication_service=authentication_service,
        bootstrap_token=generate_bootstrap_token(factory),
    )
    try:
        yield harness
    finally:
        client.close()
        engine.dispose()


def _authenticate(harness: TaskHarness) -> str:
    status_response = harness.client.get("/api/auth/status")
    assert status_response.status_code == 200
    csrf_token = harness.client.cookies.get(CSRF_COOKIE_NAME)
    assert csrf_token is not None
    bootstrap = harness.client.post(
        "/api/auth/bootstrap",
        json={
            "bootstrap_token": harness.bootstrap_token,
            "password": _PASSWORD,
        },
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )
    assert bootstrap.status_code == 201, bootstrap.text
    bound_csrf = harness.client.cookies.get(CSRF_COOKIE_NAME)
    assert bound_csrf is not None
    return bound_csrf


def _create(
    harness: TaskHarness,
    csrf_token: str,
    *,
    request: str = "Add offline support to the trip detail screen.",
    repository: str = "boppuh/mathews",
    base_revision: str = _BASE_SHA,
) -> dict[str, object]:
    response = harness.client.post(
        "/api/tasks",
        json={
            "repository": repository,
            "base_revision": base_revision,
            "request": request,
        },
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )
    assert response.status_code == 201, response.text
    return cast(dict[str, object], response.json())


def _authenticated_context(harness: TaskHarness) -> AuthenticatedSession:
    session_token = harness.client.cookies.get(SESSION_COOKIE_NAME)
    assert session_token is not None
    authentication = harness.authentication_service.authenticate(session_token)
    assert authentication is not None
    return authentication


def _seed_active_policy(harness: TaskHarness, task_id: UUID) -> None:
    with harness.factory.begin() as session:
        task = session.get(Task, task_id)
        assert task is not None
        session.add(
            PolicyVersion(
                lineage_key="mvp",
                version=1,
                predecessor_id=None,
                workflow_thresholds={},
                approved_by=task.owner_id,
                approved_at=harness.clock.now,
                owner_id=task.owner_id,
                actor_id="control-plane",
                root_correlation_id=task.root_correlation_id,
            )
        )


def test_task_api_requires_authentication_and_csrf(task_harness: TaskHarness) -> None:
    payload = {
        "repository": "boppuh/mathews",
        "base_revision": _BASE_SHA,
        "request": "Create a task.",
    }
    assert task_harness.client.get("/api/tasks").status_code == 401
    assert task_harness.client.post("/api/tasks", json=payload).status_code == 403

    _authenticate(task_harness)
    missing_csrf = task_harness.client.post(
        "/api/tasks",
        json=payload,
        headers={"Origin": _ORIGIN},
    )
    assert missing_csrf.status_code == 403
    assert missing_csrf.json() == {"detail": "CSRF validation failed"}


def test_create_persists_redacted_task_evidence_and_intake_event(
    task_harness: TaskHarness,
) -> None:
    csrf_token = _authenticate(task_harness)
    raw_request = "  Add offline support.\nKeep the cached screen readable.  "

    created = _create(
        task_harness,
        csrf_token,
        request=raw_request,
        repository="BOPPUH/Mathews",
    )

    task_id = UUID(str(created["id"]))
    assert created == {
        "id": str(task_id),
        "summary": "Add offline support. Keep the cached screen readable.",
        "state": "INTAKE",
        "repository": "boppuh/mathews",
        "base_revision": _BASE_SHA.lower(),
        "created_at": created["created_at"],
        "last_activity_at": task_harness.clock.now.isoformat().replace(
            "+00:00",
            "Z",
        ),
        "blockers": [],
        "cockpit_path": f"/tasks/{task_id}",
    }
    assert created["created_at"] is not None
    with task_harness.factory() as session:
        task = session.get(Task, task_id)
        event = session.scalar(
            select(TaskEvent).where(TaskEvent.task_id == task_id)
        )
        reference = session.scalar(
            select(TaskEventEvidenceReference).where(
                TaskEventEvidenceReference.task_id == task_id
            )
        )
        assert task is not None
        assert task.raw_request.startswith("evidence://")
        assert task.raw_request != raw_request
        evidence_id = UUID(task.raw_request.removeprefix("evidence://"))
        evidence = session.get(EvidenceRecord, evidence_id)
        assert evidence is not None
        loaded = load_evidence(session, task_harness.store, evidence)

    assert loaded.content == raw_request
    assert event is not None
    assert event.event_type == TASK_INTAKE_EVENT_TYPE
    assert event.sequence == 1
    assert event.payload["request_evidence_id"] == str(evidence_id)
    assert raw_request not in str(event.payload)
    assert reference is not None
    assert reference.evidence_id == evidence_id


def test_list_orders_recent_activity_and_projects_durable_blockers(
    task_harness: TaskHarness,
) -> None:
    csrf_token = _authenticate(task_harness)
    first = _create(task_harness, csrf_token, request="First task")
    task_harness.clock.advance(timedelta(minutes=1))
    second = _create(task_harness, csrf_token, request="Second task")
    first_id = UUID(str(first["id"]))
    second_id = UUID(str(second["id"]))

    with task_harness.factory.begin() as session:
        first_task = session.get(Task, first_id)
        assert first_task is not None
        session.add(
            ApprovalRequest(
                task_id=first_id,
                request_type=ApprovalRequestType.BRIEF.value,
                subject_type="BRIEF",
                reason="BRIEF_REVIEW_REQUIRED",
                options=[
                    ApprovalDecision.APPROVE.value,
                    ApprovalDecision.CANCEL.value,
                ],
                supporting_evidence_ids=[],
                requesting_state=TaskState.INTAKE,
                status=ApprovalStatus.PENDING,
                owner_id=first_task.owner_id,
                actor_id="control-plane",
                root_correlation_id=first_task.root_correlation_id,
            )
        )
        session.add(
            ReconciliationTarget(
                task_id=first_id,
                kind=ReconciliationTargetKind.PR_HEAD,
                target_key=f"task:{first_id}:pr",
                expected_payload={"head": "b" * 40},
                expected_fingerprint="c" * 64,
                status=ReconciliationStatus.RETRY_REQUIRED,
                owner_id=first_task.owner_id,
                actor_id="control-plane",
                root_correlation_id=first_task.root_correlation_id,
            )
        )
        session.add(
            ReconciliationTarget(
                task_id=first_id,
                kind=ReconciliationTargetKind.BRANCH_HEAD,
                target_key=f"task:{first_id}:branch",
                expected_payload={"head": "d" * 40},
                expected_fingerprint="e" * 64,
                status=ReconciliationStatus.PENDING,
                owner_id=first_task.owner_id,
                actor_id="control-plane",
                root_correlation_id=first_task.root_correlation_id,
            )
        )

    response = task_harness.client.get("/api/tasks")

    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    tasks = response.json()["tasks"]
    assert [item["id"] for item in tasks] == [str(second_id), str(first_id)]
    assert tasks[0]["blockers"] == []
    assert tasks[1]["blockers"] == [
        {
            "code": "APPROVAL_REQUIRED",
            "label": "Approval required",
            "count": 1,
        },
        {
            "code": "RECONCILIATION_REQUIRED",
            "label": "Reconciliations required",
            "count": 2,
        },
    ]


def test_cockpit_projects_durable_history_evidence_and_approvals_without_payloads(
    task_harness: TaskHarness,
) -> None:
    csrf_token = _authenticate(task_harness)
    created = _create(task_harness, csrf_token, request="Build the task cockpit")
    task_id = UUID(str(created["id"]))
    raw_payload_secret = "raw-event-payload-must-stay-private"  # noqa: S105

    with task_harness.factory.begin() as session:
        task = session.get(Task, task_id)
        assert task is not None
        session.add(
            TaskEvent(
                task_id=task_id,
                sequence=2,
                event_type="AGENT_PROGRESS",
                payload={"raw_output": raw_payload_secret},
                occurred_at=task_harness.clock.now + timedelta(minutes=1),
                owner_id=task.owner_id,
                actor_id="agent-runtime",
                root_correlation_id=task.root_correlation_id,
            )
        )
        session.add(
            ApprovalRequest(
                task_id=task_id,
                request_type=ApprovalRequestType.BRIEF.value,
                subject_type="BRIEF",
                reason="private approval reason",
                options=[ApprovalDecision.APPROVE.value],
                supporting_evidence_ids=[],
                requesting_state=TaskState.INTAKE,
                status=ApprovalStatus.PENDING,
                owner_id=task.owner_id,
                actor_id="control-plane",
                root_correlation_id=task.root_correlation_id,
            )
        )

    response = task_harness.client.get(f"/api/tasks/{task_id}")

    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    assert raw_payload_secret not in response.text
    assert "private approval reason" not in response.text
    cockpit = response.json()
    assert cockpit["task"]["id"] == str(task_id)
    assert cockpit["state_context"] == {
        "kind": "ACTIVE",
        "label": "Intake",
        "detail": "The request is captured and waiting for briefing.",
        "resume_state": None,
    }
    assert [
        (event["sequence"], event["kind"], event["summary"])
        for event in cockpit["events"]
    ] == [
        (1, "CREATED", "Task request captured."),
        (2, "ACTIVITY", "Task activity was recorded."),
    ]
    assert cockpit["events"][0]["evidence_count"] == 1
    assert cockpit["events"][1]["evidence_count"] == 0
    assert cockpit["events"][0]["occurred_at"].endswith("Z")
    assert cockpit["acceptance_criteria"] == []
    assert len(cockpit["evidence"]) == 1
    assert cockpit["evidence"][0]["evidence_type"] == "task-request"
    assert cockpit["evidence"][0] == {
        "id": cockpit["evidence"][0]["id"],
        "evidence_type": "task-request",
        "captured_at": cockpit["evidence"][0]["captured_at"],
        "status": "AVAILABLE",
        "category": "OTHER",
        "content_access": "AVAILABLE",
        "correction_of_id": None,
        "corrected_by_id": None,
        "deletion_reason": None,
        "deleted_at": None,
        "download_path": (
            f"/api/evidence/{cockpit['evidence'][0]['id']}/download"
        ),
    }
    assert cockpit["approvals"][0]["type_label"] == "Brief approval"
    assert cockpit["approvals"][0]["status"] == "PENDING"


def test_cockpit_projects_criteria_lineage_access_fences_and_tombstones(
    task_harness: TaskHarness,
) -> None:
    csrf_token = _authenticate(task_harness)
    created = _create(task_harness, csrf_token, request="Inspect delivery evidence")
    task_id = UUID(str(created["id"]))

    with task_harness.factory.begin() as session:
        task = session.get(Task, task_id)
        assert task is not None
        context: _RecordContext = {
            "owner_id": task.owner_id,
            "actor_id": "control-plane",
            "root_correlation_id": task.root_correlation_id,
            "causation_id": task.id,
            "parent_correlation_id": task.id,
        }
        brief = Brief(
            task_id=task.id,
            version=1,
            scope={"summary": "evidence views"},
            exclusions=[],
            acceptance_criteria=[
                {
                    "criterion_id": "criterion-1",
                    "requirement": "Redacted logs are searchable on demand.",
                    "verification": "HUMAN_INSPECTION",
                },
                {
                    "criterion_id": "criterion-1",
                    "requirement": "A stale duplicate must not break the cockpit.",
                    "verification": "STATIC_CHECK",
                },
            ],
            risks=[],
            affected_flow={"id": "task-cockpit"},
            test_plan=[],
            **context,
        )
        session.add(brief)
        session.flush()
        task.accepted_brief_id = brief.id

        original = capture_evidence(
            session,
            task_harness.store,
            payload="first build failed",
            media_type="text/plain; charset=utf-8",
            source_kind=EvidenceSourceKind.TOOL_OPERATION,
            evidence_type="xcodebuild-log",
            origin="host-agent:xcodebuild",
            access_classification=EvidenceAccessClass.TASK_OWNER,
            retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
            task_id=task.id,
            captured_at=task_harness.clock.now,
            **context,
        ).record
        correction = capture_evidence(
            session,
            task_harness.store,
            payload="corrected build result",
            media_type="text/plain; charset=utf-8",
            source_kind=EvidenceSourceKind.TOOL_OPERATION,
            evidence_type="xcodebuild-log",
            origin="host-agent:xcodebuild",
            access_classification=EvidenceAccessClass.TASK_OWNER,
            retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
            task_id=task.id,
            correction_of_id=original.id,
            captured_at=task_harness.clock.now + timedelta(seconds=1),
            **context,
        ).record
        protected = capture_evidence(
            session,
            task_harness.store,
            payload={"request": "GET /health", "status": 200},
            media_type="application/json",
            source_kind=EvidenceSourceKind.TOOL_OPERATION,
            evidence_type="network-trace",
            origin="simulator:network",
            access_classification=EvidenceAccessClass.RECENT_PASSWORD,
            retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
            task_id=task.id,
            captured_at=task_harness.clock.now + timedelta(seconds=2),
            **context,
        ).record
        deleted = capture_evidence(
            session,
            task_harness.store,
            payload="screenshot bytes represented safely",
            media_type="text/plain; charset=utf-8",
            source_kind=EvidenceSourceKind.RESULT,
            evidence_type="simulator-screenshot",
            origin="simulator:screen",
            access_classification=EvidenceAccessClass.TASK_OWNER,
            retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
            task_id=task.id,
            captured_at=task_harness.clock.now + timedelta(seconds=3),
            **context,
        ).record
        capture_evidence(
            session,
            task_harness.store,
            payload="internal diagnostic",
            media_type="text/plain; charset=utf-8",
            source_kind=EvidenceSourceKind.TOOL_OPERATION,
            evidence_type="private-debug-log",
            origin="control-plane:internal",
            access_classification=EvidenceAccessClass.INTERNAL,
            retention_policy=EvidenceRetentionClass.AUDIT,
            task_id=task.id,
            captured_at=task_harness.clock.now + timedelta(seconds=4),
            **context,
        )
        deletion_request = EvidenceDeletionRequest(
            evidence_id=deleted.id,
            reason_code="USER_REQUEST",
            requested_at=task_harness.clock.now + timedelta(seconds=5),
            **context,
        )
        session.add(deletion_request)
        session.flush()
        session.add(
            EvidenceTombstone(
                evidence_id=deleted.id,
                deletion_request_id=deletion_request.id,
                reason_code=deletion_request.reason_code,
                deleted_at=task_harness.clock.now + timedelta(seconds=6),
                removed_derivative_count=0,
                **context,
            )
        )

    task_harness.clock.advance(timedelta(minutes=6))
    response = task_harness.client.get(f"/api/tasks/{task_id}")

    assert response.status_code == 200, response.text
    cockpit = response.json()
    assert cockpit["acceptance_criteria"] == [
        {
            "id": "criterion-1",
            "requirement": "Redacted logs are searchable on demand.",
            "verification": "HUMAN_INSPECTION",
            "status": "PENDING",
            "validation_run_id": None,
            "validation_contract_version": None,
            "commit_sha": None,
            "tree_sha": None,
            "evidence_ids": [],
            "assertions": [],
        }
    ]
    by_id = {item["id"]: item for item in cockpit["evidence"]}
    assert len(by_id) == 5
    assert by_id[str(original.id)]["status"] == "SUPERSEDED"
    assert by_id[str(original.id)]["category"] == "LOG"
    assert by_id[str(original.id)]["corrected_by_id"] == str(correction.id)
    assert by_id[str(correction.id)]["status"] == "CORRECTION"
    assert by_id[str(correction.id)]["correction_of_id"] == str(original.id)
    assert by_id[str(protected.id)]["category"] == "NETWORK"
    assert by_id[str(protected.id)]["content_access"] == "RECENT_PASSWORD_REQUIRED"
    assert by_id[str(protected.id)]["download_path"] is None
    assert by_id[str(deleted.id)]["status"] == "DELETED"
    assert by_id[str(deleted.id)]["category"] == "ARTIFACT"
    assert by_id[str(deleted.id)]["deletion_reason"] == "USER_REQUEST"
    assert by_id[str(deleted.id)]["deleted_at"].endswith("Z")
    assert by_id[str(deleted.id)]["download_path"] is None


@pytest.mark.parametrize(
    ("state", "resume_state", "kind", "label_fragment", "detail_fragment"),
    [
        (
            TaskState.ESCALATED,
            TaskState.VALIDATING,
            "RESUMABLE_ESCALATION",
            "Resumable",
            "resume from Validating",
        ),
        (
            TaskState.FAILED,
            None,
            "TERMINAL",
            "failure",
            "cannot resume",
        ),
        (
            TaskState.CANCELLED,
            None,
            "TERMINAL",
            "cancellation",
            "cannot restart",
        ),
        (
            TaskState.PR_ACTIVE,
            None,
            "VERIFIED_DRAFT_PR",
            "Verified draft PR",
            "not yet ready",
        ),
        (
            TaskState.READY_FOR_HUMAN_MERGE,
            None,
            "HUMAN_MERGE_READY",
            "Ready for human merge",
            "human merge decision",
        ),
        (
            TaskState.HANDED_OFF,
            None,
            "AUTOMATION_HANDED_OFF",
            "Automation handed off",
            "does not mean",
        ),
    ],
)
def test_cockpit_distinguishes_workflow_boundaries(
    task_harness: TaskHarness,
    state: TaskState,
    resume_state: TaskState | None,
    kind: str,
    label_fragment: str,
    detail_fragment: str,
) -> None:
    csrf_token = _authenticate(task_harness)
    created = _create(task_harness, csrf_token)
    task_id = UUID(str(created["id"]))
    with task_harness.factory.begin() as session:
        task = session.get(Task, task_id)
        assert task is not None
        task.state = state
        task.escalation_resume_state = resume_state

    response = task_harness.client.get(f"/api/tasks/{task_id}")

    assert response.status_code == 200, response.text
    context = response.json()["state_context"]
    assert context["kind"] == kind
    assert label_fragment in context["label"]
    assert detail_fragment in context["detail"]
    assert context["resume_state"] == (
        None if resume_state is None else resume_state.value
    )


def test_cockpit_requires_authentication_and_hides_absent_tasks(
    task_harness: TaskHarness,
) -> None:
    unknown_id = UUID("11111111-1111-4111-8111-111111111111")

    assert task_harness.client.get(f"/api/tasks/{unknown_id}").status_code == 401
    _authenticate(task_harness)
    with task_harness.factory.begin() as session:
        other_owner_task = create_task_record(
            session,
            task_harness.store,
            repository="boppuh/mathews",
            base_revision=_BASE_SHA,
            requester="another-local-user",
            raw_request="This task belongs to another owner.",
            summary="Another owner's task",
            owner_id="another-local-user",
            actor_id="another-local-user",
        )
        other_owner_task_id = other_owner_task.id

    response = task_harness.client.get(f"/api/tasks/{unknown_id}")

    assert response.status_code == 404
    assert response.json() == {"detail": "task unavailable"}
    cross_owner_response = task_harness.client.get(
        f"/api/tasks/{other_owner_task_id}"
    )
    assert cross_owner_response.status_code == 404
    assert cross_owner_response.json() == {"detail": "task unavailable"}


def test_task_event_batches_replay_after_cursor_without_raw_payloads(
    task_harness: TaskHarness,
) -> None:
    csrf_token = _authenticate(task_harness)
    created = _create(task_harness, csrf_token)
    task_id = UUID(str(created["id"]))
    raw_payload = "private streamed runtime output"
    with task_harness.factory.begin() as session:
        task = session.get(Task, task_id)
        assert task is not None
        session.add(
            TaskEvent(
                task_id=task_id,
                sequence=2,
                event_type="VALIDATION_PROGRESS",
                payload={"raw_output": raw_payload},
                occurred_at=task_harness.clock.now + timedelta(seconds=1),
                owner_id=task.owner_id,
                actor_id="control-plane",
                root_correlation_id=task.root_correlation_id,
            )
        )

    authentication = _authenticated_context(task_harness)
    all_events = task_harness.task_service.events_after(
        task_id,
        authentication,
        after_sequence=0,
    )
    resumed_events = task_harness.task_service.events_after(
        task_id,
        authentication,
        after_sequence=1,
    )

    assert [event.sequence for event in all_events] == [1, 2]
    assert [event.sequence for event in resumed_events] == [2]
    encoded = _format_sse_event(resumed_events[0])
    assert encoded.startswith("id: 2\nevent: task-event\ndata: ")
    assert encoded.endswith("\n\n")
    assert "Task activity was recorded." in encoded
    assert raw_payload not in encoded

    task_harness.authentication_service.logout(authentication)
    with pytest.raises(TaskAccessError):
        task_harness.task_service.events_after(
            task_id,
            authentication,
            after_sequence=2,
        )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, 0),
        ("0", 0),
        ("1", 1),
        (str(MAX_TASK_EVENT_SEQUENCE), MAX_TASK_EVENT_SEQUENCE),
    ],
)
def test_task_event_cursor_accepts_canonical_sequences(
    value: str | None,
    expected: int,
) -> None:
    assert _last_event_sequence(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "-1",
        "+1",
        "01",
        "01x",
        " 1",
        "1 ",
        "١",
        str(MAX_TASK_EVENT_SEQUENCE + 1),
    ],
)
def test_task_event_cursor_rejects_ambiguous_or_out_of_range_values(
    value: str,
) -> None:
    with pytest.raises(InvalidTaskEventCursorError):
        _last_event_sequence(value)


def test_task_event_stream_requires_auth_and_hides_cursor_details(
    task_harness: TaskHarness,
) -> None:
    unknown_id = UUID("11111111-1111-4111-8111-111111111111")
    assert task_harness.client.get(
        f"/api/tasks/{unknown_id}/events"
    ).status_code == 401
    _authenticate(task_harness)

    invalid_cursor = task_harness.client.get(
        f"/api/tasks/{unknown_id}/events",
        headers={"Last-Event-ID": "not-a-sequence"},
    )
    assert invalid_cursor.status_code == 400
    assert invalid_cursor.json() == {"detail": "invalid task event cursor"}

    absent_task = task_harness.client.get(
        f"/api/tasks/{unknown_id}/events",
        headers={"Last-Event-ID": "0"},
    )
    assert absent_task.status_code == 404
    assert absent_task.json() == {"detail": "task unavailable"}


def test_create_redacts_summary_before_task_event_and_list_projection(
    task_harness: TaskHarness,
) -> None:
    csrf_token = _authenticate(task_harness)
    raw_email = "alice@example.com"
    raw_token = "raw-task-intake-token"  # noqa: S105 - non-secret test fixture
    raw_request = (
        f"Email {raw_email} after the fix. "
        f"Authorization: Bearer {raw_token}"
    )

    created = _create(task_harness, csrf_token, request=raw_request)
    task_id = UUID(str(created["id"]))
    summary = str(created["summary"])
    assert raw_email not in summary
    assert raw_token not in summary
    assert "[REDACTED:EMAIL]" in summary
    assert "[REDACTED:AUTHORIZATION]" in summary

    listed = task_harness.client.get("/api/tasks")
    assert listed.status_code == 200
    listed_summary = listed.json()["tasks"][0]["summary"]
    assert listed_summary == summary
    assert raw_email not in listed.text
    assert raw_token not in listed.text

    with task_harness.factory() as session:
        task = session.get(Task, task_id)
        event = session.scalar(
            select(TaskEvent).where(TaskEvent.task_id == task_id)
        )
        assert task is not None
        evidence = session.get(
            EvidenceRecord,
            UUID(task.raw_request.removeprefix("evidence://")),
        )
        assert evidence is not None
        loaded = load_evidence(session, task_harness.store, evidence)

    assert event is not None
    assert event.payload["summary"] == summary
    assert raw_email not in str(event.payload)
    assert raw_token not in str(event.payload)
    assert raw_email not in str(loaded.content)
    assert raw_token not in str(loaded.content)


def test_create_redacts_full_request_before_summary_truncation(
    task_harness: TaskHarness,
) -> None:
    csrf_token = _authenticate(task_harness)
    raw_token = f"ghp_{'A' * 24}"  # noqa: S105 - non-secret test fixture
    raw_request = f"{'x' * 150} {raw_token} must never survive"

    created = _create(task_harness, csrf_token, request=raw_request)

    summary = str(created["summary"])
    assert len(summary) <= 160
    assert raw_token not in summary
    assert "ghp_" not in summary
    assert summary.endswith("...")


@pytest.mark.parametrize(
    "payload",
    [
        {
            "repository": "boppuh/mathews",
            "base_revision": "not-a-sha",
            "request": "Create a task.",
        },
        {
            "repository": "boppuh/mathews",
            "base_revision": _BASE_SHA,
            "request": "   \n ",
        },
        {
            "repository": "boppuh/mathews",
            "base_revision": _BASE_SHA,
            "request": "Create a task.",
            "unexpected": "value",
        },
        {
            "repository": "https://github.com/boppuh/mathews.git",
            "base_revision": _BASE_SHA,
            "request": "Create a task.",
        },
    ],
)
def test_create_rejects_invalid_or_extra_input_without_echoing_it(
    task_harness: TaskHarness,
    payload: dict[str, str],
) -> None:
    csrf_token = _authenticate(task_harness)

    response = task_harness.client.post(
        "/api/tasks",
        json=payload,
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}
    with task_harness.factory() as session:
        assert session.scalar(select(func.count()).select_from(Task)) == 0


def test_create_rejects_oversized_body_before_parsing(
    task_harness: TaskHarness,
) -> None:
    csrf_token = _authenticate(task_harness)

    response = task_harness.client.post(
        "/api/tasks",
        content=b"x" * (MAX_TASK_REQUEST_BYTES + 1),
        headers={
            "Content-Type": "application/json",
            "Origin": _ORIGIN,
            CSRF_HEADER_NAME: csrf_token,
        },
    )

    assert response.status_code == 413
    assert response.json() == {"detail": "task request body too large"}
    with task_harness.factory() as session:
        assert session.scalar(select(func.count()).select_from(Task)) == 0


def test_cosmetic_steering_revises_request_and_is_idempotently_audited(
    task_harness: TaskHarness,
) -> None:
    csrf_token = _authenticate(task_harness)
    created = _create(task_harness, csrf_token)
    task_id = UUID(str(created["id"]))
    steering_id = uuid4()
    payload = {
        "steering_id": str(steering_id),
        "expected_state": "INTAKE",
        "message": "Use the existing empty-state wording.",
        "impacts": [],
    }

    response = task_harness.client.post(
        f"/api/tasks/{task_id}/steering",
        json=payload,
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["classification"] == "CLARIFICATION"
    assert body["task_state"] == "INTAKE"
    assert body["replayed"] is False
    assert body["invalidated_brief_id"] is None
    assert body["invalidated_validation_contract_id"] is None
    with task_harness.factory() as session:
        task = session.get(Task, task_id)
        steering_event = session.get(TaskEvent, UUID(body["event_id"]))
        request_evidence = session.get(
            EvidenceRecord,
            UUID(body["request_evidence_id"]),
        )
        assert task is not None
        assert request_evidence is not None
        assert task.state is TaskState.INTAKE
        assert task.summary == created["summary"]
        assert task.raw_request == f"evidence://{request_evidence.id}"
        assert steering_event is not None
        assert request_evidence.correction_of_id is not None
        revised_request = load_evidence(
            session,
            task_harness.store,
            request_evidence,
        )
    assert isinstance(revised_request.content, str)
    assert "Add offline support" in revised_request.content
    assert "Use the existing empty-state wording." in revised_request.content
    assert "Use the existing empty-state wording." not in str(steering_event.payload)

    replay = task_harness.client.post(
        f"/api/tasks/{task_id}/steering",
        json=payload,
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True

    conflict = task_harness.client.post(
        f"/api/tasks/{task_id}/steering",
        json={**payload, "message": "A different clarification."},
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )
    assert conflict.status_code == 409

    cockpit = task_harness.client.get(f"/api/tasks/{task_id}").json()
    assert cockpit["events"][-1]["summary"] == "In-scope clarification recorded."


def test_scope_steering_invalidates_execution_bindings_and_returns_to_briefing(
    task_harness: TaskHarness,
) -> None:
    csrf_token = _authenticate(task_harness)
    created = _create(task_harness, csrf_token)
    task_id = UUID(str(created["id"]))
    _seed_active_policy(task_harness, task_id)
    with task_harness.factory.begin() as session:
        task = session.get(Task, task_id)
        assert task is not None
        context: _RecordContext = {
            "owner_id": task.owner_id,
            "actor_id": "control-plane",
            "root_correlation_id": task.root_correlation_id,
            "causation_id": task.id,
            "parent_correlation_id": task.id,
        }
        brief = Brief(
            task_id=task.id,
            version=1,
            scope={"objective": "Original scope"},
            exclusions=[],
            acceptance_criteria=[],
            risks=[],
            affected_flow={},
            test_plan=[],
            **context,
        )
        repository = RepositoryConfiguration(
            repository_key=task.repository,
            version=1,
            repository_settings={},
            git_settings={},
            xcode_settings={},
            operations=[],
            e2e_assertions=[],
            artifact_settings={},
            prohibited_paths=[],
            secret_references=[],
            **context,
        )
        session.add_all([brief, repository])
        session.flush()
        contract = ValidationContract(
            task_id=task.id,
            version=1,
            brief_id=brief.id,
            repository_configuration_id=repository.id,
            required_operations=[],
            simulator_setup={},
            clean_state_setup={},
            e2e_flow={},
            typed_assertions=[],
            evidence_requirements=[],
            timeouts={},
            outcome_rules={},
            **context,
        )
        session.add(contract)
        session.flush()
        task.state = TaskState.IMPLEMENTING
        task.accepted_brief_id = brief.id
        task.repository_configuration_id = repository.id
        task.validation_contract_id = contract.id
        brief_id = brief.id
        contract_id = contract.id

    response = task_harness.client.post(
        f"/api/tasks/{task_id}/steering",
        json={
            "steering_id": str(uuid4()),
            "expected_state": "IMPLEMENTING",
            "message": "Also cover the retry screen and its simulator flow.",
            "impacts": ["PATHS", "TESTS"],
        },
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["classification"] == "SCOPE_CHANGE"
    assert body["impacts"] == ["PATHS", "TESTS"]
    assert body["task_state"] == "BRIEFING"
    assert body["invalidated_brief_id"] == str(brief_id)
    assert body["invalidated_validation_contract_id"] == str(contract_id)
    with task_harness.factory() as session:
        task = session.get(Task, task_id)
        assert task is not None
        assert task.state is TaskState.BRIEFING
        assert task.accepted_brief_id is None
        assert task.brief_approval_decision_id is None
        assert task.validation_contract_id is None
        assert task.repository_configuration_id is not None
        versions = session.scalar(
            select(func.count()).select_from(Brief).where(Brief.task_id == task_id)
        )
        contracts = session.scalar(
            select(func.count())
            .select_from(ValidationContract)
            .where(ValidationContract.task_id == task_id)
        )
    assert versions == 1
    assert contracts == 1
    cockpit = task_harness.client.get(f"/api/tasks/{task_id}").json()
    assert [event["summary"] for event in cockpit["events"][-2:]] == [
        "Scope-changing steering recorded.",
        "Scope changed; a new brief and validation contract are required.",
    ]


def test_cancellation_requires_recent_password_and_is_durable(
    task_harness: TaskHarness,
) -> None:
    csrf_token = _authenticate(task_harness)
    created = _create(task_harness, csrf_token)
    task_id = UUID(str(created["id"]))
    _seed_active_policy(task_harness, task_id)
    with task_harness.factory.begin() as session:
        task = session.get(Task, task_id)
        assert task is not None
        task.state = TaskState.IMPLEMENTING
    task_harness.clock.advance(timedelta(minutes=6))
    cancellation_id = uuid4()
    payload = {
        "cancellation_id": str(cancellation_id),
        "expected_state": "IMPLEMENTING",
        "reason_code": "USER_REQUEST",
    }

    stale = task_harness.client.post(
        f"/api/tasks/{task_id}/cancellations",
        json=payload,
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )
    assert stale.status_code == 403
    reauthenticated = task_harness.client.post(
        "/api/auth/reauthenticate",
        json={"password": _PASSWORD},
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )
    assert reauthenticated.status_code == 200, reauthenticated.text
    refreshed_csrf_token = task_harness.client.cookies.get(CSRF_COOKIE_NAME)
    assert refreshed_csrf_token is not None

    response = task_harness.client.post(
        f"/api/tasks/{task_id}/cancellations",
        json=payload,
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: refreshed_csrf_token},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["task_state"] == "CANCELLED"
    assert body["cleanup_complete"] is True
    assert body["replayed"] is False
    with task_harness.factory() as session:
        task = session.get(Task, task_id)
        cancellation = session.get(TaskCancellation, cancellation_id)
        assert task is not None and task.state is TaskState.CANCELLED
        assert cancellation is not None
        assert cancellation.partial_evidence_id == UUID(body["partial_evidence_id"])

    replay = task_harness.client.post(
        f"/api/tasks/{task_id}/cancellations",
        json=payload,
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: refreshed_csrf_token},
    )
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    cockpit = task_harness.client.get(f"/api/tasks/{task_id}").json()
    assert cockpit["events"][-1]["summary"] == (
        "Task cancelled; active automation was fenced."
    )


class _FakeReadinessService:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def acknowledge_handoff(self, task_id: UUID, **kwargs: object) -> HandoffResult:
        self.calls.append({"task_id": task_id, **kwargs})
        return HandoffResult(
            cast(UUID, kwargs["handoff_id"]),
            task_id,
            cast(str, kwargs["expected_head_sha"]),
            uuid4(),
            TaskTransitionResult(
                task_id,
                uuid4(),
                uuid4(),
                7,
                TaskState.READY_FOR_HUMAN_MERGE,
                TaskState.HANDED_OFF,
            ),
        )


def test_handoff_requires_recent_password_and_exact_acknowledgement(
    task_harness: TaskHarness,
) -> None:
    csrf_token = _authenticate(task_harness)
    task_id = UUID(str(_create(task_harness, csrf_token)["id"]))
    fake = _FakeReadinessService()
    task_harness.task_service._readiness = cast(ReadinessService, fake)
    with task_harness.factory.begin() as session:
        session.get_one(Task, task_id).state = TaskState.READY_FOR_HUMAN_MERGE
    task_harness.clock.advance(timedelta(minutes=6))
    handoff_id = uuid4()
    payload = {
        "handoff_id": str(handoff_id),
        "expected_head_sha": "a" * 40,
        "acknowledgement": HANDOFF_ACKNOWLEDGEMENT,
    }

    stale = task_harness.client.post(
        f"/api/tasks/{task_id}/handoff",
        json=payload,
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )
    assert stale.status_code == 403
    reauthenticated = task_harness.client.post(
        "/api/auth/reauthenticate",
        json={"password": _PASSWORD},
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: csrf_token},
    )
    assert reauthenticated.status_code == 200
    refreshed_csrf = task_harness.client.cookies.get(CSRF_COOKIE_NAME)
    assert refreshed_csrf is not None

    response = task_harness.client.post(
        f"/api/tasks/{task_id}/handoff",
        json=payload,
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: refreshed_csrf},
    )

    assert response.status_code == 200, response.text
    assert response.json() == {
        "handoff_id": str(handoff_id),
        "task_id": str(task_id),
        "task_state": "HANDED_OFF",
        "head_sha": "a" * 40,
        "acknowledgement_evidence_id": response.json()[
            "acknowledgement_evidence_id"
        ],
        "event_id": response.json()["event_id"],
        "meaning": HANDOFF_MEANING,
        "replayed": False,
    }
    assert len(fake.calls) == 1
    rejected = task_harness.client.post(
        f"/api/tasks/{task_id}/handoff",
        json={**payload, "acknowledgement": "merge it"},
        headers={"Origin": _ORIGIN, CSRF_HEADER_NAME: refreshed_csrf},
    )
    assert rejected.status_code == 422


@pytest.mark.parametrize(
    "operation",
    [
        "steering",
        "cancellations",
        "handoff",
    ],
)
def test_task_control_rejects_oversized_body_before_parsing(
    task_harness: TaskHarness,
    operation: str,
) -> None:
    csrf_token = _authenticate(task_harness)
    task_id = UUID(str(_create(task_harness, csrf_token)["id"]))
    response = task_harness.client.post(
        f"/api/tasks/{task_id}/{operation}",
        content=b"x" * (MAX_TASK_REQUEST_BYTES + 1),
        headers={
            "Content-Type": "application/json",
            "Origin": _ORIGIN,
            CSRF_HEADER_NAME: csrf_token,
        },
    )
    assert response.status_code == 413
