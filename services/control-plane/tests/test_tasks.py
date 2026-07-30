from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from mathews_control_plane.app import create_app
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.authentication import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    AuthenticationService,
    generate_bootstrap_token,
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
    ApprovalRequestType,
    ApprovalStatus,
    EvidenceRecord,
    ReconciliationStatus,
    ReconciliationTarget,
    ReconciliationTargetKind,
    Task,
    TaskEvent,
    TaskEventEvidenceReference,
    TaskState,
)
from mathews_control_plane.evidence import load_evidence
from mathews_control_plane.settings import Settings
from mathews_control_plane.tasks import (
    MAX_TASK_REQUEST_BYTES,
    TASK_INTAKE_EVENT_TYPE,
    TaskService,
)
from pydantic import SecretStr
from sqlalchemy import Engine, func, select

_ORIGIN = "http://localhost:3000"
_PASSWORD = "correct horse battery staple"
_BASE_SHA = "A" * 40


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
    bootstrap_token: str


@pytest.fixture
def task_harness(tmp_path: Path) -> Iterator[TaskHarness]:
    database_url = f"sqlite:///{tmp_path / 'tasks.sqlite3'}"
    engine = create_database_engine(database_url)
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    store = ArtifactStore(tmp_path / "artifacts")
    clock = MutableClock(datetime(2026, 7, 30, 12, 0, tzinfo=UTC))
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
        "last_activity_at": "2026-07-30T12:00:00Z",
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
            "label": "Reconciliation required",
            "count": 1,
        },
    ]


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
