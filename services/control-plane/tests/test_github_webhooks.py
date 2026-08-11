import hashlib
import hmac
import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from mathews_configuration import (
    GitHubAppConfiguration,
    SecretReference,
    SecretValue,
)
from mathews_control_plane.app import create_app
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.authentication import AuthenticatedSession
from mathews_control_plane.background_jobs import LeasedJobContext
from mathews_control_plane.database import (
    SessionFactory,
    create_database_engine,
    create_session_factory,
)
from mathews_control_plane.database_base import Base
from mathews_control_plane.domain_models import (
    BackgroundJob,
    EvidenceRecord,
    Task,
    TaskEvent,
    TaskEventEvidenceReference,
    TaskState,
    WebhookDelivery,
)
from mathews_control_plane.evidence import load_evidence
from mathews_control_plane.github_app import GitHubWebhookVerifier
from mathews_control_plane.github_webhooks import (
    GITHUB_CHECK_UPDATED_EVENT,
    GITHUB_REVIEW_UPDATED_EVENT,
    GitHubWebhookJobHandler,
    GitHubWebhookService,
)
from mathews_control_plane.settings import Settings
from mathews_control_plane.tasks import TaskService
from pydantic import SecretStr
from sqlalchemy import func, select

_NOW = datetime(2026, 8, 10, 15, 0, tzinfo=UTC)
_HEAD_SHA = "a" * 40
_NEW_HEAD_SHA = "b" * 40
_WEBHOOK_SECRET = "0123456789abcdef"


class StaticSecretProvider:
    def __init__(self, webhook_reference: SecretReference) -> None:
        self._webhook_reference = webhook_reference

    def get(self, reference: SecretReference) -> SecretValue:
        if reference != self._webhook_reference:
            raise AssertionError("unexpected secret reference")
        return SecretValue(_WEBHOOK_SECRET)


@dataclass(slots=True)
class WebhookHarness:
    client: TestClient
    factory: SessionFactory
    store: ArtifactStore
    service: GitHubWebhookService
    task_service: TaskService
    task_id: UUID
    clock: list[datetime]


@pytest.fixture
def webhook_harness(tmp_path: Path) -> Iterator[WebhookHarness]:
    database_url = f"sqlite:///{tmp_path / 'webhooks.sqlite3'}"
    engine = create_database_engine(database_url)
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    store = ArtifactStore(tmp_path / "artifacts")
    private_key_reference = SecretReference.parse(
        "keychain://com.boppuh.mathews.github-app/private-key"
    )
    webhook_reference = SecretReference.parse(
        "keychain://com.boppuh.mathews.github-app/webhook-secret"
    )
    configuration = GitHubAppConfiguration(
        app_id=101,
        installation_id=202,
        repository_id=303,
        repository_key="boppuh/mathews",
        private_key_ref=private_key_reference,
        webhook_secret_ref=webhook_reference,
    )
    clock = [_NOW]
    service = GitHubWebhookService(
        factory,
        store,
        configuration,
        verifier=GitHubWebhookVerifier(
            configuration,
            secret_provider=StaticSecretProvider(webhook_reference),
        ),
        clock=lambda: clock[0],
    )
    task_id = uuid4()
    with factory.begin() as session:
        session.add(
            Task(
                id=task_id,
                repository="boppuh/mathews",
                base_revision="0" * 40,
                requester="local-user",
                raw_request="evidence://test",
                summary="Observe GitHub state",
                state=TaskState.PR_ACTIVE,
                retry_count=0,
                owner_id="local-user",
                actor_id="local-user",
                root_correlation_id=task_id,
                causation_id=task_id,
            )
        )
    service.bind_pull_request(
        task_id,
        installation_id=202,
        repository_id=303,
        pull_request_number=42,
        task_branch="codex/task-6-3",
        head_sha=_HEAD_SHA,
        required_checks=("test",),
    )
    task_service = TaskService(factory, store, clock=lambda: clock[0])
    app = create_app(
        Settings(database_url=SecretStr(database_url), artifact_root=store.root),
        session_factory=factory,
        task_service=task_service,
        github_webhook_service=service,
    )
    with TestClient(app, base_url="https://localhost") as client:
        yield WebhookHarness(
            client,
            factory,
            store,
            service,
            task_service,
            task_id,
            clock,
        )
    engine.dispose()


def _check_payload(
    *,
    head_sha: str = _HEAD_SHA,
    updated_at: str = "2026-08-10T14:59:00Z",
    status: str = "completed",
    conclusion: str | None = "success",
    check_id: int = 901,
) -> dict[str, object]:
    return {
        "action": "completed" if status == "completed" else "rerequested",
        "installation": {"id": 202},
        "repository": {"id": 303, "full_name": "boppuh/mathews"},
        "check_run": {
            "id": check_id,
            "name": "test",
            "status": status,
            "conclusion": conclusion,
            "head_sha": head_sha,
            "updated_at": updated_at,
            "check_suite": {"id": 801, "head_branch": "codex/task-6-3"},
            "pull_requests": [{"number": 42}],
        },
    }


def _review_payload(
    *,
    state: str = "changes_requested",
    action: str = "submitted",
    review_id: int = 902,
    commit_id: str = _HEAD_SHA,
    submitted_at: str = "2026-08-10T14:59:30Z",
) -> dict[str, object]:
    return {
        "action": action,
        "installation": {"id": 202},
        "repository": {"id": 303, "full_name": "boppuh/mathews"},
        "pull_request": {
            "number": 42,
            "head": {"ref": "codex/task-6-3", "sha": _HEAD_SHA},
        },
        "review": {
            "id": review_id,
            "commit_id": commit_id,
            "state": state,
            "submitted_at": submitted_at,
            "user": {"id": 501, "login": "reviewer"},
        },
    }


def _pull_request_payload(*, head_sha: str) -> dict[str, object]:
    return {
        "action": "synchronize",
        "installation": {"id": 202},
        "repository": {"id": 303, "full_name": "boppuh/mathews"},
        "pull_request": {
            "number": 42,
            "head": {"ref": "codex/task-6-3", "sha": head_sha},
            "state": "open",
            "draft": True,
            "merged": False,
            "updated_at": "2026-08-10T15:00:00Z",
        },
    }


def _thread_payload(*, resolved: bool) -> dict[str, object]:
    return {
        "action": "resolved" if resolved else "unresolved",
        "installation": {"id": 202},
        "repository": {"id": 303, "full_name": "boppuh/mathews"},
        "pull_request": {
            "number": 42,
            "head": {"ref": "codex/task-6-3", "sha": _HEAD_SHA},
        },
        "thread": {"id": 777},
    }


def _post(
    harness: WebhookHarness,
    payload: dict[str, object],
    *,
    event: str = "check_run",
    delivery: str = "delivery-1",
    secret: str = _WEBHOOK_SECRET,
) -> Any:
    body = json.dumps(payload, separators=(",", ":")).encode()
    signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return harness.client.post(
        "/api/github/webhooks",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": event,
            "X-GitHub-Delivery": delivery,
            "X-Hub-Signature-256": signature,
        },
    )


def _authentication() -> AuthenticatedSession:
    return AuthenticatedSession(
        session_id=uuid4(),
        user_id=1,
        csrf_token_digest=b"0" * 32,
        expires_at=_NOW + timedelta(hours=1),
        absolute_expires_at=_NOW + timedelta(hours=1),
        reauthenticated_until=_NOW + timedelta(hours=1),
        evaluated_at=_NOW,
        recent_password_verified=True,
    )


def test_verified_delivery_is_persisted_correlated_and_wakes_task(
    webhook_harness: WebhookHarness,
) -> None:
    response = _post(webhook_harness, _check_payload())

    assert response.status_code == 202
    assert response.json()["disposition"] == "ACCEPTED"
    assert response.headers["Cache-Control"] == "no-store"
    with webhook_harness.factory() as session:
        delivery = session.scalar(select(WebhookDelivery))
        assert delivery is not None
        assert delivery.signature_verified is True
        assert delivery.payload_evidence_id is not None
        assert delivery.processed_at == _NOW.replace(tzinfo=None)
        assert delivery.quarantine_reason is None
        assert session.scalar(select(func.count(EvidenceRecord.id))) == 1
        evidence = session.get(EvidenceRecord, delivery.payload_evidence_id)
        assert evidence is not None
        receipt = load_evidence(session, webhook_harness.store, evidence)
        receipt_content = cast(dict[str, object], receipt.content)
        assert isinstance(receipt_content["signature_header"], str)
        raw_body_address = cast(str, receipt_content["raw_body_artifact"])
        assert webhook_harness.store.get_bytes(raw_body_address) == json.dumps(
            _check_payload(),
            separators=(",", ":"),
        ).encode()
        event = session.scalar(
            select(TaskEvent).where(TaskEvent.event_type == GITHUB_CHECK_UPDATED_EVENT)
        )
        assert event is not None
        assert event.payload["state"] == "PASSED"
        assert session.scalar(
            select(func.count(TaskEventEvidenceReference.id)).where(
                TaskEventEvidenceReference.task_event_id == event.id
            )
        ) == 1
        job = session.scalar(select(BackgroundJob))
        assert job is not None
        assert job.job_type == "github-webhook"
        assert job.task_id == webhook_harness.task_id

    cockpit = webhook_harness.task_service.detail(
        webhook_harness.task_id,
        _authentication(),
    )
    assert cockpit.github.ci_status == "PASSED"
    assert cockpit.github.checks_total == 1
    assert cockpit.github.checks_passed == 1


def test_durable_webhook_wakeup_reconciles_exact_task_readiness() -> None:
    task_id = uuid4()
    event_id = uuid4()
    calls: list[tuple[str, UUID]] = []

    class Reconciler:
        def __init__(self) -> None:
            self.calls: list[tuple[UUID, UUID]] = []

        def reconcile(self, task_id: UUID, *, trigger_event_id: UUID) -> object:
            self.calls.append((task_id, trigger_event_id))
            calls.append(("readiness", trigger_event_id))
            return SimpleNamespace(status=SimpleNamespace(value="READY"))

    class ReviewScheduler:
        def schedule(self, task_event_id: UUID) -> object:
            calls.append(("review", task_event_id))
            return SimpleNamespace(status=SimpleNamespace(value="IGNORED"))

    reconciler = Reconciler()
    context = SimpleNamespace(
        grant=SimpleNamespace(
            task_id=task_id,
            input_payload={
                "delivery_id": "delivery-1",
                "task_event_id": str(event_id),
                "head_sha": _HEAD_SHA,
                "resource_type": "review_comment",
                "resource_state": "OPEN",
            },
        )
    )

    result = GitHubWebhookJobHandler(reconciler, ReviewScheduler())(
        cast(LeasedJobContext, context)
    )

    assert reconciler.calls == [(task_id, event_id)]
    assert calls == [("review", event_id), ("readiness", event_id)]
    assert result["review_resolution_status"] == "IGNORED"
    assert result["readiness_status"] == "READY"


def test_duplicate_delivery_replays_without_duplicate_event_or_job(
    webhook_harness: WebhookHarness,
) -> None:
    first = _post(webhook_harness, _check_payload())
    replay = _post(webhook_harness, _check_payload())

    assert first.status_code == 202
    assert replay.status_code == 200
    assert replay.json()["disposition"] == "REPLAYED"
    with webhook_harness.factory() as session:
        assert session.scalar(select(func.count(WebhookDelivery.id))) == 1
        assert session.scalar(
            select(func.count(TaskEvent.id)).where(
                TaskEvent.event_type == GITHUB_CHECK_UPDATED_EVENT
            )
        ) == 1
        assert session.scalar(select(func.count(BackgroundJob.id))) == 1


def test_bad_signature_is_rejected_before_any_receipt(
    webhook_harness: WebhookHarness,
) -> None:
    response = _post(webhook_harness, _check_payload(), secret="wrong-secret-value")

    assert response.status_code == 401
    assert response.json() == {"detail": "webhook verification failed"}
    with webhook_harness.factory() as session:
        assert session.scalar(select(func.count(WebhookDelivery.id))) == 0
        assert session.scalar(select(func.count(EvidenceRecord.id))) == 0


def test_stale_and_old_head_deliveries_are_audited_without_regression(
    webhook_harness: WebhookHarness,
) -> None:
    accepted = _post(webhook_harness, _check_payload(), delivery="newer")
    stale = _post(
        webhook_harness,
        _check_payload(updated_at="2026-08-10T14:58:00Z"),
        delivery="older",
    )
    old_head = _post(
        webhook_harness,
        _check_payload(head_sha=_NEW_HEAD_SHA),
        delivery="old-head",
    )

    assert accepted.json()["disposition"] == "ACCEPTED"
    assert stale.json()["disposition"] == "STALE"
    assert old_head.json()["disposition"] == "STALE"
    with webhook_harness.factory() as session:
        assert session.scalar(select(func.count(WebhookDelivery.id))) == 3
        assert session.scalar(select(func.count(EvidenceRecord.id))) == 3
        assert session.scalar(
            select(func.count(TaskEvent.id)).where(
                TaskEvent.event_type == GITHUB_CHECK_UPDATED_EVENT
            )
        ) == 1
        assert session.scalar(select(func.count(BackgroundJob.id))) == 1


def test_review_updates_cockpit_and_unknown_events_are_quarantined(
    webhook_harness: WebhookHarness,
) -> None:
    review = _post(
        webhook_harness,
        _review_payload(),
        event="pull_request_review",
        delivery="review-1",
    )
    unknown = _post(
        webhook_harness,
        {"installation": {"id": 202}},
        event="issues",
        delivery="unknown-1",
    )

    assert review.status_code == 202
    assert review.json()["disposition"] == "ACCEPTED"
    assert unknown.status_code == 202
    assert unknown.json()["disposition"] == "QUARANTINED"
    cockpit = webhook_harness.task_service.detail(
        webhook_harness.task_id,
        _authentication(),
    )
    assert cockpit.github.review_status == "CHANGES_REQUESTED"
    assert cockpit.github.blocking_reviews == 1
    with webhook_harness.factory() as session:
        review_event = session.scalar(
            select(TaskEvent).where(TaskEvent.event_type == GITHUB_REVIEW_UPDATED_EVENT)
        )
        assert review_event is not None
        unknown_delivery = session.scalar(
            select(WebhookDelivery).where(
                WebhookDelivery.provider_delivery_id == "unknown-1"
            )
        )
        assert unknown_delivery is not None
        assert unknown_delivery.quarantine_reason == "event_not_allowed"


def test_reused_delivery_id_with_different_body_is_a_conflict(
    webhook_harness: WebhookHarness,
) -> None:
    assert _post(webhook_harness, _check_payload()).status_code == 202
    changed = _post(
        webhook_harness,
        _check_payload(status="in_progress", conclusion=None),
    )

    assert changed.status_code == 409
    assert changed.json() == {"detail": "webhook delivery conflict"}


def test_ambiguous_exact_correlation_is_quarantined(
    webhook_harness: WebhookHarness,
) -> None:
    second_task_id = uuid4()
    with webhook_harness.factory.begin() as session:
        session.add(
            Task(
                id=second_task_id,
                repository="boppuh/mathews",
                base_revision="0" * 40,
                requester="local-user",
                raw_request="evidence://test-2",
                summary="Conflicting binding",
                state=TaskState.PR_ACTIVE,
                retry_count=0,
                owner_id="local-user",
                actor_id="local-user",
                root_correlation_id=second_task_id,
                causation_id=second_task_id,
            )
        )
    webhook_harness.service.bind_pull_request(
        second_task_id,
        installation_id=202,
        repository_id=303,
        pull_request_number=42,
        task_branch="codex/task-6-3",
        head_sha=_HEAD_SHA,
        required_checks=("test",),
    )

    response = _post(webhook_harness, _check_payload(), delivery="ambiguous")

    assert response.status_code == 202
    assert response.json()["disposition"] == "QUARANTINED"
    with webhook_harness.factory() as session:
        delivery = session.scalar(
            select(WebhookDelivery).where(
                WebhookDelivery.provider_delivery_id == "ambiguous"
            )
        )
        assert delivery is not None
        assert delivery.quarantine_reason == "correlation_ambiguous"
        assert session.scalar(select(func.count(BackgroundJob.id))) == 0


def test_webhook_body_is_bounded_before_verification(
    webhook_harness: WebhookHarness,
) -> None:
    response = webhook_harness.client.post(
        "/api/github/webhooks",
        content=b"x" * (1024 * 1024 + 1),
        headers={
            "X-GitHub-Event": "check_run",
            "X-GitHub-Delivery": "oversized",
            "X-Hub-Signature-256": "sha256=" + "0" * 64,
        },
    )

    assert response.status_code == 413
    assert response.json() == {"detail": "webhook request body too large"}
    with webhook_harness.factory() as session:
        assert session.scalar(select(func.count(WebhookDelivery.id))) == 0


def test_check_rerun_replaces_failed_generation(
    webhook_harness: WebhookHarness,
) -> None:
    assert _post(
        webhook_harness,
        _check_payload(
            updated_at="2026-08-10T14:58:00Z",
            conclusion="failure",
        ),
        delivery="check-failed",
    ).status_code == 202
    assert _post(
        webhook_harness,
        _check_payload(check_id=902),
        delivery="check-rerun",
    ).status_code == 202

    cockpit = webhook_harness.task_service.detail(
        webhook_harness.task_id,
        _authentication(),
    )
    assert cockpit.github.ci_status == "PASSED"
    assert cockpit.github.checks_total == 1
    assert cockpit.github.checks_passed == 1


def test_missing_required_check_cannot_report_ci_passed(
    webhook_harness: WebhookHarness,
) -> None:
    webhook_harness.service.bind_pull_request(
        webhook_harness.task_id,
        installation_id=202,
        repository_id=303,
        pull_request_number=42,
        task_branch="codex/task-6-3",
        head_sha=_HEAD_SHA,
        required_checks=("lint", "test"),
    )
    assert _post(
        webhook_harness,
        _check_payload(),
        delivery="only-one-required-check",
    ).status_code == 202

    cockpit = webhook_harness.task_service.detail(
        webhook_harness.task_id,
        _authentication(),
    )
    assert cockpit.github.ci_status == "PENDING"
    assert cockpit.github.checks_total == 2
    assert cockpit.github.checks_passed == 1


def test_latest_review_per_reviewer_and_exact_commit_control_status(
    webhook_harness: WebhookHarness,
) -> None:
    assert _post(
        webhook_harness,
        _review_payload(),
        event="pull_request_review",
        delivery="changes-requested",
    ).json()["disposition"] == "ACCEPTED"
    assert _post(
        webhook_harness,
        _review_payload(
            state="approved",
            review_id=903,
            submitted_at="2026-08-10T14:59:45Z",
        ),
        event="pull_request_review",
        delivery="approved",
    ).json()["disposition"] == "ACCEPTED"
    stale_commit = _post(
        webhook_harness,
        _review_payload(
            state="changes_requested",
            review_id=904,
            commit_id=_NEW_HEAD_SHA,
            submitted_at="2026-08-10T14:59:50Z",
        ),
        event="pull_request_review",
        delivery="stale-review-commit",
    )

    assert stale_commit.json()["disposition"] == "STALE"
    cockpit = webhook_harness.task_service.detail(
        webhook_harness.task_id,
        _authentication(),
    )
    assert cockpit.github.review_status == "APPROVED"
    assert cockpit.github.blocking_reviews == 0


def test_dismissal_and_thread_resolution_replace_blocking_review_state(
    webhook_harness: WebhookHarness,
) -> None:
    assert _post(
        webhook_harness,
        _review_payload(),
        event="pull_request_review",
        delivery="review-before-dismissal",
    ).json()["disposition"] == "ACCEPTED"
    webhook_harness.clock[0] += timedelta(seconds=1)
    assert _post(
        webhook_harness,
        _review_payload(state="dismissed", action="dismissed"),
        event="pull_request_review",
        delivery="review-dismissed",
    ).json()["disposition"] == "ACCEPTED"
    assert _post(
        webhook_harness,
        _thread_payload(resolved=False),
        event="pull_request_review_thread",
        delivery="thread-open",
    ).json()["disposition"] == "ACCEPTED"
    webhook_harness.clock[0] += timedelta(seconds=1)
    assert _post(
        webhook_harness,
        _thread_payload(resolved=True),
        event="pull_request_review_thread",
        delivery="thread-resolved",
    ).json()["disposition"] == "ACCEPTED"

    cockpit = webhook_harness.task_service.detail(
        webhook_harness.task_id,
        _authentication(),
    )
    assert cockpit.github.review_status == "COMMENTED"
    assert cockpit.github.blocking_reviews == 0
    assert cockpit.github.review_comments == 0


def test_synchronized_pr_head_wakes_reconciliation_and_invalidates_projection(
    webhook_harness: WebhookHarness,
) -> None:
    response = _post(
        webhook_harness,
        _pull_request_payload(head_sha=_NEW_HEAD_SHA),
        event="pull_request",
        delivery="head-changed",
    )

    assert response.status_code == 202
    assert response.json()["disposition"] == "ACCEPTED"
    cockpit = webhook_harness.task_service.detail(
        webhook_harness.task_id,
        _authentication(),
    )
    assert cockpit.github.head_sha == _NEW_HEAD_SHA
    assert cockpit.github.ci_status == "NOT_RUN"
    check = _post(
        webhook_harness,
        _check_payload(head_sha=_NEW_HEAD_SHA),
        delivery="new-head-check",
    )
    assert check.json()["disposition"] == "ACCEPTED"
    cockpit = webhook_harness.task_service.detail(
        webhook_harness.task_id,
        _authentication(),
    )
    assert cockpit.github.ci_status == "PASSED"
    with webhook_harness.factory() as session:
        assert session.scalar(select(func.count(BackgroundJob.id))) == 2


def test_unreadable_committed_receipt_is_quarantined_without_blocking_drain(
    webhook_harness: WebhookHarness,
) -> None:
    assert _post(
        webhook_harness,
        _check_payload(),
        delivery="corrupt-receipt",
    ).status_code == 202
    with webhook_harness.factory.begin() as session:
        delivery = session.scalar(
            select(WebhookDelivery).where(
                WebhookDelivery.provider_delivery_id == "corrupt-receipt"
            )
        )
        assert delivery is not None
        evidence = session.get(EvidenceRecord, delivery.payload_evidence_id)
        assert evidence is not None
        evidence.content_address = "sha256:" + "0" * 64
        delivery.processed_at = None

    assert webhook_harness.service.process_pending() == 1
    with webhook_harness.factory() as session:
        delivery = session.scalar(
            select(WebhookDelivery).where(
                WebhookDelivery.provider_delivery_id == "corrupt-receipt"
            )
        )
        assert delivery is not None
        assert delivery.quarantine_reason == "payload_evidence_unreadable"
        assert delivery.processed_at is not None
