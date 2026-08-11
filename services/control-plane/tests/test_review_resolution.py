from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from uuid import UUID, uuid4

import mathews_control_plane.review_resolution as review_module
import pytest
from mathews_configuration import HostResponseMessage, HostResponseStatus, JsonValue
from mathews_control_plane.approvals import (
    ApprovalRequestResult,
    ApprovalService,
    BlockedOperation,
)
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.background_jobs import (
    BackgroundJobService,
    JobLeaseGrant,
    LeasedJobContext,
    ScheduledJob,
    TerminalBackgroundJobError,
)
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    ApprovalRequestType,
    ApprovalStatus,
    ReviewRule,
    TaskState,
    ValidationOutcome,
)
from mathews_control_plane.draft_pull_requests import DraftPullRequestResult
from mathews_control_plane.hermes_adapter import HermesJobPrompt
from mathews_control_plane.prompt_compiler import PromptCompilerService, PromptRole
from mathews_control_plane.review_resolution import (
    BoundedReviewClassifier,
    ReviewClassification,
    ReviewComment,
    ReviewDisposition,
    ReviewResolutionError,
    ReviewResolutionJobHandler,
    ReviewResolutionJobInput,
    ReviewResolutionService,
    ReviewRisk,
    ReviewScheduleStatus,
    _Authorization,
    _review_fingerprint,
    _ReviewContext,
    _rule_matches,
    _unsafe_reason,
    _validated_candidate_response,
)
from mathews_control_plane.task_state_machine import (
    TaskTransitionKind,
    TaskTransitionResult,
    ValidationCandidate,
)
from mathews_control_plane.validation_decisioning import ValidationDecisionResult

_NOW = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
_HEAD = "a" * 40
_CANDIDATE = "b" * 40
_TREE = "c" * 40


def _comment() -> ReviewComment:
    return ReviewComment(
        uuid4(),
        uuid4(),
        uuid4(),
        42,
        7,
        "codex/task",
        _HEAD,
        "Sources/View.swift",
        "Please apply the formatter to this file.",
        "reviewer",
    )


def _context() -> _ReviewContext:
    comment = _comment()
    return _ReviewContext(
        comment,
        "local-user",
        comment.task_id,
        0,
        uuid4(),
        ("Sources",),
        ("Project.xcodeproj", ".github"),
        uuid4(),
        3,
        uuid4(),
        4,
        uuid4(),
        1,
        3600,
    )


def _classification(**overrides: object) -> ReviewClassification:
    values: dict[str, object] = {
        "disposition": ReviewDisposition.ACTIONABLE,
        "category": "formatting",
        "action": "repair.format",
        "risk": ReviewRisk.LOW,
        "labels": ("formatter",),
        "proposed_paths": ("Sources/View.swift",),
        "rationale": "A deterministic formatting repair.",
    }
    values.update(overrides)
    return ReviewClassification.model_validate(values)


def test_bounded_classifier_rejects_untyped_or_path_unsafe_output() -> None:
    comment = _comment()
    classifier = BoundedReviewClassifier(
        lambda _comment: {
            **_classification().model_dump(mode="json"),
            "proposed_paths": ["../outside"],
        }
    )

    with pytest.raises(ReviewResolutionError, match="REVIEW_CLASSIFICATION_INVALID"):
        classifier.classify(comment)


@pytest.mark.parametrize(
    ("overrides", "retry_count", "reason"),
    [
        ({"risk": ReviewRisk.HIGH}, None, "REVIEW_RISK_NOT_LOW"),
        ({"dependency_change": True}, None, "REVIEW_DEPENDENCY_CHANGE"),
        ({"schema_change": True}, None, "REVIEW_SCHEMA_CHANGE"),
        ({"signing_change": True}, None, "REVIEW_SIGNING_CHANGE"),
        ({"security_change": True}, None, "REVIEW_SECURITY_CHANGE"),
        (
            {"disposition": ReviewDisposition.AMBIGUOUS},
            None,
            "REVIEW_AMBIGUOUS",
        ),
        (
            {"proposed_paths": ("Other/File.swift",)},
            None,
            "REVIEW_PATH_OUTSIDE_SCOPE",
        ),
        ({}, 1, "REVIEW_RETRY_BUDGET_EXHAUSTED"),
    ],
)
def test_automatic_repair_closes_for_every_non_low_risk_boundary(
    overrides: dict[str, object],
    retry_count: int | None,
    reason: str,
) -> None:
    context = _context()
    if retry_count is not None:
        context = replace(context, task_retry_count=retry_count)

    assert _unsafe_reason(context, _classification(**overrides)) == reason


def test_exact_low_risk_in_scope_classification_is_eligible() -> None:
    assert _unsafe_reason(_context(), _classification()) is None


def test_rule_match_requires_exact_action_labels_scope_and_low_risk() -> None:
    rule = ReviewRule(
        approval_status=ApprovalStatus.APPROVED,
        approval_request_type="REVIEW_RULE",
        risk_class="LOW",
        permitted_action="repair.format",
        matcher={"categories": ["formatting"], "required_labels": ["formatter"]},
        scope={"path_prefixes": ["Sources"], "max_files": 1},
        evidence_requirements=[
            "github-webhook",
            "review-repair-candidate",
            "validation-decision",
            "draft-pull-request-proof",
        ],
    )

    assert _rule_matches(rule, _classification())
    assert not _rule_matches(rule, _classification(action="repair.logic"))
    assert not _rule_matches(rule, _classification(labels=()))
    assert not _rule_matches(
        rule,
        _classification(proposed_paths=("Sources/A.swift", "Sources/B.swift")),
    )
    rule.evidence_requirements = ["unavailable-evidence"]
    assert not _rule_matches(rule, _classification())


def test_review_fingerprint_binds_comment_head_policy_and_classification() -> None:
    context = _context()
    classification = _classification()

    first = _review_fingerprint(context, classification)
    replay = _review_fingerprint(context, classification)
    changed = _review_fingerprint(
        replace(context, comment=replace(context.comment, head_sha="d" * 40)),
        classification,
    )

    assert first == replay
    assert first != changed
    assert len(first) == 64


@dataclass
class _FakeClassifier:
    result: ReviewClassification

    def classify(self, _comment: ReviewComment) -> ReviewClassification:
        return self.result


class _FakePrompts:
    def compile(self, task_id: UUID, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(
            task_id=task_id,
            role=PromptRole.IMPLEMENTER,
            template_id=uuid4(),
            template_version=2,
            policy_version_id=_kwargs["policy_version_id"],
            evaluation_label=None,
            content="Apply only the authorized review repair.",
            evidence_ids=tuple(cast(tuple[UUID, ...], _kwargs["evidence_ids"])),
        )


class _FakeApprovals:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def request(self, task_id: UUID, **kwargs: object) -> ApprovalRequestResult:
        self.calls.append({"task_id": task_id, **kwargs})
        return ApprovalRequestResult(
            task_id,
            cast(UUID, kwargs["request_id"]),
            ApprovalStatus.PENDING,
            TaskState.ESCALATED,
            uuid4(),
            uuid4(),
        )


class _FakeJobs:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def schedule(self, **kwargs: object) -> ScheduledJob:
        self.calls.append(dict(kwargs))
        return ScheduledJob(uuid4(), False)


def _service(
    tmp_path: Path,
    classification: ReviewClassification,
    approvals: _FakeApprovals,
) -> ReviewResolutionService:
    service = ReviewResolutionService(
        cast(SessionFactory, object()),
        ArtifactStore(tmp_path / "artifacts"),
        _FakeClassifier(classification),
        clock=lambda: _NOW,
        prompts=cast(PromptCompilerService, _FakePrompts()),
        approvals=cast(ApprovalService, approvals),
    )
    service._jobs = cast(BackgroundJobService, _FakeJobs())
    return service


def test_schedule_builds_exact_rule_bound_repair_job(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _context()
    classification = _classification()
    approvals = _FakeApprovals()
    service = _service(tmp_path, classification, approvals)
    authorization = _Authorization("REVIEW_RULE", uuid4(), None, "REVIEW_RULE_MATCHED")
    monkeypatch.setattr(review_module, "_review_context", lambda *_args, **_kwargs: context)
    monkeypatch.setattr(review_module, "_authorization", lambda *_args, **_kwargs: authorization)
    monkeypatch.setattr(review_module, "_capture_assessment", lambda *_args, **_kwargs: None)

    result = service.schedule(context.comment.task_event_id)

    jobs = cast(_FakeJobs, service._jobs)
    assert result.status is ReviewScheduleStatus.SCHEDULED
    assert result.job_id is not None
    assert approvals.calls == []
    assert len(jobs.calls) == 1
    job_input = ReviewResolutionJobInput.model_validate(jobs.calls[0]["input_payload"])
    assert job_input.authorization_source == "REVIEW_RULE"
    assert job_input.review_rule_id == authorization.rule_id
    assert job_input.original_head_sha == _HEAD
    assert job_input.authorized_paths == ("Sources/View.swift",)
    assert job_input.prompt.evidence_ids == (result.assessment_evidence_id,)


def test_unsafe_review_requests_bounded_one_off_approval_without_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _context()
    classification = _classification(security_change=True)
    approvals = _FakeApprovals()
    service = _service(tmp_path, classification, approvals)
    authorization = _Authorization(None, None, None, "REVIEW_SECURITY_CHANGE")
    monkeypatch.setattr(review_module, "_review_context", lambda *_args, **_kwargs: context)
    monkeypatch.setattr(review_module, "_authorization", lambda *_args, **_kwargs: authorization)
    monkeypatch.setattr(review_module, "_capture_assessment", lambda *_args, **_kwargs: None)

    result = service.schedule(context.comment.task_event_id)

    assert result.status is ReviewScheduleStatus.APPROVAL_REQUIRED
    assert result.approval_request_id is not None
    assert len(approvals.calls) == 1
    call = approvals.calls[0]
    assert call["request_type"] is ApprovalRequestType.REVIEW_CONFLICT
    assert call["reason_code"] == "REVIEW_SECURITY_CHANGE"
    assert cast(BlockedOperation, call["blocked_operation"]).operation_name == (
        "review.repair"
    )
    assert cast(_FakeJobs, service._jobs).calls == []


class _FakeTransitions:
    calls: list[dict[str, object]] = []

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        type(self).calls = []

    def transition_task(self, _grant: JobLeaseGrant, **kwargs: object) -> SimpleNamespace:
        type(self).calls.append(dict(kwargs))
        return SimpleNamespace(transition_id=kwargs["transition_id"])


class _FakeLeasedContext:
    def __init__(self, grant: JobLeaseGrant) -> None:
        self.grant = grant
        self.service = cast(BackgroundJobService, object())
        self.heartbeats: list[timedelta] = []

    def heartbeat(self, extension: timedelta) -> None:
        self.heartbeats.append(extension)


class _FakeValidator:
    def __init__(self, result: ValidationDecisionResult) -> None:
        self.result = result
        self.calls: list[ValidationCandidate] = []

    def validate(self, _context: object, **kwargs: object) -> ValidationDecisionResult:
        self.calls.append(cast(ValidationCandidate, kwargs["candidate"]))
        return self.result


class _FakePublisher:
    def __init__(self, task_id: UUID) -> None:
        self.task_id = task_id
        self.calls: list[dict[str, object]] = []

    def open(self, task_id: UUID, **kwargs: object) -> DraftPullRequestResult:
        self.calls.append({"task_id": task_id, **kwargs})
        transition = TaskTransitionResult(
            task_id,
            cast(UUID, kwargs["transition_id"]),
            uuid4(),
            10,
            TaskState.VALIDATING,
            TaskState.PR_ACTIVE,
        )
        return DraftPullRequestResult(
            task_id,
            7,
            "https://github.com/boppuh/mathews/pull/7",
            cast(str, kwargs["commit_sha"]),
            uuid4(),
            transition,
        )


def _job_input(task_id: UUID) -> ReviewResolutionJobInput:
    return ReviewResolutionJobInput(
        task_id=task_id,
        task_event_id=uuid4(),
        assessment_evidence_id=uuid4(),
        assessment_fingerprint="d" * 64,
        review_fingerprint="e" * 64,
        authorization_source="REVIEW_RULE",
        policy_version_id=uuid4(),
        review_rule_id=uuid4(),
        original_head_sha=_HEAD,
        validation_contract_id=uuid4(),
        validation_contract_version=3,
        repository_configuration_id=uuid4(),
        repository_configuration_version=4,
        authorized_paths=("Sources/View.swift",),
        max_attempts=1,
        prompt=HermesJobPrompt(
            task_id=task_id,
            role=PromptRole.IMPLEMENTER,
            template_id=uuid4(),
            template_version=2,
            policy_version_id=uuid4(),
            content="Repair the exact review finding.",
        ),
    )


def _decision(job_input: ReviewResolutionJobInput) -> ValidationDecisionResult:
    return ValidationDecisionResult(
        uuid4(),
        job_input.task_id,
        uuid4(),
        job_input.validation_contract_id,
        job_input.validation_contract_version,
        job_input.repository_configuration_id,
        job_input.repository_configuration_version,
        _CANDIDATE,
        _TREE,
        ValidationOutcome.PASSED,
        "VALIDATION_PASSED",
        uuid4(),
        _NOW,
        True,
        False,
    )


def _grant(job_input: ReviewResolutionJobInput) -> JobLeaseGrant:
    return JobLeaseGrant(
        uuid4(),
        job_input.task_id,
        uuid4(),
        "worker-1",
        1,
        1,
        _NOW + timedelta(minutes=5),
        "review-resolution",
        job_input.model_dump(mode="json"),
        None,
        0,
        False,
    )


def _commit_response(
    *,
    changed_paths: list[str] | None = None,
    fencing_token: int = 1,
    replayed: bool = False,
) -> HostResponseMessage:
    return HostResponseMessage(
        request_id=uuid4(),
        operation_name="git.commit",
        idempotency_key="review-repair-commit:test",
        host_id="host-1",
        host_version="1.0",
        status=HostResponseStatus.OK,
        code="OK",
        replayed=replayed,
        completed_at_ms=1,
        result=cast(
            dict[str, JsonValue],
            {
                "committed": True,
                "clean": True,
                "changed_paths": changed_paths or ["Sources/View.swift"],
                "head_sha": _CANDIDATE,
                "tree_sha": _TREE,
            },
        ),
        execution_fencing_token=fencing_token,
    )


def test_candidate_response_requires_exact_paths_and_current_fence() -> None:
    job_input = _job_input(uuid4())

    result = _validated_candidate_response(
        _commit_response(), job_input=job_input, fencing_token=1
    )

    assert result["head_sha"] == _CANDIDATE
    for response in (
        _commit_response(changed_paths=["Sources"]),
        _commit_response(changed_paths=["Sources/View.swift", "Sources/View.swift"]),
        _commit_response(fencing_token=2),
    ):
        with pytest.raises(TerminalBackgroundJobError, match="REVIEW_CANDIDATE_INVALID"):
            _validated_candidate_response(
                response, job_input=job_input, fencing_token=1
            )


def test_replayed_candidate_response_accepts_the_original_fence() -> None:
    result = _validated_candidate_response(
        _commit_response(fencing_token=2, replayed=True),
        job_input=_job_input(uuid4()),
        fencing_token=1,
    )

    assert result["head_sha"] == _CANDIDATE


def test_handler_commits_new_head_fully_revalidates_and_updates_only_draft_pr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    job_input = _job_input(uuid4())
    validator = _FakeValidator(_decision(job_input))
    publisher = _FakePublisher(job_input.task_id)
    handler = ReviewResolutionJobHandler(
        cast(SessionFactory, object()),
        ArtifactStore(tmp_path / "artifacts"),
        cast(review_module.ReviewHostGateway, object()),
        cast(review_module.ReviewHermesHandler, object()),
        cast(review_module.FullReviewValidator, validator),
        cast(review_module.DraftReviewPublisher, publisher),
        clock=lambda: _NOW,
    )
    monkeypatch.setattr(review_module, "BackgroundJobService", _FakeTransitions)
    monkeypatch.setattr(handler, "_run_hermes", lambda *_args: {"status": "SUCCEEDED"})
    monkeypatch.setattr(
        handler,
        "_commit",
        lambda *_args: {
            "head_sha": _CANDIDATE,
            "tree_sha": _TREE,
            "changed_paths": ["Sources/View.swift"],
            "committed": True,
            "clean": True,
        },
    )
    monkeypatch.setattr(handler, "_capture_candidate", lambda *_args: uuid4())
    context = _FakeLeasedContext(_grant(job_input))

    result = handler(cast(LeasedJobContext, context))

    assert result["status"] == "DRAFT_PR_UPDATED"
    assert result["candidate_commit_sha"] == _CANDIDATE
    assert [call["kind"] for call in _FakeTransitions.calls] == [
        TaskTransitionKind.BEGIN_REPAIR,
        TaskTransitionKind.REVALIDATE,
    ]
    assert validator.calls == [ValidationCandidate(_CANDIDATE, _TREE)]
    assert len(publisher.calls) == 1
    assert publisher.calls[0]["commit_sha"] == _CANDIDATE
    assert "merge" not in publisher.calls[0]


def test_handler_refuses_to_publish_without_current_full_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    job_input = _job_input(uuid4())
    failed = replace(_decision(job_input), outcome=ValidationOutcome.FAILED)
    validator = _FakeValidator(failed)
    publisher = _FakePublisher(job_input.task_id)
    handler = ReviewResolutionJobHandler(
        cast(SessionFactory, object()),
        ArtifactStore(tmp_path / "artifacts"),
        cast(review_module.ReviewHostGateway, object()),
        cast(review_module.ReviewHermesHandler, object()),
        cast(review_module.FullReviewValidator, validator),
        cast(review_module.DraftReviewPublisher, publisher),
        clock=lambda: _NOW,
    )
    monkeypatch.setattr(review_module, "BackgroundJobService", _FakeTransitions)
    monkeypatch.setattr(handler, "_run_hermes", lambda *_args: {"status": "SUCCEEDED"})
    monkeypatch.setattr(
        handler,
        "_commit",
        lambda *_args: {
            "head_sha": _CANDIDATE,
            "tree_sha": _TREE,
            "changed_paths": ["Sources/View.swift"],
        },
    )
    monkeypatch.setattr(handler, "_capture_candidate", lambda *_args: uuid4())

    with pytest.raises(
        TerminalBackgroundJobError, match="REVIEW_FULL_REVALIDATION_FAILED"
    ):
        handler(cast(LeasedJobContext, _FakeLeasedContext(_grant(job_input))))

    assert publisher.calls == []
