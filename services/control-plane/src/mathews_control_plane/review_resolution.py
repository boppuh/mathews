"""Policy-gated, one-cycle GitHub review repair orchestration."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Protocol, cast
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from mathews_configuration import (
    HostOperation,
    HostRequestMessage,
    HostResponseMessage,
    HostResponseStatus,
    JsonValue,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from mathews_control_plane.approvals import ApprovalService, BlockedOperation
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.background_jobs import (
    BackgroundJobService,
    JobLeaseGrant,
    LeasedJobContext,
    ScheduledJob,
    TerminalBackgroundJobError,
    require_current_job_lease,
)
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    ApprovalRequest,
    ApprovalRequestType,
    ApprovalStatus,
    Brief,
    EvidenceRecord,
    PolicyVersion,
    PolicyVersionReviewRule,
    RepositoryConfiguration,
    ReviewRule,
    Task,
    TaskCancellation,
    TaskEvent,
    TaskEventEvidenceReference,
    TaskState,
    ValidationContract,
    ValidationOutcome,
)
from mathews_control_plane.draft_pull_requests import DraftPullRequestResult
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceError,
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
    load_evidence,
)
from mathews_control_plane.github_webhooks import (
    GITHUB_PR_BOUND_EVENT,
    GITHUB_PR_HEAD_CHANGED_EVENT,
    GITHUB_REVIEW_UPDATED_EVENT,
)
from mathews_control_plane.hermes_adapter import HermesJobInput, HermesJobPrompt
from mathews_control_plane.host_gateway import authority_for_job_lease
from mathews_control_plane.prompt_compiler import PromptCompilerService, PromptRole
from mathews_control_plane.repository_configuration import (
    validated_repository_configuration,
)
from mathews_control_plane.task_state_machine import (
    TaskTransitionGateEvaluator,
    TaskTransitionGuards,
    TaskTransitionKind,
    ValidationCandidate,
)
from mathews_control_plane.validation_decisioning import ValidationDecisionResult

REVIEW_RESOLUTION_JOB_TYPE = "review-resolution"
REVIEW_RESOLUTION_SCHEMA_VERSION = 1
DEFAULT_MAX_REVIEW_REPAIRS = 1
DEFAULT_APPROVAL_LIFETIME_SECONDS = 86_400
MAX_REVIEW_REPAIRS = 5
_GIT_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_AVAILABLE_REVIEW_EVIDENCE_TYPES = frozenset(
    {
        "github-webhook",
        "review-resolution-assessment",
        "hermes-tool-proposal",
        "hermes-tool-authorization",
        "hermes-tool-result",
        "workspace-diff",
        "review-repair-candidate",
        "validation-decision",
        "draft-pull-request-proof",
    }
)


class ReviewResolutionError(RuntimeError):
    """Stable review-resolution refusal without review or artifact contents."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ReviewDisposition(StrEnum):
    ACTIONABLE = "ACTIONABLE"
    INFORMATIONAL = "INFORMATIONAL"
    AMBIGUOUS = "AMBIGUOUS"
    CONFLICTING = "CONFLICTING"
    SPECULATIVE = "SPECULATIVE"
    SCOPE_EXPANDING = "SCOPE_EXPANDING"


class ReviewRisk(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ReviewScheduleStatus(StrEnum):
    SCHEDULED = "SCHEDULED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    IGNORED = "IGNORED"


class ReviewClassification(BaseModel):
    """Bounded classifier output; it is never itself authorization."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    disposition: ReviewDisposition
    category: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9._-]+$")
    action: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._:/-]+$")
    risk: ReviewRisk
    labels: tuple[str, ...] = Field(default=(), max_length=20)
    proposed_paths: tuple[str, ...] = Field(default=(), max_length=32)
    dependency_change: bool = False
    schema_change: bool = False
    signing_change: bool = False
    security_change: bool = False
    rationale: str = Field(min_length=1, max_length=2_000)

    @field_validator("labels")
    @classmethod
    def _labels(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(
            _identifier(value, "classification label", maximum=100)
            for value in values
        )
        if len(normalized) != len(set(normalized)):
            raise ValueError("classification labels must be unique")
        return normalized

    @field_validator("proposed_paths")
    @classmethod
    def _paths(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_path(value) for value in values)
        if len(normalized) != len(set(normalized)):
            raise ValueError("classification paths must be unique")
        return normalized


@dataclass(frozen=True, slots=True)
class ReviewComment:
    task_id: UUID
    task_event_id: UUID
    evidence_id: UUID
    comment_id: int
    pull_request_number: int
    branch_name: str
    head_sha: str
    path: str
    body: str
    author: str


class ReviewClassifier(Protocol):
    def classify(self, comment: ReviewComment) -> ReviewClassification: ...


class BoundedReviewClassifier:
    """Validate an injected classifier provider at the typed trust boundary."""

    def __init__(
        self,
        provider: Callable[[ReviewComment], Mapping[str, object]],
    ) -> None:
        self._provider = provider

    def classify(self, comment: ReviewComment) -> ReviewClassification:
        try:
            return ReviewClassification.model_validate(self._provider(comment))
        except (TypeError, ValueError):
            raise ReviewResolutionError("REVIEW_CLASSIFICATION_INVALID") from None


class ConservativeReviewClassifier:
    """Fail closed to a human decision when no bounded classifier is configured."""

    def classify(self, comment: ReviewComment) -> ReviewClassification:
        return ReviewClassification(
            disposition=ReviewDisposition.AMBIGUOUS,
            category="unclassified-review",
            action="code.edit",
            risk=ReviewRisk.HIGH,
            labels=("human-classification-required",),
            proposed_paths=(comment.path,),
            rationale=(
                "No production review classifier is configured; human review is required."
            ),
        )


@dataclass(frozen=True, slots=True)
class ReviewScheduleResult:
    task_id: UUID
    task_event_id: UUID
    status: ReviewScheduleStatus
    assessment_evidence_id: UUID
    job_id: UUID | None = None
    approval_request_id: UUID | None = None
    replayed: bool = False


class ReviewResolutionJobInput(BaseModel):
    """Exact review, policy, scope, and candidate bindings for one repair."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    schema_version: int = REVIEW_RESOLUTION_SCHEMA_VERSION
    task_id: UUID
    task_event_id: UUID
    assessment_evidence_id: UUID
    assessment_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    review_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_source: str = Field(pattern=r"^(REVIEW_RULE|ONE_OFF_APPROVAL)$")
    policy_version_id: UUID
    review_rule_id: UUID | None = None
    approval_request_id: UUID | None = None
    original_head_sha: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    validation_contract_id: UUID
    validation_contract_version: int = Field(gt=0)
    repository_configuration_id: UUID
    repository_configuration_version: int = Field(gt=0)
    authorized_paths: tuple[str, ...] = Field(min_length=1, max_length=32)
    max_attempts: int = Field(ge=1, le=MAX_REVIEW_REPAIRS)
    prompt: HermesJobPrompt

    @field_validator("authorized_paths")
    @classmethod
    def _authorized_paths(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_path(value) for value in values)
        if len(normalized) != len(set(normalized)):
            raise ValueError("authorized paths must be unique")
        return normalized


class ReviewHermesHandler(Protocol):
    def __call__(self, context: LeasedJobContext) -> Mapping[str, object] | None: ...


class ReviewHostGateway(Protocol):
    def execute(self, request: HostRequestMessage) -> HostResponseMessage: ...


class FullReviewValidator(Protocol):
    def validate(
        self,
        context: LeasedJobContext,
        *,
        job_input: ReviewResolutionJobInput,
        candidate: ValidationCandidate,
        candidate_evidence_id: UUID,
    ) -> ValidationDecisionResult: ...


class DraftReviewPublisher(Protocol):
    def open(
        self,
        task_id: UUID,
        *,
        commit_sha: str,
        tree_sha: str,
        transition_id: UUID,
        grant_supplier: Callable[[], JobLeaseGrant],
    ) -> DraftPullRequestResult: ...


@dataclass(frozen=True, slots=True)
class _ReviewContext:
    comment: ReviewComment
    task_owner_id: str
    task_root_correlation_id: UUID
    task_retry_count: int
    brief_id: UUID
    included_paths: tuple[str, ...]
    prohibited_paths: tuple[str, ...]
    validation_contract_id: UUID
    validation_contract_version: int
    repository_configuration_id: UUID
    repository_configuration_version: int
    policy_version_id: UUID
    max_attempts: int
    approval_lifetime_seconds: int


@dataclass(frozen=True, slots=True)
class _Authorization:
    source: str | None
    rule_id: UUID | None
    approval_request_id: UUID | None
    reason_code: str


class ReviewResolutionService:
    """Classify a verified review and schedule only an authorized repair."""

    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        classifier: ReviewClassifier,
        *,
        principal_id: str = "control-plane",
        active_policy_lineage: str = "mvp",
        clock: Callable[[], datetime] | None = None,
        prompts: PromptCompilerService | None = None,
        approvals: ApprovalService | None = None,
    ) -> None:
        self._factory = factory
        self._store = artifact_store
        self._classifier = classifier
        self._principal = principal_id
        self._policy_lineage = active_policy_lineage
        self._clock = clock or (lambda: datetime.now(UTC))
        self._prompts = prompts or PromptCompilerService(
            factory,
            artifact_store,
            principal_id=principal_id,
            active_policy_lineage=active_policy_lineage,
            clock=self._clock,
        )
        self._approvals = approvals or ApprovalService(
            factory,
            artifact_store,
            principal_id=principal_id,
            clock=self._clock,
        )
        self._jobs = BackgroundJobService(
            factory,
            artifact_store,
            principal_id=principal_id,
            clock=self._clock,
        )

    def schedule(self, task_event_id: UUID) -> ReviewScheduleResult:
        context = _review_context(
            self._factory,
            self._store,
            task_event_id,
            policy_lineage=self._policy_lineage,
            now=_utc(self._clock()),
        )
        classification = self._classifier.classify(context.comment)
        if not isinstance(classification, ReviewClassification):
            raise ReviewResolutionError("REVIEW_CLASSIFICATION_INVALID")
        review_fingerprint = _review_fingerprint(context, classification)
        authorization = _authorization(
            self._factory,
            context,
            classification,
            review_fingerprint=review_fingerprint,
            policy_lineage=self._policy_lineage,
            now=_utc(self._clock()),
        )
        assessment_payload = _assessment_payload(
            context,
            classification,
            authorization,
            review_fingerprint=review_fingerprint,
        )
        assessment_fingerprint = cast(
            str, assessment_payload["assessment_fingerprint"]
        )
        assessment_id = uuid5(
            NAMESPACE_URL,
            f"mathews:review-assessment:{task_event_id}:{assessment_fingerprint}",
        )
        _capture_assessment(
            self._factory,
            self._store,
            context,
            assessment_id,
            assessment_payload,
            principal_id=self._principal,
            now=_utc(self._clock()),
        )
        if classification.disposition is ReviewDisposition.INFORMATIONAL:
            return ReviewScheduleResult(
                context.comment.task_id,
                task_event_id,
                ReviewScheduleStatus.IGNORED,
                assessment_id,
            )
        if authorization.source is None:
            return self._request_approval(
                context,
                assessment_id,
                review_fingerprint,
                authorization.reason_code,
            )
        prompt = self._prompts.compile(
            context.comment.task_id,
            role=PromptRole.IMPLEMENTER,
            evidence_ids=(assessment_id,),
            policy_version_id=context.policy_version_id,
        )
        job_input = ReviewResolutionJobInput(
            task_id=context.comment.task_id,
            task_event_id=task_event_id,
            assessment_evidence_id=assessment_id,
            assessment_fingerprint=assessment_fingerprint,
            review_fingerprint=review_fingerprint,
            authorization_source=authorization.source,
            policy_version_id=context.policy_version_id,
            review_rule_id=authorization.rule_id,
            approval_request_id=authorization.approval_request_id,
            original_head_sha=context.comment.head_sha,
            validation_contract_id=context.validation_contract_id,
            validation_contract_version=context.validation_contract_version,
            repository_configuration_id=context.repository_configuration_id,
            repository_configuration_version=context.repository_configuration_version,
            authorized_paths=classification.proposed_paths,
            max_attempts=context.max_attempts,
            prompt=HermesJobPrompt(
                task_id=prompt.task_id,
                role=prompt.role,
                template_id=prompt.template_id,
                template_version=prompt.template_version,
                policy_version_id=prompt.policy_version_id,
                evaluation_label=prompt.evaluation_label,
                content=prompt.content,
                evidence_ids=prompt.evidence_ids,
            ),
        )
        scheduled: ScheduledJob = self._jobs.schedule(
            task_id=context.comment.task_id,
            job_type=REVIEW_RESOLUTION_JOB_TYPE,
            idempotency_key=f"review-resolution:{task_event_id}",
            input_payload=job_input.model_dump(mode="json"),
            task_validator=lambda session, task: _validate_schedule(
                session,
                task,
                context=context,
                assessment_id=assessment_id,
                authorization=authorization,
            ),
        )
        return ReviewScheduleResult(
            context.comment.task_id,
            task_event_id,
            ReviewScheduleStatus.SCHEDULED,
            assessment_id,
            job_id=scheduled.job_id,
            replayed=scheduled.replayed,
        )

    def resume_approved(self, request_id: UUID) -> ReviewScheduleResult | None:
        with self._factory() as session:
            request = session.get(ApprovalRequest, request_id)
            blocked = None if request is None else request.blocked_operation
            if request is None or request.status is not ApprovalStatus.APPROVED:
                raise ReviewResolutionError("REVIEW_APPROVAL_UNAVAILABLE")
            if (
                request.request_type != ApprovalRequestType.REVIEW_CONFLICT.value
                or not isinstance(blocked, dict)
                or blocked.get("operation_name") != "review.repair"
            ):
                return None
            raw_assessment_id = blocked.get("checkpoint_evidence_id")
            if not isinstance(raw_assessment_id, str):
                raise ReviewResolutionError("REVIEW_APPROVAL_UNAVAILABLE")
            try:
                assessment_id = UUID(raw_assessment_id)
            except ValueError:
                raise ReviewResolutionError("REVIEW_APPROVAL_UNAVAILABLE") from None
            assessment = session.get(EvidenceRecord, assessment_id)
            if assessment is None or assessment.task_id != request.task_id:
                raise ReviewResolutionError("REVIEW_APPROVAL_UNAVAILABLE")
            payload = load_evidence(session, self._store, assessment).content
            raw_event_id = (
                payload.get("task_event_id") if isinstance(payload, dict) else None
            )
            if not isinstance(raw_event_id, str):
                raise ReviewResolutionError("REVIEW_APPROVAL_UNAVAILABLE")
            try:
                task_event_id = UUID(raw_event_id)
            except ValueError:
                raise ReviewResolutionError("REVIEW_APPROVAL_UNAVAILABLE") from None
        return self.schedule(task_event_id)

    def _request_approval(
        self,
        context: _ReviewContext,
        assessment_id: UUID,
        fingerprint: str,
        reason_code: str,
    ) -> ReviewScheduleResult:
        request_id = uuid5(
            NAMESPACE_URL,
            f"mathews:review-one-off:{context.comment.task_event_id}:{fingerprint}",
        )
        result = self._approvals.request(
            context.comment.task_id,
            request_id=request_id,
            expected_state=TaskState.PR_ACTIVE,
            request_type=ApprovalRequestType.REVIEW_CONFLICT,
            reason_code=reason_code,
            subject_type="BLOCKED_OPERATION",
            subject_id=None,
            blocked_operation=BlockedOperation(
                operation_name="review.repair",
                idempotency_key=f"review-resolution:{context.comment.task_event_id}",
                input_fingerprint=fingerprint,
                checkpoint_evidence_id=assessment_id,
            ),
            evidence_ids=(assessment_id,),
            expires_at=_utc(self._clock())
            + timedelta(seconds=context.approval_lifetime_seconds),
        )
        return ReviewScheduleResult(
            context.comment.task_id,
            context.comment.task_event_id,
            ReviewScheduleStatus.APPROVAL_REQUIRED,
            assessment_id,
            approval_request_id=result.request_id,
            replayed=result.replayed,
        )


class ReviewResolutionJobHandler:
    """Repair, commit, fully revalidate, and republish one exact review head."""

    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        host: ReviewHostGateway,
        hermes: ReviewHermesHandler,
        validator: FullReviewValidator,
        publisher: DraftReviewPublisher,
        *,
        principal_id: str = "control-plane",
        active_policy_lineage: str = "mvp",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._factory = factory
        self._store = artifact_store
        self._host = host
        self._hermes = hermes
        self._validator = validator
        self._publisher = publisher
        self._principal = principal_id
        self._policy_lineage = active_policy_lineage
        self._clock = clock or (lambda: datetime.now(UTC))

    def __call__(self, context: LeasedJobContext) -> Mapping[str, object]:
        job_input = ReviewResolutionJobInput.model_validate(context.grant.input_payload)
        if job_input.task_id != context.grant.task_id:
            raise TerminalBackgroundJobError("REVIEW_JOB_TASK_MISMATCH")
        transitions = BackgroundJobService(
            self._factory,
            self._store,
            principal_id=self._principal,
            gate_evaluator=_ReviewRepairGates(self._store, job_input),
            clock=self._clock,
        )
        transitions.transition_task(
            context.grant,
            transition_id=uuid5(
                NAMESPACE_URL, f"mathews:review-repair-start:{context.grant.job_id}"
            ),
            expected_state=TaskState.PR_ACTIVE,
            kind=TaskTransitionKind.BEGIN_REPAIR,
            reason_code="AUTHORIZED_REVIEW_REPAIR_STARTED",
            evidence_ids=(job_input.assessment_evidence_id,),
            active_policy_lineage=self._policy_lineage,
        )
        hermes_result = self._run_hermes(context, job_input)
        candidate_result = self._commit(context, job_input)
        candidate = ValidationCandidate(
            commit_sha=cast(str, candidate_result["head_sha"]),
            tree_sha=cast(str, candidate_result["tree_sha"]),
        )
        candidate_evidence_id = self._capture_candidate(
            context.grant,
            job_input,
            candidate_result,
            hermes_result,
        )
        transitions.transition_task(
            context.grant,
            transition_id=uuid5(
                NAMESPACE_URL, f"mathews:review-revalidate:{context.grant.job_id}"
            ),
            expected_state=TaskState.REPAIRING,
            kind=TaskTransitionKind.REVALIDATE,
            reason_code="REVIEW_REPAIR_COMMITTED",
            evidence_ids=(job_input.assessment_evidence_id, candidate_evidence_id),
            validation_candidate=candidate,
            active_policy_lineage=self._policy_lineage,
        )
        decision = self._validator.validate(
            context,
            job_input=job_input,
            candidate=candidate,
            candidate_evidence_id=candidate_evidence_id,
        )
        if (
            decision.task_id != job_input.task_id
            or decision.outcome is not ValidationOutcome.PASSED
            or not decision.is_current
            or decision.commit_sha != candidate.commit_sha
            or decision.tree_sha != candidate.tree_sha
            or decision.validation_contract_id != job_input.validation_contract_id
            or decision.validation_contract_version
            != job_input.validation_contract_version
            or decision.repository_configuration_id
            != job_input.repository_configuration_id
            or decision.repository_configuration_version
            != job_input.repository_configuration_version
        ):
            raise TerminalBackgroundJobError("REVIEW_FULL_REVALIDATION_FAILED")
        context.heartbeat(timedelta(seconds=30))
        published = self._publisher.open(
            job_input.task_id,
            commit_sha=candidate.commit_sha,
            tree_sha=candidate.tree_sha,
            transition_id=uuid5(
                NAMESPACE_URL, f"mathews:review-pr-update:{context.grant.job_id}"
            ),
            grant_supplier=lambda: context.grant,
        )
        if published.head_sha != candidate.commit_sha:
            raise TerminalBackgroundJobError("REVIEW_PR_HEAD_MISMATCH")
        return {
            "status": "DRAFT_PR_UPDATED",
            "task_id": str(job_input.task_id),
            "review_event_id": str(job_input.task_event_id),
            "candidate_commit_sha": candidate.commit_sha,
            "candidate_tree_sha": candidate.tree_sha,
            "candidate_evidence_id": str(candidate_evidence_id),
            "validation_decision_evidence_id": str(decision.decision_evidence_id),
            "pull_request_number": published.pull_request_number,
            "pull_request_url": published.pull_request_url,
        }

    def _run_hermes(
        self,
        context: LeasedJobContext,
        job_input: ReviewResolutionJobInput,
    ) -> Mapping[str, object]:
        original = context.grant.input_payload
        hermes_context = LeasedJobContext(
            context.service,
            replace(
                context.grant,
                input_payload=HermesJobInput(prompt=job_input.prompt).model_dump(
                    mode="json"
                ),
            ),
        )
        result = self._hermes(hermes_context) or {}
        context.grant = replace(hermes_context.grant, input_payload=original)
        if result.get("status") != "SUCCEEDED":
            raise TerminalBackgroundJobError("REVIEW_HERMES_INCOMPLETE")
        return result

    def _commit(
        self,
        context: LeasedJobContext,
        job_input: ReviewResolutionJobInput,
    ) -> Mapping[str, JsonValue]:
        context.heartbeat(timedelta(seconds=30))
        with self._factory() as session:
            record = session.get(
                RepositoryConfiguration, job_input.repository_configuration_id
            )
            if (
                record is None
                or record.version != job_input.repository_configuration_version
            ):
                raise TerminalBackgroundJobError("REVIEW_CONFIGURATION_STALE")
            configuration = validated_repository_configuration(record)
        now = _utc(self._clock())
        response = self._host.execute(
            HostRequestMessage(
                request_id=uuid4(),
                issued_at_ms=int(now.timestamp() * 1_000),
                expires_at_ms=int((now + timedelta(seconds=30)).timestamp() * 1_000),
                authority=authority_for_job_lease(
                    context.grant, configuration=configuration
                ),
                operation=HostOperation(
                    name="git.commit",
                    idempotency_key=f"review-repair-commit:{context.grant.job_id}",
                    arguments=cast(
                        dict[str, JsonValue],
                        {
                            "configuration": configuration.to_dict(),
                            "expected_head_sha": job_input.original_head_sha,
                            "message": (
                                "Address review feedback "
                                f"{job_input.assessment_fingerprint[:12]}"
                            ),
                        },
                    ),
                ),
            )
        )
        return _validated_candidate_response(
            response,
            job_input=job_input,
            fencing_token=context.grant.fencing_token,
        )

    def _capture_candidate(
        self,
        grant: JobLeaseGrant,
        job_input: ReviewResolutionJobInput,
        result: Mapping[str, JsonValue],
        hermes_result: Mapping[str, object],
    ) -> UUID:
        evidence_id = uuid5(
            NAMESPACE_URL, f"mathews:review-candidate:{grant.job_id}"
        )
        payload = {
            "schema_version": REVIEW_RESOLUTION_SCHEMA_VERSION,
            "task_event_id": str(job_input.task_event_id),
            "assessment_evidence_id": str(job_input.assessment_evidence_id),
            "authorization_source": job_input.authorization_source,
            "original_head_sha": job_input.original_head_sha,
            "candidate_commit_sha": result["head_sha"],
            "candidate_tree_sha": result["tree_sha"],
            "changed_paths": result["changed_paths"],
            "hermes_run_id": hermes_result.get("hermes_run_id"),
            "validation_contract_id": str(job_input.validation_contract_id),
            "validation_contract_version": job_input.validation_contract_version,
            "repository_configuration_id": str(
                job_input.repository_configuration_id
            ),
            "repository_configuration_version": (
                job_input.repository_configuration_version
            ),
        }
        with self._factory.begin() as session:
            require_current_job_lease(session, grant, now=_utc(self._clock()))
            existing = session.get(EvidenceRecord, evidence_id)
            if existing is not None:
                loaded = load_evidence(session, self._store, existing)
                if loaded.content != payload:
                    raise ReviewResolutionError("REVIEW_CANDIDATE_CONFLICT")
                return existing.id
            task = session.get(Task, job_input.task_id)
            if task is None or TaskState(task.state) is not TaskState.REPAIRING:
                raise ReviewResolutionError("REVIEW_TASK_STALE")
            captured = capture_evidence(
                session,
                self._store,
                payload=payload,
                media_type="application/json",
                source_kind=EvidenceSourceKind.RESULT,
                evidence_type="review-repair-candidate",
                origin="control-plane:review-resolution",
                access_classification=EvidenceAccessClass.TASK_OWNER,
                retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
                owner_id=task.owner_id,
                actor_id=self._principal,
                root_correlation_id=task.root_correlation_id,
                task_id=task.id,
                causation_id=grant.job_id,
                parent_correlation_id=job_input.task_event_id,
                evidence_id=evidence_id,
                captured_at=_utc(self._clock()),
            )
            return captured.record.id


class _ReviewRepairGates(TaskTransitionGateEvaluator):
    def __init__(self, store: ArtifactStore, job_input: ReviewResolutionJobInput) -> None:
        self._store = store
        self._input = job_input

    def evaluate(
        self,
        session: Session,
        task: Task,
        kind: TaskTransitionKind,
        *,
        policy: PolicyVersion,
        now: datetime,
    ) -> TaskTransitionGuards:
        del now
        if kind is not TaskTransitionKind.BEGIN_REPAIR:
            return TaskTransitionGuards()
        evidence = session.get(EvidenceRecord, self._input.assessment_evidence_id)
        if evidence is None or evidence.task_id != task.id:
            return TaskTransitionGuards()
        try:
            loaded = load_evidence(session, self._store, evidence)
        except EvidenceError:
            return TaskTransitionGuards()
        payload = loaded.content
        current_pr = (
            None
            if not isinstance(payload, dict)
            else _current_pr_identity(session, task.id)
        )
        if (
            not isinstance(payload, dict)
            or payload.get("assessment_fingerprint")
            != self._input.assessment_fingerprint
            or payload.get("authorized") is not True
            or payload.get("original_head_sha") != self._input.original_head_sha
            or current_pr
            != (
                payload.get("pull_request_number"),
                payload.get("branch_name"),
                self._input.original_head_sha,
            )
            or policy.id != self._input.policy_version_id
            or (
                self._input.authorization_source == "REVIEW_RULE"
                and task.retry_count >= self._input.max_attempts
            )
            or session.scalar(
                select(func.count(ApprovalRequest.id)).where(
                    ApprovalRequest.task_id == task.id,
                    ApprovalRequest.status == ApprovalStatus.PENDING,
                )
            )
            or session.scalar(
                select(func.count(TaskCancellation.id)).where(
                    TaskCancellation.task_id == task.id
                )
            )
        ):
            return TaskTransitionGuards()
        if (
            payload.get("review_fingerprint") != self._input.review_fingerprint
            or payload.get("authorization_source")
            != self._input.authorization_source
            or payload.get("policy_version_id")
            != str(self._input.policy_version_id)
            or payload.get("review_rule_id")
            != (
                None
                if self._input.review_rule_id is None
                else str(self._input.review_rule_id)
            )
            or payload.get("approval_request_id")
            != (
                None
                if self._input.approval_request_id is None
                else str(self._input.approval_request_id)
            )
        ):
            return TaskTransitionGuards()
        if self._input.authorization_source == "REVIEW_RULE":
            membership = session.scalar(
                select(PolicyVersionReviewRule).where(
                    PolicyVersionReviewRule.policy_version_id == policy.id,
                    PolicyVersionReviewRule.review_rule_id
                    == self._input.review_rule_id,
                )
            )
            rule = (
                None
                if self._input.review_rule_id is None
                else session.get(ReviewRule, self._input.review_rule_id)
            )
            authorized = (
                membership is not None
                and rule is not None
                and rule.approval_status is ApprovalStatus.APPROVED
                and rule.risk_class.upper() == ReviewRisk.LOW.value
            )
        else:
            approval = (
                None
                if self._input.approval_request_id is None
                else session.get(ApprovalRequest, self._input.approval_request_id)
            )
            blocked = None if approval is None else approval.blocked_operation
            authorized = bool(
                approval is not None
                and approval.task_id == task.id
                and approval.request_type == ApprovalRequestType.REVIEW_CONFLICT.value
                and approval.status is ApprovalStatus.APPROVED
                and isinstance(blocked, dict)
                and blocked.get("input_fingerprint")
                == self._input.review_fingerprint
            )
        return TaskTransitionGuards(repair_authorized=authorized)


def _review_context(
    factory: SessionFactory,
    store: ArtifactStore,
    task_event_id: UUID,
    *,
    policy_lineage: str,
    now: datetime,
) -> _ReviewContext:
    with factory() as session:
        event = session.get(TaskEvent, task_event_id)
        if (
            event is None
            or event.event_type != GITHUB_REVIEW_UPDATED_EVENT
            or event.payload.get("resource_type") != "review_comment"
            or event.payload.get("state") != "OPEN"
        ):
            raise ReviewResolutionError("REVIEW_EVENT_UNAVAILABLE")
        task = session.get(Task, event.task_id)
        if task is None or TaskState(task.state) is not TaskState.PR_ACTIVE:
            raise ReviewResolutionError("REVIEW_TASK_NOT_ACTIVE")
        if (
            task.accepted_brief_id is None
            or task.validation_contract_id is None
            or task.repository_configuration_id is None
        ):
            raise ReviewResolutionError("REVIEW_TASK_BINDINGS_INCOMPLETE")
        brief = session.get(Brief, task.accepted_brief_id)
        contract = session.get(ValidationContract, task.validation_contract_id)
        configuration = session.get(
            RepositoryConfiguration, task.repository_configuration_id
        )
        policy = _active_policy(
            session, task, lineage_key=policy_lineage, now=now
        )
        reference = session.scalar(
            select(TaskEventEvidenceReference).where(
                TaskEventEvidenceReference.task_event_id == event.id,
                TaskEventEvidenceReference.position == 1,
            )
        )
        evidence = (
            None if reference is None else session.get(EvidenceRecord, reference.evidence_id)
        )
        if brief is None or contract is None or configuration is None or evidence is None:
            raise ReviewResolutionError("REVIEW_EVIDENCE_UNAVAILABLE")
        try:
            loaded = load_evidence(session, store, evidence)
            captured = _mapping(loaded.content, "captured webhook")
            if captured.get("event_name") != "pull_request_review_comment":
                raise ReviewResolutionError("REVIEW_EVIDENCE_INVALID")
            webhook = _mapping(captured.get("payload"), "webhook payload")
            comment = _mapping(webhook.get("comment"), "review comment")
            pull_request = _mapping(webhook.get("pull_request"), "pull request")
            head = _mapping(pull_request.get("head"), "pull request head")
            user = _mapping(comment.get("user"), "review author")
            comment_id = _positive_int(comment.get("id"), "review comment id")
            pr_number = _positive_int(
                pull_request.get("number"), "pull request number"
            )
            branch = _identifier(head.get("ref"), "task branch")
            head_sha = _sha(head.get("sha"))
            comment_head = _sha(comment.get("commit_id"))
            path = _path(comment.get("path"))
            body = _text(comment.get("body"), "review body", maximum=65_536)
            author = _identifier(user.get("login"), "review author")
        except (TypeError, ValueError, EvidenceError):
            raise ReviewResolutionError("REVIEW_EVIDENCE_INVALID") from None
        current_pr = _current_pr_identity(session, task.id)
        if (
            current_pr != (pr_number, branch, head_sha)
            or event.payload.get("head_sha") != head_sha
            or comment_head != head_sha
            or contract.task_id != task.id
            or contract.brief_id != brief.id
            or contract.repository_configuration_id != configuration.id
        ):
            raise ReviewResolutionError("REVIEW_HEAD_STALE")
        included = _stored_paths(brief.scope.get("included_paths"))
        prohibited = _stored_paths(configuration.prohibited_paths)
        max_attempts, lifetime = _review_policy(policy)
        return _ReviewContext(
            ReviewComment(
                task.id,
                event.id,
                evidence.id,
                comment_id,
                pr_number,
                branch,
                head_sha,
                path,
                body,
                author,
            ),
            task.owner_id,
            task.root_correlation_id,
            task.retry_count,
            brief.id,
            included,
            prohibited,
            contract.id,
            contract.version,
            configuration.id,
            configuration.version,
            policy.id,
            max_attempts,
            lifetime,
        )


def _authorization(
    factory: SessionFactory,
    context: _ReviewContext,
    classification: ReviewClassification,
    *,
    review_fingerprint: str,
    policy_lineage: str,
    now: datetime,
) -> _Authorization:
    with factory() as session:
        task = session.get(Task, context.comment.task_id)
        if task is None or TaskState(task.state) is not TaskState.PR_ACTIVE:
            raise ReviewResolutionError("REVIEW_TASK_STALE")
        policy = _active_policy(session, task, lineage_key=policy_lineage, now=now)
        if policy.id != context.policy_version_id:
            raise ReviewResolutionError("REVIEW_POLICY_CHANGED")
        one_off = _approved_one_off(session, task.id, review_fingerprint)
        if one_off is not None:
            return _Authorization(
                "ONE_OFF_APPROVAL", None, one_off.id, "ONE_OFF_APPROVAL_MATCHED"
            )
        if classification.disposition is ReviewDisposition.INFORMATIONAL:
            return _Authorization(None, None, None, "REVIEW_INFORMATIONAL")
        unsafe_reason = _unsafe_reason(context, classification)
        if unsafe_reason is not None:
            return _Authorization(None, None, None, unsafe_reason)
        matches: list[ReviewRule] = []
        rules = session.scalars(
            select(ReviewRule)
            .join(
                PolicyVersionReviewRule,
                PolicyVersionReviewRule.review_rule_id == ReviewRule.id,
            )
            .where(PolicyVersionReviewRule.policy_version_id == policy.id)
            .order_by(PolicyVersionReviewRule.position)
        ).all()
        for rule in rules:
            if _rule_matches(rule, classification):
                matches.append(rule)
        if len(matches) != 1:
            return _Authorization(
                None,
                None,
                None,
                "REVIEW_RULE_UNMATCHED" if not matches else "REVIEW_RULE_CONFLICT",
            )
        return _Authorization("REVIEW_RULE", matches[0].id, None, "REVIEW_RULE_MATCHED")


def _unsafe_reason(
    context: _ReviewContext, classification: ReviewClassification
) -> str | None:
    if classification.disposition is not ReviewDisposition.ACTIONABLE:
        return f"REVIEW_{classification.disposition.value}"
    if classification.risk is not ReviewRisk.LOW:
        return "REVIEW_RISK_NOT_LOW"
    if not classification.proposed_paths:
        return "REVIEW_PATHS_MISSING"
    if classification.dependency_change:
        return "REVIEW_DEPENDENCY_CHANGE"
    if classification.schema_change:
        return "REVIEW_SCHEMA_CHANGE"
    if classification.signing_change:
        return "REVIEW_SIGNING_CHANGE"
    if classification.security_change:
        return "REVIEW_SECURITY_CHANGE"
    if context.task_retry_count >= context.max_attempts:
        return "REVIEW_RETRY_BUDGET_EXHAUSTED"
    if any(
        not _path_in_scope(path, context.included_paths)
        or _path_in_scope(path, context.prohibited_paths)
        for path in classification.proposed_paths
    ):
        return "REVIEW_PATH_OUTSIDE_SCOPE"
    if context.comment.path not in classification.proposed_paths:
        return "REVIEW_ANCHOR_PATH_MISMATCH"
    return None


def _rule_matches(rule: ReviewRule, classification: ReviewClassification) -> bool:
    if (
        rule.approval_status is not ApprovalStatus.APPROVED
        or rule.approval_request_type != ApprovalRequestType.REVIEW_RULE.value
        or rule.risk_class.upper() != ReviewRisk.LOW.value
        or rule.permitted_action != classification.action
    ):
        return False
    matcher = rule.matcher
    scope = rule.scope
    if set(matcher) != {"categories", "required_labels"} or set(scope) != {
        "path_prefixes",
        "max_files",
    }:
        return False
    categories = matcher.get("categories")
    labels = matcher.get("required_labels")
    prefixes = scope.get("path_prefixes")
    maximum = scope.get("max_files")
    requirements = rule.evidence_requirements
    if (
        not isinstance(categories, list)
        or not categories
        or any(not isinstance(value, str) for value in categories)
        or len(categories) != len(set(cast(list[str], categories)))
        or classification.category not in categories
        or not isinstance(labels, list)
        or any(not isinstance(value, str) for value in labels)
        or len(labels) != len(set(cast(list[str], labels)))
        or not set(cast(list[str], labels)).issubset(classification.labels)
        or not isinstance(prefixes, list)
        or not prefixes
        or any(not isinstance(value, str) for value in prefixes)
        or len(prefixes) != len(set(cast(list[str], prefixes)))
        or isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or not 1 <= maximum <= 32
        or len(classification.proposed_paths) > maximum
        or not isinstance(requirements, list)
        or not requirements
        or any(not isinstance(value, str) for value in requirements)
        or len(requirements) != len(set(cast(list[str], requirements)))
        or not set(cast(list[str], requirements)).issubset(
            _AVAILABLE_REVIEW_EVIDENCE_TYPES
        )
    ):
        return False
    try:
        allowed = tuple(_path(value) for value in prefixes)
    except (TypeError, ValueError):
        return False
    return all(_path_in_scope(path, allowed) for path in classification.proposed_paths)


def _assessment_payload(
    context: _ReviewContext,
    classification: ReviewClassification,
    authorization: _Authorization,
    *,
    review_fingerprint: str,
) -> dict[str, object]:
    base: dict[str, object] = {
        "schema_version": REVIEW_RESOLUTION_SCHEMA_VERSION,
        "task_id": str(context.comment.task_id),
        "task_event_id": str(context.comment.task_event_id),
        "source_evidence_id": str(context.comment.evidence_id),
        "comment_id": context.comment.comment_id,
        "pull_request_number": context.comment.pull_request_number,
        "branch_name": context.comment.branch_name,
        "original_head_sha": context.comment.head_sha,
        "comment_path": context.comment.path,
        "comment_body_sha256": hashlib.sha256(context.comment.body.encode()).hexdigest(),
        "classification": _classification_payload(classification),
        "review_fingerprint": review_fingerprint,
        "policy_version_id": str(context.policy_version_id),
        "review_rule_id": (
            None if authorization.rule_id is None else str(authorization.rule_id)
        ),
        "approval_request_id": (
            None
            if authorization.approval_request_id is None
            else str(authorization.approval_request_id)
        ),
        "authorization_source": authorization.source,
        "authorization_reason_code": authorization.reason_code,
        "authorized": authorization.source is not None,
        "validation_contract_id": str(context.validation_contract_id),
        "validation_contract_version": context.validation_contract_version,
        "repository_configuration_id": str(context.repository_configuration_id),
        "repository_configuration_version": context.repository_configuration_version,
    }
    base["assessment_fingerprint"] = _fingerprint(base)
    return base


def _capture_assessment(
    factory: SessionFactory,
    store: ArtifactStore,
    context: _ReviewContext,
    evidence_id: UUID,
    payload: dict[str, object],
    *,
    principal_id: str,
    now: datetime,
) -> None:
    with factory.begin() as session:
        existing = session.get(EvidenceRecord, evidence_id)
        if existing is not None:
            loaded = load_evidence(session, store, existing)
            if loaded.content != payload:
                raise ReviewResolutionError("REVIEW_ASSESSMENT_CONFLICT")
            return
        task = session.get(Task, context.comment.task_id)
        if task is None or TaskState(task.state) is not TaskState.PR_ACTIVE:
            raise ReviewResolutionError("REVIEW_TASK_STALE")
        capture_evidence(
            session,
            store,
            payload=payload,
            media_type="application/json",
            source_kind=EvidenceSourceKind.RESULT,
            evidence_type="review-resolution-assessment",
            origin="control-plane:review-resolution",
            access_classification=EvidenceAccessClass.TASK_OWNER,
            retention_policy=EvidenceRetentionClass.AUDIT,
            owner_id=context.task_owner_id,
            actor_id=principal_id,
            root_correlation_id=context.task_root_correlation_id,
            task_id=context.comment.task_id,
            causation_id=context.comment.task_event_id,
            parent_correlation_id=context.comment.evidence_id,
            evidence_id=evidence_id,
            captured_at=now,
        )


def _validate_schedule(
    session: Session,
    task: Task,
    *,
    context: _ReviewContext,
    assessment_id: UUID,
    authorization: _Authorization,
) -> None:
    if (
        TaskState(task.state) is not TaskState.PR_ACTIVE
        or task.accepted_brief_id != context.brief_id
        or task.validation_contract_id != context.validation_contract_id
        or task.repository_configuration_id != context.repository_configuration_id
        or _current_pr_identity(session, task.id)
        != (
            context.comment.pull_request_number,
            context.comment.branch_name,
            context.comment.head_sha,
        )
        or (
            authorization.source == "REVIEW_RULE"
            and task.retry_count >= context.max_attempts
        )
        or session.get(EvidenceRecord, assessment_id) is None
        or authorization.source is None
    ):
        raise ReviewResolutionError("REVIEW_SCHEDULE_STALE")


def _approved_one_off(
    session: Session, task_id: UUID, fingerprint: str
) -> ApprovalRequest | None:
    requests = session.scalars(
        select(ApprovalRequest)
        .where(
            ApprovalRequest.task_id == task_id,
            ApprovalRequest.request_type == ApprovalRequestType.REVIEW_CONFLICT.value,
            ApprovalRequest.status == ApprovalStatus.APPROVED,
        )
        .order_by(ApprovalRequest.decided_at.desc())
    ).all()
    matches = [
        request
        for request in requests
        if isinstance(request.blocked_operation, dict)
        and request.blocked_operation.get("operation_name") == "review.repair"
        and request.blocked_operation.get("input_fingerprint") == fingerprint
    ]
    if len(matches) > 1:
        raise ReviewResolutionError("REVIEW_APPROVAL_AMBIGUOUS")
    return None if not matches else matches[0]


def _current_pr_identity(
    session: Session, task_id: UUID
) -> tuple[int, str, str] | None:
    binding = session.scalar(
        select(TaskEvent)
        .where(
            TaskEvent.task_id == task_id,
            TaskEvent.event_type == GITHUB_PR_BOUND_EVENT,
        )
        .order_by(TaskEvent.sequence.desc(), TaskEvent.id.desc())
        .limit(1)
    )
    if binding is None:
        return None
    number = binding.payload.get("pull_request_number")
    branch = binding.payload.get("task_branch")
    head = binding.payload.get("head_sha")
    if (
        isinstance(number, bool)
        or not isinstance(number, int)
        or not isinstance(branch, str)
        or not isinstance(head, str)
    ):
        return None
    changed = session.scalar(
        select(TaskEvent)
        .where(
            TaskEvent.task_id == task_id,
            TaskEvent.event_type == GITHUB_PR_HEAD_CHANGED_EVENT,
            TaskEvent.sequence > binding.sequence,
        )
        .order_by(TaskEvent.sequence.desc(), TaskEvent.id.desc())
        .limit(1)
    )
    if changed is not None:
        changed_number = changed.payload.get("pull_request_number")
        changed_branch = changed.payload.get("task_branch")
        changed_head = changed.payload.get("head_sha")
        if changed_number == number and changed_branch == branch:
            if not isinstance(changed_head, str):
                return None
            head = changed_head
    try:
        return _positive_int(number, "pull request number"), _identifier(
            branch, "task branch"
        ), _sha(head)
    except ValueError:
        return None


def _validated_candidate_response(
    response: HostResponseMessage,
    *,
    job_input: ReviewResolutionJobInput,
    fencing_token: int,
) -> Mapping[str, JsonValue]:
    result = response.result
    changed = result.get("changed_paths")
    head = result.get("head_sha")
    tree = result.get("tree_sha")
    try:
        normalized_changed = (
            tuple(_path(value) for value in changed)
            if isinstance(changed, list)
            else ()
        )
    except (TypeError, ValueError):
        normalized_changed = ()
    if (
        response.status is not HostResponseStatus.OK
        or (
            response.execution_fencing_token != fencing_token
            and not response.replayed
        )
        or result.get("committed") is not True
        or result.get("clean") is not True
        or not isinstance(changed, list)
        or not changed
        or any(not isinstance(value, str) for value in changed)
        or normalized_changed != tuple(changed)
        or len(normalized_changed) != len(set(normalized_changed))
        or not set(normalized_changed).issubset(job_input.authorized_paths)
        or not isinstance(head, str)
        or _GIT_OBJECT.fullmatch(head) is None
        or head == job_input.original_head_sha
        or not isinstance(tree, str)
        or _GIT_OBJECT.fullmatch(tree) is None
    ):
        raise TerminalBackgroundJobError("REVIEW_CANDIDATE_INVALID")
    return result


def _active_policy(
    session: Session,
    task: Task,
    *,
    lineage_key: str,
    now: datetime,
) -> PolicyVersion:
    policy = session.scalar(
        select(PolicyVersion)
        .where(
            PolicyVersion.lineage_key == lineage_key,
            PolicyVersion.owner_id == task.owner_id,
            PolicyVersion.approved_at <= now,
        )
        .order_by(PolicyVersion.version.desc())
        .limit(1)
    )
    if policy is None:
        raise ReviewResolutionError("REVIEW_POLICY_UNAVAILABLE")
    return policy


def _review_policy(policy: PolicyVersion) -> tuple[int, int]:
    raw = policy.workflow_thresholds.get("review_resolution_policy")
    if raw is None:
        return DEFAULT_MAX_REVIEW_REPAIRS, DEFAULT_APPROVAL_LIFETIME_SECONDS
    if not isinstance(raw, dict) or set(raw) != {
        "max_attempts",
        "approval_lifetime_seconds",
    }:
        raise ReviewResolutionError("REVIEW_POLICY_INVALID")
    attempts = raw.get("max_attempts")
    lifetime = raw.get("approval_lifetime_seconds")
    if (
        isinstance(attempts, bool)
        or not isinstance(attempts, int)
        or not 1 <= attempts <= MAX_REVIEW_REPAIRS
        or isinstance(lifetime, bool)
        or not isinstance(lifetime, int)
        or not 60 <= lifetime <= 7 * 86_400
    ):
        raise ReviewResolutionError("REVIEW_POLICY_INVALID")
    return attempts, lifetime


def _classification_payload(value: ReviewClassification) -> dict[str, object]:
    return value.model_dump(mode="json")


def _review_fingerprint(
    context: _ReviewContext, classification: ReviewClassification
) -> str:
    return _fingerprint(
        {
            "schema_version": REVIEW_RESOLUTION_SCHEMA_VERSION,
            "task_id": str(context.comment.task_id),
            "task_event_id": str(context.comment.task_event_id),
            "comment_id": context.comment.comment_id,
            "pull_request_number": context.comment.pull_request_number,
            "branch_name": context.comment.branch_name,
            "head_sha": context.comment.head_sha,
            "comment_path": context.comment.path,
            "comment_body_sha256": hashlib.sha256(
                context.comment.body.encode()
            ).hexdigest(),
            "classification": _classification_payload(classification),
            "policy_version_id": str(context.policy_version_id),
            "validation_contract_id": str(context.validation_contract_id),
            "repository_configuration_id": str(
                context.repository_configuration_id
            ),
        }
    )


def _fingerprint(value: Mapping[str, object]) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
    except (TypeError, ValueError):
        raise ReviewResolutionError("REVIEW_FINGERPRINT_INVALID") from None
    return hashlib.sha256(encoded).hexdigest()


def _stored_paths(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ReviewResolutionError("REVIEW_PATH_SCOPE_INVALID")
    try:
        paths = tuple(_path(item) for item in value)
    except (TypeError, ValueError):
        raise ReviewResolutionError("REVIEW_PATH_SCOPE_INVALID") from None
    if len(paths) != len(set(paths)):
        raise ReviewResolutionError("REVIEW_PATH_SCOPE_INVALID")
    return paths


def _path_in_scope(path: str, scopes: Sequence[str]) -> bool:
    candidate = PurePosixPath(path.casefold())
    return any(
        allowed == PurePosixPath(".")
        or allowed == candidate
        or allowed in candidate.parents
        for allowed in (PurePosixPath(scope.casefold()) for scope in scopes)
    )


def _path(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("repository path is invalid")
    normalized = value.strip().replace("\\", "/")
    candidate = PurePosixPath(normalized)
    if (
        not normalized
        or normalized.startswith("/")
        or normalized.endswith("/")
        or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or len(normalized) > 500
    ):
        raise ValueError("repository path is invalid")
    return candidate.as_posix()


def _identifier(value: object, field: str, *, maximum: int = 255) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} is invalid")
    normalized = value.strip()
    if len(normalized) > maximum or _IDENTIFIER.fullmatch(normalized) is None:
        raise ValueError(f"{field} is invalid")
    return normalized


def _text(value: object, field: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} is invalid")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise ValueError(f"{field} is invalid")
    return normalized


def _mapping(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} is invalid")
    return cast(dict[str, object], value)


def _positive_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field} is invalid")
    return value


def _sha(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Git object is invalid")
    normalized = value.strip().lower()
    if _GIT_OBJECT.fullmatch(normalized) is None:
        raise ValueError("Git object is invalid")
    return normalized


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ReviewResolutionError("REVIEW_CLOCK_INVALID")
    return value.astimezone(UTC)
