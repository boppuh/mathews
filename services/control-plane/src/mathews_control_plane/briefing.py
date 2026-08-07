"""Typed, versioned task briefing with fail-closed approval policy."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, cast
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from mathews_control_plane.approvals import ApprovalRequestResult, ApprovalService
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    ApprovalRequestType,
    Brief,
    BriefApprovalDecision,
    BriefDecisionDisposition,
    EvidenceRecord,
    PolicyVersion,
    Task,
    TaskEvent,
    TaskEventEvidenceReference,
    TaskState,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
)
from mathews_control_plane.task_state_machine import (
    TaskTransitionGateEvaluator,
    TaskTransitionGuards,
    TaskTransitionKind,
    TaskTransitionResult,
    TaskTransitionService,
)

BRIEF_EVENT_TYPE = "BRIEF_VERSION_CREATED"
BRIEF_EVENT_SCHEMA_VERSION = 1
BRIEF_EVIDENCE_TYPE = "structured-brief"
BRIEF_POLICY_SCHEMA_VERSION = 1
DEFAULT_APPROVAL_LIFETIME_HOURS = 24

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"
_AMBIGUITY_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{0,99}\Z")
_BUILT_IN_SENSITIVE_PATHS = (
    ".github/workflows",
    "Package.resolved",
    "package-lock.json",
    "pyproject.toml",
    "uv.lock",
)

BriefIdentifier = Annotated[
    str,
    StringConstraints(strip_whitespace=True, pattern=_IDENTIFIER_PATTERN),
]
BriefText = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=2_000),
]
BriefShortText = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=500),
]


class BriefingError(RuntimeError):
    """Base class for stable briefing failures."""


class BriefingNotFoundError(BriefingError):
    """The task or active policy is unavailable."""


class BriefingConflictError(BriefingError):
    """The requested brief conflicts with durable state."""


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class VerificationMethod(StrEnum):
    AUTOMATED_TEST = "AUTOMATED_TEST"
    SIMULATOR_ASSERTION = "SIMULATOR_ASSERTION"
    STATIC_CHECK = "STATIC_CHECK"
    HUMAN_INSPECTION = "HUMAN_INSPECTION"


class BriefOperation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    operation_id: BriefIdentifier
    risk: RiskLevel
    rationale: BriefShortText


class BriefScope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    objective: BriefText
    included_paths: tuple[BriefShortText, ...] = Field(min_length=1, max_length=100)
    operations: tuple[BriefOperation, ...] = Field(min_length=1, max_length=50)
    scope_expansion: bool = False

    @field_validator("included_paths")
    @classmethod
    def paths_are_canonical_and_unique(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        normalized = tuple(_repository_path(value) for value in values)
        if len(normalized) != len(set(normalized)):
            raise ValueError("brief scope paths must be unique")
        return normalized

    @field_validator("operations")
    @classmethod
    def operations_are_unique(
        cls,
        values: tuple[BriefOperation, ...],
    ) -> tuple[BriefOperation, ...]:
        identifiers = tuple(value.operation_id for value in values)
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("brief operations must be unique")
        return values


class AcceptanceCriterion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    criterion_id: BriefIdentifier
    requirement: BriefText
    verification: VerificationMethod


class RiskAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    risk_id: BriefIdentifier
    level: RiskLevel
    description: BriefShortText
    mitigation: BriefShortText


class AffectedUserFlow(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    flow_id: BriefIdentifier
    actor: BriefShortText
    entry_point: BriefShortText
    expected_outcome: BriefText


class TestPlanStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    step_id: BriefIdentifier
    operation_id: BriefIdentifier
    proves_criterion_ids: tuple[BriefIdentifier, ...] = Field(
        min_length=1,
        max_length=100,
    )
    expected_result: BriefText


class StructuredBriefDraft(BaseModel):
    """Bounded planner output; unstructured prose cannot cross this boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    scope: BriefScope
    exclusions: tuple[BriefShortText, ...] = Field(max_length=100)
    acceptance_criteria: tuple[AcceptanceCriterion, ...] = Field(
        min_length=1,
        max_length=100,
    )
    risks: tuple[RiskAssessment, ...] = Field(min_length=1, max_length=100)
    affected_flow: AffectedUserFlow
    test_plan: tuple[TestPlanStep, ...] = Field(min_length=1, max_length=100)
    ambiguity_flags: tuple[BriefIdentifier, ...] = Field(default=(), max_length=100)

    @field_validator("acceptance_criteria")
    @classmethod
    def criteria_are_unique(
        cls,
        values: tuple[AcceptanceCriterion, ...],
    ) -> tuple[AcceptanceCriterion, ...]:
        identifiers = tuple(value.criterion_id for value in values)
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("acceptance criteria must be unique")
        return values

    @field_validator("risks")
    @classmethod
    def risks_are_unique(
        cls,
        values: tuple[RiskAssessment, ...],
    ) -> tuple[RiskAssessment, ...]:
        identifiers = tuple(value.risk_id for value in values)
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("risk assessments must be unique")
        return values

    @field_validator("ambiguity_flags")
    @classmethod
    def ambiguity_flags_are_canonical(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        if (
            len(values) != len(set(values))
            or any(_AMBIGUITY_PATTERN.fullmatch(value) is None for value in values)
        ):
            raise ValueError("ambiguity flags must be unique reason codes")
        return values

    @field_validator("test_plan")
    @classmethod
    def test_plan_is_bound(
        cls,
        values: tuple[TestPlanStep, ...],
        info: object,
    ) -> tuple[TestPlanStep, ...]:
        del info
        identifiers = tuple(value.step_id for value in values)
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("test plan steps must be unique")
        return values

    def validate_bindings(self) -> None:
        operations = {value.operation_id for value in self.scope.operations}
        criteria = {value.criterion_id for value in self.acceptance_criteria}
        proven: set[str] = set()
        for step in self.test_plan:
            if step.operation_id not in operations:
                raise BriefingConflictError("test plan operation is outside brief scope")
            if not set(step.proves_criterion_ids).issubset(criteria):
                raise BriefingConflictError("test plan references an unknown criterion")
            proven.update(step.proves_criterion_ids)
        if proven != criteria:
            raise BriefingConflictError("every acceptance criterion requires a test step")

    def storage_fields(self) -> dict[str, object]:
        value = self.model_dump(mode="json")
        return {
            "scope": cast(dict[str, object], value["scope"]),
            "exclusions": cast(list[object], value["exclusions"]),
            "acceptance_criteria": cast(list[object], value["acceptance_criteria"]),
            "risks": cast(list[object], value["risks"]),
            "affected_flow": cast(dict[str, object], value["affected_flow"]),
            "test_plan": cast(list[object], value["test_plan"]),
        }


@dataclass(frozen=True, slots=True)
class BriefPolicyEvaluation:
    disposition: BriefDecisionDisposition
    reason: str
    flags: tuple[str, ...]
    approval_lifetime: timedelta


@dataclass(frozen=True, slots=True)
class BriefingResult:
    task_id: UUID
    brief_id: UUID
    brief_version: int
    decision_id: UUID
    disposition: BriefDecisionDisposition
    policy_version_id: UUID
    evidence_id: UUID
    task_state: TaskState
    approval_request_id: UUID | None
    replayed: bool


@dataclass(frozen=True, slots=True)
class _BriefTransitionGates(TaskTransitionGateEvaluator):
    expected_policy_version_id: UUID

    def evaluate(
        self,
        session: Session,
        task: Task,
        kind: TaskTransitionKind,
        *,
        policy: PolicyVersion,
        now: datetime,
    ) -> TaskTransitionGuards:
        del session, task, kind, now
        return TaskTransitionGuards(
            brief_policy_bypass_authorized=(
                policy.id == self.expected_policy_version_id
            )
        )


class BriefingService:
    """Persist one immutable brief version and route its exact disposition."""

    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        *,
        active_policy_lineage: str = "mvp",
        principal_id: str = "control-plane",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._factory = factory
        self._artifact_store = artifact_store
        self._active_policy_lineage = active_policy_lineage
        self._principal_id = principal_id
        self._clock = clock or (lambda: datetime.now(UTC))

    def create(
        self,
        task_id: UUID,
        *,
        brief_id: UUID,
        draft: StructuredBriefDraft,
    ) -> BriefingResult:
        draft.validate_bindings()
        now = _as_utc(self._clock())
        stored = self._store_version(
            task_id,
            brief_id=brief_id,
            draft=draft,
            now=now,
        )
        if stored.evaluation.disposition is BriefDecisionDisposition.AUTO_ACCEPTED_BY_POLICY:
            transition = TaskTransitionService(
                self._factory,
                self._artifact_store,
                gate_evaluator=_BriefTransitionGates(stored.policy.id),
                active_policy_lineage=self._active_policy_lineage,
                principal_id=self._principal_id,
                clock=lambda: now,
            ).transition(
                task_id,
                transition_id=_derived_id(brief_id, "auto-accept"),
                expected_state=TaskState.BRIEFING,
                kind=TaskTransitionKind.AUTO_ACCEPT_BRIEF,
                reason_code="BRIEF_AUTO_ACCEPTED",
                evidence_ids=(stored.evidence.id,),
            )
            return _result(stored, transition=transition, approval=None)

        approval = ApprovalService(
            self._factory,
            self._artifact_store,
            active_policy_lineage=self._active_policy_lineage,
            principal_id=self._principal_id,
            clock=lambda: now,
        ).request(
            task_id,
            request_id=_derived_id(brief_id, "approval-request"),
            expected_state=TaskState.BRIEFING,
            request_type=ApprovalRequestType.BRIEF,
            reason_code="BRIEF_REQUIRES_APPROVAL",
            subject_type="BRIEF",
            subject_id=brief_id,
            blocked_operation=None,
            evidence_ids=(stored.evidence.id,),
            expires_at=stored.decision.decided_at + stored.evaluation.approval_lifetime,
        )
        return _result(stored, transition=None, approval=approval)

    def _store_version(
        self,
        task_id: UUID,
        *,
        brief_id: UUID,
        draft: StructuredBriefDraft,
        now: datetime,
    ) -> _StoredBrief:
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            task = session.scalar(
                select(Task).where(Task.id == task_id).with_for_update()
            )
            if task is None:
                raise BriefingNotFoundError("task is unavailable")
            existing = session.get(Brief, brief_id)
            if existing is not None:
                return _replayed_stored_brief(session, task, existing, draft)
            if TaskState(task.state) is not TaskState.BRIEFING:
                raise BriefingConflictError("task is not in briefing")

            policy = _active_policy(
                session,
                task,
                lineage_key=self._active_policy_lineage,
                now=now,
            )
            evaluation = _evaluate_policy(draft, policy)
            predecessor = session.scalar(
                select(Brief)
                .where(Brief.task_id == task.id)
                .order_by(Brief.version.desc())
                .limit(1)
                .with_for_update()
            )
            version = 1 if predecessor is None else predecessor.version + 1
            context = {
                "owner_id": task.owner_id,
                "actor_id": self._principal_id,
                "root_correlation_id": task.root_correlation_id,
                "causation_id": brief_id,
                "parent_correlation_id": task.id,
                "created_at": now,
                "updated_at": now,
            }
            fields = draft.storage_fields()
            brief = Brief(
                id=brief_id,
                task_id=task.id,
                version=version,
                predecessor_id=None if predecessor is None else predecessor.id,
                **fields,
                **context,
            )
            session.add(brief)
            session.flush()
            decision = BriefApprovalDecision(
                id=_derived_id(brief.id, "decision"),
                task_id=task.id,
                brief_id=brief.id,
                disposition=evaluation.disposition,
                evaluator_id="brief-approval-policy-v1",
                policy_version_id=policy.id,
                reason=evaluation.reason,
                ambiguity_flags=list(evaluation.flags),
                human_response=None,
                decided_at=now,
                **context,
            )
            session.add(decision)
            session.flush()
            source_request_evidence_id = _request_evidence_id(task)
            captured = capture_evidence(
                session,
                self._artifact_store,
                payload={
                    "schema_version": BRIEF_EVENT_SCHEMA_VERSION,
                    "task_id": str(task.id),
                    "brief_id": str(brief.id),
                    "brief_version": brief.version,
                    "predecessor_id": (
                        None if brief.predecessor_id is None else str(brief.predecessor_id)
                    ),
                    "source_request_evidence_id": str(source_request_evidence_id),
                    "brief": draft.model_dump(mode="json"),
                    "policy_version_id": str(policy.id),
                    "disposition": evaluation.disposition.value,
                    "decision_flags": list(evaluation.flags),
                },
                media_type="application/json",
                source_kind=EvidenceSourceKind.RESULT,
                evidence_type=BRIEF_EVIDENCE_TYPE,
                origin="control-plane:briefing",
                access_classification=EvidenceAccessClass.TASK_OWNER,
                retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
                owner_id=task.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=task.root_correlation_id,
                task_id=task.id,
                causation_id=brief.id,
                parent_correlation_id=source_request_evidence_id,
                captured_at=now,
            )
            event = TaskEvent(
                task_id=task.id,
                sequence=_next_event_sequence(session, task.id),
                event_type=BRIEF_EVENT_TYPE,
                payload={
                    "schema_version": BRIEF_EVENT_SCHEMA_VERSION,
                    "brief_id": str(brief.id),
                    "brief_version": brief.version,
                    "decision_id": str(decision.id),
                    "disposition": decision.disposition.value,
                    "policy_version_id": str(policy.id),
                },
                occurred_at=now,
                owner_id=task.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=task.root_correlation_id,
                causation_id=brief.id,
                parent_correlation_id=task.id,
            )
            session.add(event)
            session.flush()
            session.add(
                TaskEventEvidenceReference(
                    task_id=task.id,
                    task_event_id=event.id,
                    evidence_id=captured.record.id,
                    position=1,
                    owner_id=task.owner_id,
                    actor_id=self._principal_id,
                    root_correlation_id=task.root_correlation_id,
                    causation_id=event.id,
                    parent_correlation_id=brief.id,
                )
            )
            task.accepted_brief_id = brief.id
            task.brief_approval_decision_id = decision.id
            task.actor_id = self._principal_id
            task.causation_id = event.id
            session.flush()
            return _StoredBrief(
                task_id=task.id,
                brief=brief,
                decision=decision,
                policy=policy,
                evidence=captured.record,
                evaluation=evaluation,
                replayed=False,
            )


@dataclass(frozen=True, slots=True)
class _StoredBrief:
    task_id: UUID
    brief: Brief
    decision: BriefApprovalDecision
    policy: PolicyVersion
    evidence: EvidenceRecord
    evaluation: BriefPolicyEvaluation
    replayed: bool


def _result(
    stored: _StoredBrief,
    *,
    transition: TaskTransitionResult | None,
    approval: ApprovalRequestResult | None,
) -> BriefingResult:
    if transition is not None:
        state = transition.to_state
    elif approval is not None:
        state = approval.task_state
    else:
        raise BriefingConflictError("brief disposition was not routed")
    return BriefingResult(
        task_id=stored.task_id,
        brief_id=stored.brief.id,
        brief_version=stored.brief.version,
        decision_id=stored.decision.id,
        disposition=BriefDecisionDisposition(stored.decision.disposition),
        policy_version_id=stored.policy.id,
        evidence_id=stored.evidence.id,
        task_state=TaskState(state),
        approval_request_id=None if approval is None else approval.request_id,
        replayed=(
            stored.replayed
            or bool(transition and transition.replayed)
            or bool(approval and approval.replayed)
        ),
    )


def _replayed_stored_brief(
    session: Session,
    task: Task,
    brief: Brief,
    draft: StructuredBriefDraft,
) -> _StoredBrief:
    if brief.task_id != task.id or not _brief_matches(brief, draft):
        raise BriefingConflictError("brief id conflicts with durable content")
    decision = session.scalar(
        select(BriefApprovalDecision).where(
            BriefApprovalDecision.task_id == task.id,
            BriefApprovalDecision.brief_id == brief.id,
        )
    )
    evidence = session.scalar(
        select(EvidenceRecord).where(
            EvidenceRecord.task_id == task.id,
            EvidenceRecord.evidence_type == BRIEF_EVIDENCE_TYPE,
            EvidenceRecord.causation_id == brief.id,
        )
    )
    if decision is None or evidence is None or decision.policy_version_id is None:
        raise BriefingConflictError("stored brief is incomplete")
    policy = session.get(PolicyVersion, decision.policy_version_id)
    if policy is None:
        raise BriefingConflictError("stored brief policy is unavailable")
    evaluation = _evaluate_policy(draft, policy)
    if (
        evaluation.disposition is not BriefDecisionDisposition(decision.disposition)
        or tuple(decision.ambiguity_flags) != evaluation.flags
        or task.accepted_brief_id != brief.id
        or task.brief_approval_decision_id != decision.id
    ):
        raise BriefingConflictError("stored brief decision is inconsistent")
    return _StoredBrief(
        task_id=task.id,
        brief=brief,
        decision=decision,
        policy=policy,
        evidence=evidence,
        evaluation=evaluation,
        replayed=True,
    )


def _evaluate_policy(
    draft: StructuredBriefDraft,
    policy: PolicyVersion,
) -> BriefPolicyEvaluation:
    flags = list(draft.ambiguity_flags)
    if draft.scope.scope_expansion:
        flags.append("SCOPE_EXPANSION")
    raw = policy.workflow_thresholds.get("brief_approval_policy")
    expected_fields = {
        "schema_version",
        "preallowed_operations",
        "sensitive_path_prefixes",
        "approval_lifetime_hours",
    }
    if (
        not isinstance(raw, Mapping)
        or set(raw) != expected_fields
        or raw.get("schema_version") != BRIEF_POLICY_SCHEMA_VERSION
    ):
        flags.append("POLICY_CONFIGURATION_INVALID")
        preallowed: frozenset[str] = frozenset()
        configured_sensitive: tuple[str, ...] = ()
        approval_hours = DEFAULT_APPROVAL_LIFETIME_HOURS
    else:
        preallowed = _policy_identifiers(raw.get("preallowed_operations"))
        parsed_sensitive = _policy_paths(raw.get("sensitive_path_prefixes"))
        parsed_hours = _approval_hours(raw.get("approval_lifetime_hours"))
        configured_sensitive = () if parsed_sensitive is None else parsed_sensitive
        approval_hours = (
            DEFAULT_APPROVAL_LIFETIME_HOURS
            if parsed_hours is None
            else parsed_hours
        )
        if not preallowed or parsed_sensitive is None or parsed_hours is None:
            flags.append("POLICY_CONFIGURATION_INVALID")
    sensitive = (*_BUILT_IN_SENSITIVE_PATHS, *configured_sensitive)
    for path in draft.scope.included_paths:
        if any(_path_is_within(path, prefix) for prefix in sensitive):
            flags.append(f"SENSITIVE_PATH:{path}")
    for operation in draft.scope.operations:
        if operation.operation_id not in preallowed:
            flags.append(f"OPERATION_NOT_PREALLOWED:{operation.operation_id}")
        if operation.risk is not RiskLevel.LOW:
            flags.append(f"OPERATION_RISK_NOT_LOW:{operation.operation_id}")
    for risk in draft.risks:
        if risk.level is not RiskLevel.LOW:
            flags.append(f"RISK_NOT_LOW:{risk.risk_id}")
    unique_flags = tuple(dict.fromkeys(flags))
    disposition = (
        BriefDecisionDisposition.AUTO_ACCEPTED_BY_POLICY
        if not unique_flags
        else BriefDecisionDisposition.HUMAN_APPROVAL_REQUIRED
    )
    return BriefPolicyEvaluation(
        disposition=disposition,
        reason=(
            "Complete low-risk brief matched the active approval policy"
            if disposition is BriefDecisionDisposition.AUTO_ACCEPTED_BY_POLICY
            else "Exact brief requires human approval"
        ),
        flags=unique_flags,
        approval_lifetime=timedelta(hours=approval_hours),
    )


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
        .with_for_update()
    )
    if policy is None:
        raise BriefingNotFoundError("active briefing policy is unavailable")
    return policy


def _brief_matches(brief: Brief, draft: StructuredBriefDraft) -> bool:
    fields = draft.storage_fields()
    return all(getattr(brief, name) == value for name, value in fields.items())


def _request_evidence_id(task: Task) -> UUID:
    prefix = "evidence://"
    if not task.raw_request.startswith(prefix):
        raise BriefingConflictError("task request evidence is unavailable")
    try:
        return UUID(task.raw_request.removeprefix(prefix))
    except ValueError:
        raise BriefingConflictError("task request evidence is unavailable") from None


def _repository_path(value: str) -> str:
    path = value.strip()
    candidate = PurePosixPath(path)
    if (
        not path
        or len(path) > 500
        or path.startswith(("/", "~"))
        or "\\" in path
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise ValueError("brief path must be repository-relative and canonical")
    return candidate.as_posix()


def _policy_identifiers(value: object) -> frozenset[str]:
    if not isinstance(value, list) or len(value) > 100:
        return frozenset()
    identifiers = tuple(item for item in value if isinstance(item, str))
    if (
        len(identifiers) != len(value)
        or len(identifiers) != len(set(identifiers))
        or any(re.fullmatch(_IDENTIFIER_PATTERN, item) is None for item in identifiers)
    ):
        return frozenset()
    return frozenset(identifiers)


def _policy_paths(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list) or len(value) > 100:
        return None
    try:
        paths = tuple(_repository_path(item) for item in value if isinstance(item, str))
    except ValueError:
        return None
    if len(paths) != len(value) or len(paths) != len(set(paths)):
        return None
    return paths


def _approval_hours(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 168:
        return None
    return value


def _path_is_within(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(f"{prefix}/")


def _next_event_sequence(session: Session, task_id: UUID) -> int:
    current = session.scalar(
        select(func.max(TaskEvent.sequence)).where(TaskEvent.task_id == task_id)
    )
    return int(current or 0) + 1


def _derived_id(brief_id: UUID, purpose: str) -> UUID:
    return uuid5(NAMESPACE_URL, f"mathews:brief:{brief_id}:{purpose}")


def _begin_serialized(session: Session) -> None:
    if session.get_bind().dialect.name == "sqlite":
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
