"""Exact-head pull-request readiness and explicit automation handoff."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import cast
from uuid import NAMESPACE_URL, UUID, uuid5

from sqlalchemy import exists, select
from sqlalchemy.orm import Session, aliased

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    BackgroundJob,
    BackgroundJobStatus,
    EvidenceRecord,
    PolicyVersion,
    Task,
    TaskEvent,
    TaskEventEvidenceReference,
    TaskState,
)
from mathews_control_plane.draft_pull_requests import _DraftProofGates
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceError,
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
    load_evidence,
)
from mathews_control_plane.github_webhooks import (
    GITHUB_CHECK_UPDATED_EVENT,
    GITHUB_PR_BOUND_EVENT,
    GITHUB_PR_HEAD_CHANGED_EVENT,
    GITHUB_PULL_REQUEST_UPDATED_EVENT,
    GITHUB_REVIEW_UPDATED_EVENT,
)
from mathews_control_plane.review_resolution import (
    REVIEW_RESOLUTION_JOB_TYPE,
    REVIEW_RESOLUTION_SCHEMA_VERSION,
    ReviewClassification,
    ReviewDisposition,
)
from mathews_control_plane.task_state_machine import (
    DraftPrGateFacts,
    ReadinessGateFacts,
    TaskTransitionGateEvaluator,
    TaskTransitionGuards,
    TaskTransitionKind,
    TaskTransitionResult,
    TaskTransitionService,
)

READINESS_ASSESSMENT_SCHEMA_VERSION = 1
HANDOFF_ACKNOWLEDGEMENT_SCHEMA_VERSION = 1
HANDOFF_MEANING = (
    "Automation responsibility has ended; this does not mean merged, deployed, "
    "delivered, or released."
)
HANDOFF_ACKNOWLEDGEMENT = (
    "I acknowledge that automation is complete and that merge, deployment, "
    "delivery, and release remain human responsibilities."
)
_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_ACTIVE_JOB_STATES = frozenset(
    {BackgroundJobStatus.QUEUED, BackgroundJobStatus.RUNNING}
)


class ReadinessError(RuntimeError):
    """Stable readiness refusal without evidence or review contents."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ReadinessReconcileStatus(StrEnum):
    READY = "READY"
    BLOCKED = "BLOCKED"
    INVALIDATED = "INVALIDATED"
    UNCHANGED = "UNCHANGED"
    IGNORED = "IGNORED"


@dataclass(frozen=True, slots=True)
class ReadinessReconcileResult:
    task_id: UUID
    status: ReadinessReconcileStatus
    assessment_evidence_id: UUID | None = None
    transition: TaskTransitionResult | None = None
    blocker_codes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class HandoffResult:
    handoff_id: UUID
    task_id: UUID
    head_sha: str
    acknowledgement_evidence_id: UUID
    transition: TaskTransitionResult
    meaning: str = HANDOFF_MEANING


@dataclass(frozen=True, slots=True)
class _GitHubFacts:
    binding_event_id: UUID | None
    pull_request_number: int | None
    branch_name: str | None
    head_sha: str | None
    required_checks: tuple[str, ...]
    required_ci_green: bool
    no_blocking_review: bool
    current_pull_request_is_draft: bool
    open_review_event_ids: tuple[UUID, ...]
    check_states: tuple[tuple[str, str], ...]
    blocking_reviews: int
    open_threads: int


@dataclass(frozen=True, slots=True)
class _ReadinessAssessment:
    task_id: UUID
    draft_proof_evidence_id: UUID | None
    draft_pr: DraftPrGateFacts | None
    github: _GitHubFacts
    repairs_authorized: bool
    blocker_codes: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return not self.blocker_codes and self.draft_pr is not None

    def gate_facts(self) -> ReadinessGateFacts | None:
        if not self.ready or self.draft_pr is None:
            return None
        return ReadinessGateFacts(
            draft_pr=self.draft_pr,
            required_ci_green=self.github.required_ci_green,
            no_blocking_review=self.github.no_blocking_review,
            repairs_authorized=self.repairs_authorized,
        )


class ReadinessService:
    """Reconcile verified draft state and record one explicit human handoff."""

    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        *,
        principal_id: str = "control-plane",
        active_policy_lineage: str = "mvp",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._factory = factory
        self._store = artifact_store
        self._principal = principal_id
        self._policy_lineage = active_policy_lineage
        self._clock = clock or (lambda: datetime.now(UTC))

    def reconcile(
        self,
        task_id: UUID,
        *,
        trigger_event_id: UUID,
    ) -> ReadinessReconcileResult:
        now = _utc(self._clock())
        with self._factory() as session:
            task = session.get(Task, task_id)
            trigger = session.get(TaskEvent, trigger_event_id)
            if task is None or trigger is None or trigger.task_id != task.id:
                raise ReadinessError("READINESS_TRIGGER_UNAVAILABLE")
            state = TaskState(task.state)
            if state not in {TaskState.PR_ACTIVE, TaskState.READY_FOR_HUMAN_MERGE}:
                return ReadinessReconcileResult(
                    task_id, ReadinessReconcileStatus.IGNORED
                )
            policy = _active_policy(
                session,
                task,
                lineage_key=self._policy_lineage,
                now=now,
            )
            assessment = _assess(session, self._store, task, policy=policy)
        assessment_id = self._capture_assessment(
            task_id,
            trigger_event_id=trigger_event_id,
            assessment=assessment,
            now=now,
        )
        gates = _ReadinessTransitionGates(
            self._store,
            assessment_id=assessment_id,
            acknowledgement_evidence_id=None,
        )
        transitions = TaskTransitionService(
            self._factory,
            self._store,
            gate_evaluator=gates,
            active_policy_lineage=self._policy_lineage,
            principal_id=self._principal,
            clock=self._clock,
        )
        if state is TaskState.PR_ACTIVE and assessment.ready:
            transition = transitions.transition(
                task_id,
                transition_id=uuid5(
                    NAMESPACE_URL,
                    f"mathews:readiness:{task_id}:{trigger_event_id}:{assessment_id}",
                ),
                expected_state=TaskState.PR_ACTIVE,
                kind=TaskTransitionKind.MARK_MERGE_READY,
                reason_code="EXACT_HEAD_READY_FOR_HUMAN",
                evidence_ids=(assessment_id,),
            )
            return ReadinessReconcileResult(
                task_id,
                ReadinessReconcileStatus.READY,
                assessment_id,
                transition,
            )
        if state is TaskState.READY_FOR_HUMAN_MERGE and not assessment.ready:
            transition = transitions.transition(
                task_id,
                transition_id=uuid5(
                    NAMESPACE_URL,
                    f"mathews:readiness-invalidated:{task_id}:{trigger_event_id}:{assessment_id}",
                ),
                expected_state=TaskState.READY_FOR_HUMAN_MERGE,
                kind=TaskTransitionKind.INVALIDATE_READINESS,
                reason_code="EXACT_HEAD_READINESS_INVALIDATED",
                evidence_ids=(assessment_id,),
            )
            return ReadinessReconcileResult(
                task_id,
                ReadinessReconcileStatus.INVALIDATED,
                assessment_id,
                transition,
                assessment.blocker_codes,
            )
        return ReadinessReconcileResult(
            task_id,
            (
                ReadinessReconcileStatus.UNCHANGED
                if assessment.ready
                else ReadinessReconcileStatus.BLOCKED
            ),
            assessment_id,
            blocker_codes=assessment.blocker_codes,
        )

    def acknowledge_handoff(
        self,
        task_id: UUID,
        *,
        handoff_id: UUID,
        expected_head_sha: str,
        acknowledgement: str,
        actor_id: str,
    ) -> HandoffResult:
        head = _sha(expected_head_sha)
        if acknowledgement != HANDOFF_ACKNOWLEDGEMENT:
            raise ReadinessError("HANDOFF_ACKNOWLEDGEMENT_INVALID")
        evidence_id = self._capture_handoff_acknowledgement(
            task_id,
            handoff_id=handoff_id,
            head_sha=head,
            acknowledgement=acknowledgement,
            actor_id=actor_id,
        )
        transition = TaskTransitionService(
            self._factory,
            self._store,
            gate_evaluator=_ReadinessTransitionGates(
                self._store,
                assessment_id=None,
                acknowledgement_evidence_id=evidence_id,
            ),
            active_policy_lineage=self._policy_lineage,
            principal_id=actor_id,
            clock=self._clock,
        ).transition(
            task_id,
            transition_id=uuid5(
                NAMESPACE_URL, f"mathews:human-handoff:{task_id}:{handoff_id}"
            ),
            expected_state=TaskState.READY_FOR_HUMAN_MERGE,
            kind=TaskTransitionKind.ACKNOWLEDGE_HANDOFF,
            reason_code="HUMAN_ACKNOWLEDGED_AUTOMATION_HANDOFF",
            evidence_ids=(evidence_id,),
        )
        return HandoffResult(
            handoff_id,
            task_id,
            head,
            evidence_id,
            transition,
        )

    def _capture_assessment(
        self,
        task_id: UUID,
        *,
        trigger_event_id: UUID,
        assessment: _ReadinessAssessment,
        now: datetime,
    ) -> UUID:
        payload = _assessment_payload(assessment, trigger_event_id=trigger_event_id)
        fingerprint = _fingerprint(payload)
        payload["assessment_fingerprint"] = fingerprint
        evidence_id = uuid5(
            NAMESPACE_URL,
            f"mathews:readiness-assessment:{task_id}:{trigger_event_id}:{fingerprint}",
        )
        with self._factory.begin() as session:
            existing = session.get(EvidenceRecord, evidence_id)
            if existing is not None:
                if load_evidence(session, self._store, existing).content != payload:
                    raise ReadinessError("READINESS_ASSESSMENT_CONFLICT")
                return existing.id
            task = session.get(Task, task_id)
            trigger = session.get(TaskEvent, trigger_event_id)
            if (
                task is None
                or trigger is None
                or trigger.task_id != task.id
                or TaskState(task.state)
                not in {TaskState.PR_ACTIVE, TaskState.READY_FOR_HUMAN_MERGE}
            ):
                raise ReadinessError("READINESS_TASK_STALE")
            captured = capture_evidence(
                session,
                self._store,
                payload=payload,
                media_type="application/json",
                source_kind=EvidenceSourceKind.RESULT,
                evidence_type="pull-request-readiness-assessment",
                origin="control-plane:readiness",
                access_classification=EvidenceAccessClass.TASK_OWNER,
                retention_policy=EvidenceRetentionClass.AUDIT,
                owner_id=task.owner_id,
                actor_id=self._principal,
                root_correlation_id=task.root_correlation_id,
                task_id=task.id,
                causation_id=trigger.id,
                parent_correlation_id=assessment.draft_proof_evidence_id,
                evidence_id=evidence_id,
                captured_at=now,
            )
            return captured.record.id

    def _capture_handoff_acknowledgement(
        self,
        task_id: UUID,
        *,
        handoff_id: UUID,
        head_sha: str,
        acknowledgement: str,
        actor_id: str,
    ) -> UUID:
        payload = {
            "schema_version": HANDOFF_ACKNOWLEDGEMENT_SCHEMA_VERSION,
            "handoff_id": str(handoff_id),
            "task_id": str(task_id),
            "head_sha": head_sha,
            "acknowledgement": acknowledgement,
            "meaning": HANDOFF_MEANING,
            "actor_id": actor_id,
        }
        with self._factory.begin() as session:
            existing = session.get(EvidenceRecord, handoff_id)
            if existing is not None:
                if load_evidence(session, self._store, existing).content != payload:
                    raise ReadinessError("HANDOFF_IDEMPOTENCY_CONFLICT")
                return existing.id
            task = session.get(Task, task_id)
            if (
                task is None
                or task.owner_id != actor_id
                or TaskState(task.state) is not TaskState.READY_FOR_HUMAN_MERGE
            ):
                raise ReadinessError("HANDOFF_TASK_NOT_READY")
            captured = capture_evidence(
                session,
                self._store,
                payload=payload,
                media_type="application/json",
                source_kind=EvidenceSourceKind.REQUEST,
                evidence_type="human-handoff-acknowledgement",
                origin="local-user:handoff",
                access_classification=EvidenceAccessClass.TASK_OWNER,
                retention_policy=EvidenceRetentionClass.AUDIT,
                owner_id=task.owner_id,
                actor_id=actor_id,
                root_correlation_id=task.root_correlation_id,
                task_id=task.id,
                causation_id=handoff_id,
                parent_correlation_id=task.id,
                evidence_id=handoff_id,
                captured_at=_utc(self._clock()),
            )
            return captured.record.id


class _ReadinessTransitionGates(TaskTransitionGateEvaluator):
    def __init__(
        self,
        store: ArtifactStore,
        *,
        assessment_id: UUID | None,
        acknowledgement_evidence_id: UUID | None,
    ) -> None:
        self._store = store
        self._assessment_id = assessment_id
        self._acknowledgement_id = acknowledgement_evidence_id

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
        current = _assess(session, self._store, task, policy=policy)
        if kind in {
            TaskTransitionKind.MARK_MERGE_READY,
            TaskTransitionKind.INVALIDATE_READINESS,
        }:
            if self._assessment_id is None:
                return TaskTransitionGuards()
            record = session.get(EvidenceRecord, self._assessment_id)
            if record is None or record.task_id != task.id:
                return TaskTransitionGuards()
            try:
                payload = load_evidence(session, self._store, record).content
            except EvidenceError:
                return TaskTransitionGuards()
            if not _assessment_matches(payload, current):
                return TaskTransitionGuards()
            if kind is TaskTransitionKind.MARK_MERGE_READY:
                return TaskTransitionGuards(readiness=current.gate_facts())
            return TaskTransitionGuards(
                readiness_invalidation_current=not current.ready
            )
        if kind is not TaskTransitionKind.ACKNOWLEDGE_HANDOFF:
            return TaskTransitionGuards()
        acknowledgement = (
            None
            if self._acknowledgement_id is None
            else session.get(EvidenceRecord, self._acknowledgement_id)
        )
        if acknowledgement is None or acknowledgement.task_id != task.id:
            return TaskTransitionGuards()
        try:
            payload = load_evidence(session, self._store, acknowledgement).content
        except EvidenceError:
            return TaskTransitionGuards()
        facts = current.gate_facts()
        valid = (
            facts is not None
            and isinstance(payload, dict)
            and payload.get("schema_version")
            == HANDOFF_ACKNOWLEDGEMENT_SCHEMA_VERSION
            and payload.get("task_id") == str(task.id)
            and payload.get("head_sha") == facts.draft_pr.current_head_sha
            and payload.get("acknowledgement") == HANDOFF_ACKNOWLEDGEMENT
            and payload.get("meaning") == HANDOFF_MEANING
            and payload.get("actor_id") == task.owner_id
        )
        return TaskTransitionGuards(
            readiness=facts if valid else None,
            human_handoff_acknowledged=valid,
        )


def _assess(
    session: Session,
    store: ArtifactStore,
    task: Task,
    *,
    policy: PolicyVersion,
) -> _ReadinessAssessment:
    proof_id, draft = _draft_pr_facts(session, store, task, policy=policy)
    events = tuple(
        session.scalars(
            select(TaskEvent)
            .where(TaskEvent.task_id == task.id)
            .order_by(TaskEvent.sequence, TaskEvent.id)
        )
    )
    github = _github_facts(events)
    repairs_authorized = _repairs_authorized(
        session,
        store,
        task,
        current_head=github.head_sha,
        open_review_event_ids=github.open_review_event_ids,
    )
    blockers: list[str] = []
    if draft is None or proof_id is None:
        blockers.append("VERIFIED_DRAFT_PROOF_UNAVAILABLE")
    if github.binding_event_id is None or github.head_sha is None:
        blockers.append("PULL_REQUEST_NOT_BOUND")
    if (
        draft is not None
        and github.head_sha is not None
        and draft.current_head_sha != github.head_sha
    ):
        blockers.append("PULL_REQUEST_HEAD_CHANGED")
    if not github.current_pull_request_is_draft:
        blockers.append("PULL_REQUEST_NOT_DRAFT")
    if not github.required_ci_green:
        blockers.append("REQUIRED_CI_NOT_GREEN")
    if not github.no_blocking_review:
        blockers.append("BLOCKING_REVIEW_PRESENT")
    if not repairs_authorized:
        blockers.append("REVIEW_REPAIRS_NOT_SETTLED")
    return _ReadinessAssessment(
        task.id,
        proof_id,
        draft,
        github,
        repairs_authorized,
        tuple(blockers),
    )


def _draft_pr_facts(
    session: Session,
    store: ArtifactStore,
    task: Task,
    *,
    policy: PolicyVersion,
) -> tuple[UUID | None, DraftPrGateFacts | None]:
    transition = session.scalar(
        select(TaskEvent)
        .where(
            TaskEvent.task_id == task.id,
            TaskEvent.transition_kind
            == TaskTransitionKind.OPEN_VERIFIED_DRAFT_PR.value,
        )
        .order_by(TaskEvent.sequence.desc(), TaskEvent.id.desc())
        .limit(1)
    )
    if transition is None:
        return None, None
    references = tuple(
        session.scalars(
            select(TaskEventEvidenceReference)
            .where(TaskEventEvidenceReference.task_event_id == transition.id)
            .order_by(TaskEventEvidenceReference.position)
        )
    )
    proof: EvidenceRecord | None = None
    for reference in references:
        candidate = session.get(EvidenceRecord, reference.evidence_id)
        if candidate is not None and candidate.evidence_type == "draft-pull-request-proof":
            proof = candidate
            break
    if proof is None:
        return None, None
    try:
        guards = _DraftProofGates(store, proof.id).evaluate(
            session,
            task,
            TaskTransitionKind.OPEN_VERIFIED_DRAFT_PR,
            policy=policy,
            now=datetime.now(UTC),
        )
    except (EvidenceError, ValueError):
        return proof.id, None
    facts = guards.draft_pr
    if (
        facts is None
        or transition.gate_head_sha is None
        or facts.current_head_sha != transition.gate_head_sha
    ):
        return proof.id, None
    return proof.id, facts


def _github_facts(events: Sequence[TaskEvent]) -> _GitHubFacts:
    binding = next(
        (event for event in reversed(events) if event.event_type == GITHUB_PR_BOUND_EVENT),
        None,
    )
    if binding is None:
        return _empty_github_facts()
    number = binding.payload.get("pull_request_number")
    branch = binding.payload.get("task_branch")
    head = binding.payload.get("head_sha")
    checks_value = binding.payload.get("required_checks")
    if (
        isinstance(number, bool)
        or not isinstance(number, int)
        or number <= 0
        or not isinstance(branch, str)
        or not branch
        or not isinstance(head, str)
        or _SHA.fullmatch(head) is None
        or not isinstance(checks_value, list)
        or not checks_value
        or any(not isinstance(value, str) or not value for value in checks_value)
        or len(checks_value) != len(set(cast(list[str], checks_value)))
    ):
        return _empty_github_facts()
    required_checks = tuple(cast(list[str], checks_value))
    head_change = next(
        (
            event
            for event in reversed(events)
            if event.sequence > binding.sequence
            and event.event_type == GITHUB_PR_HEAD_CHANGED_EVENT
            and event.payload.get("pull_request_number") == number
            and event.payload.get("task_branch") == branch
        ),
        None,
    )
    projection_start = binding.sequence
    if head_change is not None:
        changed_head = head_change.payload.get("head_sha")
        if not isinstance(changed_head, str) or _SHA.fullmatch(changed_head) is None:
            return _empty_github_facts()
        head = changed_head
        projection_start = head_change.sequence
    latest: dict[tuple[object, object], TaskEvent] = {}
    for event in events:
        if (
            event.sequence < projection_start
            or event.event_type
            not in {
                GITHUB_CHECK_UPDATED_EVENT,
                GITHUB_REVIEW_UPDATED_EVENT,
                GITHUB_PULL_REQUEST_UPDATED_EVENT,
                GITHUB_PR_HEAD_CHANGED_EVENT,
            }
            or event.payload.get("head_sha") != head
            or event.payload.get("pull_request_number") != number
            or event.payload.get("task_branch") != branch
        ):
            continue
        key = (event.payload.get("resource_type"), event.payload.get("resource_id"))
        previous = latest.get(key)
        if (
            key[0] == "review"
            and event.payload.get("state") == "COMMENTED"
            and previous is not None
        ):
            continue
        latest[key] = event
    check_events: dict[str, TaskEvent] = {}
    for (resource_type, _resource_id), event in latest.items():
        label = event.payload.get("resource_label")
        if resource_type == "check_run" and isinstance(label, str):
            previous = check_events.get(label)
            if previous is None or _event_recency(event) > _event_recency(previous):
                check_events[label] = event
    check_states = tuple(
        (name, str(check_events[name].payload.get("state")))
        for name in required_checks
        if name in check_events
    )
    required_ci_green = len(check_states) == len(required_checks) and all(
        state in {"PASSED", "NEUTRAL"} for _name, state in check_states
    )
    review_states = tuple(
        str(event.payload.get("state"))
        for (resource_type, _resource_id), event in latest.items()
        if resource_type == "review"
    )
    thread_states = tuple(
        str(event.payload.get("state"))
        for (resource_type, _resource_id), event in latest.items()
        if resource_type == "review_thread"
    )
    blocking_reviews = sum(state == "CHANGES_REQUESTED" for state in review_states)
    open_threads = sum(state == "OPEN" for state in thread_states)
    current_pr = next(
        (
            event
            for (resource_type, _resource_id), event in latest.items()
            if resource_type == "pull_request"
        ),
        None,
    )
    current_pull_request_is_draft = (
        current_pr is None or current_pr.payload.get("state") == "DRAFT"
    )
    open_review_events = tuple(
        event.id
        for (resource_type, _resource_id), event in latest.items()
        if resource_type == "review_comment" and event.payload.get("state") == "OPEN"
    )
    return _GitHubFacts(
        binding.id,
        number,
        branch,
        head,
        required_checks,
        required_ci_green,
        blocking_reviews == 0 and open_threads == 0,
        current_pull_request_is_draft,
        open_review_events,
        check_states,
        blocking_reviews,
        open_threads,
    )


def _repairs_authorized(
    session: Session,
    store: ArtifactStore,
    task: Task,
    *,
    current_head: str | None,
    open_review_event_ids: Sequence[UUID],
) -> bool:
    active_job = session.scalar(
        select(BackgroundJob.id)
        .where(
            BackgroundJob.task_id == task.id,
            BackgroundJob.job_type == REVIEW_RESOLUTION_JOB_TYPE,
            BackgroundJob.status.in_(_ACTIVE_JOB_STATES),
        )
        .limit(1)
    )
    if active_job is not None or current_head is None:
        return False
    if not open_review_event_ids:
        return True
    correction = aliased(EvidenceRecord)
    records = tuple(
        session.scalars(
            select(EvidenceRecord).where(
                EvidenceRecord.task_id == task.id,
                EvidenceRecord.evidence_type == "review-resolution-assessment",
                EvidenceRecord.origin == "control-plane:review-resolution",
                EvidenceRecord.correction_of_id.is_(None),
                EvidenceRecord.deleted_at.is_(None),
                ~exists().where(correction.correction_of_id == EvidenceRecord.id),
            )
        )
    )
    informational: set[UUID] = set()
    for record in records:
        try:
            payload = load_evidence(session, store, record).content
        except EvidenceError:
            continue
        if (
            not isinstance(payload, dict)
            or payload.get("schema_version") != REVIEW_RESOLUTION_SCHEMA_VERSION
            or payload.get("task_id") != str(task.id)
            or payload.get("original_head_sha") != current_head
        ):
            continue
        raw_event_id = payload.get("task_event_id")
        classification = payload.get("classification")
        fingerprint = payload.get("assessment_fingerprint")
        if not isinstance(raw_event_id, str) or not isinstance(fingerprint, str):
            continue
        try:
            event_id = UUID(raw_event_id)
            parsed = ReviewClassification.model_validate(classification)
        except (TypeError, ValueError):
            continue
        unsigned = dict(payload)
        unsigned.pop("assessment_fingerprint", None)
        expected_id = uuid5(
            NAMESPACE_URL,
            f"mathews:review-assessment:{event_id}:{fingerprint}",
        )
        if (
            record.id != expected_id
            or fingerprint != _fingerprint(unsigned)
            or parsed.disposition is not ReviewDisposition.INFORMATIONAL
        ):
            continue
        informational.add(event_id)
    return set(open_review_event_ids).issubset(informational)


def _event_recency(event: TaskEvent) -> tuple[datetime, int, str]:
    raw = event.payload.get("source_updated_at")
    if isinstance(raw, str):
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if parsed.tzinfo is not None and parsed.utcoffset() is not None:
                return parsed.astimezone(UTC), event.sequence, str(event.id)
        except ValueError:
            pass
    return datetime.min.replace(tzinfo=UTC), event.sequence, str(event.id)


def _assessment_payload(
    assessment: _ReadinessAssessment,
    *,
    trigger_event_id: UUID,
) -> dict[str, object]:
    github = assessment.github
    return {
        "schema_version": READINESS_ASSESSMENT_SCHEMA_VERSION,
        "task_id": str(assessment.task_id),
        "trigger_event_id": str(trigger_event_id),
        "draft_proof_evidence_id": (
            None
            if assessment.draft_proof_evidence_id is None
            else str(assessment.draft_proof_evidence_id)
        ),
        "verified_head_sha": (
            None
            if assessment.draft_pr is None
            else assessment.draft_pr.current_head_sha
        ),
        "binding_event_id": (
            None if github.binding_event_id is None else str(github.binding_event_id)
        ),
        "pull_request_number": github.pull_request_number,
        "branch_name": github.branch_name,
        "current_head_sha": github.head_sha,
        "required_checks": list(github.required_checks),
        "check_states": [list(value) for value in github.check_states],
        "required_ci_green": github.required_ci_green,
        "blocking_reviews": github.blocking_reviews,
        "open_review_threads": github.open_threads,
        "no_blocking_review": github.no_blocking_review,
        "current_pull_request_is_draft": github.current_pull_request_is_draft,
        "repairs_authorized": assessment.repairs_authorized,
        "blocker_codes": list(assessment.blocker_codes),
        "ready_for_human_merge": assessment.ready,
        "merge_available_to_automation": False,
    }


def _assessment_matches(payload: object, assessment: _ReadinessAssessment) -> bool:
    if not isinstance(payload, dict):
        return False
    trigger = payload.get("trigger_event_id")
    if not isinstance(trigger, str):
        return False
    try:
        expected = _assessment_payload(assessment, trigger_event_id=UUID(trigger))
    except ValueError:
        return False
    fingerprint = payload.get("assessment_fingerprint")
    return (
        isinstance(fingerprint, str)
        and _SHA256.fullmatch(fingerprint) is not None
        and payload == {**expected, "assessment_fingerprint": _fingerprint(expected)}
    )


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _empty_github_facts() -> _GitHubFacts:
    return _GitHubFacts(
        None,
        None,
        None,
        None,
        (),
        False,
        False,
        False,
        (),
        (),
        0,
        0,
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
    )
    if policy is None:
        raise ReadinessError("READINESS_POLICY_UNAVAILABLE")
    return policy


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
        raise ReadinessError("READINESS_FINGERPRINT_INVALID") from None
    return hashlib.sha256(encoded).hexdigest()


def _sha(value: str) -> str:
    normalized = value.strip().lower()
    if _SHA.fullmatch(normalized) is None:
        raise ReadinessError("HANDOFF_HEAD_INVALID")
    return normalized


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ReadinessError("READINESS_CLOCK_INVALID")
    return value.astimezone(UTC)
