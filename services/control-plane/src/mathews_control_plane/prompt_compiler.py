"""Bounded role prompts and immutable human-governed promotion."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    Brief,
    EvidenceRecord,
    PolicyVersion,
    PolicyVersionPromptTemplate,
    PolicyVersionReviewRule,
    PromptTemplateVersion,
    Task,
)
from mathews_control_plane.evidence import load_evidence

PROMPT_TEMPLATE_SCHEMA_VERSION = 1
MAX_EVIDENCE_REFERENCES = 20
MAX_PROMPT_CHARACTERS = 32_000
_LABEL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")
PromptInstruction = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=1_000),
]


class PromptCompilerError(RuntimeError):
    """Base class for stable prompt failures."""


class PromptNotFoundError(PromptCompilerError):
    """A required durable prompt input is unavailable."""


class PromptConflictError(PromptCompilerError):
    """A prompt command conflicts with durable state or policy."""


class PromptRole(StrEnum):
    PLANNER = "planner"
    IMPLEMENTER = "implementer"
    VALIDATOR = "validator"
    PR_WRITER = "pr_writer"
    REVIEWER = "reviewer"


class StructuredPromptTemplate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    schema_version: int = PROMPT_TEMPLATE_SCHEMA_VERSION
    role: PromptRole
    instructions: tuple[PromptInstruction, ...] = Field(min_length=1, max_length=40)
    evidence_limit: int = Field(default=8, ge=0, le=MAX_EVIDENCE_REFERENCES)
    max_prompt_characters: int = Field(default=16_000, ge=1_000, le=MAX_PROMPT_CHARACTERS)

    @field_validator("schema_version")
    @classmethod
    def schema_is_current(cls, value: int) -> int:
        if value != PROMPT_TEMPLATE_SCHEMA_VERSION:
            raise ValueError("prompt template schema version is unsupported")
        return value


@dataclass(frozen=True, slots=True)
class CompiledPrompt:
    task_id: UUID
    role: PromptRole
    template_id: UUID
    template_version: int
    policy_version_id: UUID
    evaluation_label: str | None
    content: str
    evidence_ids: tuple[UUID, ...]

    @property
    def evaluation_mode(self) -> bool:
        return self.evaluation_label is not None


@dataclass(frozen=True, slots=True)
class PromptPromotionResult:
    candidate_id: UUID
    promoted_prompt_id: UUID
    promoted_prompt_version: int
    policy_version_id: UUID
    policy_version: int
    rollback_policy_version_id: UUID
    replayed: bool


class PromptCompilerService:
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
        self._store = artifact_store
        self._policy_lineage = active_policy_lineage
        self._principal_id = _required_text(principal_id, "principal")
        self._clock = clock or (lambda: datetime.now(UTC))

    def create_candidate(
        self,
        *,
        prompt_id: UUID,
        lineage_key: str,
        template: StructuredPromptTemplate,
        owner_id: str,
        root_correlation_id: UUID,
    ) -> PromptTemplateVersion:
        lineage = _required_text(lineage_key, "prompt lineage")
        now = _as_utc(self._clock())
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            existing = session.get(PromptTemplateVersion, prompt_id)
            persisted = template.model_dump(mode="json")
            if existing is not None:
                if (
                    existing.lineage_key != lineage
                    or existing.structured_template != persisted
                    or existing.promoted
                ):
                    raise PromptConflictError("prompt candidate id conflicts")
                return existing
            predecessor = session.scalar(
                select(PromptTemplateVersion)
                .where(PromptTemplateVersion.lineage_key == lineage)
                .order_by(PromptTemplateVersion.version.desc())
                .limit(1)
                .with_for_update()
            )
            if predecessor is not None and predecessor.role != template.role.value:
                raise PromptConflictError("prompt lineage cannot change roles")
            candidate = PromptTemplateVersion(
                id=prompt_id,
                lineage_key=lineage,
                role=template.role.value,
                version=1 if predecessor is None else predecessor.version + 1,
                predecessor_id=None if predecessor is None else predecessor.id,
                structured_template=persisted,
                evaluation_threshold_passed=False,
                regression_reviewed=False,
                promoted=False,
                owner_id=_required_text(owner_id, "owner"),
                actor_id=self._principal_id,
                root_correlation_id=root_correlation_id,
                causation_id=prompt_id,
                created_at=now,
                updated_at=now,
            )
            session.add(candidate)
            session.flush()
            return candidate

    def compile(
        self,
        task_id: UUID,
        *,
        role: PromptRole,
        evidence_ids: Sequence[UUID] = (),
        template_id: UUID | None = None,
        evaluation_label: str | None = None,
        policy_version_id: UUID | None = None,
    ) -> CompiledPrompt:
        evidence_ids = tuple(evidence_ids)
        if len(evidence_ids) != len(set(evidence_ids)):
            raise PromptConflictError("prompt evidence references must be unique")
        with self._factory() as session, session.begin():
            task = session.get(Task, task_id)
            if task is None:
                raise PromptNotFoundError("task is unavailable")
            now = _as_utc(self._clock())
            policy: PolicyVersion | None
            if policy_version_id is None:
                policy = _active_policy(
                    session,
                    owner_id=task.owner_id,
                    lineage_key=self._policy_lineage,
                    now=now,
                )
            else:
                policy = session.get(PolicyVersion, policy_version_id)
                if (
                    policy is None
                    or policy.owner_id != task.owner_id
                    or policy.lineage_key != self._policy_lineage
                    or policy.approved_by is None
                    or policy.approved_at is None
                    or _as_utc(policy.approved_at) > now
                ):
                    raise PromptNotFoundError("policy version is unavailable")
            default = _default_prompt(session, policy.id, role)
            selected = default if template_id is None else session.get(
                PromptTemplateVersion, template_id
            )
            if (
                selected is None
                or selected.role != role.value
                or selected.owner_id != task.owner_id
            ):
                raise PromptNotFoundError("role prompt is unavailable")
            label = _evaluation_label(evaluation_label)
            if selected.id != default.id and label is None:
                raise PromptConflictError("non-default prompts require a labeled evaluation")
            if selected.id == default.id and label is not None:
                raise PromptConflictError("default prompts cannot use an evaluation label")
            template = StructuredPromptTemplate.model_validate(selected.structured_template)
            if len(evidence_ids) > template.evidence_limit:
                raise PromptConflictError("prompt evidence limit exceeded")
            payload = {
                "schema_version": PROMPT_TEMPLATE_SCHEMA_VERSION,
                "role": role.value,
                "instructions": list(template.instructions),
                "task": _task_context(session, task, role),
                "verified_evidence": _verified_evidence(
                    session, self._store, task, evidence_ids
                ),
                "execution": {
                    "policy_version_id": str(policy.id),
                    "template_id": str(selected.id),
                    "template_version": selected.version,
                    "evaluation_label": label,
                },
            }
            content = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            if len(content) > template.max_prompt_characters:
                raise PromptConflictError("compiled prompt exceeds its character budget")
            return CompiledPrompt(
                task_id=task.id,
                role=role,
                template_id=selected.id,
                template_version=selected.version,
                policy_version_id=policy.id,
                evaluation_label=label,
                content=content,
                evidence_ids=evidence_ids,
            )

    def promote(
        self,
        *,
        candidate_id: UUID,
        promoted_prompt_id: UUID,
        policy_version_id: UUID,
        evaluation_evidence_id: UUID,
        evaluation_score: float,
        regression_reviewed: bool,
        approved_by: str,
    ) -> PromptPromotionResult:
        now = _as_utc(self._clock())
        approver = _required_text(approved_by, "human approver")
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            if (
                session.get(PolicyVersion, policy_version_id) is not None
                or session.get(PromptTemplateVersion, promoted_prompt_id) is not None
            ):
                return _replayed_promotion(
                    session,
                    candidate_id=candidate_id,
                    promoted_prompt_id=promoted_prompt_id,
                    policy_version_id=policy_version_id,
                    evaluation_evidence_id=evaluation_evidence_id,
                    evaluation_score=evaluation_score,
                    regression_reviewed=regression_reviewed,
                    approved_by=approver,
                )
            candidate = session.scalar(
                select(PromptTemplateVersion)
                .where(PromptTemplateVersion.id == candidate_id)
                .with_for_update()
            )
            if candidate is None or candidate.promoted:
                raise PromptNotFoundError("unpromoted prompt candidate is unavailable")
            latest_candidate_id = session.scalar(
                select(PromptTemplateVersion.id)
                .where(PromptTemplateVersion.lineage_key == candidate.lineage_key)
                .order_by(PromptTemplateVersion.version.desc())
                .limit(1)
                .with_for_update()
            )
            if latest_candidate_id != candidate.id:
                raise PromptConflictError("only the latest prompt candidate can be promoted")
            active = _active_policy(
                session,
                owner_id=candidate.owner_id,
                lineage_key=self._policy_lineage,
                now=now,
                for_update=True,
            )
            threshold = _promotion_threshold(active)
            if (
                not regression_reviewed
                or isinstance(evaluation_score, bool)
                or not 0 <= evaluation_score <= 1
                or evaluation_score < threshold
            ):
                raise PromptConflictError("prompt promotion requirements are not satisfied")
            evidence = session.get(EvidenceRecord, evaluation_evidence_id)
            if (
                evidence is None
                or evidence.owner_id != candidate.owner_id
                or evidence.evidence_type != "prompt-evaluation"
            ):
                raise PromptNotFoundError("prompt evaluation evidence is unavailable")
            load_evidence(session, self._store, evidence)
            promoted = PromptTemplateVersion(
                id=promoted_prompt_id,
                lineage_key=candidate.lineage_key,
                role=candidate.role,
                version=candidate.version + 1,
                predecessor_id=candidate.id,
                structured_template=candidate.structured_template,
                evaluation_evidence_id=evidence.id,
                evaluation_score=evaluation_score,
                evaluation_threshold_passed=True,
                regression_reviewed=True,
                promoted=True,
                approved_by=approver,
                approved_at=now,
                owner_id=candidate.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=candidate.root_correlation_id,
                causation_id=candidate.id,
                parent_correlation_id=active.id,
                created_at=now,
                updated_at=now,
            )
            policy = PolicyVersion(
                id=policy_version_id,
                lineage_key=active.lineage_key,
                version=active.version + 1,
                predecessor_id=active.id,
                workflow_thresholds=active.workflow_thresholds,
                approved_by=approver,
                approved_at=now,
                rollback_policy_version_id=active.id,
                owner_id=active.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=active.root_correlation_id,
                causation_id=promoted.id,
                parent_correlation_id=active.id,
                created_at=now,
                updated_at=now,
            )
            session.add_all([promoted, policy])
            session.flush()
            _copy_policy_memberships(
                session,
                active=active,
                replacement=promoted,
                policy=policy,
                actor_id=self._principal_id,
                occurred_at=now,
            )
            return PromptPromotionResult(
                candidate_id=candidate.id,
                promoted_prompt_id=promoted.id,
                promoted_prompt_version=promoted.version,
                policy_version_id=policy.id,
                policy_version=policy.version,
                rollback_policy_version_id=active.id,
                replayed=False,
            )


def _task_context(session: Session, task: Task, role: PromptRole) -> dict[str, object]:
    context: dict[str, object] = {
        "task_id": str(task.id),
        "repository": task.repository,
        "base_revision": task.base_revision,
        "summary": task.summary,
        "request_evidence": task.raw_request,
        "state": task.state.value,
    }
    if role is PromptRole.PLANNER:
        return context
    if task.accepted_brief_id is None:
        raise PromptConflictError("role prompt requires an accepted brief")
    brief = session.get(Brief, task.accepted_brief_id)
    if brief is None or brief.task_id != task.id:
        raise PromptNotFoundError("accepted brief is unavailable")
    context["brief"] = {
        "id": str(brief.id),
        "version": brief.version,
        "scope": brief.scope,
        "exclusions": brief.exclusions,
        "acceptance_criteria": brief.acceptance_criteria,
        "risks": brief.risks,
        "affected_flow": brief.affected_flow,
        "test_plan": brief.test_plan,
    }
    return context


def _verified_evidence(
    session: Session,
    store: ArtifactStore,
    task: Task,
    evidence_ids: tuple[UUID, ...],
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for evidence_id in evidence_ids:
        record = session.get(EvidenceRecord, evidence_id)
        if record is None or record.task_id != task.id or record.deleted_at is not None:
            raise PromptNotFoundError("verified prompt evidence is unavailable")
        load_evidence(session, store, record)
        result.append(
            {
                "evidence_id": str(record.id),
                "evidence_type": record.evidence_type,
                "content_hash": record.content_hash,
                "captured_at": record.captured_at.isoformat(),
            }
        )
    return result


def _default_prompt(
    session: Session,
    policy_id: UUID,
    role: PromptRole,
) -> PromptTemplateVersion:
    prompts = session.scalars(
        select(PromptTemplateVersion)
        .join(
            PolicyVersionPromptTemplate,
            PolicyVersionPromptTemplate.prompt_template_version_id
            == PromptTemplateVersion.id,
        )
        .where(
            PolicyVersionPromptTemplate.policy_version_id == policy_id,
            PromptTemplateVersion.role == role.value,
            PromptTemplateVersion.promoted.is_(True),
        )
    ).all()
    if len(prompts) != 1:
        raise PromptNotFoundError("active policy requires exactly one role prompt")
    return prompts[0]


def _active_policy(
    session: Session,
    *,
    owner_id: str,
    lineage_key: str,
    now: datetime,
    for_update: bool = False,
) -> PolicyVersion:
    query = (
        select(PolicyVersion)
        .where(
            PolicyVersion.owner_id == owner_id,
            PolicyVersion.lineage_key == lineage_key,
            PolicyVersion.approved_at <= now,
        )
        .order_by(PolicyVersion.version.desc())
        .limit(1)
    )
    if for_update:
        query = query.with_for_update()
    policy = session.scalar(query)
    if policy is None:
        raise PromptNotFoundError("active prompt policy is unavailable")
    return policy


def _promotion_threshold(policy: PolicyVersion) -> float:
    raw = policy.workflow_thresholds.get("prompt_promotion_policy")
    if not isinstance(raw, Mapping) or set(raw) != {"schema_version", "minimum_score"}:
        raise PromptConflictError("prompt promotion policy is invalid")
    version = raw.get("schema_version")
    score = raw.get("minimum_score")
    if (
        version != 1
        or isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not 0 <= float(score) <= 1
    ):
        raise PromptConflictError("prompt promotion policy is invalid")
    return float(score)


def _copy_policy_memberships(
    session: Session,
    *,
    active: PolicyVersion,
    replacement: PromptTemplateVersion,
    policy: PolicyVersion,
    actor_id: str,
    occurred_at: datetime,
) -> None:
    context = {
        "owner_id": policy.owner_id,
        "actor_id": actor_id,
        "root_correlation_id": policy.root_correlation_id,
        "causation_id": replacement.id,
        "parent_correlation_id": active.id,
        "created_at": occurred_at,
        "updated_at": occurred_at,
    }
    rules = session.scalars(
        select(PolicyVersionReviewRule)
        .where(PolicyVersionReviewRule.policy_version_id == active.id)
        .order_by(PolicyVersionReviewRule.position)
    ).all()
    for rule in rules:
        session.add(
            PolicyVersionReviewRule(
                policy_version_id=policy.id,
                review_rule_id=rule.review_rule_id,
                position=rule.position,
                **context,
            )
        )
    prompts = session.scalars(
        select(PromptTemplateVersion)
        .join(
            PolicyVersionPromptTemplate,
            PolicyVersionPromptTemplate.prompt_template_version_id
            == PromptTemplateVersion.id,
        )
        .where(PolicyVersionPromptTemplate.policy_version_id == active.id)
        .order_by(PolicyVersionPromptTemplate.position)
    ).all()
    kept = [prompt for prompt in prompts if prompt.role != replacement.role]
    for position, prompt in enumerate((*kept, replacement), start=1):
        session.add(
            PolicyVersionPromptTemplate(
                policy_version_id=policy.id,
                prompt_template_version_id=prompt.id,
                prompt_promoted=True,
                position=position,
                **context,
            )
        )
    session.flush()


def _replayed_promotion(
    session: Session,
    *,
    candidate_id: UUID,
    promoted_prompt_id: UUID,
    policy_version_id: UUID,
    evaluation_evidence_id: UUID,
    evaluation_score: float,
    regression_reviewed: bool,
    approved_by: str,
) -> PromptPromotionResult:
    prompt = session.get(PromptTemplateVersion, promoted_prompt_id)
    policy = session.get(PolicyVersion, policy_version_id)
    if (
        prompt is None
        or policy is None
        or prompt.predecessor_id != candidate_id
        or not prompt.promoted
        or prompt.evaluation_evidence_id != evaluation_evidence_id
        or prompt.evaluation_score != evaluation_score
        or prompt.regression_reviewed is not regression_reviewed
        or prompt.approved_by != approved_by
        or policy.predecessor_id is None
        or policy.rollback_policy_version_id != policy.predecessor_id
        or policy.approved_by != approved_by
    ):
        raise PromptConflictError("prompt promotion ids conflict")
    membership = session.scalar(
        select(PolicyVersionPromptTemplate).where(
            PolicyVersionPromptTemplate.policy_version_id == policy.id,
            PolicyVersionPromptTemplate.prompt_template_version_id == prompt.id,
        )
    )
    if membership is None:
        raise PromptConflictError("stored prompt promotion is incomplete")
    return PromptPromotionResult(
        candidate_id=candidate_id,
        promoted_prompt_id=prompt.id,
        promoted_prompt_version=prompt.version,
        policy_version_id=policy.id,
        policy_version=policy.version,
        rollback_policy_version_id=policy.predecessor_id,
        replayed=True,
    )


def _evaluation_label(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if _LABEL_PATTERN.fullmatch(normalized) is None:
        raise PromptConflictError("evaluation label is invalid")
    return normalized


def _required_text(value: str, field: str) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > 255:
        raise PromptConflictError(f"{field} is invalid")
    return normalized


def _begin_serialized(session: Session) -> None:
    if session.get_bind().dialect.name == "sqlite":
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
