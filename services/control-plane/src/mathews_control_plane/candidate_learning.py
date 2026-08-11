"""Cited, non-authoritative summaries and non-executable rule candidates."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    EvidenceDeletionRequest,
    EvidenceDerivative,
    EvidenceRecord,
    RuleCandidate,
    RuleCandidateStatus,
    Task,
)
from mathews_control_plane.evidence import (
    EvidenceError,
    load_evidence,
    load_evidence_derivative,
    normalize_evidence_timestamp,
    register_evidence_derivative,
)

CANDIDATE_LEARNING_SCHEMA_VERSION = 1
DERIVED_SUMMARY_TYPE = "candidate-learning-summary-v1"
NON_AUTHORITATIVE = "NON_AUTHORITATIVE"
MAX_CITATIONS = 100
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}\Z")


class CandidateLearningError(RuntimeError):
    """Fail-closed candidate-learning boundary."""


class CandidateRisk(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class CitedSummaryDraft(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    summary: str = Field(min_length=1, max_length=10_000)
    cited_evidence_ids: tuple[UUID, ...] = Field(min_length=1, max_length=MAX_CITATIONS)

    @field_validator("summary")
    @classmethod
    def _summary(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("summary must not be blank")
        return normalized

    @field_validator("cited_evidence_ids")
    @classmethod
    def _citations(cls, values: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(values) != len(set(values)):
            raise ValueError("citations must be unique")
        return values


class ReviewRuleDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    lineage_key: str = Field(min_length=1, max_length=255)
    scope: dict[str, object]
    matcher: dict[str, object]
    permitted_action: str = Field(min_length=1, max_length=255)
    risk_class: CandidateRisk
    evidence_requirements: tuple[str, ...] = Field(min_length=1, max_length=100)

    @field_validator("lineage_key", "permitted_action")
    @classmethod
    def _identifier(cls, value: str) -> str:
        normalized = value.strip()
        if _IDENTIFIER.fullmatch(normalized) is None:
            raise ValueError("rule identifier is invalid")
        return normalized

    @field_validator("scope", "matcher")
    @classmethod
    def _json_object(cls, value: dict[str, object]) -> dict[str, object]:
        if not value:
            raise ValueError("rule object must not be empty")
        _validate_json(value)
        return value

    @field_validator("evidence_requirements")
    @classmethod
    def _requirements(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(value.strip() for value in values)
        if (
            any(_IDENTIFIER.fullmatch(value) is None for value in normalized)
            or len(normalized) != len(set(normalized))
        ):
            raise ValueError("evidence requirements are invalid")
        return normalized


class RuleCandidateDraft(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    summary_id: UUID
    proposed_rule: str = Field(min_length=1, max_length=10_000)
    recurrence_assessment: str = Field(min_length=1, max_length=2_000)
    severity_assessment: str = Field(min_length=1, max_length=100)
    false_positive_risks: tuple[str, ...] = Field(default=(), max_length=100)
    review_rule: ReviewRuleDefinition

    @field_validator(
        "proposed_rule",
        "recurrence_assessment",
        "severity_assessment",
    )
    @classmethod
    def _text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("candidate text must not be blank")
        return normalized

    @field_validator("false_positive_risks")
    @classmethod
    def _risks(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(value.strip() for value in values)
        if (
            any(not value or len(value) > 500 for value in normalized)
            or len(normalized) != len(set(normalized))
        ):
            raise ValueError("false-positive risks are invalid")
        return normalized


@dataclass(frozen=True, slots=True)
class CitedSummaryResult:
    task_id: UUID
    summary_id: UUID
    cited_evidence_ids: tuple[UUID, ...]
    source_hashes: tuple[str, ...]
    authority: str = NON_AUTHORITATIVE
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class RuleCandidateResult:
    task_id: UUID
    candidate_id: UUID
    summary_id: UUID
    cited_evidence_ids: tuple[UUID, ...]
    status: RuleCandidateStatus
    authority: str = NON_AUTHORITATIVE
    replayed: bool = False


class CandidateLearningService:
    """Persist learning outputs without granting them workflow authority."""

    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._factory = factory
        self._store = artifact_store
        self._clock = clock or (lambda: datetime.now(UTC))

    def create_summary(
        self,
        task_id: UUID,
        *,
        summary_id: UUID,
        draft: CitedSummaryDraft,
        actor_id: str,
    ) -> CitedSummaryResult:
        actor = _identifier(actor_id, "learning actor")
        now = normalize_evidence_timestamp(self._clock())
        try:
            with self._factory.begin() as session:
                task = _task(session, task_id)
                existing = session.get(EvidenceDerivative, summary_id)
                if existing is not None:
                    return _replayed_summary(
                        session,
                        self._store,
                        task,
                        existing,
                        draft,
                    )
                records = _citation_records(
                    session,
                    self._store,
                    task,
                    draft.cited_evidence_ids,
                )
                source_hashes = tuple(record.content_hash for record in records)
                payload = _summary_payload(task.id, draft, source_hashes)
                register_evidence_derivative(
                    session,
                    self._store,
                    evidence_id=records[0].id,
                    derivative_type=DERIVED_SUMMARY_TYPE,
                    payload=payload,
                    media_type="application/json",
                    actor_id=actor,
                    derivative_id=summary_id,
                    captured_at=now,
                )
                return CitedSummaryResult(
                    task.id,
                    summary_id,
                    draft.cited_evidence_ids,
                    source_hashes,
                )
        except IntegrityError:
            raise CandidateLearningError("LEARNING_SUMMARY_CONFLICT") from None

    def create_rule_candidate(
        self,
        task_id: UUID,
        *,
        candidate_id: UUID,
        draft: RuleCandidateDraft,
        actor_id: str,
    ) -> RuleCandidateResult:
        actor = _identifier(actor_id, "learning actor")
        now = normalize_evidence_timestamp(self._clock())
        try:
            with self._factory.begin() as session:
                task = _task(session, task_id)
                summary = session.get(EvidenceDerivative, draft.summary_id)
                citations, _hashes = _validated_summary(
                    session,
                    self._store,
                    task,
                    summary,
                )
                existing = session.get(RuleCandidate, candidate_id)
                if existing is not None:
                    _require_same_candidate(existing, task, draft, citations)
                    return RuleCandidateResult(
                        task.id,
                        existing.id,
                        draft.summary_id,
                        citations,
                        RuleCandidateStatus(existing.status),
                        replayed=True,
                    )
                evaluation = {
                    "passed": True,
                    "review_rule": draft.review_rule.model_dump(mode="json"),
                }
                candidate = RuleCandidate(
                    id=candidate_id,
                    task_id=task.id,
                    proposed_rule=draft.proposed_rule,
                    cited_evidence_ids=[str(value) for value in citations],
                    recurrence_assessment=draft.recurrence_assessment,
                    severity_assessment=draft.severity_assessment,
                    false_positive_risks=list(draft.false_positive_risks),
                    evaluation_result=evaluation,
                    status=RuleCandidateStatus.EVALUATED,
                    owner_id=task.owner_id,
                    actor_id=actor,
                    root_correlation_id=task.root_correlation_id,
                    causation_id=draft.summary_id,
                    parent_correlation_id=draft.summary_id,
                    created_at=now,
                    updated_at=now,
                )
                session.add(candidate)
                session.flush()
                return RuleCandidateResult(
                    task.id,
                    candidate.id,
                    draft.summary_id,
                    citations,
                    RuleCandidateStatus.EVALUATED,
                )
        except IntegrityError:
            raise CandidateLearningError("RULE_CANDIDATE_CONFLICT") from None


def _task(session: Session, task_id: UUID) -> Task:
    task = session.get(Task, task_id)
    if task is None or task.owner_id != "local-user":
        raise CandidateLearningError("LEARNING_TASK_UNAVAILABLE")
    return task


def _citation_records(
    session: Session,
    store: ArtifactStore,
    task: Task,
    evidence_ids: Sequence[UUID],
) -> tuple[EvidenceRecord, ...]:
    records = tuple(
        session.scalars(
            select(EvidenceRecord).where(EvidenceRecord.id.in_(evidence_ids))
        )
    )
    by_id = {record.id: record for record in records}
    corrected = set(
        session.scalars(
            select(EvidenceRecord.correction_of_id).where(
                EvidenceRecord.correction_of_id.in_(evidence_ids)
            )
        )
    )
    deletion_requested = set(
        session.scalars(
            select(EvidenceDeletionRequest.evidence_id).where(
                EvidenceDeletionRequest.evidence_id.in_(evidence_ids)
            )
        )
    )
    ordered: list[EvidenceRecord] = []
    for evidence_id in evidence_ids:
        record = by_id.get(evidence_id)
        if (
            record is None
            or record.task_id != task.id
            or record.owner_id != task.owner_id
            or record.root_correlation_id != task.root_correlation_id
            or record.deleted_at is not None
            or record.id in corrected
            or record.id in deletion_requested
        ):
            raise CandidateLearningError("LEARNING_CITATION_UNAVAILABLE")
        try:
            load_evidence(session, store, record)
        except EvidenceError:
            raise CandidateLearningError("LEARNING_CITATION_UNAVAILABLE") from None
        ordered.append(record)
    return tuple(ordered)


def _summary_payload(
    task_id: UUID,
    draft: CitedSummaryDraft,
    source_hashes: Sequence[str],
) -> dict[str, object]:
    identity = {
        "schema_version": CANDIDATE_LEARNING_SCHEMA_VERSION,
        "authority": NON_AUTHORITATIVE,
        "task_id": str(task_id),
        "summary": draft.summary,
        "citations": [
            {"evidence_id": str(evidence_id), "source_hash": source_hash}
            for evidence_id, source_hash in zip(
                draft.cited_evidence_ids,
                source_hashes,
                strict=True,
            )
        ],
    }
    return {**identity, "summary_fingerprint": _fingerprint(identity)}


def _validated_summary(
    session: Session,
    store: ArtifactStore,
    task: Task,
    summary: EvidenceDerivative | None,
) -> tuple[tuple[UUID, ...], tuple[str, ...]]:
    if summary is None or summary.derivative_type != DERIVED_SUMMARY_TYPE:
        raise CandidateLearningError("LEARNING_SUMMARY_UNAVAILABLE")
    try:
        content = load_evidence_derivative(session, store, summary).content
    except EvidenceError:
        raise CandidateLearningError("LEARNING_SUMMARY_UNAVAILABLE") from None
    if not isinstance(content, dict):
        raise CandidateLearningError("LEARNING_SUMMARY_INVALID")
    citations = content.get("citations")
    if (
        set(content)
        != {
            "schema_version",
            "authority",
            "task_id",
            "summary",
            "citations",
            "summary_fingerprint",
        }
        or content.get("schema_version") != CANDIDATE_LEARNING_SCHEMA_VERSION
        or content.get("authority") != NON_AUTHORITATIVE
        or content.get("task_id") != str(task.id)
        or not isinstance(content.get("summary"), str)
        or not isinstance(citations, list)
        or not citations
        or len(citations) > MAX_CITATIONS
    ):
        raise CandidateLearningError("LEARNING_SUMMARY_INVALID")
    ids: list[UUID] = []
    hashes: list[str] = []
    try:
        for item in citations:
            if not isinstance(item, dict) or set(item) != {"evidence_id", "source_hash"}:
                raise ValueError
            ids.append(UUID(cast(str, item.get("evidence_id"))))
            hashes.append(cast(str, item.get("source_hash")))
    except (TypeError, ValueError):
        raise CandidateLearningError("LEARNING_SUMMARY_INVALID") from None
    records = _citation_records(session, store, task, ids)
    current_hashes = tuple(record.content_hash for record in records)
    identity = {key: value for key, value in content.items() if key != "summary_fingerprint"}
    if (
        tuple(hashes) != current_hashes
        or content.get("summary_fingerprint") != _fingerprint(identity)
    ):
        raise CandidateLearningError("LEARNING_SUMMARY_STALE")
    return tuple(ids), current_hashes


def _replayed_summary(
    session: Session,
    store: ArtifactStore,
    task: Task,
    summary: EvidenceDerivative,
    draft: CitedSummaryDraft,
) -> CitedSummaryResult:
    citations, hashes = _validated_summary(session, store, task, summary)
    loaded = load_evidence_derivative(session, store, summary).content
    if (
        citations != draft.cited_evidence_ids
        or not isinstance(loaded, dict)
        or loaded.get("summary") != draft.summary
    ):
        raise CandidateLearningError("LEARNING_SUMMARY_CONFLICT")
    return CitedSummaryResult(
        task.id,
        summary.id,
        citations,
        hashes,
        replayed=True,
    )


def _require_same_candidate(
    candidate: RuleCandidate,
    task: Task,
    draft: RuleCandidateDraft,
    citations: Sequence[UUID],
) -> None:
    expected_evaluation = {
        "passed": True,
        "review_rule": draft.review_rule.model_dump(mode="json"),
    }
    if (
        candidate.task_id != task.id
        or candidate.owner_id != task.owner_id
        or candidate.parent_correlation_id != draft.summary_id
        or candidate.proposed_rule != draft.proposed_rule
        or candidate.cited_evidence_ids != [str(value) for value in citations]
        or candidate.recurrence_assessment != draft.recurrence_assessment
        or candidate.severity_assessment != draft.severity_assessment
        or candidate.false_positive_risks != list(draft.false_positive_risks)
        or candidate.evaluation_result != expected_evaluation
        or candidate.status is not RuleCandidateStatus.EVALUATED
    ):
        raise CandidateLearningError("RULE_CANDIDATE_CONFLICT")


def _validate_json(value: object, *, depth: int = 0) -> None:
    if depth > 10:
        raise ValueError("rule JSON is too deep")
    if value is None or isinstance(value, str | bool | int):
        return
    if isinstance(value, float):
        if value != value or value in {float("inf"), float("-inf")}:
            raise ValueError("rule JSON is invalid")
        return
    if isinstance(value, list):
        if len(value) > 100:
            raise ValueError("rule JSON is too large")
        for item in value:
            _validate_json(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if not value or len(value) > 100:
            raise ValueError("rule JSON is invalid")
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 255:
                raise ValueError("rule JSON key is invalid")
            _validate_json(item, depth=depth + 1)
        return
    raise ValueError("rule JSON is invalid")


def _identifier(value: str, field: str) -> str:
    normalized = value.strip()
    if _IDENTIFIER.fullmatch(normalized) is None:
        raise CandidateLearningError(f"{field} is invalid")
    return normalized


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
        raise CandidateLearningError("LEARNING_PAYLOAD_INVALID") from None
    return hashlib.sha256(encoded).hexdigest()
