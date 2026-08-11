"""Cited, non-authoritative summaries and non-executable rule candidates."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.authentication import (
    AuthenticatedSession,
    require_authenticated_session,
)
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    EvidenceDerivative,
    EvidenceDerivativeCitation,
    EvidenceRecord,
    RuleCandidate,
    RuleCandidateCitation,
    RuleCandidateStatus,
    Task,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceError,
    invalidated_evidence_ids,
    load_evidence,
    load_evidence_derivative,
    normalize_evidence_timestamp,
    redact_evidence_content,
    register_evidence_derivative,
)
from mathews_control_plane.principals import LOCAL_OWNER_ID
from mathews_control_plane.review_rule_contract import executable_review_rule

CANDIDATE_LEARNING_SCHEMA_VERSION = 1
DERIVED_SUMMARY_TYPE = "candidate-learning-summary-v1"
NON_AUTHORITATIVE = "NON_AUTHORITATIVE"
MAX_CITATIONS = 100
MAX_RULE_DEFINITION_BYTES = 64 * 1024
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}\Z")
AuthenticatedLearningSession = Annotated[
    AuthenticatedSession,
    Depends(require_authenticated_session),
]


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

    @model_validator(mode="after")
    def _executable(self) -> ReviewRuleDefinition:
        if len(
            json.dumps(
                {"matcher": self.matcher, "scope": self.scope},
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ) > MAX_RULE_DEFINITION_BYTES:
            raise ValueError("review rule definition is too large")
        executable_review_rule(
            scope=self.scope,
            matcher=self.matcher,
            risk_class=self.risk_class.value,
            evidence_requirements=self.evidence_requirements,
        )
        return self


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


class CreateCitedSummaryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    summary_id: UUID
    draft: CitedSummaryDraft


class CreateRuleCandidateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    candidate_id: UUID
    draft: RuleCandidateDraft


class CitedSummaryResponse(BaseModel):
    task_id: UUID
    summary_id: UUID
    cited_evidence_ids: tuple[UUID, ...]
    source_hashes: tuple[str, ...]
    authority: Literal["NON_AUTHORITATIVE"]
    replayed: bool


class RuleCandidateResponse(BaseModel):
    task_id: UUID
    candidate_id: UUID
    summary_id: UUID
    cited_evidence_ids: tuple[UUID, ...]
    status: RuleCandidateStatus
    authority: Literal["NON_AUTHORITATIVE"]
    replayed: bool


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
        artifact_addresses: list[str] = []
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
                derivative = register_evidence_derivative(
                    session,
                    self._store,
                    evidence_id=records[0].id,
                    derivative_type=DERIVED_SUMMARY_TYPE,
                    payload=payload,
                    media_type="application/json",
                    actor_id=actor,
                    derivative_id=summary_id,
                    captured_at=now,
                    artifact_observer=artifact_addresses.append,
                )
                session.add_all(
                    EvidenceDerivativeCitation(
                        derivative_id=derivative.id,
                        evidence_id=record.id,
                        source_hash=record.content_hash,
                        owner_id=task.owner_id,
                        actor_id=actor,
                        root_correlation_id=task.root_correlation_id,
                        causation_id=derivative.id,
                        parent_correlation_id=record.id,
                        created_at=now,
                        updated_at=now,
                    )
                    for record in records
                )
                session.flush()
                return CitedSummaryResult(
                    task.id,
                    summary_id,
                    draft.cited_evidence_ids,
                    source_hashes,
                )
        except IntegrityError:
            self._delete_unreferenced_artifact(
                artifact_addresses[-1] if artifact_addresses else None
            )
            raise CandidateLearningError("LEARNING_SUMMARY_CONFLICT") from None
        except SQLAlchemyError:
            self._delete_unreferenced_artifact(
                artifact_addresses[-1] if artifact_addresses else None
            )
            raise CandidateLearningError("LEARNING_SUMMARY_PERSISTENCE_FAILED") from None

    def _delete_unreferenced_artifact(self, address: str | None) -> None:
        if address is None:
            return
        with self._factory() as session:
            referenced = session.scalar(
                select(EvidenceDerivative.id)
                .where(
                    EvidenceDerivative.content_address == address,
                    EvidenceDerivative.deleted_at.is_(None),
                )
                .limit(1)
            )
        if referenced is None:
            self._store.delete_bytes(address)

    def create_rule_candidate(
        self,
        task_id: UUID,
        *,
        candidate_id: UUID,
        draft: RuleCandidateDraft,
        actor_id: str,
    ) -> RuleCandidateResult:
        actor = _identifier(actor_id, "learning actor")
        normalized_draft = _redacted_candidate_draft(draft)
        now = normalize_evidence_timestamp(self._clock())
        try:
            with self._factory.begin() as session:
                task = _task(session, task_id)
                summary = session.get(EvidenceDerivative, normalized_draft.summary_id)
                citations, source_hashes, _summary_content = _validated_summary(
                    session,
                    self._store,
                    task,
                    summary,
                )
                existing = session.get(RuleCandidate, candidate_id)
                if existing is not None:
                    _require_same_candidate(existing, task, normalized_draft, citations)
                    return RuleCandidateResult(
                        task.id,
                        existing.id,
                        normalized_draft.summary_id,
                        citations,
                        RuleCandidateStatus(existing.status),
                        replayed=True,
                    )
                evaluation = {
                    "passed": True,
                    "review_rule": normalized_draft.review_rule.model_dump(mode="json"),
                }
                candidate = RuleCandidate(
                    id=candidate_id,
                    task_id=task.id,
                    proposed_rule=normalized_draft.proposed_rule,
                    cited_evidence_ids=[str(value) for value in citations],
                    recurrence_assessment=normalized_draft.recurrence_assessment,
                    severity_assessment=normalized_draft.severity_assessment,
                    false_positive_risks=list(normalized_draft.false_positive_risks),
                    evaluation_result=evaluation,
                    status=RuleCandidateStatus.EVALUATED,
                    owner_id=task.owner_id,
                    actor_id=actor,
                    root_correlation_id=task.root_correlation_id,
                    causation_id=normalized_draft.summary_id,
                    parent_correlation_id=normalized_draft.summary_id,
                    created_at=now,
                    updated_at=now,
                )
                session.add(candidate)
                session.flush()
                session.add_all(
                    RuleCandidateCitation(
                        candidate_id=candidate.id,
                        evidence_id=evidence_id,
                        source_hash=source_hash,
                        owner_id=task.owner_id,
                        actor_id=actor,
                        root_correlation_id=task.root_correlation_id,
                        causation_id=candidate.id,
                        parent_correlation_id=evidence_id,
                        created_at=now,
                        updated_at=now,
                    )
                    for evidence_id, source_hash in zip(
                        citations,
                        source_hashes,
                        strict=True,
                    )
                )
                session.flush()
                return RuleCandidateResult(
                    task.id,
                    candidate.id,
                    normalized_draft.summary_id,
                    citations,
                    RuleCandidateStatus.EVALUATED,
                )
        except IntegrityError:
            try:
                with self._factory() as session:
                    task = _task(session, task_id)
                    summary = session.get(
                        EvidenceDerivative,
                        normalized_draft.summary_id,
                    )
                    citations, _hashes, _content = _validated_summary(
                        session,
                        self._store,
                        task,
                        summary,
                    )
                    existing = session.get(RuleCandidate, candidate_id)
                    if existing is None:
                        raise CandidateLearningError("RULE_CANDIDATE_CONFLICT")
                    _require_same_candidate(
                        existing,
                        task,
                        normalized_draft,
                        citations,
                    )
                    return RuleCandidateResult(
                        task.id,
                        existing.id,
                        normalized_draft.summary_id,
                        citations,
                        RuleCandidateStatus(existing.status),
                        replayed=True,
                    )
            except CandidateLearningError:
                raise CandidateLearningError("RULE_CANDIDATE_CONFLICT") from None


def _task(session: Session, task_id: UUID) -> Task:
    task = session.get(Task, task_id)
    if task is None or task.owner_id != LOCAL_OWNER_ID:
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
            select(EvidenceRecord)
            .where(EvidenceRecord.id.in_(evidence_ids))
            .with_for_update()
        )
    )
    by_id = {record.id: record for record in records}
    invalidated_ids = invalidated_evidence_ids(session, evidence_ids)
    ordered: list[EvidenceRecord] = []
    for evidence_id in evidence_ids:
        record = by_id.get(evidence_id)
        if (
            record is None
            or record.task_id != task.id
            or record.owner_id != task.owner_id
            or record.root_correlation_id != task.root_correlation_id
            or record.deleted_at is not None
            or record.access_classification
            not in {
                EvidenceAccessClass.TASK_OWNER.value,
                EvidenceAccessClass.OWNER.value,
            }
            or record.id in invalidated_ids
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
    raw_identity = {
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
    redacted = redact_evidence_content(
        raw_identity,
        media_type="application/json",
    ).value
    if not isinstance(redacted, dict):
        raise CandidateLearningError("LEARNING_PAYLOAD_INVALID")
    identity = cast(dict[str, object], redacted)
    return {**identity, "summary_fingerprint": _fingerprint(identity)}


def _validated_summary(
    session: Session,
    store: ArtifactStore,
    task: Task,
    summary: EvidenceDerivative | None,
) -> tuple[tuple[UUID, ...], tuple[str, ...], dict[str, object]]:
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
    lineage = tuple(
        session.scalars(
            select(EvidenceDerivativeCitation)
            .where(EvidenceDerivativeCitation.derivative_id == summary.id)
            .order_by(EvidenceDerivativeCitation.created_at, EvidenceDerivativeCitation.id)
        )
    )
    lineage_hashes = {
        item.evidence_id: item.source_hash
        for item in lineage
    }
    identity = {key: value for key, value in content.items() if key != "summary_fingerprint"}
    if (
        tuple(hashes) != current_hashes
        or lineage_hashes
        != dict(zip(ids, current_hashes, strict=True))
        or content.get("summary_fingerprint") != _fingerprint(identity)
    ):
        raise CandidateLearningError("LEARNING_SUMMARY_STALE")
    return tuple(ids), current_hashes, cast(dict[str, object], content)


def _replayed_summary(
    session: Session,
    store: ArtifactStore,
    task: Task,
    summary: EvidenceDerivative,
    draft: CitedSummaryDraft,
) -> CitedSummaryResult:
    citations, hashes, loaded = _validated_summary(session, store, task, summary)
    expected = _summary_payload(task.id, draft, hashes)
    if citations != draft.cited_evidence_ids or loaded != expected:
        raise CandidateLearningError("LEARNING_SUMMARY_CONFLICT")
    return CitedSummaryResult(
        task.id,
        summary.id,
        citations,
        hashes,
        replayed=True,
    )


def _redacted_candidate_draft(draft: RuleCandidateDraft) -> RuleCandidateDraft:
    raw = draft.model_dump(mode="json")
    redacted = redact_evidence_content(raw, media_type="application/json").value
    try:
        return RuleCandidateDraft.model_validate(redacted)
    except (TypeError, ValueError):
        raise CandidateLearningError("RULE_CANDIDATE_REDACTION_INVALID") from None


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
        or candidate.status
        not in {
            RuleCandidateStatus.EVALUATED,
            RuleCandidateStatus.APPROVED,
            RuleCandidateStatus.REJECTED,
        }
    ):
        raise CandidateLearningError("RULE_CANDIDATE_CONFLICT")


def _validate_json(value: object, *, depth: int = 0) -> None:
    if depth > 10:
        raise ValueError("rule JSON is too deep")
    if isinstance(value, str):
        if len(value) > 2_000:
            raise ValueError("rule JSON string is too large")
        return
    if value is None or isinstance(value, bool | int):
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


def create_candidate_learning_router(service: CandidateLearningService) -> APIRouter:
    """Expose authenticated non-authoritative learning ingestion."""

    router = APIRouter(prefix="/api/tasks", tags=["candidate-learning"])

    @router.post(
        "/{task_id}/learning-summaries",
        response_model=CitedSummaryResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def create_summary(
        task_id: UUID,
        body: CreateCitedSummaryRequest,
        _authentication: AuthenticatedLearningSession,
        response: Response,
    ) -> CitedSummaryResponse:
        response.headers["Cache-Control"] = "no-store"
        try:
            result = service.create_summary(
                task_id,
                summary_id=body.summary_id,
                draft=body.draft,
                actor_id="candidate-learning-api",
            )
        except CandidateLearningError:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="candidate learning conflicts with durable evidence",
            ) from None
        return CitedSummaryResponse.model_validate(asdict(result))

    @router.post(
        "/{task_id}/rule-candidates",
        response_model=RuleCandidateResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def create_candidate(
        task_id: UUID,
        body: CreateRuleCandidateRequest,
        _authentication: AuthenticatedLearningSession,
        response: Response,
    ) -> RuleCandidateResponse:
        response.headers["Cache-Control"] = "no-store"
        try:
            result = service.create_rule_candidate(
                task_id,
                candidate_id=body.candidate_id,
                draft=body.draft,
                actor_id="candidate-learning-api",
            )
        except CandidateLearningError:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="candidate learning conflicts with durable evidence",
            ) from None
        return RuleCandidateResponse.model_validate(asdict(result))

    return router
