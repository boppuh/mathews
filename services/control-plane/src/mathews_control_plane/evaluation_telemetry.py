"""Version-bound, reproducible evaluation telemetry for agent runs."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    AgentRunEvaluation,
    EvaluationContractVersion,
    HermesRun,
    HermesRunStatus,
    PolicyActivation,
    PolicyVersion,
    PromptTemplateVersion,
    RetrievalIndexChunk,
    RetrievalIndexGeneration,
)
from mathews_control_plane.evidence import normalize_evidence_timestamp
from mathews_control_plane.policy_activation import lock_policy_promotion
from mathews_control_plane.principals import LOCAL_OWNER_ID
from mathews_control_plane.retrieval_index import RetrievalSearchResult

Clock = Callable[[], datetime]
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}\Z")


class EvaluationTelemetryError(RuntimeError):
    """Base class for safe evaluation telemetry failures."""


class EvaluationTelemetryValidationError(EvaluationTelemetryError):
    """Raised when telemetry is incomplete or conflicts with frozen versions."""


class QualityOutcome(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class AgentRunMetrics:
    model_provider: str
    model_name: str
    model_version: str
    input_tokens: int
    output_tokens: int
    cached_tokens: int
    cost_microusd: int
    quality_outcome: QualityOutcome
    quality_score: float
    regression_results: Mapping[str, bool]


@dataclass(frozen=True, slots=True)
class EvaluationComparison:
    prompt_template_version_id: UUID
    prompt_template_version: int
    retrieval_index_version: str
    retrieval_chunker_version: str
    retrieval_verifier_version: str
    model_provider: str
    model_name: str
    model_version: str
    run_count: int
    average_quality_score: float
    average_cost_microusd: float
    regression_pass_rate: float
    promotion_eligible: bool


class EvaluationTelemetryService:
    """Persist exact run inputs and compare only like-for-like contract results."""

    def __init__(self, factory: SessionFactory, *, clock: Clock | None = None) -> None:
        self._factory = factory
        self._clock = clock or (lambda: datetime.now(UTC))

    def create_contract_version(
        self,
        *,
        lineage_key: str,
        promotion_thresholds: Mapping[str, object],
        regression_cases: Sequence[str],
        actor_id: str,
        activate: bool = False,
    ) -> EvaluationContractVersion:
        lineage = _identifier(lineage_key, "evaluation lineage")
        actor = _identifier(actor_id, "evaluation actor")
        thresholds = _thresholds(promotion_thresholds)
        cases = _regression_cases(regression_cases)
        now = normalize_evidence_timestamp(self._clock())
        fingerprint = _fingerprint({"thresholds": thresholds, "cases": cases})
        with self._factory.begin() as session:
            latest = session.scalar(
                select(EvaluationContractVersion)
                .where(EvaluationContractVersion.lineage_key == lineage)
                .order_by(EvaluationContractVersion.version.desc())
                .limit(1)
                .with_for_update()
            )
            if latest is not None and latest.contract_fingerprint == fingerprint:
                return latest
            if activate:
                active = session.scalar(
                    select(EvaluationContractVersion)
                    .where(
                        EvaluationContractVersion.lineage_key == lineage,
                        EvaluationContractVersion.active.is_(True),
                    )
                    .with_for_update()
                )
                if active is not None:
                    active.active = False
            contract = EvaluationContractVersion(
                lineage_key=lineage,
                version=1 if latest is None else latest.version + 1,
                predecessor_id=None if latest is None else latest.id,
                promotion_thresholds=thresholds,
                regression_cases=list(cases),
                contract_fingerprint=fingerprint,
                active=activate,
                activated_at=now if activate else None,
                owner_id=LOCAL_OWNER_ID,
                actor_id=actor,
                root_correlation_id=(latest.root_correlation_id if latest else uuid4()),
                causation_id=None if latest is None else latest.id,
            )
            session.add(contract)
            session.flush()
            session.expunge(contract)
            return contract

    def record(
        self,
        *,
        run_id: UUID,
        contract_id: UUID,
        retrieval: RetrievalSearchResult,
        metrics: AgentRunMetrics,
        actor_id: str,
    ) -> AgentRunEvaluation:
        actor = _identifier(actor_id, "evaluation actor")
        now = normalize_evidence_timestamp(self._clock())
        with self._factory.begin() as session:
            run = session.get(HermesRun, run_id)
            contract = session.get(EvaluationContractVersion, contract_id)
            generation = (
                None
                if retrieval.generation_id is None
                else session.get(RetrievalIndexGeneration, retrieval.generation_id)
            )
            if (
                run is None
                or run.status not in {HermesRunStatus.SUCCEEDED, HermesRunStatus.FAILED}
                or contract is None
                or generation is None
                or generation.task_id != run.task_id
                or retrieval.task_id != run.task_id
                or retrieval.index_version != generation.index_version
            ):
                raise EvaluationTelemetryValidationError("evaluation version binding is invalid")
            prompt = session.get(PromptTemplateVersion, run.prompt_template_version_id)
            policy = session.get(PolicyVersion, run.policy_version_id)
            if prompt is None or policy is None:
                raise EvaluationTelemetryValidationError("evaluation prompt binding is invalid")
            lock_policy_promotion(session, policy.lineage_key)
            normalized_metrics = _metrics(metrics, contract)
            retrieval_set = _retrieval_set(session, retrieval, generation)
            payload = {
                "run_id": str(run.id),
                "task_id": str(run.task_id),
                "contract_id": str(contract.id),
                "contract_fingerprint": contract.contract_fingerprint,
                "retrieval_generation_id": str(generation.id),
                "retrieval_index_version": generation.index_version,
                "retrieval_chunker_version": generation.chunker_version,
                "retrieval_verifier_version": generation.verifier_version,
                "retrieval_set": retrieval_set,
                "prompt_template_version_id": str(prompt.id),
                "prompt_template_version": prompt.version,
                "policy_version_id": str(policy.id),
                "policy_version": policy.version,
                **normalized_metrics,
            }
            fingerprint = _fingerprint(payload)
            existing = session.scalar(
                select(AgentRunEvaluation).where(AgentRunEvaluation.run_id == run.id)
            )
            if existing is not None:
                if existing.evaluation_fingerprint != fingerprint:
                    raise EvaluationTelemetryValidationError("agent run evaluation conflicts")
                session.expunge(existing)
                return existing
            if (
                session.scalar(
                    select(PolicyActivation.id).where(
                        PolicyActivation.subject_type == "PROMPT_TEMPLATE_VERSION",
                        PolicyActivation.subject_id == prompt.id,
                    )
                )
                is not None
            ):
                raise EvaluationTelemetryValidationError("evaluation group is closed")
            evaluation = AgentRunEvaluation(
                run_id=run.id,
                task_id=run.task_id,
                evaluation_contract_version_id=contract.id,
                retrieval_generation_id=generation.id,
                retrieval_index_version=generation.index_version,
                retrieval_chunker_version=generation.chunker_version,
                retrieval_verifier_version=generation.verifier_version,
                retrieval_set=retrieval_set,
                prompt_template_version_id=prompt.id,
                prompt_template_version=prompt.version,
                policy_version_id=policy.id,
                policy_version=policy.version,
                evaluation_fingerprint=fingerprint,
                evaluated_at=now,
                owner_id=run.owner_id,
                actor_id=actor,
                root_correlation_id=run.root_correlation_id,
                causation_id=run.id,
                parent_correlation_id=run.job_id,
                **normalized_metrics,
            )
            session.add(evaluation)
            session.flush()
            session.expunge(evaluation)
            return evaluation

    def compare(self, contract_id: UUID) -> tuple[EvaluationComparison, ...]:
        with self._factory() as session:
            contract = session.get(EvaluationContractVersion, contract_id)
            if contract is None:
                raise EvaluationTelemetryValidationError("evaluation contract is unavailable")
            rows = tuple(
                session.scalars(
                    select(AgentRunEvaluation).where(
                        AgentRunEvaluation.evaluation_contract_version_id == contract.id
                    )
                )
            )
        thresholds = _thresholds(contract.promotion_thresholds)
        groups: dict[tuple[object, ...], list[AgentRunEvaluation]] = defaultdict(list)
        for row in rows:
            groups[
                (
                    row.prompt_template_version_id,
                    row.prompt_template_version,
                    row.retrieval_index_version,
                    row.retrieval_chunker_version,
                    row.retrieval_verifier_version,
                    row.model_provider,
                    row.model_name,
                    row.model_version,
                )
            ].append(row)
        comparisons: list[EvaluationComparison] = []
        for key, items in groups.items():
            (
                prompt_id,
                prompt_version,
                index_version,
                chunker_version,
                verifier_version,
                model_provider,
                model_name,
                model_version,
            ) = key
            quality = sum(item.quality_score for item in items) / len(items)
            cost = sum(item.cost_microusd for item in items) / len(items)
            regression_values = [
                bool(value) for item in items for value in item.regression_results.values()
            ]
            regression_rate = (
                sum(regression_values) / len(regression_values) if regression_values else 1.0
            )
            comparisons.append(
                EvaluationComparison(
                    prompt_template_version_id=UUID(str(prompt_id)),
                    prompt_template_version=int(str(prompt_version)),
                    retrieval_index_version=str(index_version),
                    retrieval_chunker_version=str(chunker_version),
                    retrieval_verifier_version=str(verifier_version),
                    model_provider=str(model_provider),
                    model_name=str(model_name),
                    model_version=str(model_version),
                    run_count=len(items),
                    average_quality_score=quality,
                    average_cost_microusd=cost,
                    regression_pass_rate=regression_rate,
                    promotion_eligible=(
                        len(items) >= thresholds["minimum_run_count"]
                        and quality >= thresholds["minimum_quality_score"]
                        and cost <= thresholds["maximum_average_cost_microusd"]
                        and regression_rate >= thresholds["minimum_regression_pass_rate"]
                    ),
                )
            )
        return tuple(
            sorted(
                comparisons,
                key=lambda item: (
                    str(item.prompt_template_version_id),
                    item.retrieval_index_version,
                    item.retrieval_chunker_version,
                    item.retrieval_verifier_version,
                    item.model_provider,
                    item.model_name,
                    item.model_version,
                ),
            )
        )


def _metrics(metrics: AgentRunMetrics, contract: EvaluationContractVersion) -> dict[str, object]:
    values = (
        metrics.input_tokens,
        metrics.output_tokens,
        metrics.cached_tokens,
        metrics.cost_microusd,
    )
    if (
        any(value < 0 for value in values)
        or metrics.cached_tokens > metrics.input_tokens
        or not 0 <= metrics.quality_score <= 1
    ):
        raise EvaluationTelemetryValidationError("evaluation metrics are invalid")
    cases = set(_regression_cases(tuple(str(item) for item in contract.regression_cases)))
    if set(metrics.regression_results) != cases or any(
        not isinstance(value, bool) for value in metrics.regression_results.values()
    ):
        raise EvaluationTelemetryValidationError("regression results are incomplete")
    return {
        "model_provider": _identifier(metrics.model_provider, "model provider"),
        "model_name": _identifier(metrics.model_name, "model name"),
        "model_version": _identifier(metrics.model_version, "model version"),
        "input_tokens": metrics.input_tokens,
        "output_tokens": metrics.output_tokens,
        "cached_tokens": metrics.cached_tokens,
        "total_tokens": metrics.input_tokens + metrics.output_tokens,
        "cost_microusd": metrics.cost_microusd,
        "quality_outcome": metrics.quality_outcome.value,
        "quality_score": metrics.quality_score,
        "regression_results": dict(sorted(metrics.regression_results.items())),
    }


def _retrieval_set(
    session: Session,
    retrieval: RetrievalSearchResult,
    generation: RetrievalIndexGeneration,
) -> list[object]:
    items: list[object] = []
    for position, hit in enumerate(retrieval.hits, 1):
        if (
            hit.generation_id != generation.id
            or hit.index_version != generation.index_version
            or hit.chunker_version != generation.chunker_version
            or hit.verifier_version != generation.verifier_version
        ):
            raise EvaluationTelemetryValidationError("retrieval set versions conflict")
        chunk = session.scalar(
            select(RetrievalIndexChunk).where(
                RetrievalIndexChunk.generation_id == generation.id,
                RetrievalIndexChunk.derivative_id == hit.derivative_id,
            )
        )
        if (
            chunk is None
            or chunk.task_id != retrieval.task_id
            or chunk.evidence_id != hit.evidence_id
            or chunk.source_hash != hit.source_hash
            or chunk.source_envelope_hash != hit.source_envelope_hash
            or chunk.chunk_hash != hit.chunk_hash
            or chunk.ordinal != hit.ordinal
        ):
            raise EvaluationTelemetryValidationError("retrieval set source binding is invalid")
        items.append(
            {
                "position": position,
                "evidence_id": str(hit.evidence_id),
                "derivative_id": str(hit.derivative_id),
                "source_hash": hit.source_hash,
                "source_envelope_hash": hit.source_envelope_hash,
                "chunk_hash": hit.chunk_hash,
                "ordinal": hit.ordinal,
                "score": hit.score,
            }
        )
    return items


def _thresholds(value: Mapping[str, object]) -> dict[str, int | float]:
    keys = {
        "minimum_run_count",
        "minimum_quality_score",
        "maximum_average_cost_microusd",
        "minimum_regression_pass_rate",
    }
    if set(value) != keys:
        raise EvaluationTelemetryValidationError("evaluation thresholds are invalid")
    run_count = value["minimum_run_count"]
    quality = value["minimum_quality_score"]
    cost = value["maximum_average_cost_microusd"]
    regression = value["minimum_regression_pass_rate"]
    if (
        not isinstance(run_count, int)
        or isinstance(run_count, bool)
        or run_count < 1
        or not isinstance(cost, int)
        or isinstance(cost, bool)
        or cost < 0
        or not isinstance(quality, int | float)
        or isinstance(quality, bool)
        or not 0 <= float(quality) <= 1
        or not isinstance(regression, int | float)
        or isinstance(regression, bool)
        or not 0 <= float(regression) <= 1
    ):
        raise EvaluationTelemetryValidationError("evaluation thresholds are invalid")
    return {
        "minimum_run_count": run_count,
        "minimum_quality_score": float(quality),
        "maximum_average_cost_microusd": cost,
        "minimum_regression_pass_rate": float(regression),
    }


def _regression_cases(values: Sequence[str]) -> tuple[str, ...]:
    cases = tuple(_identifier(value, "regression case") for value in values)
    if not cases or len(cases) > 100 or len(set(cases)) != len(cases):
        raise EvaluationTelemetryValidationError("regression cases are invalid")
    return cases


def _identifier(value: str, field: str) -> str:
    normalized = value.strip()
    if not _IDENTIFIER.fullmatch(normalized):
        raise EvaluationTelemetryValidationError(f"{field} is invalid")
    return normalized


def _fingerprint(value: Mapping[str, object]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()
