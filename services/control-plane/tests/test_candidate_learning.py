from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.candidate_learning import (
    NON_AUTHORITATIVE,
    CandidateLearningError,
    CandidateLearningService,
    CandidateRisk,
    CitedSummaryDraft,
    ReviewRuleDefinition,
    RuleCandidateDraft,
)
from mathews_control_plane.database import (
    Base,
    SessionFactory,
    create_database_engine,
    create_session_factory,
)
from mathews_control_plane.domain_models import (
    ApprovalRequest,
    EvidenceDerivative,
    EvidenceRecord,
    PolicyVersion,
    PolicyVersionPromptTemplate,
    PolicyVersionReviewRule,
    PromptTemplateVersion,
    ReviewRule,
    RuleCandidate,
    RuleCandidateStatus,
    Task,
    TaskState,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
    load_evidence_derivative,
)
from sqlalchemy import Engine, func, select

_NOW = datetime(2026, 8, 11, 15, 0, tzinfo=UTC)


@dataclass(slots=True)
class LearningHarness:
    engine: Engine
    factory: SessionFactory
    store: ArtifactStore
    task_id: UUID
    source_ids: tuple[UUID, UUID]


@pytest.fixture
def learning_harness(tmp_path: Path) -> Iterator[LearningHarness]:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'learning.sqlite3'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    store = ArtifactStore(tmp_path / "artifacts")
    task_id = uuid4()
    with factory.begin() as session:
        task = Task(
            id=task_id,
            repository="boppuh/mathews",
            base_revision="0" * 40,
            requester="local-user",
            raw_request="evidence://learning",
            summary="Learn only as a candidate",
            state=TaskState.PR_ACTIVE,
            retry_count=0,
            owner_id="local-user",
            actor_id="local-user",
            root_correlation_id=task_id,
            causation_id=task_id,
        )
        session.add(task)
        session.flush()
        first = capture_evidence(
            session,
            store,
            payload={"review": "Formatter failed on Sources/View.swift"},
            media_type="application/json",
            source_kind=EvidenceSourceKind.EXTERNAL_EVENT,
            evidence_type="github-webhook",
            origin="github:webhook",
            access_classification=EvidenceAccessClass.TASK_OWNER,
            retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
            owner_id=task.owner_id,
            actor_id="github-webhook",
            root_correlation_id=task.root_correlation_id,
            task_id=task.id,
        )
        second = capture_evidence(
            session,
            store,
            payload={"result": "Formatting repair passed validation"},
            media_type="application/json",
            source_kind=EvidenceSourceKind.RESULT,
            evidence_type="validation-decision",
            origin="control-plane:validation",
            access_classification=EvidenceAccessClass.TASK_OWNER,
            retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
            owner_id=task.owner_id,
            actor_id="control-plane",
            root_correlation_id=task.root_correlation_id,
            task_id=task.id,
        )
        source_ids = (first.record.id, second.record.id)
    try:
        yield LearningHarness(engine, factory, store, task_id, source_ids)
    finally:
        engine.dispose()


def _service(harness: LearningHarness) -> CandidateLearningService:
    return CandidateLearningService(
        harness.factory,
        harness.store,
        clock=lambda: _NOW,
    )


def _summary(harness: LearningHarness) -> CitedSummaryDraft:
    return CitedSummaryDraft(
        summary="Two cited records show a recurring formatter-only repair.",
        cited_evidence_ids=harness.source_ids,
    )


def _candidate(summary_id: UUID) -> RuleCandidateDraft:
    return RuleCandidateDraft(
        summary_id=summary_id,
        proposed_rule="Allow the deterministic formatter for matching review comments.",
        recurrence_assessment="Confirmed by the review and its passing repair evidence.",
        severity_assessment="LOW",
        false_positive_risks=("A prose match could identify a non-formatting request.",),
        review_rule=ReviewRuleDefinition(
            lineage_key="formatter-review",
            scope={"path_prefixes": ["Sources"], "max_files": 1},
            matcher={"categories": ["formatting"], "required_labels": ["formatter"]},
            permitted_action="repair.format",
            risk_class=CandidateRisk.LOW,
            evidence_requirements=(
                "github-webhook",
                "validation-decision",
            ),
        ),
    )


def test_cited_summary_is_redacted_non_authoritative_and_replayable(
    learning_harness: LearningHarness,
) -> None:
    service = _service(learning_harness)
    summary_id = uuid4()
    draft = _summary(learning_harness)

    created = service.create_summary(
        learning_harness.task_id,
        summary_id=summary_id,
        draft=draft,
        actor_id="candidate-learning",
    )
    replayed = service.create_summary(
        learning_harness.task_id,
        summary_id=summary_id,
        draft=draft,
        actor_id="candidate-learning",
    )

    assert created.authority == NON_AUTHORITATIVE
    assert created.cited_evidence_ids == learning_harness.source_ids
    assert not created.replayed
    assert replayed.replayed
    with learning_harness.factory() as session:
        derivative = session.get(EvidenceDerivative, summary_id)
        assert derivative is not None
        content = load_evidence_derivative(
            session,
            learning_harness.store,
            derivative,
        ).content
    assert isinstance(content, dict)
    assert content["authority"] == NON_AUTHORITATIVE
    citations = cast(list[dict[str, object]], content["citations"])
    assert [item["evidence_id"] for item in citations] == [
        str(value) for value in learning_harness.source_ids
    ]
    assert len(cast(str, content["summary_fingerprint"])) == 64


def test_rule_candidate_cannot_create_authority_or_approval(
    learning_harness: LearningHarness,
) -> None:
    service = _service(learning_harness)
    summary_id = uuid4()
    candidate_id = uuid4()
    service.create_summary(
        learning_harness.task_id,
        summary_id=summary_id,
        draft=_summary(learning_harness),
        actor_id="candidate-learning",
    )

    created = service.create_rule_candidate(
        learning_harness.task_id,
        candidate_id=candidate_id,
        draft=_candidate(summary_id),
        actor_id="candidate-learning",
    )
    replayed = service.create_rule_candidate(
        learning_harness.task_id,
        candidate_id=candidate_id,
        draft=_candidate(summary_id),
        actor_id="candidate-learning",
    )

    assert created.status is RuleCandidateStatus.EVALUATED
    assert created.authority == NON_AUTHORITATIVE
    assert replayed.replayed
    with learning_harness.factory() as session:
        candidate = session.get(RuleCandidate, candidate_id)
        assert candidate is not None
        assert candidate.parent_correlation_id == summary_id
        assert candidate.cited_evidence_ids == [
            str(value) for value in learning_harness.source_ids
        ]
        assert candidate.evaluation_result is not None
        assert candidate.evaluation_result["passed"] is True
        for model in (
            ApprovalRequest,
            ReviewRule,
            PolicyVersion,
            PromptTemplateVersion,
            PolicyVersionReviewRule,
            PolicyVersionPromptTemplate,
        ):
            assert session.scalar(select(func.count()).select_from(model)) == 0


def test_summary_id_conflict_and_cross_task_citations_fail_closed(
    learning_harness: LearningHarness,
) -> None:
    service = _service(learning_harness)
    summary_id = uuid4()
    service.create_summary(
        learning_harness.task_id,
        summary_id=summary_id,
        draft=_summary(learning_harness),
        actor_id="candidate-learning",
    )

    with pytest.raises(CandidateLearningError, match="LEARNING_SUMMARY_CONFLICT"):
        service.create_summary(
            learning_harness.task_id,
            summary_id=summary_id,
            draft=_summary(learning_harness).model_copy(
                update={"summary": "A conflicting derived claim."}
            ),
            actor_id="candidate-learning",
        )

    other_task_id = uuid4()
    with learning_harness.factory.begin() as session:
        session.add(
            Task(
                id=other_task_id,
                repository="boppuh/mathews",
                base_revision="0" * 40,
                requester="local-user",
                raw_request="evidence://other",
                summary="Other task",
                state=TaskState.PR_ACTIVE,
                retry_count=0,
                owner_id="local-user",
                actor_id="local-user",
                root_correlation_id=other_task_id,
                causation_id=other_task_id,
            )
        )
    with pytest.raises(CandidateLearningError, match="LEARNING_CITATION_UNAVAILABLE"):
        service.create_summary(
            other_task_id,
            summary_id=uuid4(),
            draft=_summary(learning_harness),
            actor_id="candidate-learning",
        )


def test_corrected_source_revokes_summary_and_candidate_eligibility(
    learning_harness: LearningHarness,
) -> None:
    service = _service(learning_harness)
    summary_id = uuid4()
    service.create_summary(
        learning_harness.task_id,
        summary_id=summary_id,
        draft=_summary(learning_harness),
        actor_id="candidate-learning",
    )
    with learning_harness.factory.begin() as session:
        source = session.get(EvidenceRecord, learning_harness.source_ids[0])
        assert source is not None
        capture_evidence(
            session,
            learning_harness.store,
            payload={"review": "Corrected source"},
            media_type="application/json",
            source_kind=EvidenceSourceKind.EXTERNAL_EVENT,
            evidence_type=source.evidence_type,
            origin="local-user:correction",
            access_classification=EvidenceAccessClass(source.access_classification),
            retention_policy=EvidenceRetentionClass(source.retention_policy),
            owner_id=source.owner_id,
            actor_id=source.owner_id,
            root_correlation_id=source.root_correlation_id,
            task_id=source.task_id,
            correction_of_id=source.id,
        )

    with pytest.raises(CandidateLearningError, match="LEARNING_CITATION_UNAVAILABLE"):
        service.create_rule_candidate(
            learning_harness.task_id,
            candidate_id=uuid4(),
            draft=_candidate(summary_id),
            actor_id="candidate-learning",
        )
