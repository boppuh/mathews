from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.database import (
    Base,
    SessionFactory,
    create_database_engine,
    create_session_factory,
    create_task_record,
)
from mathews_control_plane.domain_models import (
    Brief,
    PolicyVersion,
    PolicyVersionPromptTemplate,
    PromptTemplateVersion,
    TaskState,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
)
from mathews_control_plane.prompt_compiler import (
    PromptCompilerService,
    PromptConflictError,
    PromptNotFoundError,
    PromptRole,
    StructuredPromptTemplate,
)
from sqlalchemy import Engine, func, select

_NOW = datetime(2026, 8, 7, 16, 0, tzinfo=UTC)


@dataclass(slots=True)
class PromptHarness:
    engine: Engine
    factory: SessionFactory
    store: ArtifactStore
    task_id: UUID
    policy_id: UUID
    prompt_ids: dict[PromptRole, UUID]
    evidence_id: UUID


@pytest.fixture
def prompt_harness(tmp_path: Path) -> Iterator[PromptHarness]:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'prompts.sqlite3'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    store = ArtifactStore(tmp_path / "artifacts")
    with factory.begin() as session:
        task = create_task_record(
            session,
            store,
            repository="boppuh/mathews",
            base_revision="a" * 40,
            requester="local-user",
            raw_request="Build safe role prompts",
            summary="Build role prompts",
            owner_id="local-user",
            actor_id="local-user",
        )
        task.state = TaskState.IMPLEMENTING
        brief = Brief(
            task_id=task.id,
            version=1,
            scope={"objective": "Compile bounded prompts"},
            exclusions=["No deployment"],
            acceptance_criteria=[{"id": "bounded", "requirement": "Bound inputs"}],
            risks=[{"id": "logs", "level": "LOW"}],
            affected_flow={"actor": "operator"},
            test_plan=[{"step": "compile"}],
            owner_id=task.owner_id,
            actor_id="local-user",
            root_correlation_id=task.root_correlation_id,
        )
        session.add(brief)
        session.flush()
        task.accepted_brief_id = brief.id
        evidence = capture_evidence(
            session,
            store,
            payload="FULL MUTABLE LOG secret-value",
            media_type="text/plain; charset=utf-8",
            source_kind=EvidenceSourceKind.RESULT,
            evidence_type="prompt-evaluation",
            origin="test:prompt",
            access_classification=EvidenceAccessClass.TASK_OWNER,
            retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
            owner_id=task.owner_id,
            actor_id="local-user",
            root_correlation_id=task.root_correlation_id,
            task_id=task.id,
        ).record
        prompt_ids: dict[PromptRole, UUID] = {}
        prompts: list[PromptTemplateVersion] = []
        for role in PromptRole:
            prompt = PromptTemplateVersion(
                lineage_key=role.value,
                role=role.value,
                version=1,
                structured_template=_template(role).model_dump(mode="json"),
                evaluation_score=1.0,
                evaluation_threshold_passed=True,
                regression_reviewed=True,
                promoted=True,
                approved_by="local-user",
                approved_at=_NOW - timedelta(minutes=2),
                owner_id=task.owner_id,
                actor_id="local-user",
                root_correlation_id=task.root_correlation_id,
            )
            prompts.append(prompt)
            session.add(prompt)
        policy = PolicyVersion(
            lineage_key="mvp",
            version=1,
            workflow_thresholds={
                "prompt_promotion_policy": {
                    "schema_version": 1,
                    "minimum_score": 0.9,
                }
            },
            approved_by="local-user",
            approved_at=_NOW - timedelta(minutes=1),
            owner_id=task.owner_id,
            actor_id="local-user",
            root_correlation_id=task.root_correlation_id,
        )
        session.add(policy)
        session.flush()
        for position, prompt in enumerate(prompts, start=1):
            prompt_ids[PromptRole(prompt.role)] = prompt.id
            session.add(
                PolicyVersionPromptTemplate(
                    policy_version_id=policy.id,
                    prompt_template_version_id=prompt.id,
                    position=position,
                    owner_id=task.owner_id,
                    actor_id="local-user",
                    root_correlation_id=task.root_correlation_id,
                )
            )
        task_id = task.id
        policy_id = policy.id
        evidence_id = evidence.id
    yield PromptHarness(engine, factory, store, task_id, policy_id, prompt_ids, evidence_id)
    engine.dispose()


def _template(role: PromptRole, *, evidence_limit: int = 8) -> StructuredPromptTemplate:
    return StructuredPromptTemplate(
        role=role,
        instructions=(f"Act only as the {role.value}.", "Use only supplied facts."),
        evidence_limit=evidence_limit,
        max_prompt_characters=16_000,
    )


def _service(harness: PromptHarness) -> PromptCompilerService:
    return PromptCompilerService(
        harness.factory,
        harness.store,
        clock=lambda: _NOW,
    )


@pytest.mark.parametrize("role", list(PromptRole))
def test_default_role_prompts_are_bounded_and_use_only_verified_metadata(
    prompt_harness: PromptHarness,
    role: PromptRole,
) -> None:
    result = _service(prompt_harness).compile(
        prompt_harness.task_id,
        role=role,
        evidence_ids=(prompt_harness.evidence_id,),
    )

    payload = json.loads(result.content)
    assert result.template_id == prompt_harness.prompt_ids[role]
    assert result.evaluation_mode is False
    assert payload["role"] == role.value
    assert payload["verified_evidence"][0]["evidence_id"] == str(
        prompt_harness.evidence_id
    )
    assert "FULL MUTABLE LOG" not in result.content
    assert "secret-value" not in result.content
    if role is PromptRole.PLANNER:
        assert "brief" not in payload["task"]
    else:
        assert payload["task"]["brief"]["version"] == 1


def test_non_default_prompt_requires_a_valid_evaluation_label(
    prompt_harness: PromptHarness,
) -> None:
    candidate = _service(prompt_harness).create_candidate(
        prompt_id=uuid4(),
        lineage_key="implementer-experiment",
        template=_template(PromptRole.IMPLEMENTER),
        owner_id="local-user",
        root_correlation_id=prompt_harness.task_id,
    )

    with pytest.raises(PromptConflictError, match="labeled evaluation"):
        _service(prompt_harness).compile(
            prompt_harness.task_id,
            role=PromptRole.IMPLEMENTER,
            template_id=candidate.id,
        )
    evaluated = _service(prompt_harness).compile(
        prompt_harness.task_id,
        role=PromptRole.IMPLEMENTER,
        template_id=candidate.id,
        evaluation_label="eval/prompt-42",
    )

    assert evaluated.evaluation_mode is True
    assert evaluated.evaluation_label == "eval/prompt-42"
    with pytest.raises(PromptConflictError, match="cannot use"):
        _service(prompt_harness).compile(
            prompt_harness.task_id,
            role=PromptRole.IMPLEMENTER,
            evaluation_label="eval/default",
        )


def test_prompt_rejects_unverified_or_excess_evidence(
    prompt_harness: PromptHarness,
) -> None:
    with pytest.raises(PromptNotFoundError, match="evidence"):
        _service(prompt_harness).compile(
            prompt_harness.task_id,
            role=PromptRole.VALIDATOR,
            evidence_ids=(uuid4(),),
        )
    candidate = _service(prompt_harness).create_candidate(
        prompt_id=uuid4(),
        lineage_key="validator-no-evidence",
        template=_template(PromptRole.VALIDATOR, evidence_limit=0),
        owner_id="local-user",
        root_correlation_id=prompt_harness.task_id,
    )
    with pytest.raises(PromptConflictError, match="limit"):
        _service(prompt_harness).compile(
            prompt_harness.task_id,
            role=PromptRole.VALIDATOR,
            template_id=candidate.id,
            evaluation_label="eval/no-evidence",
            evidence_ids=(prompt_harness.evidence_id,),
        )


def test_promotion_creates_immutable_prompt_and_policy_successors(
    prompt_harness: PromptHarness,
) -> None:
    service = _service(prompt_harness)
    candidate = service.create_candidate(
        prompt_id=uuid4(),
        lineage_key="implementer-experiment",
        template=_template(PromptRole.IMPLEMENTER),
        owner_id="local-user",
        root_correlation_id=prompt_harness.task_id,
    )
    promoted_id = uuid4()
    policy_id = uuid4()

    result = service.promote(
        candidate_id=candidate.id,
        promoted_prompt_id=promoted_id,
        policy_version_id=policy_id,
        evaluation_evidence_id=prompt_harness.evidence_id,
        evaluation_score=0.95,
        regression_reviewed=True,
        approved_by="human-reviewer",
    )
    replay = service.promote(
        candidate_id=candidate.id,
        promoted_prompt_id=promoted_id,
        policy_version_id=policy_id,
        evaluation_evidence_id=prompt_harness.evidence_id,
        evaluation_score=0.95,
        regression_reviewed=True,
        approved_by="human-reviewer",
    )

    assert result.rollback_policy_version_id == prompt_harness.policy_id
    assert result.promoted_prompt_version == candidate.version + 1
    assert replay.replayed is True
    compiled = service.compile(
        prompt_harness.task_id,
        role=PromptRole.IMPLEMENTER,
    )
    assert compiled.template_id == promoted_id
    bound = service.compile(
        prompt_harness.task_id,
        role=PromptRole.IMPLEMENTER,
        policy_version_id=prompt_harness.policy_id,
    )
    assert bound.policy_version_id == prompt_harness.policy_id
    assert bound.template_id == prompt_harness.prompt_ids[PromptRole.IMPLEMENTER]
    with prompt_harness.factory() as session:
        stored_candidate = session.get(PromptTemplateVersion, candidate.id)
        promoted = session.get(PromptTemplateVersion, promoted_id)
        policy = session.get(PolicyVersion, policy_id)
        assert stored_candidate is not None and stored_candidate.promoted is False
        assert promoted is not None and promoted.promoted is True
        assert promoted.approved_by == "human-reviewer"
        assert policy is not None and policy.rollback_policy_version_id == prompt_harness.policy_id
        assert session.scalar(
            select(func.count())
            .select_from(PolicyVersionPromptTemplate)
            .where(PolicyVersionPromptTemplate.policy_version_id == policy_id)
        ) == len(PromptRole)

    with pytest.raises(PromptConflictError, match="ids conflict"):
        service.promote(
            candidate_id=candidate.id,
            promoted_prompt_id=promoted_id,
            policy_version_id=policy_id,
            evaluation_evidence_id=prompt_harness.evidence_id,
            evaluation_score=0.99,
            regression_reviewed=True,
            approved_by="human-reviewer",
        )


def test_only_latest_candidate_in_a_lineage_can_be_promoted(
    prompt_harness: PromptHarness,
) -> None:
    service = _service(prompt_harness)
    older = service.create_candidate(
        prompt_id=uuid4(),
        lineage_key="planner-experiment",
        template=_template(PromptRole.PLANNER),
        owner_id="local-user",
        root_correlation_id=prompt_harness.task_id,
    )
    service.create_candidate(
        prompt_id=uuid4(),
        lineage_key="planner-experiment",
        template=_template(PromptRole.PLANNER),
        owner_id="local-user",
        root_correlation_id=prompt_harness.task_id,
    )

    with pytest.raises(PromptConflictError, match="latest"):
        service.promote(
            candidate_id=older.id,
            promoted_prompt_id=uuid4(),
            policy_version_id=uuid4(),
            evaluation_evidence_id=prompt_harness.evidence_id,
            evaluation_score=0.95,
            regression_reviewed=True,
            approved_by="human-reviewer",
        )


@pytest.mark.parametrize(
    ("score", "regression_reviewed"),
    [(0.89, True), (0.95, False)],
)
def test_promotion_fails_closed_without_all_governance_gates(
    prompt_harness: PromptHarness,
    score: float,
    regression_reviewed: bool,
) -> None:
    service = _service(prompt_harness)
    candidate = service.create_candidate(
        prompt_id=uuid4(),
        lineage_key="reviewer-experiment",
        template=_template(PromptRole.REVIEWER),
        owner_id="local-user",
        root_correlation_id=prompt_harness.task_id,
    )

    with pytest.raises(PromptConflictError, match="requirements"):
        service.promote(
            candidate_id=candidate.id,
            promoted_prompt_id=uuid4(),
            policy_version_id=uuid4(),
            evaluation_evidence_id=prompt_harness.evidence_id,
            evaluation_score=score,
            regression_reviewed=regression_reviewed,
            approved_by="human-reviewer",
        )

    with prompt_harness.factory() as session:
        assert session.scalar(select(func.count()).select_from(PolicyVersion)) == 1
        stored = session.get(PromptTemplateVersion, candidate.id)
        assert stored is not None and stored.promoted is False
