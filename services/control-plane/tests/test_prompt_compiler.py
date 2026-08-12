from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.authentication import AuthenticatedSession
from mathews_control_plane.database import (
    Base,
    SessionFactory,
    create_database_engine,
    create_session_factory,
    create_task_record,
)
from mathews_control_plane.domain_models import (
    AgentRunEvaluation,
    BackgroundJob,
    BackgroundJobLease,
    Brief,
    EvaluationContractVersion,
    HermesRun,
    HermesRunStatus,
    PolicyActivation,
    PolicyVersion,
    PolicyVersionPromptTemplate,
    PromptTemplateVersion,
    RetrievalIndexGeneration,
    Task,
    TaskState,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
)
from mathews_control_plane.policy_activation import PolicyActivationAuthorizationError
from mathews_control_plane.prompt_compiler import (
    PromptCompilerService,
    PromptConflictError,
    PromptEvaluationBasis,
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


def _authentication(*, recent: bool = True) -> AuthenticatedSession:
    return AuthenticatedSession(
        session_id=uuid4(),
        user_id=1,
        csrf_token_digest=b"x" * 32,
        expires_at=_NOW + timedelta(hours=1),
        absolute_expires_at=_NOW + timedelta(hours=2),
        reauthenticated_until=_NOW + timedelta(minutes=5),
        evaluated_at=_NOW,
        recent_password_verified=recent,
    )


def _evaluation_basis() -> PromptEvaluationBasis:
    return PromptEvaluationBasis(
        retrieval_index_version="retrieval-v1",
        retrieval_chunker_version="chunker-v1",
        retrieval_verifier_version="verifier-v1",
        model_provider="openai",
        model_name="gpt-5",
        model_version="2026-08-01",
    )


def _record_candidate_evaluation(
    harness: PromptHarness,
    candidate: PromptTemplateVersion,
    *,
    quality_score: float = 0.95,
) -> UUID:
    basis = _evaluation_basis()
    with harness.factory.begin() as session:
        task = session.get(Task, harness.task_id)
        assert task is not None
        job = BackgroundJob(
            task_id=task.id,
            job_type="prompt-evaluation",
            input_payload={},
            input_fingerprint="1" * 64,
            idempotency_key=f"prompt-evaluation:{candidate.id}",
            owner_id=task.owner_id,
            actor_id="evaluation-worker",
            root_correlation_id=task.root_correlation_id,
        )
        session.add(job)
        session.flush()
        lease = BackgroundJobLease(
            job_id=job.id,
            lease_owner="evaluation-worker",
            attempt=1,
            fencing_token=1,
            idempotency_key=f"prompt-evaluation-lease:{candidate.id}",
            claim_fingerprint="2" * 64,
            heartbeat_at=_NOW - timedelta(minutes=2),
            expires_at=_NOW + timedelta(minutes=2),
            owner_id=task.owner_id,
            actor_id="evaluation-worker",
            root_correlation_id=task.root_correlation_id,
        )
        session.add(lease)
        generation = RetrievalIndexGeneration(
            task_id=task.id,
            index_version=basis.retrieval_index_version,
            chunker_version=basis.retrieval_chunker_version,
            verifier_version=basis.retrieval_verifier_version,
            indexed_at=_NOW - timedelta(minutes=1),
            source_count=0,
            chunk_count=0,
            owner_id=task.owner_id,
            actor_id="evaluation-worker",
            root_correlation_id=task.root_correlation_id,
        )
        contract = EvaluationContractVersion(
            lineage_key=f"prompt-evaluation-{candidate.id}",
            version=1,
            promotion_thresholds={
                "minimum_run_count": 1,
                "minimum_quality_score": 0.9,
                "maximum_average_cost_microusd": 2_000,
                "minimum_regression_pass_rate": 1.0,
            },
            regression_cases=["baseline"],
            contract_fingerprint="3" * 64,
            active=True,
            activated_at=_NOW - timedelta(minutes=1),
            owner_id=task.owner_id,
            actor_id="evaluation-worker",
            root_correlation_id=task.root_correlation_id,
        )
        session.add_all((generation, contract))
        session.flush()
        run = HermesRun(
            task_id=task.id,
            job_id=job.id,
            lease_id=lease.id,
            fencing_token=lease.fencing_token,
            attempt=1,
            prompt_template_version_id=candidate.id,
            policy_version_id=harness.policy_id,
            evaluation_label="candidate-evaluation",
            prompt_fingerprint="4" * 64,
            status=HermesRunStatus.SUCCEEDED,
            started_at=_NOW - timedelta(minutes=1),
            completed_at=_NOW,
            owner_id=task.owner_id,
            actor_id="evaluation-worker",
            root_correlation_id=task.root_correlation_id,
        )
        session.add(run)
        session.flush()
        session.add(
            AgentRunEvaluation(
                run_id=run.id,
                task_id=task.id,
                evaluation_contract_version_id=contract.id,
                retrieval_generation_id=generation.id,
                retrieval_index_version=basis.retrieval_index_version,
                retrieval_chunker_version=basis.retrieval_chunker_version,
                retrieval_verifier_version=basis.retrieval_verifier_version,
                retrieval_set=[],
                prompt_template_version_id=candidate.id,
                prompt_template_version=candidate.version,
                policy_version_id=harness.policy_id,
                policy_version=1,
                model_provider=basis.model_provider,
                model_name=basis.model_name,
                model_version=basis.model_version,
                input_tokens=100,
                output_tokens=20,
                cached_tokens=0,
                total_tokens=120,
                cost_microusd=1_000,
                quality_outcome="PASSED",
                quality_score=quality_score,
                regression_results={"baseline": True},
                evaluation_fingerprint="5" * 64,
                evaluated_at=_NOW,
                owner_id=task.owner_id,
                actor_id="evaluation-worker",
                root_correlation_id=task.root_correlation_id,
            )
        )
        return contract.id


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
    activation_id = uuid4()
    contract_id = _record_candidate_evaluation(prompt_harness, candidate)

    result = service.promote(
        candidate_id=candidate.id,
        candidate_version=candidate.version,
        activation_id=activation_id,
        promoted_prompt_id=promoted_id,
        policy_version_id=policy_id,
        rollback_policy_version_id=prompt_harness.policy_id,
        evaluation_contract_version_id=contract_id,
        evaluation_basis=_evaluation_basis(),
        regression_reviewed=True,
        activation_time_value=_NOW,
        authentication=_authentication(),
    )
    replay = service.promote(
        candidate_id=candidate.id,
        candidate_version=candidate.version,
        activation_id=activation_id,
        promoted_prompt_id=promoted_id,
        policy_version_id=policy_id,
        rollback_policy_version_id=prompt_harness.policy_id,
        evaluation_contract_version_id=contract_id,
        evaluation_basis=_evaluation_basis(),
        regression_reviewed=True,
        activation_time_value=_NOW,
        authentication=_authentication(),
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
        activation = session.get(PolicyActivation, activation_id)
        assert stored_candidate is not None and stored_candidate.promoted is False
        assert promoted is not None and promoted.promoted is True
        assert promoted.approved_by == "local-user"
        assert policy is not None and policy.rollback_policy_version_id == prompt_harness.policy_id
        assert activation is not None and activation.policy_version_id == policy_id
        assert activation.threshold_evidence["promotion_eligible"] is True
        assert session.scalar(
            select(func.count())
            .select_from(PolicyVersionPromptTemplate)
            .where(PolicyVersionPromptTemplate.policy_version_id == policy_id)
        ) == len(PromptRole)

    with pytest.raises(PromptConflictError, match="ids conflict"):
        service.promote(
            candidate_id=candidate.id,
            candidate_version=candidate.version,
            activation_id=activation_id,
            promoted_prompt_id=promoted_id,
            policy_version_id=policy_id,
            rollback_policy_version_id=prompt_harness.policy_id,
            evaluation_contract_version_id=uuid4(),
            evaluation_basis=_evaluation_basis(),
            regression_reviewed=True,
            activation_time_value=_NOW,
            authentication=_authentication(),
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
            candidate_version=older.version,
            activation_id=uuid4(),
            promoted_prompt_id=uuid4(),
            policy_version_id=uuid4(),
            rollback_policy_version_id=prompt_harness.policy_id,
            evaluation_contract_version_id=uuid4(),
            evaluation_basis=_evaluation_basis(),
            regression_reviewed=True,
            activation_time_value=_NOW,
            authentication=_authentication(),
        )


def test_prompt_promotion_rejects_worker_or_stale_human_authorization(
    prompt_harness: PromptHarness,
) -> None:
    service = _service(prompt_harness)
    candidate = service.create_candidate(
        prompt_id=uuid4(),
        lineage_key="human-only-experiment",
        template=_template(PromptRole.PLANNER),
        owner_id="local-user",
        root_correlation_id=prompt_harness.task_id,
    )
    contract_id = _record_candidate_evaluation(prompt_harness, candidate)

    with pytest.raises(PolicyActivationAuthorizationError, match="recent password"):
        service.promote(
            candidate_id=candidate.id,
            candidate_version=candidate.version,
            activation_id=uuid4(),
            promoted_prompt_id=uuid4(),
            policy_version_id=uuid4(),
            rollback_policy_version_id=prompt_harness.policy_id,
            evaluation_contract_version_id=contract_id,
            evaluation_basis=_evaluation_basis(),
            regression_reviewed=True,
            activation_time_value=_NOW,
            authentication=_authentication(recent=False),
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
    contract_id = _record_candidate_evaluation(
        prompt_harness,
        candidate,
        quality_score=score,
    )

    with pytest.raises(PromptConflictError, match="requirements"):
        service.promote(
            candidate_id=candidate.id,
            candidate_version=candidate.version,
            activation_id=uuid4(),
            promoted_prompt_id=uuid4(),
            policy_version_id=uuid4(),
            rollback_policy_version_id=prompt_harness.policy_id,
            evaluation_contract_version_id=contract_id,
            evaluation_basis=_evaluation_basis(),
            regression_reviewed=regression_reviewed,
            activation_time_value=_NOW,
            authentication=_authentication(),
        )

    with prompt_harness.factory() as session:
        assert session.scalar(select(func.count()).select_from(PolicyVersion)) == 1
        stored = session.get(PromptTemplateVersion, candidate.id)
        assert stored is not None and stored.promoted is False
