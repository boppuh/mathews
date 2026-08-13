import json
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.authentication import AuthenticatedSession
from mathews_control_plane.briefing import (
    AcceptanceCriterion,
    AffectedUserFlow,
    BriefOperation,
    BriefScope,
    RiskAssessment,
    RiskLevel,
    StructuredBriefDraft,
    VerificationMethod,
    _evaluate_policy,
)
from mathews_control_plane.briefing import (
    TestPlanStep as BriefTestPlanStep,
)
from mathews_control_plane.database import (
    SessionFactory,
    create_database_engine,
    create_session_factory,
)
from mathews_control_plane.database_base import Base
from mathews_control_plane.domain_models import (
    EvaluationContractVersion,
    PolicyVersion,
    PolicyVersionPromptTemplate,
    PolicyVersionReviewRule,
    PromptTemplateVersion,
    ReviewRule,
    Task,
)
from mathews_control_plane.mvp_authority_bootstrap import (
    BOOTSTRAP_ACTOR,
    MvpAuthorityBootstrapConflictError,
    MvpAuthorityBootstrapService,
    mvp_authority_definition,
)
from mathews_control_plane.prompt_compiler import (
    PromptCompilerService,
    PromptNotFoundError,
    PromptRole,
)
from mathews_control_plane.readiness import ReadinessError
from mathews_control_plane.readiness import (
    _active_policy as readiness_active_policy,
)
from mathews_control_plane.review_resolution import (
    ReviewClassification,
    ReviewComment,
    ReviewDisposition,
    ReviewRisk,
    _ReviewContext,
    _rule_matches,
    _unsafe_reason,
)
from mathews_control_plane.tasks import TaskNotFoundError, TaskService
from sqlalchemy import Engine, func, select

_REPOSITORY = "boppuh/mathews-ios-acceptance"
_NOW = datetime(2026, 8, 12, 12, tzinfo=UTC)


@pytest.fixture
def bootstrap_database(tmp_path: Path) -> Iterator[tuple[Engine, MvpAuthorityBootstrapService]]:
    engine = create_database_engine(
        f"sqlite:///{tmp_path / 'bootstrap.sqlite3'}",
        connect_args={"timeout": 30.0},
    )
    Base.metadata.create_all(engine)
    service = MvpAuthorityBootstrapService(create_session_factory(engine), repository=_REPOSITORY)
    try:
        yield engine, service
    finally:
        engine.dispose()


def test_first_bootstrap_creates_exact_authority_shape_and_order(
    bootstrap_database: tuple[Engine, MvpAuthorityBootstrapService],
) -> None:
    engine, service = bootstrap_database

    result = service.bootstrap()

    assert result.operation == "created"
    assert [prompt.role for prompt in result.definition.prompts] == list(PromptRole)
    with create_session_factory(engine)() as session:
        assert session.scalar(select(func.count(PolicyVersion.id))) == 1
        assert session.scalar(select(func.count(PromptTemplateVersion.id))) == 5
        assert session.scalar(select(func.count(ReviewRule.id))) == 1
        assert session.scalar(select(func.count(EvaluationContractVersion.id))) == 1
        contract = session.get(EvaluationContractVersion, result.definition.evaluation_contract_id)
        prompt_memberships = tuple(
            session.scalars(
                select(PolicyVersionPromptTemplate).order_by(PolicyVersionPromptTemplate.position)
            )
        )
        rule_memberships = tuple(
            session.scalars(
                select(PolicyVersionReviewRule).order_by(PolicyVersionReviewRule.position)
            )
        )
    assert [row.position for row in prompt_memberships] == [1, 2, 3, 4, 5]
    assert [row.prompt_template_version_id for row in prompt_memberships] == [
        prompt.id for prompt in result.definition.prompts
    ]
    assert [(row.position, row.review_rule_id) for row in rule_memberships] == [
        (1, result.definition.review_rule_id)
    ]
    assert contract is not None
    assert contract.active
    assert contract.version == 1
    assert contract.lineage_key == "mvp-prompt-evaluation"
    assert contract.contract_fingerprint == result.definition.evaluation_contract_fingerprint
    assert contract.promotion_thresholds == result.definition.evaluation_thresholds


def test_exact_replay_returns_same_records_without_new_rows(
    bootstrap_database: tuple[Engine, MvpAuthorityBootstrapService],
) -> None:
    engine, service = bootstrap_database
    first = service.bootstrap()

    replay = service.bootstrap()

    assert replay.operation == "replayed"
    assert (
        replay.safe_dict()["definition_fingerprint"] == first.safe_dict()["definition_fingerprint"]
    )
    with create_session_factory(engine)() as session:
        assert session.scalar(select(func.count(PolicyVersion.id))) == 1
        assert session.scalar(select(func.count(PromptTemplateVersion.id))) == 5
        assert session.scalar(select(func.count(ReviewRule.id))) == 1
        assert session.scalar(select(func.count(EvaluationContractVersion.id))) == 1


def test_replay_completes_a_pre_contract_bootstrap(
    bootstrap_database: tuple[Engine, MvpAuthorityBootstrapService],
) -> None:
    engine, service = bootstrap_database
    definition = service.bootstrap().definition
    factory = create_session_factory(engine)
    with factory.begin() as session:
        contract = session.get(EvaluationContractVersion, definition.evaluation_contract_id)
        assert contract is not None
        session.delete(contract)

    completed = service.bootstrap()

    assert completed.operation == "created"
    with factory() as session:
        contracts = tuple(session.scalars(select(EvaluationContractVersion)))
    assert [contract.id for contract in contracts] == [definition.evaluation_contract_id]
    assert contracts[0].active


def test_changed_evaluation_contract_conflicts_without_repairing_it(
    bootstrap_database: tuple[Engine, MvpAuthorityBootstrapService],
) -> None:
    engine, service = bootstrap_database
    definition = service.bootstrap().definition
    factory = create_session_factory(engine)
    with factory.begin() as session:
        contract = session.get(EvaluationContractVersion, definition.evaluation_contract_id)
        assert contract is not None
        contract.promotion_thresholds = {
            **contract.promotion_thresholds,
            "minimum_run_count": 999,
        }

    with pytest.raises(MvpAuthorityBootstrapConflictError):
        service.bootstrap()

    with factory() as session:
        contract = session.get(EvaluationContractVersion, definition.evaluation_contract_id)
        assert contract is not None
        assert contract.promotion_thresholds["minimum_run_count"] == 999


def test_changed_bootstrap_repository_conflicts_without_modifying_records(
    bootstrap_database: tuple[Engine, MvpAuthorityBootstrapService],
) -> None:
    engine, service = bootstrap_database
    service.bootstrap()
    changed = MvpAuthorityBootstrapService(
        create_session_factory(engine), repository="boppuh/different-repository"
    )

    with pytest.raises(MvpAuthorityBootstrapConflictError):
        changed.bootstrap()

    with create_session_factory(engine)() as session:
        assert session.scalar(select(func.count(PolicyVersion.id))) == 1
        assert session.scalar(select(func.count(PromptTemplateVersion.id))) == 5
        assert session.scalar(select(func.count(ReviewRule.id))) == 1


def test_concurrent_bootstrap_serializes_the_initial_lineage(
    bootstrap_database: tuple[Engine, MvpAuthorityBootstrapService],
) -> None:
    engine, _service = bootstrap_database
    factory = create_session_factory(engine)

    def invoke() -> str:
        return MvpAuthorityBootstrapService(factory, repository=_REPOSITORY).bootstrap().operation

    with ThreadPoolExecutor(max_workers=4) as executor:
        operations = sorted(executor.map(lambda _value: invoke(), range(4)))

    assert operations == ["created", "replayed", "replayed", "replayed"]
    with factory() as session:
        assert session.scalar(select(func.count(PolicyVersion.id))) == 1


def test_prompts_are_promoted_role_specific_and_deterministic(
    bootstrap_database: tuple[Engine, MvpAuthorityBootstrapService],
) -> None:
    engine, service = bootstrap_database
    definition = service.bootstrap().definition

    with create_session_factory(engine)() as session:
        prompts = tuple(
            session.scalars(select(PromptTemplateVersion).order_by(PromptTemplateVersion.role))
        )
    assert {prompt.role for prompt in prompts} == {role.value for role in PromptRole}
    assert all(
        prompt.version == 1
        and prompt.promoted
        and prompt.evaluation_threshold_passed
        and prompt.regression_reviewed
        and prompt.evaluation_score == 1.0
        and prompt.approved_by == "local-user"
        and prompt.actor_id == BOOTSTRAP_ACTOR
        for prompt in prompts
    )
    assert mvp_authority_definition(_REPOSITORY).definition_fingerprint == (
        definition.definition_fingerprint
    )


def test_review_rule_is_narrow_and_forbidden_changes_fail_closed(
    bootstrap_database: tuple[Engine, MvpAuthorityBootstrapService],
) -> None:
    engine, service = bootstrap_database
    definition = service.bootstrap().definition
    with create_session_factory(engine)() as session:
        rule = session.get(ReviewRule, definition.review_rule_id)
    assert rule is not None
    assert rule.scope == {
        "path_prefixes": ["mathews-ios-acceptance/ContentView.swift"],
        "max_files": 1,
    }
    classification = ReviewClassification(
        disposition=ReviewDisposition.ACTIONABLE,
        category="formatting",
        action="repair.format",
        risk=ReviewRisk.LOW,
        labels=("formatter",),
        proposed_paths=("mathews-ios-acceptance/ContentView.swift",),
        rationale="Apply deterministic formatting only.",
    )
    assert _rule_matches(rule, classification)
    assert not _rule_matches(
        rule,
        classification.model_copy(
            update={"proposed_paths": ("mathews-ios-acceptance.xcodeproj/project.pbxproj",)}
        ),
    )
    context = _review_context(definition.policy_id)
    for flag in ("dependency_change", "schema_change", "signing_change", "security_change"):
        changed = classification.model_copy(update={flag: True})
        assert _unsafe_reason(context, changed) is not None


def test_policy_is_consumable_by_briefing_prompts_review_and_readiness(
    bootstrap_database: tuple[Engine, MvpAuthorityBootstrapService],
    tmp_path: Path,
) -> None:
    engine, service = bootstrap_database
    definition = service.bootstrap().definition
    factory = create_session_factory(engine)
    with factory() as session:
        task = session.get(Task, definition.audit_task_id)
        policy = session.get(PolicyVersion, definition.policy_id)
        assert task is not None
        assert policy is not None
        assert readiness_active_policy(session, task, lineage_key="mvp", now=_NOW).id == policy.id
        evaluation = _evaluate_policy(
            _brief(),
            policy,
            repository_prohibited_paths=("mathews-ios-acceptanceTests",),
            repository_configuration_valid=True,
        )
    assert not evaluation.flags
    compiled = PromptCompilerService(
        factory,
        ArtifactStore(tmp_path / "artifacts"),
        clock=lambda: _NOW,
    ).compile(definition.audit_task_id, role=PromptRole.PLANNER)
    assert compiled.template_id == definition.prompts[0].id
    assert _rule_matches(
        _load_rule(factory, definition.review_rule_id),
        ReviewClassification(
            disposition=ReviewDisposition.ACTIONABLE,
            category="formatting",
            action="repair.format",
            risk=ReviewRisk.LOW,
            labels=("formatter",),
            proposed_paths=("mathews-ios-acceptance/ContentView.swift",),
            rationale="Bounded formatting repair.",
        ),
    )


def test_repository_bound_policy_fails_closed_for_a_different_task_repository(
    bootstrap_database: tuple[Engine, MvpAuthorityBootstrapService],
    tmp_path: Path,
) -> None:
    engine, service = bootstrap_database
    definition = service.bootstrap().definition
    factory = create_session_factory(engine)
    with factory.begin() as session:
        task = session.get(Task, definition.audit_task_id)
        assert task is not None
        task.repository = "boppuh/different-repository"

    with factory() as session:
        task = session.get(Task, definition.audit_task_id)
        assert task is not None
        with pytest.raises(ReadinessError, match="READINESS_POLICY_UNAVAILABLE"):
            readiness_active_policy(session, task, lineage_key="mvp", now=_NOW)
    with pytest.raises(PromptNotFoundError, match="policy version is unavailable"):
        PromptCompilerService(
            factory,
            ArtifactStore(tmp_path / "artifacts"),
            clock=lambda: _NOW,
        ).compile(definition.audit_task_id, role=PromptRole.PLANNER)


def test_bootstrap_audit_task_is_hidden_and_not_operable(
    bootstrap_database: tuple[Engine, MvpAuthorityBootstrapService],
    tmp_path: Path,
) -> None:
    engine, service = bootstrap_database
    definition = service.bootstrap().definition
    now = datetime.now(UTC)
    authentication = AuthenticatedSession(
        session_id=uuid4(),
        user_id=1,
        csrf_token_digest=b"0" * 32,
        expires_at=now + timedelta(hours=1),
        absolute_expires_at=now + timedelta(hours=1),
        reauthenticated_until=now + timedelta(hours=1),
        evaluated_at=now,
        recent_password_verified=True,
    )
    tasks = TaskService(
        create_session_factory(engine),
        ArtifactStore(tmp_path / "artifacts"),
        repository_key=_REPOSITORY,
    )

    assert tasks.list(authentication).tasks == []
    with pytest.raises(TaskNotFoundError, match="task is unavailable"):
        tasks.detail(definition.audit_task_id, authentication)


def test_dry_run_and_output_are_non_secret_and_omit_prompt_bodies(
    bootstrap_database: tuple[Engine, MvpAuthorityBootstrapService],
) -> None:
    _engine, service = bootstrap_database
    rendered = json.dumps(service.dry_run().safe_dict(), sort_keys=True)

    assert '"operation": "dry-run"' in rendered
    assert "keychain://" not in rendered
    assert "token" not in rendered.lower()
    assert "Use only the supplied task context" not in rendered
    assert "instructions" not in rendered
    assert '"evaluation_contract"' in rendered


def _review_context(policy_id: UUID) -> _ReviewContext:
    comment = ReviewComment(
        task_id=uuid4(),
        task_event_id=uuid4(),
        evidence_id=uuid4(),
        comment_id=1,
        pull_request_number=1,
        branch_name="mathews/task",
        head_sha="a" * 40,
        path="mathews-ios-acceptance/ContentView.swift",
        body="Format this file.",
        author="reviewer",
    )
    return _ReviewContext(
        comment=comment,
        task_owner_id="local-user",
        task_root_correlation_id=comment.task_id,
        task_retry_count=0,
        brief_id=uuid4(),
        included_paths=("mathews-ios-acceptance/ContentView.swift",),
        prohibited_paths=(
            ".github",
            "mathews-ios-acceptance.xcodeproj",
            "mathews-ios-acceptanceTests",
            "mathews-ios-acceptanceUITests",
        ),
        validation_contract_id=uuid4(),
        validation_contract_version=1,
        repository_configuration_id=uuid4(),
        repository_configuration_version=1,
        policy_version_id=policy_id,
        max_attempts=1,
        approval_lifetime_seconds=86_400,
    )


def _brief() -> StructuredBriefDraft:
    return StructuredBriefDraft(
        scope=BriefScope(
            objective="Format the ordinary application view.",
            included_paths=("mathews-ios-acceptance/ContentView.swift",),
            operations=(
                BriefOperation(
                    operation_id="edit",
                    risk=RiskLevel.LOW,
                    rationale="Apply the approved source edit.",
                ),
                BriefOperation(
                    operation_id="test",
                    risk=RiskLevel.LOW,
                    rationale="Verify the change.",
                ),
            ),
        ),
        exclusions=("Do not change project or test configuration.",),
        acceptance_criteria=(
            AcceptanceCriterion(
                criterion_id="format-applied",
                requirement="The source view uses the approved formatting.",
                verification=VerificationMethod.STATIC_CHECK,
            ),
        ),
        risks=(
            RiskAssessment(
                risk_id="scope",
                level=RiskLevel.LOW,
                description="The repair could expand beyond one source file.",
                mitigation="Restrict the accepted path and review rule.",
            ),
        ),
        affected_flow=AffectedUserFlow(
            flow_id="primary",
            actor="Acceptance operator",
            entry_point="Application launch",
            expected_outcome="The ordinary source view renders.",
        ),
        test_plan=(
            BriefTestPlanStep(
                step_id="static-check",
                operation_id="test",
                proves_criterion_ids=("format-applied",),
                expected_result="The configured check passes.",
            ),
        ),
    )


def _load_rule(factory: SessionFactory, rule_id: UUID) -> ReviewRule:
    with factory() as session:
        rule = session.get(ReviewRule, rule_id)
        assert rule is not None
        return rule
