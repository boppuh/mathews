from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from mathews_control_plane.approvals import ApprovalConflictError, ApprovalService
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.briefing import (
    AcceptanceCriterion,
    AffectedUserFlow,
    BriefingConflictError,
    BriefingService,
    BriefOperation,
    BriefScope,
    RiskAssessment,
    RiskLevel,
    StructuredBriefDraft,
    VerificationMethod,
    _BriefTransitionGates,
)
from mathews_control_plane.briefing import (
    TestPlanStep as BriefTestPlanStep,
)
from mathews_control_plane.database import (
    Base,
    SessionFactory,
    create_database_engine,
    create_session_factory,
    create_task_record,
)
from mathews_control_plane.domain_models import (
    ApprovalDecision,
    ApprovalRequest,
    Brief,
    BriefApprovalDecision,
    BriefDecisionDisposition,
    EvidenceRecord,
    PolicyVersion,
    RepositoryConfiguration,
    Task,
    TaskEvent,
    TaskEventEvidenceReference,
    TaskState,
)
from mathews_control_plane.evidence import load_evidence
from mathews_control_plane.task_state_machine import TaskTransitionKind
from pydantic import ValidationError
from sqlalchemy import Engine, func, select

_NOW = datetime(2026, 8, 7, 12, 0, tzinfo=UTC)


@dataclass(slots=True)
class BriefingHarness:
    engine: Engine
    factory: SessionFactory
    store: ArtifactStore


@pytest.fixture
def briefing_harness(tmp_path: Path) -> Iterator[BriefingHarness]:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'briefing.sqlite3'}")
    Base.metadata.create_all(engine)
    yield BriefingHarness(
        engine=engine,
        factory=create_session_factory(engine),
        store=ArtifactStore(tmp_path / "artifacts"),
    )
    engine.dispose()


def _create_task_and_policy(
    harness: BriefingHarness,
    *,
    policy_version: int = 1,
    repository_prohibited_paths: tuple[str, ...] | None = None,
) -> UUID:
    with harness.factory.begin() as session:
        task = create_task_record(
            session,
            harness.store,
            repository="boppuh/mathews",
            base_revision="a" * 40,
            requester="local-user",
            raw_request="Add a durable structured briefing boundary",
            summary="Add structured briefing",
            owner_id="local-user",
            actor_id="local-user",
        )
        task.state = TaskState.BRIEFING
        if repository_prohibited_paths is not None:
            configuration = RepositoryConfiguration(
                repository_key=task.repository,
                version=1,
                predecessor_id=None,
                repository_settings={},
                git_settings={},
                xcode_settings={},
                operations=[],
                e2e_assertions=[],
                artifact_settings={},
                prohibited_paths=list(repository_prohibited_paths),
                secret_references=[],
                owner_id=task.owner_id,
                actor_id="local-user",
                root_correlation_id=task.root_correlation_id,
            )
            session.add(configuration)
            session.flush()
            task.repository_configuration_id = configuration.id
        session.add(
            PolicyVersion(
                lineage_key="mvp",
                version=policy_version,
                workflow_thresholds={
                    "brief_approval_policy": {
                        "schema_version": 1,
                        "preallowed_operations": ["inspect", "edit", "test"],
                        "sensitive_path_prefixes": ["secrets"],
                        "approval_lifetime_hours": 12,
                    }
                },
                approved_by="local-user",
                approved_at=_NOW - timedelta(minutes=1),
                owner_id=task.owner_id,
                actor_id="local-user",
                root_correlation_id=task.root_correlation_id,
            )
        )
        session.flush()
        return task.id


def _source_request_id(harness: BriefingHarness, task_id: UUID) -> UUID:
    with harness.factory() as session:
        task = session.get(Task, task_id)
        assert task is not None
        return UUID(task.raw_request.removeprefix("evidence://"))


def _draft(
    *,
    path: str = "services/control-plane/src/mathews_control_plane/briefing.py",
    operation_risk: RiskLevel = RiskLevel.LOW,
    risk_level: RiskLevel = RiskLevel.LOW,
    scope_expansion: bool = False,
    ambiguity_flags: tuple[str, ...] = (),
    operation_id: str = "edit",
) -> StructuredBriefDraft:
    return StructuredBriefDraft(
        scope=BriefScope(
            objective="Persist a typed, versioned brief and route its approval.",
            included_paths=(path,),
            operations=(
                BriefOperation(
                    operation_id=operation_id,
                    risk=operation_risk,
                    rationale="Implement the approved task scope.",
                ),
                BriefOperation(
                    operation_id="test",
                    risk=RiskLevel.LOW,
                    rationale="Verify the acceptance criteria.",
                ),
            ),
            scope_expansion=scope_expansion,
        ),
        exclusions=("Do not modify deployment or release behavior.",),
        acceptance_criteria=(
            AcceptanceCriterion(
                criterion_id="brief-persisted",
                requirement="The exact structured brief version is durable.",
                verification=VerificationMethod.AUTOMATED_TEST,
            ),
            AcceptanceCriterion(
                criterion_id="decision-bound",
                requirement="Exactly one policy disposition is bound to the brief.",
                verification=VerificationMethod.STATIC_CHECK,
            ),
        ),
        risks=(
            RiskAssessment(
                risk_id="workflow-state",
                level=risk_level,
                description="A stale brief could advance the wrong task version.",
                mitigation="Bind decisions and transitions to immutable identifiers.",
            ),
        ),
        affected_flow=AffectedUserFlow(
            flow_id="task-briefing",
            actor="Authenticated local operator",
            entry_point="A task in BRIEFING",
            expected_outcome="The task advances or waits on exact human approval.",
        ),
        test_plan=(
            BriefTestPlanStep(
                step_id="persist-and-route",
                operation_id="test",
                proves_criterion_ids=("brief-persisted", "decision-bound"),
                expected_result="The brief, evidence, decision, and state agree.",
            ),
        ),
        ambiguity_flags=ambiguity_flags,
    )


def _service(harness: BriefingHarness) -> BriefingService:
    return BriefingService(
        harness.factory,
        harness.store,
        clock=lambda: _NOW,
    )


def test_complete_low_risk_brief_auto_accepts_once_with_evidence(
    briefing_harness: BriefingHarness,
) -> None:
    task_id = _create_task_and_policy(briefing_harness)
    brief_id = uuid4()

    first = _service(briefing_harness).create(
        task_id,
        brief_id=brief_id,
        source_request_evidence_id=_source_request_id(briefing_harness, task_id),
        draft=_draft(),
    )
    replay = _service(briefing_harness).create(
        task_id,
        brief_id=brief_id,
        source_request_evidence_id=_source_request_id(briefing_harness, task_id),
        draft=_draft(),
    )

    assert first.disposition is BriefDecisionDisposition.AUTO_ACCEPTED_BY_POLICY
    assert first.task_state is TaskState.IMPLEMENTING
    assert first.approval_request_id is None
    assert first.replayed is False
    assert replay.replayed is True
    with briefing_harness.factory() as session:
        task = session.get(Task, task_id)
        decision = session.get(BriefApprovalDecision, first.decision_id)
        evidence = session.get(EvidenceRecord, first.evidence_id)
        assert task is not None and task.state is TaskState.IMPLEMENTING
        assert task.accepted_brief_id == brief_id
        assert task.brief_approval_decision_id == first.decision_id
        assert decision is not None and decision.policy_version_id == first.policy_version_id
        assert decision.ambiguity_flags == []
        assert session.scalar(
            select(func.count()).select_from(Brief).where(Brief.task_id == task_id)
        ) == 1
        assert session.scalar(
            select(func.count())
            .select_from(BriefApprovalDecision)
            .where(BriefApprovalDecision.brief_id == brief_id)
        ) == 1
        assert evidence is not None
        loaded = load_evidence(session, briefing_harness.store, evidence)
        assert isinstance(loaded.content, dict)
        assert loaded.content["brief_id"] == str(brief_id)
        assert loaded.content["source_request_evidence_id"] != str(first.evidence_id)
        event = session.scalar(
            select(TaskEvent).where(TaskEvent.event_type == "BRIEF_VERSION_CREATED")
        )
        assert event is not None
        assert session.scalar(
            select(func.count())
            .select_from(TaskEventEvidenceReference)
            .where(TaskEventEvidenceReference.task_event_id == event.id)
        ) == 1


@pytest.mark.parametrize(
    ("draft", "expected_flag"),
    [
        (_draft(ambiguity_flags=("UNCLEAR_SCOPE",)), "UNCLEAR_SCOPE"),
        (_draft(scope_expansion=True), "SCOPE_EXPANSION"),
        (_draft(path="secrets/account.json"), "SENSITIVE_PATH:secrets/account.json"),
        (
            _draft(path=".github/workflows/ci.yml"),
            "SENSITIVE_PATH:.github/workflows/ci.yml",
        ),
        (_draft(path=".github"), "SENSITIVE_PATH:.github"),
        (_draft(operation_id="deploy"), "OPERATION_NOT_PREALLOWED:deploy"),
        (
            _draft(operation_risk=RiskLevel.MEDIUM),
            "OPERATION_RISK_NOT_LOW:edit",
        ),
        (_draft(risk_level=RiskLevel.HIGH), "RISK_NOT_LOW:workflow-state"),
    ],
)
def test_nontrivial_brief_waits_for_exact_human_approval(
    briefing_harness: BriefingHarness,
    draft: StructuredBriefDraft,
    expected_flag: str,
) -> None:
    task_id = _create_task_and_policy(briefing_harness)

    result = _service(briefing_harness).create(
        task_id,
        brief_id=uuid4(),
        source_request_evidence_id=_source_request_id(briefing_harness, task_id),
        draft=draft,
    )

    assert result.disposition is BriefDecisionDisposition.HUMAN_APPROVAL_REQUIRED
    assert result.task_state is TaskState.BRIEF_PENDING_APPROVAL
    assert result.approval_request_id is not None
    with briefing_harness.factory() as session:
        decision = session.get(BriefApprovalDecision, result.decision_id)
        request = session.get(ApprovalRequest, result.approval_request_id)
        assert decision is not None and expected_flag in decision.ambiguity_flags
        assert decision.human_response is None
        assert request is not None
        assert request.subject_type == "BRIEF"
        assert request.subject_id == result.brief_id


def test_revision_creates_a_new_version_and_returns_to_policy_routing(
    briefing_harness: BriefingHarness,
) -> None:
    task_id = _create_task_and_policy(briefing_harness)
    service = _service(briefing_harness)
    original = service.create(
        task_id,
        brief_id=uuid4(),
        source_request_evidence_id=_source_request_id(briefing_harness, task_id),
        draft=_draft(ambiguity_flags=("UNCLEAR_SCOPE",)),
    )
    assert original.approval_request_id is not None
    ApprovalService(
        briefing_harness.factory,
        briefing_harness.store,
        clock=lambda: _NOW,
    ).decide(
        original.approval_request_id,
        decision_id=uuid4(),
        decision=ApprovalDecision.REQUEST_REVISION,
        actor_id="local-user",
        evidence_ids=(original.evidence_id,),
    )

    revised = service.create(
        task_id,
        brief_id=uuid4(),
        source_request_evidence_id=_source_request_id(briefing_harness, task_id),
        draft=_draft(),
    )

    assert revised.brief_version == 2
    assert revised.task_state is TaskState.IMPLEMENTING
    with briefing_harness.factory() as session:
        brief = session.get(Brief, revised.brief_id)
        assert brief is not None and brief.predecessor_id == original.brief_id
        assert session.scalar(
            select(func.count())
            .select_from(BriefApprovalDecision)
            .where(BriefApprovalDecision.task_id == task_id)
        ) == 2


def test_repository_prohibited_path_requires_human_approval(
    briefing_harness: BriefingHarness,
) -> None:
    task_id = _create_task_and_policy(
        briefing_harness,
        repository_prohibited_paths=(".env",),
    )

    result = _service(briefing_harness).create(
        task_id,
        brief_id=uuid4(),
        source_request_evidence_id=_source_request_id(briefing_harness, task_id),
        draft=_draft(path=".env"),
    )

    assert result.disposition is BriefDecisionDisposition.HUMAN_APPROVAL_REQUIRED
    with briefing_harness.factory() as session:
        decision = session.get(BriefApprovalDecision, result.decision_id)
        assert decision is not None
        assert "SENSITIVE_PATH:.env" in decision.ambiguity_flags


def test_stale_request_evidence_cannot_create_a_brief(
    briefing_harness: BriefingHarness,
) -> None:
    task_id = _create_task_and_policy(briefing_harness)
    stale_source_id = _source_request_id(briefing_harness, task_id)
    with briefing_harness.factory.begin() as session:
        task = session.get(Task, task_id)
        assert task is not None
        task.raw_request = f"evidence://{uuid4()}"

    with pytest.raises(BriefingConflictError, match="no longer current"):
        _service(briefing_harness).create(
            task_id,
            brief_id=uuid4(),
            source_request_evidence_id=stale_source_id,
            draft=_draft(),
        )

    with briefing_harness.factory() as session:
        assert session.scalar(select(func.count()).select_from(Brief)) == 0


def test_auto_accept_gate_requires_every_exact_brief_binding(
    briefing_harness: BriefingHarness,
) -> None:
    task_id = _create_task_and_policy(briefing_harness)
    source_id = _source_request_id(briefing_harness, task_id)
    brief_id = uuid4()
    decision_id = uuid4()
    with briefing_harness.factory() as session:
        task = session.get(Task, task_id)
        policy = session.scalar(select(PolicyVersion))
        assert task is not None and policy is not None
        task.accepted_brief_id = brief_id
        task.brief_approval_decision_id = decision_id
        exact = _BriefTransitionGates(
            expected_policy_version_id=policy.id,
            expected_brief_id=brief_id,
            expected_decision_id=decision_id,
            expected_source_request_evidence_id=source_id,
            expected_repository_configuration_id=None,
        )
        stale = _BriefTransitionGates(
            expected_policy_version_id=policy.id,
            expected_brief_id=brief_id,
            expected_decision_id=uuid4(),
            expected_source_request_evidence_id=source_id,
            expected_repository_configuration_id=None,
        )

        assert exact.evaluate(
            session,
            task,
            TaskTransitionKind.AUTO_ACCEPT_BRIEF,
            policy=policy,
            now=_NOW,
        ).brief_policy_bypass_authorized
        assert not stale.evaluate(
            session,
            task,
            TaskTransitionKind.AUTO_ACCEPT_BRIEF,
            policy=policy,
            now=_NOW,
        ).brief_policy_bypass_authorized


def test_routing_failure_cannot_be_bypassed_with_a_different_brief(
    briefing_harness: BriefingHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task_id = _create_task_and_policy(briefing_harness)
    stranded_brief_id = uuid4()

    def routing_failure(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError("simulated routing failure")

    monkeypatch.setattr(ApprovalService, "request", routing_failure)
    with pytest.raises(RuntimeError, match="simulated routing failure"):
        _service(briefing_harness).create(
            task_id,
            brief_id=stranded_brief_id,
            source_request_evidence_id=_source_request_id(
                briefing_harness,
                task_id,
            ),
            draft=_draft(ambiguity_flags=("UNCLEAR_SCOPE",)),
        )

    with pytest.raises(
        BriefingConflictError,
        match="exact stored brief must be routed",
    ):
        _service(briefing_harness).create(
            task_id,
            brief_id=uuid4(),
            source_request_evidence_id=_source_request_id(
                briefing_harness,
                task_id,
            ),
            draft=_draft(),
        )

    with briefing_harness.factory() as session:
        task = session.get(Task, task_id)
        assert task is not None and task.state is TaskState.BRIEFING
        assert task.accepted_brief_id == stranded_brief_id
        assert session.scalar(
            select(func.count()).select_from(Brief).where(Brief.task_id == task_id)
        ) == 1


def test_invalid_policy_configuration_fails_closed_to_human_approval(
    briefing_harness: BriefingHarness,
) -> None:
    task_id = _create_task_and_policy(briefing_harness)
    with briefing_harness.factory.begin() as session:
        policy = session.scalar(select(PolicyVersion))
        assert policy is not None
        policy.workflow_thresholds = {
            "brief_approval_policy": {
                "schema_version": 1,
                "preallowed_operations": ["edit", "test"],
                "sensitive_path_prefixes": ["secrets"],
                "approval_lifetime_hours": 0,
            }
        }

    result = _service(briefing_harness).create(
        task_id,
        brief_id=uuid4(),
        source_request_evidence_id=_source_request_id(briefing_harness, task_id),
        draft=_draft(),
    )

    assert result.disposition is BriefDecisionDisposition.HUMAN_APPROVAL_REQUIRED
    assert result.task_state is TaskState.BRIEF_PENDING_APPROVAL
    with briefing_harness.factory() as session:
        decision = session.get(BriefApprovalDecision, result.decision_id)
        assert decision is not None
        assert "POLICY_CONFIGURATION_INVALID" in decision.ambiguity_flags


def test_brief_rejects_unstructured_or_unbound_planner_output() -> None:
    with pytest.raises(ValidationError):
        StructuredBriefDraft.model_validate({"prose": "Trust me, this is complete."})
    with pytest.raises(ValidationError):
        StructuredBriefDraft.model_validate(
            {
                **_draft().model_dump(mode="json"),
                "acceptance_criteria": [],
            }
        )

    draft = _draft().model_copy(
        update={
            "test_plan": (
                BriefTestPlanStep(
                    step_id="unknown-operation",
                    operation_id="deploy",
                    proves_criterion_ids=("brief-persisted", "decision-bound"),
                    expected_result="Deployment succeeds.",
                ),
            )
        }
    )
    with pytest.raises(BriefingConflictError, match="outside brief scope"):
        draft.validate_bindings()


def test_exact_brief_cannot_approve_under_a_different_active_policy(
    briefing_harness: BriefingHarness,
) -> None:
    task_id = _create_task_and_policy(briefing_harness)
    result = _service(briefing_harness).create(
        task_id,
        brief_id=uuid4(),
        source_request_evidence_id=_source_request_id(briefing_harness, task_id),
        draft=_draft(ambiguity_flags=("UNCLEAR_SCOPE",)),
    )
    assert result.approval_request_id is not None
    with briefing_harness.factory.begin() as session:
        task = session.get(Task, task_id)
        assert task is not None
        session.add(
            PolicyVersion(
                lineage_key="mvp",
                version=2,
                workflow_thresholds={
                    "brief_approval_policy": {
                        "schema_version": 1,
                        "preallowed_operations": ["inspect", "edit", "test"],
                        "sensitive_path_prefixes": ["secrets"],
                        "approval_lifetime_hours": 12,
                    }
                },
                approved_by="local-user",
                approved_at=_NOW,
                owner_id=task.owner_id,
                actor_id="local-user",
                root_correlation_id=task.root_correlation_id,
            )
        )

    with pytest.raises(ApprovalConflictError):
        ApprovalService(
            briefing_harness.factory,
            briefing_harness.store,
            clock=lambda: _NOW + timedelta(minutes=1),
        ).decide(
            result.approval_request_id,
            decision_id=uuid4(),
            decision=ApprovalDecision.APPROVE,
            actor_id="local-user",
            evidence_ids=(result.evidence_id,),
        )
