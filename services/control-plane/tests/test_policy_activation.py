from __future__ import annotations

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
    PolicyActivation,
    PolicyActivationKind,
    PolicyVersion,
    PolicyVersionPromptTemplate,
    PromptTemplateVersion,
)
from mathews_control_plane.policy_activation import (
    PolicyActivationAuthorizationError,
    PolicyActivationConflictError,
    PolicyActivationService,
)
from mathews_control_plane.prompt_compiler import PromptRole, StructuredPromptTemplate
from sqlalchemy import Engine, select

_NOW = datetime(2026, 8, 11, 18, 0, tzinfo=UTC)


@dataclass(slots=True)
class PolicyHarness:
    engine: Engine
    factory: SessionFactory
    source_policy_id: UUID
    rollback_target_id: UUID
    rollback_prompt_id: UUID


@pytest.fixture
def policy_harness(tmp_path: Path) -> Iterator[PolicyHarness]:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'policy-activation.sqlite3'}")
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
            raw_request="Test immutable policy rollback",
            summary="Test policy rollback",
            owner_id="local-user",
            actor_id="local-user",
        )
        prompts: list[PromptTemplateVersion] = []
        for version in (1, 2):
            prompt = PromptTemplateVersion(
                lineage_key="implementer",
                role=PromptRole.IMPLEMENTER.value,
                version=version,
                predecessor_id=None if version == 1 else prompts[0].id,
                structured_template=StructuredPromptTemplate(
                    role=PromptRole.IMPLEMENTER,
                    instructions=(f"Use immutable prompt {version}.",),
                ).model_dump(mode="json"),
                evaluation_score=1.0,
                evaluation_threshold_passed=True,
                regression_reviewed=True,
                promoted=True,
                approved_by="local-user",
                approved_at=_NOW - timedelta(minutes=3 - version),
                owner_id=task.owner_id,
                actor_id="local-user",
                root_correlation_id=task.root_correlation_id,
            )
            session.add(prompt)
            session.flush()
            prompts.append(prompt)
        target = PolicyVersion(
            lineage_key="mvp",
            version=1,
            workflow_thresholds={"version": 1},
            approved_by="local-user",
            approved_at=_NOW - timedelta(minutes=2),
            owner_id=task.owner_id,
            actor_id="local-user",
            root_correlation_id=task.root_correlation_id,
        )
        session.add(target)
        session.flush()
        source = PolicyVersion(
            lineage_key="mvp",
            version=2,
            predecessor_id=target.id,
            workflow_thresholds={"version": 2},
            approved_by="local-user",
            approved_at=_NOW - timedelta(minutes=1),
            rollback_policy_version_id=target.id,
            owner_id=task.owner_id,
            actor_id="local-user",
            root_correlation_id=task.root_correlation_id,
        )
        session.add(source)
        session.flush()
        for policy, prompt in ((target, prompts[0]), (source, prompts[1])):
            session.add(
                PolicyVersionPromptTemplate(
                    policy_version_id=policy.id,
                    prompt_template_version_id=prompt.id,
                    prompt_promoted=True,
                    position=1,
                    owner_id=task.owner_id,
                    actor_id="local-user",
                    root_correlation_id=task.root_correlation_id,
                )
            )
        source_id = source.id
        target_id = target.id
        target_prompt_id = prompts[0].id
    yield PolicyHarness(engine, factory, source_id, target_id, target_prompt_id)
    engine.dispose()


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


def test_rollback_creates_an_audited_successor_with_prior_immutable_memberships(
    policy_harness: PolicyHarness,
) -> None:
    service = PolicyActivationService(policy_harness.factory, clock=lambda: _NOW)
    activation_id = uuid4()
    restored_id = uuid4()

    result = service.rollback(
        policy_harness.source_policy_id,
        activation_id=activation_id,
        restored_policy_version_id=restored_id,
        restore_from_policy_version_id=policy_harness.rollback_target_id,
        activation_time_value=_NOW,
        authentication=_authentication(),
    )
    replay = service.rollback(
        policy_harness.source_policy_id,
        activation_id=activation_id,
        restored_policy_version_id=restored_id,
        restore_from_policy_version_id=policy_harness.rollback_target_id,
        activation_time_value=_NOW,
        authentication=_authentication(),
    )
    with pytest.raises(PolicyActivationConflictError, match="policy rollback ids conflict"):
        service.rollback(
            policy_harness.source_policy_id,
            activation_id=activation_id,
            restored_policy_version_id=restored_id,
            restore_from_policy_version_id=uuid4(),
            activation_time_value=_NOW,
            authentication=_authentication(),
        )

    assert result.restored_policy_version == 3
    assert replay.replayed is True
    with policy_harness.factory() as session:
        restored = session.get(PolicyVersion, restored_id)
        activation = session.get(PolicyActivation, activation_id)
        prompt_ids = session.scalars(
            select(PolicyVersionPromptTemplate.prompt_template_version_id)
            .where(PolicyVersionPromptTemplate.policy_version_id == restored_id)
            .order_by(PolicyVersionPromptTemplate.position)
        ).all()
    assert restored is not None
    assert restored.workflow_thresholds == {"version": 1}
    assert restored.predecessor_id == policy_harness.source_policy_id
    assert restored.rollback_policy_version_id == policy_harness.source_policy_id
    assert prompt_ids == [policy_harness.rollback_prompt_id]
    assert activation is not None
    assert activation.activation_kind is PolicyActivationKind.ROLLBACK
    assert activation.subject_id == policy_harness.rollback_target_id
    assert activation.approved_by == "local-user"


def test_rollback_requires_recent_human_authorization(
    policy_harness: PolicyHarness,
) -> None:
    service = PolicyActivationService(policy_harness.factory, clock=lambda: _NOW)

    with pytest.raises(PolicyActivationAuthorizationError, match="recent password"):
        service.rollback(
            policy_harness.source_policy_id,
            activation_id=uuid4(),
            restored_policy_version_id=uuid4(),
            restore_from_policy_version_id=policy_harness.rollback_target_id,
            activation_time_value=_NOW,
            authentication=_authentication(recent=False),
        )


def test_rollback_rejects_any_target_other_than_the_recorded_active_target(
    policy_harness: PolicyHarness,
) -> None:
    service = PolicyActivationService(policy_harness.factory, clock=lambda: _NOW)

    with pytest.raises(PolicyActivationConflictError, match="target"):
        service.rollback(
            policy_harness.source_policy_id,
            activation_id=uuid4(),
            restored_policy_version_id=uuid4(),
            restore_from_policy_version_id=uuid4(),
            activation_time_value=_NOW,
            authentication=_authentication(),
        )


def test_rollback_uses_server_time_to_reject_a_newer_active_policy(
    policy_harness: PolicyHarness,
) -> None:
    newer_policy_id = uuid4()
    with policy_harness.factory.begin() as session:
        source = session.get(PolicyVersion, policy_harness.source_policy_id)
        assert source is not None
        session.add(
            PolicyVersion(
                id=newer_policy_id,
                lineage_key="mvp",
                version=3,
                predecessor_id=source.id,
                workflow_thresholds={"version": 3},
                approved_by="local-user",
                approved_at=_NOW,
                rollback_policy_version_id=source.id,
                owner_id=source.owner_id,
                actor_id="local-user",
                root_correlation_id=source.root_correlation_id,
            )
        )
    service = PolicyActivationService(policy_harness.factory, clock=lambda: _NOW)

    with pytest.raises(PolicyActivationConflictError, match="active policy changed"):
        service.rollback(
            policy_harness.source_policy_id,
            activation_id=uuid4(),
            restored_policy_version_id=uuid4(),
            restore_from_policy_version_id=policy_harness.rollback_target_id,
            activation_time_value=_NOW - timedelta(seconds=30),
            authentication=_authentication(),
        )


def test_rollback_rejects_an_activation_time_outside_the_server_window(
    policy_harness: PolicyHarness,
) -> None:
    service = PolicyActivationService(policy_harness.factory, clock=lambda: _NOW)

    with pytest.raises(PolicyActivationConflictError, match="stale or future-dated"):
        service.rollback(
            policy_harness.source_policy_id,
            activation_id=uuid4(),
            restored_policy_version_id=uuid4(),
            restore_from_policy_version_id=policy_harness.rollback_target_id,
            activation_time_value=_NOW + timedelta(minutes=5),
            authentication=_authentication(),
        )
