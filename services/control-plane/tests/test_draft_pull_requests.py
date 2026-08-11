from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID

import pytest
from mathews_configuration import GitHubCredentialPurpose
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
    RepositoryConfiguration,
    Task,
    TaskState,
    ValidationContract,
    ValidationOutcome,
    ValidationRun,
)
from mathews_control_plane.draft_pull_requests import (
    DraftPullRequestError,
    GitHubDraftPullRequestPublisher,
    _DraftProofGates,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
)
from mathews_control_plane.github_app import (
    GitHubAppCredentialBroker,
    GitHubHttpResponse,
)
from mathews_control_plane.task_state_machine import TaskTransitionKind
from sqlalchemy import Engine, select

_SHA = "a" * 40
_OTHER_SHA = "b" * 40
_TREE = "c" * 40
_NOW = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)


@dataclass(slots=True)
class _GateHarness:
    engine: Engine
    factory: SessionFactory
    store: ArtifactStore


@pytest.fixture
def gate_harness(tmp_path: Path) -> Iterator[_GateHarness]:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'draft-pr.sqlite3'}")
    Base.metadata.create_all(engine)
    yield _GateHarness(
        engine,
        create_session_factory(engine),
        ArtifactStore(tmp_path / "artifacts"),
    )
    engine.dispose()


@dataclass(frozen=True)
class _Request:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes | None


class _Transport:
    def __init__(self, *responses: GitHubHttpResponse) -> None:
        self.responses = list(responses)
        self.requests: list[_Request] = []

    def request(
        self,
        *,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> GitHubHttpResponse:
        assert timeout_seconds == 10
        self.requests.append(_Request(method, path, dict(headers), body))
        return self.responses.pop(0)


class _Credential:
    purpose = GitHubCredentialPurpose.PULL_REQUEST_WRITE
    repository_id = 303
    repository_key = "boppuh/mathews"
    expires_at = datetime.now(UTC) + timedelta(minutes=30)
    permissions = (("pull_requests", "write"),)

    def github_authorization_header(self) -> str:
        return "Bearer installation-token"


class _Broker:
    def __init__(self) -> None:
        self.minted: list[GitHubCredentialPurpose] = []
        self.revoked: list[_Credential] = []

    def mint_installation_token(self, purpose: GitHubCredentialPurpose) -> _Credential:
        self.minted.append(purpose)
        return _Credential()

    def revoke_installation_token(self, credential: _Credential) -> None:
        self.revoked.append(credential)


def _response(status: int, value: object) -> GitHubHttpResponse:
    return GitHubHttpResponse(
        status_code=status,
        content_type="application/json; charset=utf-8",
        body=json.dumps(value).encode(),
    )


def _pull_request(*, sha: str = _SHA, draft: bool = True) -> dict[str, object]:
    return {
        "number": 42,
        "html_url": "https://github.com/boppuh/mathews/pull/42",
        "draft": draft,
        "state": "open",
        "head": {"ref": "codex/task-1", "sha": sha},
    }


def test_publisher_creates_one_draft_and_revokes_credential() -> None:
    broker = _Broker()
    transport = _Transport(_response(200, []), _response(201, _pull_request()))
    publisher = GitHubDraftPullRequestPublisher(
        cast(GitHubAppCredentialBroker, broker),
        "boppuh/mathews",
        transport=transport,
    )

    result = publisher.ensure_draft(
        branch_name="codex/task-1",
        base_branch="main",
        title="Verified candidate",
        body="## Summary\n\nDone\n",
        expected_head_sha=_SHA,
    )

    assert result.number == 42
    assert result.head_sha == _SHA
    assert result.is_draft
    assert broker.minted == [GitHubCredentialPurpose.PULL_REQUEST_WRITE]
    assert len(broker.revoked) == 1
    assert [request.method for request in transport.requests] == ["GET", "POST"]
    assert "head=boppuh%3Acodex%2Ftask-1" in transport.requests[0].path
    assert json.loads(cast(bytes, transport.requests[1].body)) == {
        "base": "main",
        "body": "## Summary\n\nDone\n",
        "draft": True,
        "head": "codex/task-1",
        "title": "Verified candidate",
    }
    assert transport.requests[1].headers["Authorization"] == ("Bearer installation-token")


def test_publisher_reuses_the_single_exact_branch_draft() -> None:
    broker = _Broker()
    transport = _Transport(_response(200, [_pull_request()]))
    publisher = GitHubDraftPullRequestPublisher(
        cast(GitHubAppCredentialBroker, broker),
        "boppuh/mathews",
        transport=transport,
    )

    result = publisher.ensure_draft(
        branch_name="codex/task-1",
        base_branch="main",
        title="ignored for existing PR",
        body="ignored for existing PR",
        expected_head_sha=_SHA,
    )

    assert result.number == 42
    assert [request.method for request in transport.requests] == ["GET"]
    assert len(broker.revoked) == 1


def test_publisher_reconciles_an_ambiguous_create_without_duplication() -> None:
    broker = _Broker()
    transport = _Transport(
        _response(200, []),
        _response(500, {"message": "response lost"}),
        _response(200, [_pull_request()]),
    )
    publisher = GitHubDraftPullRequestPublisher(
        cast(GitHubAppCredentialBroker, broker),
        "boppuh/mathews",
        transport=transport,
    )

    result = publisher.ensure_draft(
        branch_name="codex/task-1",
        base_branch="main",
        title="Verified candidate",
        body="body",
        expected_head_sha=_SHA,
    )

    assert result.number == 42
    assert [request.method for request in transport.requests] == ["GET", "POST", "GET"]
    assert len(broker.revoked) == 1


@pytest.mark.parametrize(
    ("value", "code"),
    [
        ([_pull_request(), _pull_request()], "PULL_REQUEST_IDENTITY_AMBIGUOUS"),
        ([_pull_request(sha=_OTHER_SHA)], "PULL_REQUEST_HEAD_MISMATCH"),
        ([_pull_request(draft=False)], "PULL_REQUEST_HEAD_MISMATCH"),
    ],
)
def test_publisher_fails_closed_and_still_revokes_token(value: object, code: str) -> None:
    broker = _Broker()
    publisher = GitHubDraftPullRequestPublisher(
        cast(GitHubAppCredentialBroker, broker),
        "boppuh/mathews",
        transport=_Transport(_response(200, value)),
    )

    with pytest.raises(DraftPullRequestError, match=code):
        publisher.ensure_draft(
            branch_name="codex/task-1",
            base_branch="main",
            title="Verified candidate",
            body="body",
            expected_head_sha=_SHA,
        )

    assert len(broker.revoked) == 1


def test_observe_requires_a_draft_pr_shape() -> None:
    broker = _Broker()
    publisher = GitHubDraftPullRequestPublisher(
        cast(GitHubAppCredentialBroker, broker),
        "boppuh/mathews",
        transport=_Transport(_response(200, _pull_request())),
    )

    result = publisher.observe(42)

    assert result.url.endswith("/pull/42")
    assert len(broker.revoked) == 1


def test_immutable_gate_reloads_exact_passing_run_and_all_four_heads(
    gate_harness: _GateHarness,
) -> None:
    task_id, proof_id, policy_id = _persist_gate_proof(gate_harness)

    with gate_harness.factory() as session:
        task = session.get_one(Task, task_id)
        policy = session.get_one(PolicyVersion, policy_id)
        guards = _DraftProofGates(gate_harness.store, proof_id).evaluate(
            session,
            task,
            TaskTransitionKind.OPEN_VERIFIED_DRAFT_PR,
            policy=policy,
            now=_NOW,
        )

    assert guards.draft_pr is not None
    assert guards.draft_pr.current_head_sha == _SHA
    assert guards.draft_pr.remote_branch_sha == _SHA
    assert guards.draft_pr.pull_request_head_sha == _SHA


def test_immutable_gate_closes_when_persisted_validation_is_no_longer_passing(
    gate_harness: _GateHarness,
) -> None:
    task_id, proof_id, policy_id = _persist_gate_proof(gate_harness)
    with gate_harness.factory.begin() as session:
        run = session.scalars(select(ValidationRun)).one()
        run.outcome = ValidationOutcome.FAILED

    with gate_harness.factory() as session:
        task = session.get_one(Task, task_id)
        policy = session.get_one(PolicyVersion, policy_id)
        guards = _DraftProofGates(gate_harness.store, proof_id).evaluate(
            session,
            task,
            TaskTransitionKind.OPEN_VERIFIED_DRAFT_PR,
            policy=policy,
            now=_NOW,
        )

    assert guards.draft_pr is None


def _persist_gate_proof(harness: _GateHarness) -> tuple[UUID, UUID, UUID]:
    with harness.factory.begin() as session:
        task = create_task_record(
            session,
            harness.store,
            repository="boppuh/mathews",
            base_revision="d" * 40,
            requester="user",
            raw_request="Implement task 6.2",
            summary="Verified draft PR",
            owner_id="local-user",
            actor_id="local-user",
        )
        policy = PolicyVersion(
            lineage_key="mvp",
            version=1,
            predecessor_id=None,
            workflow_thresholds={},
            approved_by="owner",
            approved_at=_NOW,
            rollback_policy_version_id=None,
            owner_id=task.owner_id,
            actor_id="control-plane",
            root_correlation_id=task.root_correlation_id,
        )
        session.add(policy)
        session.flush()
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
            prohibited_paths=[],
            secret_references=[],
            owner_id=task.owner_id,
            actor_id="control-plane",
            root_correlation_id=task.root_correlation_id,
        )
        brief = Brief(
            task_id=task.id,
            version=1,
            predecessor_id=None,
            scope={},
            exclusions=[],
            acceptance_criteria=[],
            risks=[],
            affected_flow={},
            test_plan=[],
            owner_id=task.owner_id,
            actor_id="control-plane",
            root_correlation_id=task.root_correlation_id,
        )
        session.add_all((configuration, brief))
        session.flush()
        contract = ValidationContract(
            task_id=task.id,
            version=1,
            predecessor_id=None,
            brief_id=brief.id,
            repository_configuration_id=configuration.id,
            required_operations=[],
            simulator_setup={},
            clean_state_setup={},
            e2e_flow={},
            typed_assertions=[],
            evidence_requirements=[],
            timeouts={},
            outcome_rules={},
            owner_id=task.owner_id,
            actor_id="control-plane",
            root_correlation_id=task.root_correlation_id,
        )
        session.add(contract)
        session.flush()
        task.accepted_brief_id = brief.id
        task.repository_configuration_id = configuration.id
        task.validation_contract_id = contract.id
        task.state = TaskState.VALIDATING
        run = ValidationRun(
            task_id=task.id,
            validation_contract_id=contract.id,
            repository_configuration_id=configuration.id,
            commit_sha=_SHA,
            tree_sha=_TREE,
            configured_test_plan=[],
            operation_results=[],
            assertion_results=[],
            simulator_target=None,
            outcome=ValidationOutcome.PASSED,
            duration_ms=1,
            acceptance_criterion_results=[],
            owner_id=task.owner_id,
            actor_id="control-plane",
            root_correlation_id=task.root_correlation_id,
        )
        session.add(run)
        session.flush()
        decision = capture_evidence(
            session,
            harness.store,
            payload={"outcome": "PASSED"},
            media_type="application/json",
            source_kind=EvidenceSourceKind.RESULT,
            evidence_type="validation-decision",
            origin="control-plane:validation-decision",
            access_classification=EvidenceAccessClass.TASK_OWNER,
            retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
            owner_id=task.owner_id,
            actor_id="control-plane",
            root_correlation_id=task.root_correlation_id,
            task_id=task.id,
            validation_run_id=run.id,
        )
        observation = {
            "branch_name": f"codex/{task.id}",
            "head_sha": _SHA,
            "tree_sha": _TREE,
            "clean": True,
            "remote_head_sha": None,
        }
        pushed = {**observation, "remote_head_sha": _SHA}
        proof = capture_evidence(
            session,
            harness.store,
            payload={
                "schema_version": 1,
                "brief_id": str(brief.id),
                "validation_contract_id": str(contract.id),
                "validation_contract_version": contract.version,
                "repository_configuration_id": str(configuration.id),
                "repository_configuration_version": configuration.version,
                "validation_run_id": str(run.id),
                "validation_decision_evidence_id": str(decision.record.id),
                "commit_sha": _SHA,
                "tree_sha": _TREE,
                "local_before_push": observation,
                "push_result": pushed,
                "local_after_push": observation,
                "pull_request": {
                    "number": 42,
                    "url": "https://github.com/boppuh/mathews/pull/42",
                    "branch_name": observation["branch_name"],
                    "head_sha": _SHA,
                    "is_draft": True,
                },
            },
            media_type="application/json",
            source_kind=EvidenceSourceKind.TOOL_OPERATION,
            evidence_type="draft-pull-request-proof",
            origin="control-plane:draft-pull-request",
            access_classification=EvidenceAccessClass.TASK_OWNER,
            retention_policy=EvidenceRetentionClass.AUDIT,
            owner_id=task.owner_id,
            actor_id="control-plane",
            root_correlation_id=task.root_correlation_id,
            task_id=task.id,
            validation_run_id=run.id,
        )
        return task.id, proof.record.id, policy.id
