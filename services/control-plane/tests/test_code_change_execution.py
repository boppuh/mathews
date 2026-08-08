from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest
from mathews_configuration import (
    HostRequestMessage,
    HostResponseMessage,
    HostResponseStatus,
    JsonValue,
    TaskLeaseHostAuthority,
)
from mathews_configuration import RepositoryConfiguration as ValidatedRepositoryConfiguration
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.background_jobs import BackgroundJobService, JobLeaseGrant, RetryPolicy
from mathews_control_plane.code_change_execution import (
    HermesToolProposalRequest,
    ScopedCodeExecutionService,
    ScopedToolAmbiguousError,
    ScopedToolName,
)
from mathews_control_plane.database import (
    Base,
    SessionFactory,
    create_database_engine,
    create_session_factory,
    create_task_record,
)
from mathews_control_plane.domain_models import (
    Brief,
    BriefApprovalDecision,
    BriefDecisionDisposition,
    EvidenceRecord,
    HermesToolDecision,
    HermesToolDecisionStatus,
    HermesToolProposal,
    HermesToolResult,
    HermesToolResultStatus,
    PolicyVersion,
    PolicyVersionPromptTemplate,
    PromptTemplateVersion,
    RepositoryConfiguration,
    TaskEvent,
    TaskState,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
    load_evidence,
)
from mathews_control_plane.hermes import HermesRunService
from mathews_control_plane.host_gateway import HostGatewayError
from mathews_control_plane.prompt_compiler import (
    CompiledPrompt,
    PromptRole,
    StructuredPromptTemplate,
)
from mathews_control_plane.repository_configuration import RepositoryPreflightNotReadyError
from sqlalchemy import Engine, select

_NOW = datetime(2026, 8, 7, 18, 0, tzinfo=UTC)


@dataclass(slots=True)
class ToolHarness:
    engine: Engine
    factory: SessionFactory
    store: ArtifactStore
    task_id: UUID
    run_id: UUID
    grant: JobLeaseGrant
    configuration_id: UUID


@dataclass(frozen=True)
class _Configuration:
    configuration_id: UUID
    repository_key: str = "boppuh/mathews"
    digest: str = "sha256:" + "1" * 64
    prohibited_paths: tuple[str, ...] = (".git", ".env", "Sources/Generated")

    def to_dict(self) -> dict[str, object]:
        return {"repository_key": self.repository_key, "version": 1}


class _Gateway:
    def __init__(
        self,
        responses: list[HostResponseStatus] | None = None,
        *,
        result_path: str = "Sources/App.swift",
    ) -> None:
        self.requests: list[HostRequestMessage] = []
        self._responses = responses or [HostResponseStatus.OK]
        self._result_path = result_path

    def execute(self, request: HostRequestMessage) -> HostResponseMessage:
        self.requests.append(request)
        status = self._responses[min(len(self.requests) - 1, len(self._responses) - 1)]
        result = (
            {
                "head_sha": "a" * 40,
                "base_sha": "a" * 40,
                "changed_paths": [self._result_path],
                "diff": f"--- a/{self._result_path}\n+++ b/{self._result_path}\n",
                "applied_paths": [self._result_path],
            }
            if status is HostResponseStatus.OK
            else {}
        )
        return HostResponseMessage(
            request_id=request.request_id,
            operation_name=request.operation.name,
            idempotency_key=request.operation.idempotency_key,
            host_id="host-1",
            host_version="0.1.0",
            status=status,
            code=("OK" if status is HostResponseStatus.OK else "OPERATION_AMBIGUOUS"),
            replayed=len(self.requests) > 1,
            completed_at_ms=1_800_000_000_000,
            execution_fencing_token=cast(
                TaskLeaseHostAuthority,
                request.authority,
            ).fencing_token,
            result=cast(dict[str, JsonValue], result),
        )


class _UnavailableGateway:
    def execute(self, _request: HostRequestMessage) -> HostResponseMessage:
        raise HostGatewayError("HOST_UNAVAILABLE")


class _OversizedResultGateway(_Gateway):
    def execute(self, request: HostRequestMessage) -> HostResponseMessage:
        self.requests.append(request)
        return HostResponseMessage(
            request_id=request.request_id,
            operation_name=request.operation.name,
            idempotency_key=request.operation.idempotency_key,
            host_id="host-1",
            host_version="0.1.0",
            status=HostResponseStatus.OK,
            code="OK",
            replayed=False,
            completed_at_ms=1_800_000_000_000,
            execution_fencing_token=cast(
                TaskLeaseHostAuthority,
                request.authority,
            ).fencing_token,
            result={
                "head_sha": "a" * 40,
                **{f"content_{index}": "x" * 60_000 for index in range(16)},
            },
        )


@pytest.fixture
def tool_harness(tmp_path: Path) -> Iterator[ToolHarness]:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'tools.sqlite3'}")
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
            raw_request="Change the application safely",
            summary="Change application",
            owner_id="local-user",
            actor_id="local-user",
        )
        task.state = TaskState.IMPLEMENTING
        brief = Brief(
            task_id=task.id,
            version=1,
            scope={
                "objective": "Change the application",
                "included_paths": ["Sources"],
                "operations": [
                    {"operation_id": "inspect", "risk": "LOW", "rationale": "Inspect code"},
                    {"operation_id": "edit", "risk": "LOW", "rationale": "Edit code"},
                ],
                "scope_expansion": False,
            },
            exclusions=[],
            acceptance_criteria=[],
            risks=[],
            affected_flow={},
            test_plan=[],
            owner_id=task.owner_id,
            actor_id="local-user",
            root_correlation_id=task.root_correlation_id,
        )
        configuration = RepositoryConfiguration(
            repository_key=task.repository,
            version=1,
            repository_settings={},
            git_settings={},
            xcode_settings={},
            operations=[],
            e2e_assertions=[],
            artifact_settings={},
            prohibited_paths=[".git", ".env"],
            secret_references=[],
            owner_id=task.owner_id,
            actor_id="local-user",
            root_correlation_id=task.root_correlation_id,
        )
        template = PromptTemplateVersion(
            lineage_key="implementer",
            role=PromptRole.IMPLEMENTER.value,
            version=1,
            structured_template=StructuredPromptTemplate(
                role=PromptRole.IMPLEMENTER,
                instructions=("Implement only the exact brief.",),
            ).model_dump(mode="json"),
            evaluation_score=1.0,
            evaluation_threshold_passed=True,
            regression_reviewed=True,
            promoted=True,
            approved_by="local-user",
            approved_at=_NOW - timedelta(minutes=1),
            owner_id=task.owner_id,
            actor_id="local-user",
            root_correlation_id=task.root_correlation_id,
        )
        policy = PolicyVersion(
            lineage_key="mvp",
            version=1,
            workflow_thresholds={
                "hermes_tool_policy": {
                    "schema_version": 1,
                    "tools": {
                        "workspace.list_files": "inspect",
                        "workspace.read_file": "inspect",
                        "workspace.search": "inspect",
                        "workspace.diff": "inspect",
                        "git.apply_patch": "edit",
                    },
                }
            },
            approved_by="local-user",
            approved_at=_NOW - timedelta(minutes=1),
            owner_id=task.owner_id,
            actor_id="local-user",
            root_correlation_id=task.root_correlation_id,
        )
        session.add_all([brief, configuration, template, policy])
        session.flush()
        brief_decision = BriefApprovalDecision(
            task_id=task.id,
            brief_id=brief.id,
            disposition=BriefDecisionDisposition.AUTO_ACCEPTED_BY_POLICY,
            evaluator_id="brief-approval-policy-v1",
            policy_version_id=policy.id,
            reason="Exact brief was accepted by policy",
            ambiguity_flags=[],
            decided_at=_NOW - timedelta(minutes=1),
            owner_id=task.owner_id,
            actor_id="local-user",
            root_correlation_id=task.root_correlation_id,
        )
        session.add(brief_decision)
        session.flush()
        preflight = capture_evidence(
            session,
            store,
            payload={"status": "PASSED"},
            media_type="application/json",
            source_kind=EvidenceSourceKind.RESULT,
            evidence_type="repository-preflight-report",
            origin="host-agent:preflight",
            access_classification=EvidenceAccessClass.TASK_OWNER,
            retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
            owner_id=task.owner_id,
            actor_id="local-user",
            root_correlation_id=task.root_correlation_id,
            task_id=task.id,
        ).record
        configuration.preflight_evidence_id = preflight.id
        task.accepted_brief_id = brief.id
        task.brief_approval_decision_id = brief_decision.id
        task.repository_configuration_id = configuration.id
        session.add(
            PolicyVersionPromptTemplate(
                policy_version_id=policy.id,
                prompt_template_version_id=template.id,
                prompt_promoted=True,
                position=1,
                owner_id=task.owner_id,
                actor_id="local-user",
                root_correlation_id=task.root_correlation_id,
            )
        )
        task_id = task.id
        configuration_id = configuration.id
        prompt = CompiledPrompt(
            task_id=task.id,
            role=PromptRole.IMPLEMENTER,
            template_id=template.id,
            template_version=template.version,
            policy_version_id=policy.id,
            evaluation_label=None,
            content="{}",
            evidence_ids=(),
        )
    jobs = BackgroundJobService(factory, store, clock=lambda: _NOW)
    job_id = jobs.schedule(
        task_id=task_id,
        job_type="hermes-run",
        idempotency_key=f"hermes:{task_id}",
        input_payload={"task_id": str(task_id)},
        retry_policy=RetryPolicy(max_attempts=2, base_delay_seconds=1, max_delay_seconds=2),
    ).job_id
    grant = jobs.claim_next(worker_id="worker-1", lease_duration=timedelta(minutes=5))
    assert grant is not None and grant.job_id == job_id
    runs = HermesRunService(factory, store, clock=lambda: _NOW)
    run_id = uuid4()
    runs.prepare(grant, run_id=run_id, prompt=prompt)
    runs.record_started(grant, run_id=run_id, external_run_id="run-1")
    yield ToolHarness(engine, factory, store, task_id, run_id, grant, configuration_id)
    engine.dispose()


def _service(
    harness: ToolHarness,
    gateway: _Gateway,
    monkeypatch: pytest.MonkeyPatch,
) -> ScopedCodeExecutionService:
    import mathews_control_plane.code_change_execution as module

    monkeypatch.setattr(
        module,
        "_validated_configuration",
        lambda record: cast(
            ValidatedRepositoryConfiguration,
            _Configuration(record.id),
        ),
    )
    monkeypatch.setattr(
        module,
        "repository_configuration_digest",
        lambda _record: "sha256:" + "1" * 64,
    )
    monkeypatch.setattr(module, "require_preflight_ready", lambda *_args, **_kwargs: object())
    return ScopedCodeExecutionService(
        harness.factory,
        harness.store,
        gateway,
        clock=lambda: _NOW,
    )


def _proposal(path: str = "Sources/App.swift") -> HermesToolProposalRequest:
    return HermesToolProposalRequest(
        proposal_id="proposal-1",
        tool_name=ScopedToolName.APPLY_PATCH,
        arguments={
            "changes": [
                {
                    "path": path,
                    "expected_digest": "sha256:" + "2" * 64,
                    "content": "let enabled = true\n",
                }
            ]
        },
    )


def test_authorized_tool_is_dispatched_once_and_attaches_decision_result_and_diff(
    tool_harness: ToolHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = _Gateway()
    service = _service(tool_harness, gateway, monkeypatch)

    first = service.execute(tool_harness.grant, run_id=tool_harness.run_id, proposal=_proposal())
    replay = service.execute(tool_harness.grant, run_id=tool_harness.run_id, proposal=_proposal())

    assert first.status is HermesToolResultStatus.SUCCEEDED
    assert first.diff_evidence_id is not None
    assert replay.replayed is True
    assert len(gateway.requests) == 1
    request = gateway.requests[0]
    assert request.operation.name == "git.apply_patch"
    assert request.operation.arguments["configuration"] == {
        "repository_key": "boppuh/mathews",
        "version": 1,
    }
    with tool_harness.factory() as session:
        decision = session.scalar(select(HermesToolDecision))
        result = session.scalar(select(HermesToolResult))
        assert decision is not None and decision.status is HermesToolDecisionStatus.AUTHORIZED
        assert result is not None and result.repository_revision == "a" * 40
        assert len(tuple(session.scalars(select(HermesToolProposal)))) == 1
        assert {event.event_type for event in session.scalars(select(TaskEvent))} >= {
            "HERMES_TOOL_AUTHORIZATION",
            "HERMES_TOOL_RESULT",
        }
        evidence_record = session.get(EvidenceRecord, first.result_evidence_id)
        assert evidence_record is not None
        evidence = load_evidence(session, tool_harness.store, evidence_record).content
        assert isinstance(evidence, dict)
        assert evidence["repository_revision"] == "a" * 40


def test_out_of_brief_path_is_denied_without_host_dispatch(
    tool_harness: ToolHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = _Gateway()
    result = _service(tool_harness, gateway, monkeypatch).execute(
        tool_harness.grant,
        run_id=tool_harness.run_id,
        proposal=_proposal("Secrets/App.swift"),
    )

    assert result.status is HermesToolResultStatus.REJECTED
    assert result.code == "PATH_OUTSIDE_BRIEF"
    assert gateway.requests == []
    with tool_harness.factory() as session:
        decision = session.scalar(select(HermesToolDecision))
        assert decision is not None and decision.status is HermesToolDecisionStatus.DENIED


def test_repository_root_is_not_accepted_as_a_patch_file(
    tool_harness: ToolHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = _Gateway()
    result = _service(tool_harness, gateway, monkeypatch).execute(
        tool_harness.grant,
        run_id=tool_harness.run_id,
        proposal=_proposal("."),
    )

    assert result.status is HermesToolResultStatus.REJECTED
    assert result.code == "INVALID_TOOL_ARGUMENTS"
    assert gateway.requests == []


def test_preflight_binding_is_revalidated_while_the_host_effect_is_dispatched(
    tool_harness: ToolHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mathews_control_plane.code_change_execution as module

    gateway = _Gateway()
    service = _service(tool_harness, gateway, monkeypatch)
    calls = 0

    def require_current(*_args: object, **_kwargs: object) -> object:
        nonlocal calls
        calls += 1
        if calls > 1:
            raise RepositoryPreflightNotReadyError("configuration was superseded")
        return object()

    monkeypatch.setattr(module, "require_preflight_ready", require_current)

    result = service.execute(
        tool_harness.grant,
        run_id=tool_harness.run_id,
        proposal=_proposal(),
    )

    assert result.status is HermesToolResultStatus.REJECTED
    assert result.code == "AUTHORIZATION_STALE"
    assert calls == 2
    assert gateway.requests == []


def test_ambiguous_host_attempt_is_evidenced_and_idempotently_reconciled(
    tool_harness: ToolHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = _Gateway([HostResponseStatus.AMBIGUOUS, HostResponseStatus.OK])
    service = _service(tool_harness, gateway, monkeypatch)

    with pytest.raises(ScopedToolAmbiguousError):
        service.execute(tool_harness.grant, run_id=tool_harness.run_id, proposal=_proposal())
    completed = service.execute(
        tool_harness.grant,
        run_id=tool_harness.run_id,
        proposal=_proposal(),
    )

    assert completed.status is HermesToolResultStatus.SUCCEEDED
    assert len(gateway.requests) == 2
    assert (
        gateway.requests[0].operation.idempotency_key
        == gateway.requests[1].operation.idempotency_key
    )
    with tool_harness.factory() as session:
        results = tuple(
            session.scalars(select(HermesToolResult).order_by(HermesToolResult.attempt))
        )
        assert [result.status for result in results] == [
            HermesToolResultStatus.AMBIGUOUS,
            HermesToolResultStatus.SUCCEEDED,
        ]


def test_host_result_outside_brief_is_not_returned_or_captured(
    tool_harness: ToolHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = _Gateway(result_path="Secrets/App.swift")
    result = _service(tool_harness, gateway, monkeypatch).execute(
        tool_harness.grant,
        run_id=tool_harness.run_id,
        proposal=_proposal(),
    )

    assert result.status is HermesToolResultStatus.REJECTED
    assert result.code == "HOST_RESULT_OUTSIDE_BRIEF"
    assert result.result == {"head_sha": "a" * 40}
    assert result.diff_evidence_id is None


def test_prohibited_host_result_is_not_returned_or_captured(
    tool_harness: ToolHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = _Gateway(result_path="Sources/Generated/App.swift")
    result = _service(tool_harness, gateway, monkeypatch).execute(
        tool_harness.grant,
        run_id=tool_harness.run_id,
        proposal=_proposal(),
    )

    assert result.status is HermesToolResultStatus.REJECTED
    assert result.code == "HOST_RESULT_PROHIBITED"
    assert result.result == {"head_sha": "a" * 40}
    assert result.diff_evidence_id is None


def test_oversized_host_result_is_recorded_as_a_bounded_rejection(
    tool_harness: ToolHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = _OversizedResultGateway()
    result = _service(tool_harness, gateway, monkeypatch).execute(
        tool_harness.grant,
        run_id=tool_harness.run_id,
        proposal=_proposal(),
    )

    assert result.status is HermesToolResultStatus.REJECTED
    assert result.code == "HOST_RESULT_UNBOUNDED"
    assert result.result == {"head_sha": "a" * 40}
    with tool_harness.factory() as session:
        stored = session.scalar(select(HermesToolResult))
        assert stored is not None and stored.status is HermesToolResultStatus.REJECTED


def test_host_outage_is_evidenced_as_ambiguous_before_retry(
    tool_harness: ToolHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(
        tool_harness,
        cast(_Gateway, _UnavailableGateway()),
        monkeypatch,
    )

    with pytest.raises(ScopedToolAmbiguousError):
        service.execute(
            tool_harness.grant,
            run_id=tool_harness.run_id,
            proposal=_proposal(),
        )

    with tool_harness.factory() as session:
        stored = session.scalar(select(HermesToolResult))
        assert stored is not None
        assert stored.status is HermesToolResultStatus.AMBIGUOUS
        assert stored.code == "HOST_UNAVAILABLE"
