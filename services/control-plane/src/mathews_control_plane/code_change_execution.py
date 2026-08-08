"""Control-plane authorization and evidence boundary for Hermes workspace tools."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from pathlib import PurePosixPath
from typing import Protocol, cast
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from mathews_configuration import (
    HostOperation,
    HostRequestMessage,
    HostResponseMessage,
    HostResponseStatus,
    JsonValue,
)
from mathews_configuration import (
    RepositoryConfiguration as ValidatedRepositoryConfiguration,
)
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.background_jobs import JobLeaseGrant
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    BackgroundJob,
    BackgroundJobLease,
    BackgroundJobStatus,
    BackgroundJobToolGrant,
    Brief,
    BriefApprovalDecision,
    BriefDecisionDisposition,
    EvidenceRecord,
    HermesRun,
    HermesRunStatus,
    HermesToolDecision,
    HermesToolDecisionStatus,
    HermesToolProposal,
    HermesToolResult,
    HermesToolResultStatus,
    PolicyVersion,
    PromptTemplateVersion,
    RepositoryConfiguration,
    Task,
    TaskEvent,
    TaskEventEvidenceReference,
    TaskState,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
    load_evidence,
)
from mathews_control_plane.host_gateway import HostGatewayError, authority_for_job_lease
from mathews_control_plane.repository_configuration import (
    RepositoryPreflightNotReadyError,
    repository_configuration_digest,
    require_preflight_ready,
)

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GIT_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_ACTIVE_STATES = frozenset({TaskState.IMPLEMENTING, TaskState.REPAIRING})
_INSPECTION_TOOLS = frozenset(
    {
        "workspace.list_files",
        "workspace.read_file",
        "workspace.search",
        "workspace.diff",
    }
)
_MUTATION_TOOLS = frozenset({"git.apply_patch"})
_TOOLS = _INSPECTION_TOOLS | _MUTATION_TOOLS


class ScopedToolError(RuntimeError):
    pass


class ScopedToolConflictError(ScopedToolError):
    pass


class ScopedToolAmbiguousError(ScopedToolError):
    pass


class ScopedToolName(StrEnum):
    LIST_FILES = "workspace.list_files"
    READ_FILE = "workspace.read_file"
    SEARCH = "workspace.search"
    DIFF = "workspace.diff"
    APPLY_PATCH = "git.apply_patch"


class HermesToolProposalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    proposal_id: str = Field(
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$",
    )
    tool_name: ScopedToolName
    arguments: dict[str, object]


@dataclass(frozen=True, slots=True)
class ScopedToolExecutionResult:
    proposal_id: str
    status: HermesToolResultStatus
    code: str
    result: dict[str, object]
    decision_evidence_id: UUID
    result_evidence_id: UUID
    diff_evidence_id: UUID | None
    replayed: bool


class HostGateway(Protocol):
    def execute(self, request: HostRequestMessage) -> HostResponseMessage: ...


@dataclass(frozen=True, slots=True)
class _Authorization:
    proposal_id: UUID
    decision_id: UUID
    decision_status: HermesToolDecisionStatus
    reason_code: str
    decision_evidence_id: UUID
    configuration: ValidatedRepositoryConfiguration | None
    normalized_arguments: dict[str, object] | None
    replayed: bool


class ScopedCodeExecutionService:
    """Persist, authorize, dispatch, and evidence every Hermes tool proposal."""

    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        host_gateway: HostGateway,
        *,
        principal_id: str = "control-plane",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._factory = factory
        self._store = artifact_store
        self._host = host_gateway
        self._principal_id = _identifier(principal_id, "principal")
        self._clock = clock or (lambda: datetime.now(UTC))

    def execute(
        self,
        grant: JobLeaseGrant,
        *,
        run_id: UUID,
        proposal: HermesToolProposalRequest,
    ) -> ScopedToolExecutionResult:
        authorization = self._authorize(grant, run_id=run_id, proposal=proposal)
        terminal = self._terminal_result(authorization.proposal_id, proposal.proposal_id)
        if terminal is not None:
            return terminal
        if authorization.decision_status is HermesToolDecisionStatus.DENIED:
            return self._record_result(
                authorization,
                proposal=proposal,
                response_status=HostResponseStatus.REJECTED,
                code=authorization.reason_code,
                result={},
                replayed=authorization.replayed,
            )
        assert authorization.configuration is not None
        assert authorization.normalized_arguments is not None
        try:
            self._assert_dispatch_still_authorized(grant, authorization.proposal_id)
        except ScopedToolConflictError:
            return self._record_result(
                authorization,
                proposal=proposal,
                response_status=HostResponseStatus.REJECTED,
                code="AUTHORIZATION_STALE",
                result={},
                replayed=False,
            )
        now = _as_utc(self._clock())
        configuration = authorization.configuration
        operation_arguments = cast(
            dict[str, JsonValue],
            {
                "configuration": configuration.to_dict(),
                **authorization.normalized_arguments,
            },
        )
        request = HostRequestMessage(
            request_id=uuid4(),
            issued_at_ms=int(now.timestamp() * 1_000),
            expires_at_ms=int((now + timedelta(seconds=30)).timestamp() * 1_000),
            authority=authority_for_job_lease(grant, configuration=configuration),
            operation=HostOperation(
                name=proposal.tool_name.value,
                idempotency_key=f"hermes-tool:{authorization.proposal_id}",
                arguments=operation_arguments,
            ),
        )
        try:
            response = self._host.execute(request)
        except HostGatewayError as error:
            self._record_result(
                authorization,
                proposal=proposal,
                response_status=HostResponseStatus.AMBIGUOUS,
                code=error.code,
                result={},
                replayed=False,
            )
            raise ScopedToolAmbiguousError("host tool execution is unavailable") from None
        recorded = self._record_result(
            authorization,
            proposal=proposal,
            response_status=response.status,
            code=response.code,
            result=cast(dict[str, object], response.result),
            replayed=response.replayed,
        )
        if recorded.status is HermesToolResultStatus.AMBIGUOUS:
            raise ScopedToolAmbiguousError("host tool execution requires reconciliation")
        return recorded

    def _authorize(
        self,
        grant: JobLeaseGrant,
        *,
        run_id: UUID,
        proposal: HermesToolProposalRequest,
    ) -> _Authorization:
        now = _as_utc(self._clock())
        internal_id = uuid5(
            NAMESPACE_URL,
            f"mathews:hermes-tool:{run_id}:{proposal.proposal_id}",
        )
        arguments_fingerprint = _fingerprint(proposal.arguments)
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            run, task, tool_grant = _proposal_context(session, grant, run_id, now)
            existing = session.scalar(
                select(HermesToolProposal).where(HermesToolProposal.id == internal_id)
            )
            if existing is not None:
                if (
                    existing.run_id != run.id
                    or existing.external_proposal_id != proposal.proposal_id
                    or existing.tool_name != proposal.tool_name.value
                    or existing.arguments_fingerprint != arguments_fingerprint
                ):
                    raise ScopedToolConflictError("Hermes tool proposal id conflicts")
                decision = session.scalar(
                    select(HermesToolDecision).where(HermesToolDecision.proposal_id == existing.id)
                )
                if decision is None:
                    raise ScopedToolConflictError("stored tool proposal is incomplete")
                configuration = _validated_configuration_for_decision(session, decision)
                normalized = (
                    None
                    if decision.status is HermesToolDecisionStatus.DENIED
                    else _normalize_arguments(proposal)
                )
                return _Authorization(
                    existing.id,
                    decision.id,
                    decision.status,
                    decision.reason_code,
                    decision.decision_evidence_id,
                    configuration,
                    normalized,
                    True,
                )

            proposal_evidence_id = uuid5(NAMESPACE_URL, f"mathews:tool-proposal:{internal_id}")
            capture_evidence(
                session,
                self._store,
                payload={
                    "schema_version": 1,
                    "proposal_id": proposal.proposal_id,
                    "run_id": str(run.id),
                    "tool_name": proposal.tool_name.value,
                    "arguments": proposal.arguments,
                    "arguments_fingerprint": arguments_fingerprint,
                },
                media_type="application/json",
                source_kind=EvidenceSourceKind.REQUEST,
                evidence_type="hermes-tool-proposal",
                origin="hermes:tool-proposal",
                access_classification=EvidenceAccessClass.TASK_OWNER,
                retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
                owner_id=task.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=task.root_correlation_id,
                task_id=task.id,
                causation_id=run.id,
                parent_correlation_id=run.job_id,
                evidence_id=proposal_evidence_id,
                captured_at=now,
            )
            stored = HermesToolProposal(
                id=internal_id,
                run_id=run.id,
                task_id=task.id,
                job_id=run.job_id,
                lease_id=run.lease_id,
                fencing_token=run.fencing_token,
                external_proposal_id=proposal.proposal_id,
                tool_name=proposal.tool_name.value,
                arguments_fingerprint=arguments_fingerprint,
                proposal_evidence_id=proposal_evidence_id,
                proposed_at=now,
                owner_id=task.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=task.root_correlation_id,
                causation_id=run.id,
                parent_correlation_id=run.job_id,
            )
            session.add(stored)
            session.flush()
            status, reason, brief, configuration, normalized = _authorization_decision(
                session,
                artifact_store=self._store,
                task=task,
                run=run,
                tool_grant=tool_grant,
                proposal=proposal,
            )
            decision_id = uuid5(NAMESPACE_URL, f"mathews:tool-decision:{internal_id}")
            decision_evidence_id = uuid5(
                NAMESPACE_URL,
                f"mathews:tool-decision-evidence:{internal_id}",
            )
            decision_payload = {
                "schema_version": 1,
                "proposal_id": proposal.proposal_id,
                "tool_name": proposal.tool_name.value,
                "status": status.value,
                "reason_code": reason,
                "task_state": task.state.value,
                "brief_id": None if brief is None else str(brief.id),
                "repository_configuration_id": (
                    None if configuration is None else str(configuration.configuration_id)
                ),
                "policy_version_id": str(run.policy_version_id),
                "tool_grant_id": str(tool_grant.id),
            }
            capture_evidence(
                session,
                self._store,
                payload=decision_payload,
                media_type="application/json",
                source_kind=EvidenceSourceKind.TOOL_OPERATION,
                evidence_type="hermes-tool-authorization",
                origin="control-plane:tool-gateway",
                access_classification=EvidenceAccessClass.TASK_OWNER,
                retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
                owner_id=task.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=task.root_correlation_id,
                task_id=task.id,
                causation_id=stored.id,
                parent_correlation_id=run.id,
                evidence_id=decision_evidence_id,
                captured_at=now,
            )
            session.add(
                HermesToolDecision(
                    id=decision_id,
                    proposal_id=stored.id,
                    status=status,
                    reason_code=reason,
                    tool_grant_id=tool_grant.id,
                    brief_id=None if brief is None else brief.id,
                    repository_configuration_id=(
                        None if configuration is None else configuration.configuration_id
                    ),
                    policy_version_id=run.policy_version_id,
                    decision_evidence_id=decision_evidence_id,
                    decided_at=now,
                    owner_id=task.owner_id,
                    actor_id=self._principal_id,
                    root_correlation_id=task.root_correlation_id,
                    causation_id=stored.id,
                    parent_correlation_id=run.id,
                )
            )
            _task_event(
                session,
                task=task,
                event_type="HERMES_TOOL_AUTHORIZATION",
                payload={
                    "schema_version": 1,
                    "proposal_id": proposal.proposal_id,
                    "tool_name": proposal.tool_name.value,
                    "status": status.value,
                    "reason_code": reason,
                    "evidence_id": str(decision_evidence_id),
                },
                evidence_id=decision_evidence_id,
                causation_id=decision_id,
                parent_correlation_id=run.id,
                occurred_at=now,
                principal_id=self._principal_id,
            )
            return _Authorization(
                stored.id,
                decision_id,
                status,
                reason,
                decision_evidence_id,
                configuration,
                normalized,
                False,
            )

    def _assert_dispatch_still_authorized(
        self,
        grant: JobLeaseGrant,
        proposal_id: UUID,
    ) -> None:
        now = _as_utc(self._clock())
        with self._factory() as session:
            proposal = session.get(HermesToolProposal, proposal_id)
            if proposal is None:
                raise ScopedToolConflictError("tool proposal is unavailable")
            _proposal_context(session, grant, proposal.run_id, now)
            task = session.get(Task, grant.task_id)
            if task is None or task.state not in _ACTIVE_STATES:
                raise ScopedToolConflictError("tool authorization is no longer current")

    def _terminal_result(
        self,
        proposal_id: UUID,
        external_proposal_id: str,
    ) -> ScopedToolExecutionResult | None:
        with self._factory() as session:
            decision = session.scalar(
                select(HermesToolDecision).where(HermesToolDecision.proposal_id == proposal_id)
            )
            if decision is None:
                return None
            result = session.scalar(
                select(HermesToolResult)
                .where(
                    HermesToolResult.proposal_id == proposal_id,
                    HermesToolResult.status != HermesToolResultStatus.AMBIGUOUS,
                )
                .order_by(HermesToolResult.attempt.desc())
            )
            if result is None:
                return None
            payload = _evidence_payload(session, self._store, result.result_evidence_id)
            raw_result = payload.get("result")
            return ScopedToolExecutionResult(
                external_proposal_id,
                result.status,
                result.code,
                cast(dict[str, object], raw_result if isinstance(raw_result, dict) else {}),
                decision.decision_evidence_id,
                result.result_evidence_id,
                result.diff_evidence_id,
                True,
            )

    def _record_result(
        self,
        authorization: _Authorization,
        *,
        proposal: HermesToolProposalRequest,
        response_status: HostResponseStatus,
        code: str,
        result: dict[str, object],
        replayed: bool,
    ) -> ScopedToolExecutionResult:
        now = _as_utc(self._clock())
        normalized_result = _bounded_result(result)
        result_code = _error_code(code)
        status = {
            HostResponseStatus.OK: HermesToolResultStatus.SUCCEEDED,
            HostResponseStatus.REJECTED: HermesToolResultStatus.REJECTED,
            HostResponseStatus.AMBIGUOUS: HermesToolResultStatus.AMBIGUOUS,
        }[response_status]
        with self._factory() as session, session.begin():
            _begin_serialized(session)
            stored_proposal = session.scalar(
                select(HermesToolProposal)
                .where(HermesToolProposal.id == authorization.proposal_id)
                .with_for_update()
            )
            if stored_proposal is None:
                raise ScopedToolConflictError("tool proposal is unavailable")
            terminal = session.scalar(
                select(HermesToolResult).where(
                    HermesToolResult.proposal_id == authorization.proposal_id,
                    HermesToolResult.status != HermesToolResultStatus.AMBIGUOUS,
                )
            )
            if terminal is not None:
                payload = _evidence_payload(session, self._store, terminal.result_evidence_id)
                stored_result = payload.get("result")
                return ScopedToolExecutionResult(
                    proposal.proposal_id,
                    terminal.status,
                    terminal.code,
                    cast(
                        dict[str, object],
                        stored_result if isinstance(stored_result, dict) else {},
                    ),
                    authorization.decision_evidence_id,
                    terminal.result_evidence_id,
                    terminal.diff_evidence_id,
                    True,
                )
            attempt = (
                int(
                    session.scalar(
                        select(func.count())
                        .select_from(HermesToolResult)
                        .where(HermesToolResult.proposal_id == authorization.proposal_id)
                    )
                    or 0
                )
                + 1
            )
            decision = session.get(HermesToolDecision, authorization.decision_id)
            if decision is None:
                raise ScopedToolConflictError("tool authorization is unavailable")
            if status is HermesToolResultStatus.SUCCEEDED:
                validation_code = _host_result_validation_code(
                    session,
                    decision=decision,
                    tool_name=proposal.tool_name,
                    result=normalized_result,
                )
                if validation_code is not None:
                    status = HermesToolResultStatus.REJECTED
                    result_code = validation_code
                    revision = normalized_result.get("head_sha")
                    normalized_result = {
                        "head_sha": revision if isinstance(revision, str) else None,
                    }
            result_id = uuid5(
                NAMESPACE_URL,
                f"mathews:tool-result:{authorization.proposal_id}:{attempt}",
            )
            result_evidence_id = uuid5(
                NAMESPACE_URL,
                f"mathews:tool-result-evidence:{authorization.proposal_id}:{attempt}",
            )
            repository_revision = normalized_result.get("head_sha")
            if (
                not isinstance(repository_revision, str)
                or _GIT_OBJECT.fullmatch(repository_revision) is None
            ):
                repository_revision = None
            result_payload = {
                "schema_version": 1,
                "proposal_id": proposal.proposal_id,
                "tool_name": proposal.tool_name.value,
                "status": status.value,
                "code": result_code,
                "repository_revision": repository_revision,
                "host_replayed": replayed,
                "result": normalized_result,
            }
            capture_evidence(
                session,
                self._store,
                payload=result_payload,
                media_type="application/json",
                source_kind=EvidenceSourceKind.RESULT,
                evidence_type="hermes-tool-result",
                origin="host-agent:tool-result",
                access_classification=EvidenceAccessClass.TASK_OWNER,
                retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
                owner_id=stored_proposal.owner_id,
                actor_id=self._principal_id,
                root_correlation_id=stored_proposal.root_correlation_id,
                task_id=stored_proposal.task_id,
                causation_id=authorization.decision_id,
                parent_correlation_id=stored_proposal.run_id,
                evidence_id=result_evidence_id,
                captured_at=now,
            )
            raw_diff = normalized_result.get("diff")
            diff_evidence_id: UUID | None = None
            if isinstance(raw_diff, str):
                diff_evidence_id = uuid5(
                    NAMESPACE_URL,
                    f"mathews:tool-diff-evidence:{authorization.proposal_id}:{attempt}",
                )
                capture_evidence(
                    session,
                    self._store,
                    payload={
                        "schema_version": 1,
                        "proposal_id": proposal.proposal_id,
                        "repository_revision": repository_revision,
                        "changed_paths": normalized_result.get("changed_paths", []),
                        "diff": raw_diff,
                    },
                    media_type="application/json",
                    source_kind=EvidenceSourceKind.RESULT,
                    evidence_type="workspace-diff",
                    origin="host-agent:workspace-diff",
                    access_classification=EvidenceAccessClass.TASK_OWNER,
                    retention_policy=EvidenceRetentionClass.TASK_LIFETIME,
                    owner_id=stored_proposal.owner_id,
                    actor_id=self._principal_id,
                    root_correlation_id=stored_proposal.root_correlation_id,
                    task_id=stored_proposal.task_id,
                    causation_id=result_id,
                    parent_correlation_id=authorization.decision_id,
                    evidence_id=diff_evidence_id,
                    captured_at=now,
                )
            session.add(
                HermesToolResult(
                    id=result_id,
                    proposal_id=authorization.proposal_id,
                    attempt=attempt,
                    status=status,
                    code=result_code,
                    repository_revision=repository_revision,
                    result_evidence_id=result_evidence_id,
                    diff_evidence_id=diff_evidence_id,
                    completed_at=now,
                    owner_id=stored_proposal.owner_id,
                    actor_id=self._principal_id,
                    root_correlation_id=stored_proposal.root_correlation_id,
                    causation_id=authorization.decision_id,
                    parent_correlation_id=stored_proposal.run_id,
                )
            )
            task = session.get(Task, stored_proposal.task_id)
            assert task is not None
            _task_event(
                session,
                task=task,
                event_type="HERMES_TOOL_RESULT",
                payload={
                    "schema_version": 1,
                    "proposal_id": proposal.proposal_id,
                    "tool_name": proposal.tool_name.value,
                    "status": status.value,
                    "code": result_code,
                    "repository_revision": repository_revision,
                    "result_evidence_id": str(result_evidence_id),
                    "diff_evidence_id": (
                        None if diff_evidence_id is None else str(diff_evidence_id)
                    ),
                },
                evidence_id=result_evidence_id,
                causation_id=result_id,
                parent_correlation_id=authorization.decision_id,
                occurred_at=now,
                principal_id=self._principal_id,
                extra_evidence_ids=(() if diff_evidence_id is None else (diff_evidence_id,)),
            )
            return ScopedToolExecutionResult(
                proposal.proposal_id,
                status,
                result_code,
                normalized_result,
                authorization.decision_evidence_id,
                result_evidence_id,
                diff_evidence_id,
                False,
            )


def _authorization_decision(
    session: Session,
    *,
    artifact_store: ArtifactStore,
    task: Task,
    run: HermesRun,
    tool_grant: BackgroundJobToolGrant,
    proposal: HermesToolProposalRequest,
) -> tuple[
    HermesToolDecisionStatus,
    str,
    Brief | None,
    ValidatedRepositoryConfiguration | None,
    dict[str, object] | None,
]:
    if task.state not in _ACTIVE_STATES:
        return HermesToolDecisionStatus.DENIED, "TASK_STATE_NOT_ALLOWED", None, None, None
    if tool_grant.revoked_at is not None:
        return HermesToolDecisionStatus.DENIED, "TOOL_GRANT_REVOKED", None, None, None
    scope = tool_grant.capability_scope
    if scope.get("run_id") != str(run.id) or scope.get("task_id") != str(task.id):
        return HermesToolDecisionStatus.DENIED, "TOOL_GRANT_SCOPE_MISMATCH", None, None, None
    template = session.get(PromptTemplateVersion, run.prompt_template_version_id)
    if template is None or template.role != "implementer":
        return HermesToolDecisionStatus.DENIED, "ROLE_NOT_ALLOWED", None, None, None
    policy = session.get(PolicyVersion, run.policy_version_id)
    if policy is None or policy.approved_by is None or policy.approved_at is None:
        return HermesToolDecisionStatus.DENIED, "POLICY_UNAVAILABLE", None, None, None
    policy_tools = _policy_tools(policy)
    required_operation = policy_tools.get(proposal.tool_name.value)
    if required_operation is None:
        return HermesToolDecisionStatus.DENIED, "TOOL_NOT_ALLOWLISTED", None, None, None
    if task.accepted_brief_id is None:
        return HermesToolDecisionStatus.DENIED, "BRIEF_UNAVAILABLE", None, None, None
    brief = session.get(Brief, task.accepted_brief_id)
    if brief is None or brief.task_id != task.id:
        return HermesToolDecisionStatus.DENIED, "BRIEF_UNAVAILABLE", None, None, None
    brief_decision = (
        None
        if task.brief_approval_decision_id is None
        else session.get(BriefApprovalDecision, task.brief_approval_decision_id)
    )
    if (
        brief_decision is None
        or brief_decision.task_id != task.id
        or brief_decision.brief_id != brief.id
        or brief_decision.policy_version_id != run.policy_version_id
        or (
            brief_decision.disposition is BriefDecisionDisposition.HUMAN_APPROVAL_REQUIRED
            and brief_decision.human_response != "APPROVE"
        )
    ):
        return HermesToolDecisionStatus.DENIED, "BRIEF_NOT_APPROVED", brief, None, None
    operations = brief.scope.get("operations")
    if not isinstance(operations, list) or required_operation not in {
        operation.get("operation_id") for operation in operations if isinstance(operation, dict)
    }:
        return HermesToolDecisionStatus.DENIED, "BRIEF_OPERATION_NOT_ALLOWED", brief, None, None
    if task.repository_configuration_id is None:
        return HermesToolDecisionStatus.DENIED, "CONFIGURATION_UNAVAILABLE", brief, None, None
    record = session.get(RepositoryConfiguration, task.repository_configuration_id)
    if (
        record is None
        or record.repository_key != task.repository
        or record.preflight_evidence_id is None
        or session.get(EvidenceRecord, record.preflight_evidence_id) is None
    ):
        return HermesToolDecisionStatus.DENIED, "CONFIGURATION_UNAVAILABLE", brief, None, None
    try:
        configuration = _validated_configuration(record)
        require_preflight_ready(
            session,
            artifact_store,
            repository_key=task.repository,
            configuration_id=record.id,
            configuration_version=record.version,
            configuration_digest=repository_configuration_digest(record),
            resolved_base_sha=task.base_revision,
        )
    except (RepositoryPreflightNotReadyError, ValueError, TypeError):
        return HermesToolDecisionStatus.DENIED, "CONFIGURATION_UNAVAILABLE", brief, None, None
    try:
        normalized = _normalize_arguments(proposal)
    except (ValueError, TypeError):
        return HermesToolDecisionStatus.DENIED, "INVALID_TOOL_ARGUMENTS", brief, None, None
    included = _included_paths(brief)
    proposal_paths = _proposal_paths(proposal.tool_name, normalized)
    if any(not _path_in_scope(path, included) for path in proposal_paths):
        return HermesToolDecisionStatus.DENIED, "PATH_OUTSIDE_BRIEF", brief, None, None
    prohibited = tuple(path.casefold() for path in configuration.prohibited_paths)
    if any(_path_prohibited(path, prohibited) for path in proposal_paths):
        return HermesToolDecisionStatus.DENIED, "PATH_PROHIBITED", brief, None, None
    return HermesToolDecisionStatus.AUTHORIZED, "AUTHORIZED", brief, configuration, normalized


def _proposal_context(
    session: Session,
    grant: JobLeaseGrant,
    run_id: UUID,
    now: datetime,
) -> tuple[HermesRun, Task, BackgroundJobToolGrant]:
    job = session.scalar(
        select(BackgroundJob).where(BackgroundJob.id == grant.job_id).with_for_update()
    )
    lease = session.scalar(
        select(BackgroundJobLease).where(BackgroundJobLease.id == grant.lease_id).with_for_update()
    )
    run = session.scalar(select(HermesRun).where(HermesRun.id == run_id).with_for_update())
    task = session.scalar(select(Task).where(Task.id == grant.task_id).with_for_update())
    if (
        job is None
        or lease is None
        or run is None
        or task is None
        or job.task_id != grant.task_id
        or job.status is not BackgroundJobStatus.RUNNING
        or job.current_lease_id != grant.lease_id
        or job.current_fencing_token != grant.fencing_token
        or job.lease_owner != grant.worker_id
        or job.lease_expires_at is None
        or _as_utc(job.lease_expires_at) <= now
        or job.cancellation_requested_at is not None
        or lease.job_id != grant.job_id
        or lease.lease_owner != grant.worker_id
        or lease.attempt != grant.attempt
        or lease.fencing_token != grant.fencing_token
        or lease.released_at is not None
        or _as_utc(lease.expires_at) <= now
        or run.task_id != grant.task_id
        or run.job_id != grant.job_id
        or run.lease_id != grant.lease_id
        or run.fencing_token != grant.fencing_token
        or run.attempt != grant.attempt
        or run.status is not HermesRunStatus.RUNNING
    ):
        raise ScopedToolConflictError("Hermes tool lease is no longer current")
    tool_grant = session.scalar(
        select(BackgroundJobToolGrant).where(
            BackgroundJobToolGrant.job_id == grant.job_id,
            BackgroundJobToolGrant.lease_id == grant.lease_id,
            BackgroundJobToolGrant.fencing_token == grant.fencing_token,
            BackgroundJobToolGrant.grant_key == f"hermes:{run.id}",
        )
    )
    if tool_grant is None:
        raise ScopedToolConflictError("Hermes tool grant is unavailable")
    return run, task, tool_grant


def _policy_tools(policy: PolicyVersion) -> dict[str, str]:
    raw = policy.workflow_thresholds.get("hermes_tool_policy")
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        return {}
    tools = raw.get("tools")
    if not isinstance(tools, dict) or set(tools) - _TOOLS:
        return {}
    result: dict[str, str] = {}
    for name, operation in tools.items():
        if (
            not isinstance(name, str)
            or not isinstance(operation, str)
            or _IDENTIFIER.fullmatch(operation) is None
        ):
            return {}
        result[name] = operation
    return result


def _normalize_arguments(proposal: HermesToolProposalRequest) -> dict[str, object]:
    arguments = proposal.arguments
    tool = proposal.tool_name
    if tool is ScopedToolName.DIFF:
        if arguments:
            raise ValueError("diff arguments are invalid")
        return {}
    if tool is ScopedToolName.READ_FILE:
        if set(arguments) != {"path"}:
            raise ValueError("read arguments are invalid")
        return {"path": _path(arguments["path"])}
    if tool is ScopedToolName.LIST_FILES:
        if set(arguments) != {"path_prefix", "limit"}:
            raise ValueError("list arguments are invalid")
        return {
            "path_prefix": _path(arguments["path_prefix"], allow_root=True),
            "limit": _limit(arguments["limit"]),
        }
    if tool is ScopedToolName.SEARCH:
        if set(arguments) != {"query", "path_prefix", "limit"}:
            raise ValueError("search arguments are invalid")
        query = arguments["query"]
        if not isinstance(query, str) or not query or len(query.encode()) > 1_000:
            raise ValueError("search query is invalid")
        return {
            "query": query,
            "path_prefix": _path(arguments["path_prefix"], allow_root=True),
            "limit": _limit(arguments["limit"]),
        }
    if tool is ScopedToolName.APPLY_PATCH:
        if set(arguments) != {"changes"}:
            raise ValueError("patch arguments are invalid")
        raw_changes = arguments["changes"]
        if not isinstance(raw_changes, list) or not 0 < len(raw_changes) <= 32:
            raise ValueError("patch changes are invalid")
        changes: list[dict[str, object]] = []
        total = 0
        seen: set[str] = set()
        for raw in raw_changes:
            if not isinstance(raw, dict) or set(raw) != {
                "path",
                "expected_digest",
                "content",
            }:
                raise ValueError("patch change is invalid")
            path = _path(raw["path"])
            digest = raw["expected_digest"]
            content = raw["content"]
            if path in seen:
                raise ValueError("patch path is duplicated")
            seen.add(path)
            if digest is not None and (
                not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None
            ):
                raise ValueError("patch digest is invalid")
            if content is not None and not isinstance(content, str):
                raise ValueError("patch content is invalid")
            if content is None and digest is None:
                raise ValueError("new absent file cannot be deleted")
            total += 0 if content is None else len(content.encode())
            if total > 256 * 1024:
                raise ValueError("patch content is too large")
            changes.append({"path": path, "expected_digest": digest, "content": content})
        return {"changes": changes}
    raise ValueError("tool is unsupported")


def _proposal_paths(tool: ScopedToolName, arguments: Mapping[str, object]) -> tuple[str, ...]:
    if tool is ScopedToolName.DIFF:
        return ()
    if tool in {ScopedToolName.READ_FILE}:
        return (cast(str, arguments["path"]),)
    if tool in {ScopedToolName.LIST_FILES, ScopedToolName.SEARCH}:
        return (cast(str, arguments["path_prefix"]),)
    changes = cast(list[dict[str, object]], arguments["changes"])
    return tuple(cast(str, change["path"]) for change in changes)


def _included_paths(brief: Brief) -> tuple[str, ...]:
    raw = brief.scope.get("included_paths")
    if not isinstance(raw, list):
        return ()
    try:
        return tuple(_path(path, allow_root=True) for path in raw)
    except (TypeError, ValueError):
        return ()


def _path_in_scope(path: str, included: tuple[str, ...]) -> bool:
    candidate = PurePosixPath(path.casefold())
    return any(
        allowed == PurePosixPath(".") or allowed == candidate or allowed in candidate.parents
        for allowed in (PurePosixPath(value.casefold()) for value in included)
    )


def _path_prohibited(path: str, prohibited: tuple[str, ...]) -> bool:
    candidate = PurePosixPath(path.casefold())
    return any(
        denied == candidate or denied in candidate.parents
        for denied in (PurePosixPath(value) for value in prohibited)
    )


def _path(value: object, *, allow_root: bool = False) -> str:
    if not isinstance(value, str) or len(value) > 4_096:
        raise ValueError("path is invalid")
    if allow_root and value == ".":
        return value
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or path.as_posix() != value
        or "\\" in value
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError("path is invalid")
    return value


def _limit(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= 200:
        raise ValueError("limit is invalid")
    return value


def _validated_configuration(record: RepositoryConfiguration) -> ValidatedRepositoryConfiguration:
    return ValidatedRepositoryConfiguration.from_dict(
        record.id,
        {
            "repository_key": record.repository_key,
            "version": record.version,
            "repository_settings": record.repository_settings,
            "git_settings": record.git_settings,
            "xcode_settings": record.xcode_settings,
            "operations": record.operations,
            "e2e_assertions": record.e2e_assertions,
            "artifact_settings": record.artifact_settings,
            "prohibited_paths": record.prohibited_paths,
            "secret_references": record.secret_references,
        },
    )


def _validated_configuration_for_decision(
    session: Session,
    decision: HermesToolDecision,
) -> ValidatedRepositoryConfiguration | None:
    if decision.repository_configuration_id is None:
        return None
    record = session.get(RepositoryConfiguration, decision.repository_configuration_id)
    if record is None:
        raise ScopedToolConflictError("authorized configuration is unavailable")
    return _validated_configuration(record)


def _bounded_result(result: Mapping[str, object]) -> dict[str, object]:
    try:
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        raise ScopedToolConflictError("host tool result is not JSON safe") from None
    if len(encoded.encode()) > 900_000:
        raise ScopedToolConflictError("host tool result exceeds its evidence limit")
    decoded = json.loads(encoded)
    assert isinstance(decoded, dict)
    return cast(dict[str, object], decoded)


def _host_result_validation_code(
    session: Session,
    *,
    decision: HermesToolDecision,
    tool_name: ScopedToolName,
    result: Mapping[str, object],
) -> str | None:
    revision = result.get("head_sha")
    if not isinstance(revision, str) or _GIT_OBJECT.fullmatch(revision) is None:
        return "HOST_RESULT_INVALID"
    brief = None if decision.brief_id is None else session.get(Brief, decision.brief_id)
    if brief is None:
        return "HOST_RESULT_INVALID"
    if tool_name in {ScopedToolName.DIFF, ScopedToolName.APPLY_PATCH} and (
        not isinstance(result.get("diff"), str) or not isinstance(result.get("changed_paths"), list)
    ):
        return "HOST_RESULT_INVALID"
    raw_paths: list[object] = []
    for field in ("files", "changed_paths", "applied_paths"):
        value = result.get(field, [])
        if not isinstance(value, list):
            return "HOST_RESULT_INVALID"
        raw_paths.extend(value)
    path = result.get("path")
    if path is not None:
        raw_paths.append(path)
    matches = result.get("matches", [])
    if not isinstance(matches, list):
        return "HOST_RESULT_INVALID"
    for match in matches:
        if not isinstance(match, dict):
            return "HOST_RESULT_INVALID"
        raw_paths.append(match.get("path"))
    try:
        paths = tuple(_path(value) for value in raw_paths)
    except (TypeError, ValueError):
        return "HOST_RESULT_INVALID"
    included = _included_paths(brief)
    if any(not _path_in_scope(path, included) for path in paths):
        return "HOST_RESULT_OUTSIDE_BRIEF"
    return None


def _fingerprint(value: Mapping[str, object]) -> str:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        raise ScopedToolConflictError("Hermes tool arguments are not JSON safe") from None
    if len(encoded.encode()) > 512 * 1024:
        raise ScopedToolConflictError("Hermes tool arguments exceed their size limit")
    return sha256(encoded.encode()).hexdigest()


def _task_event(
    session: Session,
    *,
    task: Task,
    event_type: str,
    payload: dict[str, object],
    evidence_id: UUID,
    causation_id: UUID,
    parent_correlation_id: UUID,
    occurred_at: datetime,
    principal_id: str,
    extra_evidence_ids: tuple[UUID, ...] = (),
) -> None:
    sequence = (
        int(
            session.scalar(select(func.max(TaskEvent.sequence)).where(TaskEvent.task_id == task.id))
            or 0
        )
        + 1
    )
    event = TaskEvent(
        task_id=task.id,
        sequence=sequence,
        event_type=event_type,
        payload=payload,
        occurred_at=occurred_at,
        owner_id=task.owner_id,
        actor_id=principal_id,
        root_correlation_id=task.root_correlation_id,
        causation_id=causation_id,
        parent_correlation_id=parent_correlation_id,
    )
    session.add(event)
    session.flush()
    for position, reference in enumerate((evidence_id, *extra_evidence_ids), start=1):
        session.add(
            TaskEventEvidenceReference(
                task_id=task.id,
                task_event_id=event.id,
                evidence_id=reference,
                position=position,
                owner_id=task.owner_id,
                actor_id=principal_id,
                root_correlation_id=task.root_correlation_id,
                causation_id=event.id,
                parent_correlation_id=causation_id,
            )
        )


def _evidence_payload(
    session: Session,
    store: ArtifactStore,
    evidence_id: UUID,
) -> dict[str, object]:
    evidence = session.get(EvidenceRecord, evidence_id)
    if evidence is None:
        raise ScopedToolConflictError("tool result evidence is unavailable")
    content = load_evidence(session, store, evidence).content
    if not isinstance(content, dict):
        raise ScopedToolConflictError("tool result evidence is invalid")
    return cast(dict[str, object], content)


def _begin_serialized(session: Session) -> None:
    if session.bind is not None and session.bind.dialect.name == "sqlite":
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _identifier(value: str, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{field} is invalid")
    return value


def _error_code(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[A-Z][A-Z0-9_]{0,99}", value) is None:
        return "HOST_RESPONSE_INVALID"
    return value
