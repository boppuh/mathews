"""Exact-head draft pull-request publication and immutable activation proof."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast
from urllib.parse import urlencode
from uuid import UUID, uuid4

from mathews_configuration import (
    GitHubCredentialPurpose,
    HostOperation,
    HostRequestMessage,
    HostResponseMessage,
    HostResponseStatus,
    JsonValue,
)
from mathews_configuration import (
    RepositoryConfiguration as ValidatedRepositoryConfiguration,
)
from sqlalchemy import exists, select
from sqlalchemy.orm import Session

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.background_jobs import JobLeaseGrant
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    ApprovalRequest,
    ApprovalStatus,
    Brief,
    EvidenceRecord,
    PolicyVersion,
    RepositoryConfiguration,
    Task,
    TaskCancellation,
    TaskState,
    ValidationContract,
    ValidationOutcome,
    ValidationRun,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
    load_evidence,
)
from mathews_control_plane.github_app import (
    GITHUB_API_VERSION,
    GitHubAppCredentialBroker,
    GitHubHttpResponse,
    GitHubHttpTransport,
    UrllibGitHubTransport,
)
from mathews_control_plane.host_gateway import (
    HostGatewayError,
    authority_for_job_lease,
)
from mathews_control_plane.repository_configuration import (
    validated_repository_configuration,
)
from mathews_control_plane.task_state_machine import (
    DraftPrGateFacts,
    TaskTransitionGateEvaluator,
    TaskTransitionGuards,
    TaskTransitionKind,
    TaskTransitionResult,
    TaskTransitionService,
)
from mathews_control_plane.validation_decisioning import ValidationDecisionResult

_SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_BRANCH = re.compile(r"(?!.*(?:\.\.|//|@\{|\\))[A-Za-z0-9][A-Za-z0-9._/-]{0,254}\Z")
_REPOSITORY = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,38})/[a-z0-9](?:[a-z0-9._-]{0,99})\Z")
_PROOF_SCHEMA_VERSION = 1
DRAFT_PULL_REQUEST_PROOF_KEYS = frozenset(
    {
        "schema_version",
        "task_id",
        "brief_id",
        "validation_contract_id",
        "validation_contract_version",
        "repository_configuration_id",
        "repository_configuration_version",
        "validation_run_id",
        "validation_decision_evidence_id",
        "commit_sha",
        "tree_sha",
        "local_before_push",
        "push_result",
        "local_after_push",
        "pull_request",
        "pull_request_content_sha256",
    }
)


class DraftPullRequestError(RuntimeError):
    """Stable fail-closed refusal without repository or credential contents."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class GitHeadObservation:
    branch_name: str
    head_sha: str
    tree_sha: str
    clean: bool
    remote_head_sha: str | None = None


@dataclass(frozen=True, slots=True)
class DraftPullRequestObservation:
    number: int
    url: str
    branch_name: str
    head_sha: str
    is_draft: bool


@dataclass(frozen=True, slots=True)
class DraftPullRequestResult:
    task_id: UUID
    pull_request_number: int
    pull_request_url: str
    head_sha: str
    proof_evidence_id: UUID
    transition: TaskTransitionResult


class ValidationDecisionReader(Protocol):
    def get_exact(
        self, task_id: UUID, *, commit_sha: str, tree_sha: str
    ) -> ValidationDecisionResult: ...


class DraftPullRequestHost(Protocol):
    def inspect(
        self,
        grant: JobLeaseGrant,
        configuration: ValidatedRepositoryConfiguration,
        *,
        idempotency_key: str,
    ) -> GitHeadObservation: ...

    def push(
        self,
        grant: JobLeaseGrant,
        configuration: ValidatedRepositoryConfiguration,
        *,
        expected_head_sha: str,
        idempotency_key: str,
    ) -> GitHeadObservation: ...


class DraftPullRequestPublisher(Protocol):
    def ensure_draft(
        self,
        *,
        branch_name: str,
        base_branch: str,
        title: str,
        body: str,
        expected_head_sha: str,
    ) -> DraftPullRequestObservation: ...

    def observe(self, pull_request_number: int) -> DraftPullRequestObservation: ...


class PullRequestBinder(Protocol):
    def bind_pull_request(
        self,
        task_id: UUID,
        *,
        installation_id: int,
        repository_id: int,
        pull_request_number: int,
        task_branch: str,
        head_sha: str,
        required_checks: Sequence[str],
    ) -> UUID: ...


class PostDraftReadinessReconciler(Protocol):
    def reconcile(
        self,
        task_id: UUID,
        *,
        trigger_event_id: UUID,
    ) -> object: ...


class HostGateway(Protocol):
    def execute(self, request: HostRequestMessage) -> HostResponseMessage: ...


class LeaseBoundDraftPullRequestHost:
    """Issue exact-candidate inspect/push operations through the lease boundary."""

    def __init__(self, gateway: HostGateway, *, clock: Callable[[], datetime] | None = None):
        self._gateway = gateway
        self._clock = clock or (lambda: datetime.now(UTC))

    def inspect(
        self,
        grant: JobLeaseGrant,
        configuration: ValidatedRepositoryConfiguration,
        *,
        idempotency_key: str,
    ) -> GitHeadObservation:
        return self._execute(
            grant,
            configuration,
            operation="git.inspect",
            arguments={"configuration": configuration.to_dict()},
            idempotency_key=idempotency_key,
        )

    def push(
        self,
        grant: JobLeaseGrant,
        configuration: ValidatedRepositoryConfiguration,
        *,
        expected_head_sha: str,
        idempotency_key: str,
    ) -> GitHeadObservation:
        candidate = _sha(expected_head_sha)
        return self._execute(
            grant,
            configuration,
            operation="git.push",
            arguments={
                "configuration": configuration.to_dict(),
                "expected_head_sha": candidate,
            },
            idempotency_key=idempotency_key,
        )

    def _execute(
        self,
        grant: JobLeaseGrant,
        configuration: ValidatedRepositoryConfiguration,
        *,
        operation: str,
        arguments: dict[str, object],
        idempotency_key: str,
    ) -> GitHeadObservation:
        now = _utc(self._clock())
        request = HostRequestMessage(
            request_id=uuid4(),
            issued_at_ms=int(now.timestamp() * 1_000),
            expires_at_ms=int((now + timedelta(seconds=30)).timestamp() * 1_000),
            authority=authority_for_job_lease(grant, configuration=configuration),
            operation=HostOperation(
                name=operation,
                idempotency_key=idempotency_key,
                arguments=cast(dict[str, JsonValue], arguments),
            ),
        )
        try:
            response = self._gateway.execute(request)
        except HostGatewayError:
            raise DraftPullRequestError("HOST_GIT_UNAVAILABLE") from None
        if response.status is not HostResponseStatus.OK:
            raise DraftPullRequestError("HOST_GIT_REJECTED")
        result = response.result
        try:
            branch = _branch(result["branch_name"])
            head = _sha(result["head_sha"])
            tree = _sha(result["tree_sha"])
        except (KeyError, TypeError, DraftPullRequestError):
            raise DraftPullRequestError("HOST_GIT_RESPONSE_INVALID") from None
        if result.get("clean") is not True:
            raise DraftPullRequestError("CANDIDATE_NOT_CLEAN")
        remote = result.get("remote_head_after")
        if operation == "git.push":
            if not isinstance(remote, str):
                raise DraftPullRequestError("REMOTE_HEAD_UNVERIFIED")
            remote = _sha(remote)
        else:
            remote = None
        return GitHeadObservation(branch, head, tree, True, remote)


class GitHubDraftPullRequestPublisher:
    """Reconcile one branch-bound draft PR using a purpose-scoped App token."""

    def __init__(
        self,
        broker: GitHubAppCredentialBroker,
        repository_key: str,
        *,
        transport: GitHubHttpTransport | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self._broker = broker
        normalized_repository = repository_key.strip().lower()
        if _REPOSITORY.fullmatch(normalized_repository) is None:
            raise DraftPullRequestError("GITHUB_REPOSITORY_INVALID")
        if timeout_seconds <= 0 or timeout_seconds > 30:
            raise DraftPullRequestError("GITHUB_TIMEOUT_INVALID")
        self._repository_key = normalized_repository
        self._transport = transport or UrllibGitHubTransport()
        self._timeout = timeout_seconds

    def ensure_draft(
        self,
        *,
        branch_name: str,
        base_branch: str,
        title: str,
        body: str,
        expected_head_sha: str,
    ) -> DraftPullRequestObservation:
        branch = _branch(branch_name)
        base = _branch(base_branch)
        expected = _sha(expected_head_sha)
        owner = self._repository_key.split("/", 1)[0]
        credential = self._broker.mint_installation_token(
            GitHubCredentialPurpose.PULL_REQUEST_WRITE
        )
        try:
            authorization = credential.github_authorization_header()
            observed = self._find_open_branch_draft(
                owner=owner,
                branch=branch,
                base=base,
                authorization=authorization,
            )
            if observed is None:
                try:
                    created = self._json(
                        "POST",
                        f"/repos/{self._repository_key}/pulls",
                        authorization,
                        {
                            "title": title,
                            "head": branch,
                            "base": base,
                            "body": body,
                            "draft": True,
                        },
                        {201},
                    )
                    observed = _pull_request(created, repository_key=self._repository_key)
                except DraftPullRequestError as error:
                    # The POST may have committed even when its response was lost.
                    # Reconcile by exact identity before allowing a retry to create
                    # a duplicate pull request.
                    try:
                        observed = self._find_open_branch_draft(
                            owner=owner,
                            branch=branch,
                            base=base,
                            authorization=authorization,
                        )
                    except DraftPullRequestError as lookup_error:
                        raise error from lookup_error
                    if observed is None:
                        raise error
            _require_pr_head(observed, branch=branch, head_sha=expected)
            return observed
        finally:
            self._broker.revoke_installation_token(credential)

    def observe(self, pull_request_number: int) -> DraftPullRequestObservation:
        if isinstance(pull_request_number, bool) or pull_request_number <= 0:
            raise DraftPullRequestError("PULL_REQUEST_IDENTITY_INVALID")
        credential = self._broker.mint_installation_token(
            GitHubCredentialPurpose.PULL_REQUEST_WRITE
        )
        try:
            value = self._json(
                "GET",
                f"/repos/{self._repository_key}/pulls/{pull_request_number}",
                credential.github_authorization_header(),
                None,
                {200},
            )
            return _pull_request(value, repository_key=self._repository_key)
        finally:
            self._broker.revoke_installation_token(credential)

    def _find_open_branch_draft(
        self,
        *,
        owner: str,
        branch: str,
        base: str,
        authorization: str,
    ) -> DraftPullRequestObservation | None:
        query = urlencode({"state": "open", "head": f"{owner}:{branch}", "base": base})
        values = self._json(
            "GET",
            f"/repos/{self._repository_key}/pulls?{query}",
            authorization,
            None,
            {200},
        )
        if not isinstance(values, list) or len(values) > 1:
            raise DraftPullRequestError("PULL_REQUEST_IDENTITY_AMBIGUOUS")
        return None if not values else _pull_request(values[0], repository_key=self._repository_key)

    def _json(
        self,
        method: str,
        path: str,
        authorization: str,
        body: Mapping[str, object] | None,
        success: set[int],
    ) -> object:
        response: GitHubHttpResponse = self._transport.request(
            method=method,
            path=path,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": authorization,
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
                "User-Agent": "mathews-control-plane",
                **({"Content-Type": "application/json"} if body is not None else {}),
            },
            body=(
                None
                if body is None
                else json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
            ),
            timeout_seconds=self._timeout,
        )
        if response.status_code not in success:
            raise DraftPullRequestError("GITHUB_PULL_REQUEST_UNAVAILABLE")
        if response.content_type is None or "application/json" not in response.content_type:
            raise DraftPullRequestError("GITHUB_PULL_REQUEST_RESPONSE_INVALID")
        try:
            return json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise DraftPullRequestError("GITHUB_PULL_REQUEST_RESPONSE_INVALID") from None


@dataclass(frozen=True, slots=True)
class _TaskContext:
    task_id: UUID
    owner_id: str
    root_correlation_id: UUID
    summary: str
    brief_id: UUID
    contract_id: UUID
    contract_version: int
    configuration_id: UUID
    configuration_version: int
    configuration: ValidatedRepositoryConfiguration
    title: str
    body: str
    required_checks: tuple[str, ...]


class VerifiedDraftPullRequestService:
    """Publish a validated exact head and activate only its immutable proof."""

    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        *,
        validation_decisions: ValidationDecisionReader,
        host: DraftPullRequestHost,
        publisher: DraftPullRequestPublisher,
        binder: PullRequestBinder,
        installation_id: int,
        repository_id: int,
        readiness: PostDraftReadinessReconciler | None = None,
        principal_id: str = "control-plane",
        active_policy_lineage: str = "mvp",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._factory = factory
        self._store = artifact_store
        self._decisions = validation_decisions
        self._host = host
        self._publisher = publisher
        self._binder = binder
        self._installation_id = installation_id
        self._repository_id = repository_id
        if readiness is None:
            from mathews_control_plane.readiness import ReadinessService

            readiness = ReadinessService(
                factory,
                artifact_store,
                principal_id=principal_id,
                active_policy_lineage=active_policy_lineage,
                clock=clock,
            )
        self._readiness = readiness
        self._principal = principal_id
        self._policy_lineage = active_policy_lineage
        self._clock = clock or (lambda: datetime.now(UTC))

    def open(
        self,
        task_id: UUID,
        *,
        commit_sha: str,
        tree_sha: str,
        transition_id: UUID,
        grant_supplier: Callable[[], JobLeaseGrant],
    ) -> DraftPullRequestResult:
        commit, tree = _sha(commit_sha), _sha(tree_sha)
        context = self._context(task_id)
        decision = self._current_pass(context, commit, tree)
        grant = grant_supplier()
        before = self._host.inspect(
            grant,
            context.configuration,
            idempotency_key=f"draft-pr:{transition_id}:before",
        )
        _require_local(before, context, commit, tree)
        pushed = self._host.push(
            grant,
            context.configuration,
            expected_head_sha=commit,
            idempotency_key=f"draft-pr:{transition_id}:push",
        )
        _require_local(pushed, context, commit, tree)
        if pushed.remote_head_sha != commit:
            raise DraftPullRequestError("REMOTE_HEAD_MISMATCH")
        pull_request = self._publisher.ensure_draft(
            branch_name=before.branch_name,
            base_branch=_base_branch(context.configuration),
            title=context.title,
            body=context.body,
            expected_head_sha=commit,
        )
        _require_pr_head(pull_request, branch=before.branch_name, head_sha=commit)
        observed = self._publisher.observe(pull_request.number)
        _require_pr_head(observed, branch=before.branch_name, head_sha=commit)
        after = self._host.inspect(
            grant_supplier(),
            context.configuration,
            idempotency_key=f"draft-pr:{transition_id}:after",
        )
        _require_local(after, context, commit, tree)
        self._current_pass(context, commit, tree)
        proof_id = self._capture_proof(
            context,
            decision,
            before=before,
            pushed=pushed,
            after=after,
            pull_request=observed,
        )
        self._binder.bind_pull_request(
            task_id,
            installation_id=self._installation_id,
            repository_id=self._repository_id,
            pull_request_number=observed.number,
            task_branch=observed.branch_name,
            head_sha=commit,
            required_checks=context.required_checks,
        )
        gates = _DraftProofGates(self._store, proof_id)
        transition = TaskTransitionService(
            self._factory,
            self._store,
            gate_evaluator=gates,
            active_policy_lineage=self._policy_lineage,
            principal_id=self._principal,
            clock=self._clock,
        ).transition(
            task_id,
            transition_id=transition_id,
            expected_state=TaskState.VALIDATING,
            kind=TaskTransitionKind.OPEN_VERIFIED_DRAFT_PR,
            reason_code="VERIFIED_DRAFT_PR_OPENED",
            evidence_ids=(decision.decision_evidence_id, proof_id),
        )
        self._readiness.reconcile(
            task_id,
            trigger_event_id=transition.event_id,
        )
        return DraftPullRequestResult(
            task_id, observed.number, observed.url, commit, proof_id, transition
        )

    def _context(self, task_id: UUID) -> _TaskContext:
        with self._factory() as session:
            task = session.get(Task, task_id)
            if task is None or TaskState(task.state) is not TaskState.VALIDATING:
                raise DraftPullRequestError("TASK_NOT_VALIDATING")
            if (
                task.accepted_brief_id is None
                or task.validation_contract_id is None
                or task.repository_configuration_id is None
            ):
                raise DraftPullRequestError("TASK_BINDINGS_INCOMPLETE")
            brief = session.get(Brief, task.accepted_brief_id)
            contract = session.get(ValidationContract, task.validation_contract_id)
            record = session.get(RepositoryConfiguration, task.repository_configuration_id)
            if (
                brief is None
                or contract is None
                or record is None
                or brief.task_id != task.id
                or contract.task_id != task.id
                or contract.brief_id != brief.id
                or contract.repository_configuration_id != record.id
            ):
                raise DraftPullRequestError("TASK_BINDINGS_INVALID")
            _require_no_human_or_cancel_fence(session, task.id)
            configuration = validated_repository_configuration(record)
            title = task.summary.strip()[:240] or f"Task {task.id}"
            body = _pull_request_body(task, brief, contract)
            return _TaskContext(
                task.id,
                task.owner_id,
                task.root_correlation_id,
                task.summary,
                brief.id,
                contract.id,
                contract.version,
                record.id,
                record.version,
                configuration,
                title,
                body,
                tuple(operation.operation_id for operation in configuration.operations),
            )

    def _current_pass(
        self, context: _TaskContext, commit: str, tree: str
    ) -> ValidationDecisionResult:
        result = self._decisions.get_exact(context.task_id, commit_sha=commit, tree_sha=tree)
        if (
            result.outcome is not ValidationOutcome.PASSED
            or not result.is_current
            or result.commit_sha != commit
            or result.tree_sha != tree
            or result.validation_contract_id != context.contract_id
            or result.validation_contract_version != context.contract_version
            or result.repository_configuration_id != context.configuration_id
            or result.repository_configuration_version != context.configuration_version
        ):
            raise DraftPullRequestError("VALIDATION_PASS_NOT_CURRENT")
        return result

    def _capture_proof(
        self,
        context: _TaskContext,
        decision: ValidationDecisionResult,
        *,
        before: GitHeadObservation,
        pushed: GitHeadObservation,
        after: GitHeadObservation,
        pull_request: DraftPullRequestObservation,
    ) -> UUID:
        now = _utc(self._clock())
        payload = {
            "schema_version": _PROOF_SCHEMA_VERSION,
            "task_id": str(context.task_id),
            "brief_id": str(context.brief_id),
            "validation_contract_id": str(context.contract_id),
            "validation_contract_version": context.contract_version,
            "repository_configuration_id": str(context.configuration_id),
            "repository_configuration_version": context.configuration_version,
            "validation_run_id": str(decision.validation_run_id),
            "validation_decision_evidence_id": str(decision.decision_evidence_id),
            "commit_sha": decision.commit_sha,
            "tree_sha": decision.tree_sha,
            "local_before_push": asdict(before),
            "push_result": asdict(pushed),
            "local_after_push": asdict(after),
            "pull_request": asdict(pull_request),
            "pull_request_content_sha256": hashlib.sha256(
                f"{context.title}\0{context.body}".encode()
            ).hexdigest(),
        }
        with self._factory.begin() as session:
            task = session.get(Task, context.task_id)
            if not _same_context(task, context):
                raise DraftPullRequestError("TASK_BINDINGS_CHANGED")
            _require_no_human_or_cancel_fence(session, context.task_id)
            captured = capture_evidence(
                session,
                self._store,
                payload=payload,
                media_type="application/json",
                source_kind=EvidenceSourceKind.TOOL_OPERATION,
                evidence_type="draft-pull-request-proof",
                origin="control-plane:draft-pull-request",
                access_classification=EvidenceAccessClass.TASK_OWNER,
                retention_policy=EvidenceRetentionClass.AUDIT,
                owner_id=context.owner_id,
                actor_id=self._principal,
                root_correlation_id=context.root_correlation_id,
                task_id=context.task_id,
                validation_run_id=decision.validation_run_id,
                causation_id=decision.decision_evidence_id,
                parent_correlation_id=context.contract_id,
                captured_at=now,
            )
            return captured.record.id


class _DraftProofGates(TaskTransitionGateEvaluator):
    def __init__(self, store: ArtifactStore, proof_id: UUID) -> None:
        self._store = store
        self._proof_id = proof_id

    def evaluate(
        self,
        session: Session,
        task: Task,
        kind: TaskTransitionKind,
        *,
        policy: PolicyVersion,
        now: datetime,
    ) -> TaskTransitionGuards:
        del policy, now
        if kind is not TaskTransitionKind.OPEN_VERIFIED_DRAFT_PR:
            return TaskTransitionGuards()
        record = session.get(EvidenceRecord, self._proof_id)
        if (
            record is None
            or record.task_id != task.id
            or record.evidence_type != "draft-pull-request-proof"
        ):
            return TaskTransitionGuards()
        loaded = load_evidence(session, self._store, record)
        payload = loaded.content
        if (
            not isinstance(payload, dict)
            or set(payload) != DRAFT_PULL_REQUEST_PROOF_KEYS
        ):
            return TaskTransitionGuards()
        try:
            commit = _sha(payload["commit_sha"])
            proof_task_id = _uuid_member(payload, "task_id")
            brief_id = _uuid_member(payload, "brief_id")
            run_id = _uuid_member(payload, "validation_run_id")
            contract_id = _uuid_member(payload, "validation_contract_id")
            config_id = _uuid_member(payload, "repository_configuration_id")
            decision_id = _uuid_member(payload, "validation_decision_evidence_id")
            before = _object_member(payload, "local_before_push")
            pushed = _object_member(payload, "push_result")
            after = _object_member(payload, "local_after_push")
            pull_request = _object_member(payload, "pull_request")
        except (KeyError, TypeError, ValueError, DraftPullRequestError):
            return TaskTransitionGuards()
        run = session.get(ValidationRun, run_id)
        contract = session.get(ValidationContract, contract_id)
        configuration = session.get(RepositoryConfiguration, config_id)
        decision = session.get(EvidenceRecord, decision_id)
        if decision is not None:
            load_evidence(session, self._store, decision)
        valid = (
            payload.get("schema_version") == _PROOF_SCHEMA_VERSION
            and proof_task_id == task.id
            and task.accepted_brief_id is not None
            and brief_id == task.accepted_brief_id
            and task.validation_contract_id == contract_id
            and task.repository_configuration_id == config_id
            and contract is not None
            and contract.task_id == task.id
            and contract.brief_id == task.accepted_brief_id
            and contract.version == payload.get("validation_contract_version")
            and configuration is not None
            and configuration.version == payload.get("repository_configuration_version")
            and run is not None
            and run.task_id == task.id
            and run.validation_contract_id == contract_id
            and run.repository_configuration_id == config_id
            and ValidationOutcome(run.outcome) is ValidationOutcome.PASSED
            and run.commit_sha == commit
            and run.tree_sha == payload.get("tree_sha")
            and decision is not None
            and decision.task_id == task.id
            and decision.validation_run_id == run.id
            and decision.evidence_type == "validation-decision"
            and payload.get("validation_decision_evidence_id") == str(decision.id)
            and isinstance(payload.get("pull_request_content_sha256"), str)
            and re.fullmatch(
                r"[0-9a-f]{64}", cast(str, payload["pull_request_content_sha256"])
            )
            is not None
            and before.get("head_sha") == commit
            and before.get("tree_sha") == run.tree_sha
            and before.get("clean") is True
            and pushed.get("head_sha") == commit
            and pushed.get("tree_sha") == run.tree_sha
            and pushed.get("remote_head_sha") == commit
            and pushed.get("clean") is True
            and after.get("head_sha") == commit
            and after.get("tree_sha") == run.tree_sha
            and after.get("clean") is True
            and pull_request.get("head_sha") == commit
            and pull_request.get("is_draft") is True
            and before.get("branch_name") == pushed.get("branch_name")
            and before.get("branch_name") == after.get("branch_name")
            and before.get("branch_name") == pull_request.get("branch_name")
            and not _human_or_cancel_fence(session, task.id)
        )
        if not valid:
            return TaskTransitionGuards()
        return TaskTransitionGuards(
            draft_pr=DraftPrGateFacts(
                current_head_sha=commit,
                validation_commit_sha=commit,
                local_branch_sha=commit,
                remote_branch_sha=commit,
                pull_request_head_sha=commit,
                validation_passed=True,
                required_artifacts_present=True,
                branch_clean=True,
                pull_request_is_draft=True,
                no_unresolved_approval=True,
                cancellation_clear=True,
            )
        )


def _pull_request_body(task: Task, brief: Brief, contract: ValidationContract) -> str:
    sections = (
        ("Summary", task.summary),
        ("Scope", brief.scope),
        ("Acceptance criteria", brief.acceptance_criteria),
        (
            "Test evidence",
            {
                "required_operations": contract.required_operations,
                "typed_assertions": contract.typed_assertions,
                "evidence_requirements": contract.evidence_requirements,
            },
        ),
        ("Known risks", brief.risks),
    )
    rendered: list[str] = []
    for heading, value in sections:
        content = (
            value
            if isinstance(value, str)
            else f"```json\n{json.dumps(value, indent=2, sort_keys=True)}\n```"
        )
        rendered.append(f"## {heading}\n\n{content}")
    return "\n\n".join(rendered) + "\n"


def _pull_request(value: object, *, repository_key: str) -> DraftPullRequestObservation:
    if not isinstance(value, dict):
        raise DraftPullRequestError("GITHUB_PULL_REQUEST_RESPONSE_INVALID")
    try:
        number = value["number"]
        url = value["html_url"]
        draft = value["draft"]
        state = value["state"]
        head = value["head"]
        branch = head["ref"]
        sha = head["sha"]
    except (KeyError, TypeError):
        raise DraftPullRequestError("GITHUB_PULL_REQUEST_RESPONSE_INVALID") from None
    if (
        isinstance(number, bool)
        or not isinstance(number, int)
        or number <= 0
        or not isinstance(url, str)
        or url != f"https://github.com/{repository_key}/pull/{number}"
        or not isinstance(draft, bool)
        or state != "open"
    ):
        raise DraftPullRequestError("GITHUB_PULL_REQUEST_RESPONSE_INVALID")
    return DraftPullRequestObservation(number, url, _branch(branch), _sha(sha), draft)


def _require_pr_head(value: DraftPullRequestObservation, *, branch: str, head_sha: str) -> None:
    if not value.is_draft or value.branch_name != branch or value.head_sha != head_sha:
        raise DraftPullRequestError("PULL_REQUEST_HEAD_MISMATCH")


def _require_local(
    value: GitHeadObservation, context: _TaskContext, commit: str, tree: str
) -> None:
    expected_branch = context.configuration.git.task_branch_template.format(
        task_id=str(context.task_id)
    )
    if (
        value.branch_name != expected_branch
        or value.head_sha != commit
        or value.tree_sha != tree
        or not value.clean
    ):
        raise DraftPullRequestError("LOCAL_CANDIDATE_MISMATCH")


def _base_branch(configuration: ValidatedRepositoryConfiguration) -> str:
    prefix = f"refs/remotes/{configuration.git.remote_name}/"
    value = configuration.git.default_base_ref
    if not value.startswith(prefix):
        raise DraftPullRequestError("BASE_BRANCH_INVALID")
    return _branch(value.removeprefix(prefix))


def _same_context(task: Task | None, context: _TaskContext) -> bool:
    return bool(
        task is not None
        and TaskState(task.state) is TaskState.VALIDATING
        and task.accepted_brief_id == context.brief_id
        and task.validation_contract_id == context.contract_id
        and task.repository_configuration_id == context.configuration_id
    )


def _human_or_cancel_fence(session: Session, task_id: UUID) -> bool:
    return bool(
        session.scalar(
            select(
                exists().where(
                    ApprovalRequest.task_id == task_id,
                    ApprovalRequest.status == ApprovalStatus.PENDING,
                )
            )
        )
        or session.scalar(select(exists().where(TaskCancellation.task_id == task_id)))
    )


def _uuid_member(payload: Mapping[str, object], key: str) -> UUID:
    value = payload.get(key)
    if not isinstance(value, str):
        raise ValueError("proof UUID member is invalid")
    return UUID(value)


def _object_member(payload: Mapping[str, object], key: str) -> dict[str, object]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise ValueError("proof object member is invalid")
    return cast(dict[str, object], value)


def _require_no_human_or_cancel_fence(session: Session, task_id: UUID) -> None:
    if _human_or_cancel_fence(session, task_id):
        raise DraftPullRequestError("TASK_FENCED")


def _sha(value: object) -> str:
    if not isinstance(value, str):
        raise DraftPullRequestError("GIT_OBJECT_INVALID")
    normalized = value.strip().lower()
    if _SHA.fullmatch(normalized) is None:
        raise DraftPullRequestError("GIT_OBJECT_INVALID")
    return normalized


def _branch(value: object) -> str:
    if not isinstance(value, str) or _BRANCH.fullmatch(value) is None:
        raise DraftPullRequestError("GIT_BRANCH_INVALID")
    return value


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise DraftPullRequestError("CLOCK_INVALID")
    return value.astimezone(UTC)
