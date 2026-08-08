"""Authenticated, allowlist-only dispatch for the local host boundary."""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Mapping
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from types import TracebackType
from typing import TypeVar, cast
from uuid import UUID

from mathews_configuration import (
    RepositoryConfiguration,
    RepositoryConfigurationError,
    SecretProvider,
)
from mathews_configuration.host_protocol import (
    HostAuthorityKind,
    HostMessageAuthenticator,
    HostOperation,
    HostProtocolError,
    HostRequestMessage,
    HostResponseMessage,
    HostResponseStatus,
    JsonValue,
    RepositoryHostAuthority,
    SignedHostRequest,
    SignedHostResponse,
    TaskLeaseHostAuthority,
    normalize_host_json_object,
    validate_host_identifier,
)

from mathews_host_agent import __version__
from mathews_host_agent.execution import (
    ConfiguredExecutionError,
    ConfiguredOperationRunner,
    HostArtifactStore,
)
from mathews_host_agent.git_transport import GitCredentialPushTransport
from mathews_host_agent.journal import (
    HostJournalError,
    HostOperationJournal,
    JournalAction,
    JournalResult,
    OperationStatus,
)
from mathews_host_agent.preflight import RepositoryPreflightRunner
from mathews_host_agent.secrets import KeychainSecretProvider
from mathews_host_agent.workspaces import (
    GitWorkspaceLifecycle,
    WorkspaceLifecycleError,
)

HostOperationHandler = Callable[
    ["HostOperationContext", dict[str, JsonValue]],
    dict[str, JsonValue],
]
HostArgumentValidator = Callable[[dict[str, JsonValue]], dict[str, JsonValue]]
EffectResult = TypeVar("EffectResult")

_GIT_OBJECT_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")

_SAFE_JOURNAL_CODES = frozenset(
    {
        "AUTHORITY_CONFLICT",
        "FENCED",
        "FENCING_TOKEN_CONFLICT",
        "IDEMPOTENCY_CONFLICT",
        "JOURNAL_CORRUPT",
        "JOURNAL_UNAVAILABLE",
        "LEASE_EXPIRED",
        "OPERATION_NOT_RESERVED",
        "REQUEST_ID_CONFLICT",
    }
)


class HostOperationRejected(RuntimeError):
    """An expected operation rejection with a stable public code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class HostEffectAmbiguous(RuntimeError):
    """Carry bounded recovery evidence when a completed effect cannot journal."""

    def __init__(self, result: object) -> None:
        self.result = result
        super().__init__("authorized effect became ambiguous")


class HostTaskGuard:
    """Re-entrant, bounded-stripe guard for one task lease's host effects."""

    def __init__(self, lock: RLock) -> None:
        self._lock = lock

    def __enter__(self) -> None:
        self.acquire()

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.release()

    def acquire(self) -> None:
        self._lock.acquire()

    def release(self) -> None:
        self._lock.release()


class HostExecutionCoordinator:
    """Serialize fence advancement with mutations using a bounded lock set."""

    def __init__(self, *, stripes: int = 64) -> None:
        if stripes <= 0 or stripes > 1024:
            raise ValueError("host execution coordinator stripes are invalid")
        self._stripes = tuple(RLock() for _ in range(stripes))

    def guard(self, request: HostRequestMessage) -> HostTaskGuard:
        authority = request.authority
        if not isinstance(authority, TaskLeaseHostAuthority):
            raise HostOperationRejected("AUTHORITY_NOT_ALLOWED")
        return HostTaskGuard(self._stripes[authority.job_id.int % len(self._stripes)])


@dataclass(slots=True)
class HostOperationContext:
    request: HostRequestMessage
    _journal: HostOperationJournal
    _task_guard: HostTaskGuard | None
    _authorized_effects: int = field(default=0, init=False)
    _effect_attempted: bool = field(default=False, init=False)

    def perform_authorized_effect(
        self,
        effect: Callable[[], EffectResult],
    ) -> EffectResult:
        """Run one narrow host mutation while its durable lease fence is current."""

        if self._task_guard is None:
            raise HostOperationRejected("AUTHORITY_NOT_ALLOWED")
        with self._task_guard:
            self._journal.assert_authorized(self.request)
            self._effect_attempted = True
            result = effect()
            self._journal.assert_authorized(self.request)
        self._authorized_effects += 1
        return result

    def perform_staged_authorized_effect(
        self,
        effect: Callable[[Callable[[], None]], EffectResult],
    ) -> EffectResult:
        """Validate under the fence and mark ambiguity only at mutation start."""

        if self._task_guard is None:
            raise HostOperationRejected("AUTHORITY_NOT_ALLOWED")
        with self._task_guard:
            self._journal.assert_authorized(self.request)

            def mark_effect_attempted() -> None:
                self._effect_attempted = True

            result = effect(mark_effect_attempted)
            self._journal.assert_authorized(self.request)
        self._authorized_effects += 1
        return result

    def perform_renewable_authorized_effect(
        self,
        effect: Callable[
            [Callable[[], None], Callable[[], None], Callable[[], None]],
            EffectResult,
        ],
    ) -> EffectResult:
        """Start under the fence, then permit renewal during a long process."""

        guard = self._task_guard
        if guard is None:
            raise HostOperationRejected("AUTHORITY_NOT_ALLOWED")
        guard.acquire()
        guard_held = True
        try:
            self._journal.assert_authorized(self.request)

            def mark_effect_attempted() -> None:
                self._effect_attempted = True

            def yield_guard() -> None:
                nonlocal guard_held
                if guard_held:
                    guard.release()
                    guard_held = False

            def assert_authorized() -> None:
                with guard:
                    self._journal.assert_authorized(self.request)

            result = effect(mark_effect_attempted, yield_guard, assert_authorized)
        finally:
            if guard_held:
                guard.release()
        try:
            with guard:
                self._journal.assert_authorized(self.request)
        except HostJournalError:
            raise HostEffectAmbiguous(result) from None
        self._authorized_effects += 1
        return result

    def operation_status(
        self,
        *,
        operation_name: str,
        idempotency_key: str,
    ) -> OperationStatus | None:
        """Read bounded reconciliation metadata for this request's scope."""

        return self._journal.status(
            scope_key=HostOperationJournal.scope_key(self.request),
            operation_name=operation_name,
            idempotency_key=idempotency_key,
        )

    @property
    def used_authorized_effect(self) -> bool:
        return self._authorized_effects > 0

    @property
    def effect_attempted(self) -> bool:
        return self._effect_attempted


@dataclass(frozen=True, slots=True)
class HostOperationDefinition:
    authority: HostAuthorityKind
    validate: HostArgumentValidator
    handle: HostOperationHandler
    mutates_host: bool = False


class HostOperationRegistry:
    """Immutable literal-name registry; it has no command fallback."""

    def __init__(
        self,
        definitions: Mapping[str, HostOperationDefinition],
    ) -> None:
        if not definitions:
            raise ValueError("host operation registry must not be empty")
        self._definitions = dict(definitions)
        for name, definition in self._definitions.items():
            HostOperation(
                name=name,
                idempotency_key="registry-validation",
                arguments={},
            )
            if definition.mutates_host and definition.authority is not HostAuthorityKind.TASK_LEASE:
                raise ValueError("mutating host operations require task lease authority")

    def resolve(self, name: str) -> HostOperationDefinition:
        try:
            return self._definitions[name]
        except KeyError:
            raise HostOperationRejected("OPERATION_NOT_ALLOWLISTED") from None

    @property
    def capabilities(self) -> tuple[str, ...]:
        return tuple(sorted(self._definitions))


class HostRequestDispatcher:
    """Verify, fence, journal, and dispatch one signed host request."""

    def __init__(
        self,
        *,
        authenticator: HostMessageAuthenticator,
        journal: HostOperationJournal,
        registry: HostOperationRegistry,
        host_id: str,
        clock_ms: Callable[[], int] | None = None,
        coordinator: HostExecutionCoordinator | None = None,
    ) -> None:
        validate_host_identifier(host_id)
        self._authenticator = authenticator
        self._journal = journal
        self._registry = registry
        self._host_id = host_id
        self._clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)
        self._coordinator = coordinator or HostExecutionCoordinator()

    def dispatch(self, envelope: SignedHostRequest) -> SignedHostResponse:
        request = self._authenticator.verify_request(envelope)
        try:
            definition = self._registry.resolve(request.operation.name)
            if definition.authority is not request.authority.kind:
                raise HostOperationRejected("AUTHORITY_NOT_ALLOWED")
            arguments = definition.validate(request.operation.arguments)
        except HostOperationRejected as error:
            return self._signed_response(
                request,
                status=HostResponseStatus.REJECTED,
                code=error.code,
                result={},
                replayed=False,
            )
        except Exception:
            return self._signed_response(
                request,
                status=HostResponseStatus.REJECTED,
                code="INVALID_ARGUMENTS",
                result={},
                replayed=False,
            )

        task_guard = (
            self._coordinator.guard(request)
            if isinstance(request.authority, TaskLeaseHostAuthority)
            else None
        )
        return self._dispatch_validated(
            request,
            definition=definition,
            arguments=arguments,
            task_guard=task_guard,
        )

    def _dispatch_validated(
        self,
        request: HostRequestMessage,
        *,
        definition: HostOperationDefinition,
        arguments: dict[str, JsonValue],
        task_guard: HostTaskGuard | None,
    ) -> SignedHostResponse:
        try:
            with task_guard or nullcontext():
                decision = self._journal.begin(request)
        except HostJournalError as error:
            return self._signed_response(
                request,
                status=HostResponseStatus.REJECTED,
                code=_safe_journal_code(error),
                result={},
                replayed=False,
            )

        if decision.action is JournalAction.AMBIGUOUS:
            return self._signed_response(
                request,
                status=HostResponseStatus.AMBIGUOUS,
                code="OPERATION_AMBIGUOUS",
                result={},
                replayed=False,
            )
        if decision.action is JournalAction.REPLAY:
            assert decision.result is not None
            return self._signed_response(
                request,
                status=decision.result.status,
                code=decision.result.code,
                result=decision.result.result,
                replayed=True,
                execution_fencing_token=decision.result.execution_fencing_token,
            )

        context = HostOperationContext(
            request=request,
            _journal=self._journal,
            _task_guard=task_guard,
        )
        try:
            result = definition.handle(
                context,
                arguments,
            )
            if definition.mutates_host and not context.used_authorized_effect:
                raise HostOperationRejected("AUTHORIZATION_GUARD_REQUIRED")
            journal_result = JournalResult(
                status=HostResponseStatus.OK,
                code="OK",
                result=normalize_host_json_object(result),
                execution_fencing_token=_fencing_token(request),
            )
        except HostEffectAmbiguous as error:
            return self._ambiguous_response(
                request,
                result=normalize_host_json_object(cast(dict[str, object], error.result)),
            )
        except HostOperationRejected as error:
            journal_result = JournalResult(
                status=HostResponseStatus.REJECTED,
                code=error.code,
                result={},
                execution_fencing_token=_fencing_token(request),
            )
        except HostJournalError as error:
            journal_result = JournalResult(
                status=HostResponseStatus.REJECTED,
                code=_safe_journal_code(error),
                result={},
                execution_fencing_token=_fencing_token(request),
            )
        except Exception:
            journal_result = JournalResult(
                status=HostResponseStatus.REJECTED,
                code="OPERATION_FAILED",
                result={},
                execution_fencing_token=_fencing_token(request),
            )

        if context.effect_attempted and (journal_result.status is not HostResponseStatus.OK):
            return self._ambiguous_response(request)

        try:
            with task_guard or nullcontext():
                self._journal.finish(request, result=journal_result)
        except HostJournalError:
            return self._ambiguous_response(request)
        return self._signed_response(
            request,
            status=journal_result.status,
            code=journal_result.code,
            result=journal_result.result,
            replayed=False,
            execution_fencing_token=journal_result.execution_fencing_token,
        )

    def _ambiguous_response(
        self,
        request: HostRequestMessage,
        *,
        result: dict[str, JsonValue] | None = None,
    ) -> SignedHostResponse:
        return self._signed_response(
            request,
            status=HostResponseStatus.AMBIGUOUS,
            code="OPERATION_AMBIGUOUS",
            result={} if result is None else result,
            replayed=False,
        )

    def _signed_response(
        self,
        request: HostRequestMessage,
        *,
        status: HostResponseStatus,
        code: str,
        result: dict[str, JsonValue],
        replayed: bool,
        execution_fencing_token: int | None = None,
    ) -> SignedHostResponse:
        return self._authenticator.sign_response(
            HostResponseMessage(
                request_id=request.request_id,
                operation_name=request.operation.name,
                idempotency_key=request.operation.idempotency_key,
                host_id=self._host_id,
                host_version=__version__,
                status=status,
                code=code,
                replayed=replayed,
                completed_at_ms=self._clock_ms(),
                execution_fencing_token=execution_fencing_token,
                result=result,
            )
        )


def default_operation_registry(
    *,
    preflight: RepositoryPreflightRunner | None = None,
    workspaces: GitWorkspaceLifecycle | None = None,
    git_credentials: SecretProvider | None = None,
    git_push_transport: GitCredentialPushTransport | None = None,
    configured_execution: ConfiguredOperationRunner | None = None,
) -> HostOperationRegistry:
    runner = preflight or RepositoryPreflightRunner()
    workspace_lifecycle = workspaces or GitWorkspaceLifecycle(
        Path.home() / "Library" / "Application Support" / "Mathews" / "workspaces"
    )
    credential_provider = git_credentials or KeychainSecretProvider()
    push_transport = git_push_transport or GitCredentialPushTransport(
        Path.home() / "Library" / "Application Support" / "Mathews" / "git-helpers"
    )
    default_artifact_store = HostArtifactStore(
        Path.home() / "Library" / "Application Support" / "Mathews" / "validation-artifacts"
    )
    execution_runner = configured_execution or ConfiguredOperationRunner(
        workspace_lifecycle,
        default_artifact_store,
        secrets=credential_provider,
    )
    artifact_store = getattr(
        execution_runner,
        "artifact_store",
        default_artifact_store,
    )

    def health(
        _context: HostOperationContext,
        _arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        return {
            "service": "host-agent",
            "status": "ok",
            "version": __version__,
        }

    def repository_preflight(
        context: HostOperationContext,
        arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        authority = context.request.authority
        if not isinstance(authority, RepositoryHostAuthority):
            raise HostOperationRejected("AUTHORITY_NOT_ALLOWED")
        configuration = _configuration_argument(authority, arguments)
        attempt_id = _uuid_argument(arguments["attempt_id"])
        return cast(
            dict[str, JsonValue],
            runner.run(configuration, attempt_id=attempt_id).to_dict(),
        )

    def workspace_create(
        context: HostOperationContext,
        arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        authority = _task_authority(context)
        configuration = _configuration_argument(authority, arguments)
        try:
            result = context.perform_authorized_effect(
                lambda: workspace_lifecycle.create(authority, configuration)
            )
        except WorkspaceLifecycleError as error:
            raise HostOperationRejected(error.code) from None
        return cast(dict[str, JsonValue], result)

    def workspace_inspect(
        context: HostOperationContext,
        arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        authority = _task_authority(context)
        configuration = _configuration_argument(authority, arguments)
        try:
            result = workspace_lifecycle.inspect(authority, configuration)
        except WorkspaceLifecycleError as error:
            raise HostOperationRejected(error.code) from None
        return cast(dict[str, JsonValue], result)

    def workspace_cleanup(
        context: HostOperationContext,
        arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        authority = _task_authority(context)
        configuration = _configuration_argument(authority, arguments)
        cancellation_id = (
            None
            if arguments["cancellation_id"] is None
            else _uuid_argument(arguments["cancellation_id"])
        )
        try:
            result = context.perform_authorized_effect(
                lambda: workspace_lifecycle.cleanup(
                    authority,
                    configuration,
                    reason=cast(str, arguments["reason"]),
                    cancellation_id=cancellation_id,
                )
            )
        except WorkspaceLifecycleError as error:
            raise HostOperationRejected(error.code) from None
        return cast(dict[str, JsonValue], result)

    def git_inspect(
        context: HostOperationContext,
        arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        authority = _task_authority(context)
        configuration = _configuration_argument(authority, arguments)
        try:
            result = workspace_lifecycle.inspect_git(authority, configuration)
        except WorkspaceLifecycleError as error:
            raise HostOperationRejected(error.code) from None
        return cast(dict[str, JsonValue], result)

    def workspace_list_files(
        context: HostOperationContext,
        arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        authority = _task_authority(context)
        configuration = _configuration_argument(authority, arguments)
        try:
            result = workspace_lifecycle.list_files(
                authority,
                configuration,
                path_prefix=cast(str, arguments["path_prefix"]),
                limit=cast(int, arguments["limit"]),
            )
        except WorkspaceLifecycleError as error:
            raise HostOperationRejected(error.code) from None
        return cast(dict[str, JsonValue], result)

    def workspace_read_file(
        context: HostOperationContext,
        arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        authority = _task_authority(context)
        configuration = _configuration_argument(authority, arguments)
        try:
            result = workspace_lifecycle.read_file(
                authority,
                configuration,
                path=cast(str, arguments["path"]),
            )
        except WorkspaceLifecycleError as error:
            raise HostOperationRejected(error.code) from None
        return cast(dict[str, JsonValue], result)

    def workspace_search(
        context: HostOperationContext,
        arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        authority = _task_authority(context)
        configuration = _configuration_argument(authority, arguments)
        try:
            result = workspace_lifecycle.search_files(
                authority,
                configuration,
                query=cast(str, arguments["query"]),
                path_prefix=cast(str, arguments["path_prefix"]),
                limit=cast(int, arguments["limit"]),
            )
        except WorkspaceLifecycleError as error:
            raise HostOperationRejected(error.code) from None
        return cast(dict[str, JsonValue], result)

    def workspace_diff(
        context: HostOperationContext,
        arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        authority = _task_authority(context)
        configuration = _configuration_argument(authority, arguments)
        try:
            result = workspace_lifecycle.diff_workspace(authority, configuration)
        except WorkspaceLifecycleError as error:
            raise HostOperationRejected(error.code) from None
        return cast(dict[str, JsonValue], result)

    def git_apply_patch(
        context: HostOperationContext,
        arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        authority = _task_authority(context)
        configuration = _configuration_argument(authority, arguments)
        raw_changes = cast(list[JsonValue], arguments["changes"])
        changes = tuple(cast(dict[str, object], change) for change in raw_changes)
        try:
            result = context.perform_authorized_effect(
                lambda: workspace_lifecycle.apply_file_changes(
                    authority,
                    configuration,
                    changes=changes,
                )
            )
        except WorkspaceLifecycleError as error:
            raise HostOperationRejected(error.code) from None
        return cast(dict[str, JsonValue], result)

    def git_commit(
        context: HostOperationContext,
        arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        authority = _task_authority(context)
        configuration = _configuration_argument(authority, arguments)
        try:
            result = context.perform_authorized_effect(
                lambda: workspace_lifecycle.commit_candidate(
                    authority,
                    configuration,
                    expected_head_sha=cast(str, arguments["expected_head_sha"]),
                    message=cast(str, arguments["message"]),
                )
            )
        except WorkspaceLifecycleError as error:
            raise HostOperationRejected(error.code) from None
        return cast(dict[str, JsonValue], result)

    def git_push(
        context: HostOperationContext,
        arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        authority = _task_authority(context)
        configuration = _configuration_argument(authority, arguments)
        credential_reference = configuration.git.push_credential
        if credential_reference is None:
            raise HostOperationRejected("GIT_PUSH_CREDENTIAL_REQUIRED")
        credential = credential_provider.get(credential_reference)
        try:
            result = context.perform_staged_authorized_effect(
                lambda effect_started: workspace_lifecycle.push_candidate(
                    authority,
                    configuration,
                    expected_head_sha=cast(str, arguments["expected_head_sha"]),
                    credential=credential,
                    transport=push_transport,
                    effect_started=effect_started,
                )
            )
        except WorkspaceLifecycleError as error:
            raise HostOperationRejected(error.code) from None
        return cast(dict[str, JsonValue], result)

    def validation_run(
        context: HostOperationContext,
        arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        authority = _task_authority(context)
        configuration = _configuration_argument(authority, arguments)
        try:
            result = context.perform_renewable_authorized_effect(
                lambda effect_started, effect_yielded, assert_authorized: execution_runner.run(
                    authority,
                    configuration,
                    operation_id=cast(str, arguments["operation_id"]),
                    expected_head_sha=cast(str, arguments["expected_head_sha"]),
                    validation_contract_version=cast(
                        int,
                        arguments["validation_contract_version"],
                    ),
                    effect_started=effect_started,
                    effect_yielded=effect_yielded,
                    assert_authorized=assert_authorized,
                )
            )
        except ConfiguredExecutionError as error:
            raise HostOperationRejected(error.code) from None
        return cast(dict[str, JsonValue], result)

    def artifact_read(
        context: HostOperationContext,
        arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        authority = _task_authority(context)
        try:
            result = artifact_store.read_chunk(
                authority.task_id,
                address=cast(str, arguments["address"]),
                offset=cast(int, arguments["offset"]),
                length=cast(int, arguments["length"]),
            )
        except ConfiguredExecutionError as error:
            raise HostOperationRejected(error.code) from None
        return cast(dict[str, JsonValue], result)

    def lease_probe(
        context: HostOperationContext,
        _arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        authority = context.request.authority
        if not isinstance(authority, TaskLeaseHostAuthority):
            raise HostOperationRejected("AUTHORITY_NOT_ALLOWED")
        return {
            "accepted": True,
            "job_id": str(authority.job_id),
            "task_id": str(authority.task_id),
            "fencing_token": authority.fencing_token,
        }

    def reconcile(
        context: HostOperationContext,
        arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        authority = context.request.authority
        if not isinstance(authority, TaskLeaseHostAuthority):
            raise HostOperationRejected("AUTHORITY_NOT_ALLOWED")
        target_name = cast(str, arguments["operation_name"])
        target_key = cast(str, arguments["idempotency_key"])
        status = context.operation_status(
            operation_name=target_name,
            idempotency_key=target_key,
        )
        if status is None:
            return {"found": False}
        return {
            "found": True,
            "state": status.state,
            "request_id": status.request_id,
            "status": None if status.status is None else status.status.value,
            "code": status.code,
            "execution_fencing_token": status.execution_fencing_token,
        }

    return HostOperationRegistry(
        {
            "artifact.read": HostOperationDefinition(
                authority=HostAuthorityKind.TASK_LEASE,
                validate=_validate_artifact_read,
                handle=artifact_read,
            ),
            "git.commit": HostOperationDefinition(
                authority=HostAuthorityKind.TASK_LEASE,
                validate=_validate_git_commit,
                handle=git_commit,
                mutates_host=True,
            ),
            "git.inspect": HostOperationDefinition(
                authority=HostAuthorityKind.TASK_LEASE,
                validate=_validate_configuration,
                handle=git_inspect,
            ),
            "git.apply_patch": HostOperationDefinition(
                authority=HostAuthorityKind.TASK_LEASE,
                validate=_validate_apply_patch,
                handle=git_apply_patch,
                mutates_host=True,
            ),
            "git.push": HostOperationDefinition(
                authority=HostAuthorityKind.TASK_LEASE,
                validate=_validate_git_push,
                handle=git_push,
                mutates_host=True,
            ),
            "host.health": HostOperationDefinition(
                authority=HostAuthorityKind.SYSTEM,
                validate=_validate_empty,
                handle=health,
            ),
            "operation.reconcile": HostOperationDefinition(
                authority=HostAuthorityKind.TASK_LEASE,
                validate=_validate_reconcile,
                handle=reconcile,
            ),
            "repository.preflight": HostOperationDefinition(
                authority=HostAuthorityKind.REPOSITORY,
                validate=_validate_preflight,
                handle=repository_preflight,
            ),
            "task.lease_probe": HostOperationDefinition(
                authority=HostAuthorityKind.TASK_LEASE,
                validate=_validate_empty,
                handle=lease_probe,
            ),
            "validation.run": HostOperationDefinition(
                authority=HostAuthorityKind.TASK_LEASE,
                validate=_validate_validation_run,
                handle=validation_run,
                mutates_host=True,
            ),
            "workspace.cleanup": HostOperationDefinition(
                authority=HostAuthorityKind.TASK_LEASE,
                validate=_validate_workspace_cleanup,
                handle=workspace_cleanup,
                mutates_host=True,
            ),
            "workspace.create": HostOperationDefinition(
                authority=HostAuthorityKind.TASK_LEASE,
                validate=_validate_configuration,
                handle=workspace_create,
                mutates_host=True,
            ),
            "workspace.inspect": HostOperationDefinition(
                authority=HostAuthorityKind.TASK_LEASE,
                validate=_validate_configuration,
                handle=workspace_inspect,
            ),
            "workspace.diff": HostOperationDefinition(
                authority=HostAuthorityKind.TASK_LEASE,
                validate=_validate_configuration,
                handle=workspace_diff,
            ),
            "workspace.list_files": HostOperationDefinition(
                authority=HostAuthorityKind.TASK_LEASE,
                validate=_validate_workspace_list,
                handle=workspace_list_files,
            ),
            "workspace.read_file": HostOperationDefinition(
                authority=HostAuthorityKind.TASK_LEASE,
                validate=_validate_workspace_read,
                handle=workspace_read_file,
            ),
            "workspace.search": HostOperationDefinition(
                authority=HostAuthorityKind.TASK_LEASE,
                validate=_validate_workspace_search,
                handle=workspace_search,
            ),
        }
    )


def _validate_empty(arguments: dict[str, JsonValue]) -> dict[str, JsonValue]:
    if arguments:
        raise HostOperationRejected("INVALID_ARGUMENTS")
    return {}


def _validate_preflight(
    arguments: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    if set(arguments) != {"attempt_id", "configuration"}:
        raise HostOperationRejected("INVALID_ARGUMENTS")
    _uuid_argument(arguments["attempt_id"])
    if not isinstance(arguments["configuration"], dict):
        raise HostOperationRejected("INVALID_ARGUMENTS")
    return arguments


def _validate_configuration(
    arguments: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    if set(arguments) != {"configuration"} or not isinstance(arguments["configuration"], dict):
        raise HostOperationRejected("INVALID_ARGUMENTS")
    return arguments


def _workspace_path_argument(value: JsonValue, *, allow_root: bool = False) -> str:
    if not isinstance(value, str) or len(value) > 4_096:
        raise HostOperationRejected("INVALID_ARGUMENTS")
    if allow_root and value == ".":
        return value
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or any(ord(character) < 32 for character in value)
    ):
        raise HostOperationRejected("INVALID_ARGUMENTS")
    return value


def _bounded_limit(value: JsonValue) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= 200:
        raise HostOperationRejected("INVALID_ARGUMENTS")
    return value


def _validate_workspace_list(
    arguments: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    if set(arguments) != {"configuration", "path_prefix", "limit"}:
        raise HostOperationRejected("INVALID_ARGUMENTS")
    _validate_configuration_field(arguments)
    _workspace_path_argument(arguments["path_prefix"], allow_root=True)
    _bounded_limit(arguments["limit"])
    return arguments


def _validate_workspace_read(
    arguments: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    if set(arguments) != {"configuration", "path"}:
        raise HostOperationRejected("INVALID_ARGUMENTS")
    _validate_configuration_field(arguments)
    _workspace_path_argument(arguments["path"])
    return arguments


def _validate_workspace_search(
    arguments: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    if set(arguments) != {"configuration", "query", "path_prefix", "limit"}:
        raise HostOperationRejected("INVALID_ARGUMENTS")
    _validate_configuration_field(arguments)
    query = arguments["query"]
    if (
        not isinstance(query, str)
        or not query
        or len(query.encode("utf-8")) > 1_000
        or any(ord(character) < 32 and character not in {"\t"} for character in query)
    ):
        raise HostOperationRejected("INVALID_ARGUMENTS")
    _workspace_path_argument(arguments["path_prefix"], allow_root=True)
    _bounded_limit(arguments["limit"])
    return arguments


def _validate_apply_patch(
    arguments: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    if set(arguments) != {"configuration", "changes"}:
        raise HostOperationRejected("INVALID_ARGUMENTS")
    _validate_configuration_field(arguments)
    changes = arguments["changes"]
    if not isinstance(changes, list) or not 0 < len(changes) <= 32:
        raise HostOperationRejected("INVALID_ARGUMENTS")
    total_bytes = 0
    for change in changes:
        if not isinstance(change, dict) or set(change) != {
            "path",
            "expected_digest",
            "content",
        }:
            raise HostOperationRejected("INVALID_ARGUMENTS")
        _workspace_path_argument(change["path"])
        digest = change["expected_digest"]
        content = change["content"]
        if digest is not None and (
            not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
        ):
            raise HostOperationRejected("INVALID_ARGUMENTS")
        if content is not None and not isinstance(content, str):
            raise HostOperationRejected("INVALID_ARGUMENTS")
        if content is None and digest is None:
            raise HostOperationRejected("INVALID_ARGUMENTS")
        if isinstance(content, str):
            total_bytes += len(content.encode("utf-8"))
        if total_bytes > 256 * 1024:
            raise HostOperationRejected("INVALID_ARGUMENTS")
    return arguments


def _validate_workspace_cleanup(
    arguments: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    if set(arguments) != {"configuration", "reason", "cancellation_id"}:
        raise HostOperationRejected("INVALID_ARGUMENTS")
    if not isinstance(arguments["configuration"], dict):
        raise HostOperationRejected("INVALID_ARGUMENTS")
    reason = arguments["reason"]
    cancellation_id = arguments["cancellation_id"]
    if reason not in {"CANCELLED", "COMPLETED"}:
        raise HostOperationRejected("INVALID_ARGUMENTS")
    if reason == "CANCELLED":
        _uuid_argument(cancellation_id)
    elif cancellation_id is not None:
        raise HostOperationRejected("INVALID_ARGUMENTS")
    return arguments


def _validate_git_commit(
    arguments: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    if set(arguments) != {"configuration", "expected_head_sha", "message"}:
        raise HostOperationRejected("INVALID_ARGUMENTS")
    _validate_configuration_field(arguments)
    _git_object_argument(arguments["expected_head_sha"])
    message = arguments["message"]
    if (
        not isinstance(message, str)
        or not message
        or message.strip() != message
        or len(message) > 255
        or not message.isprintable()
        or "\n" in message
        or "\r" in message
    ):
        raise HostOperationRejected("INVALID_ARGUMENTS")
    return arguments


def _validate_git_push(
    arguments: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    if set(arguments) != {"configuration", "expected_head_sha"}:
        raise HostOperationRejected("INVALID_ARGUMENTS")
    _validate_configuration_field(arguments)
    _git_object_argument(arguments["expected_head_sha"])
    return arguments


def _validate_validation_run(
    arguments: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    if set(arguments) != {
        "configuration",
        "expected_head_sha",
        "operation_id",
        "validation_contract_version",
    }:
        raise HostOperationRejected("INVALID_ARGUMENTS")
    _validate_configuration_field(arguments)
    _git_object_argument(arguments["expected_head_sha"])
    operation_id = arguments["operation_id"]
    contract_version = arguments["validation_contract_version"]
    if (
        not isinstance(operation_id, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}", operation_id) is None
        or isinstance(contract_version, bool)
        or not isinstance(contract_version, int)
        or not 0 < contract_version <= 2_147_483_647
    ):
        raise HostOperationRejected("INVALID_ARGUMENTS")
    return arguments


def _validate_artifact_read(
    arguments: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    if set(arguments) != {"address", "offset", "length"}:
        raise HostOperationRejected("INVALID_ARGUMENTS")
    address = arguments["address"]
    offset = arguments["offset"]
    length = arguments["length"]
    if (
        not isinstance(address, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", address) is None
        or isinstance(offset, bool)
        or not isinstance(offset, int)
        or offset < 0
        or isinstance(length, bool)
        or not isinstance(length, int)
        or not 0 < length <= 256 * 1024
    ):
        raise HostOperationRejected("INVALID_ARGUMENTS")
    return arguments


def _validate_configuration_field(arguments: dict[str, JsonValue]) -> None:
    if not isinstance(arguments["configuration"], dict):
        raise HostOperationRejected("INVALID_ARGUMENTS")


def _git_object_argument(value: JsonValue) -> str:
    if not isinstance(value, str) or _GIT_OBJECT_PATTERN.fullmatch(value) is None:
        raise HostOperationRejected("INVALID_ARGUMENTS")
    return value


def _configuration_argument(
    authority: RepositoryHostAuthority | TaskLeaseHostAuthority,
    arguments: dict[str, JsonValue],
) -> RepositoryConfiguration:
    raw_configuration = arguments["configuration"]
    assert isinstance(raw_configuration, dict)
    try:
        configuration = RepositoryConfiguration.from_dict(
            authority.configuration_id,
            raw_configuration,
        )
    except RepositoryConfigurationError:
        raise HostOperationRejected("INVALID_CONFIGURATION") from None
    if (
        configuration.repository_key != authority.repository_key
        or configuration.digest != authority.configuration_digest
    ):
        raise HostOperationRejected("CONFIGURATION_BINDING_MISMATCH")
    return configuration


def _task_authority(context: HostOperationContext) -> TaskLeaseHostAuthority:
    authority = context.request.authority
    if not isinstance(authority, TaskLeaseHostAuthority):
        raise HostOperationRejected("AUTHORITY_NOT_ALLOWED")
    return authority


def _validate_reconcile(
    arguments: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    if set(arguments) != {"operation_name", "idempotency_key"}:
        raise HostOperationRejected("INVALID_ARGUMENTS")
    for field_name in ("operation_name", "idempotency_key"):
        value = arguments[field_name]
        if not isinstance(value, str):
            raise HostOperationRejected("INVALID_ARGUMENTS")
    try:
        HostOperation(
            name=cast(str, arguments["operation_name"]),
            idempotency_key=cast(str, arguments["idempotency_key"]),
            arguments={},
        )
    except HostProtocolError:
        raise HostOperationRejected("INVALID_ARGUMENTS") from None
    return arguments


def _uuid_argument(value: JsonValue) -> UUID:
    if not isinstance(value, str):
        raise HostOperationRejected("INVALID_ARGUMENTS")
    try:
        identifier = UUID(value)
    except ValueError:
        raise HostOperationRejected("INVALID_ARGUMENTS") from None
    if str(identifier) != value:
        raise HostOperationRejected("INVALID_ARGUMENTS")
    return identifier


def _fencing_token(request: HostRequestMessage) -> int | None:
    if isinstance(request.authority, TaskLeaseHostAuthority):
        return request.authority.fencing_token
    return None


def _safe_journal_code(error: HostJournalError) -> str:
    if error.code in _SAFE_JOURNAL_CODES:
        return error.code
    return "JOURNAL_UNAVAILABLE"
