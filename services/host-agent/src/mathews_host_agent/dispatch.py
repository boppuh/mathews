"""Authenticated, allowlist-only dispatch for the local host boundary."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from contextlib import nullcontext
from dataclasses import dataclass, field
from threading import RLock
from types import TracebackType
from typing import TypeVar, cast
from uuid import UUID

from mathews_configuration import RepositoryConfiguration, RepositoryConfigurationError
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
from mathews_host_agent.journal import (
    HostJournalError,
    HostOperationJournal,
    JournalAction,
    JournalResult,
    OperationStatus,
)
from mathews_host_agent.preflight import RepositoryPreflightRunner

HostOperationHandler = Callable[
    ["HostOperationContext", dict[str, JsonValue]],
    dict[str, JsonValue],
]
HostArgumentValidator = Callable[[dict[str, JsonValue]], dict[str, JsonValue]]
EffectResult = TypeVar("EffectResult")

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


class HostTaskGuard:
    """Re-entrant, bounded-stripe guard for one task lease's host effects."""

    def __init__(self, lock: RLock) -> None:
        self._lock = lock

    def __enter__(self) -> None:
        self._lock.acquire()

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
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
    ) -> SignedHostResponse:
        return self._signed_response(
            request,
            status=HostResponseStatus.AMBIGUOUS,
            code="OPERATION_AMBIGUOUS",
            result={},
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
) -> HostOperationRegistry:
    runner = preflight or RepositoryPreflightRunner()

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
        attempt_id = _uuid_argument(arguments["attempt_id"])
        return cast(
            dict[str, JsonValue],
            runner.run(configuration, attempt_id=attempt_id).to_dict(),
        )

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
