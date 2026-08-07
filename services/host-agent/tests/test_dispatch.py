import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import replace
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import mathews_host_agent.dispatch as dispatch_module
import pytest
from mathews_configuration import (
    HostAuthorityKind,
    HostMessageAuthenticator,
    HostOperation,
    HostProtocolError,
    HostRequestMessage,
    HostResponseStatus,
    JsonValue,
    RepositoryHostAuthority,
    SecretProvider,
    SecretReference,
    SecretValue,
    SystemHostAuthority,
    TaskLeaseHostAuthority,
)
from mathews_host_agent.dispatch import (
    HostOperationContext,
    HostOperationDefinition,
    HostOperationRegistry,
    HostRequestDispatcher,
    default_operation_registry,
)
from mathews_host_agent.git_transport import GitCredentialPushTransport
from mathews_host_agent.journal import (
    HostJournalError,
    HostOperationJournal,
    JournalResult,
)
from mathews_host_agent.preflight import RepositoryPreflightRunner
from mathews_host_agent.workspaces import GitWorkspaceLifecycle

NOW_MS = 1_800_000_000_000


def _runtime_directory(tmp_path: Path) -> Path:
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    return runtime


def _authenticator() -> HostMessageAuthenticator:
    return HostMessageAuthenticator(
        SecretValue("a" * 32),
        key_id="control-plane-v1",
        clock_ms=lambda: NOW_MS,
    )


def _task_authority(
    *,
    lease_id: UUID | None = None,
    worker_id: str = "worker-1",
    attempt: int = 1,
    fencing_token: int = 1,
    lease_expires_at_ms: int = NOW_MS + 60_000,
) -> TaskLeaseHostAuthority:
    return TaskLeaseHostAuthority(
        task_id=UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        job_id=UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
        lease_id=lease_id or UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
        worker_id=worker_id,
        attempt=attempt,
        fencing_token=fencing_token,
        lease_expires_at_ms=lease_expires_at_ms,
        repository_key="boppuh/mathews",
        configuration_id=UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
        configuration_digest="sha256:" + "1" * 64,
    )


def _request(
    *,
    name: str = "test.execute",
    authority: SystemHostAuthority | TaskLeaseHostAuthority | None = None,
    idempotency_key: str = "operation-1",
    arguments: dict[str, JsonValue] | None = None,
) -> HostRequestMessage:
    return HostRequestMessage(
        request_id=uuid4(),
        issued_at_ms=NOW_MS,
        expires_at_ms=NOW_MS + 10_000,
        authority=authority or _task_authority(),
        operation=HostOperation(
            name=name,
            idempotency_key=idempotency_key,
            arguments=arguments or {},
        ),
    )


def _empty(arguments: dict[str, JsonValue]) -> dict[str, JsonValue]:
    if arguments:
        raise ValueError("unexpected arguments")
    return arguments


def _dispatcher(
    tmp_path: Path,
    handler: Callable[
        [HostOperationContext, dict[str, JsonValue]],
        dict[str, JsonValue],
    ],
    *,
    mutates_host: bool = False,
) -> tuple[HostRequestDispatcher, HostMessageAuthenticator]:
    authenticator = _authenticator()
    journal = HostOperationJournal(
        _runtime_directory(tmp_path) / "journal.sqlite3",
        clock_ms=lambda: NOW_MS,
    )
    registry = HostOperationRegistry(
        {
            "test.execute": HostOperationDefinition(
                authority=HostAuthorityKind.TASK_LEASE,
                validate=_empty,
                handle=handler,
                mutates_host=mutates_host,
            )
        }
    )
    return (
        HostRequestDispatcher(
            authenticator=authenticator,
            journal=journal,
            registry=registry,
            host_id="host-1",
            clock_ms=lambda: NOW_MS,
        ),
        authenticator,
    )


def test_authenticated_dispatch_executes_once_and_replays_signed_result(
    tmp_path: Path,
) -> None:
    invocations = 0

    def handler(
        _context: HostOperationContext,
        _arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        nonlocal invocations
        invocations += 1
        return {"value": 42}

    dispatcher, authenticator = _dispatcher(tmp_path, handler)
    first_request = _request()
    first = authenticator.verify_response(
        dispatcher.dispatch(authenticator.sign_request(first_request))
    )
    retry = authenticator.verify_response(
        dispatcher.dispatch(authenticator.sign_request(replace(first_request, request_id=uuid4())))
    )

    assert invocations == 1
    assert first.status is HostResponseStatus.OK
    assert first.replayed is False
    assert first.execution_fencing_token == 1
    assert retry.result == {"value": 42}
    assert retry.replayed is True


def test_wrong_authentication_never_reaches_handler(tmp_path: Path) -> None:
    invoked = False

    def handler(
        _context: HostOperationContext,
        _arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        nonlocal invoked
        invoked = True
        return {}

    dispatcher, _authenticator_value = _dispatcher(tmp_path, handler)
    wrong_authenticator = HostMessageAuthenticator(
        SecretValue("b" * 32),
        key_id="control-plane-v1",
        clock_ms=lambda: NOW_MS,
    )

    with pytest.raises(HostProtocolError, match="UNAUTHENTICATED"):
        dispatcher.dispatch(wrong_authenticator.sign_request(_request()))
    assert invoked is False


def test_unknown_operation_authority_mismatch_and_arguments_fail_closed(
    tmp_path: Path,
) -> None:
    authenticator = _authenticator()
    journal = HostOperationJournal(
        _runtime_directory(tmp_path) / "journal.sqlite3",
        clock_ms=lambda: NOW_MS,
    )
    dispatcher = HostRequestDispatcher(
        authenticator=authenticator,
        journal=journal,
        registry=default_operation_registry(),
        host_id="host-1",
        clock_ms=lambda: NOW_MS,
    )
    requests = (
        _request(name="host.shell", authority=SystemHostAuthority()),
        _request(name="host.health"),
        _request(
            name="host.health",
            authority=SystemHostAuthority(),
            arguments={"command": "rm -rf /"},
        ),
    )

    responses = [
        authenticator.verify_response(dispatcher.dispatch(authenticator.sign_request(request)))
        for request in requests
    ]

    assert [response.code for response in responses] == [
        "OPERATION_NOT_ALLOWLISTED",
        "AUTHORITY_NOT_ALLOWED",
        "INVALID_ARGUMENTS",
    ]
    assert all(response.status is HostResponseStatus.REJECTED for response in responses)


def test_unexpected_handler_failure_returns_no_exception_or_secret_text(
    tmp_path: Path,
) -> None:
    def handler(
        _context: HostOperationContext,
        _arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        raise RuntimeError("secret-value-from-local-machine")

    dispatcher, authenticator = _dispatcher(tmp_path, handler)

    response = authenticator.verify_response(
        dispatcher.dispatch(authenticator.sign_request(_request()))
    )

    assert response.status is HostResponseStatus.REJECTED
    assert response.code == "OPERATION_FAILED"
    assert response.result == {}
    assert "secret-value" not in repr(response)


def test_non_json_handler_result_fails_closed_without_poisoning_response(
    tmp_path: Path,
) -> None:
    def handler(
        _context: HostOperationContext,
        _arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        return cast(dict[str, JsonValue], {"unsupported": 1.5})

    dispatcher, authenticator = _dispatcher(tmp_path, handler)

    response = authenticator.verify_response(
        dispatcher.dispatch(authenticator.sign_request(_request()))
    )

    assert response.status is HostResponseStatus.REJECTED
    assert response.code == "OPERATION_FAILED"
    assert response.result == {}


def test_new_fence_rejects_stale_worker_before_a_new_operation(
    tmp_path: Path,
) -> None:
    def handler(
        _context: HostOperationContext,
        _arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        return {"executed": True}

    dispatcher, authenticator = _dispatcher(tmp_path, handler)
    first = _request(idempotency_key="first")
    dispatcher.dispatch(authenticator.sign_request(first))
    takeover_authority = _task_authority(
        lease_id=uuid4(),
        worker_id="worker-2",
        attempt=2,
        fencing_token=2,
    )
    dispatcher.dispatch(
        authenticator.sign_request(
            _request(
                authority=takeover_authority,
                idempotency_key="takeover",
            )
        )
    )

    stale = authenticator.verify_response(
        dispatcher.dispatch(
            authenticator.sign_request(
                _request(
                    authority=_task_authority(fencing_token=1),
                    idempotency_key="stale",
                )
            )
        )
    )

    assert stale.status is HostResponseStatus.REJECTED
    assert stale.code == "FENCED"


def test_mutation_and_fence_takeover_are_serialized_at_effect_boundary(
    tmp_path: Path,
) -> None:
    first_entered = threading.Event()
    release_first = threading.Event()
    order: list[str] = []

    def handler(
        context: HostOperationContext,
        _arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        authority = cast(TaskLeaseHostAuthority, context.request.authority)

        def effect() -> None:
            if authority.fencing_token == 1:
                first_entered.set()
                assert release_first.wait(timeout=2)
            order.append(f"effect-{authority.fencing_token}")

        context.perform_authorized_effect(effect)
        return {"token": authority.fencing_token}

    dispatcher, authenticator = _dispatcher(
        tmp_path,
        handler,
        mutates_host=True,
    )
    first = _request(idempotency_key="first-mutation")
    takeover = _request(
        authority=_task_authority(
            lease_id=uuid4(),
            worker_id="worker-2",
            attempt=2,
            fencing_token=2,
        ),
        idempotency_key="takeover-mutation",
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(
            dispatcher.dispatch,
            authenticator.sign_request(first),
        )
        assert first_entered.wait(timeout=2)
        takeover_future = executor.submit(
            dispatcher.dispatch,
            authenticator.sign_request(takeover),
        )
        with pytest.raises(FutureTimeout):
            takeover_future.result(timeout=0.05)
        release_first.set()
        first_response = authenticator.verify_response(first_future.result(timeout=2))
        takeover_response = authenticator.verify_response(takeover_future.result(timeout=2))

    assert order == ["effect-1", "effect-2"]
    assert first_response.status in {
        HostResponseStatus.OK,
        HostResponseStatus.AMBIGUOUS,
    }
    assert takeover_response.status is HostResponseStatus.OK


def test_failure_after_an_effect_attempt_remains_ambiguous(
    tmp_path: Path,
) -> None:
    effects: list[str] = []

    def handler(
        context: HostOperationContext,
        _arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        context.perform_authorized_effect(lambda: effects.append("executed"))
        raise RuntimeError("failure after mutation")

    dispatcher, authenticator = _dispatcher(
        tmp_path,
        handler,
        mutates_host=True,
    )
    request = _request()

    first = authenticator.verify_response(dispatcher.dispatch(authenticator.sign_request(request)))
    retry = authenticator.verify_response(
        dispatcher.dispatch(authenticator.sign_request(replace(request, request_id=uuid4())))
    )

    assert effects == ["executed"]
    assert first.status is HostResponseStatus.AMBIGUOUS
    assert first.code == "OPERATION_AMBIGUOUS"
    assert retry.status is HostResponseStatus.AMBIGUOUS
    assert retry.code == "OPERATION_AMBIGUOUS"


def test_finish_failure_remains_ambiguous_without_an_effect(
    tmp_path: Path,
) -> None:
    invocations = 0
    authenticator = _authenticator()

    class FinishFailingJournal(HostOperationJournal):
        def finish(
            self,
            request: HostRequestMessage,
            *,
            result: JournalResult,
        ) -> None:
            raise HostJournalError("JOURNAL_UNAVAILABLE")

    def handler(
        _context: HostOperationContext,
        _arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        nonlocal invocations
        invocations += 1
        return {"value": 42}

    dispatcher = HostRequestDispatcher(
        authenticator=authenticator,
        journal=FinishFailingJournal(
            _runtime_directory(tmp_path) / "journal.sqlite3",
            clock_ms=lambda: NOW_MS,
        ),
        registry=HostOperationRegistry(
            {
                "test.execute": HostOperationDefinition(
                    authority=HostAuthorityKind.TASK_LEASE,
                    validate=_empty,
                    handle=handler,
                )
            }
        ),
        host_id="host-1",
        clock_ms=lambda: NOW_MS,
    )
    request = _request()

    first = authenticator.verify_response(dispatcher.dispatch(authenticator.sign_request(request)))
    retry = authenticator.verify_response(
        dispatcher.dispatch(authenticator.sign_request(replace(request, request_id=uuid4())))
    )

    assert invocations == 1
    assert first.status is HostResponseStatus.AMBIGUOUS
    assert first.code == "OPERATION_AMBIGUOUS"
    assert retry.status is HostResponseStatus.AMBIGUOUS
    assert retry.code == "OPERATION_AMBIGUOUS"


def test_same_lease_can_renew_while_mutating_handler_is_between_effects(
    tmp_path: Path,
) -> None:
    clock = [NOW_MS]
    authenticator = HostMessageAuthenticator(
        SecretValue("a" * 32),
        key_id="control-plane-v1",
        clock_ms=lambda: clock[0],
    )
    journal = HostOperationJournal(
        _runtime_directory(tmp_path) / "journal.sqlite3",
        clock_ms=lambda: clock[0],
    )
    effect_completed = threading.Event()
    release_mutation = threading.Event()

    def mutation(
        context: HostOperationContext,
        _arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        context.perform_authorized_effect(lambda: None)
        effect_completed.set()
        assert release_mutation.wait(timeout=2)
        return {"mutated": True}

    dispatcher = HostRequestDispatcher(
        authenticator=authenticator,
        journal=journal,
        registry=HostOperationRegistry(
            {
                "test.execute": HostOperationDefinition(
                    authority=HostAuthorityKind.TASK_LEASE,
                    validate=_empty,
                    handle=mutation,
                    mutates_host=True,
                ),
                "test.renew": HostOperationDefinition(
                    authority=HostAuthorityKind.TASK_LEASE,
                    validate=_empty,
                    handle=lambda _context, _arguments: {"renewed": True},
                ),
            }
        ),
        host_id="host-1",
        clock_ms=lambda: clock[0],
    )
    initial_authority = _task_authority(lease_expires_at_ms=NOW_MS + 10)
    mutation_request = _request(
        authority=initial_authority,
        idempotency_key="mutation",
    )
    renewed_authority = replace(
        initial_authority,
        lease_expires_at_ms=NOW_MS + 100,
    )
    renewal_request = _request(
        name="test.renew",
        authority=renewed_authority,
        idempotency_key="renewal",
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        mutation_future = executor.submit(
            dispatcher.dispatch,
            authenticator.sign_request(mutation_request),
        )
        assert effect_completed.wait(timeout=2)
        clock[0] = NOW_MS + 5
        renewal_future = executor.submit(
            dispatcher.dispatch,
            authenticator.sign_request(renewal_request),
        )
        try:
            renewal_response = authenticator.verify_response(renewal_future.result(timeout=0.5))
            clock[0] = NOW_MS + 20
        finally:
            release_mutation.set()
        mutation_response = authenticator.verify_response(mutation_future.result(timeout=2))

    assert renewal_response.status is HostResponseStatus.OK
    assert mutation_response.status is HostResponseStatus.OK


def test_mutating_handler_must_use_authorized_effect_guard(
    tmp_path: Path,
) -> None:
    dispatcher, authenticator = _dispatcher(
        tmp_path,
        lambda _context, _arguments: {"unguarded": True},
        mutates_host=True,
    )

    response = authenticator.verify_response(
        dispatcher.dispatch(authenticator.sign_request(_request()))
    )

    assert response.status is HostResponseStatus.REJECTED
    assert response.code == "AUTHORIZATION_GUARD_REQUIRED"


def test_registry_rejects_mutation_without_task_lease_authority() -> None:
    with pytest.raises(ValueError, match="task lease authority"):
        HostOperationRegistry(
            {
                "test.execute": HostOperationDefinition(
                    authority=HostAuthorityKind.SYSTEM,
                    validate=_empty,
                    handle=lambda _context, _arguments: {},
                    mutates_host=True,
                )
            }
        )


def test_handler_crossing_lease_expiry_cannot_commit(tmp_path: Path) -> None:
    clock = [NOW_MS]
    invocations = 0
    authenticator = HostMessageAuthenticator(
        SecretValue("a" * 32),
        key_id="control-plane-v1",
        clock_ms=lambda: clock[0],
    )
    journal = HostOperationJournal(
        _runtime_directory(tmp_path) / "journal.sqlite3",
        clock_ms=lambda: clock[0],
    )

    def cross_expiry(
        _context: HostOperationContext,
        _arguments: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        nonlocal invocations
        invocations += 1
        clock[0] = NOW_MS + 61_000
        return {"must_not_commit": True}

    dispatcher = HostRequestDispatcher(
        authenticator=authenticator,
        journal=journal,
        registry=HostOperationRegistry(
            {
                "test.execute": HostOperationDefinition(
                    authority=HostAuthorityKind.TASK_LEASE,
                    validate=_empty,
                    handle=cross_expiry,
                )
            }
        ),
        host_id="host-1",
        clock_ms=lambda: clock[0],
    )
    request = _request()

    response = authenticator.verify_response(
        dispatcher.dispatch(authenticator.sign_request(request))
    )
    clock[0] = NOW_MS
    retry = authenticator.verify_response(
        dispatcher.dispatch(authenticator.sign_request(replace(request, request_id=uuid4())))
    )

    assert invocations == 1
    assert response.status is HostResponseStatus.AMBIGUOUS
    assert response.code == "OPERATION_AMBIGUOUS"
    assert response.result == {}
    assert retry.status is HostResponseStatus.AMBIGUOUS
    assert retry.code == "OPERATION_AMBIGUOUS"


def test_default_registry_exposes_only_typed_non_shell_capabilities() -> None:
    registry = default_operation_registry()

    assert registry.capabilities == (
        "git.commit",
        "git.inspect",
        "git.push",
        "host.health",
        "operation.reconcile",
        "repository.preflight",
        "task.lease_probe",
        "workspace.cleanup",
        "workspace.create",
        "workspace.inspect",
    )
    assert all(
        forbidden not in capability
        for capability in registry.capabilities
        for forbidden in ("command", "exec", "shell")
    )


def test_health_is_a_system_authority_operation(tmp_path: Path) -> None:
    authenticator = _authenticator()
    dispatcher = HostRequestDispatcher(
        authenticator=authenticator,
        journal=HostOperationJournal(
            _runtime_directory(tmp_path) / "journal.sqlite3",
            clock_ms=lambda: NOW_MS,
        ),
        registry=default_operation_registry(),
        host_id="host-1",
        clock_ms=lambda: NOW_MS,
    )
    request = _request(
        name="host.health",
        authority=SystemHostAuthority(),
    )

    response = authenticator.verify_response(
        dispatcher.dispatch(authenticator.sign_request(request))
    )

    assert response.status is HostResponseStatus.OK
    assert response.result == {
        "service": "host-agent",
        "status": "ok",
        "version": "0.1.0",
    }


def test_repository_preflight_binds_typed_configuration_to_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration_id = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
    attempt_id = uuid4()
    calls: list[tuple[object, UUID]] = []

    class FakeConfiguration:
        repository_key = "boppuh/mathews"
        digest = "sha256:" + "1" * 64

    class FakeConfigurationFactory:
        @staticmethod
        def from_dict(
            received_configuration_id: UUID,
            value: object,
        ) -> FakeConfiguration:
            assert received_configuration_id == configuration_id
            assert value == {"typed": "configuration"}
            return FakeConfiguration()

    class FakeReport:
        def to_dict(self) -> dict[str, JsonValue]:
            return {"status": "PASSED", "attempt_id": str(attempt_id)}

    class FakePreflight:
        def run(
            self,
            configuration: object,
            *,
            attempt_id: UUID,
        ) -> FakeReport:
            calls.append((configuration, attempt_id))
            return FakeReport()

    monkeypatch.setattr(
        dispatch_module,
        "RepositoryConfiguration",
        FakeConfigurationFactory,
    )
    authenticator = _authenticator()
    dispatcher = HostRequestDispatcher(
        authenticator=authenticator,
        journal=HostOperationJournal(
            _runtime_directory(tmp_path) / "journal.sqlite3",
            clock_ms=lambda: NOW_MS,
        ),
        registry=default_operation_registry(
            preflight=cast(RepositoryPreflightRunner, FakePreflight())
        ),
        host_id="host-1",
        clock_ms=lambda: NOW_MS,
    )
    request = HostRequestMessage(
        request_id=uuid4(),
        issued_at_ms=NOW_MS,
        expires_at_ms=NOW_MS + 10_000,
        authority=RepositoryHostAuthority(
            repository_key="boppuh/mathews",
            configuration_id=configuration_id,
            configuration_digest="sha256:" + "1" * 64,
        ),
        operation=HostOperation(
            name="repository.preflight",
            idempotency_key="preflight-1",
            arguments={
                "attempt_id": str(attempt_id),
                "configuration": {"typed": "configuration"},
            },
        ),
    )

    response = authenticator.verify_response(
        dispatcher.dispatch(authenticator.sign_request(request))
    )

    assert response.status is HostResponseStatus.OK
    assert response.result == {
        "status": "PASSED",
        "attempt_id": str(attempt_id),
    }
    assert len(calls) == 1
    assert calls[0][1] == attempt_id


def test_workspace_operations_are_configuration_bound_fenced_and_typed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration_id = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
    cancellation_id = uuid4()
    calls: list[tuple[str, UUID]] = []

    class FakeConfiguration:
        repository_key = "boppuh/mathews"
        digest = "sha256:" + "1" * 64

    class FakeConfigurationFactory:
        @staticmethod
        def from_dict(
            received_configuration_id: UUID,
            value: object,
        ) -> FakeConfiguration:
            assert received_configuration_id == configuration_id
            assert value == {"typed": "configuration"}
            return FakeConfiguration()

    class FakeWorkspaces:
        def create(
            self,
            authority: TaskLeaseHostAuthority,
            _configuration: object,
        ) -> dict[str, object]:
            calls.append(("create", authority.task_id))
            return {
                "task_id": str(authority.task_id),
                "branch_name": f"mathews/{authority.task_id}",
                "clean": True,
            }

        def inspect(
            self,
            authority: TaskLeaseHostAuthority,
            _configuration: object,
        ) -> dict[str, object]:
            calls.append(("inspect", authority.task_id))
            return {"task_id": str(authority.task_id), "clean": True}

        def cleanup(
            self,
            authority: TaskLeaseHostAuthority,
            _configuration: object,
            *,
            reason: str,
            cancellation_id: UUID | None,
        ) -> dict[str, object]:
            calls.append(("cleanup", authority.task_id))
            return {
                "task_id": str(authority.task_id),
                "state": "CLEANED",
                "reason": reason,
                "cancellation_id": (
                    None if cancellation_id is None else str(cancellation_id)
                ),
            }

    monkeypatch.setattr(
        dispatch_module,
        "RepositoryConfiguration",
        FakeConfigurationFactory,
    )
    authenticator = _authenticator()
    dispatcher = HostRequestDispatcher(
        authenticator=authenticator,
        journal=HostOperationJournal(
            _runtime_directory(tmp_path) / "journal.sqlite3",
            clock_ms=lambda: NOW_MS,
        ),
        registry=default_operation_registry(
            workspaces=cast(GitWorkspaceLifecycle, FakeWorkspaces())
        ),
        host_id="host-1",
        clock_ms=lambda: NOW_MS,
    )
    authority = _task_authority()
    requests = (
        _request(
            name="workspace.create",
            authority=authority,
            idempotency_key="workspace-create",
            arguments={"configuration": {"typed": "configuration"}},
        ),
        _request(
            name="workspace.inspect",
            authority=authority,
            idempotency_key="workspace-inspect",
            arguments={"configuration": {"typed": "configuration"}},
        ),
        _request(
            name="workspace.cleanup",
            authority=authority,
            idempotency_key="workspace-cleanup",
            arguments={
                "configuration": {"typed": "configuration"},
                "reason": "CANCELLED",
                "cancellation_id": str(cancellation_id),
            },
        ),
    )

    responses = tuple(
        authenticator.verify_response(
            dispatcher.dispatch(authenticator.sign_request(request))
        )
        for request in requests
    )

    assert [response.status for response in responses] == [
        HostResponseStatus.OK,
        HostResponseStatus.OK,
        HostResponseStatus.OK,
    ]
    assert responses[0].execution_fencing_token == 1
    assert responses[1].execution_fencing_token == 1
    assert responses[2].result["cancellation_id"] == str(cancellation_id)
    assert calls == [
        ("create", authority.task_id),
        ("inspect", authority.task_id),
        ("cleanup", authority.task_id),
    ]


def test_controlled_git_operations_are_fenced_and_resolve_credentials_off_message(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration_id = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
    push_reference = SecretReference.parse("keychain://mathews/git-push")
    calls: list[str] = []

    class FakeGit:
        push_credential = push_reference

    class FakeConfiguration:
        repository_key = "boppuh/mathews"
        digest = "sha256:" + "1" * 64
        git = FakeGit()

    class FakeConfigurationFactory:
        @staticmethod
        def from_dict(
            received_configuration_id: UUID,
            value: object,
        ) -> FakeConfiguration:
            assert received_configuration_id == configuration_id
            assert value == {"typed": "configuration"}
            return FakeConfiguration()

    class FakeCredentials:
        def get(self, reference: SecretReference) -> SecretValue:
            assert reference == push_reference
            calls.append("credential")
            return SecretValue("never-persist-this")

    class FakeWorkspaces:
        def inspect_git(
            self,
            _authority: TaskLeaseHostAuthority,
            _configuration: object,
        ) -> dict[str, object]:
            calls.append("inspect")
            return {"head_sha": "a" * 40, "clean": True}

        def commit_candidate(
            self,
            _authority: TaskLeaseHostAuthority,
            _configuration: object,
            *,
            expected_head_sha: str,
            message: str,
        ) -> dict[str, object]:
            assert expected_head_sha == "a" * 40
            assert message == "Candidate commit"
            calls.append("commit")
            return {"head_sha": "b" * 40, "clean": True, "committed": True}

        def push_candidate(
            self,
            _authority: TaskLeaseHostAuthority,
            _configuration: object,
            *,
            expected_head_sha: str,
            credential: SecretValue,
            transport: object,
        ) -> dict[str, object]:
            assert expected_head_sha == "b" * 40
            assert str(credential) == "[REDACTED]"
            assert isinstance(transport, GitCredentialPushTransport)
            calls.append("push")
            return {
                "head_sha": expected_head_sha,
                "remote_head_after": expected_head_sha,
                "pushed": True,
            }

    monkeypatch.setattr(
        dispatch_module,
        "RepositoryConfiguration",
        FakeConfigurationFactory,
    )
    authenticator = _authenticator()
    dispatcher = HostRequestDispatcher(
        authenticator=authenticator,
        journal=HostOperationJournal(
            _runtime_directory(tmp_path) / "journal.sqlite3",
            clock_ms=lambda: NOW_MS,
        ),
        registry=default_operation_registry(
            workspaces=cast(GitWorkspaceLifecycle, FakeWorkspaces()),
            git_credentials=cast(SecretProvider, FakeCredentials()),
            git_push_transport=GitCredentialPushTransport(
                (tmp_path / "git-helpers").resolve()
            ),
        ),
        host_id="host-1",
        clock_ms=lambda: NOW_MS,
    )
    authority = _task_authority()
    requests = (
        _request(
            name="git.inspect",
            authority=authority,
            idempotency_key="git-inspect",
            arguments={"configuration": {"typed": "configuration"}},
        ),
        _request(
            name="git.commit",
            authority=authority,
            idempotency_key="git-commit",
            arguments={
                "configuration": {"typed": "configuration"},
                "expected_head_sha": "a" * 40,
                "message": "Candidate commit",
            },
        ),
        _request(
            name="git.push",
            authority=authority,
            idempotency_key="git-push",
            arguments={
                "configuration": {"typed": "configuration"},
                "expected_head_sha": "b" * 40,
            },
        ),
    )

    responses = tuple(
        authenticator.verify_response(
            dispatcher.dispatch(authenticator.sign_request(request))
        )
        for request in requests
    )

    assert all(response.status is HostResponseStatus.OK for response in responses)
    assert responses[1].execution_fencing_token == 1
    assert responses[2].execution_fencing_token == 1
    assert "never-persist-this" not in repr(responses)
    assert push_reference.uri not in repr(responses)
    assert calls == ["inspect", "commit", "credential", "push"]


def test_git_push_rejects_legacy_configuration_without_a_credential(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class LegacyGit:
        push_credential = None

    class LegacyConfiguration:
        repository_key = "boppuh/mathews"
        digest = "sha256:" + "1" * 64
        git = LegacyGit()

    class LegacyConfigurationFactory:
        @staticmethod
        def from_dict(
            _configuration_id: UUID,
            _value: object,
        ) -> LegacyConfiguration:
            return LegacyConfiguration()

    monkeypatch.setattr(
        dispatch_module,
        "RepositoryConfiguration",
        LegacyConfigurationFactory,
    )
    authenticator = _authenticator()
    dispatcher = HostRequestDispatcher(
        authenticator=authenticator,
        journal=HostOperationJournal(
            _runtime_directory(tmp_path) / "journal.sqlite3",
            clock_ms=lambda: NOW_MS,
        ),
        registry=default_operation_registry(),
        host_id="host-1",
        clock_ms=lambda: NOW_MS,
    )

    response = authenticator.verify_response(
        dispatcher.dispatch(
            authenticator.sign_request(
                _request(
                    name="git.push",
                    authority=_task_authority(),
                    idempotency_key="legacy-git-push",
                    arguments={
                        "configuration": {"legacy": True},
                        "expected_head_sha": "a" * 40,
                    },
                )
            )
        )
    )

    assert response.status is HostResponseStatus.REJECTED
    assert response.code == "GIT_PUSH_CREDENTIAL_REQUIRED"


@pytest.mark.parametrize(
    ("name", "arguments"),
    (
        (
            "git.commit",
            {
                "configuration": {},
                "expected_head_sha": "a" * 40,
                "message": "line one\nline two",
            },
        ),
        (
            "git.commit",
            {
                "configuration": {},
                "expected_head_sha": "not-a-sha",
                "message": "Candidate commit",
            },
        ),
        (
            "git.push",
            {
                "configuration": {},
                "expected_head_sha": "a" * 40,
                "force": True,
            },
        ),
    ),
)
def test_controlled_git_operations_reject_unbounded_or_force_arguments(
    tmp_path: Path,
    name: str,
    arguments: dict[str, JsonValue],
) -> None:
    authenticator = _authenticator()
    dispatcher = HostRequestDispatcher(
        authenticator=authenticator,
        journal=HostOperationJournal(
            _runtime_directory(tmp_path) / "journal.sqlite3",
            clock_ms=lambda: NOW_MS,
        ),
        registry=default_operation_registry(),
        host_id="host-1",
        clock_ms=lambda: NOW_MS,
    )

    response = authenticator.verify_response(
        dispatcher.dispatch(
            authenticator.sign_request(
                _request(
                    name=name,
                    idempotency_key=f"invalid-{name}",
                    arguments=arguments,
                )
            )
        )
    )

    assert response.status is HostResponseStatus.REJECTED
    assert response.code == "INVALID_ARGUMENTS"


@pytest.mark.parametrize(
    ("reason", "cancellation_id"),
    (
        ("CANCELLED", None),
        ("COMPLETED", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        ("UNKNOWN", None),
    ),
)
def test_workspace_cleanup_rejects_inconsistent_reason_metadata(
    tmp_path: Path,
    reason: str,
    cancellation_id: str | None,
) -> None:
    authenticator = _authenticator()
    dispatcher = HostRequestDispatcher(
        authenticator=authenticator,
        journal=HostOperationJournal(
            _runtime_directory(tmp_path) / "journal.sqlite3",
            clock_ms=lambda: NOW_MS,
        ),
        registry=default_operation_registry(
            workspaces=GitWorkspaceLifecycle((tmp_path / "workspaces").resolve())
        ),
        host_id="host-1",
        clock_ms=lambda: NOW_MS,
    )
    request = _request(
        name="workspace.cleanup",
        idempotency_key=f"cleanup-{reason.lower()}",
        arguments={
            "configuration": {},
            "reason": reason,
            "cancellation_id": cancellation_id,
        },
    )

    response = authenticator.verify_response(
        dispatcher.dispatch(authenticator.sign_request(request))
    )

    assert response.status is HostResponseStatus.REJECTED
    assert response.code == "INVALID_ARGUMENTS"
