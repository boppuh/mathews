import os
import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from mathews_configuration import (
    HostOperation,
    HostRequestMessage,
    HostResponseStatus,
    JsonValue,
    SystemHostAuthority,
    TaskLeaseHostAuthority,
)
from mathews_host_agent.journal import (
    HostJournalError,
    HostOperationJournal,
    JournalAction,
    JournalResult,
)

NOW_MS = 1_800_000_000_000


def _runtime_directory(tmp_path: Path) -> Path:
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700, parents=True)
    return runtime


def _authority(
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
    request_id: UUID | None = None,
    authority: TaskLeaseHostAuthority | SystemHostAuthority | None = None,
    idempotency_key: str = "operation-1",
    arguments: dict[str, JsonValue] | None = None,
) -> HostRequestMessage:
    return HostRequestMessage(
        request_id=request_id or uuid4(),
        issued_at_ms=NOW_MS,
        expires_at_ms=NOW_MS + 10_000,
        authority=authority or _authority(),
        operation=HostOperation(
            name="task.lease_probe",
            idempotency_key=idempotency_key,
            arguments=arguments or {},
        ),
    )


def _success(token: int | None = 1) -> JournalResult:
    return JournalResult(
        status=HostResponseStatus.OK,
        code="OK",
        result={"accepted": True},
        execution_fencing_token=token,
    )


def test_terminal_result_replays_by_delivery_and_logical_idempotency(
    tmp_path: Path,
) -> None:
    journal = HostOperationJournal(
        _runtime_directory(tmp_path) / "journal.sqlite3",
        clock_ms=lambda: NOW_MS,
    )
    request = _request()

    assert journal.begin(request).action is JournalAction.EXECUTE
    journal.finish(request, result=_success())

    delivery_replay = journal.begin(request)
    logical_replay = journal.begin(replace(request, request_id=uuid4()))

    assert delivery_replay == logical_replay
    assert logical_replay.action is JournalAction.REPLAY
    assert logical_replay.result == _success()


def test_terminal_result_survives_process_restart(tmp_path: Path) -> None:
    path = _runtime_directory(tmp_path) / "journal.sqlite3"
    request = _request()
    first_process = HostOperationJournal(path, clock_ms=lambda: NOW_MS)
    assert first_process.begin(request).action is JournalAction.EXECUTE
    first_process.finish(request, result=_success())

    restarted = HostOperationJournal(path, clock_ms=lambda: NOW_MS + 1)

    assert restarted.begin(replace(request, request_id=uuid4())).action is JournalAction.REPLAY


def test_conflicting_request_id_and_idempotency_key_are_rejected(
    tmp_path: Path,
) -> None:
    journal = HostOperationJournal(
        _runtime_directory(tmp_path) / "journal.sqlite3",
        clock_ms=lambda: NOW_MS,
    )
    request = _request()
    assert journal.begin(request).action is JournalAction.EXECUTE

    with pytest.raises(HostJournalError, match="REQUEST_ID_CONFLICT"):
        journal.begin(
            replace(
                request,
                operation=replace(
                    request.operation,
                    idempotency_key="different-operation",
                ),
            )
        )
    journal.finish(request, result=_success())
    with pytest.raises(HostJournalError, match="IDEMPOTENCY_CONFLICT"):
        journal.begin(
            replace(
                request,
                request_id=uuid4(),
                operation=replace(request.operation, arguments={"changed": "yes"}),
            )
        )


def test_lower_and_equal_conflicting_fences_are_rejected(tmp_path: Path) -> None:
    journal = HostOperationJournal(
        _runtime_directory(tmp_path) / "journal.sqlite3",
        clock_ms=lambda: NOW_MS,
    )
    request = _request(authority=_authority(fencing_token=2))
    assert journal.begin(request).action is JournalAction.EXECUTE

    with pytest.raises(HostJournalError, match="FENCED"):
        journal.begin(
            replace(
                request,
                request_id=uuid4(),
                authority=_authority(fencing_token=1),
            )
        )
    with pytest.raises(HostJournalError, match="FENCING_TOKEN_CONFLICT"):
        journal.begin(
            replace(
                request,
                request_id=uuid4(),
                authority=_authority(
                    lease_id=uuid4(),
                    worker_id="worker-2",
                    attempt=2,
                    fencing_token=2,
                ),
            )
        )


def test_takeover_fences_old_completion_and_reconciles_crash_as_ambiguous(
    tmp_path: Path,
) -> None:
    path = _runtime_directory(tmp_path) / "journal.sqlite3"
    first = _request(authority=_authority(fencing_token=1))
    journal = HostOperationJournal(path, clock_ms=lambda: NOW_MS)
    assert journal.begin(first).action is JournalAction.EXECUTE

    takeover = replace(
        first,
        request_id=uuid4(),
        authority=_authority(
            lease_id=uuid4(),
            worker_id="worker-2",
            attempt=2,
            fencing_token=2,
        ),
    )
    restarted = HostOperationJournal(path, clock_ms=lambda: NOW_MS + 1)

    assert restarted.begin(takeover).action is JournalAction.AMBIGUOUS
    with pytest.raises(HostJournalError, match="FENCED"):
        journal.finish(first, result=_success())


def test_repository_binding_cannot_change_for_an_existing_job(
    tmp_path: Path,
) -> None:
    journal = HostOperationJournal(
        _runtime_directory(tmp_path) / "journal.sqlite3",
        clock_ms=lambda: NOW_MS,
    )
    first = _request()
    assert journal.begin(first).action is JournalAction.EXECUTE
    changed_authority = replace(
        _authority(fencing_token=2),
        repository_key="another/repository",
    )

    with pytest.raises(HostJournalError, match="AUTHORITY_CONFLICT"):
        journal.begin(replace(first, request_id=uuid4(), authority=changed_authority))


def test_journal_file_and_parent_must_be_private(tmp_path: Path) -> None:
    runtime = _runtime_directory(tmp_path)
    journal_path = runtime / "journal.sqlite3"

    HostOperationJournal(journal_path)

    assert stat.S_IMODE(journal_path.stat().st_mode) == 0o600
    os.chmod(runtime, 0o755)
    with pytest.raises(HostJournalError, match="UNSAFE_JOURNAL_PATH"):
        HostOperationJournal(runtime / "second.sqlite3")


def test_expired_lease_cannot_commit_and_remains_ambiguous(
    tmp_path: Path,
) -> None:
    clock = [NOW_MS]
    journal = HostOperationJournal(
        _runtime_directory(tmp_path) / "journal.sqlite3",
        clock_ms=lambda: clock[0],
    )
    request = _request(authority=_authority(lease_expires_at_ms=NOW_MS + 10))
    assert journal.begin(request).action is JournalAction.EXECUTE

    clock[0] = NOW_MS + 10

    with pytest.raises(HostJournalError, match="LEASE_EXPIRED"):
        journal.finish(request, result=_success())
    assert (
        journal.begin(
            replace(
                request,
                request_id=uuid4(),
                authority=_authority(
                    lease_id=uuid4(),
                    worker_id="worker-2",
                    attempt=2,
                    fencing_token=2,
                    lease_expires_at_ms=NOW_MS + 100,
                ),
            )
        ).action
        is JournalAction.AMBIGUOUS
    )


def test_signed_same_lease_renewal_must_arrive_before_expiry(
    tmp_path: Path,
) -> None:
    clock = [NOW_MS]
    journal = HostOperationJournal(
        _runtime_directory(tmp_path) / "journal.sqlite3",
        clock_ms=lambda: clock[0],
    )
    first = _request(
        authority=_authority(lease_expires_at_ms=NOW_MS + 10),
        idempotency_key="first",
    )
    assert journal.begin(first).action is JournalAction.EXECUTE
    clock[0] = NOW_MS + 5
    renewal = _request(
        authority=_authority(lease_expires_at_ms=NOW_MS + 100),
        idempotency_key="renewal",
    )
    assert journal.begin(renewal).action is JournalAction.EXECUTE
    clock[0] = NOW_MS + 20
    journal.finish(first, result=_success())

    late_runtime = _runtime_directory(tmp_path / "late")
    late_clock = [NOW_MS]
    late = HostOperationJournal(
        late_runtime / "journal.sqlite3",
        clock_ms=lambda: late_clock[0],
    )
    assert late.begin(first).action is JournalAction.EXECUTE
    late_clock[0] = NOW_MS + 11
    with pytest.raises(HostJournalError, match="LEASE_EXPIRED"):
        late.begin(renewal)


def test_concurrent_logical_duplicates_reserve_exactly_once(
    tmp_path: Path,
) -> None:
    path = _runtime_directory(tmp_path) / "journal.sqlite3"
    requests = (_request(), _request())

    def reserve(request: HostRequestMessage) -> JournalAction:
        return (
            HostOperationJournal(
                path,
                clock_ms=lambda: NOW_MS,
            )
            .begin(request)
            .action
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        actions = tuple(executor.map(reserve, requests))

    assert sorted(actions) == [JournalAction.AMBIGUOUS, JournalAction.EXECUTE]


def test_sqlite_failures_are_normalized_to_safe_journal_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = HostOperationJournal(
        _runtime_directory(tmp_path) / "journal.sqlite3",
        clock_ms=lambda: NOW_MS,
    )

    def unavailable() -> sqlite3.Connection:
        raise sqlite3.OperationalError("local path detail")

    monkeypatch.setattr(journal, "_connect", unavailable)

    with pytest.raises(HostJournalError, match="JOURNAL_UNAVAILABLE"):
        journal.begin(_request())


@pytest.mark.parametrize(
    "corruption",
    (
        "code = NULL",
        "code = 'not-a-valid-code'",
        "execution_fencing_token = NULL",
        "execution_fencing_token = -1",
        "execution_fencing_token = 'not-an-integer'",
    ),
)
def test_corrupt_terminal_fields_fail_as_journal_corrupt(
    tmp_path: Path,
    corruption: str,
) -> None:
    path = _runtime_directory(tmp_path) / "journal.sqlite3"
    journal = HostOperationJournal(path, clock_ms=lambda: NOW_MS)
    request = _request()
    assert journal.begin(request).action is JournalAction.EXECUTE
    journal.finish(request, result=_success())
    with sqlite3.connect(path) as connection:
        connection.execute(f"UPDATE operations SET {corruption}")

    with pytest.raises(HostJournalError, match="JOURNAL_CORRUPT"):
        journal.begin(replace(request, request_id=uuid4()))


def test_corrupt_status_metadata_fails_as_journal_corrupt(
    tmp_path: Path,
) -> None:
    path = _runtime_directory(tmp_path) / "journal.sqlite3"
    journal = HostOperationJournal(path, clock_ms=lambda: NOW_MS)
    request = _request()
    assert journal.begin(request).action is JournalAction.EXECUTE
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE operations SET request_id = 'not-a-request-id'")

    with pytest.raises(HostJournalError, match="JOURNAL_CORRUPT"):
        journal.status(
            scope_key=HostOperationJournal.scope_key(request),
            operation_name=request.operation.name,
            idempotency_key=request.operation.idempotency_key,
        )
