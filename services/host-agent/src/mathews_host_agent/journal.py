"""Durable fencing and idempotency journal for host operations."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import cast
from uuid import UUID

from mathews_configuration.host_protocol import (
    HostProtocolError,
    HostRequestMessage,
    HostResponseStatus,
    JsonValue,
    RepositoryHostAuthority,
    SystemHostAuthority,
    TaskLeaseHostAuthority,
    normalize_host_json_object,
    validate_host_fencing_token,
    validate_host_response_code,
)


class HostJournalError(RuntimeError):
    """A stable journal failure that does not expose local data."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class JournalAction(StrEnum):
    EXECUTE = "EXECUTE"
    REPLAY = "REPLAY"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True, slots=True)
class JournalResult:
    status: HostResponseStatus
    code: str
    result: dict[str, JsonValue]
    execution_fencing_token: int | None


@dataclass(frozen=True, slots=True)
class JournalDecision:
    action: JournalAction
    result: JournalResult | None = None

    def __post_init__(self) -> None:
        if (self.action is JournalAction.REPLAY) != (self.result is not None):
            raise ValueError("only replay decisions contain a stored result")


@dataclass(frozen=True, slots=True)
class OperationStatus:
    state: str
    request_id: str
    status: HostResponseStatus | None
    code: str | None
    execution_fencing_token: int | None


class HostOperationJournal:
    """Persist operation reservations, terminal results, and task fences."""

    def __init__(
        self,
        path: Path,
        *,
        clock_ms: Callable[[], int] | None = None,
    ) -> None:
        self._path = path
        self._clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)
        prepare_journal_file(path)
        self._initialize()

    def begin(self, request: HostRequestMessage) -> JournalDecision:
        """Fence the request and atomically reserve or replay its operation."""

        try:
            return self._begin(request)
        except HostJournalError:
            raise
        except sqlite3.Error:
            raise HostJournalError("JOURNAL_UNAVAILABLE") from None

    def _begin(self, request: HostRequestMessage) -> JournalDecision:
        request_digest = _request_digest(request)
        scope_key = _scope_key(request)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._apply_fence(connection, request)

            receipt = connection.execute(
                """
                SELECT request_digest
                  FROM request_receipts
                 WHERE request_id = ?
                """,
                (str(request.request_id),),
            ).fetchone()
            if receipt is not None:
                if cast(str, receipt["request_digest"]) != request_digest:
                    raise HostJournalError("REQUEST_ID_CONFLICT")
            else:
                connection.execute(
                    """
                    INSERT INTO request_receipts (
                        request_id,
                        request_digest,
                        received_at_ms
                    ) VALUES (?, ?, ?)
                    """,
                    (
                        str(request.request_id),
                        request_digest,
                        self._clock_ms(),
                    ),
                )

            delivery = connection.execute(
                """
                SELECT request_digest, status, code, result_json,
                       execution_fencing_token
                  FROM deliveries
                 WHERE request_id = ?
                """,
                (str(request.request_id),),
            ).fetchone()
            if delivery is not None:
                if cast(str, delivery["request_digest"]) != request_digest:
                    raise HostJournalError("REQUEST_ID_CONFLICT")
                connection.commit()
                return JournalDecision(
                    JournalAction.REPLAY,
                    _stored_result(
                        delivery,
                        task_scoped=isinstance(
                            request.authority,
                            TaskLeaseHostAuthority,
                        ),
                    ),
                )

            operation = connection.execute(
                """
                SELECT state, semantic_fingerprint, status, code, result_json,
                       execution_fencing_token
                  FROM operations
                 WHERE scope_key = ?
                   AND operation_name = ?
                   AND idempotency_key = ?
                """,
                (
                    scope_key,
                    request.operation.name,
                    request.operation.idempotency_key,
                ),
            ).fetchone()
            if operation is not None:
                if cast(str, operation["semantic_fingerprint"]) != request.semantic_fingerprint:
                    raise HostJournalError("IDEMPOTENCY_CONFLICT")
                if cast(str, operation["state"]) == "RUNNING":
                    connection.commit()
                    return JournalDecision(JournalAction.AMBIGUOUS)
                result = _stored_result(
                    operation,
                    task_scoped=isinstance(
                        request.authority,
                        TaskLeaseHostAuthority,
                    ),
                )
                self._record_delivery(
                    connection,
                    request=request,
                    request_digest=request_digest,
                    result=result,
                )
                connection.commit()
                return JournalDecision(JournalAction.REPLAY, result)

            now = self._clock_ms()
            connection.execute(
                """
                INSERT INTO operations (
                    scope_key,
                    operation_name,
                    idempotency_key,
                    semantic_fingerprint,
                    request_id,
                    state,
                    created_at_ms,
                    updated_at_ms
                ) VALUES (?, ?, ?, ?, ?, 'RUNNING', ?, ?)
                """,
                (
                    scope_key,
                    request.operation.name,
                    request.operation.idempotency_key,
                    request.semantic_fingerprint,
                    str(request.request_id),
                    now,
                    now,
                ),
            )
            connection.commit()
            return JournalDecision(JournalAction.EXECUTE)

    def finish(
        self,
        request: HostRequestMessage,
        *,
        result: JournalResult,
    ) -> None:
        """Store one terminal outcome if the request still holds the task fence."""

        try:
            self._finish(request, result=result)
        except HostJournalError:
            raise
        except (sqlite3.Error, TypeError, ValueError):
            raise HostJournalError("JOURNAL_UNAVAILABLE") from None

    def assert_authorized(self, request: HostRequestMessage) -> None:
        """Recheck the live durable fence immediately around a host effect."""

        try:
            with self._connect() as connection:
                connection.execute("BEGIN")
                self._assert_current_fence(connection, request)
                connection.commit()
        except HostJournalError:
            raise
        except (sqlite3.Error, TypeError, ValueError):
            raise HostJournalError("JOURNAL_UNAVAILABLE") from None

    def _finish(
        self,
        request: HostRequestMessage,
        *,
        result: JournalResult,
    ) -> None:
        request_digest = _request_digest(request)
        scope_key = _scope_key(request)
        result_json = _encode_result(result.result)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._assert_current_fence(connection, request)
            cursor = connection.execute(
                """
                UPDATE operations
                   SET state = ?,
                       status = ?,
                       code = ?,
                       result_json = ?,
                       execution_fencing_token = ?,
                       updated_at_ms = ?
                 WHERE scope_key = ?
                   AND operation_name = ?
                   AND idempotency_key = ?
                   AND semantic_fingerprint = ?
                   AND state = 'RUNNING'
                """,
                (
                    "SUCCEEDED" if result.status is HostResponseStatus.OK else "FAILED",
                    result.status.value,
                    result.code,
                    result_json,
                    result.execution_fencing_token,
                    self._clock_ms(),
                    scope_key,
                    request.operation.name,
                    request.operation.idempotency_key,
                    request.semantic_fingerprint,
                ),
            )
            if cursor.rowcount != 1:
                raise HostJournalError("OPERATION_NOT_RESERVED")
            self._record_delivery(
                connection,
                request=request,
                request_digest=request_digest,
                result=result,
            )
            connection.commit()

    def status(
        self,
        *,
        scope_key: str,
        operation_name: str,
        idempotency_key: str,
    ) -> OperationStatus | None:
        """Return bounded reconciliation metadata without exposing result payloads."""

        try:
            with self._connect() as connection:
                row = connection.execute(
                    """
                    SELECT state, request_id, status, code, execution_fencing_token
                      FROM operations
                     WHERE scope_key = ?
                       AND operation_name = ?
                       AND idempotency_key = ?
                    """,
                    (scope_key, operation_name, idempotency_key),
                ).fetchone()
        except sqlite3.Error:
            raise HostJournalError("JOURNAL_UNAVAILABLE") from None
        if row is None:
            return None
        try:
            state = _stored_state(row["state"])
            request_id = _stored_request_id(row["request_id"])
            raw_status = row["status"]
            status = None if raw_status is None else HostResponseStatus(cast(str, raw_status))
            code = (
                None if row["code"] is None else validate_host_response_code(cast(str, row["code"]))
            )
            token = _stored_fencing_token(row["execution_fencing_token"])
            if state == "RUNNING":
                if status is not None or code is not None or token is not None:
                    raise HostJournalError("JOURNAL_CORRUPT")
            elif status is None or code is None:
                raise HostJournalError("JOURNAL_CORRUPT")
            elif scope_key.startswith("job:") != (token is not None):
                raise HostJournalError("JOURNAL_CORRUPT")
            return OperationStatus(
                state=state,
                request_id=request_id,
                status=status,
                code=code,
                execution_fencing_token=token,
            )
        except (HostProtocolError, TypeError, ValueError):
            raise HostJournalError("JOURNAL_CORRUPT") from None

    @staticmethod
    def scope_key(request: HostRequestMessage) -> str:
        """Expose the canonical scope key for a verified request."""

        return _scope_key(request)

    def _apply_fence(
        self,
        connection: sqlite3.Connection,
        request: HostRequestMessage,
    ) -> None:
        authority = request.authority
        if not isinstance(authority, TaskLeaseHostAuthority):
            return
        now = self._clock_ms()
        if now >= authority.lease_expires_at_ms:
            raise HostJournalError("LEASE_EXPIRED")
        row = connection.execute(
            """
            SELECT task_id, lease_id, worker_id, attempt, fencing_token,
                   lease_expires_at_ms, repository_key, configuration_id,
                   configuration_digest
              FROM job_fences
             WHERE job_id = ?
            """,
            (str(authority.job_id),),
        ).fetchone()
        if row is None:
            connection.execute(
                """
                INSERT INTO job_fences (
                    job_id,
                    task_id,
                    lease_id,
                    worker_id,
                    attempt,
                    fencing_token,
                    lease_expires_at_ms,
                    repository_key,
                    configuration_id,
                    configuration_digest,
                    updated_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(authority.job_id),
                    str(authority.task_id),
                    str(authority.lease_id),
                    authority.worker_id,
                    authority.attempt,
                    authority.fencing_token,
                    authority.lease_expires_at_ms,
                    authority.repository_key,
                    str(authority.configuration_id),
                    authority.configuration_digest,
                    self._clock_ms(),
                ),
            )
            return

        existing_token = cast(int, row["fencing_token"])
        if authority.fencing_token < existing_token:
            raise HostJournalError("FENCED")
        invariant_binding = (
            cast(str, row["task_id"]) == str(authority.task_id)
            and cast(str, row["repository_key"]) == authority.repository_key
            and cast(str, row["configuration_id"]) == str(authority.configuration_id)
            and cast(str, row["configuration_digest"]) == authority.configuration_digest
        )
        if not invariant_binding:
            raise HostJournalError("AUTHORITY_CONFLICT")
        if authority.fencing_token == existing_token:
            exact_lease = (
                cast(str, row["lease_id"]) == str(authority.lease_id)
                and cast(str, row["worker_id"]) == authority.worker_id
                and cast(int, row["attempt"]) == authority.attempt
            )
            if not exact_lease:
                raise HostJournalError("FENCING_TOKEN_CONFLICT")
            existing_expiry = cast(int, row["lease_expires_at_ms"])
            if now >= existing_expiry:
                raise HostJournalError("LEASE_EXPIRED")
            if authority.lease_expires_at_ms > existing_expiry:
                connection.execute(
                    """
                    UPDATE job_fences
                       SET lease_expires_at_ms = ?,
                           updated_at_ms = ?
                     WHERE job_id = ?
                    """,
                    (
                        authority.lease_expires_at_ms,
                        now,
                        str(authority.job_id),
                    ),
                )
            return

        connection.execute(
            """
            UPDATE job_fences
               SET lease_id = ?,
                   worker_id = ?,
                   attempt = ?,
                   fencing_token = ?,
                   lease_expires_at_ms = ?,
                   updated_at_ms = ?
             WHERE job_id = ?
            """,
            (
                str(authority.lease_id),
                authority.worker_id,
                authority.attempt,
                authority.fencing_token,
                authority.lease_expires_at_ms,
                self._clock_ms(),
                str(authority.job_id),
            ),
        )

    def _assert_current_fence(
        self,
        connection: sqlite3.Connection,
        request: HostRequestMessage,
    ) -> None:
        authority = request.authority
        if not isinstance(authority, TaskLeaseHostAuthority):
            return
        row = connection.execute(
            """
            SELECT task_id, lease_id, worker_id, attempt, fencing_token,
                   lease_expires_at_ms
              FROM job_fences
             WHERE job_id = ?
            """,
            (str(authority.job_id),),
        ).fetchone()
        if row is None or (
            cast(str, row["task_id"]) != str(authority.task_id)
            or cast(str, row["lease_id"]) != str(authority.lease_id)
            or cast(str, row["worker_id"]) != authority.worker_id
            or cast(int, row["attempt"]) != authority.attempt
            or cast(int, row["fencing_token"]) != authority.fencing_token
        ):
            raise HostJournalError("FENCED")
        if self._clock_ms() >= cast(int, row["lease_expires_at_ms"]):
            raise HostJournalError("LEASE_EXPIRED")

    def _record_delivery(
        self,
        connection: sqlite3.Connection,
        *,
        request: HostRequestMessage,
        request_digest: str,
        result: JournalResult,
    ) -> None:
        connection.execute(
            """
            INSERT INTO deliveries (
                request_id,
                request_digest,
                status,
                code,
                result_json,
                execution_fencing_token,
                completed_at_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(request.request_id),
                request_digest,
                result.status.value,
                result.code,
                _encode_result(result.result),
                result.execution_fencing_token,
                self._clock_ms(),
            ),
        )

    def _initialize(self) -> None:
        try:
            with self._connect() as connection:
                connection.executescript(
                    """
                PRAGMA journal_mode = DELETE;
                PRAGMA synchronous = FULL;
                PRAGMA foreign_keys = ON;

                CREATE TABLE IF NOT EXISTS job_fences (
                    job_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    lease_id TEXT NOT NULL,
                    worker_id TEXT NOT NULL,
                    attempt INTEGER NOT NULL CHECK (attempt > 0),
                    fencing_token INTEGER NOT NULL CHECK (fencing_token > 0),
                    lease_expires_at_ms INTEGER NOT NULL,
                    repository_key TEXT NOT NULL,
                    configuration_id TEXT NOT NULL,
                    configuration_digest TEXT NOT NULL,
                    updated_at_ms INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS operations (
                    scope_key TEXT NOT NULL,
                    operation_name TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    semantic_fingerprint TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    state TEXT NOT NULL
                        CHECK (state IN ('RUNNING', 'SUCCEEDED', 'FAILED')),
                    status TEXT,
                    code TEXT,
                    result_json TEXT,
                    execution_fencing_token INTEGER,
                    created_at_ms INTEGER NOT NULL,
                    updated_at_ms INTEGER NOT NULL,
                    PRIMARY KEY (scope_key, operation_name, idempotency_key)
                );

                CREATE TABLE IF NOT EXISTS request_receipts (
                    request_id TEXT PRIMARY KEY,
                    request_digest TEXT NOT NULL,
                    received_at_ms INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS deliveries (
                    request_id TEXT PRIMARY KEY,
                    request_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    code TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    execution_fencing_token INTEGER,
                    completed_at_ms INTEGER NOT NULL
                );
                    """
                )
        except sqlite3.Error:
            raise HostJournalError("JOURNAL_UNAVAILABLE") from None

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._path,
            timeout=5.0,
            isolation_level=None,
        )
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA foreign_keys = ON")
        except BaseException:
            connection.close()
            raise
        return connection


def prepare_journal_file(path: Path) -> None:
    if not path.is_absolute():
        raise HostJournalError("UNSAFE_JOURNAL_PATH")
    parent = path.parent
    try:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent_stat = parent.lstat()
    except OSError:
        raise HostJournalError("JOURNAL_UNAVAILABLE") from None
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != os.geteuid()
        or stat.S_IMODE(parent_stat.st_mode) & 0o077
    ):
        raise HostJournalError("UNSAFE_JOURNAL_PATH")

    try:
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    except OSError:
        raise HostJournalError("JOURNAL_UNAVAILABLE") from None
    try:
        file_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_uid != os.geteuid()
            or stat.S_IMODE(file_stat.st_mode) & 0o077
        ):
            raise HostJournalError("UNSAFE_JOURNAL_PATH")
    finally:
        os.close(descriptor)


def _scope_key(request: HostRequestMessage) -> str:
    authority = request.authority
    if isinstance(authority, SystemHostAuthority):
        return "system"
    if isinstance(authority, RepositoryHostAuthority):
        return (
            f"repository:{authority.repository_key}:"
            f"{authority.configuration_id}:{authority.configuration_digest}"
        )
    return f"job:{authority.job_id}"


def _request_digest(request: HostRequestMessage) -> str:
    encoded = json.dumps(
        request.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _encode_result(result: Mapping[str, JsonValue]) -> str:
    return json.dumps(
        result,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _stored_result(
    row: sqlite3.Row,
    *,
    task_scoped: bool,
) -> JournalResult:
    try:
        raw_result = json.loads(cast(str, row["result_json"]))
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise HostJournalError("JOURNAL_CORRUPT") from None
    if not isinstance(raw_result, dict):
        raise HostJournalError("JOURNAL_CORRUPT")
    try:
        result = normalize_host_json_object(raw_result)
        status = HostResponseStatus(cast(str, row["status"]))
        code = validate_host_response_code(cast(str, row["code"]))
        token = _stored_fencing_token(row["execution_fencing_token"])
        if task_scoped != (token is not None):
            raise HostJournalError("JOURNAL_CORRUPT")
    except (HostProtocolError, TypeError, ValueError):
        raise HostJournalError("JOURNAL_CORRUPT") from None
    return JournalResult(
        status=status,
        code=code,
        result=result,
        execution_fencing_token=token,
    )


def _stored_fencing_token(value: object) -> int | None:
    if value is None:
        return None
    return validate_host_fencing_token(cast(int, value))


def _stored_state(value: object) -> str:
    if not isinstance(value, str) or value not in {
        "RUNNING",
        "SUCCEEDED",
        "FAILED",
    }:
        raise HostJournalError("JOURNAL_CORRUPT")
    return value


def _stored_request_id(value: object) -> str:
    if not isinstance(value, str):
        raise HostJournalError("JOURNAL_CORRUPT")
    try:
        identifier = UUID(value)
    except ValueError:
        raise HostJournalError("JOURNAL_CORRUPT") from None
    if str(identifier) != value or identifier.version != 4:
        raise HostJournalError("JOURNAL_CORRUPT")
    return value
