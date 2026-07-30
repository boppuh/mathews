"""Exact-identity process-group ownership and idempotent termination."""

from __future__ import annotations

import hashlib
import os
import signal
import sqlite3
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol, cast
from uuid import UUID

from mathews_host_agent.journal import HostJournalError, _prepare_journal_file


class OwnedProcessError(RuntimeError):
    """A stable refusal to act on an unproven process identity."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class OwnedProcessState(StrEnum):
    RUNNING = "RUNNING"
    TERMINATED = "TERMINATED"
    GONE = "GONE"


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    job_id: UUID
    lease_id: UUID
    fencing_token: int
    pid: int
    process_group_id: int
    birth_token: str
    ownership_nonce: UUID

    def __post_init__(self) -> None:
        if (
            self.fencing_token <= 0
            or self.pid <= 1
            or self.process_group_id <= 1
            or self.pid != self.process_group_id
            or not self.birth_token
            or len(self.birth_token) > 255
        ):
            raise OwnedProcessError("INVALID_PROCESS_IDENTITY")


@dataclass(frozen=True, slots=True)
class ObservedProcess:
    pid: int
    process_group_id: int
    birth_token: str


@dataclass(frozen=True, slots=True)
class TerminationResult:
    state: OwnedProcessState
    replayed: bool


class ProcessController(Protocol):
    """Small OS boundary used only after durable identity verification."""

    def observe(self, pid: int) -> ObservedProcess | None: ...

    def terminate_group(
        self,
        expected: ObservedProcess,
        *,
        grace_seconds: float,
    ) -> bool: ...


class LocalProcessController:
    """Observe process birth before sending signals to a dedicated group."""

    def observe(self, pid: int) -> ObservedProcess | None:
        if pid <= 1:
            return None
        try:
            result = subprocess.run(
                (
                    "/bin/ps",
                    "-p",
                    str(pid),
                    "-o",
                    "pgid=",
                    "-o",
                    "lstart=",
                ),
                check=False,
                capture_output=True,
                env={
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": os.defpath,
                },
                text=True,
                timeout=2,
            )
        except (OSError, subprocess.SubprocessError):
            raise OwnedProcessError("PROCESS_OBSERVATION_FAILED") from None
        if result.returncode != 0 or result.stderr:
            return None
        fields = result.stdout.strip().split(maxsplit=1)
        if len(fields) != 2:
            return None
        try:
            process_group_id = int(fields[0])
        except ValueError:
            raise OwnedProcessError("PROCESS_OBSERVATION_FAILED") from None
        return ObservedProcess(
            pid=pid,
            process_group_id=process_group_id,
            birth_token=hashlib.sha256(fields[1].encode("ascii")).hexdigest(),
        )

    def terminate_group(
        self,
        expected: ObservedProcess,
        *,
        grace_seconds: float,
    ) -> bool:
        process_group_id = expected.process_group_id
        if process_group_id <= 1:
            raise OwnedProcessError("INVALID_PROCESS_IDENTITY")
        if self.observe(expected.pid) != expected:
            return False
        try:
            os.killpg(process_group_id, signal.SIGTERM)
        except ProcessLookupError:
            return True
        except OSError:
            raise OwnedProcessError("PROCESS_TERMINATION_FAILED") from None
        deadline = time.monotonic() + grace_seconds
        while time.monotonic() < deadline:
            try:
                os.killpg(process_group_id, 0)
            except ProcessLookupError:
                return True
            except OSError:
                raise OwnedProcessError(
                    "PROCESS_TERMINATION_FAILED"
                ) from None
            time.sleep(0.02)
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except ProcessLookupError:
            return True
        except OSError:
            raise OwnedProcessError("PROCESS_TERMINATION_FAILED") from None
        return True


class OwnedProcessGroupManager:
    """Persist ownership proof and never signal a mismatched or reused PID."""

    def __init__(
        self,
        path: Path,
        *,
        controller: ProcessController | None = None,
        clock_ms: Callable[[], int] | None = None,
    ) -> None:
        self._path = path
        self._controller = controller or LocalProcessController()
        self._clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)
        try:
            _prepare_journal_file(path)
        except HostJournalError as error:
            raise OwnedProcessError(error.code) from None
        self._initialize()

    def register(self, identity: ProcessIdentity) -> None:
        """Record a process only while its observed birth identity matches."""

        observed = self._controller.observe(identity.pid)
        if not _same_identity(identity, observed):
            raise OwnedProcessError("PROCESS_IDENTITY_MISMATCH")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    """
                    SELECT job_id, lease_id, fencing_token, pid,
                           process_group_id, birth_token
                      FROM owned_process_groups
                     WHERE ownership_nonce = ?
                    """,
                    (str(identity.ownership_nonce),),
                ).fetchone()
                values = (
                    str(identity.job_id),
                    str(identity.lease_id),
                    identity.fencing_token,
                    identity.pid,
                    identity.process_group_id,
                    identity.birth_token,
                )
                if existing is not None:
                    if tuple(existing) != values:
                        raise OwnedProcessError("PROCESS_OWNERSHIP_CONFLICT")
                    connection.commit()
                    return
                connection.execute(
                    """
                    INSERT INTO owned_process_groups (
                        ownership_nonce,
                        job_id,
                        lease_id,
                        fencing_token,
                        pid,
                        process_group_id,
                        birth_token,
                        state,
                        registered_at_ms,
                        updated_at_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'RUNNING', ?, ?)
                    """,
                    (
                        str(identity.ownership_nonce),
                        *values,
                        self._clock_ms(),
                        self._clock_ms(),
                    ),
                )
                connection.commit()
        except OwnedProcessError:
            raise
        except sqlite3.Error:
            raise OwnedProcessError("PROCESS_JOURNAL_UNAVAILABLE") from None

    def terminate_owned(
        self,
        identity: ProcessIdentity,
        *,
        idempotency_key: str,
        grace_seconds: float = 2.0,
    ) -> TerminationResult:
        """Signal only the exact registered group; mismatches are treated as gone."""

        if (
            not idempotency_key
            or len(idempotency_key) > 255
            or not 0 < grace_seconds <= 10
        ):
            raise OwnedProcessError("INVALID_TERMINATION_REQUEST")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT job_id, lease_id, fencing_token, pid,
                           process_group_id, birth_token, state,
                           termination_key
                      FROM owned_process_groups
                     WHERE ownership_nonce = ?
                    """,
                    (str(identity.ownership_nonce),),
                ).fetchone()
                if row is None or not _row_matches(identity, row):
                    raise OwnedProcessError("PROCESS_NOT_OWNED")
                state = OwnedProcessState(cast(str, row["state"]))
                stored_key = cast(str | None, row["termination_key"])
                if state is not OwnedProcessState.RUNNING:
                    if stored_key != idempotency_key:
                        raise OwnedProcessError(
                            "TERMINATION_IDEMPOTENCY_CONFLICT"
                        )
                    connection.commit()
                    return TerminationResult(state=state, replayed=True)
                if stored_key not in {None, idempotency_key}:
                    raise OwnedProcessError(
                        "TERMINATION_IDEMPOTENCY_CONFLICT"
                    )
                connection.execute(
                    """
                    UPDATE owned_process_groups
                       SET termination_key = ?,
                           updated_at_ms = ?
                     WHERE ownership_nonce = ?
                       AND state = 'RUNNING'
                    """,
                    (
                        idempotency_key,
                        self._clock_ms(),
                        str(identity.ownership_nonce),
                    ),
                )
                connection.commit()
        except OwnedProcessError:
            raise
        except (sqlite3.Error, ValueError):
            raise OwnedProcessError("PROCESS_JOURNAL_UNAVAILABLE") from None

        observed = self._controller.observe(identity.pid)
        if _same_identity(identity, observed):
            terminated = self._controller.terminate_group(
                cast(ObservedProcess, observed),
                grace_seconds=grace_seconds,
            )
            state = (
                OwnedProcessState.TERMINATED
                if terminated
                else OwnedProcessState.GONE
            )
        else:
            # A missing process or reused PID is safe to reconcile as gone.
            # Crucially, no signal is sent to the observed replacement.
            state = OwnedProcessState.GONE
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    """
                    UPDATE owned_process_groups
                       SET state = ?,
                           terminated_at_ms = ?,
                           updated_at_ms = ?
                     WHERE ownership_nonce = ?
                       AND state = 'RUNNING'
                       AND termination_key = ?
                    """,
                    (
                        state.value,
                        self._clock_ms(),
                        self._clock_ms(),
                        str(identity.ownership_nonce),
                        idempotency_key,
                    ),
                )
                if cursor.rowcount != 1:
                    raise OwnedProcessError("PROCESS_OWNERSHIP_CONFLICT")
                connection.commit()
        except OwnedProcessError:
            raise
        except sqlite3.Error:
            raise OwnedProcessError("PROCESS_JOURNAL_UNAVAILABLE") from None
        return TerminationResult(state=state, replayed=False)

    def _initialize(self) -> None:
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS owned_process_groups (
                        ownership_nonce TEXT PRIMARY KEY,
                        job_id TEXT NOT NULL,
                        lease_id TEXT NOT NULL,
                        fencing_token INTEGER NOT NULL
                            CHECK (fencing_token > 0),
                        pid INTEGER NOT NULL CHECK (pid > 1),
                        process_group_id INTEGER NOT NULL
                            CHECK (process_group_id > 1),
                        birth_token TEXT NOT NULL,
                        state TEXT NOT NULL
                            CHECK (state IN ('RUNNING', 'TERMINATED', 'GONE')),
                        termination_key TEXT,
                        registered_at_ms INTEGER NOT NULL,
                        terminated_at_ms INTEGER,
                        updated_at_ms INTEGER NOT NULL,
                        CHECK (
                            (state = 'RUNNING' AND terminated_at_ms IS NULL)
                            OR
                            (state IN ('TERMINATED', 'GONE')
                             AND termination_key IS NOT NULL
                             AND terminated_at_ms IS NOT NULL)
                        )
                    )
                    """
                )
        except sqlite3.Error:
            raise OwnedProcessError("PROCESS_JOURNAL_UNAVAILABLE") from None

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._path,
            timeout=5.0,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection


def _same_identity(
    expected: ProcessIdentity,
    observed: ObservedProcess | None,
) -> bool:
    return bool(
        observed is not None
        and observed.pid == expected.pid
        and observed.process_group_id == expected.process_group_id
        and observed.birth_token == expected.birth_token
    )


def _row_matches(identity: ProcessIdentity, row: sqlite3.Row) -> bool:
    return bool(
        cast(str, row["job_id"]) == str(identity.job_id)
        and cast(str, row["lease_id"]) == str(identity.lease_id)
        and cast(int, row["fencing_token"]) == identity.fencing_token
        and cast(int, row["pid"]) == identity.pid
        and cast(int, row["process_group_id"]) == identity.process_group_id
        and cast(str, row["birth_token"]) == identity.birth_token
    )
