"""Bounded configured build/test execution with immutable artifact capture."""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import tempfile
import time
from base64 import b64encode
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from threading import BoundedSemaphore, Event, Lock, Thread
from uuid import UUID

from mathews_configuration import (
    E2EFlow,
    OperationKind,
    RepositoryConfiguration,
    SecretProvider,
    SecretValue,
    TaskLeaseHostAuthority,
)

from mathews_host_agent.workspaces import GitWorkspaceLifecycle, WorkspaceLifecycleError

_MAX_CAPTURE_BYTES = 128 * 1024 * 1024
_MAX_TOTAL_ARTIFACT_BYTES = 512 * 1024 * 1024
_MAX_ARTIFACTS = 256
_MAX_ARTIFACT_READ_BYTES = 256 * 1024
_ARTIFACT_ADDRESS = re.compile(r"sha256:([0-9a-f]{64})\Z")


class ConfiguredExecutionError(RuntimeError):
    """A stable execution refusal that never contains command output."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ArtifactReference:
    address: str
    size_bytes: int
    role: str
    source_path: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "address": self.address,
            "size_bytes": self.size_bytes,
            "role": self.role,
            "source_path": self.source_path,
        }


class HostArtifactStore:
    """Private content-addressed storage for host-produced immutable bytes."""

    def __init__(self, root: Path) -> None:
        if not root.is_absolute():
            raise ValueError("host artifact root must be absolute")
        self._root = root

    def put_file(
        self,
        source: Path,
        *,
        task_id: UUID,
        role: str,
        source_path: str | None,
    ) -> ArtifactReference:
        scope_root = self._prepare_scope(task_id)
        try:
            descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            raise ConfiguredExecutionError("ARTIFACT_UNAVAILABLE") from None
        temporary_path: Path | None = None
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_size > _MAX_CAPTURE_BYTES:
                raise ConfiguredExecutionError("ARTIFACT_INVALID")
            digest = hashlib.sha256()
            temporary_descriptor, raw_temporary_path = tempfile.mkstemp(
                prefix=".capture-",
                dir=scope_root,
            )
            temporary_path = Path(raw_temporary_path)
            try:
                os.fchmod(temporary_descriptor, 0o600)
                size = 0
                while chunk := os.read(descriptor, 1024 * 1024):
                    size += len(chunk)
                    if size > _MAX_CAPTURE_BYTES:
                        raise ConfiguredExecutionError("ARTIFACT_INVALID")
                    digest.update(chunk)
                    offset = 0
                    while offset < len(chunk):
                        written = os.write(temporary_descriptor, chunk[offset:])
                        if written <= 0:
                            raise ConfiguredExecutionError(
                                "ARTIFACT_STORE_UNAVAILABLE"
                            )
                        offset += written
                os.fsync(temporary_descriptor)
            finally:
                os.close(temporary_descriptor)
            address = f"sha256:{digest.hexdigest()}"
            destination = scope_root / digest.hexdigest()
            try:
                os.link(temporary_path, destination)
            except FileExistsError:
                if self._digest_file(destination) != (digest.hexdigest(), size):
                    raise ConfiguredExecutionError("ARTIFACT_CORRUPT") from None
            except OSError:
                raise ConfiguredExecutionError("ARTIFACT_STORE_UNAVAILABLE") from None
            self._fsync_directory(scope_root)
            return ArtifactReference(address, size, role, source_path)
        finally:
            os.close(descriptor)
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass

    def read_chunk(
        self,
        task_id: UUID,
        *,
        address: str,
        offset: int,
        length: int,
    ) -> dict[str, object]:
        """Read one authenticated, task-scoped, response-bounded artifact chunk."""

        match = _ARTIFACT_ADDRESS.fullmatch(address)
        if (
            match is None
            or isinstance(offset, bool)
            or not isinstance(offset, int)
            or offset < 0
            or isinstance(length, bool)
            or not isinstance(length, int)
            or not 0 < length <= _MAX_ARTIFACT_READ_BYTES
        ):
            raise ConfiguredExecutionError("ARTIFACT_READ_INVALID")
        scope_root = self._prepare_scope(task_id, create=False)
        path = scope_root / match.group(1)
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            raise ConfiguredExecutionError("ARTIFACT_UNAVAILABLE") from None
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise ConfiguredExecutionError("ARTIFACT_CORRUPT")
            total_size = opened.st_size
            if offset > total_size:
                raise ConfiguredExecutionError("ARTIFACT_READ_INVALID")
            chunk = os.pread(descriptor, min(length, total_size - offset), offset)
        finally:
            os.close(descriptor)
        return {
            "address": address,
            "offset": offset,
            "size_bytes": total_size,
            "data_base64": b64encode(chunk).decode("ascii"),
            "eof": offset + len(chunk) == total_size,
        }

    def _prepare_root(self) -> None:
        try:
            self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
            resolved = self._root.resolve(strict=True)
            root_stat = self._root.lstat()
        except OSError:
            raise ConfiguredExecutionError("ARTIFACT_STORE_UNAVAILABLE") from None
        if (
            resolved != self._root
            or not stat.S_ISDIR(root_stat.st_mode)
            or stat.S_ISLNK(root_stat.st_mode)
            or root_stat.st_uid != os.geteuid()
            or stat.S_IMODE(root_stat.st_mode) & 0o077
        ):
            raise ConfiguredExecutionError("ARTIFACT_STORE_UNAVAILABLE")

    def _prepare_scope(self, task_id: UUID, *, create: bool = True) -> Path:
        self._prepare_root()
        scope_root = self._root / str(task_id)
        try:
            if create:
                scope_root.mkdir(mode=0o700, exist_ok=True)
            resolved = scope_root.resolve(strict=True)
            scope_stat = scope_root.lstat()
        except OSError:
            code = "ARTIFACT_STORE_UNAVAILABLE" if create else "ARTIFACT_UNAVAILABLE"
            raise ConfiguredExecutionError(code) from None
        if (
            resolved != scope_root
            or not stat.S_ISDIR(scope_stat.st_mode)
            or stat.S_ISLNK(scope_stat.st_mode)
            or scope_stat.st_uid != os.geteuid()
            or stat.S_IMODE(scope_stat.st_mode) & 0o077
        ):
            raise ConfiguredExecutionError("ARTIFACT_STORE_UNAVAILABLE")
        if create:
            self._fsync_directory(self._root)
        return scope_root

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError:
            raise ConfiguredExecutionError("ARTIFACT_STORE_UNAVAILABLE") from None

    @staticmethod
    def _digest_file(path: Path) -> tuple[str, int]:
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            raise ConfiguredExecutionError("ARTIFACT_CORRUPT") from None
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise ConfiguredExecutionError("ARTIFACT_CORRUPT")
            digest = hashlib.sha256()
            size = 0
            while chunk := os.read(descriptor, 1024 * 1024):
                size += len(chunk)
                digest.update(chunk)
            return digest.hexdigest(), size
        finally:
            os.close(descriptor)


class ConfiguredOperationRunner:
    """Execute one configured operation against one exact host-owned candidate."""

    def __init__(
        self,
        workspaces: GitWorkspaceLifecycle,
        artifacts: HostArtifactStore,
        *,
        secrets: SecretProvider | None = None,
        maximum_concurrent_operations: int = 6,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not 0 < maximum_concurrent_operations <= 7:
            raise ValueError("configured execution concurrency is invalid")
        self._workspaces = workspaces
        self._artifacts = artifacts
        self._secrets = secrets
        self._monotonic = monotonic
        self._capacity = BoundedSemaphore(maximum_concurrent_operations)
        self._task_locks = tuple(Lock() for _ in range(64))
        self._shutdown = Event()
        self._active_lock = Lock()
        self._active_processes: dict[int, subprocess.Popen[bytes]] = {}
        self._shutdown_process_ids: set[int] = set()

    @property
    def artifact_store(self) -> HostArtifactStore:
        return self._artifacts

    def request_shutdown(self) -> None:
        """Stop accepting validation work and terminate every active group."""

        self._shutdown.set()
        with self._active_lock:
            active = tuple(self._active_processes.values())
            self._shutdown_process_ids.update(process.pid for process in active)
        terminators = tuple(
            Thread(target=self._terminate, args=(process,), daemon=True)
            for process in active
        )
        for terminator in terminators:
            terminator.start()
        for terminator in terminators:
            terminator.join()

    def run(
        self,
        authority: TaskLeaseHostAuthority,
        configuration: RepositoryConfiguration,
        *,
        operation_id: str,
        expected_head_sha: str,
        validation_contract_version: int,
        effect_started: Callable[[], None] | None = None,
        effect_yielded: Callable[[], None] | None = None,
        assert_authorized: Callable[[], None] | None = None,
    ) -> dict[str, object]:
        if self._shutdown.is_set():
            raise ConfiguredExecutionError("HOST_SHUTTING_DOWN")
        if not self._capacity.acquire(blocking=False):
            raise ConfiguredExecutionError("VALIDATION_CAPACITY_UNAVAILABLE")
        task_lock = self._task_lock(authority)
        if not task_lock.acquire(blocking=False):
            self._capacity.release()
            raise ConfiguredExecutionError("VALIDATION_CAPACITY_UNAVAILABLE")
        try:
            return self._run(
                authority,
                configuration,
                operation_id=operation_id,
                expected_head_sha=expected_head_sha,
                validation_contract_version=validation_contract_version,
                effect_started=effect_started,
                effect_yielded=effect_yielded,
                assert_authorized=assert_authorized,
            )
        finally:
            task_lock.release()
            self._capacity.release()

    def _run(
        self,
        authority: TaskLeaseHostAuthority,
        configuration: RepositoryConfiguration,
        *,
        operation_id: str,
        expected_head_sha: str,
        validation_contract_version: int,
        effect_started: Callable[[], None] | None,
        effect_yielded: Callable[[], None] | None,
        assert_authorized: Callable[[], None] | None,
    ) -> dict[str, object]:
        if validation_contract_version <= 0:
            raise ConfiguredExecutionError("VALIDATION_CONTRACT_VERSION_INVALID")
        operations = tuple(
            operation
            for operation in configuration.operations
            if operation.operation_id == operation_id
        )
        if len(operations) != 1:
            raise ConfiguredExecutionError("CONFIGURED_OPERATION_UNAVAILABLE")
        operation = operations[0]
        e2e_flow = getattr(operation, "e2e_flow", None)
        try:
            before = self._workspaces.execution_context(
                authority,
                configuration,
                expected_head_sha=expected_head_sha,
            )
        except WorkspaceLifecycleError as error:
            raise ConfiguredExecutionError(error.code) from None
        workspace = Path(str(before["workspace_path"]))
        argv, simulator_id = self._resolved_argv(
            workspace,
            operation.argv,
            configuration,
        )
        e2e_secret: SecretValue | None = None
        if operation.kind is OperationKind.SIMULATOR_E2E:
            flow = e2e_flow
            if flow is None or simulator_id is None:
                raise ConfiguredExecutionError("E2E_CONFIGURATION_INVALID")
            self._verify_e2e_inputs(workspace, flow)
            if self._secrets is None:
                raise ConfiguredExecutionError("E2E_SECRET_UNAVAILABLE")
            try:
                e2e_secret = self._secrets.get(flow.test_account)
            except Exception:
                raise ConfiguredExecutionError("E2E_SECRET_UNAVAILABLE") from None
        artifact_snapshot = self._artifact_snapshot(workspace, configuration)
        started = self._monotonic()
        with tempfile.TemporaryDirectory(prefix="execution-output-") as raw_output:
            output_root = Path(raw_output)
            stdout_path = output_root / "stdout"
            stderr_path = output_root / "stderr"
            returncode, cancellation_status, output_limited = self._execute(
                workspace,
                argv,
                operation.timeout_seconds,
                stdout_path,
                stderr_path,
                simulator_id=simulator_id,
                e2e_flow=e2e_flow,
                e2e_secret=e2e_secret,
                effect_started=effect_started,
                effect_yielded=effect_yielded,
                assert_authorized=assert_authorized,
            )
            duration_ms = max(0, round((self._monotonic() - started) * 1000))
            references = [
                self._artifacts.put_file(
                    stdout_path,
                    task_id=authority.task_id,
                    role="STDOUT",
                    source_path=None,
                ),
                self._artifacts.put_file(
                    stderr_path,
                    task_id=authority.task_id,
                    role="STDERR",
                    source_path=None,
                ),
            ]
            references.extend(
                self._collect_configured_artifacts(
                    workspace,
                    configuration,
                    task_id=authority.task_id,
                    captured_bytes=sum(reference.size_bytes for reference in references),
                    artifact_snapshot=artifact_snapshot,
                )
            )
        try:
            after = self._workspaces.execution_context(
                authority,
                configuration,
                expected_head_sha=expected_head_sha,
            )
        except WorkspaceLifecycleError:
            after = None
        repository_state_valid = (
            after is not None
            and after["head_sha"] == before["head_sha"]
            and after["tree_sha"] == before["tree_sha"]
        )
        cancelled = cancellation_status != "NOT_REQUESTED"
        return {
            "operation_id": operation.operation_id,
            "operation_kind": operation.kind.value,
            "exit_status": returncode,
            "duration_ms": duration_ms,
            "passed": (
                returncode == 0
                and not cancelled
                and not output_limited
                and repository_state_valid
            ),
            "cancellation_status": cancellation_status,
            "termination_signal": -returncode if returncode < 0 else None,
            "output_limited": output_limited,
            "head_sha": before["head_sha"],
            "tree_sha": before["tree_sha"],
            "repository_state_valid": repository_state_valid,
            "configuration_id": str(configuration.configuration_id),
            "configuration_version": configuration.version,
            "configuration_digest": configuration.digest,
            "validation_contract_version": validation_contract_version,
            "fencing_token": authority.fencing_token,
            "artifacts": [reference.to_dict() for reference in references],
        }

    def _task_lock(self, authority: TaskLeaseHostAuthority) -> Lock:
        return self._task_locks[authority.task_id.int % len(self._task_locks)]

    @staticmethod
    def _resolved_argv(
        workspace: Path,
        argv: tuple[str, ...],
        configuration: RepositoryConfiguration,
    ) -> tuple[tuple[str, ...], str | None]:
        placeholder = "MATHEWS_CONFIGURED_SIMULATOR"
        if placeholder not in argv:
            return argv, None
        try:
            result = subprocess.run(
                ("xcrun", "simctl", "list", "-j"),
                cwd=workspace,
                check=False,
                capture_output=True,
                env={"LANG": "C", "LC_ALL": "C", "PATH": os.defpath},
                text=True,
                timeout=10,
            )
            payload = json.loads(result.stdout)
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            raise ConfiguredExecutionError("SIMULATOR_UNAVAILABLE") from None
        if not isinstance(payload, dict):
            raise ConfiguredExecutionError("SIMULATOR_UNAVAILABLE")
        simulator = configuration.xcode.simulator
        runtime = next(
            (
                item.get("identifier")
                for item in payload.get("runtimes", [])
                if isinstance(item, dict)
                and item.get("isAvailable") is True
                and simulator.runtime_identifier
                in {item.get("identifier"), item.get("name")}
            ),
            None,
        )
        devices = payload.get("devices", {}).get(runtime, [])
        identifiers = sorted(
            item["udid"]
            for item in devices
            if isinstance(item, dict)
            and item.get("isAvailable") is True
            and item.get("deviceTypeIdentifier")
            == simulator.device_type_identifier
            and isinstance(item.get("udid"), str)
        )
        if result.returncode != 0 or not identifiers:
            raise ConfiguredExecutionError("SIMULATOR_UNAVAILABLE")
        simulator_id = identifiers[0]
        destination = f"id={simulator_id}"
        return (
            tuple(destination if argument == placeholder else argument for argument in argv),
            simulator_id,
        )

    @staticmethod
    def _verify_e2e_inputs(workspace: Path, flow: E2EFlow) -> None:
        pinned_files = (
            *flow.harness_files,
            flow.fixture_file,
            flow.test_account_recipe_file,
        )
        for pinned in pinned_files:
            candidate = workspace / pinned.path
            try:
                if (
                    candidate.is_symlink()
                    or candidate.resolve(strict=True) != candidate
                    or not candidate.is_file()
                ):
                    raise ConfiguredExecutionError("E2E_INPUT_INVALID")
            except OSError:
                raise ConfiguredExecutionError("E2E_INPUT_INVALID") from None
            digest, _size = HostArtifactStore._digest_file(candidate)
            if pinned.digest != f"sha256:{digest}":
                raise ConfiguredExecutionError("E2E_INPUT_INVALID")

        source_root = workspace / flow.harness_source_root
        expected = {
            pinned.path
            for pinned in flow.harness_files
            if pinned.path == flow.harness_source_root
            or pinned.path.startswith(f"{flow.harness_source_root}/")
        }
        try:
            if (
                source_root.is_symlink()
                or source_root.resolve(strict=True) != source_root
                or not source_root.is_dir()
            ):
                raise ConfiguredExecutionError("E2E_INPUT_INVALID")
            entries = tuple(source_root.rglob("*"))
            if any(
                path.is_symlink() or not (path.is_file() or path.is_dir())
                for path in entries
            ):
                raise ConfiguredExecutionError("E2E_INPUT_INVALID")
            actual = {
                path.relative_to(workspace).as_posix()
                for path in entries
                if path.is_file()
            }
        except OSError:
            raise ConfiguredExecutionError("E2E_INPUT_INVALID") from None
        if actual != expected:
            raise ConfiguredExecutionError("E2E_INPUT_INVALID")

    def _execute(
        self,
        workspace: Path,
        argv: tuple[str, ...],
        timeout_seconds: int,
        stdout_path: Path,
        stderr_path: Path,
        *,
        simulator_id: str | None,
        e2e_flow: E2EFlow | None,
        e2e_secret: SecretValue | None,
        effect_started: Callable[[], None] | None,
        effect_yielded: Callable[[], None] | None,
        assert_authorized: Callable[[], None] | None,
    ) -> tuple[int, str, bool]:
        isolated_home = stdout_path.parent / "home"
        isolated_temporary = stdout_path.parent / "tmp"
        isolated_home.mkdir(mode=0o700)
        isolated_temporary.mkdir(mode=0o700)
        environment = {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "CFFIXED_USER_HOME": str(isolated_home),
            "HOME": str(isolated_home),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.defpath,
            "TMPDIR": str(isolated_temporary),
        }
        secret_path: Path | None = None
        if e2e_flow is not None:
            if simulator_id is None or e2e_secret is None:
                raise ConfiguredExecutionError("E2E_CONFIGURATION_INVALID")
            secret_path = stdout_path.parent / "e2e-account-secret"
            try:
                descriptor = os.open(
                    secret_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                try:
                    secret_bytes = e2e_secret.reveal().encode("utf-8")
                    offset = 0
                    while offset < len(secret_bytes):
                        written = os.write(descriptor, secret_bytes[offset:])
                        if written <= 0:
                            raise OSError("secret write failed")
                        offset += written
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            except OSError:
                raise ConfiguredExecutionError("E2E_SECRET_UNAVAILABLE") from None
            environment.update(
                {
                    "MATHEWS_E2E_ACCOUNT_RECIPE_PATH": str(
                        workspace / e2e_flow.test_account_recipe_file.path
                    ),
                    "MATHEWS_E2E_ACCOUNT_SECRET_PATH": str(secret_path),
                    "MATHEWS_E2E_FIXTURE_PATH": str(
                        workspace / e2e_flow.fixture_file.path
                    ),
                    "MATHEWS_E2E_LOCALE": e2e_flow.locale_identifier,
                    "MATHEWS_E2E_TIME_ZONE": e2e_flow.time_zone_identifier,
                }
            )
        try:
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                if simulator_id is not None and e2e_flow is not None:
                    if effect_started is not None:
                        effect_started()
                        effect_started = None
                    if effect_yielded is not None:
                        effect_yielded()
                        effect_yielded = None
                    self._prepare_simulator(
                        workspace,
                        simulator_id,
                        assert_authorized=assert_authorized,
                    )
                process = subprocess.Popen(
                    argv,
                    cwd=workspace,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    start_new_session=True,
                )
                with self._active_lock:
                    self._active_processes[process.pid] = process
                if effect_started is not None:
                    effect_started()
                if effect_yielded is not None:
                    effect_yielded()
                deadline = time.monotonic() + timeout_seconds
                authorization_deadline = time.monotonic() + 1
                timed_out = False
                output_limited = False
                authorization_lost = False
                shutdown_requested = False
                try:
                    while process.poll() is None:
                        now = time.monotonic()
                        timed_out = now >= deadline
                        shutdown_requested = self._shutdown.is_set()
                        output_limited = any(
                            path.stat().st_size > _MAX_CAPTURE_BYTES
                            for path in (stdout_path, stderr_path)
                        )
                        if timed_out or output_limited or shutdown_requested:
                            self._terminate(process)
                            break
                        if assert_authorized is not None and now >= authorization_deadline:
                            try:
                                assert_authorized()
                            except Exception:
                                authorization_lost = True
                                self._terminate(process)
                                break
                            authorization_deadline = now + 1
                        time.sleep(0.02)
                    try:
                        returncode = process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        returncode = process.wait(timeout=2)
                finally:
                    with self._active_lock:
                        self._active_processes.pop(process.pid, None)
                        shutdown_requested = (
                            process.pid in self._shutdown_process_ids
                        ) or shutdown_requested
                        self._shutdown_process_ids.discard(process.pid)
                output_limited = output_limited or any(
                    path.stat().st_size > _MAX_CAPTURE_BYTES
                    for path in (stdout_path, stderr_path)
                )
                if output_limited:
                    for path in (stdout_path, stderr_path):
                        with path.open("r+b") as capture:
                            capture.truncate(_MAX_CAPTURE_BYTES)
                cancellation_status = (
                    "TIMED_OUT"
                    if timed_out
                    else "AUTHORIZATION_LOST"
                    if authorization_lost
                    else "AGENT_SHUTDOWN"
                    if shutdown_requested
                    else "NOT_REQUESTED"
                )
                return returncode, cancellation_status, output_limited
        except (OSError, subprocess.SubprocessError):
            raise ConfiguredExecutionError("CONFIGURED_OPERATION_FAILED") from None
        finally:
            if secret_path is not None:
                try:
                    secret_path.unlink()
                except FileNotFoundError:
                    pass

    def _prepare_simulator(
        self,
        workspace: Path,
        simulator_id: str,
        *,
        assert_authorized: Callable[[], None] | None,
    ) -> None:
        """Apply the fixed clean-state sequence before xcodebuild installs/tests."""

        commands = (
            (("xcrun", "simctl", "shutdown", simulator_id), True, 30),
            (("xcrun", "simctl", "erase", simulator_id), False, 60),
            (("xcrun", "simctl", "boot", simulator_id), False, 60),
            (("xcrun", "simctl", "bootstatus", simulator_id, "-b"), False, 120),
        )
        environment = {"LANG": "C", "LC_ALL": "C", "PATH": os.defpath}
        for command, allow_failure, timeout in commands:
            if self._shutdown.is_set():
                raise ConfiguredExecutionError("HOST_SHUTTING_DOWN")
            if assert_authorized is not None:
                assert_authorized()
            try:
                result = subprocess.run(
                    command,
                    cwd=workspace,
                    check=False,
                    capture_output=True,
                    env=environment,
                    timeout=timeout,
                )
            except (OSError, subprocess.SubprocessError):
                raise ConfiguredExecutionError("SIMULATOR_PREPARATION_FAILED") from None
            if result.returncode != 0 and not allow_failure:
                raise ConfiguredExecutionError("SIMULATOR_PREPARATION_FAILED")
        # The configured `xcodebuild test` invocation performs INSTALL_CANDIDATE
        # before launching the single pinned XCTest journey.

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        process_group_id = process.pid
        try:
            if os.getpgid(process.pid) != process_group_id:
                return
            os.killpg(process_group_id, signal.SIGTERM)
        except (PermissionError, ProcessLookupError):
            return
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            process.poll()
            try:
                os.killpg(process_group_id, 0)
            except (PermissionError, ProcessLookupError):
                return
            time.sleep(0.02)
        try:
            os.killpg(process_group_id, signal.SIGKILL)
        except (PermissionError, ProcessLookupError):
            return

    def _collect_configured_artifacts(
        self,
        workspace: Path,
        configuration: RepositoryConfiguration,
        *,
        task_id: UUID,
        captured_bytes: int,
        artifact_snapshot: dict[str, tuple[str, int]],
    ) -> list[ArtifactReference]:
        references: list[ArtifactReference] = []
        for relative, candidate in sorted(
            self._artifact_candidates(workspace, configuration).items()
        ):
            digest, candidate_size = HostArtifactStore._digest_file(candidate)
            if artifact_snapshot.get(relative) == (digest, candidate_size):
                continue
            if captured_bytes + candidate_size > _MAX_TOTAL_ARTIFACT_BYTES:
                raise ConfiguredExecutionError("ARTIFACT_LIMIT_EXCEEDED")
            references.append(
                self._artifacts.put_file(
                    candidate,
                    task_id=task_id,
                    role="CONFIGURED",
                    source_path=relative,
                )
            )
            captured_bytes += candidate_size
        return references

    def _artifact_snapshot(
        self,
        workspace: Path,
        configuration: RepositoryConfiguration,
    ) -> dict[str, tuple[str, int]]:
        return {
            relative: HostArtifactStore._digest_file(candidate)
            for relative, candidate in self._artifact_candidates(
                workspace,
                configuration,
            ).items()
        }

    @staticmethod
    def _artifact_candidates(
        workspace: Path,
        configuration: RepositoryConfiguration,
    ) -> dict[str, Path]:
        discovered: dict[str, Path] = {}
        for configured_path in configuration.artifacts.collection_paths:
            root = workspace / configured_path
            if not root.exists():
                continue
            try:
                if root.is_symlink() or root.resolve(strict=True) != root:
                    raise ConfiguredExecutionError("ARTIFACT_PATH_INVALID")
            except OSError:
                raise ConfiguredExecutionError("ARTIFACT_PATH_INVALID") from None
            candidates = (root,) if root.is_file() else root.rglob("*")
            for candidate in candidates:
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                try:
                    relative = candidate.relative_to(workspace).as_posix()
                except ValueError:
                    raise ConfiguredExecutionError("ARTIFACT_PATH_INVALID") from None
                discovered[relative] = candidate
                if len(discovered) > _MAX_ARTIFACTS:
                    raise ConfiguredExecutionError("ARTIFACT_LIMIT_EXCEEDED")
        return discovered
