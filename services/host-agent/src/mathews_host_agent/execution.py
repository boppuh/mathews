"""Bounded configured build/test execution with immutable artifact capture."""

from __future__ import annotations

import hashlib
import os
import signal
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from mathews_configuration import RepositoryConfiguration, TaskLeaseHostAuthority

from mathews_host_agent.workspaces import GitWorkspaceLifecycle, WorkspaceLifecycleError

_MAX_CAPTURE_BYTES = 128 * 1024 * 1024
_MAX_ARTIFACTS = 256


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
        role: str,
        source_path: str | None,
    ) -> ArtifactReference:
        self._prepare_root()
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
                dir=self._root,
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
            destination = self._root / digest.hexdigest()
            try:
                os.link(temporary_path, destination)
            except FileExistsError:
                if self._digest_file(destination) != (digest.hexdigest(), size):
                    raise ConfiguredExecutionError("ARTIFACT_CORRUPT") from None
            except OSError:
                raise ConfiguredExecutionError("ARTIFACT_STORE_UNAVAILABLE") from None
            return ArtifactReference(address, size, role, source_path)
        finally:
            os.close(descriptor)
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass

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
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._workspaces = workspaces
        self._artifacts = artifacts
        self._monotonic = monotonic

    def run(
        self,
        authority: TaskLeaseHostAuthority,
        configuration: RepositoryConfiguration,
        *,
        operation_id: str,
        expected_head_sha: str,
        validation_contract_version: int,
        effect_started: Callable[[], None] | None = None,
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
        try:
            before = self._workspaces.execution_context(
                authority,
                configuration,
                expected_head_sha=expected_head_sha,
            )
        except WorkspaceLifecycleError as error:
            raise ConfiguredExecutionError(error.code) from None
        workspace = Path(str(before["workspace_path"]))
        started = self._monotonic()
        with tempfile.TemporaryDirectory(prefix="execution-output-") as raw_output:
            output_root = Path(raw_output)
            stdout_path = output_root / "stdout"
            stderr_path = output_root / "stderr"
            if effect_started is not None:
                effect_started()
            returncode, timed_out, output_limited = self._execute(
                workspace,
                operation.argv,
                operation.timeout_seconds,
                stdout_path,
                stderr_path,
            )
            duration_ms = max(0, round((self._monotonic() - started) * 1000))
            references = [
                self._artifacts.put_file(stdout_path, role="STDOUT", source_path=None),
                self._artifacts.put_file(stderr_path, role="STDERR", source_path=None),
            ]
            references.extend(self._collect_configured_artifacts(workspace, configuration))
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
        cancellation_status = (
            "TIMED_OUT"
            if timed_out
            else "TERMINATED"
            if returncode < 0
            else "NOT_REQUESTED"
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

    @staticmethod
    def _execute(
        workspace: Path,
        argv: tuple[str, ...],
        timeout_seconds: int,
        stdout_path: Path,
        stderr_path: Path,
    ) -> tuple[int, bool, bool]:
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
        try:
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                process = subprocess.Popen(
                    argv,
                    cwd=workspace,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    start_new_session=True,
                )
                deadline = time.monotonic() + timeout_seconds
                timed_out = False
                output_limited = False
                while process.poll() is None:
                    timed_out = time.monotonic() >= deadline
                    output_limited = any(
                        path.stat().st_size > _MAX_CAPTURE_BYTES
                        for path in (stdout_path, stderr_path)
                    )
                    if timed_out or output_limited:
                        ConfiguredOperationRunner._terminate(process)
                        break
                    time.sleep(0.02)
                returncode = process.wait(timeout=2)
                if output_limited:
                    for path in (stdout_path, stderr_path):
                        with path.open("r+b") as capture:
                            capture.truncate(_MAX_CAPTURE_BYTES)
                return returncode, timed_out, output_limited
        except (OSError, subprocess.SubprocessError):
            raise ConfiguredExecutionError("CONFIGURED_OPERATION_FAILED") from None

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        try:
            if os.getpgid(process.pid) == process.pid:
                os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=2)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            if os.getpgid(process.pid) == process.pid:
                os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return

    def _collect_configured_artifacts(
        self,
        workspace: Path,
        configuration: RepositoryConfiguration,
    ) -> list[ArtifactReference]:
        references: list[ArtifactReference] = []
        for configured_path in configuration.artifacts.collection_paths:
            root = workspace / configured_path
            if not root.exists():
                continue
            try:
                if root.is_symlink() or root.resolve(strict=True) != root:
                    raise ConfiguredExecutionError("ARTIFACT_PATH_INVALID")
            except OSError:
                raise ConfiguredExecutionError("ARTIFACT_PATH_INVALID") from None
            discovered: list[Path] = []
            candidates = (root,) if root.is_file() else root.rglob("*")
            for candidate in candidates:
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                discovered.append(candidate)
                if len(references) + len(discovered) > _MAX_ARTIFACTS:
                    raise ConfiguredExecutionError("ARTIFACT_LIMIT_EXCEEDED")
            for candidate in sorted(discovered):
                try:
                    relative = candidate.relative_to(workspace).as_posix()
                except ValueError:
                    raise ConfiguredExecutionError("ARTIFACT_PATH_INVALID") from None
                references.append(
                    self._artifacts.put_file(
                        candidate,
                        role="CONFIGURED",
                        source_path=relative,
                    )
                )
        return references
