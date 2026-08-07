"""Task-owned, narrowly scoped Git workspace lifecycle operations."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from threading import RLock
from uuid import UUID, uuid4

from mathews_configuration import RepositoryConfiguration, TaskLeaseHostAuthority

_GIT_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_MANIFEST_VERSION = 1
_MAX_GIT_OUTPUT_BYTES = 64 * 1024
_GIT_TIMEOUT_SECONDS = 30


class WorkspaceLifecycleError(RuntimeError):
    """A stable workspace failure that does not expose local command output."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class WorkspaceOwnership:
    task_id: str
    job_id: str
    repository_key: str
    configuration_id: str
    configuration_digest: str
    repository_root: str
    workspace_path: str
    branch_name: str
    base_sha: str
    state: str

    def to_dict(self) -> dict[str, object]:
        return {
            "version": _MANIFEST_VERSION,
            "task_id": self.task_id,
            "job_id": self.job_id,
            "repository_key": self.repository_key,
            "configuration_id": self.configuration_id,
            "configuration_digest": self.configuration_digest,
            "repository_root": self.repository_root,
            "workspace_path": self.workspace_path,
            "branch_name": self.branch_name,
            "base_sha": self.base_sha,
            "state": self.state,
        }

    @classmethod
    def from_dict(cls, value: object) -> WorkspaceOwnership:
        if not isinstance(value, dict) or set(value) != {
            "version",
            "task_id",
            "job_id",
            "repository_key",
            "configuration_id",
            "configuration_digest",
            "repository_root",
            "workspace_path",
            "branch_name",
            "base_sha",
            "state",
        }:
            raise WorkspaceLifecycleError("WORKSPACE_OWNERSHIP_CORRUPT")
        if value["version"] != _MANIFEST_VERSION:
            raise WorkspaceLifecycleError("WORKSPACE_OWNERSHIP_CORRUPT")
        string_fields = {
            name: value[name]
            for name in value
            if name != "version"
        }
        if any(not isinstance(item, str) for item in string_fields.values()):
            raise WorkspaceLifecycleError("WORKSPACE_OWNERSHIP_CORRUPT")
        try:
            task_id = UUID(string_fields["task_id"])
            job_id = UUID(string_fields["job_id"])
            configuration_id = UUID(string_fields["configuration_id"])
        except ValueError:
            raise WorkspaceLifecycleError("WORKSPACE_OWNERSHIP_CORRUPT") from None
        if (
            str(task_id) != string_fields["task_id"]
            or str(job_id) != string_fields["job_id"]
            or str(configuration_id) != string_fields["configuration_id"]
            or _GIT_OBJECT.fullmatch(string_fields["base_sha"]) is None
            or string_fields["state"] not in {"CREATING", "ACTIVE", "CLEANED"}
        ):
            raise WorkspaceLifecycleError("WORKSPACE_OWNERSHIP_CORRUPT")
        return cls(**string_fields)


class GitWorkspaceLifecycle:
    """Create, inspect, and clean only workspaces proven to belong to a task."""

    def __init__(self, root: Path) -> None:
        if not root.is_absolute():
            raise ValueError("workspace registry root must be absolute")
        self._root = root
        self._lock = RLock()

    def create(
        self,
        authority: TaskLeaseHostAuthority,
        configuration: RepositoryConfiguration,
    ) -> dict[str, object]:
        with self._lock:
            return self._create(authority, configuration)

    def _create(
        self,
        authority: TaskLeaseHostAuthority,
        configuration: RepositoryConfiguration,
    ) -> dict[str, object]:
        repository_root = self._repository_root(configuration)
        self._prepare_root()
        branch_name = configuration.git.task_branch_template.format(
            task_id=str(authority.task_id)
        )
        self._validate_branch(repository_root, branch_name)
        workspace_path = self._workspace_path(authority.task_id)
        manifest_path = self._manifest_path(authority.task_id)
        ownership = self._read_ownership(manifest_path)
        if ownership is not None:
            self._assert_owned(
                ownership,
                authority=authority,
                configuration=configuration,
                repository_root=repository_root,
                workspace_path=workspace_path,
                branch_name=branch_name,
            )
            if ownership.state == "CLEANED":
                raise WorkspaceLifecycleError("WORKSPACE_ALREADY_CLEANED")
            if ownership.state == "ACTIVE":
                return self._repository_state(ownership)
            return self._resume_creation(ownership, manifest_path)

        if workspace_path.exists() or workspace_path.is_symlink():
            raise WorkspaceLifecycleError("WORKSPACE_NOT_OWNED")
        if self._branch_sha(repository_root, branch_name) is not None:
            raise WorkspaceLifecycleError("BRANCH_NOT_OWNED")
        base_sha = self._git_object(
            repository_root,
            "rev-parse",
            "--verify",
            "--end-of-options",
            f"{configuration.git.default_base_ref}^{{commit}}",
            failure_code="BASE_REVISION_UNAVAILABLE",
        )
        ownership = WorkspaceOwnership(
            task_id=str(authority.task_id),
            job_id=str(authority.job_id),
            repository_key=authority.repository_key,
            configuration_id=str(authority.configuration_id),
            configuration_digest=authority.configuration_digest,
            repository_root=str(repository_root),
            workspace_path=str(workspace_path),
            branch_name=branch_name,
            base_sha=base_sha,
            state="CREATING",
        )
        self._write_ownership(manifest_path, ownership)
        return self._resume_creation(ownership, manifest_path)

    def inspect(
        self,
        authority: TaskLeaseHostAuthority,
        configuration: RepositoryConfiguration,
    ) -> dict[str, object]:
        with self._lock:
            return self._inspect(authority, configuration)

    def _inspect(
        self,
        authority: TaskLeaseHostAuthority,
        configuration: RepositoryConfiguration,
    ) -> dict[str, object]:
        repository_root = self._repository_root(configuration)
        if not self._root.exists():
            raise WorkspaceLifecycleError("WORKSPACE_NOT_FOUND")
        self._validate_root()
        workspace_path = self._workspace_path(authority.task_id)
        branch_name = configuration.git.task_branch_template.format(
            task_id=str(authority.task_id)
        )
        ownership = self._read_ownership(self._manifest_path(authority.task_id))
        if ownership is None:
            raise WorkspaceLifecycleError("WORKSPACE_NOT_FOUND")
        self._assert_owned(
            ownership,
            authority=authority,
            configuration=configuration,
            repository_root=repository_root,
            workspace_path=workspace_path,
            branch_name=branch_name,
        )
        if ownership.state != "ACTIVE":
            raise WorkspaceLifecycleError(
                "WORKSPACE_ALREADY_CLEANED"
                if ownership.state == "CLEANED"
                else "WORKSPACE_INCOMPLETE"
            )
        return self._repository_state(ownership)

    def cleanup(
        self,
        authority: TaskLeaseHostAuthority,
        configuration: RepositoryConfiguration,
        *,
        reason: str,
        cancellation_id: UUID | None,
    ) -> dict[str, object]:
        with self._lock:
            return self._cleanup(
                authority,
                configuration,
                reason=reason,
                cancellation_id=cancellation_id,
            )

    def _cleanup(
        self,
        authority: TaskLeaseHostAuthority,
        configuration: RepositoryConfiguration,
        *,
        reason: str,
        cancellation_id: UUID | None,
    ) -> dict[str, object]:
        repository_root = self._repository_root(configuration)
        self._prepare_root()
        manifest_path = self._manifest_path(authority.task_id)
        ownership = self._read_ownership(manifest_path)
        if ownership is None:
            return self._cleanup_result(
                authority.task_id,
                reason=reason,
                cancellation_id=cancellation_id,
                state="ABSENT",
            )
        expected_path = self._workspace_path(authority.task_id)
        branch_name = configuration.git.task_branch_template.format(
            task_id=str(authority.task_id)
        )
        self._assert_owned(
            ownership,
            authority=authority,
            configuration=configuration,
            repository_root=repository_root,
            workspace_path=expected_path,
            branch_name=branch_name,
        )
        if ownership.state == "CLEANED":
            return self._cleanup_result(
                authority.task_id,
                reason=reason,
                cancellation_id=cancellation_id,
                state="CLEANED",
            )

        workspace_path = Path(ownership.workspace_path)
        if workspace_path.is_symlink():
            raise WorkspaceLifecycleError("WORKSPACE_BOUNDARY_VIOLATION")
        if workspace_path.exists():
            if str(workspace_path) in self._registered_worktrees(
                repository_root
            ):
                self._run_git(
                    repository_root,
                    "worktree",
                    "remove",
                    "--force",
                    str(workspace_path),
                    failure_code="WORKSPACE_CLEANUP_FAILED",
                )
            else:
                self._remove_owned_partial_path(workspace_path)
        else:
            self._run_git(
                repository_root,
                "worktree",
                "prune",
                "--expire",
                "now",
                failure_code="WORKSPACE_CLEANUP_FAILED",
            )
        branch_sha = self._branch_sha(
            repository_root,
            ownership.branch_name,
        )
        if branch_sha is not None:
            self._run_git(
                repository_root,
                "branch",
                "-D",
                "--",
                ownership.branch_name,
                failure_code="WORKSPACE_CLEANUP_FAILED",
            )
        self._write_ownership(
            manifest_path,
            replace(ownership, state="CLEANED"),
        )
        return self._cleanup_result(
            authority.task_id,
            reason=reason,
            cancellation_id=cancellation_id,
            state="CLEANED",
        )

    def _resume_creation(
        self,
        ownership: WorkspaceOwnership,
        manifest_path: Path,
    ) -> dict[str, object]:
        repository_root = Path(ownership.repository_root)
        workspace_path = Path(ownership.workspace_path)
        branch_sha = self._branch_sha(repository_root, ownership.branch_name)
        if workspace_path.is_symlink():
            raise WorkspaceLifecycleError("WORKSPACE_BOUNDARY_VIOLATION")
        if not workspace_path.exists():
            if branch_sha is None:
                self._run_git(
                    repository_root,
                    "worktree",
                    "add",
                    "-b",
                    ownership.branch_name,
                    str(workspace_path),
                    ownership.base_sha,
                    failure_code="WORKSPACE_CREATE_FAILED",
                )
            elif branch_sha == ownership.base_sha:
                self._run_git(
                    repository_root,
                    "worktree",
                    "add",
                    str(workspace_path),
                    ownership.branch_name,
                    failure_code="WORKSPACE_CREATE_FAILED",
                )
            else:
                raise WorkspaceLifecycleError("BRANCH_OWNERSHIP_CONFLICT")
        state = self._repository_state(ownership)
        if state["head_sha"] != ownership.base_sha:
            raise WorkspaceLifecycleError("WORKSPACE_BASE_MISMATCH")
        active = replace(ownership, state="ACTIVE")
        self._write_ownership(manifest_path, active)
        return state

    def _repository_state(self, ownership: WorkspaceOwnership) -> dict[str, object]:
        workspace_path = Path(ownership.workspace_path)
        if not workspace_path.is_dir() or workspace_path.is_symlink():
            raise WorkspaceLifecycleError("WORKSPACE_UNAVAILABLE")
        top_level = self._run_git(
            workspace_path,
            "rev-parse",
            "--show-toplevel",
            failure_code="WORKSPACE_UNAVAILABLE",
        )
        try:
            resolved_top_level = Path(top_level).resolve(strict=True)
            resolved_workspace = workspace_path.resolve(strict=True)
        except OSError:
            raise WorkspaceLifecycleError("WORKSPACE_UNAVAILABLE") from None
        if resolved_top_level != resolved_workspace:
            raise WorkspaceLifecycleError("WORKSPACE_BOUNDARY_VIOLATION")
        branch_name = self._run_git(
            workspace_path,
            "symbolic-ref",
            "--quiet",
            "--short",
            "HEAD",
            failure_code="WORKSPACE_UNAVAILABLE",
        )
        if branch_name != ownership.branch_name:
            raise WorkspaceLifecycleError("BRANCH_OWNERSHIP_CONFLICT")
        head_sha = self._git_object(
            workspace_path,
            "rev-parse",
            "--verify",
            "HEAD^{commit}",
            failure_code="WORKSPACE_UNAVAILABLE",
        )
        tree_sha = self._git_object(
            workspace_path,
            "rev-parse",
            "--verify",
            "HEAD^{tree}",
            failure_code="WORKSPACE_UNAVAILABLE",
        )
        status = self._run_git(
            workspace_path,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            failure_code="WORKSPACE_UNAVAILABLE",
        )
        return {
            "task_id": ownership.task_id,
            "repository_key": ownership.repository_key,
            "workspace_path": ownership.workspace_path,
            "branch_name": ownership.branch_name,
            "base_sha": ownership.base_sha,
            "head_sha": head_sha,
            "tree_sha": tree_sha,
            "clean": not status,
        }

    def _repository_root(self, configuration: RepositoryConfiguration) -> Path:
        configured = Path(configuration.repository.root)
        try:
            repository_root = configured.resolve(strict=True)
        except OSError:
            raise WorkspaceLifecycleError("REPOSITORY_UNAVAILABLE") from None
        if (
            str(repository_root) != configuration.repository.root
            or not repository_root.is_dir()
        ):
            raise WorkspaceLifecycleError("REPOSITORY_BOUNDARY_MISMATCH")
        top_level = self._run_git(
            repository_root,
            "rev-parse",
            "--show-toplevel",
            failure_code="REPOSITORY_UNAVAILABLE",
        )
        if top_level != str(repository_root):
            raise WorkspaceLifecycleError("REPOSITORY_BOUNDARY_MISMATCH")
        return repository_root

    def _assert_owned(
        self,
        ownership: WorkspaceOwnership,
        *,
        authority: TaskLeaseHostAuthority,
        configuration: RepositoryConfiguration,
        repository_root: Path,
        workspace_path: Path,
        branch_name: str,
    ) -> None:
        self._assert_authority_binding(ownership, authority)
        if (
            ownership.repository_root != str(repository_root)
            or ownership.workspace_path != str(workspace_path)
            or ownership.branch_name != branch_name
            or ownership.repository_key != configuration.repository_key
        ):
            raise WorkspaceLifecycleError("WORKSPACE_NOT_OWNED")

    @staticmethod
    def _assert_authority_binding(
        ownership: WorkspaceOwnership,
        authority: TaskLeaseHostAuthority,
    ) -> None:
        if (
            ownership.task_id != str(authority.task_id)
            or ownership.repository_key != authority.repository_key
            or ownership.configuration_id != str(authority.configuration_id)
            or ownership.configuration_digest != authority.configuration_digest
        ):
            raise WorkspaceLifecycleError("WORKSPACE_NOT_OWNED")

    def _prepare_root(self) -> None:
        try:
            self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
            root_stat = self._root.lstat()
            (self._root / "ownership").mkdir(mode=0o700, exist_ok=True)
            ownership_stat = (self._root / "ownership").lstat()
            (self._root / "tasks").mkdir(mode=0o700, exist_ok=True)
            tasks_stat = (self._root / "tasks").lstat()
        except OSError:
            raise WorkspaceLifecycleError("WORKSPACE_REGISTRY_UNAVAILABLE") from None
        self._validate_root_stats(root_stat, ownership_stat, tasks_stat)

    def _validate_root(self) -> None:
        try:
            root_stat = self._root.lstat()
            ownership_stat = (self._root / "ownership").lstat()
            tasks_stat = (self._root / "tasks").lstat()
        except OSError:
            raise WorkspaceLifecycleError("WORKSPACE_REGISTRY_UNAVAILABLE") from None
        self._validate_root_stats(root_stat, ownership_stat, tasks_stat)

    @staticmethod
    def _validate_root_stats(*directory_stats: os.stat_result) -> None:
        for directory_stat in directory_stats:
            if (
                not stat.S_ISDIR(directory_stat.st_mode)
                or directory_stat.st_uid != os.geteuid()
                or stat.S_IMODE(directory_stat.st_mode) & 0o077
            ):
                raise WorkspaceLifecycleError("UNSAFE_WORKSPACE_REGISTRY")

    def _manifest_path(self, task_id: UUID) -> Path:
        return self._root / "ownership" / f"{task_id}.json"

    def _workspace_path(self, task_id: UUID) -> Path:
        return self._root / "tasks" / str(task_id)

    def _read_ownership(self, path: Path) -> WorkspaceOwnership | None:
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        except OSError:
            raise WorkspaceLifecycleError("WORKSPACE_OWNERSHIP_CORRUPT") from None
        try:
            file_stat = os.fstat(descriptor)
            if (
                not stat.S_ISREG(file_stat.st_mode)
                or file_stat.st_uid != os.geteuid()
                or stat.S_IMODE(file_stat.st_mode) & 0o077
                or file_stat.st_size > 16 * 1024
            ):
                raise WorkspaceLifecycleError("WORKSPACE_OWNERSHIP_CORRUPT")
            with os.fdopen(descriptor, encoding="utf-8") as ownership_file:
                descriptor = -1
                return WorkspaceOwnership.from_dict(json.load(ownership_file))
        except (json.JSONDecodeError, OSError, UnicodeError):
            raise WorkspaceLifecycleError("WORKSPACE_OWNERSHIP_CORRUPT") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _write_ownership(self, path: Path, ownership: WorkspaceOwnership) -> None:
        temporary = path.with_name(f".{path.name}.{uuid4()}.tmp")
        payload = json.dumps(
            ownership.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            try:
                offset = 0
                while offset < len(payload):
                    written = os.write(descriptor, payload[offset:])
                    if written <= 0:
                        raise OSError("ownership manifest write did not advance")
                    offset += written
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, path)
            directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except OSError:
            try:
                temporary.unlink()
            except OSError:
                pass
            raise WorkspaceLifecycleError("WORKSPACE_REGISTRY_UNAVAILABLE") from None

    @staticmethod
    def _cleanup_result(
        task_id: UUID,
        *,
        reason: str,
        cancellation_id: UUID | None,
        state: str,
    ) -> dict[str, object]:
        return {
            "task_id": str(task_id),
            "state": state,
            "reason": reason,
            "cancellation_id": (
                None if cancellation_id is None else str(cancellation_id)
            ),
        }

    def _validate_branch(self, repository_root: Path, branch_name: str) -> None:
        self._run_git(
            repository_root,
            "check-ref-format",
            "--branch",
            branch_name,
            failure_code="INVALID_TASK_BRANCH",
        )

    def _branch_sha(self, repository_root: Path, branch_name: str) -> str | None:
        result = self._run_git_result(
            repository_root,
            "rev-parse",
            "--verify",
            "--quiet",
            f"refs/heads/{branch_name}^{{commit}}",
        )
        if result.returncode == 1:
            return None
        if result.returncode != 0:
            raise WorkspaceLifecycleError("REPOSITORY_UNAVAILABLE")
        return self._validated_git_object(result.stdout)

    def _registered_worktrees(self, repository_root: Path) -> frozenset[str]:
        output = self._run_git(
            repository_root,
            "worktree",
            "list",
            "--porcelain",
            "-z",
            failure_code="WORKSPACE_CLEANUP_FAILED",
        )
        paths = {
            field.removeprefix("worktree ")
            for field in output.split("\0")
            if field.startswith("worktree ")
        }
        if not paths or any(not path.startswith("/") for path in paths):
            raise WorkspaceLifecycleError("INVALID_REPOSITORY_STATE")
        return frozenset(paths)

    def _remove_owned_partial_path(self, workspace_path: Path) -> None:
        try:
            if workspace_path.parent.resolve(strict=True) != (
                self._root / "tasks"
            ).resolve(strict=True):
                raise WorkspaceLifecycleError("WORKSPACE_BOUNDARY_VIOLATION")
            path_stat = workspace_path.lstat()
            if stat.S_ISLNK(path_stat.st_mode):
                raise WorkspaceLifecycleError("WORKSPACE_BOUNDARY_VIOLATION")
            if stat.S_ISDIR(path_stat.st_mode):
                shutil.rmtree(workspace_path)
            else:
                workspace_path.unlink()
        except WorkspaceLifecycleError:
            raise
        except OSError:
            raise WorkspaceLifecycleError("WORKSPACE_CLEANUP_FAILED") from None

    def _git_object(
        self,
        repository_root: Path,
        *arguments: str,
        failure_code: str,
    ) -> str:
        return self._validated_git_object(
            self._run_git(
                repository_root,
                *arguments,
                failure_code=failure_code,
            )
        )

    @staticmethod
    def _validated_git_object(value: str) -> str:
        if _GIT_OBJECT.fullmatch(value) is None:
            raise WorkspaceLifecycleError("INVALID_REPOSITORY_STATE")
        return value

    def _run_git(
        self,
        repository_root: Path,
        *arguments: str,
        failure_code: str,
    ) -> str:
        result = self._run_git_result(repository_root, *arguments)
        if result.returncode != 0:
            raise WorkspaceLifecycleError(failure_code)
        return result.stdout

    @staticmethod
    def _run_git_result(
        repository_root: Path,
        *arguments: str,
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        }
        try:
            result = subprocess.run(
                (
                    "git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-C",
                    str(repository_root),
                    *arguments,
                ),
                check=False,
                capture_output=True,
                env=environment,
                text=True,
                timeout=_GIT_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise WorkspaceLifecycleError("GIT_UNAVAILABLE") from None
        if (
            len(result.stdout.encode("utf-8")) > _MAX_GIT_OUTPUT_BYTES
            or len(result.stderr.encode("utf-8")) > _MAX_GIT_OUTPUT_BYTES
        ):
            raise WorkspaceLifecycleError("GIT_OUTPUT_TOO_LARGE")
        result.stdout = result.stdout.rstrip("\n")
        return result
