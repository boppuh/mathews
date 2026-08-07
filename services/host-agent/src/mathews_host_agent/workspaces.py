"""Task-owned, narrowly scoped Git workspace lifecycle operations."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from threading import RLock
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from mathews_configuration import (
    RepositoryConfiguration,
    SecretValue,
    TaskLeaseHostAuthority,
)

from mathews_host_agent.git_transport import GitPushTransport, GitTransportError

_GIT_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_MANIFEST_VERSION = 2
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
    candidate_head_sha: str | None = None

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
            "candidate_head_sha": self.candidate_head_sha,
        }

    @classmethod
    def from_dict(cls, value: object) -> WorkspaceOwnership:
        common_fields = {
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
        }
        if not isinstance(value, dict):
            raise WorkspaceLifecycleError("WORKSPACE_OWNERSHIP_CORRUPT")
        version = value.get("version")
        expected_fields = (
            common_fields
            if version == 1
            else common_fields | {"candidate_head_sha"}
            if version == _MANIFEST_VERSION
            else set()
        )
        if not expected_fields or set(value) != expected_fields:
            raise WorkspaceLifecycleError("WORKSPACE_OWNERSHIP_CORRUPT")
        string_fields = {
            name: value[name]
            for name in value
            if name not in {"version", "candidate_head_sha"}
        }
        if any(not isinstance(item, str) for item in string_fields.values()):
            raise WorkspaceLifecycleError("WORKSPACE_OWNERSHIP_CORRUPT")
        candidate_head_sha = value.get("candidate_head_sha")
        if candidate_head_sha is not None and (
            not isinstance(candidate_head_sha, str)
            or _GIT_OBJECT.fullmatch(candidate_head_sha) is None
        ):
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
        return cls(**string_fields, candidate_head_sha=candidate_head_sha)


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
        self._assert_no_external_filters(repository_root)
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
        ownership = self._active_ownership(authority, configuration)
        return self._repository_state(ownership)

    def inspect_git(
        self,
        authority: TaskLeaseHostAuthority,
        configuration: RepositoryConfiguration,
    ) -> dict[str, object]:
        with self._lock:
            ownership = self._active_ownership(authority, configuration)
            return self._git_boundary_state(ownership, configuration)

    def commit_candidate(
        self,
        authority: TaskLeaseHostAuthority,
        configuration: RepositoryConfiguration,
        *,
        expected_head_sha: str,
        message: str,
    ) -> dict[str, object]:
        with self._lock:
            ownership = self._active_ownership(authority, configuration)
            before = self._git_boundary_state(ownership, configuration)
            if before["head_sha"] != expected_head_sha:
                raise WorkspaceLifecycleError("HEAD_MISMATCH")
            if expected_head_sha != ownership.base_sha:
                raise WorkspaceLifecycleError("CANDIDATE_PARENT_NOT_FROZEN_BASE")
            changed_paths = self._changed_paths(ownership)
            if not changed_paths:
                raise WorkspaceLifecycleError("NOTHING_TO_COMMIT")
            self._assert_paths_allowed(changed_paths, configuration)
            workspace_path = Path(ownership.workspace_path)
            identity_environment = {
                "GIT_AUTHOR_NAME": configuration.git.author.name,
                "GIT_AUTHOR_EMAIL": configuration.git.author.email,
                "GIT_COMMITTER_NAME": configuration.git.committer.name,
                "GIT_COMMITTER_EMAIL": configuration.git.committer.email,
            }
            candidate_head_sha, staged_paths = self._create_isolated_commit(
                ownership,
                expected_head_sha=expected_head_sha,
                message=message,
                changed_paths=changed_paths,
                identity_environment=identity_environment,
            )
            self._assert_paths_allowed(staged_paths, configuration)
            current_changed_paths = self._changed_paths(ownership)
            self._assert_paths_allowed(current_changed_paths, configuration)
            if current_changed_paths != changed_paths:
                raise WorkspaceLifecycleError("CANDIDATE_COMMIT_INVALID")
            manifest_path = self._manifest_path(authority.task_id)
            candidate_ownership = replace(
                ownership,
                candidate_head_sha=candidate_head_sha,
            )
            self._write_ownership(manifest_path, candidate_ownership)
            self._run_git(
                workspace_path,
                "read-tree",
                candidate_head_sha,
                failure_code="GIT_COMMIT_FAILED",
            )
            self._run_git(
                workspace_path,
                "update-ref",
                "HEAD",
                candidate_head_sha,
                expected_head_sha,
                failure_code="GIT_COMMIT_FAILED",
            )
            after = self._git_boundary_state(ownership, configuration)
            parents = after["parent_shas"]
            if (
                not after["clean"]
                or after["head_sha"] == expected_head_sha
                or not isinstance(parents, list)
                or parents != [expected_head_sha]
            ):
                if after["head_sha"] == candidate_head_sha:
                    self._run_git(
                        workspace_path,
                        "update-ref",
                        "HEAD",
                        expected_head_sha,
                        candidate_head_sha,
                        failure_code="GIT_COMMIT_FAILED",
                    )
                    self._run_git(
                        workspace_path,
                        "read-tree",
                        expected_head_sha,
                        failure_code="GIT_COMMIT_FAILED",
                    )
                    self._write_ownership(manifest_path, ownership)
                raise WorkspaceLifecycleError("CANDIDATE_COMMIT_INVALID")
            if after["head_sha"] != candidate_head_sha:
                raise WorkspaceLifecycleError("CANDIDATE_COMMIT_INVALID")
            return {
                **after,
                "committed": True,
                "changed_paths": list(staged_paths),
            }

    def push_candidate(
        self,
        authority: TaskLeaseHostAuthority,
        configuration: RepositoryConfiguration,
        *,
        expected_head_sha: str,
        credential: SecretValue,
        transport: GitPushTransport,
        effect_started: Callable[[], None] | None = None,
    ) -> dict[str, object]:
        with self._lock:
            ownership = self._active_ownership(authority, configuration)
            state = self._git_boundary_state(ownership, configuration)
            if state["head_sha"] != expected_head_sha:
                raise WorkspaceLifecycleError("HEAD_MISMATCH")
            if expected_head_sha == ownership.base_sha:
                raise WorkspaceLifecycleError("CANDIDATE_COMMIT_REQUIRED")
            if ownership.candidate_head_sha != expected_head_sha:
                raise WorkspaceLifecycleError("CANDIDATE_COMMIT_NOT_HOST_OWNED")
            if state["parent_shas"] != [ownership.base_sha]:
                raise WorkspaceLifecycleError("CANDIDATE_COMMIT_INVALID")
            if not state["clean"]:
                raise WorkspaceLifecycleError("WORKSPACE_NOT_CLEAN")
            self._assert_paths_allowed(
                self._candidate_history_paths(ownership),
                configuration,
            )
            remote_url = self._push_remote_url(ownership, configuration)
        try:
            observation = transport.push(
                workspace_path=Path(ownership.workspace_path),
                remote_url=remote_url,
                branch_name=ownership.branch_name,
                expected_sha=expected_head_sha,
                credential=credential,
                before_mutation=effect_started,
            )
        except GitTransportError as error:
            raise WorkspaceLifecycleError(error.code) from None
        with self._lock:
            current_ownership = self._active_ownership(authority, configuration)
            if current_ownership != ownership:
                raise WorkspaceLifecycleError("LOCAL_HEAD_CHANGED_DURING_PUSH")
            after = self._git_boundary_state(current_ownership, configuration)
            if after["head_sha"] != expected_head_sha or not after["clean"]:
                raise WorkspaceLifecycleError("LOCAL_HEAD_CHANGED_DURING_PUSH")
            return {
                **after,
                "remote_head_before": observation.before_sha,
                "remote_head_after": observation.after_sha,
                "pushed": observation.pushed,
            }

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

    def _active_ownership(
        self,
        authority: TaskLeaseHostAuthority,
        configuration: RepositoryConfiguration,
    ) -> WorkspaceOwnership:
        repository_root = self._repository_root(configuration)
        self._assert_no_external_filters(repository_root)
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
        return ownership

    def _assert_no_external_filters(self, repository_root: Path) -> None:
        result = self._run_git_result(
            repository_root,
            "config",
            "--name-only",
            "--get-regexp",
            r"^filter\..*\.(clean|process|smudge)$",
        )
        if result.returncode == 0:
            raise WorkspaceLifecycleError("GIT_FILTER_CONFIGURATION_PROHIBITED")
        if result.returncode != 1:
            raise WorkspaceLifecycleError("GIT_FILTER_CONFIGURATION_UNAVAILABLE")

    def _git_boundary_state(
        self,
        ownership: WorkspaceOwnership,
        configuration: RepositoryConfiguration,
    ) -> dict[str, object]:
        state = self._repository_state(ownership)
        ancestry = self._run_git_result(
            Path(ownership.workspace_path),
            "merge-base",
            "--is-ancestor",
            ownership.base_sha,
            "HEAD",
        )
        if ancestry.returncode == 1:
            raise WorkspaceLifecycleError("BASE_NOT_ANCESTOR")
        if ancestry.returncode != 0:
            raise WorkspaceLifecycleError("COMMIT_ANCESTRY_UNAVAILABLE")
        # Validate the effective push remote at every Git boundary.
        self._push_remote_url(ownership, configuration)
        metadata = self._run_git(
            Path(ownership.workspace_path),
            "show",
            "-s",
            "--format=%an%x00%ae%x00%cn%x00%ce%x00%P",
            "HEAD",
            failure_code="COMMIT_METADATA_UNAVAILABLE",
        ).split("\0")
        if len(metadata) != 5:
            raise WorkspaceLifecycleError("COMMIT_METADATA_INVALID")
        author_name, author_email, committer_name, committer_email, parents = metadata
        actual_identity = (
            author_name,
            author_email,
            committer_name,
            committer_email,
        )
        expected_identity = (
            configuration.git.author.name,
            configuration.git.author.email,
            configuration.git.committer.name,
            configuration.git.committer.email,
        )
        if state["head_sha"] != ownership.base_sha and actual_identity != expected_identity:
            raise WorkspaceLifecycleError("COMMIT_IDENTITY_MISMATCH")
        parent_shas = [] if not parents else parents.split(" ")
        if any(_GIT_OBJECT.fullmatch(parent) is None for parent in parent_shas):
            raise WorkspaceLifecycleError("COMMIT_METADATA_INVALID")
        return {
            **state,
            "remote_name": configuration.git.remote_name,
            "author_name": author_name,
            "author_email": author_email,
            "committer_name": committer_name,
            "committer_email": committer_email,
            "parent_shas": parent_shas,
        }

    def _changed_paths(self, ownership: WorkspaceOwnership) -> tuple[str, ...]:
        workspace_path = Path(ownership.workspace_path)
        commands = (
            ("diff", "--name-only", "--no-renames", "-z"),
            ("diff", "--cached", "--name-only", "--no-renames", "-z"),
            ("ls-files", "--others", "--exclude-standard", "-z"),
        )
        paths: set[str] = set()
        for command in commands:
            output = self._run_git(
                workspace_path,
                *command,
                failure_code="GIT_STATUS_UNAVAILABLE",
            )
            paths.update(path for path in output.split("\0") if path)
        return tuple(sorted(paths))

    def _create_isolated_commit(
        self,
        ownership: WorkspaceOwnership,
        *,
        expected_head_sha: str,
        message: str,
        changed_paths: tuple[str, ...],
        identity_environment: Mapping[str, str],
    ) -> tuple[str, tuple[str, ...]]:
        workspace_path = Path(ownership.workspace_path)
        object_directory = self._git_object_directory(workspace_path)
        try:
            with tempfile.TemporaryDirectory(
                prefix="commit-",
                dir=self._root,
            ) as raw_directory:
                git_directory = Path(raw_directory)
                self._write_isolated_git_config(git_directory, expected_head_sha)
                self._run_isolated_git(
                    git_directory,
                    workspace_path,
                    object_directory,
                    "read-tree",
                    expected_head_sha,
                    failure_code="GIT_STAGE_FAILED",
                )
                self._run_isolated_git(
                    git_directory,
                    workspace_path,
                    object_directory,
                    "add",
                    "--all",
                    f"--pathspec-from-file={self._write_pathspec(git_directory, changed_paths)}",
                    "--pathspec-file-nul",
                    failure_code="GIT_STAGE_FAILED",
                )
                staged_output = self._run_isolated_git(
                    git_directory,
                    workspace_path,
                    object_directory,
                    "diff",
                    "--cached",
                    "--name-only",
                    "--no-renames",
                    "-z",
                    failure_code="GIT_STATUS_UNAVAILABLE",
                )
                staged_paths = tuple(
                    sorted(path for path in staged_output.split("\0") if path)
                )
                if not staged_paths:
                    raise WorkspaceLifecycleError("NOTHING_TO_COMMIT")
                tree_sha = self._validated_git_object(
                    self._run_isolated_git(
                        git_directory,
                        workspace_path,
                        object_directory,
                        "write-tree",
                        failure_code="GIT_COMMIT_FAILED",
                    )
                )
                candidate_head_sha = self._validated_git_object(
                    self._run_isolated_git(
                        git_directory,
                        workspace_path,
                        object_directory,
                        "commit-tree",
                        tree_sha,
                        "-p",
                        expected_head_sha,
                        "-m",
                        message,
                        failure_code="GIT_COMMIT_FAILED",
                        extra_environment=identity_environment,
                    )
                )
                return candidate_head_sha, staged_paths
        except WorkspaceLifecycleError:
            raise
        except OSError:
            raise WorkspaceLifecycleError("GIT_STAGE_FAILED") from None

    def _git_object_directory(self, workspace_path: Path) -> Path:
        raw_path = self._run_git(
            workspace_path,
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "objects",
            failure_code="GIT_STAGE_FAILED",
        )
        try:
            object_directory = Path(raw_path).resolve(strict=True)
            directory_stat = object_directory.lstat()
        except OSError:
            raise WorkspaceLifecycleError("GIT_STAGE_FAILED") from None
        if (
            not object_directory.is_absolute()
            or not stat.S_ISDIR(directory_stat.st_mode)
            or directory_stat.st_uid != os.geteuid()
        ):
            raise WorkspaceLifecycleError("GIT_STAGE_FAILED")
        alternates_path = object_directory / "info" / "alternates"
        try:
            if alternates_path.exists() and alternates_path.read_bytes().strip():
                raise WorkspaceLifecycleError("GIT_OBJECT_ALTERNATES_PROHIBITED")
        except OSError:
            raise WorkspaceLifecycleError("GIT_STAGE_FAILED") from None
        return object_directory

    def _write_pathspec(
        self,
        git_directory: Path,
        changed_paths: tuple[str, ...],
    ) -> Path:
        path = git_directory / "candidate-paths"
        self._write_private_file(path, "\0".join(changed_paths) + "\0")
        return path

    def _write_isolated_git_config(
        self,
        git_directory: Path,
        expected_head_sha: str,
    ) -> None:
        (git_directory / "refs" / "heads").mkdir(mode=0o700, parents=True)
        object_format = "sha256" if len(expected_head_sha) == 64 else "sha1"
        repository_version = "1" if object_format == "sha256" else "0"
        config = (
            "[core]\n"
            f"\trepositoryformatversion = {repository_version}\n"
            "\tbare = false\n"
        )
        if object_format == "sha256":
            config += "[extensions]\n\tobjectformat = sha256\n"
        self._write_private_file(git_directory / "config", config)
        self._write_private_file(git_directory / "HEAD", f"{expected_head_sha}\n")

    def _run_isolated_git(
        self,
        git_directory: Path,
        workspace_path: Path,
        object_directory: Path,
        *arguments: str,
        failure_code: str,
        extra_environment: Mapping[str, str] | None = None,
    ) -> str:
        environment = {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_OBJECT_DIRECTORY": str(object_directory),
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        }
        if extra_environment is not None:
            if set(environment) & set(extra_environment):
                raise WorkspaceLifecycleError("GIT_ENVIRONMENT_OVERRIDE")
            environment.update(extra_environment)
        try:
            result = subprocess.run(
                (
                    "git",
                    f"--git-dir={git_directory}",
                    f"--work-tree={workspace_path}",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "core.fsmonitor=false",
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
            len(result.stdout.encode()) > _MAX_GIT_OUTPUT_BYTES
            or len(result.stderr.encode()) > _MAX_GIT_OUTPUT_BYTES
        ):
            raise WorkspaceLifecycleError("GIT_OUTPUT_TOO_LARGE")
        if result.returncode != 0:
            raise WorkspaceLifecycleError(failure_code)
        return result.stdout.rstrip("\n")

    @staticmethod
    def _write_private_file(path: Path, payload: str) -> None:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            encoded = payload.encode()
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    raise OSError("private Git file write did not advance")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _candidate_history_paths(
        self,
        ownership: WorkspaceOwnership,
    ) -> tuple[str, ...]:
        output = self._run_git(
            Path(ownership.workspace_path),
            "log",
            "--format=",
            "--name-only",
            "-m",
            "--no-renames",
            "-z",
            f"{ownership.base_sha}..HEAD",
            "--",
            failure_code="GIT_STATUS_UNAVAILABLE",
        )
        return tuple(sorted({path for path in output.split("\0") if path}))

    @staticmethod
    def _assert_paths_allowed(
        changed_paths: tuple[str, ...],
        configuration: RepositoryConfiguration,
    ) -> None:
        prohibited = tuple(
            PurePosixPath(path.casefold())
            for path in configuration.prohibited_paths
        )
        for raw_path in changed_paths:
            path = PurePosixPath(raw_path)
            folded_path = PurePosixPath(raw_path.casefold())
            if (
                not raw_path
                or path.is_absolute()
                or ".." in path.parts
                or "\\" in raw_path
                or len(raw_path) > 4096
                or any(ord(character) < 32 for character in raw_path)
                or any(
                    denied == folded_path or denied in folded_path.parents
                    for denied in prohibited
                )
            ):
                raise WorkspaceLifecycleError("PROHIBITED_PATH_CHANGED")

    def _push_remote_url(
        self,
        ownership: WorkspaceOwnership,
        configuration: RepositoryConfiguration,
    ) -> str:
        remote_url = self._run_git(
            Path(ownership.workspace_path),
            "remote",
            "get-url",
            "--push",
            "--",
            configuration.git.remote_name,
            failure_code="GIT_REMOTE_UNAVAILABLE",
        )
        parsed = urlsplit(remote_url)
        expected_path = f"/{configuration.repository_key}"
        try:
            port = parsed.port
        except ValueError:
            raise WorkspaceLifecycleError("GIT_REMOTE_BINDING_MISMATCH") from None
        if (
            parsed.scheme != "https"
            or parsed.hostname != "github.com"
            or parsed.username is not None
            or parsed.password is not None
            or port not in {None, 443}
            or parsed.path.removesuffix(".git") != expected_path
            or parsed.query
            or parsed.fragment
        ):
            raise WorkspaceLifecycleError("GIT_REMOTE_BINDING_MISMATCH")
        return remote_url

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
        untracked = self._run_git(
            workspace_path,
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            failure_code="WORKSPACE_UNAVAILABLE",
        )
        index_clean = self._quiet_git_clean(
            workspace_path,
            "diff",
            "--cached",
            "--quiet",
        )
        worktree_clean = self._quiet_git_clean(
            workspace_path,
            "diff",
            "--quiet",
        ) and not untracked
        return {
            "task_id": ownership.task_id,
            "repository_key": ownership.repository_key,
            "workspace_path": ownership.workspace_path,
            "branch_name": ownership.branch_name,
            "base_sha": ownership.base_sha,
            "head_sha": head_sha,
            "tree_sha": tree_sha,
            "index_clean": index_clean,
            "worktree_clean": worktree_clean,
            "clean": index_clean and worktree_clean,
        }

    def _quiet_git_clean(
        self,
        repository_root: Path,
        *arguments: str,
    ) -> bool:
        result = self._run_git_result(repository_root, *arguments)
        if result.returncode not in {0, 1}:
            raise WorkspaceLifecycleError("GIT_STATUS_UNAVAILABLE")
        return result.returncode == 0

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
        extra_environment: Mapping[str, str] | None = None,
    ) -> str:
        result = self._run_git_result(
            repository_root,
            *arguments,
            extra_environment=extra_environment,
        )
        if result.returncode != 0:
            raise WorkspaceLifecycleError(failure_code)
        return result.stdout

    @staticmethod
    def _run_git_result(
        repository_root: Path,
        *arguments: str,
        extra_environment: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        }
        if extra_environment is not None:
            if set(environment) & set(extra_environment):
                raise WorkspaceLifecycleError("GIT_ENVIRONMENT_OVERRIDE")
            environment.update(extra_environment)
        try:
            result = subprocess.run(
                (
                    "git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "core.fsmonitor=false",
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
