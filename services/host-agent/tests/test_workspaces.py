import os
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest
from mathews_configuration import (
    RepositoryConfiguration,
    SecretReference,
    SecretValue,
    TaskLeaseHostAuthority,
)
from mathews_host_agent.git_transport import GitPushObservation, GitPushTransport
from mathews_host_agent.workspaces import (
    GitWorkspaceLifecycle,
    WorkspaceLifecycleError,
)


@dataclass(frozen=True)
class _Repository:
    root: str


@dataclass(frozen=True)
class _Identity:
    name: str
    email: str


@dataclass(frozen=True)
class _Git:
    default_base_ref: str = "main"
    task_branch_template: str = "mathews/{task_id}"
    remote_name: str = "origin"
    push_credential: SecretReference = field(
        default_factory=lambda: SecretReference(
            provider="keychain",
            service="mathews",
            account="git-push",
        )
    )
    author: _Identity = field(
        default_factory=lambda: _Identity(
            "Configured Author",
            "author@example.invalid",
        )
    )
    committer: _Identity = field(
        default_factory=lambda: _Identity(
            "Configured Committer",
            "committer@example.invalid",
        )
    )


@dataclass(frozen=True)
class _Configuration:
    repository_key: str
    repository: _Repository
    git: _Git = field(default_factory=_Git)
    prohibited_paths: tuple[str, ...] = (".git", ".env")


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(root), *arguments),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _repository(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "-b", "main")
    (root / "README.md").write_text("base\n")
    _git(root, "add", "README.md")
    _git(
        root,
        "-c",
        "user.name=Mathews Test",
        "-c",
        "user.email=mathews@example.invalid",
        "commit",
        "-m",
        "base",
    )
    _git(
        root,
        "remote",
        "add",
        "origin",
        "https://github.com/boppuh/mathews.git",
    )
    return root.resolve(), _git(root, "rev-parse", "HEAD")


def _configuration(root: Path) -> RepositoryConfiguration:
    return cast(
        RepositoryConfiguration,
        _Configuration(
            repository_key="boppuh/mathews",
            repository=_Repository(root=str(root)),
        ),
    )


def _authority(
    *,
    task_id: UUID | None = None,
    job_id: UUID | None = None,
) -> TaskLeaseHostAuthority:
    return TaskLeaseHostAuthority(
        task_id=task_id or uuid4(),
        job_id=job_id or uuid4(),
        lease_id=uuid4(),
        worker_id="worker-1",
        attempt=1,
        fencing_token=1,
        lease_expires_at_ms=1_900_000_000_000,
        repository_key="boppuh/mathews",
        configuration_id=UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
        configuration_digest="sha256:" + "1" * 64,
    )


def test_create_freezes_base_and_returns_exact_clean_repository_state(
    tmp_path: Path,
) -> None:
    repository, original_base = _repository(tmp_path)
    registry = tmp_path / "host-runtime" / "workspaces"
    lifecycle = GitWorkspaceLifecycle(registry.resolve())
    authority = _authority()
    configuration = _configuration(repository)

    created = lifecycle.create(authority, configuration)

    assert created["base_sha"] == original_base
    assert created["head_sha"] == original_base
    assert created["clean"] is True
    assert created["branch_name"] == f"mathews/{authority.task_id}"
    workspace = Path(cast(str, created["workspace_path"]))
    assert workspace.is_dir()
    assert _git(workspace, "rev-parse", "--show-toplevel") == str(workspace)
    assert oct(os.stat(registry).st_mode & 0o777) == "0o700"

    (repository / "README.md").write_text("new main\n")
    _git(repository, "add", "README.md")
    _git(
        repository,
        "-c",
        "user.name=Mathews Test",
        "-c",
        "user.email=mathews@example.invalid",
        "commit",
        "-m",
        "advance main",
    )

    inspected = lifecycle.inspect(authority, configuration)
    replayed = lifecycle.create(authority, configuration)
    assert inspected["base_sha"] == original_base
    assert inspected["head_sha"] == original_base
    assert replayed == inspected


def test_distinct_tasks_receive_unique_branches_and_workspaces(tmp_path: Path) -> None:
    repository, _base = _repository(tmp_path)
    lifecycle = GitWorkspaceLifecycle((tmp_path / "registry").resolve())
    configuration = _configuration(repository)

    first = lifecycle.create(_authority(), configuration)
    second = lifecycle.create(_authority(), configuration)

    assert first["branch_name"] != second["branch_name"]
    assert first["workspace_path"] != second["workspace_path"]


def test_inspect_is_read_only_when_no_workspace_registry_exists(
    tmp_path: Path,
) -> None:
    repository, _base = _repository(tmp_path)
    registry = (tmp_path / "missing-registry").resolve()
    lifecycle = GitWorkspaceLifecycle(registry)

    with pytest.raises(WorkspaceLifecycleError, match="WORKSPACE_NOT_FOUND"):
        lifecycle.inspect(_authority(), _configuration(repository))

    assert not registry.exists()


def test_cleanup_is_explicit_idempotent_and_cancellation_aware(
    tmp_path: Path,
) -> None:
    repository, _base = _repository(tmp_path)
    lifecycle = GitWorkspaceLifecycle((tmp_path / "registry").resolve())
    authority = _authority()
    created = lifecycle.create(authority, _configuration(repository))
    cancellation_id = uuid4()

    cleaned = lifecycle.cleanup(
        authority,
        _configuration(repository),
        reason="CANCELLED",
        cancellation_id=cancellation_id,
    )
    replayed = lifecycle.cleanup(
        authority,
        _configuration(repository),
        reason="CANCELLED",
        cancellation_id=cancellation_id,
    )

    assert cleaned == {
        "task_id": str(authority.task_id),
        "state": "CLEANED",
        "reason": "CANCELLED",
        "cancellation_id": str(cancellation_id),
    }
    assert replayed == cleaned
    assert not Path(cast(str, created["workspace_path"])).exists()
    assert (
        subprocess.run(
            (
                "git",
                "-C",
                str(repository),
                "show-ref",
                "--verify",
                "--quiet",
                f"refs/heads/{created['branch_name']}",
            ),
            check=False,
        ).returncode
        == 1
    )


def test_cleanup_never_touches_a_workspace_without_an_ownership_record(
    tmp_path: Path,
) -> None:
    repository, _base = _repository(tmp_path)
    configuration = _configuration(repository)
    registry = (tmp_path / "registry").resolve()
    authority = _authority()
    lifecycle = GitWorkspaceLifecycle(registry)
    assert (
        lifecycle.cleanup(
            authority,
            configuration,
            reason="COMPLETED",
            cancellation_id=None,
        )["state"]
        == "ABSENT"
    )
    foreign_workspace = registry / "tasks" / str(authority.task_id)
    foreign_workspace.mkdir()
    sentinel = foreign_workspace / "keep.txt"
    sentinel.write_text("unowned\n")

    result = lifecycle.cleanup(
        authority,
        configuration,
        reason="COMPLETED",
        cancellation_id=None,
    )

    assert result["state"] == "ABSENT"
    assert sentinel.read_text() == "unowned\n"


def test_workspace_is_task_owned_across_jobs_but_rejects_changed_configuration(
    tmp_path: Path,
) -> None:
    repository, _base = _repository(tmp_path)
    lifecycle = GitWorkspaceLifecycle((tmp_path / "registry").resolve())
    authority = _authority()
    configuration = _configuration(repository)
    lifecycle.create(authority, configuration)
    changed_job = replace(authority, job_id=uuid4(), lease_id=uuid4())
    assert lifecycle.inspect(changed_job, configuration)["task_id"] == str(
        authority.task_id
    )
    changed_configuration = replace(
        authority,
        configuration_digest="sha256:" + "2" * 64,
    )

    with pytest.raises(WorkspaceLifecycleError, match="WORKSPACE_NOT_OWNED"):
        lifecycle.inspect(changed_configuration, configuration)
    with pytest.raises(WorkspaceLifecycleError, match="WORKSPACE_NOT_OWNED"):
        lifecycle.cleanup(
            changed_configuration,
            configuration,
            reason="COMPLETED",
            cancellation_id=None,
        )


def test_preexisting_task_branch_is_not_adopted_without_ownership(
    tmp_path: Path,
) -> None:
    repository, base = _repository(tmp_path)
    authority = _authority()
    branch_name = f"mathews/{authority.task_id}"
    _git(repository, "branch", branch_name, base)
    lifecycle = GitWorkspaceLifecycle((tmp_path / "registry").resolve())

    with pytest.raises(WorkspaceLifecycleError, match="BRANCH_NOT_OWNED"):
        lifecycle.create(authority, _configuration(repository))


def test_cleanup_recovers_an_owned_but_unregistered_partial_directory(
    tmp_path: Path,
) -> None:
    repository, _base = _repository(tmp_path)
    lifecycle = GitWorkspaceLifecycle((tmp_path / "registry").resolve())
    authority = _authority()
    created = lifecycle.create(authority, _configuration(repository))
    workspace = Path(cast(str, created["workspace_path"]))
    _git(repository, "worktree", "remove", "--force", str(workspace))
    workspace.mkdir()
    sentinel = workspace / "partial"
    sentinel.write_text("incomplete\n")

    result = lifecycle.cleanup(
        authority,
        _configuration(repository),
        reason="COMPLETED",
        cancellation_id=None,
    )

    assert result["state"] == "CLEANED"
    assert not workspace.exists()


class _PushTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []
        self.remote_sha: str | None = None

    def push(
        self,
        *,
        workspace_path: Path,
        remote_url: str,
        branch_name: str,
        expected_sha: str,
        credential: SecretValue,
    ) -> GitPushObservation:
        assert credential.reveal() == "transport-secret"
        self.calls.append((str(workspace_path), remote_url, branch_name))
        before = self.remote_sha
        self.remote_sha = expected_sha
        return GitPushObservation(
            before_sha=before,
            after_sha=expected_sha,
            pushed=before != expected_sha,
        )


def test_candidate_commit_uses_configured_identity_and_returns_exact_clean_state(
    tmp_path: Path,
) -> None:
    repository, base = _repository(tmp_path)
    lifecycle = GitWorkspaceLifecycle((tmp_path / "registry").resolve())
    authority = _authority()
    configuration = _configuration(repository)
    created = lifecycle.create(authority, configuration)
    workspace = Path(cast(str, created["workspace_path"]))
    (workspace / "feature.txt").write_text("candidate\n")

    committed = lifecycle.commit_candidate(
        authority,
        configuration,
        expected_head_sha=base,
        message="Add candidate feature",
    )

    assert committed["committed"] is True
    assert committed["head_sha"] != base
    assert committed["parent_shas"] == [base]
    assert committed["changed_paths"] == ["feature.txt"]
    assert committed["author_name"] == "Configured Author"
    assert committed["author_email"] == "author@example.invalid"
    assert committed["committer_name"] == "Configured Committer"
    assert committed["committer_email"] == "committer@example.invalid"
    assert committed["index_clean"] is True
    assert committed["worktree_clean"] is True
    assert committed["clean"] is True
    assert lifecycle.inspect_git(authority, configuration) == {
        key: value for key, value in committed.items() if key not in {"committed", "changed_paths"}
    }


def test_candidate_commit_rejects_head_drift_and_prohibited_paths(
    tmp_path: Path,
) -> None:
    repository, base = _repository(tmp_path)
    lifecycle = GitWorkspaceLifecycle((tmp_path / "registry").resolve())
    authority = _authority()
    configuration = _configuration(repository)
    created = lifecycle.create(authority, configuration)
    workspace = Path(cast(str, created["workspace_path"]))
    (workspace / "feature.txt").write_text("candidate\n")

    with pytest.raises(WorkspaceLifecycleError, match="HEAD_MISMATCH"):
        lifecycle.commit_candidate(
            authority,
            configuration,
            expected_head_sha="f" * 40,
            message="Wrong boundary",
        )
    (workspace / ".env").write_text("SECRET=value\n")
    with pytest.raises(WorkspaceLifecycleError, match="PROHIBITED_PATH_CHANGED"):
        lifecycle.commit_candidate(
            authority,
            configuration,
            expected_head_sha=base,
            message="Unsafe candidate",
        )
    (workspace / ".env").unlink()
    (workspace / ".ENV").write_text("SECRET=value\n")
    with pytest.raises(WorkspaceLifecycleError, match="PROHIBITED_PATH_CHANGED"):
        lifecycle.commit_candidate(
            authority,
            configuration,
            expected_head_sha=base,
            message="Case-variant unsafe candidate",
        )
    assert _git(workspace, "rev-parse", "HEAD") == base


def test_candidate_commit_rejects_unconfigured_head_identity(
    tmp_path: Path,
) -> None:
    repository, _base = _repository(tmp_path)
    lifecycle = GitWorkspaceLifecycle((tmp_path / "registry").resolve())
    authority = _authority()
    configuration = _configuration(repository)
    created = lifecycle.create(authority, configuration)
    workspace = Path(cast(str, created["workspace_path"]))
    (workspace / "foreign.txt").write_text("foreign\n")
    _git(workspace, "add", "foreign.txt")
    _git(
        workspace,
        "-c",
        "user.name=Foreign Author",
        "-c",
        "user.email=foreign@example.invalid",
        "commit",
        "-m",
        "foreign candidate",
    )
    foreign_head = _git(workspace, "rev-parse", "HEAD")
    (workspace / "feature.txt").write_text("candidate\n")

    with pytest.raises(WorkspaceLifecycleError, match="COMMIT_IDENTITY_MISMATCH"):
        lifecycle.commit_candidate(
            authority,
            configuration,
            expected_head_sha=foreign_head,
            message="Add candidate feature",
        )


def test_candidate_commit_revalidates_paths_after_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, base = _repository(tmp_path)
    lifecycle = GitWorkspaceLifecycle((tmp_path / "registry").resolve())
    authority = _authority()
    configuration = _configuration(repository)
    created = lifecycle.create(authority, configuration)
    workspace = Path(cast(str, created["workspace_path"]))
    (workspace / "feature.txt").write_text("candidate\n")
    original_run_git = lifecycle._run_git

    def inject_prohibited_path(
        repository_root: Path,
        *arguments: str,
        failure_code: str,
        extra_environment: Mapping[str, str] | None = None,
    ) -> str:
        if arguments[:2] == ("add", "--all"):
            (workspace / ".ENV").write_text("SECRET=value\n")
        return original_run_git(
            repository_root,
            *arguments,
            failure_code=failure_code,
            extra_environment=extra_environment,
        )

    monkeypatch.setattr(lifecycle, "_run_git", inject_prohibited_path)

    with pytest.raises(WorkspaceLifecycleError, match="PROHIBITED_PATH_CHANGED"):
        lifecycle.commit_candidate(
            authority,
            configuration,
            expected_head_sha=base,
            message="Unsafe staged candidate",
        )

    assert _git(workspace, "rev-parse", "HEAD") == base


def test_git_runner_rejects_restricted_environment_overrides(
    tmp_path: Path,
) -> None:
    repository, _base = _repository(tmp_path)

    with pytest.raises(WorkspaceLifecycleError, match="GIT_ENVIRONMENT_OVERRIDE"):
        GitWorkspaceLifecycle._run_git_result(
            repository,
            "status",
            extra_environment={"GIT_TERMINAL_PROMPT": "1"},
        )


def test_candidate_push_is_exact_non_force_idempotent_and_credential_free(
    tmp_path: Path,
) -> None:
    repository, base = _repository(tmp_path)
    lifecycle = GitWorkspaceLifecycle((tmp_path / "registry").resolve())
    authority = _authority()
    configuration = _configuration(repository)
    created = lifecycle.create(authority, configuration)
    workspace = Path(cast(str, created["workspace_path"]))
    (workspace / "feature.txt").write_text("candidate\n")
    committed = lifecycle.commit_candidate(
        authority,
        configuration,
        expected_head_sha=base,
        message="Add candidate feature",
    )
    candidate_sha = cast(str, committed["head_sha"])
    transport = _PushTransport()

    first = lifecycle.push_candidate(
        authority,
        configuration,
        expected_head_sha=candidate_sha,
        credential=SecretValue("transport-secret"),
        transport=cast(GitPushTransport, transport),
    )
    second = lifecycle.push_candidate(
        authority,
        configuration,
        expected_head_sha=candidate_sha,
        credential=SecretValue("transport-secret"),
        transport=cast(GitPushTransport, transport),
    )

    assert first["remote_head_before"] is None
    assert first["remote_head_after"] == candidate_sha
    assert first["pushed"] is True
    assert second["remote_head_before"] == candidate_sha
    assert second["pushed"] is False
    assert len(transport.calls) == 2
    assert "transport-secret" not in repr(first)
    assert configuration.git.push_credential is not None
    assert configuration.git.push_credential.uri not in repr(first)


def test_candidate_push_rejects_the_frozen_base(
    tmp_path: Path,
) -> None:
    repository, base = _repository(tmp_path)
    lifecycle = GitWorkspaceLifecycle((tmp_path / "registry").resolve())
    authority = _authority()
    configuration = _configuration(repository)
    lifecycle.create(authority, configuration)
    transport = _PushTransport()

    with pytest.raises(
        WorkspaceLifecycleError,
        match="CANDIDATE_COMMIT_REQUIRED",
    ):
        lifecycle.push_candidate(
            authority,
            configuration,
            expected_head_sha=base,
            credential=SecretValue("transport-secret"),
            transport=cast(GitPushTransport, transport),
        )

    assert transport.calls == []


def test_candidate_push_rejects_dirty_state_and_remote_rebinding(
    tmp_path: Path,
) -> None:
    repository, base = _repository(tmp_path)
    lifecycle = GitWorkspaceLifecycle((tmp_path / "registry").resolve())
    authority = _authority()
    configuration = _configuration(repository)
    created = lifecycle.create(authority, configuration)
    workspace = Path(cast(str, created["workspace_path"]))
    transport = _PushTransport()
    (workspace / "feature.txt").write_text("candidate\n")
    committed = lifecycle.commit_candidate(
        authority,
        configuration,
        expected_head_sha=base,
        message="Add candidate feature",
    )
    candidate_sha = cast(str, committed["head_sha"])
    (workspace / "dirty.txt").write_text("dirty\n")

    with pytest.raises(WorkspaceLifecycleError, match="WORKSPACE_NOT_CLEAN"):
        lifecycle.push_candidate(
            authority,
            configuration,
            expected_head_sha=candidate_sha,
            credential=SecretValue("transport-secret"),
            transport=cast(GitPushTransport, transport),
        )
    (workspace / "dirty.txt").unlink()
    _git(
        workspace,
        "remote",
        "set-url",
        "--push",
        "origin",
        "https://github.com/boppuh/unrelated.git",
    )
    with pytest.raises(WorkspaceLifecycleError, match="GIT_REMOTE_BINDING_MISMATCH"):
        lifecycle.push_candidate(
            authority,
            configuration,
            expected_head_sha=candidate_sha,
            credential=SecretValue("transport-secret"),
            transport=cast(GitPushTransport, transport),
        )
    assert transport.calls == []


def test_git_boundary_rejects_a_task_branch_detached_from_frozen_base(
    tmp_path: Path,
) -> None:
    repository, _base = _repository(tmp_path)
    lifecycle = GitWorkspaceLifecycle((tmp_path / "registry").resolve())
    authority = _authority()
    configuration = _configuration(repository)
    created = lifecycle.create(authority, configuration)
    workspace = Path(cast(str, created["workspace_path"]))
    empty_tree = _git(workspace, "hash-object", "-t", "tree", "/dev/null")
    unrelated = _git(
        workspace,
        "-c",
        "user.name=Unrelated",
        "-c",
        "user.email=unrelated@example.invalid",
        "commit-tree",
        empty_tree,
        "-m",
        "unrelated root",
    )
    _git(workspace, "reset", "--hard", unrelated)

    with pytest.raises(WorkspaceLifecycleError, match="BASE_NOT_ANCESTOR"):
        lifecycle.inspect_git(authority, configuration)
