import os
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest
from mathews_configuration import RepositoryConfiguration, TaskLeaseHostAuthority
from mathews_host_agent.workspaces import (
    GitWorkspaceLifecycle,
    WorkspaceLifecycleError,
)


@dataclass(frozen=True)
class _Repository:
    root: str


@dataclass(frozen=True)
class _Git:
    default_base_ref: str = "main"
    task_branch_template: str = "mathews/{task_id}"


@dataclass(frozen=True)
class _Configuration:
    repository_key: str
    repository: _Repository
    git: _Git = _Git()


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
