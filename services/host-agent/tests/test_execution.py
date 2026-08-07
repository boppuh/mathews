import hashlib
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import pytest
from mathews_configuration import RepositoryConfiguration, TaskLeaseHostAuthority
from mathews_host_agent.execution import (
    ConfiguredExecutionError,
    ConfiguredOperationRunner,
    HostArtifactStore,
)
from mathews_host_agent.workspaces import GitWorkspaceLifecycle, WorkspaceLifecycleError


class _Kind(StrEnum):
    BUILD = "BUILD"


@dataclass(frozen=True)
class _Operation:
    operation_id: str
    kind: _Kind
    argv: tuple[str, ...]
    timeout_seconds: int


@dataclass(frozen=True)
class _Artifacts:
    collection_paths: tuple[str, ...]


@dataclass(frozen=True)
class _Configuration:
    operations: tuple[_Operation, ...]
    artifacts: _Artifacts
    configuration_id: UUID = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
    version: int = 7
    digest: str = "sha256:" + "c" * 64


class _Workspaces:
    def __init__(self, workspace: Path, *, head: str = "a" * 40) -> None:
        self.workspace = workspace
        self.head = head
        self.tree = "b" * 40
        self.calls = 0

    def execution_context(
        self,
        _authority: TaskLeaseHostAuthority,
        _configuration: RepositoryConfiguration,
        *,
        expected_head_sha: str,
    ) -> dict[str, object]:
        self.calls += 1
        if expected_head_sha != self.head:
            raise WorkspaceLifecycleError("HEAD_MISMATCH")
        return {
            "workspace_path": str(self.workspace),
            "head_sha": self.head,
            "tree_sha": self.tree,
            "clean": True,
        }


def _authority() -> TaskLeaseHostAuthority:
    return TaskLeaseHostAuthority(
        task_id=uuid4(),
        job_id=uuid4(),
        lease_id=uuid4(),
        worker_id="worker-1",
        attempt=1,
        fencing_token=9,
        lease_expires_at_ms=1_900_000_000_000,
        repository_key="boppuh/mathews",
        configuration_id=UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
        configuration_digest="sha256:" + "c" * 64,
    )


def _artifact_bytes(root: Path, address: object) -> bytes:
    assert isinstance(address, str)
    return (root / address.removeprefix("sha256:")).read_bytes()


def test_configured_operation_returns_exact_evidence_and_immutable_artifacts(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact_directory = workspace / "artifacts"
    program = (
        "from pathlib import Path; "
        "Path('artifacts').mkdir(); "
        "Path('artifacts/result.txt').write_text('result'); "
        "print('build output')"
    )
    configuration = cast(
        RepositoryConfiguration,
        _Configuration(
            operations=(
                _Operation(
                    "build",
                    _Kind.BUILD,
                    (sys.executable, "-c", program),
                    5,
                ),
            ),
            artifacts=_Artifacts(("artifacts",)),
        ),
    )
    workspaces = _Workspaces(workspace)
    store_root = (tmp_path / "store").resolve()
    mutation_starts: list[str] = []

    result = ConfiguredOperationRunner(
        cast(GitWorkspaceLifecycle, workspaces),
        HostArtifactStore(store_root),
    ).run(
        _authority(),
        configuration,
        operation_id="build",
        expected_head_sha="a" * 40,
        validation_contract_version=3,
        effect_started=lambda: mutation_starts.append("started"),
    )

    references = cast(list[dict[str, object]], result["artifacts"])
    assert result["exit_status"] == 0
    assert result["passed"] is True
    assert result["cancellation_status"] == "NOT_REQUESTED"
    assert result["head_sha"] == "a" * 40
    assert result["tree_sha"] == "b" * 40
    assert result["configuration_version"] == 7
    assert result["validation_contract_version"] == 3
    assert result["fencing_token"] == 9
    assert mutation_starts == ["started"]
    assert workspaces.calls == 2
    assert artifact_directory.joinpath("result.txt").read_text() == "result"
    assert {reference["role"] for reference in references} == {
        "STDOUT",
        "STDERR",
        "CONFIGURED",
    }
    stdout = next(reference for reference in references if reference["role"] == "STDOUT")
    configured = next(
        reference for reference in references if reference["role"] == "CONFIGURED"
    )
    assert _artifact_bytes(store_root, stdout["address"]) == b"build output\n"
    assert _artifact_bytes(store_root, configured["address"]) == b"result"
    assert configured["source_path"] == "artifacts/result.txt"


def test_timed_out_operation_retains_partial_output_and_never_passes(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    program = "import time; print('partial', flush=True); time.sleep(10)"
    configuration = cast(
        RepositoryConfiguration,
        _Configuration(
            operations=(
                _Operation(
                    "unit-tests",
                    _Kind.BUILD,
                    (sys.executable, "-c", program),
                    1,
                ),
            ),
            artifacts=_Artifacts(("missing-artifacts",)),
        ),
    )
    store_root = (tmp_path / "store").resolve()

    result = ConfiguredOperationRunner(
        cast(GitWorkspaceLifecycle, _Workspaces(workspace)),
        HostArtifactStore(store_root),
    ).run(
        _authority(),
        configuration,
        operation_id="unit-tests",
        expected_head_sha="a" * 40,
        validation_contract_version=1,
    )

    references = cast(list[dict[str, object]], result["artifacts"])
    stdout = next(reference for reference in references if reference["role"] == "STDOUT")
    assert result["passed"] is False
    assert result["cancellation_status"] == "TIMED_OUT"
    assert isinstance(result["exit_status"], int)
    assert _artifact_bytes(store_root, stdout["address"]) == b"partial\n"


def test_artifact_store_reuses_verified_content_and_rejects_corruption(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"immutable")
    store_root = (tmp_path / "store").resolve()
    store = HostArtifactStore(store_root)

    first = store.put_file(source, role="STDOUT", source_path=None)
    second = store.put_file(source, role="STDOUT", source_path=None)

    assert first == second
    destination = store_root / hashlib.sha256(b"immutable").hexdigest()
    destination.write_bytes(b"corrupt")
    with pytest.raises(ConfiguredExecutionError, match="ARTIFACT_CORRUPT"):
        store.put_file(source, role="STDOUT", source_path=None)


def test_execution_rejects_unknown_operation_before_starting_effect(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    configuration = cast(
        RepositoryConfiguration,
        _Configuration(operations=(), artifacts=_Artifacts(("artifacts",))),
    )
    starts: list[str] = []

    with pytest.raises(
        ConfiguredExecutionError,
        match="CONFIGURED_OPERATION_UNAVAILABLE",
    ):
        ConfiguredOperationRunner(
            cast(GitWorkspaceLifecycle, _Workspaces(workspace)),
            HostArtifactStore((tmp_path / "store").resolve()),
        ).run(
            _authority(),
            configuration,
            operation_id="missing",
            expected_head_sha="a" * 40,
            validation_contract_version=1,
            effect_started=lambda: starts.append("started"),
        )

    assert starts == []
