import hashlib
import json
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from uuid import UUID, uuid4

import pytest
from mathews_configuration import (
    E2EFlow,
    RepositoryConfiguration,
    SecretValue,
    TaskLeaseHostAuthority,
)
from mathews_host_agent.execution import (
    ConfiguredExecutionError,
    ConfiguredOperationRunner,
    HostArtifactStore,
)
from mathews_host_agent.workspaces import GitWorkspaceLifecycle, WorkspaceLifecycleError


class _Kind(StrEnum):
    BUILD = "BUILD"


_CONFIGURATION_ID = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")


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
    configuration_id: UUID = _CONFIGURATION_ID
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
        configuration_id=_CONFIGURATION_ID,
        configuration_digest="sha256:" + "c" * 64,
    )


def _artifact_bytes(
    root: Path,
    task_id: UUID,
    address: object,
) -> bytes:
    assert isinstance(address, str)
    return (root / str(task_id) / address.removeprefix("sha256:")).read_bytes()


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
    yielded: list[str] = []

    authority = _authority()
    result = ConfiguredOperationRunner(
        cast(GitWorkspaceLifecycle, workspaces),
        HostArtifactStore(store_root),
    ).run(
        authority,
        configuration,
        operation_id="build",
        expected_head_sha="a" * 40,
        validation_contract_version=3,
        effect_started=lambda: mutation_starts.append("started"),
        effect_yielded=lambda: yielded.append("yielded"),
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
    assert yielded == ["yielded"]
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
    assert _artifact_bytes(store_root, authority.task_id, stdout["address"]) == b"build output\n"
    assert _artifact_bytes(store_root, authority.task_id, configured["address"]) == b"result"
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

    authority = _authority()
    result = ConfiguredOperationRunner(
        cast(GitWorkspaceLifecycle, _Workspaces(workspace)),
        HostArtifactStore(store_root),
    ).run(
        authority,
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
    assert _artifact_bytes(store_root, authority.task_id, stdout["address"]) == b"partial\n"


def test_artifact_store_reuses_verified_content_and_rejects_corruption(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"immutable")
    store_root = (tmp_path / "store").resolve()
    store = HostArtifactStore(store_root)
    task_id = uuid4()

    first = store.put_file(source, task_id=task_id, role="STDOUT", source_path=None)
    second = store.put_file(source, task_id=task_id, role="STDOUT", source_path=None)

    assert first == second
    destination = store_root / str(task_id) / hashlib.sha256(b"immutable").hexdigest()
    destination.write_bytes(b"corrupt")
    with pytest.raises(ConfiguredExecutionError, match="ARTIFACT_CORRUPT"):
        store.put_file(source, task_id=task_id, role="STDOUT", source_path=None)


def test_authorization_error_terminates_work_retains_output_and_is_not_relabelled(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    configuration = cast(
        RepositoryConfiguration,
        _Configuration(
            operations=(
                _Operation(
                    "build",
                    _Kind.BUILD,
                    (
                        sys.executable,
                        "-c",
                        "import time; print('partial', flush=True); time.sleep(10)",
                    ),
                    5,
                ),
            ),
            artifacts=_Artifacts(("artifacts",)),
        ),
    )
    store_root = (tmp_path / "store").resolve()

    authority = _authority()
    result = ConfiguredOperationRunner(
            cast(GitWorkspaceLifecycle, _Workspaces(workspace)),
            HostArtifactStore(store_root),
        ).run(
            authority,
            configuration,
            operation_id="build",
            expected_head_sha="a" * 40,
            validation_contract_version=1,
            assert_authorized=lambda: (_ for _ in ()).throw(
                RuntimeError("journal unavailable")
            ),
        )

    partial_address = hashlib.sha256(b"partial\n").hexdigest()
    assert result["passed"] is False
    assert result["cancellation_status"] == "AUTHORIZATION_LOST"
    assert (store_root / str(authority.task_id) / partial_address).read_bytes() == b"partial\n"


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


def test_configured_simulator_is_resolved_to_available_device(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {
        "runtimes": [
            {
                "identifier": "com.apple.CoreSimulator.SimRuntime.iOS-18-0",
                "name": "iOS 18.0",
                "isAvailable": True,
            }
        ],
        "devices": {
            "com.apple.CoreSimulator.SimRuntime.iOS-18-0": [
                {
                    "udid": "BBBBBBBB-BBBB-4BBB-8BBB-BBBBBBBBBBBB",
                    "deviceTypeIdentifier": "com.apple.CoreSimulator.SimDeviceType.iPhone-16",
                    "isAvailable": True,
                },
                {
                    "udid": "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
                    "deviceTypeIdentifier": "com.apple.CoreSimulator.SimDeviceType.iPhone-16",
                    "isAvailable": True,
                },
            ]
        },
    }
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        ),
    )
    configuration = SimpleNamespace(
        xcode=SimpleNamespace(
            simulator=SimpleNamespace(
                runtime_identifier="com.apple.CoreSimulator.SimRuntime.iOS-18-0",
                device_type_identifier="com.apple.CoreSimulator.SimDeviceType.iPhone-16",
            )
        )
    )

    argv, simulator_id = ConfiguredOperationRunner._resolved_argv(
        tmp_path,
        ("xcodebuild", "test", "MATHEWS_CONFIGURED_SIMULATOR"),
        cast(RepositoryConfiguration, configuration),
    )

    assert simulator_id == "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
    assert argv == (
        "xcodebuild",
        "test",
        "id=AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
    )


def test_e2e_execution_prepares_simulator_and_exposes_only_secret_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    fixture = workspace / "fixture.json"
    recipe = workspace / "recipe.json"
    fixture.write_text("{}")
    recipe.write_text("{}")
    flow = cast(
        E2EFlow,
        SimpleNamespace(
            fixture_file=SimpleNamespace(path="fixture.json"),
            test_account_recipe_file=SimpleNamespace(path="recipe.json"),
            locale_identifier="en_US_POSIX",
            time_zone_identifier="UTC",
        ),
    )
    runner = ConfiguredOperationRunner(
        cast(GitWorkspaceLifecycle, _Workspaces(workspace)),
        HostArtifactStore((tmp_path / "store").resolve()),
    )
    prepared: list[str] = []
    monkeypatch.setattr(
        runner,
        "_prepare_simulator",
        lambda _workspace, simulator_id, **_kwargs: prepared.append(simulator_id),
    )
    output_root = tmp_path / "output"
    output_root.mkdir()
    stdout_path = output_root / "stdout"
    stderr_path = output_root / "stderr"
    program = (
        "import os, pathlib; "
        "secret = pathlib.Path(os.environ['MATHEWS_E2E_ACCOUNT_SECRET_PATH']); "
        "assert secret.read_text() == 'credential'; "
        "assert os.environ['MATHEWS_E2E_FIXTURE_PATH'].endswith('fixture.json'); "
        "assert os.environ['MATHEWS_E2E_ACCOUNT_RECIPE_PATH'].endswith('recipe.json')"
    )

    result = runner._execute(
        workspace,
        (sys.executable, "-c", program),
        5,
        stdout_path,
        stderr_path,
        simulator_id="simulator-1",
        e2e_flow=flow,
        e2e_secret=SecretValue("credential"),
        effect_started=None,
        effect_yielded=None,
        assert_authorized=None,
    )

    assert result == (0, "NOT_REQUESTED", False)
    assert prepared == ["simulator-1"]
    assert not (output_root / "e2e-account-secret").exists()


def test_simulator_preparation_applies_fixed_clean_state_sequence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runner = ConfiguredOperationRunner(
        cast(GitWorkspaceLifecycle, _Workspaces(workspace)),
        HostArtifactStore((tmp_path / "store").resolve()),
    )
    commands: list[tuple[str, ...]] = []
    authorization_checks: list[str] = []
    events: list[str] = []

    class FakeProcess:
        def __init__(
            self,
            command: tuple[str, ...],
            *_args: object,
            **_kwargs: object,
        ) -> None:
            self.pid = 10_000 + len(commands)
            commands.append(command)
            events.append("spawned")

        def wait(self, *, timeout: float) -> int:
            assert timeout > 0
            return 0

    monkeypatch.setattr(subprocess, "Popen", FakeProcess)

    runner._prepare_simulator(
        workspace,
        "simulator-1",
        effect_started=lambda: events.append("started"),
        effect_yielded=lambda: events.append("yielded"),
        assert_authorized=lambda: authorization_checks.append("checked"),
    )

    assert commands == [
        ("xcrun", "simctl", "shutdown", "simulator-1"),
        ("xcrun", "simctl", "erase", "simulator-1"),
        ("xcrun", "simctl", "boot", "simulator-1"),
        ("xcrun", "simctl", "bootstatus", "simulator-1", "-b"),
    ]
    assert authorization_checks == ["checked"] * 4
    assert events[:3] == ["spawned", "started", "yielded"]
    assert events.count("started") == 1
    assert events.count("yielded") == 1


def test_simulator_spawn_failure_precedes_effect_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runner = ConfiguredOperationRunner(
        cast(GitWorkspaceLifecycle, _Workspaces(workspace)),
        HostArtifactStore((tmp_path / "store").resolve()),
    )
    effects: list[str] = []

    def fail_spawn(*_args: object, **_kwargs: object) -> None:
        raise OSError("spawn failed")

    monkeypatch.setattr(subprocess, "Popen", fail_spawn)

    with pytest.raises(
        ConfiguredExecutionError,
        match="SIMULATOR_PREPARATION_FAILED",
    ):
        runner._prepare_simulator(
            workspace,
            "simulator-1",
            effect_started=lambda: effects.append("started"),
            effect_yielded=lambda: effects.append("yielded"),
            assert_authorized=None,
        )

    assert effects == []


def test_e2e_inputs_are_rehashed_and_exact_before_launch(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    harness = workspace / "Harness"
    harness.mkdir(parents=True)
    runner_source = harness / "Runner.swift"
    fixture = workspace / "fixture.json"
    recipe = workspace / "recipe.json"
    runner_source.write_bytes(b"runner")
    fixture.write_bytes(b"fixture")
    recipe.write_bytes(b"recipe")

    def pinned(path: str, payload: bytes) -> SimpleNamespace:
        return SimpleNamespace(
            path=path,
            digest=f"sha256:{hashlib.sha256(payload).hexdigest()}",
        )

    flow = cast(
        E2EFlow,
        SimpleNamespace(
            harness_source_root="Harness",
            harness_files=(pinned("Harness/Runner.swift", b"runner"),),
            fixture_file=pinned("fixture.json", b"fixture"),
            test_account_recipe_file=pinned("recipe.json", b"recipe"),
        ),
    )

    ConfiguredOperationRunner._verify_e2e_inputs(workspace, flow)
    runner_source.write_bytes(b"changed")

    with pytest.raises(ConfiguredExecutionError, match="E2E_INPUT_INVALID"):
        ConfiguredOperationRunner._verify_e2e_inputs(workspace, flow)


def test_artifact_reads_are_bounded_and_task_scoped(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"immutable-evidence")
    store = HostArtifactStore((tmp_path / "store").resolve())
    task_id = uuid4()
    reference = store.put_file(
        source,
        task_id=task_id,
        role="STDOUT",
        source_path=None,
    )

    first = store.read_chunk(
        task_id,
        address=reference.address,
        offset=0,
        length=9,
    )
    second = store.read_chunk(
        task_id,
        address=reference.address,
        offset=9,
        length=256,
    )

    assert first["data_base64"] == "aW1tdXRhYmxl"
    assert first["eof"] is False
    assert second["data_base64"] == "LWV2aWRlbmNl"
    assert second["eof"] is True
    with pytest.raises(ConfiguredExecutionError, match="ARTIFACT_UNAVAILABLE"):
        store.read_chunk(
            uuid4(),
            address=reference.address,
            offset=0,
            length=9,
        )


def test_spontaneous_signal_is_not_reported_as_cancellation(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    configuration = cast(
        RepositoryConfiguration,
        _Configuration(
            operations=(
                _Operation(
                    "crash",
                    _Kind.BUILD,
                    (
                        sys.executable,
                        "-c",
                        "import os, signal; os.kill(os.getpid(), signal.SIGTERM)",
                    ),
                    5,
                ),
            ),
            artifacts=_Artifacts(()),
        ),
    )

    result = ConfiguredOperationRunner(
        cast(GitWorkspaceLifecycle, _Workspaces(workspace)),
        HostArtifactStore((tmp_path / "store").resolve()),
    ).run(
        _authority(),
        configuration,
        operation_id="crash",
        expected_head_sha="a" * 40,
        validation_contract_version=1,
    )

    assert result["exit_status"] == -signal.SIGTERM
    assert result["termination_signal"] == signal.SIGTERM
    assert result["cancellation_status"] == "NOT_REQUESTED"
    assert result["passed"] is False


def test_capacity_rejection_preserves_a_worker_for_renewals_and_shutdown(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    configuration = cast(
        RepositoryConfiguration,
        _Configuration(
            operations=(
                _Operation(
                    "long",
                    _Kind.BUILD,
                    (sys.executable, "-c", "import time; time.sleep(30)"),
                    60,
                ),
            ),
            artifacts=_Artifacts(()),
        ),
    )
    runner = ConfiguredOperationRunner(
        cast(GitWorkspaceLifecycle, _Workspaces(workspace)),
        HostArtifactStore((tmp_path / "store").resolve()),
        maximum_concurrent_operations=1,
    )
    started = threading.Event()

    with ThreadPoolExecutor(max_workers=1) as executor:
        active = executor.submit(
            runner.run,
            _authority(),
            configuration,
            operation_id="long",
            expected_head_sha="a" * 40,
            validation_contract_version=1,
            effect_started=started.set,
        )
        assert started.wait(timeout=2)
        with pytest.raises(
            ConfiguredExecutionError,
            match="VALIDATION_CAPACITY_UNAVAILABLE",
        ):
            runner.run(
                _authority(),
                configuration,
                operation_id="long",
                expected_head_sha="a" * 40,
                validation_contract_version=1,
            )
        runner.request_shutdown()
        result = active.result(timeout=7)

    assert result["cancellation_status"] == "AGENT_SHUTDOWN"
    assert result["passed"] is False


def test_termination_kills_descendants_that_ignore_term(tmp_path: Path) -> None:
    pid_path = tmp_path / "child.pid"
    child_program = (
        "import os, signal, time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"open({str(pid_path)!r}, 'w').write(str(os.getpid())); "
        "time.sleep(30)"
    )
    parent_program = (
        "import signal, subprocess, sys, time; "
        "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0)); "
        f"subprocess.Popen([sys.executable, '-c', {child_program!r}]); "
        "time.sleep(30)"
    )
    process = subprocess.Popen(
        (sys.executable, "-c", parent_program),
        start_new_session=True,
    )
    deadline = time.monotonic() + 2
    while not pid_path.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert pid_path.exists()
    child_pid = int(pid_path.read_text())

    ConfiguredOperationRunner._terminate(process)
    process.wait(timeout=5)
    observed = subprocess.run(
        ("/bin/ps", "-p", str(child_pid), "-o", "stat="),
        check=False,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert not observed or observed.startswith("Z")


def test_termination_helper_reaps_the_group_leader() -> None:
    process = subprocess.Popen(
        (sys.executable, "-c", "import time; time.sleep(30)"),
        start_new_session=True,
    )

    ConfiguredOperationRunner._terminate_and_reap(process)

    assert process.poll() is not None
