import hashlib
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import mathews_host_agent.preflight as preflight_module
import pytest
from mathews_configuration import (
    ArtifactSettings,
    AssertionCatalogEntry,
    AssertionKind,
    E2EFlow,
    GitIdentity,
    GitSettings,
    OperationKind,
    PreflightCheckCode,
    PreflightStatus,
    ProhibitedOperation,
    RepositoryConfiguration,
    RepositorySettings,
    SecretReference,
    SimulatorSettings,
    XcodeContainerKind,
    XcodeSettings,
)
from mathews_configuration import TestOperation as RepositoryOperation
from mathews_host_agent.preflight import (
    CommandProbe,
    CommandRequest,
    CommandResult,
    LocalCommandProbe,
    LocalFilesystemProbe,
    RepositoryPreflightRunner,
    UnsafePreflightCommandError,
)


@pytest.mark.parametrize(
    "timeout_seconds",
    (0.0, -1.0, 10.01, float("inf"), float("-inf"), float("nan")),
)
def test_command_request_rejects_unbounded_timeout(
    tmp_path: Path,
    timeout_seconds: float,
) -> None:
    with pytest.raises(ValueError, match="finite and between 0 and 10"):
        CommandRequest(
            argv=("git", "rev-parse", "--show-toplevel"),
            cwd=tmp_path,
            timeout_seconds=timeout_seconds,
        )


@pytest.mark.parametrize(
    "argv",
    (
        ("git", "fetch", "origin"),
        ("git", "checkout", "main"),
        ("git", "status"),
        ("xcodebuild", "-list"),
        ("xcrun", "simctl", "boot", "device"),
        ("sh", "-c", "git rev-parse --show-toplevel"),
    ),
)
def test_local_command_probe_rejects_mutating_network_and_shell_commands(
    tmp_path: Path,
    argv: tuple[str, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invoked = False

    def fail_if_invoked(*_args: object, **_kwargs: object) -> CommandResult:
        nonlocal invoked
        invoked = True
        raise AssertionError("subprocess must not run")

    monkeypatch.setattr(preflight_module, "_run_bounded_process", fail_if_invoked)

    with pytest.raises(UnsafePreflightCommandError):
        LocalCommandProbe().run(CommandRequest(argv=argv, cwd=tmp_path))

    assert invoked is False


def test_local_command_probe_uses_argv_sanitized_environment_and_no_shell(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def capture_run(
        bounded_request: CommandRequest,
        environment: dict[str, str],
    ) -> CommandResult:
        captured["request"] = bounded_request
        captured["environment"] = environment
        return CommandResult(returncode=0, stdout="/repo\n", stderr="")

    monkeypatch.setattr(preflight_module, "_run_bounded_process", capture_run)
    request = CommandRequest(
        argv=("git", "rev-parse", "--show-toplevel"),
        cwd=tmp_path,
    )

    result = LocalCommandProbe().run(request)

    assert result.returncode == 0
    assert result.stdout == "/repo\n"
    assert captured["request"] == request
    assert captured["environment"] == {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
    }


@pytest.mark.parametrize(
    "program",
    (
        "import os; os.write(1, b'x' * 1_000_001)",
        "import os; os.write(1, b'\\xff')",
    ),
)
def test_bounded_process_rejects_oversized_or_non_utf8_output(
    tmp_path: Path,
    program: str,
) -> None:
    result = preflight_module._run_bounded_process(
        CommandRequest(
            argv=(sys.executable, "-c", program),
            cwd=tmp_path,
            timeout_seconds=5.0,
        ),
        {"PATH": os.defpath},
    )

    assert result == CommandResult(returncode=125, stdout="", stderr="")


class GitAndSimulatorProbe(CommandProbe):
    def __init__(self, simulator_payload: str) -> None:
        self.requests: list[CommandRequest] = []
        self._git = LocalCommandProbe()
        self._simulator_payload = simulator_payload

    def run(self, request: CommandRequest) -> CommandResult:
        self.requests.append(request)
        if request.argv == ("xcrun", "simctl", "list", "-j"):
            return CommandResult(0, self._simulator_payload, "")
        return self._git.run(request)


class RecordingFilesystemProbe(LocalFilesystemProbe):
    def __init__(self) -> None:
        self.resolved: list[tuple[Path, bool]] = []

    def resolve(self, path: Path, *, strict: bool) -> Path:
        self.resolved.append((path, strict))
        return super().resolve(path, strict=strict)


def _run_setup_git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        capture_output=True,
        check=True,
        cwd=root,
        env={
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": str(root),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.defpath,
        },
        text=True,
    )
    return completed.stdout.strip()


def _repository_fixture(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "repository"
    root.mkdir()
    _run_setup_git(root, "init", "--initial-branch=main")
    (root / "README.md").write_text("fixture\n")
    _run_setup_git(root, "add", "README.md")
    _run_setup_git(
        root,
        "-c",
        "user.name=Mathews Test",
        "-c",
        "user.email=mathews@example.invalid",
        "commit",
        "-m",
        "fixture",
    )
    _run_setup_git(
        root,
        "remote",
        "add",
        "origin",
        "https://github.com/boppuh/mathews.git",
    )
    sha = _run_setup_git(root, "rev-parse", "HEAD")
    _run_setup_git(root, "update-ref", "refs/remotes/origin/main", sha)

    scheme_directory = (
        root / "Mathews.xcodeproj" / "xcshareddata" / "xcschemes"
    )
    scheme_directory.mkdir(parents=True)
    (scheme_directory / "Mathews.xcscheme").write_text("<Scheme/>\n")
    return root, sha


def _configuration(root: Path) -> RepositoryConfiguration:
    test_account = SecretReference.parse(
        "keychain://com.boppuh.mathews.test/account"
    )
    e2e_flow = E2EFlow(
        flow_id="primary",
        version=1,
        entry_point="APP_LAUNCH",
        terminal_state="READY",
        fixture_id="default",
        fixture_version=1,
        test_account=test_account,
        expected_network_signals=("fixture_loaded",),
        expected_log_signals=("ready",),
    )
    return RepositoryConfiguration(
        configuration_id=uuid4(),
        repository_key="boppuh/mathews",
        version=1,
        repository=RepositorySettings(root=str(root)),
        git=GitSettings(
            default_base_ref="main",
            task_branch_template="mathews/{task_id}",
            remote_name="origin",
            author=GitIdentity("Mathews", "mathews@example.invalid"),
            committer=GitIdentity("Mathews", "mathews@example.invalid"),
        ),
        xcode=XcodeSettings(
            container_path="Mathews.xcodeproj",
            container_kind=XcodeContainerKind.PROJECT,
            scheme="Mathews",
            simulator=SimulatorSettings(
                runtime_identifier="com.apple.CoreSimulator.SimRuntime.iOS-18-5",
                device_type_identifier=(
                    "com.apple.CoreSimulator.SimDeviceType.iPhone-16-Pro"
                ),
            ),
        ),
        operations=(
            RepositoryOperation(
                "build",
                OperationKind.BUILD,
                (
                    "xcodebuild",
                    "build",
                    "-project",
                    "Mathews.xcodeproj",
                    "-scheme",
                    "Mathews",
                    "-destination",
                    "MATHEWS_CONFIGURED_SIMULATOR",
                ),
                300,
            ),
            RepositoryOperation(
                "unit",
                OperationKind.UNIT_TEST,
                (
                    "xcodebuild",
                    "test",
                    "-project",
                    "Mathews.xcodeproj",
                    "-scheme",
                    "Mathews",
                    "-destination",
                    "MATHEWS_CONFIGURED_SIMULATOR",
                ),
                300,
            ),
            RepositoryOperation(
                "integration",
                OperationKind.INTEGRATION_TEST,
                (
                    "xcodebuild",
                    "test",
                    "-project",
                    "Mathews.xcodeproj",
                    "-scheme",
                    "Mathews",
                    "-destination",
                    "MATHEWS_CONFIGURED_SIMULATOR",
                ),
                300,
            ),
            RepositoryOperation(
                "e2e",
                OperationKind.SIMULATOR_E2E,
                (
                    "xcodebuild",
                    "test",
                    "-project",
                    "Mathews.xcodeproj",
                    "-scheme",
                    "Mathews",
                    "-destination",
                    "MATHEWS_CONFIGURED_SIMULATOR",
                ),
                300,
                e2e_flow=e2e_flow,
            ),
        ),
        assertion_catalog=(
            AssertionCatalogEntry(
                assertion_id="ready",
                kind=AssertionKind.NAVIGATION_STATE_REACHED,
                catalog_key="ready",
            ),
        ),
        artifacts=ArtifactSettings(
            collection_paths=("artifacts/test.log",),
        ),
        prohibited_paths=(".git",),
        secret_references=(test_account,),
    )


def _snapshot(root: Path) -> tuple[tuple[str, str, int], ...]:
    entries: list[tuple[str, str, int]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            entries.append((relative, digest, path.stat().st_mode))
        elif path.is_dir():
            entries.append((relative + "/", "", path.stat().st_mode))
    return tuple(entries)


def _simulator_payload() -> str:
    return json.dumps(
        {
            "runtimes": [
                {
                    "identifier": "com.apple.CoreSimulator.SimRuntime.iOS-18-5",
                    "isAvailable": True,
                    "name": "iOS 18.5",
                }
            ],
            "devicetypes": [
                {
                    "identifier": "com.apple.CoreSimulator.SimDeviceType.iPhone-16-Pro",
                    "name": "iPhone 16 Pro",
                }
            ],
            "devices": {
                "com.apple.CoreSimulator.SimRuntime.iOS-18-5": [
                    {
                        "deviceTypeIdentifier": (
                            "com.apple.CoreSimulator.SimDeviceType.iPhone-16-Pro"
                        ),
                        "isAvailable": True,
                        "name": "iPhone 16 Pro",
                    }
                ]
            },
        }
    )


def test_preflight_resolves_exact_local_base_without_mutating_repository(
    tmp_path: Path,
) -> None:
    root, expected_sha = _repository_fixture(tmp_path)
    commands = GitAndSimulatorProbe(_simulator_payload())
    filesystem = RecordingFilesystemProbe()
    before = _snapshot(root)

    report = RepositoryPreflightRunner(
        commands=commands,
        filesystem=filesystem,
    ).run(_configuration(root), attempt_id=uuid4())

    after = _snapshot(root)
    assert report.ready is True, report.to_dict()
    assert report.status is PreflightStatus.PASSED
    assert report.resolved_base_sha == expected_sha
    assert before == after
    assert not (root / ".mathews" / "workspaces").exists()
    assert {
        request.argv for request in commands.requests
    } == {
        ("git", "rev-parse", "--show-toplevel"),
        ("git", "remote", "get-url", "--", "origin"),
        (
            "git",
            "rev-parse",
            "--verify",
            "--end-of-options",
            "refs/remotes/origin/main^{commit}",
        ),
        ("xcrun", "simctl", "list", "-j"),
    }
    assert filesystem.resolved


def test_blocked_preflight_has_no_base_sha_or_raw_command_output(
    tmp_path: Path,
) -> None:
    root, _sha = _repository_fixture(tmp_path)
    configuration = _configuration(root)
    configuration = replace(
        configuration,
        git=replace(configuration.git, default_base_ref="missing"),
    )
    commands = GitAndSimulatorProbe(_simulator_payload())

    report = RepositoryPreflightRunner(commands=commands).run(
        configuration,
        attempt_id=uuid4(),
    )

    assert report.ready is False
    assert report.status is PreflightStatus.BLOCKED
    assert report.resolved_base_sha is None
    serialized_checks = json.dumps([check.to_dict() for check in report.checks])
    assert "fatal:" not in serialized_checks
    assert str(root) not in serialized_checks
    assert "github.com" not in serialized_checks


def test_preflight_requires_an_available_configured_simulator_device(
    tmp_path: Path,
) -> None:
    root, _sha = _repository_fixture(tmp_path)
    inventory = json.loads(_simulator_payload())
    inventory["devices"] = {}

    report = RepositoryPreflightRunner(
        commands=GitAndSimulatorProbe(json.dumps(inventory))
    ).run(_configuration(root), attempt_id=uuid4())

    simulator_check = next(
        check
        for check in report.checks
        if check.code is PreflightCheckCode.SIMULATOR
    )
    assert report.status is PreflightStatus.BLOCKED
    assert simulator_check.status is PreflightStatus.BLOCKED


def test_preflight_fails_closed_when_simulator_availability_is_omitted(
    tmp_path: Path,
) -> None:
    root, _sha = _repository_fixture(tmp_path)
    inventory = json.loads(_simulator_payload())
    del inventory["runtimes"][0]["isAvailable"]

    report = RepositoryPreflightRunner(
        commands=GitAndSimulatorProbe(json.dumps(inventory))
    ).run(_configuration(root), attempt_id=uuid4())

    assert report.status is PreflightStatus.BLOCKED
    assert next(
        check
        for check in report.checks
        if check.code is PreflightCheckCode.SIMULATOR
    ).status is PreflightStatus.BLOCKED


@pytest.mark.parametrize(
    "remote_url",
    (
        "git://github.com/boppuh/mathews.git",
        "ssh://git@github.com:2222/boppuh/mathews.git",
        "https://credential@github.com/boppuh/mathews.git",
        "https://[invalid/path",
    ),
)
def test_preflight_rejects_noncanonical_or_credential_bearing_remote_transport(
    tmp_path: Path,
    remote_url: str,
) -> None:
    root, _sha = _repository_fixture(tmp_path)
    _run_setup_git(root, "remote", "set-url", "origin", remote_url)

    report = RepositoryPreflightRunner(
        commands=GitAndSimulatorProbe(_simulator_payload())
    ).run(_configuration(root), attempt_id=uuid4())

    assert next(
        check
        for check in report.checks
        if check.code is PreflightCheckCode.GIT_REMOTE
    ).status is PreflightStatus.BLOCKED


def test_preflight_rejects_a_non_remote_tracking_base_ref(
    tmp_path: Path,
) -> None:
    root, _sha = _repository_fixture(tmp_path)
    configuration = _configuration(root)
    object.__setattr__(configuration.git, "default_base_ref", "refs/heads/main")

    report = RepositoryPreflightRunner(
        commands=GitAndSimulatorProbe(_simulator_payload())
    ).run(configuration, attempt_id=uuid4())

    assert next(
        check
        for check in report.checks
        if check.code is PreflightCheckCode.BASE_REVISION
    ).status is PreflightStatus.BLOCKED


def test_preflight_blocks_missing_deny_floor_and_shell_operation(
    tmp_path: Path,
) -> None:
    root, _sha = _repository_fixture(tmp_path)
    configuration = _configuration(root)
    object.__setattr__(
        configuration.operations[0],
        "argv",
        ("sh", "-c", "xcodebuild build"),
    )
    object.__setattr__(
        configuration.repository,
        "prohibited_operations",
        (ProhibitedOperation.MERGE, ProhibitedOperation.RELEASE),
    )
    object.__setattr__(configuration, "prohibited_paths", ())

    report = RepositoryPreflightRunner(
        commands=GitAndSimulatorProbe(_simulator_payload())
    ).run(configuration, attempt_id=uuid4())

    assert report.status is PreflightStatus.BLOCKED
    assert report.resolved_base_sha is not None
    assert {
        check.code
        for check in report.checks
        if check.status is PreflightStatus.BLOCKED
    } >= {PreflightCheckCode.OPERATIONS, PreflightCheckCode.PROHIBITIONS}


def test_preflight_blocks_symlink_escape_and_credential_bearing_expected_remote(
    tmp_path: Path,
) -> None:
    root, _sha = _repository_fixture(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "escaped").symlink_to(outside, target_is_directory=True)
    _run_setup_git(
        root,
        "remote",
        "set-url",
        "origin",
        "https://credential-value@github.com/boppuh/mathews.git",
    )
    configuration = _configuration(root)
    configuration = replace(
        configuration,
        artifacts=ArtifactSettings(collection_paths=("escaped/report.log",)),
    )

    report = RepositoryPreflightRunner(
        commands=GitAndSimulatorProbe(_simulator_payload())
    ).run(configuration, attempt_id=uuid4())

    assert report.status is PreflightStatus.BLOCKED
    detail_codes = " ".join(check.detail_code for check in report.checks)
    assert "credential-value" not in detail_codes
    assert {
        check.code
        for check in report.checks
        if check.status is PreflightStatus.BLOCKED
    } >= {PreflightCheckCode.ARTIFACT_PATHS, PreflightCheckCode.GIT_REMOTE}


def test_preflight_blocks_a_configured_symlink_repository_root(
    tmp_path: Path,
) -> None:
    root, _sha = _repository_fixture(tmp_path)
    symlink_root = tmp_path / "repository-link"
    symlink_root.symlink_to(root, target_is_directory=True)

    report = RepositoryPreflightRunner(
        commands=GitAndSimulatorProbe(_simulator_payload())
    ).run(_configuration(symlink_root), attempt_id=uuid4())

    assert report.status is PreflightStatus.BLOCKED
    root_check = next(
        check
        for check in report.checks
        if check.code is PreflightCheckCode.REPOSITORY_ROOT
    )
    assert root_check.status is PreflightStatus.BLOCKED


def test_preflight_rejects_a_symlinked_shared_scheme_escape(
    tmp_path: Path,
) -> None:
    root, _sha = _repository_fixture(tmp_path)
    scheme = (
        root
        / "Mathews.xcodeproj"
        / "xcshareddata"
        / "xcschemes"
        / "Mathews.xcscheme"
    )
    outside = tmp_path / "outside.xcscheme"
    outside.write_text("<Scheme/>\n")
    scheme.unlink()
    scheme.symlink_to(outside)

    report = RepositoryPreflightRunner(
        commands=GitAndSimulatorProbe(_simulator_payload())
    ).run(_configuration(root), attempt_id=uuid4())

    assert next(
        check
        for check in report.checks
        if check.code is PreflightCheckCode.SHARED_SCHEME
    ).status is PreflightStatus.BLOCKED
