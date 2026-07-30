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
    AssertionRole,
    E2EFlow,
    ElementValueVerifier,
    GitIdentity,
    GitSettings,
    LogEventVerifier,
    NavigationStateVerifier,
    NetworkMethod,
    NetworkResponseVerifier,
    NoCrashVerifier,
    OperationKind,
    PinnedRepositoryFile,
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
        (
            "git",
            "rev-parse",
            "--verify",
            "--end-of-options",
            "HEAD:.env",
        ),
        (
            "git",
            "hash-object",
            "--no-filters",
            "--",
            "../outside",
        ),
        (
            "git",
            "ls-tree",
            "-r",
            "--name-only",
            "a" * 40,
            "--",
            "../outside",
        ),
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
    workspace = root / "Mathews.xcworkspace"
    scheme_directory = workspace / "xcshareddata" / "xcschemes"
    scheme_directory.mkdir(parents=True)
    (workspace / "contents.xcworkspacedata").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Workspace version="1.0">\n'
        '  <FileRef location="group:Mathews.xcodeproj"/>\n'
        '  <FileRef location="group:MathewsHarness.xcodeproj"/>\n'
        "</Workspace>\n"
    )
    (scheme_directory / "Mathews.xcscheme").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Scheme version="1.7">\n'
        '  <TestAction buildConfiguration="Debug">\n'
        "    <Testables>\n"
        '      <TestableReference skipped="NO">\n'
        "        <BuildableReference "
        'BuildableIdentifier="primary" '
        'BlueprintIdentifier="AAAAAAAAAAAAAAAAAAAAAAAA" '
        'BuildableName="MathewsUITests.xctest" '
        'BlueprintName="MathewsUITests" '
        'ReferencedContainer="container:MathewsHarness.xcodeproj"/>\n'
        "      </TestableReference>\n"
        "    </Testables>\n"
        "  </TestAction>\n"
        "</Scheme>\n"
    )
    harness_project = root / "MathewsHarness.xcodeproj"
    harness_project.mkdir()
    (harness_project / "project.pbxproj").write_text(
        "// !$*UTF8*$!\n"
        "{\n"
        "\tobjects = {\n"
        "\t\tAAAAAAAAAAAAAAAAAAAAAAAA /* MathewsUITests */ = {\n"
        "\t\t\tisa = PBXNativeTarget;\n"
        "\t\t\tbuildConfigurationList = 111111111111111111111111;\n"
        "\t\t\tbuildPhases = (\n"
        "\t\t\t\tBBBBBBBBBBBBBBBBBBBBBBBB /* Sources */,\n"
        "\t\t\t\tEEEEEEEEEEEEEEEEEEEEEEEE /* Frameworks */,\n"
        "\t\t\t\tFFFFFFFFFFFFFFFFFFFFFFFF /* Resources */,\n"
        "\t\t\t);\n"
        "\t\t\tbuildRules = (\n"
        "\t\t\t);\n"
        "\t\t\tdependencies = (\n"
        "\t\t\t);\n"
        "\t\t\tname = MathewsUITests;\n"
        "\t\t\tpackageProductDependencies = (\n"
        "\t\t\t);\n"
        "\t\t\tproductType = com.apple.product-type.bundle.ui-testing;\n"
        "\t\t};\n"
        "\t\tBBBBBBBBBBBBBBBBBBBBBBBB /* Sources */ = {\n"
        "\t\t\tisa = PBXSourcesBuildPhase;\n"
        "\t\t\tfiles = (\n"
        "\t\t\t\tCCCCCCCCCCCCCCCCCCCCCCCC /* PrimaryJourneyTests.swift in Sources */,\n"
        "\t\t\t);\n"
        "\t\t};\n"
        "\t\tCCCCCCCCCCCCCCCCCCCCCCCC /* PrimaryJourneyTests.swift in Sources */ = {\n"
        "\t\t\tisa = PBXBuildFile;\n"
        "\t\t\tfileRef = DDDDDDDDDDDDDDDDDDDDDDDD /* PrimaryJourneyTests.swift */;\n"
        "\t\t};\n"
        "\t\tDDDDDDDDDDDDDDDDDDDDDDDD /* PrimaryJourneyTests.swift */ = {\n"
        "\t\t\tisa = PBXFileReference;\n"
        "\t\t\tlastKnownFileType = sourcecode.swift;\n"
        "\t\t\tpath = MathewsUITests/PrimaryJourneyTests.swift;\n"
        "\t\t\tsourceTree = SOURCE_ROOT;\n"
        "\t\t};\n"
        "\t\tEEEEEEEEEEEEEEEEEEEEEEEE /* Frameworks */ = {\n"
        "\t\t\tisa = PBXFrameworksBuildPhase;\n"
        "\t\t\tfiles = (\n"
        "\t\t\t);\n"
        "\t\t};\n"
        "\t\tFFFFFFFFFFFFFFFFFFFFFFFF /* Resources */ = {\n"
        "\t\t\tisa = PBXResourcesBuildPhase;\n"
        "\t\t\tfiles = (\n"
        "\t\t\t);\n"
        "\t\t};\n"
        "\t\t111111111111111111111111 = {\n"
        "\t\t\tisa = XCConfigurationList;\n"
        "\t\t\tbuildConfigurations = (\n"
        "\t\t\t\t222222222222222222222222,\n"
        "\t\t\t);\n"
        "\t\t};\n"
        "\t\t222222222222222222222222 = {\n"
        "\t\t\tisa = XCBuildConfiguration;\n"
        "\t\t\tbuildSettings = {\n"
        "\t\t\t\tGENERATE_INFOPLIST_FILE = YES;\n"
        "\t\t\t\tPRODUCT_BUNDLE_IDENTIFIER = com.boppuh.mathews.tests;\n"
        "\t\t\t\tPRODUCT_NAME = \"$(TARGET_NAME)\";\n"
        "\t\t\t\tSWIFT_VERSION = 5.0;\n"
        "\t\t\t};\n"
        "\t\t\tname = Debug;\n"
        "\t\t};\n"
        "\t\t333333333333333333333333 = {\n"
        "\t\t\tisa = PBXProject;\n"
        "\t\t\tbuildConfigurationList = 444444444444444444444444;\n"
        "\t\t\ttargets = (\n"
        "\t\t\t\tAAAAAAAAAAAAAAAAAAAAAAAA,\n"
        "\t\t\t);\n"
        "\t\t};\n"
        "\t\t444444444444444444444444 = {\n"
        "\t\t\tisa = XCConfigurationList;\n"
        "\t\t\tbuildConfigurations = (\n"
        "\t\t\t\t555555555555555555555555,\n"
        "\t\t\t);\n"
        "\t\t};\n"
        "\t\t555555555555555555555555 = {\n"
        "\t\t\tisa = XCBuildConfiguration;\n"
        "\t\t\tbuildSettings = {\n"
        "\t\t\t};\n"
        "\t\t\tname = Debug;\n"
        "\t\t};\n"
        "\t};\n"
        "\trootObject = 333333333333333333333333;\n"
        "}\n"
    )
    ui_tests = root / "MathewsUITests"
    ui_tests.mkdir()
    (ui_tests / "PrimaryJourneyTests.swift").write_text(
        "// pinned deterministic journey\n"
    )
    fixtures = root / "Fixtures"
    fixtures.mkdir()
    (fixtures / "primary.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "fixture_id": "default",
                "fixture_version": 1,
                "values": {"ready.title": "Ready"},
            },
            sort_keys=True,
        )
        + "\n"
    )
    (fixtures / "primary-account.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "recipe_id": "primary_account",
                "recipe_version": 1,
                "credential_source": "OPAQUE_SECRET_REFERENCE",
            },
            sort_keys=True,
        )
        + "\n"
    )
    _run_setup_git(root, "add", ".")
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

    return root, sha


def _pinned(root: Path, path: str) -> PinnedRepositoryFile:
    digest = hashlib.sha256((root / path).read_bytes()).hexdigest()
    return PinnedRepositoryFile(path=path, digest=f"sha256:{digest}")


def _commit_fixture_change(root: Path, path: str, content: str) -> str:
    (root / path).write_text(content)
    _run_setup_git(root, "add", "--", path)
    _run_setup_git(
        root,
        "-c",
        "user.name=Mathews Test",
        "-c",
        "user.email=mathews@example.invalid",
        "commit",
        "-m",
        f"change {path}",
    )
    sha = _run_setup_git(root, "rev-parse", "HEAD")
    _run_setup_git(root, "update-ref", "refs/remotes/origin/main", sha)
    return sha


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
        fixture_digest=_pinned(root, "Fixtures/primary.json").digest,
        test_account_recipe_id="primary_account",
        test_account_recipe_version=1,
        test_account_recipe_digest=_pinned(
            root,
            "Fixtures/primary-account.json",
        ).digest,
        test_account=test_account,
        runner_test_identifier=(
            "MathewsUITests/PrimaryJourneyTests/testPrimaryJourney"
        ),
        app_bundle_identifier="com.boppuh.mathews",
        harness_source_root="MathewsUITests",
        harness_project_path="MathewsHarness.xcodeproj",
        harness_target_identifier="AAAAAAAAAAAAAAAAAAAAAAAA",
        runner_source_file="MathewsUITests/PrimaryJourneyTests.swift",
        harness_files=(
            _pinned(root, "Mathews.xcworkspace/contents.xcworkspacedata"),
            _pinned(
                root,
                "Mathews.xcworkspace/xcshareddata/xcschemes/Mathews.xcscheme",
            ),
            _pinned(root, "MathewsHarness.xcodeproj/project.pbxproj"),
            _pinned(root, "MathewsUITests/PrimaryJourneyTests.swift"),
        ),
        fixture_file=_pinned(root, "Fixtures/primary.json"),
        test_account_recipe_file=_pinned(
            root,
            "Fixtures/primary-account.json",
        ),
        required_assertion_ids=(
            "ready_title",
            "ready",
            "fixture_response",
            "ready_log",
            "no_crash",
        ),
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
            container_path="Mathews.xcworkspace",
            container_kind=XcodeContainerKind.WORKSPACE,
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
                    "-workspace",
                    "Mathews.xcworkspace",
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
                    "-workspace",
                    "Mathews.xcworkspace",
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
                    "-workspace",
                    "Mathews.xcworkspace",
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
                    "-workspace",
                    "Mathews.xcworkspace",
                    "-scheme",
                    "Mathews",
                    "-destination",
                    "MATHEWS_CONFIGURED_SIMULATOR",
                    "-only-testing:MathewsUITests/PrimaryJourneyTests/testPrimaryJourney",
                ),
                300,
                e2e_flow=e2e_flow,
            ),
        ),
        assertion_catalog=(
            AssertionCatalogEntry(
                assertion_id="ready_title",
                kind=AssertionKind.ELEMENT_VALUE_PRESENT,
                role=AssertionRole.FLOW_BASELINE,
                catalog_key="ready.title",
                verifier=ElementValueVerifier(
                    accessibility_identifier="ready.title",
                    expected_value_fixture_key="ready.title",
                ),
            ),
            AssertionCatalogEntry(
                assertion_id="ready",
                kind=AssertionKind.NAVIGATION_STATE_REACHED,
                role=AssertionRole.FLOW_BASELINE,
                catalog_key="ready",
                verifier=NavigationStateVerifier(
                    state_id="READY",
                    marker_accessibility_identifier="ready.screen",
                ),
            ),
            AssertionCatalogEntry(
                assertion_id="fixture_response",
                kind=AssertionKind.EXPECTED_NETWORK_RESPONSE,
                role=AssertionRole.FLOW_BASELINE,
                catalog_key="fixture.response",
                verifier=NetworkResponseVerifier(
                    endpoint_class="fixture_loaded",
                    method=NetworkMethod.GET,
                    expected_status_code=200,
                ),
            ),
            AssertionCatalogEntry(
                assertion_id="ready_log",
                kind=AssertionKind.EXPECTED_LOG_EVENT,
                role=AssertionRole.FLOW_BASELINE,
                catalog_key="ready.log",
                verifier=LogEventVerifier(
                    subsystem="com.boppuh.mathews",
                    category="journey",
                    event_key="ready",
                ),
            ),
            AssertionCatalogEntry(
                assertion_id="no_crash",
                kind=AssertionKind.NO_CRASH,
                role=AssertionRole.FLOW_BASELINE,
                catalog_key="app.process",
                verifier=NoCrashVerifier(
                    bundle_identifier="com.boppuh.mathews",
                ),
            ),
            AssertionCatalogEntry(
                assertion_id="task_ready_title",
                kind=AssertionKind.ELEMENT_VALUE_PRESENT,
                role=AssertionRole.TASK_SELECTABLE,
                catalog_key="ready.title.task",
                verifier=ElementValueVerifier(
                    accessibility_identifier="ready.title",
                    expected_value_fixture_key="ready.title",
                ),
            ),
        ),
        artifacts=ArtifactSettings(
            collection_paths=("artifacts/test.log",),
        ),
        prohibited_paths=(
            ".git",
            "Mathews.xcworkspace/contents.xcworkspacedata",
            "Mathews.xcworkspace/xcshareddata/xcschemes/Mathews.xcscheme",
            "MathewsHarness.xcodeproj/project.pbxproj",
            "MathewsUITests",
            "Fixtures/primary.json",
            "Fixtures/primary-account.json",
        ),
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
    configuration = _configuration(root)

    report = RepositoryPreflightRunner(
        commands=commands,
        filesystem=filesystem,
    ).run(configuration, attempt_id=uuid4())

    after = _snapshot(root)
    assert report.ready is True, report.to_dict()
    assert report.status is PreflightStatus.PASSED
    assert report.resolved_base_sha == expected_sha
    assert before == after
    assert not (root / ".mathews" / "workspaces").exists()
    flow = next(
        operation.e2e_flow
        for operation in configuration.operations
        if operation.kind is OperationKind.SIMULATOR_E2E
    )
    assert flow is not None
    pinned_paths = {
        pinned.path
        for pinned in (
            *flow.harness_files,
            flow.fixture_file,
            flow.test_account_recipe_file,
        )
    }
    expected_requests = {
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
        (
            "git",
            "ls-tree",
            "-r",
            "--name-only",
            expected_sha,
            "--",
            flow.harness_source_root,
        ),
    }
    expected_requests |= {
        (
            "git",
            "ls-tree",
            "--format=%(objectmode) %(objecttype) %(objectname)",
            expected_sha,
            "--",
            path,
        )
        for path in pinned_paths
    }
    expected_requests |= {
        (
            "git",
            "hash-object",
            "--no-filters",
            "--",
            path,
        )
        for path in pinned_paths
    }
    assert {request.argv for request in commands.requests} == expected_requests
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


@pytest.mark.parametrize(
    "pinned_path",
    (
        "MathewsUITests/PrimaryJourneyTests.swift",
        "Fixtures/primary.json",
        "Fixtures/primary-account.json",
        "Mathews.xcworkspace/contents.xcworkspacedata",
        "Mathews.xcworkspace/xcshareddata/xcschemes/Mathews.xcscheme",
        "MathewsHarness.xcodeproj/project.pbxproj",
    ),
)
def test_preflight_blocks_tampered_flow_harness_fixture_or_recipe(
    tmp_path: Path,
    pinned_path: str,
) -> None:
    root, _sha = _repository_fixture(tmp_path)
    configuration = _configuration(root)
    (root / pinned_path).write_bytes(b"tampered after configuration")

    report = RepositoryPreflightRunner(
        commands=GitAndSimulatorProbe(_simulator_payload())
    ).run(configuration, attempt_id=uuid4())

    e2e_check = next(
        check
        for check in report.checks
        if check.code is PreflightCheckCode.E2E_FLOW
    )
    assert report.status is PreflightStatus.BLOCKED
    assert e2e_check.status is PreflightStatus.BLOCKED


def test_preflight_blocks_unpinned_files_in_the_harness_source_root(
    tmp_path: Path,
) -> None:
    root, _sha = _repository_fixture(tmp_path)
    configuration = _configuration(root)
    (root / "MathewsUITests" / "UnpinnedVerifier.swift").write_text(
        "// would bypass the pinned verifier set\n"
    )

    report = RepositoryPreflightRunner(
        commands=GitAndSimulatorProbe(_simulator_payload())
    ).run(configuration, attempt_id=uuid4())

    assert next(
        check
        for check in report.checks
        if check.code is PreflightCheckCode.E2E_FLOW
    ).status is PreflightStatus.BLOCKED


def test_preflight_binds_pinned_bytes_to_the_resolved_base_commit(
    tmp_path: Path,
) -> None:
    root, _sha = _repository_fixture(tmp_path)
    harness = root / "MathewsUITests" / "PrimaryJourneyTests.swift"
    harness.write_text("// dirty harness matches config but not resolved base\n")
    configuration = _configuration(root)

    report = RepositoryPreflightRunner(
        commands=GitAndSimulatorProbe(_simulator_payload())
    ).run(configuration, attempt_id=uuid4())

    assert next(
        check
        for check in report.checks
        if check.code is PreflightCheckCode.E2E_FLOW
    ).status is PreflightStatus.BLOCKED


def test_preflight_compares_raw_bytes_without_git_attribute_normalization(
    tmp_path: Path,
) -> None:
    root, _sha = _repository_fixture(tmp_path)
    (root / ".gitattributes").write_text("*.swift text eol=lf\n")
    _run_setup_git(root, "add", "--", ".gitattributes")
    _run_setup_git(
        root,
        "-c",
        "user.name=Mathews Test",
        "-c",
        "user.email=mathews@example.invalid",
        "commit",
        "-m",
        "configure line endings",
    )
    sha = _run_setup_git(root, "rev-parse", "HEAD")
    _run_setup_git(root, "update-ref", "refs/remotes/origin/main", sha)
    harness = root / "MathewsUITests" / "PrimaryJourneyTests.swift"
    harness.write_bytes(harness.read_bytes().replace(b"\n", b"\r\n"))
    configuration = _configuration(root)

    report = RepositoryPreflightRunner(
        commands=GitAndSimulatorProbe(_simulator_payload())
    ).run(configuration, attempt_id=uuid4())

    assert next(
        check
        for check in report.checks
        if check.code is PreflightCheckCode.E2E_FLOW
    ).status is PreflightStatus.BLOCKED


def test_preflight_rejects_a_decoy_runner_outside_the_pinned_source_closure(
    tmp_path: Path,
) -> None:
    root, _sha = _repository_fixture(tmp_path)
    project = root / "MathewsHarness.xcodeproj" / "project.pbxproj"
    _commit_fixture_change(
        root,
        "MathewsHarness.xcodeproj/project.pbxproj",
        project.read_text().replace(
            "path = MathewsUITests/PrimaryJourneyTests.swift;",
            "path = Mutable/PrimaryJourneyTests.swift;",
        ),
    )
    configuration = _configuration(root)

    report = RepositoryPreflightRunner(
        commands=GitAndSimulatorProbe(_simulator_payload())
    ).run(configuration, attempt_id=uuid4())

    assert next(
        check
        for check in report.checks
        if check.code is PreflightCheckCode.E2E_FLOW
    ).status is PreflightStatus.BLOCKED


def test_preflight_rejects_a_scheme_bound_to_an_unrelated_harness_project(
    tmp_path: Path,
) -> None:
    root, _sha = _repository_fixture(tmp_path)
    scheme_path = (
        "Mathews.xcworkspace/xcshareddata/xcschemes/Mathews.xcscheme"
    )
    scheme = root / scheme_path
    _commit_fixture_change(
        root,
        scheme_path,
        scheme.read_text().replace(
            "container:MathewsHarness.xcodeproj",
            "container:Unrelated.xcodeproj",
        ),
    )
    configuration = _configuration(root)

    report = RepositoryPreflightRunner(
        commands=GitAndSimulatorProbe(_simulator_payload())
    ).run(configuration, attempt_id=uuid4())

    assert next(
        check
        for check in report.checks
        if check.code is PreflightCheckCode.E2E_FLOW
    ).status is PreflightStatus.BLOCKED


def test_preflight_rejects_scheme_execution_actions(
    tmp_path: Path,
) -> None:
    root, _sha = _repository_fixture(tmp_path)
    scheme_path = (
        "Mathews.xcworkspace/xcshareddata/xcschemes/Mathews.xcscheme"
    )
    scheme = root / scheme_path
    _commit_fixture_change(
        root,
        scheme_path,
        scheme.read_text().replace(
            '  <TestAction buildConfiguration="Debug">\n',
            '  <TestAction buildConfiguration="Debug">\n'
            "    <PreActions>\n"
            "      <ExecutionAction "
            'ActionType="Xcode.IDEStandardExecutionActionsCore.'
            'ExecutionActionType.ShellScriptAction"/>\n'
            "    </PreActions>\n",
        ),
    )
    configuration = _configuration(root)

    report = RepositoryPreflightRunner(
        commands=GitAndSimulatorProbe(_simulator_payload())
    ).run(configuration, attempt_id=uuid4())

    assert next(
        check
        for check in report.checks
        if check.code is PreflightCheckCode.E2E_FLOW
    ).status is PreflightStatus.BLOCKED


@pytest.mark.parametrize(
    ("needle", "replacement"),
    (
        (
            '  <TestAction buildConfiguration="Debug">\n',
            "  <BuildAction>\n"
            '    <BuildActionEntry buildForTesting="YES">\n'
            "      <BuildableReference "
            'BuildableIdentifier="primary" '
            'BlueprintIdentifier="999999999999999999999999" '
            'BuildableName="Mutable.app" '
            'BlueprintName="MutableTarget" '
            'ReferencedContainer="container:Mutable.xcodeproj"/>\n'
            "    </BuildActionEntry>\n"
            "  </BuildAction>\n"
            '  <TestAction buildConfiguration="Debug">\n',
        ),
        (
            "    <Testables>\n",
            "    <TestPlans>\n"
            '      <TestPlanReference default="YES" '
            'reference="container:Mutable.xctestplan"/>\n'
            "    </TestPlans>\n"
            "    <Testables>\n",
        ),
        (
            "        <BuildableReference ",
            "        <SkippedTests>\n"
            '          <Test Identifier="PrimaryJourneyTests/testPrimaryJourney"/>\n'
            "        </SkippedTests>\n"
            "        <BuildableReference ",
        ),
        (
            'ReferencedContainer="container:MathewsHarness.xcodeproj"/>\n',
            'ReferencedContainer="container:MathewsHarness.xcodeproj">\n'
            "          <UnknownExecutionInput/>\n"
            "        </BuildableReference>\n",
        ),
    ),
)
def test_preflight_rejects_external_scheme_execution_inputs(
    tmp_path: Path,
    needle: str,
    replacement: str,
) -> None:
    root, _sha = _repository_fixture(tmp_path)
    scheme_path = (
        "Mathews.xcworkspace/xcshareddata/xcschemes/Mathews.xcscheme"
    )
    scheme = root / scheme_path
    _commit_fixture_change(
        root,
        scheme_path,
        scheme.read_text().replace(needle, replacement, 1),
    )
    configuration = _configuration(root)

    report = RepositoryPreflightRunner(
        commands=GitAndSimulatorProbe(_simulator_payload())
    ).run(configuration, attempt_id=uuid4())

    assert next(
        check
        for check in report.checks
        if check.code is PreflightCheckCode.E2E_FLOW
    ).status is PreflightStatus.BLOCKED


@pytest.mark.parametrize(
    ("needle", "replacement"),
    (
        (
            "\t\t\tbuildSettings = {\n",
            "\t\t\tbaseConfigurationReference = DDDDDDDDDDDDDDDDDDDDDDDD;\n"
            "\t\t\tbuildSettings = {\n",
        ),
        (
            "\t\t\t\tGENERATE_INFOPLIST_FILE = YES;\n",
            "\t\t\t\tGENERATE_INFOPLIST_FILE = YES;\n"
            "\t\t\t\tOTHER_SWIFT_FLAGS = \"@mutable.rsp\";\n",
        ),
    ),
)
def test_preflight_rejects_unpinned_harness_build_configuration_inputs(
    tmp_path: Path,
    needle: str,
    replacement: str,
) -> None:
    root, _sha = _repository_fixture(tmp_path)
    project_path = "MathewsHarness.xcodeproj/project.pbxproj"
    project = root / project_path
    _commit_fixture_change(
        root,
        project_path,
        project.read_text().replace(needle, replacement, 1),
    )
    configuration = _configuration(root)

    report = RepositoryPreflightRunner(
        commands=GitAndSimulatorProbe(_simulator_payload())
    ).run(configuration, attempt_id=uuid4())

    assert next(
        check
        for check in report.checks
        if check.code is PreflightCheckCode.E2E_FLOW
    ).status is PreflightStatus.BLOCKED


def test_preflight_does_not_parse_decoy_pbx_objects_inside_comments(
    tmp_path: Path,
) -> None:
    root, _sha = _repository_fixture(tmp_path)
    project_path = "MathewsHarness.xcodeproj/project.pbxproj"
    project = root / project_path
    _commit_fixture_change(
        root,
        project_path,
        f"/*\n{project.read_text()}\n*/\n{{}}\n",
    )
    configuration = _configuration(root)

    report = RepositoryPreflightRunner(
        commands=GitAndSimulatorProbe(_simulator_payload())
    ).run(configuration, attempt_id=uuid4())

    assert next(
        check
        for check in report.checks
        if check.code is PreflightCheckCode.E2E_FLOW
    ).status is PreflightStatus.BLOCKED


def test_preflight_rejects_a_base_symlink_with_the_same_blob_bytes(
    tmp_path: Path,
) -> None:
    root, _sha = _repository_fixture(tmp_path)
    runner = root / "MathewsUITests" / "PrimaryJourneyTests.swift"
    runner.unlink()
    runner.symlink_to("runner.swift")
    _run_setup_git(root, "add", "--", "MathewsUITests/PrimaryJourneyTests.swift")
    _run_setup_git(
        root,
        "-c",
        "user.name=Mathews Test",
        "-c",
        "user.email=mathews@example.invalid",
        "commit",
        "-m",
        "replace runner with symlink",
    )
    sha = _run_setup_git(root, "rev-parse", "HEAD")
    _run_setup_git(root, "update-ref", "refs/remotes/origin/main", sha)
    runner.unlink()
    runner.write_text("runner.swift")
    configuration = _configuration(root)

    report = RepositoryPreflightRunner(
        commands=GitAndSimulatorProbe(_simulator_payload())
    ).run(configuration, attempt_id=uuid4())

    assert next(
        check
        for check in report.checks
        if check.code is PreflightCheckCode.E2E_FLOW
    ).status is PreflightStatus.BLOCKED


@pytest.mark.parametrize(
    ("path", "manifest"),
    (
        (
            "Fixtures/primary.json",
            {
                "schema_version": 1,
                "fixture_id": "default",
                "fixture_version": 1,
                "values": {"unrelated.value": "Ready"},
            },
        ),
        (
            "Fixtures/primary-account.json",
            {
                "schema_version": 1,
                "recipe_id": "primary_account",
                "recipe_version": 1,
                "credential_source": "OPAQUE_SECRET_REFERENCE",
                "credential_value": "must-never-be-in-repository",
            },
        ),
    ),
)
def test_preflight_rejects_unusable_or_credential_bearing_recipes(
    tmp_path: Path,
    path: str,
    manifest: dict[str, object],
) -> None:
    root, _sha = _repository_fixture(tmp_path)
    _commit_fixture_change(root, path, json.dumps(manifest, sort_keys=True) + "\n")
    configuration = _configuration(root)

    report = RepositoryPreflightRunner(
        commands=GitAndSimulatorProbe(_simulator_payload())
    ).run(configuration, attempt_id=uuid4())

    assert next(
        check
        for check in report.checks
        if check.code is PreflightCheckCode.E2E_FLOW
    ).status is PreflightStatus.BLOCKED


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
        / "Mathews.xcworkspace"
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
