import json
from dataclasses import replace
from uuid import uuid4

import pytest
from mathews_configuration.repository import (
    MANDATORY_PROHIBITED_OPERATIONS,
    REQUIRED_PREFLIGHT_CHECKS,
    ArtifactSettings,
    AssertionCatalogEntry,
    AssertionKind,
    E2EFlow,
    GitIdentity,
    GitSettings,
    OperationKind,
    PreflightCheck,
    PreflightCheckCode,
    PreflightStatus,
    ProhibitedOperation,
    RepositoryConfiguration,
    RepositoryConfigurationError,
    RepositoryPreflightReport,
    RepositorySettings,
    SimulatorSettings,
    XcodeContainerKind,
    XcodeSettings,
)
from mathews_configuration.repository import TestOperation as ConfiguredOperation
from mathews_configuration.secrets import SecretReference


def _operation(
    kind: OperationKind,
    *,
    flow: E2EFlow | None = None,
) -> ConfiguredOperation:
    action = "build" if kind is OperationKind.BUILD else "test"
    return ConfiguredOperation(
        operation_id=kind.value.lower(),
        kind=kind,
        argv=(
            "xcodebuild",
            action,
            "-workspace",
            "Example.xcworkspace",
            "-scheme",
            "Example",
            "-destination",
            "MATHEWS_CONFIGURED_SIMULATOR",
        ),
        timeout_seconds=600,
        e2e_flow=flow,
    )


def _configuration() -> RepositoryConfiguration:
    test_account = SecretReference.parse("keychain://mathews-tests/primary-account")
    flow = E2EFlow(
        flow_id="primary_journey",
        version=1,
        entry_point="app.launch",
        terminal_state="task.completed",
        fixture_id="primary_fixture",
        fixture_version=1,
        test_account=test_account,
        expected_network_signals=("task.created",),
        expected_log_signals=("task.completed",),
        acceptable_warnings=("simulator.noise",),
    )
    return RepositoryConfiguration(
        configuration_id=uuid4(),
        repository_key="boppuh/example-ios",
        version=2,
        repository=RepositorySettings(
            root="/Users/operator/dev/example-ios",
            prohibited_operations=tuple(ProhibitedOperation),
        ),
        git=GitSettings(
            default_base_ref="refs/remotes/origin/main",
            task_branch_template="mathews/{task_id}",
            remote_name="origin",
            author=GitIdentity(name="Mathews", email="mathews@example.test"),
            committer=GitIdentity(name="Mathews", email="mathews@example.test"),
        ),
        xcode=XcodeSettings(
            container_kind=XcodeContainerKind.WORKSPACE,
            container_path="Example.xcworkspace",
            scheme="Example",
            simulator=SimulatorSettings(
                runtime_identifier="com.apple.CoreSimulator.SimRuntime.iOS-26-0",
                device_type_identifier=(
                    "com.apple.CoreSimulator.SimDeviceType.iPhone-17-Pro"
                ),
            ),
        ),
        operations=tuple(
            _operation(kind, flow=flow if kind is OperationKind.SIMULATOR_E2E else None)
            for kind in OperationKind
        ),
        assertion_catalog=(
            AssertionCatalogEntry(
                assertion_id="terminal_state",
                kind=AssertionKind.NAVIGATION_STATE_REACHED,
                catalog_key="task.completed",
            ),
            AssertionCatalogEntry(
                assertion_id="no_crash",
                kind=AssertionKind.NO_CRASH,
                catalog_key="app.process",
            ),
        ),
        artifacts=ArtifactSettings(
            collection_paths=("artifacts/build", "artifacts/test")
        ),
        prohibited_paths=(".git", "fastlane/metadata"),
        secret_references=(test_account,),
    )


def _passed_checks() -> tuple[PreflightCheck, ...]:
    return tuple(
        PreflightCheck.for_status(code, PreflightStatus.PASSED)
        for code in PreflightCheckCode
    )


def test_configuration_has_stable_lossless_canonical_persistence_mapping() -> None:
    configuration = _configuration()
    payload = configuration.to_dict()

    assert set(payload) == {
        "repository_key",
        "version",
        "repository_settings",
        "git_settings",
        "xcode_settings",
        "operations",
        "e2e_assertions",
        "artifact_settings",
        "prohibited_paths",
        "secret_references",
    }
    assert str(configuration.configuration_id) not in configuration.to_json()
    assert configuration.to_json() == json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    assert RepositoryConfiguration.from_dict(
        configuration.configuration_id,
        json.loads(configuration.to_json()),
    ) == configuration
    assert RepositoryConfiguration.from_dict(
        uuid4(),
        json.loads(configuration.to_json()),
    ).digest == configuration.digest


def test_configuration_requires_exactly_one_of_each_operation_and_one_e2e_flow() -> None:
    configuration = _configuration()

    with pytest.raises(RepositoryConfigurationError, match="exactly one BUILD"):
        replace(configuration, operations=configuration.operations[:-1])

    duplicate = replace(
        configuration.operations[0],
        kind=OperationKind.UNIT_TEST,
        argv=("xcodebuild", "test"),
    )
    with pytest.raises(RepositoryConfigurationError, match="exactly one BUILD"):
        replace(configuration, operations=(duplicate, *configuration.operations[1:]))


def test_configuration_rejects_shell_and_release_operations() -> None:
    with pytest.raises(RepositoryConfigurationError, match="invoke xcodebuild directly"):
        replace(_configuration().operations[0], argv=("sh", "-c", "xcodebuild build"))

    with pytest.raises(RepositoryConfigurationError, match="archive"):
        replace(
            _configuration().operations[0],
            argv=("xcodebuild", "archive"),
        )


@pytest.mark.parametrize(
    "repository_key",
    (
        "Boppuh/mathews",
        "boppuh/mathews.git",
        "boppuh/mathews/extra",
        "boppuh/%6dathews",
    ),
)
def test_configuration_requires_one_canonical_repository_key(
    repository_key: str,
) -> None:
    with pytest.raises(RepositoryConfigurationError, match="canonical lowercase"):
        replace(_configuration(), repository_key=repository_key)


@pytest.mark.parametrize(
    "base_ref",
    (
        "refs/heads/main",
        "refs/tags/v1",
        "refs/pull/1/head",
        "refs/remotes/upstream/main",
    ),
)
def test_configuration_restricts_base_to_the_configured_remote(
    base_ref: str,
) -> None:
    with pytest.raises(RepositoryConfigurationError, match="remote-tracking"):
        replace(_configuration().git, default_base_ref=base_ref)


@pytest.mark.parametrize(
    "argv",
    (
        (
            "xcodebuild",
            "build",
            "-project",
            "Other.xcodeproj",
            "-scheme",
            "Other",
        ),
        (
            "xcodebuild",
            "build",
            "-workspace",
            "Example.xcworkspace",
            "-scheme",
            "Example",
            "SYMROOT=/tmp/out",
        ),
        (
            "xcodebuild",
            "build",
            "-workspace",
            "Example.xcworkspace",
            "-scheme",
            "Example",
            "-derivedDataPath",
            "/tmp/out",
        ),
    ),
)
def test_configuration_binds_operations_to_xcode_and_rejects_overrides(
    argv: tuple[str, ...],
) -> None:
    configuration = _configuration()
    with pytest.raises(RepositoryConfigurationError):
        replace(
            configuration,
            operations=(replace(configuration.operations[0], argv=argv),)
            + configuration.operations[1:],
        )


def test_artifacts_and_xcode_inputs_cannot_overlap_prohibited_paths() -> None:
    configuration = _configuration()
    with pytest.raises(RepositoryConfigurationError, match="must not overlap"):
        replace(
            configuration,
            artifacts=ArtifactSettings(collection_paths=(".git/config",)),
        )


def test_configuration_cannot_weaken_prohibition_floors() -> None:
    without_merge = tuple(
        operation
        for operation in ProhibitedOperation
        if operation is not ProhibitedOperation.MERGE
    )
    with pytest.raises(RepositoryConfigurationError, match="mandatory floor"):
        RepositorySettings(
            root="/Users/operator/dev/example-ios",
            prohibited_operations=without_merge,
        )

    assert MANDATORY_PROHIBITED_OPERATIONS == frozenset(ProhibitedOperation)
    with pytest.raises(RepositoryConfigurationError, match=r"mandatory \.git floor"):
        replace(_configuration(), prohibited_paths=("Sources",))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("root", "relative/repository", "canonical absolute"),
        ("root", "/", "canonical absolute"),
        ("branch", "mathews/{task_id}/../main", "one safe"),
        ("artifact", "../outside", "repository-relative"),
    ),
)
def test_configuration_rejects_path_and_branch_escape(
    field: str,
    value: str,
    message: str,
) -> None:
    configuration = _configuration()
    with pytest.raises(RepositoryConfigurationError, match=message):
        if field == "root":
            replace(configuration.repository, root=value)
        elif field == "branch":
            replace(configuration.git, task_branch_template=value)
        else:
            ArtifactSettings(collection_paths=(value,))


def test_configuration_accepts_only_opaque_keychain_references() -> None:
    configuration = _configuration()
    payload = configuration.to_dict()
    payload["secret_references"] = ["plain-text-password"]

    with pytest.raises(ValueError, match="keychain"):
        RepositoryConfiguration.from_dict(configuration.configuration_id, payload)


def test_assertion_vocabulary_is_exactly_the_frozen_five_kinds() -> None:
    assert {kind.value for kind in AssertionKind} == {
        "ELEMENT_VALUE_PRESENT",
        "NAVIGATION_STATE_REACHED",
        "EXPECTED_NETWORK_RESPONSE",
        "EXPECTED_LOG_EVENT",
        "NO_CRASH",
    }


def test_passed_preflight_requires_all_checks_and_exact_base_sha() -> None:
    configuration = _configuration()
    report = RepositoryPreflightReport(
        attempt_id=uuid4(),
        configuration_id=configuration.configuration_id,
        configuration_version=configuration.version,
        configuration_digest=configuration.digest,
        status=PreflightStatus.PASSED,
        checks=_passed_checks(),
        resolved_base_sha="a" * 40,
    )

    assert report.ready
    assert RepositoryPreflightReport.from_dict(report.to_dict()) == report
    assert {check.code for check in report.checks} == REQUIRED_PREFLIGHT_CHECKS

    with pytest.raises(RepositoryConfigurationError, match="every check"):
        replace(report, checks=report.checks[:-1])
    with pytest.raises(RepositoryConfigurationError, match="exact lowercase"):
        replace(report, resolved_base_sha=None)


def test_blocked_preflight_can_record_failure_before_base_resolution() -> None:
    configuration = _configuration()
    checks = list(_passed_checks())
    base_index = next(
        index
        for index, check in enumerate(checks)
        if check.code is PreflightCheckCode.BASE_REVISION
    )
    checks[base_index] = PreflightCheck.for_status(
        PreflightCheckCode.BASE_REVISION,
        PreflightStatus.BLOCKED,
    )

    report = RepositoryPreflightReport(
        attempt_id=uuid4(),
        configuration_id=configuration.configuration_id,
        configuration_version=configuration.version,
        configuration_digest=configuration.digest,
        status=PreflightStatus.BLOCKED,
        checks=tuple(checks),
        resolved_base_sha=None,
    )

    assert not report.ready
    assert RepositoryPreflightReport.from_dict(report.to_dict()) == report


def test_preflight_check_rejects_unbounded_or_unknown_shapes() -> None:
    with pytest.raises(RepositoryConfigurationError, match="missing or unknown"):
        PreflightCheck.from_dict(
            {
                "code": "CONFIGURATION",
                "status": "PASSED",
                "detail_code": "configuration.passed",
                "raw_stdout": "credential-bearing output",
            }
        )
    with pytest.raises(RepositoryConfigurationError, match="code and status"):
        PreflightCheck(
            code=PreflightCheckCode.CONFIGURATION,
            status=PreflightStatus.BLOCKED,
            detail_code="configuration.canonical",
        )
