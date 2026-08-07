import json
from dataclasses import replace
from typing import cast
from uuid import uuid4

import pytest
from mathews_configuration.repository import (
    MANDATORY_PROHIBITED_OPERATIONS,
    REQUIRED_PREFLIGHT_CHECKS,
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
from mathews_configuration.simulator import (
    AcceptedBriefAssertionSource,
    BriefApprovalDisposition,
    CriterionAssertionBinding,
    CriterionAssertionRequirement,
    PersistedBriefApprovalRecord,
    TaskAssertionContract,
)


def _operation(
    kind: OperationKind,
    *,
    flow: E2EFlow | None = None,
) -> ConfiguredOperation:
    action = "build" if kind is OperationKind.BUILD else "test"
    argv: tuple[str, ...] = (
        "xcodebuild",
        action,
        "-workspace",
        "Example.xcworkspace",
        "-scheme",
        "Example",
        "-destination",
        "MATHEWS_CONFIGURED_SIMULATOR",
    )
    if kind is OperationKind.SIMULATOR_E2E:
        argv += (
            "-only-testing:ExampleUITests/PrimaryJourneyTests/testPrimaryJourney",
        )
    return ConfiguredOperation(
        operation_id=kind.value.lower(),
        kind=kind,
        argv=argv,
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
        fixture_digest=f"sha256:{'1' * 64}",
        test_account_recipe_id="primary_account",
        test_account_recipe_version=1,
        test_account_recipe_digest=f"sha256:{'2' * 64}",
        test_account=test_account,
        runner_test_identifier=(
            "ExampleUITests/PrimaryJourneyTests/testPrimaryJourney"
        ),
        app_bundle_identifier="com.example.Example",
        harness_source_root="ExampleUITests",
        harness_project_path="ExampleHarness.xcodeproj",
        harness_target_identifier="AAAAAAAAAAAAAAAAAAAAAAAA",
        runner_source_file="ExampleUITests/PrimaryJourneyTests.swift",
        harness_files=(
            PinnedRepositoryFile(
                path="Example.xcworkspace/contents.xcworkspacedata",
                digest=f"sha256:{'3' * 64}",
            ),
            PinnedRepositoryFile(
                path=(
                    "Example.xcworkspace/xcshareddata/xcschemes/Example.xcscheme"
                ),
                digest=f"sha256:{'4' * 64}",
            ),
            PinnedRepositoryFile(
                path="ExampleHarness.xcodeproj/project.pbxproj",
                digest=f"sha256:{'5' * 64}",
            ),
            PinnedRepositoryFile(
                path="ExampleUITests/PrimaryJourneyTests.swift",
                digest=f"sha256:{'6' * 64}",
            ),
        ),
        fixture_file=PinnedRepositoryFile(
            path="Fixtures/primary.json",
            digest=f"sha256:{'1' * 64}",
        ),
        test_account_recipe_file=PinnedRepositoryFile(
            path="Fixtures/primary-account.json",
            digest=f"sha256:{'2' * 64}",
        ),
        required_assertion_ids=(
            "task_title",
            "terminal_state",
            "network_response",
            "log_event",
            "no_crash",
        ),
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
            push_credential=SecretReference.parse(
                "keychain://com.boppuh.mathews.git/example-ios-push"
            ),
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
                assertion_id="task_title",
                kind=AssertionKind.ELEMENT_VALUE_PRESENT,
                role=AssertionRole.FLOW_BASELINE,
                catalog_key="task.title",
                verifier=ElementValueVerifier(
                    accessibility_identifier="task.title",
                    expected_value_fixture_key="task.title",
                ),
            ),
            AssertionCatalogEntry(
                assertion_id="terminal_state",
                kind=AssertionKind.NAVIGATION_STATE_REACHED,
                role=AssertionRole.FLOW_BASELINE,
                catalog_key="task.completed",
                verifier=NavigationStateVerifier(
                    state_id="task.completed",
                    marker_accessibility_identifier="task.completed",
                ),
            ),
            AssertionCatalogEntry(
                assertion_id="network_response",
                kind=AssertionKind.EXPECTED_NETWORK_RESPONSE,
                role=AssertionRole.FLOW_BASELINE,
                catalog_key="task.created.response",
                verifier=NetworkResponseVerifier(
                    endpoint_class="task.created",
                    method=NetworkMethod.POST,
                    expected_status_code=201,
                ),
            ),
            AssertionCatalogEntry(
                assertion_id="log_event",
                kind=AssertionKind.EXPECTED_LOG_EVENT,
                role=AssertionRole.FLOW_BASELINE,
                catalog_key="task.completed.log",
                verifier=LogEventVerifier(
                    subsystem="com.example.Example",
                    category="task",
                    event_key="task.completed",
                ),
            ),
            AssertionCatalogEntry(
                assertion_id="no_crash",
                kind=AssertionKind.NO_CRASH,
                role=AssertionRole.FLOW_BASELINE,
                catalog_key="app.process",
                verifier=NoCrashVerifier(
                    bundle_identifier="com.example.Example",
                ),
            ),
            AssertionCatalogEntry(
                assertion_id="changed_task_title",
                kind=AssertionKind.ELEMENT_VALUE_PRESENT,
                role=AssertionRole.TASK_SELECTABLE,
                catalog_key="task.title.changed",
                verifier=ElementValueVerifier(
                    accessibility_identifier="task.title",
                    expected_value_fixture_key="task.title",
                ),
            ),
            AssertionCatalogEntry(
                assertion_id="changed_terminal_state",
                kind=AssertionKind.NAVIGATION_STATE_REACHED,
                role=AssertionRole.TASK_SELECTABLE,
                catalog_key="task.completed.changed",
                verifier=NavigationStateVerifier(
                    state_id="task.completed",
                    marker_accessibility_identifier="task.completed",
                ),
            ),
            AssertionCatalogEntry(
                assertion_id="changed_no_crash",
                kind=AssertionKind.NO_CRASH,
                role=AssertionRole.TASK_SELECTABLE,
                catalog_key="app.process.changed",
                verifier=NoCrashVerifier(
                    bundle_identifier="com.example.Example",
                ),
            ),
        ),
        artifacts=ArtifactSettings(
            collection_paths=("artifacts/build", "artifacts/test")
        ),
        prohibited_paths=(
            ".git",
            "fastlane/metadata",
            "Example.xcworkspace/contents.xcworkspacedata",
            "Example.xcworkspace/xcshareddata/xcschemes/Example.xcscheme",
            "ExampleHarness.xcodeproj/project.pbxproj",
            "ExampleUITests",
            "Fixtures/primary.json",
            "Fixtures/primary-account.json",
        ),
        secret_references=(
            test_account,
            SecretReference.parse(
                "keychain://com.boppuh.mathews.git/example-ios-push"
            ),
        ),
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


def test_configured_git_push_credential_must_be_an_explicit_opaque_reference() -> None:
    configuration = _configuration()

    with pytest.raises(RepositoryConfigurationError, match="Git push credential"):
        replace(
            configuration,
            secret_references=(configuration.secret_references[0],),
        )
    with pytest.raises(RepositoryConfigurationError, match="distinct"):
        replace(
            configuration,
            git=replace(
                configuration.git,
                push_credential=configuration.secret_references[0],
            ),
        )


def test_legacy_configuration_without_push_credential_remains_readable() -> None:
    configuration = _configuration()
    payload = configuration.to_dict()
    git_settings = cast(dict[str, object], payload["git_settings"])
    push_reference = cast(str, git_settings.pop("push_credential"))
    payload["secret_references"] = [
        reference
        for reference in cast(list[str], payload["secret_references"])
        if reference != push_reference
    ]

    restored = RepositoryConfiguration.from_dict(
        configuration.configuration_id,
        payload,
    )

    assert restored.git.push_credential is None
    assert restored.to_dict() == payload
    assert (
        RepositoryConfiguration.from_dict(
            configuration.configuration_id,
            restored.to_dict(),
        ).digest
        == restored.digest
    )


def test_push_credential_cannot_be_explicitly_null() -> None:
    configuration = _configuration()
    payload = configuration.to_dict()
    cast(dict[str, object], payload["git_settings"])["push_credential"] = None

    with pytest.raises(RepositoryConfigurationError, match="must be text"):
        RepositoryConfiguration.from_dict(configuration.configuration_id, payload)


def test_assertion_vocabulary_is_exactly_the_frozen_five_kinds() -> None:
    assert {kind.value for kind in AssertionKind} == {
        "ELEMENT_VALUE_PRESENT",
        "NAVIGATION_STATE_REACHED",
        "EXPECTED_NETWORK_RESPONSE",
        "EXPECTED_LOG_EVENT",
        "NO_CRASH",
    }


def test_e2e_operation_is_bound_to_exactly_one_pinned_runner_test() -> None:
    configuration = _configuration()
    e2e_index = next(
        index
        for index, operation in enumerate(configuration.operations)
        if operation.kind is OperationKind.SIMULATOR_E2E
    )
    operation = configuration.operations[e2e_index]
    for extras in (
        (),
        ("-skip-testing:ExampleUITests/OtherTests/testOther",),
        (
            "-only-testing:ExampleUITests/PrimaryJourneyTests/testPrimaryJourney",
            "-only-testing:ExampleUITests/OtherTests/testOther",
        ),
    ):
        prefix = operation.argv[:8]
        with pytest.raises(RepositoryConfigurationError, match="exactly its configured"):
            replace(
                configuration,
                operations=(
                    *configuration.operations[:e2e_index],
                    replace(operation, argv=(*prefix, *extras)),
                    *configuration.operations[e2e_index + 1 :],
                ),
            )


@pytest.mark.parametrize(
    "runner_test_identifier",
    (
        "ExampleUITests",
        "ExampleUITests/PrimaryJourneyTests",
        "ExampleUITests//testPrimaryJourney",
        "/PrimaryJourneyTests/testPrimaryJourney",
        "ExampleUITests/PrimaryJourneyTests/",
        "///",
        "ExampleUITests/PrimaryJourneyTests/notATest",
    ),
)
def test_e2e_runner_identifier_names_one_canonical_test_method(
    runner_test_identifier: str,
) -> None:
    configuration = _configuration()
    flow = next(
        operation.e2e_flow
        for operation in configuration.operations
        if operation.kind is OperationKind.SIMULATOR_E2E
    )
    assert flow is not None
    with pytest.raises(RepositoryConfigurationError, match="runner test identifier"):
        replace(flow, runner_test_identifier=runner_test_identifier)


def test_e2e_rejects_test_without_building_and_mutable_operation_arguments() -> None:
    configuration = _configuration()
    operation = next(
        operation
        for operation in configuration.operations
        if operation.kind is OperationKind.SIMULATOR_E2E
    )
    with pytest.raises(RepositoryConfigurationError, match="exact candidate"):
        replace(
            operation,
            argv=("xcodebuild", "test-without-building", *operation.argv[2:]),
        )
    with pytest.raises(RepositoryConfigurationError, match="immutable tuple"):
        replace(operation, argv=list(operation.argv))  # type: ignore[arg-type]


def test_e2e_assertions_bind_to_structured_flow_semantics_and_app() -> None:
    configuration = _configuration()
    navigation_index = next(
        index
        for index, assertion in enumerate(configuration.assertion_catalog)
        if assertion.kind is AssertionKind.NAVIGATION_STATE_REACHED
    )
    navigation = configuration.assertion_catalog[navigation_index]
    with pytest.raises(RepositoryConfigurationError, match="terminal state"):
        replace(
            configuration,
            assertion_catalog=(
                *configuration.assertion_catalog[:navigation_index],
                replace(
                    navigation,
                    verifier=NavigationStateVerifier(
                        state_id="task.failed",
                        marker_accessibility_identifier="task.completed",
                    ),
                ),
                *configuration.assertion_catalog[navigation_index + 1 :],
            ),
        )

    crash_index = next(
        index
        for index, assertion in enumerate(configuration.assertion_catalog)
        if assertion.kind is AssertionKind.NO_CRASH
    )
    crash = configuration.assertion_catalog[crash_index]
    with pytest.raises(RepositoryConfigurationError, match="launched application"):
        replace(
            configuration,
            assertion_catalog=(
                *configuration.assertion_catalog[:crash_index],
                replace(
                    crash,
                    verifier=NoCrashVerifier(
                        bundle_identifier="com.example.Unrelated",
                    ),
                ),
                *configuration.assertion_catalog[crash_index + 1 :],
            ),
        )


def test_e2e_trust_files_are_content_pinned_and_prohibited_from_task_mutation() -> None:
    configuration = _configuration()
    with pytest.raises(RepositoryConfigurationError, match="dedicated harness"):
        replace(
            configuration,
            operations=tuple(
                replace(
                    operation,
                    e2e_flow=(
                        replace(
                            operation.e2e_flow,
                            harness_files=operation.e2e_flow.harness_files[1:],
                        )
                        if operation.e2e_flow is not None
                        else None
                    ),
                )
                for operation in configuration.operations
            ),
        )

    with pytest.raises(RepositoryConfigurationError, match="prohibited from task"):
        replace(
            configuration,
            prohibited_paths=tuple(
                path
                for path in configuration.prohibited_paths
                if path != "ExampleUITests"
            ),
        )


def _accepted_brief() -> AcceptedBriefAssertionSource:
    return AcceptedBriefAssertionSource.from_approval_record(
        PersistedBriefApprovalRecord(
            task_id=uuid4(),
            brief_id=uuid4(),
            decision_id=uuid4(),
            disposition=BriefApprovalDisposition.ACCEPTED,
            brief_version=3,
            brief_digest=f"sha256:{'a' * 64}",
            assertion_requirements=(
                CriterionAssertionRequirement(
                    acceptance_criterion_id="criterion.user-outcome",
                    required_assertion_ids=("changed_task_title",),
                ),
                CriterionAssertionRequirement(
                    acceptance_criterion_id="criterion.stability",
                    required_assertion_ids=("changed_terminal_state",),
                ),
            ),
        )
    )


def test_task_assertions_are_total_typed_and_bound_to_exact_brief_and_config() -> None:
    configuration = _configuration()
    brief = _accepted_brief()
    contract = TaskAssertionContract.for_configuration(
        configuration,
        accepted_brief=brief,
        assertion_selections=(
            ("criterion.user-outcome", "changed_task_title"),
            ("criterion.stability", "changed_terminal_state"),
        ),
    )

    assert contract.required_assertion_ids == (
        "task_title",
        "terminal_state",
        "network_response",
        "log_event",
        "no_crash",
    )
    assert {binding.kind for binding in contract.bindings} == {
        AssertionKind.ELEMENT_VALUE_PRESENT,
        AssertionKind.NAVIGATION_STATE_REACHED,
    }
    assert TaskAssertionContract.from_dict(
        configuration,
        brief,
        json.loads(contract.to_json()),
    ) == contract
    assert contract.digest.startswith("sha256:")
    permuted = TaskAssertionContract.for_configuration(
        configuration,
        accepted_brief=brief,
        assertion_selections=(
            ("criterion.stability", "changed_terminal_state"),
            ("criterion.user-outcome", "changed_task_title"),
        ),
    )
    assert permuted == contract
    assert permuted.digest == contract.digest
    noncanonical_payload = contract.to_dict()
    serialized_bindings = noncanonical_payload["bindings"]
    assert isinstance(serialized_bindings, list)
    noncanonical_payload["bindings"] = list(reversed(serialized_bindings))
    with pytest.raises(RepositoryConfigurationError, match="canonical"):
        TaskAssertionContract.from_dict(
            configuration,
            brief,
            noncanonical_payload,
        )

    changed_brief = AcceptedBriefAssertionSource.from_approval_record(
        PersistedBriefApprovalRecord(
            task_id=brief.task_id,
            brief_id=brief.brief_id,
            decision_id=brief.approval_decision_id,
            disposition=BriefApprovalDisposition.ACCEPTED,
            brief_version=brief.brief_version + 1,
            brief_digest=brief.brief_digest,
            assertion_requirements=brief.assertion_requirements,
        )
    )
    with pytest.raises(RepositoryConfigurationError, match="not bound"):
        contract.validate_against(configuration, changed_brief)


def test_task_assertions_reject_missing_unknown_or_agent_authored_claims() -> None:
    configuration = _configuration()
    brief = _accepted_brief()
    with pytest.raises(RepositoryConfigurationError, match="exactly match"):
        TaskAssertionContract.for_configuration(
            configuration,
            accepted_brief=brief,
            assertion_selections=(
                ("criterion.user-outcome", "changed_task_title"),
            ),
        )
    with pytest.raises(RepositoryConfigurationError, match="task-selectable"):
        TaskAssertionContract.for_configuration(
            configuration,
            accepted_brief=brief,
            assertion_selections=(
                ("criterion.user-outcome", "no_crash"),
                ("criterion.stability", "no_crash"),
            ),
        )
    with pytest.raises(RepositoryConfigurationError, match="outside"):
        TaskAssertionContract.for_configuration(
            configuration,
            accepted_brief=brief,
            assertion_selections=(
                ("criterion.user-outcome", "agent_claimed_success"),
                ("criterion.stability", "changed_terminal_state"),
            ),
        )

    contract = TaskAssertionContract.for_configuration(
        configuration,
        accepted_brief=brief,
        assertion_selections=(
            ("criterion.user-outcome", "changed_task_title"),
            ("criterion.stability", "changed_terminal_state"),
        ),
    )
    payload = contract.to_dict()
    payload["agent_claim"] = "everything passed"
    with pytest.raises(RepositoryConfigurationError, match="missing or unknown"):
        TaskAssertionContract.from_dict(configuration, brief, payload)
    with pytest.raises(RepositoryConfigurationError, match="must be compiled"):
        replace(contract)


def test_task_specific_no_crash_may_be_required_by_the_accepted_brief() -> None:
    configuration = _configuration()
    base = _accepted_brief()
    brief = AcceptedBriefAssertionSource.from_approval_record(
        PersistedBriefApprovalRecord(
            task_id=base.task_id,
            brief_id=base.brief_id,
            decision_id=base.approval_decision_id,
            disposition=BriefApprovalDisposition.ACCEPTED,
            brief_version=base.brief_version,
            brief_digest=base.brief_digest,
            assertion_requirements=(
                CriterionAssertionRequirement(
                    acceptance_criterion_id="criterion.stability",
                    required_assertion_ids=("changed_no_crash",),
                ),
            ),
        )
    )

    contract = TaskAssertionContract.for_configuration(
        configuration,
        accepted_brief=brief,
        assertion_selections=(
            ("criterion.stability", "changed_no_crash"),
        ),
    )

    assert contract.bindings[0].kind is AssertionKind.NO_CRASH


def test_new_assertion_contracts_reject_mutable_or_wrong_runtime_types() -> None:
    brief = _accepted_brief()
    with pytest.raises(RepositoryConfigurationError, match="persisted"):
        AcceptedBriefAssertionSource(
            task_id=brief.task_id,
            brief_id=brief.brief_id,
            approval_decision_id=brief.approval_decision_id,
            brief_version=brief.brief_version,
            brief_digest=brief.brief_digest,
            assertion_requirements=brief.assertion_requirements,
        )
    with pytest.raises(RepositoryConfigurationError, match="unsupported"):
        CriterionAssertionBinding(
            acceptance_criterion_id="criterion",
            assertion_id="assertion",
            kind="NO_CRASH",  # type: ignore[arg-type]
            verifier_catalog_key="app.process",
        )
    rejected = PersistedBriefApprovalRecord(
        task_id=brief.task_id,
        brief_id=brief.brief_id,
        decision_id=brief.approval_decision_id,
        disposition=BriefApprovalDisposition.REJECTED,
        brief_version=brief.brief_version,
        brief_digest=brief.brief_digest,
        assertion_requirements=brief.assertion_requirements,
    )
    with pytest.raises(RepositoryConfigurationError, match="accepted persisted"):
        AcceptedBriefAssertionSource.from_approval_record(rejected)


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
