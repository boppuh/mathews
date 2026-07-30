"""Validated, canonical repository execution configuration contracts.

The contracts in this module are deliberately data-only. They describe the
small allowlisted surface that a host may preflight and, in later tasks,
execute. They never accept shell command strings or secret values.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Self, cast
from uuid import UUID

from mathews_configuration.secrets import SecretReference

_TEXT_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,254}")
_SCHEME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,254}")
_REMOTE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_REPOSITORY_KEY_PATTERN = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,38})/[a-z0-9](?:[a-z0-9._-]{0,99})"
)
_BRANCH_TEMPLATE_PATTERN = re.compile(r"[A-Za-z0-9._/-]*\{task_id\}[A-Za-z0-9._/-]*")
_EMAIL_PATTERN = re.compile(r"[^@\s<>]+@[^@\s<>]+")
_GIT_OBJECT_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_CHECK_DETAIL_PATTERN = re.compile(r"[a-z][a-z0-9._-]{0,79}")
_MAX_TIMEOUT_SECONDS = 3_600
_MAX_OPERATION_ARGUMENTS = 32
_MAX_OPERATION_ARGUMENT_LENGTH = 1_024
_TEST_SELECTOR_PATTERN = re.compile(r"-(?:only|skip)-testing:[A-Za-z0-9_./-]{1,255}")
_EXPECTED_CLEAN_STATE_STEPS = (
    "SHUTDOWN",
    "ERASE",
    "BOOT",
    "INSTALL_CANDIDATE",
)


class RepositoryConfigurationError(ValueError):
    """Raised when repository execution configuration is unsafe or incomplete."""


class OperationKind(StrEnum):
    """The complete initial repository operation vocabulary."""

    BUILD = "BUILD"
    UNIT_TEST = "UNIT_TEST"
    INTEGRATION_TEST = "INTEGRATION_TEST"
    SIMULATOR_E2E = "SIMULATOR_E2E"


class AssertionKind(StrEnum):
    """The frozen bounded assertion vocabulary shared with task 5.1."""

    ELEMENT_VALUE_PRESENT = "ELEMENT_VALUE_PRESENT"
    NAVIGATION_STATE_REACHED = "NAVIGATION_STATE_REACHED"
    EXPECTED_NETWORK_RESPONSE = "EXPECTED_NETWORK_RESPONSE"
    EXPECTED_LOG_EVENT = "EXPECTED_LOG_EVENT"
    NO_CRASH = "NO_CRASH"


class ProhibitedOperation(StrEnum):
    """Operations that configuration may strengthen but never enable."""

    ARBITRARY_SHELL = "ARBITRARY_SHELL"
    DEPLOY = "DEPLOY"
    FORCE_PUSH = "FORCE_PUSH"
    MERGE = "MERGE"
    PRODUCTION_SIGNING = "PRODUCTION_SIGNING"
    RELEASE = "RELEASE"
    TAG = "TAG"


MANDATORY_PROHIBITED_OPERATIONS = frozenset(ProhibitedOperation)
MANDATORY_PROHIBITED_PATHS = frozenset({".git"})
# The later allowlisted executor must replace this token with the UDID selected
# from the runtime/device pair proven by the active preflight evidence.
SIMULATOR_DESTINATION_PLACEHOLDER = "MATHEWS_CONFIGURED_SIMULATOR"


class XcodeContainerKind(StrEnum):
    PROJECT = "PROJECT"
    WORKSPACE = "WORKSPACE"


class PreflightStatus(StrEnum):
    PASSED = "PASSED"
    BLOCKED = "BLOCKED"


class PreflightCheckCode(StrEnum):
    CONFIGURATION = "CONFIGURATION"
    REPOSITORY_ROOT = "REPOSITORY_ROOT"
    GIT_TOP_LEVEL = "GIT_TOP_LEVEL"
    GIT_REMOTE = "GIT_REMOTE"
    BASE_REVISION = "BASE_REVISION"
    XCODE_CONTAINER = "XCODE_CONTAINER"
    SHARED_SCHEME = "SHARED_SCHEME"
    SIMULATOR = "SIMULATOR"
    OPERATIONS = "OPERATIONS"
    E2E_FLOW = "E2E_FLOW"
    ARTIFACT_PATHS = "ARTIFACT_PATHS"
    PROHIBITIONS = "PROHIBITIONS"
    SECRET_REFERENCES = "SECRET_REFERENCES"


REQUIRED_PREFLIGHT_CHECKS = frozenset(PreflightCheckCode)
_PREFLIGHT_DETAIL_CODES = {
    (PreflightCheckCode.CONFIGURATION, PreflightStatus.PASSED): (
        "configuration.canonical"
    ),
    (PreflightCheckCode.CONFIGURATION, PreflightStatus.BLOCKED): (
        "configuration.invalid"
    ),
    (PreflightCheckCode.REPOSITORY_ROOT, PreflightStatus.PASSED): (
        "repository_root.canonical"
    ),
    (PreflightCheckCode.REPOSITORY_ROOT, PreflightStatus.BLOCKED): (
        "repository_root.invalid"
    ),
    (PreflightCheckCode.GIT_TOP_LEVEL, PreflightStatus.PASSED): (
        "git_top_level.matches"
    ),
    (PreflightCheckCode.GIT_TOP_LEVEL, PreflightStatus.BLOCKED): (
        "git_top_level.mismatch"
    ),
    (PreflightCheckCode.GIT_REMOTE, PreflightStatus.PASSED): "git_remote.matches",
    (PreflightCheckCode.GIT_REMOTE, PreflightStatus.BLOCKED): "git_remote.mismatch",
    (PreflightCheckCode.BASE_REVISION, PreflightStatus.PASSED): (
        "base_revision.resolved"
    ),
    (PreflightCheckCode.BASE_REVISION, PreflightStatus.BLOCKED): (
        "base_revision.unresolved"
    ),
    (PreflightCheckCode.XCODE_CONTAINER, PreflightStatus.PASSED): (
        "xcode_container.present"
    ),
    (PreflightCheckCode.XCODE_CONTAINER, PreflightStatus.BLOCKED): (
        "xcode_container.invalid"
    ),
    (PreflightCheckCode.SHARED_SCHEME, PreflightStatus.PASSED): (
        "shared_scheme.present"
    ),
    (PreflightCheckCode.SHARED_SCHEME, PreflightStatus.BLOCKED): (
        "shared_scheme.missing"
    ),
    (PreflightCheckCode.SIMULATOR, PreflightStatus.PASSED): "simulator.available",
    (PreflightCheckCode.SIMULATOR, PreflightStatus.BLOCKED): "simulator.unavailable",
    (PreflightCheckCode.OPERATIONS, PreflightStatus.PASSED): "operations.valid",
    (PreflightCheckCode.OPERATIONS, PreflightStatus.BLOCKED): "operations.invalid",
    (PreflightCheckCode.E2E_FLOW, PreflightStatus.PASSED): "e2e_flow.valid",
    (PreflightCheckCode.E2E_FLOW, PreflightStatus.BLOCKED): "e2e_flow.invalid",
    (PreflightCheckCode.ARTIFACT_PATHS, PreflightStatus.PASSED): (
        "artifact_paths.contained"
    ),
    (PreflightCheckCode.ARTIFACT_PATHS, PreflightStatus.BLOCKED): (
        "artifact_paths.invalid"
    ),
    (PreflightCheckCode.PROHIBITIONS, PreflightStatus.PASSED): (
        "prohibitions.complete"
    ),
    (PreflightCheckCode.PROHIBITIONS, PreflightStatus.BLOCKED): (
        "prohibitions.incomplete"
    ),
    (PreflightCheckCode.SECRET_REFERENCES, PreflightStatus.PASSED): (
        "secret_references.opaque"
    ),
    (PreflightCheckCode.SECRET_REFERENCES, PreflightStatus.BLOCKED): (
        "secret_references.invalid"
    ),
}


@dataclass(frozen=True, slots=True)
class GitIdentity:
    name: str
    email: str

    def __post_init__(self) -> None:
        _bounded_text(self.name, "Git identity name", maximum=255)
        if "\n" in self.name or "\r" in self.name:
            raise RepositoryConfigurationError("Git identity name must be one line")
        if _EMAIL_PATTERN.fullmatch(self.email) is None or len(self.email) > 255:
            raise RepositoryConfigurationError("Git identity email is invalid")

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "email": self.email}

    @classmethod
    def from_dict(cls, value: object) -> Self:
        fields = _exact_mapping(value, {"name", "email"}, "Git identity")
        return cls(
            name=_string(fields["name"], "Git identity name"),
            email=_string(fields["email"], "Git identity email"),
        )


@dataclass(frozen=True, slots=True)
class RepositorySettings:
    root: str
    prohibited_operations: tuple[ProhibitedOperation, ...] = tuple(ProhibitedOperation)

    def __post_init__(self) -> None:
        _absolute_canonical_path(self.root, "repository root")
        operations = frozenset(self.prohibited_operations)
        if len(operations) != len(self.prohibited_operations):
            raise RepositoryConfigurationError("prohibited operations must be unique")
        missing = MANDATORY_PROHIBITED_OPERATIONS - operations
        if missing:
            names = ", ".join(sorted(operation.value for operation in missing))
            raise RepositoryConfigurationError(
                f"prohibited operations cannot remove the mandatory floor: {names}"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "root": self.root,
            "prohibited_operations": sorted(
                operation.value for operation in self.prohibited_operations
            ),
        }

    @classmethod
    def from_dict(cls, value: object) -> Self:
        fields = _exact_mapping(
            value,
            {"root", "prohibited_operations"},
            "repository settings",
        )
        return cls(
            root=_string(fields["root"], "repository root"),
            prohibited_operations=tuple(
                _enum_value(item, ProhibitedOperation, "prohibited operation")
                for item in _sequence(fields["prohibited_operations"], "prohibited operations")
            ),
        )


@dataclass(frozen=True, slots=True)
class GitSettings:
    default_base_ref: str
    task_branch_template: str
    remote_name: str
    author: GitIdentity
    committer: GitIdentity

    def __post_init__(self) -> None:
        if _REMOTE_PATTERN.fullmatch(self.remote_name) is None:
            raise RepositoryConfigurationError("Git remote name is invalid")
        _base_ref(self.default_base_ref, self.remote_name)
        _branch_template(self.task_branch_template)

    def to_dict(self) -> dict[str, object]:
        return {
            "default_base_ref": self.default_base_ref,
            "task_branch_template": self.task_branch_template,
            "remote_name": self.remote_name,
            "author": self.author.to_dict(),
            "committer": self.committer.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: object) -> Self:
        fields = _exact_mapping(
            value,
            {
                "default_base_ref",
                "task_branch_template",
                "remote_name",
                "author",
                "committer",
            },
            "Git settings",
        )
        return cls(
            default_base_ref=_string(fields["default_base_ref"], "default base ref"),
            task_branch_template=_string(
                fields["task_branch_template"], "task branch template"
            ),
            remote_name=_string(fields["remote_name"], "Git remote name"),
            author=GitIdentity.from_dict(fields["author"]),
            committer=GitIdentity.from_dict(fields["committer"]),
        )


@dataclass(frozen=True, slots=True)
class SimulatorSettings:
    runtime_identifier: str
    device_type_identifier: str

    def __post_init__(self) -> None:
        _identifier(self.runtime_identifier, "simulator runtime identifier", maximum=255)
        _identifier(
            self.device_type_identifier,
            "simulator device type identifier",
            maximum=255,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "runtime_identifier": self.runtime_identifier,
            "device_type_identifier": self.device_type_identifier,
        }

    @classmethod
    def from_dict(cls, value: object) -> Self:
        fields = _exact_mapping(
            value,
            {"runtime_identifier", "device_type_identifier"},
            "simulator settings",
        )
        return cls(
            runtime_identifier=_string(
                fields["runtime_identifier"], "simulator runtime identifier"
            ),
            device_type_identifier=_string(
                fields["device_type_identifier"], "simulator device type identifier"
            ),
        )


@dataclass(frozen=True, slots=True)
class XcodeSettings:
    container_kind: XcodeContainerKind
    container_path: str
    scheme: str
    simulator: SimulatorSettings

    def __post_init__(self) -> None:
        _relative_repository_path(self.container_path, "Xcode container path")
        expected_suffix = (
            ".xcodeproj"
            if self.container_kind is XcodeContainerKind.PROJECT
            else ".xcworkspace"
        )
        if not self.container_path.endswith(expected_suffix):
            raise RepositoryConfigurationError(
                f"Xcode container path must end in {expected_suffix}"
            )
        _bounded_text(self.scheme, "Xcode scheme", maximum=255)
        if _SCHEME_PATTERN.fullmatch(self.scheme) is None:
            raise RepositoryConfigurationError(
                "Xcode scheme contains unsupported characters"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "container_kind": self.container_kind.value,
            "container_path": self.container_path,
            "scheme": self.scheme,
            "simulator": self.simulator.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: object) -> Self:
        fields = _exact_mapping(
            value,
            {"container_kind", "container_path", "scheme", "simulator"},
            "Xcode settings",
        )
        return cls(
            container_kind=_enum_value(
                fields["container_kind"], XcodeContainerKind, "Xcode container kind"
            ),
            container_path=_string(fields["container_path"], "Xcode container path"),
            scheme=_string(fields["scheme"], "Xcode scheme"),
            simulator=SimulatorSettings.from_dict(fields["simulator"]),
        )


@dataclass(frozen=True, slots=True)
class E2EFlow:
    flow_id: str
    version: int
    entry_point: str
    terminal_state: str
    fixture_id: str
    fixture_version: int
    test_account: SecretReference
    clean_state_steps: tuple[str, ...] = _EXPECTED_CLEAN_STATE_STEPS
    expected_network_signals: tuple[str, ...] = ()
    expected_log_signals: tuple[str, ...] = ()
    acceptable_warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _identifier(self.flow_id, "E2E flow id")
        _positive_integer(self.version, "E2E flow version")
        _identifier(self.entry_point, "E2E entry point", maximum=255)
        _identifier(self.terminal_state, "E2E terminal state", maximum=255)
        _identifier(self.fixture_id, "fixture id")
        _positive_integer(self.fixture_version, "fixture version")
        if self.clean_state_steps != _EXPECTED_CLEAN_STATE_STEPS:
            raise RepositoryConfigurationError(
                "E2E clean state must be SHUTDOWN, ERASE, BOOT, INSTALL_CANDIDATE"
            )
        _unique_identifiers(self.expected_network_signals, "expected network signals")
        _unique_identifiers(self.expected_log_signals, "expected log signals")
        _unique_identifiers(self.acceptable_warnings, "acceptable warnings")
        if not self.expected_network_signals or not self.expected_log_signals:
            raise RepositoryConfigurationError(
                "E2E flow must define expected network and log signals"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "flow_id": self.flow_id,
            "version": self.version,
            "entry_point": self.entry_point,
            "terminal_state": self.terminal_state,
            "fixture_id": self.fixture_id,
            "fixture_version": self.fixture_version,
            "test_account": self.test_account.uri,
            "clean_state_steps": list(self.clean_state_steps),
            "expected_network_signals": list(self.expected_network_signals),
            "expected_log_signals": list(self.expected_log_signals),
            "acceptable_warnings": list(self.acceptable_warnings),
        }

    @classmethod
    def from_dict(cls, value: object) -> Self:
        fields = _exact_mapping(
            value,
            {
                "flow_id",
                "version",
                "entry_point",
                "terminal_state",
                "fixture_id",
                "fixture_version",
                "test_account",
                "clean_state_steps",
                "expected_network_signals",
                "expected_log_signals",
                "acceptable_warnings",
            },
            "E2E flow",
        )
        return cls(
            flow_id=_string(fields["flow_id"], "E2E flow id"),
            version=_integer(fields["version"], "E2E flow version"),
            entry_point=_string(fields["entry_point"], "E2E entry point"),
            terminal_state=_string(fields["terminal_state"], "E2E terminal state"),
            fixture_id=_string(fields["fixture_id"], "fixture id"),
            fixture_version=_integer(fields["fixture_version"], "fixture version"),
            test_account=SecretReference.parse(
                _string(fields["test_account"], "test account secret reference")
            ),
            clean_state_steps=_string_tuple(
                fields["clean_state_steps"], "clean state steps"
            ),
            expected_network_signals=_string_tuple(
                fields["expected_network_signals"], "expected network signals"
            ),
            expected_log_signals=_string_tuple(
                fields["expected_log_signals"], "expected log signals"
            ),
            acceptable_warnings=_string_tuple(
                fields["acceptable_warnings"], "acceptable warnings"
            ),
        )


@dataclass(frozen=True, slots=True)
class TestOperation:
    operation_id: str
    kind: OperationKind
    argv: tuple[str, ...]
    timeout_seconds: int
    e2e_flow: E2EFlow | None = None

    def __post_init__(self) -> None:
        _identifier(self.operation_id, "operation id")
        _positive_integer(self.timeout_seconds, "operation timeout")
        if self.timeout_seconds > _MAX_TIMEOUT_SECONDS:
            raise RepositoryConfigurationError(
                f"operation timeout must not exceed {_MAX_TIMEOUT_SECONDS} seconds"
            )
        if not self.argv or self.argv[0] != "xcodebuild":
            raise RepositoryConfigurationError(
                "configured operations must invoke xcodebuild directly"
            )
        if len(self.argv) > _MAX_OPERATION_ARGUMENTS:
            raise RepositoryConfigurationError(
                f"operation argv must not exceed {_MAX_OPERATION_ARGUMENTS} arguments"
            )
        for argument in self.argv:
            if (
                not argument
                or len(argument) > _MAX_OPERATION_ARGUMENT_LENGTH
                or "\x00" in argument
                or "\n" in argument
                or "\r" in argument
                or "=" in argument
                or argument.startswith(("/", "~"))
                or ".." in PurePosixPath(argument).parts
                or "\\" in argument
            ):
                raise RepositoryConfigurationError(
                    "operation arguments must be bounded, relative, and non-overriding"
                )
        lowered = {argument.lower() for argument in self.argv}
        prohibited_arguments = {
            "archive",
            "-exportarchive",
            "-exportnotarizedapp",
            "-allowprovisioningupdates",
        }
        if lowered & prohibited_arguments:
            raise RepositoryConfigurationError(
                "configured operations may not archive, export, or provision"
            )
        if self.kind is OperationKind.BUILD and (
            len(self.argv) < 2 or self.argv[1].lower() != "build"
        ):
            raise RepositoryConfigurationError("BUILD operation must use the build action")
        if self.kind is not OperationKind.BUILD and (
            len(self.argv) < 2
            or self.argv[1].lower() not in {"test", "test-without-building"}
        ):
            raise RepositoryConfigurationError(
                f"{self.kind.value} operation must use an Xcode test action"
            )
        if (self.kind is OperationKind.SIMULATOR_E2E) != (self.e2e_flow is not None):
            raise RepositoryConfigurationError(
                "exactly the SIMULATOR_E2E operation must contain the E2E flow"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "kind": self.kind.value,
            "argv": list(self.argv),
            "timeout_seconds": self.timeout_seconds,
            "e2e_flow": None if self.e2e_flow is None else self.e2e_flow.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: object) -> Self:
        fields = _exact_mapping(
            value,
            {"operation_id", "kind", "argv", "timeout_seconds", "e2e_flow"},
            "test operation",
        )
        flow = fields["e2e_flow"]
        return cls(
            operation_id=_string(fields["operation_id"], "operation id"),
            kind=_enum_value(fields["kind"], OperationKind, "operation kind"),
            argv=_string_tuple(fields["argv"], "operation arguments"),
            timeout_seconds=_integer(fields["timeout_seconds"], "operation timeout"),
            e2e_flow=None if flow is None else E2EFlow.from_dict(flow),
        )


@dataclass(frozen=True, slots=True)
class AssertionCatalogEntry:
    assertion_id: str
    kind: AssertionKind
    catalog_key: str

    def __post_init__(self) -> None:
        _identifier(self.assertion_id, "assertion id")
        _identifier(self.catalog_key, "assertion catalog key", maximum=255)

    def to_dict(self) -> dict[str, object]:
        return {
            "assertion_id": self.assertion_id,
            "kind": self.kind.value,
            "catalog_key": self.catalog_key,
        }

    @classmethod
    def from_dict(cls, value: object) -> Self:
        fields = _exact_mapping(
            value,
            {"assertion_id", "kind", "catalog_key"},
            "assertion catalog entry",
        )
        return cls(
            assertion_id=_string(fields["assertion_id"], "assertion id"),
            kind=_enum_value(fields["kind"], AssertionKind, "assertion kind"),
            catalog_key=_string(fields["catalog_key"], "assertion catalog key"),
        )


@dataclass(frozen=True, slots=True)
class ArtifactSettings:
    collection_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.collection_paths:
            raise RepositoryConfigurationError("artifact collection paths must not be empty")
        for path in self.collection_paths:
            _relative_repository_path(path, "artifact collection path")
        if len(set(self.collection_paths)) != len(self.collection_paths):
            raise RepositoryConfigurationError("artifact collection paths must be unique")

    def to_dict(self) -> dict[str, object]:
        return {"collection_paths": list(self.collection_paths)}

    @classmethod
    def from_dict(cls, value: object) -> Self:
        fields = _exact_mapping(value, {"collection_paths"}, "artifact settings")
        return cls(
            collection_paths=_string_tuple(
                fields["collection_paths"], "artifact collection paths"
            )
        )


@dataclass(frozen=True, slots=True)
class RepositoryConfiguration:
    """One immutable, versioned, execution-safe repository configuration."""

    configuration_id: UUID
    repository_key: str
    version: int
    repository: RepositorySettings
    git: GitSettings
    xcode: XcodeSettings
    operations: tuple[TestOperation, ...]
    assertion_catalog: tuple[AssertionCatalogEntry, ...]
    artifacts: ArtifactSettings
    prohibited_paths: tuple[str, ...]
    secret_references: tuple[SecretReference, ...]

    def __post_init__(self) -> None:
        _repository_key(self.repository_key)
        _positive_integer(self.version, "configuration version")
        kinds = [operation.kind for operation in self.operations]
        if len(self.operations) != len(OperationKind) or set(kinds) != set(OperationKind):
            raise RepositoryConfigurationError(
                "configuration must define exactly one BUILD, UNIT_TEST, "
                "INTEGRATION_TEST, and SIMULATOR_E2E operation"
            )
        operation_ids = [operation.operation_id for operation in self.operations]
        if len(set(operation_ids)) != len(operation_ids):
            raise RepositoryConfigurationError("operation ids must be unique")
        e2e_operations = [
            operation
            for operation in self.operations
            if operation.kind is OperationKind.SIMULATOR_E2E
        ]
        if len(e2e_operations) != 1 or e2e_operations[0].e2e_flow is None:
            raise RepositoryConfigurationError(
                "configuration must contain exactly one deterministic E2E flow"
            )
        if not self.assertion_catalog:
            raise RepositoryConfigurationError("assertion catalog must not be empty")
        assertion_ids = [entry.assertion_id for entry in self.assertion_catalog]
        catalog_keys = [entry.catalog_key for entry in self.assertion_catalog]
        if len(set(assertion_ids)) != len(assertion_ids):
            raise RepositoryConfigurationError("assertion ids must be unique")
        if len(set(catalog_keys)) != len(catalog_keys):
            raise RepositoryConfigurationError("assertion catalog keys must be unique")
        for path in self.prohibited_paths:
            _relative_repository_path(path, "prohibited path")
        if len(set(self.prohibited_paths)) != len(self.prohibited_paths):
            raise RepositoryConfigurationError("prohibited paths must be unique")
        missing_paths = MANDATORY_PROHIBITED_PATHS - set(self.prohibited_paths)
        if missing_paths:
            raise RepositoryConfigurationError(
                "prohibited paths cannot remove the mandatory .git floor"
            )
        self._validate_operation_bindings()
        self._validate_path_boundaries()
        reference_uris = [reference.uri for reference in self.secret_references]
        if len(set(reference_uris)) != len(reference_uris):
            raise RepositoryConfigurationError("secret references must be unique")
        flow = e2e_operations[0].e2e_flow
        assert flow is not None
        if flow.test_account.uri not in reference_uris:
            raise RepositoryConfigurationError(
                "E2E test account must be listed in opaque secret references"
            )

    def _validate_operation_bindings(self) -> None:
        container_flag = (
            "-project"
            if self.xcode.container_kind is XcodeContainerKind.PROJECT
            else "-workspace"
        )
        for operation in self.operations:
            prefix = (
                "xcodebuild",
                operation.argv[1],
                container_flag,
                self.xcode.container_path,
                "-scheme",
                self.xcode.scheme,
                "-destination",
                SIMULATOR_DESTINATION_PLACEHOLDER,
            )
            if operation.argv[: len(prefix)] != prefix:
                raise RepositoryConfigurationError(
                    "operation argv must be bound to the configured Xcode container and scheme"
                )
            extras = operation.argv[len(prefix) :]
            if len(set(extras)) != len(extras) or any(
                extra != "-quiet" and _TEST_SELECTOR_PATTERN.fullmatch(extra) is None
                for extra in extras
            ):
                raise RepositoryConfigurationError(
                    "operation argv contains an unsupported Xcode flag or override"
                )

    def _validate_path_boundaries(self) -> None:
        prohibited = tuple(PurePosixPath(path) for path in self.prohibited_paths)
        if any(
            denied == artifact
            or denied in artifact.parents
            or artifact in denied.parents
            for artifact in (
                PurePosixPath(path) for path in self.artifacts.collection_paths
            )
            for denied in prohibited
        ) or any(
            denied == PurePosixPath(self.xcode.container_path)
            or denied in PurePosixPath(self.xcode.container_path).parents
            for denied in prohibited
        ):
            raise RepositoryConfigurationError(
                "Xcode and artifact paths must not overlap prohibited paths"
            )

    def to_dict(self) -> dict[str, object]:
        """Return exactly the eight JSON columns plus key/version for hashing."""

        return {
            "repository_key": self.repository_key,
            "version": self.version,
            "repository_settings": self.repository.to_dict(),
            "git_settings": self.git.to_dict(),
            "xcode_settings": self.xcode.to_dict(),
            "operations": [operation.to_dict() for operation in self.operations],
            "e2e_assertions": [
                assertion.to_dict() for assertion in self.assertion_catalog
            ],
            "artifact_settings": self.artifacts.to_dict(),
            "prohibited_paths": list(self.prohibited_paths),
            "secret_references": [
                reference.uri for reference in self.secret_references
            ],
        }

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    @property
    def digest(self) -> str:
        return f"sha256:{hashlib.sha256(self.to_json().encode()).hexdigest()}"

    @classmethod
    def from_dict(cls, configuration_id: UUID, value: object) -> Self:
        fields = _exact_mapping(
            value,
            {
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
            },
            "repository configuration",
        )
        return cls(
            configuration_id=configuration_id,
            repository_key=_string(fields["repository_key"], "repository key"),
            version=_integer(fields["version"], "configuration version"),
            repository=RepositorySettings.from_dict(fields["repository_settings"]),
            git=GitSettings.from_dict(fields["git_settings"]),
            xcode=XcodeSettings.from_dict(fields["xcode_settings"]),
            operations=tuple(
                TestOperation.from_dict(operation)
                for operation in _sequence(fields["operations"], "operations")
            ),
            assertion_catalog=tuple(
                AssertionCatalogEntry.from_dict(assertion)
                for assertion in _sequence(
                    fields["e2e_assertions"], "E2E assertion catalog"
                )
            ),
            artifacts=ArtifactSettings.from_dict(fields["artifact_settings"]),
            prohibited_paths=_string_tuple(fields["prohibited_paths"], "prohibited paths"),
            secret_references=tuple(
                SecretReference.parse(
                    _string(reference, "opaque secret reference")
                )
                for reference in _sequence(
                    fields["secret_references"], "secret references"
                )
            ),
        )


@dataclass(frozen=True, slots=True)
class PreflightCheck:
    code: PreflightCheckCode
    status: PreflightStatus
    detail_code: str

    def __post_init__(self) -> None:
        if (
            _CHECK_DETAIL_PATTERN.fullmatch(self.detail_code) is None
            or self.detail_code != _PREFLIGHT_DETAIL_CODES[(self.code, self.status)]
        ):
            raise RepositoryConfigurationError(
                "preflight check detail must match its code and status"
            )

    @classmethod
    def for_status(
        cls,
        code: PreflightCheckCode,
        status: PreflightStatus,
    ) -> Self:
        return cls(
            code=code,
            status=status,
            detail_code=_PREFLIGHT_DETAIL_CODES[(code, status)],
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code.value,
            "status": self.status.value,
            "detail_code": self.detail_code,
        }

    @classmethod
    def from_dict(cls, value: object) -> Self:
        fields = _exact_mapping(
            value,
            {"code", "status", "detail_code"},
            "preflight check",
        )
        return cls(
            code=_enum_value(fields["code"], PreflightCheckCode, "preflight check code"),
            status=_enum_value(fields["status"], PreflightStatus, "preflight check status"),
            detail_code=_string(fields["detail_code"], "preflight check detail"),
        )


@dataclass(frozen=True, slots=True)
class RepositoryPreflightReport:
    attempt_id: UUID
    configuration_id: UUID
    configuration_version: int
    configuration_digest: str
    status: PreflightStatus
    checks: tuple[PreflightCheck, ...]
    resolved_base_sha: str | None

    def __post_init__(self) -> None:
        _positive_integer(self.configuration_version, "configuration version")
        if _DIGEST_PATTERN.fullmatch(self.configuration_digest) is None:
            raise RepositoryConfigurationError(
                "configuration digest must be a canonical SHA-256 address"
            )
        codes = [check.code for check in self.checks]
        if len(codes) != len(set(codes)) or set(codes) != REQUIRED_PREFLIGHT_CHECKS:
            raise RepositoryConfigurationError(
                "preflight report must contain every check exactly once"
            )
        all_passed = all(check.status is PreflightStatus.PASSED for check in self.checks)
        if self.status is PreflightStatus.PASSED:
            if not all_passed:
                raise RepositoryConfigurationError(
                    "PASSED preflight requires every check to pass"
                )
            if self.resolved_base_sha is None or (
                _GIT_OBJECT_PATTERN.fullmatch(self.resolved_base_sha) is None
            ):
                raise RepositoryConfigurationError(
                    "PASSED preflight requires an exact lowercase Git object id"
                )
        else:
            if all_passed:
                raise RepositoryConfigurationError(
                    "BLOCKED preflight requires at least one blocked check"
                )
            if self.resolved_base_sha is not None and (
                _GIT_OBJECT_PATTERN.fullmatch(self.resolved_base_sha) is None
            ):
                raise RepositoryConfigurationError(
                    "resolved base SHA must be null or an exact lowercase Git object id"
                )

    @property
    def ready(self) -> bool:
        return self.status is PreflightStatus.PASSED

    def to_dict(self) -> dict[str, object]:
        return {
            "attempt_id": str(self.attempt_id),
            "configuration_id": str(self.configuration_id),
            "configuration_version": self.configuration_version,
            "configuration_digest": self.configuration_digest,
            "status": self.status.value,
            "checks": [check.to_dict() for check in self.checks],
            "resolved_base_sha": self.resolved_base_sha,
        }

    @classmethod
    def from_dict(cls, value: object) -> Self:
        fields = _exact_mapping(
            value,
            {
                "attempt_id",
                "configuration_id",
                "configuration_version",
                "configuration_digest",
                "status",
                "checks",
                "resolved_base_sha",
            },
            "preflight report",
        )
        raw_configuration_id = _string(fields["configuration_id"], "configuration id")
        raw_attempt_id = _string(fields["attempt_id"], "preflight attempt id")
        try:
            configuration_id = UUID(raw_configuration_id)
            attempt_id = UUID(raw_attempt_id)
        except ValueError:
            raise RepositoryConfigurationError(
                "preflight attempt and configuration ids must be UUIDs"
            ) from None
        raw_sha = fields["resolved_base_sha"]
        return cls(
            attempt_id=attempt_id,
            configuration_id=configuration_id,
            configuration_version=_integer(
                fields["configuration_version"], "configuration version"
            ),
            configuration_digest=_string(
                fields["configuration_digest"], "configuration digest"
            ),
            status=_enum_value(fields["status"], PreflightStatus, "preflight status"),
            checks=tuple(
                PreflightCheck.from_dict(check)
                for check in _sequence(fields["checks"], "preflight checks")
            ),
            resolved_base_sha=(
                None if raw_sha is None else _string(raw_sha, "resolved base SHA")
            ),
        )


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        raise RepositoryConfigurationError(
            "configuration must contain canonical JSON values"
        ) from None


def _exact_mapping(value: object, keys: set[str], field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise RepositoryConfigurationError(f"{field} must be an object")
    normalized = cast(Mapping[str, object], value)
    if set(normalized) != keys:
        raise RepositoryConfigurationError(f"{field} has missing or unknown fields")
    return normalized


def _sequence(value: object, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise RepositoryConfigurationError(f"{field} must be an array")
    return value


def _string(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise RepositoryConfigurationError(f"{field} must be text")
    return value


def _integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RepositoryConfigurationError(f"{field} must be an integer")
    return value


def _enum_value[T: StrEnum](value: object, enum_type: type[T], field: str) -> T:
    if not isinstance(value, str):
        raise RepositoryConfigurationError(f"{field} must be text")
    try:
        return enum_type(value)
    except ValueError:
        raise RepositoryConfigurationError(f"{field} is unsupported") from None


def _string_tuple(value: object, field: str) -> tuple[str, ...]:
    return tuple(_string(item, field) for item in _sequence(value, field))


def _positive_integer(value: int, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RepositoryConfigurationError(f"{field} must be a positive integer")


def _bounded_text(value: str, field: str, *, maximum: int) -> None:
    if not value or value != value.strip() or len(value) > maximum or "\x00" in value:
        raise RepositoryConfigurationError(
            f"{field} must be non-empty, normalized, and at most {maximum} characters"
        )


def _identifier(value: str, field: str, *, maximum: int = 128) -> None:
    _bounded_text(value, field, maximum=maximum)
    if len(value) > maximum or _TEXT_PATTERN.fullmatch(value) is None:
        raise RepositoryConfigurationError(f"{field} contains unsupported characters")


def _unique_identifiers(values: tuple[str, ...], field: str) -> None:
    for value in values:
        _identifier(value, field, maximum=255)
    if len(set(values)) != len(values):
        raise RepositoryConfigurationError(f"{field} must be unique")


def _repository_key(value: str) -> None:
    _bounded_text(value, "repository key", maximum=500)
    if (
        _REPOSITORY_KEY_PATTERN.fullmatch(value) is None
        or value.endswith(".git")
    ):
        raise RepositoryConfigurationError(
            "repository key must use canonical lowercase owner/repository form"
        )


def _absolute_canonical_path(value: str, field: str) -> None:
    _bounded_text(value, field, maximum=1024)
    path = PurePosixPath(value)
    if not path.is_absolute() or str(path) != value or value == "/":
        raise RepositoryConfigurationError(
            f"{field} must be a canonical absolute non-root POSIX path"
        )


def _relative_repository_path(value: str, field: str) -> None:
    _bounded_text(value, field, maximum=1024)
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or value in {".", ".."} or ".." in path.parts:
        raise RepositoryConfigurationError(
            f"{field} must be a canonical repository-relative path"
        )


def _git_ref(value: str, field: str) -> None:
    _bounded_text(value, field, maximum=255)
    unsafe = ("..", "@{", "\\", " ", "~", "^", ":", "?", "*", "[")
    if value.startswith(("-", ".")) or value.endswith(("/", ".", ".lock")) or any(
        marker in value for marker in unsafe
    ):
        raise RepositoryConfigurationError(f"{field} is not a safe Git ref")


def _base_ref(value: str, remote_name: str) -> None:
    _git_ref(value, "default base ref")
    remote_prefix = f"refs/remotes/{remote_name}/"
    if value.startswith("refs/") and not value.startswith(remote_prefix):
        raise RepositoryConfigurationError(
            "default base ref must name the configured remote-tracking branch"
        )
    branch = value.removeprefix(remote_prefix)
    if not branch or branch.startswith("refs/"):
        raise RepositoryConfigurationError(
            "default base ref must name the configured remote-tracking branch"
        )
    _git_ref(branch, "default base branch")


def _branch_template(value: str) -> None:
    _bounded_text(value, "task branch template", maximum=255)
    if (
        _BRANCH_TEMPLATE_PATTERN.fullmatch(value) is None
        or value.count("{task_id}") != 1
        or "//" in value
        or ".." in value
        or "@{" in value
        or value.startswith(("-", "/", "."))
        or value.endswith(("/", ".", ".lock"))
    ):
        raise RepositoryConfigurationError(
            "task branch template must contain one safe {task_id} placeholder"
        )
