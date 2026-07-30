"""Strictly read-only repository preflight probes.

This module deliberately exposes no generic command execution surface. The
local command probe accepts only the exact Git and Simulator inventory queries
needed by repository preflight.
"""

from __future__ import annotations

import json
import os
import re
import selectors
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from math import isfinite
from pathlib import Path
from typing import Protocol, cast
from urllib.parse import urlsplit
from uuid import UUID

from mathews_configuration import (
    MANDATORY_PROHIBITED_OPERATIONS,
    MANDATORY_PROHIBITED_PATHS,
    OperationKind,
    PreflightCheck,
    PreflightCheckCode,
    PreflightStatus,
    RepositoryConfiguration,
    RepositoryConfigurationError,
    RepositoryPreflightReport,
    SecretReference,
    SecretReferenceError,
)

_MAX_COMMAND_TIMEOUT_SECONDS = 10.0
_MAX_COMMAND_OUTPUT_BYTES = 1_000_000
_GIT_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SCHEME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}\Z")
_GIT_OBJECT_ID_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REQUIRED_OPERATION_KINDS = frozenset(
    {"build", "integration_test", "simulator_e2e", "unit_test"}
)
_PROHIBITED_OPERATION_ARGUMENTS = frozenset(
    operation.value.lower() for operation in MANDATORY_PROHIBITED_OPERATIONS
)
_READ_ONLY_COMMAND_PREFIXES = (
    ("git", "rev-parse", "--show-toplevel"),
    ("git", "rev-parse", "--verify", "--end-of-options"),
    ("git", "remote", "get-url", "--"),
    ("xcrun", "simctl", "list", "-j"),
)


class UnsafePreflightCommandError(ValueError):
    """Raised before a command outside the fixed read-only vocabulary can run."""


@dataclass(frozen=True, slots=True)
class CommandRequest:
    """A bounded, argument-vector-only read request."""

    argv: tuple[str, ...]
    cwd: Path
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if (
            not isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
            or self.timeout_seconds > _MAX_COMMAND_TIMEOUT_SECONDS
        ):
            raise ValueError(
                "preflight command timeout must be finite and between 0 and 10 seconds"
            )


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Captured process result kept inside the preflight trust boundary."""

    returncode: int
    stdout: str
    stderr: str


class CommandProbe(Protocol):
    """Injected boundary for the small fixed set of read-only host commands."""

    def run(self, request: CommandRequest) -> CommandResult:
        """Run one preflight query without invoking a shell."""


class FilesystemProbe(Protocol):
    """Injected read-only filesystem boundary used by repository preflight."""

    def resolve(self, path: Path, *, strict: bool) -> Path:
        """Resolve a path without creating or modifying it."""

    def is_dir(self, path: Path) -> bool:
        """Return whether ``path`` is an existing directory."""

    def is_file(self, path: Path) -> bool:
        """Return whether ``path`` is an existing regular file."""


class LocalFilesystemProbe:
    """Read-only implementation backed by ``pathlib``."""

    def resolve(self, path: Path, *, strict: bool) -> Path:
        return path.resolve(strict=strict)

    def is_dir(self, path: Path) -> bool:
        return path.is_dir()

    def is_file(self, path: Path) -> bool:
        return path.is_file()


class LocalCommandProbe:
    """Run only the fixed local queries permitted during preflight."""

    def run(self, request: CommandRequest) -> CommandResult:
        _validate_read_only_command(request.argv)
        environment = {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.defpath,
        }
        return _run_bounded_process(request, environment)


def _run_bounded_process(
    request: CommandRequest,
    environment: Mapping[str, str],
) -> CommandResult:
    """Read one combined output pipe incrementally with a hard byte limit."""

    process = subprocess.Popen(
        list(request.argv),
        cwd=request.cwd,
        env=environment,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        return CommandResult(returncode=125, stdout="", stderr="")

    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + request.timeout_seconds
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(request.argv, request.timeout_seconds)
            events = selector.select(remaining)
            if not events:
                raise subprocess.TimeoutExpired(request.argv, request.timeout_seconds)
            for key, _event_mask in events:
                total_size = sum(len(output) for output in outputs.values())
                allowance = _MAX_COMMAND_OUTPUT_BYTES + 1 - total_size
                chunk = os.read(key.fd, min(65_536, allowance))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                outputs[cast(str, key.data)].extend(chunk)
                if sum(len(output) for output in outputs.values()) > _MAX_COMMAND_OUTPUT_BYTES:
                    process.kill()
                    process.wait()
                    return CommandResult(returncode=125, stdout="", stderr="")
        returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()

    try:
        stdout = outputs["stdout"].decode("utf-8", errors="strict")
        stderr = outputs["stderr"].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return CommandResult(returncode=125, stdout="", stderr="")
    return CommandResult(
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


class RepositoryPreflightRunner:
    """Evaluate repository readiness using only fixed local read operations."""

    def __init__(
        self,
        *,
        commands: CommandProbe | None = None,
        filesystem: FilesystemProbe | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        if (
            not isfinite(timeout_seconds)
            or timeout_seconds <= 0
            or timeout_seconds > _MAX_COMMAND_TIMEOUT_SECONDS
        ):
            raise ValueError("preflight timeout must be finite and between 0 and 10 seconds")
        self._commands = commands or LocalCommandProbe()
        self._filesystem = filesystem or LocalFilesystemProbe()
        self._timeout_seconds = timeout_seconds

    def run(
        self,
        configuration: RepositoryConfiguration,
        *,
        attempt_id: UUID,
    ) -> RepositoryPreflightReport:
        checks: list[PreflightCheck] = []
        resolved_base_sha: str | None = None

        configuration_id = configuration.configuration_id
        configuration_version = configuration.version
        configuration_digest = configuration.digest
        try:
            round_tripped_configuration = RepositoryConfiguration.from_dict(
                configuration_id,
                configuration.to_dict(),
            )
            shape_valid = (
                round_tripped_configuration == configuration
                and isinstance(configuration_version, int)
                and not isinstance(configuration_version, bool)
                and configuration_version > 0
                and isinstance(configuration.repository_key, str)
                and bool(configuration.repository_key.strip())
                and isinstance(configuration_digest, str)
                and _DIGEST_PATTERN.fullmatch(configuration_digest) is not None
            )
        except (AttributeError, RepositoryConfigurationError, TypeError, ValueError):
            shape_valid = False
        checks.append(
            _check(
                PreflightCheckCode.CONFIGURATION,
                shape_valid,
            )
        )

        configured_root = _text_field(configuration.repository, "root")
        root: Path | None = None
        if configured_root is not None:
            candidate = Path(configured_root)
            if candidate.is_absolute():
                try:
                    resolved = self._filesystem.resolve(candidate, strict=True)
                except (OSError, RuntimeError):
                    resolved = None
                if (
                    resolved is not None
                    and resolved == candidate
                    and self._filesystem.is_dir(resolved)
                ):
                    root = resolved
        checks.append(
            _check(
                PreflightCheckCode.REPOSITORY_ROOT,
                root is not None,
            )
        )

        git_root_valid = False
        if root is not None:
            result = self._query(("git", "rev-parse", "--show-toplevel"), root)
            reported_root = _single_line(result.stdout) if result is not None else None
            if result is not None and result.returncode == 0 and reported_root is not None:
                try:
                    git_root = self._filesystem.resolve(Path(reported_root), strict=True)
                except (OSError, RuntimeError):
                    git_root = None
                git_root_valid = git_root == root
        checks.append(
            _check(
                PreflightCheckCode.GIT_TOP_LEVEL,
                git_root_valid,
            )
        )

        remote_name = _text_field(configuration.git, "remote_name")
        remote_valid = False
        if (
            root is not None
            and remote_name is not None
            and _GIT_NAME_PATTERN.fullmatch(remote_name) is not None
        ):
            result = self._query(
                ("git", "remote", "get-url", "--", remote_name),
                root,
            )
            actual_remote = _single_line(result.stdout) if result is not None else None
            actual_identity = (
                _remote_identity(actual_remote) if actual_remote is not None else None
            )
            expected_identity = f"github.com/{configuration.repository_key.removesuffix('.git')}"
            remote_valid = (
                result is not None
                and result.returncode == 0
                and actual_identity == expected_identity
            )
        checks.append(
            _check(
                PreflightCheckCode.GIT_REMOTE,
                remote_valid,
            )
        )

        base_branch = _text_field(configuration.git, "default_base_ref")
        base_ref = (
            _base_reference(base_branch, remote_name)
            if base_branch is not None and remote_name is not None
            else None
        )
        if root is not None and base_ref is not None:
            result = self._query(
                (
                    "git",
                    "rev-parse",
                    "--verify",
                    "--end-of-options",
                    f"{base_ref}^{{commit}}",
                ),
                root,
            )
            candidate_sha = _single_line(result.stdout) if result is not None else None
            if (
                result is not None
                and result.returncode == 0
                and candidate_sha is not None
                and _GIT_OBJECT_ID_PATTERN.fullmatch(candidate_sha) is not None
            ):
                resolved_base_sha = candidate_sha
        checks.append(
            _check(
                PreflightCheckCode.BASE_REVISION,
                resolved_base_sha is not None,
            )
        )

        container_path = _text_field(configuration.xcode, "container_path")
        container_kind = _enum_text(_field(configuration.xcode, "container_kind"))
        scheme = _text_field(configuration.xcode, "scheme")
        container: Path | None = None
        if root is not None and container_path is not None:
            container = self._contained_path(root, container_path, must_exist=True)
        expected_suffix = ".xcodeproj" if container_kind == "project" else ".xcworkspace"
        container_valid = (
            container is not None
            and container_kind in {"project", "workspace"}
            and container.name.endswith(expected_suffix)
            and self._filesystem.is_dir(container)
        )
        checks.append(
            _check(
                PreflightCheckCode.XCODE_CONTAINER,
                container_valid,
            )
        )

        shared_scheme_valid = False
        if (
            container_valid
            and container is not None
            and root is not None
            and scheme is not None
            and _SCHEME_PATTERN.fullmatch(scheme) is not None
        ):
            assert container is not None
            verified_container: Path = container
            try:
                shared_scheme = self._filesystem.resolve(
                    verified_container
                    / "xcshareddata"
                    / "xcschemes"
                    / f"{scheme}.xcscheme",
                    strict=True,
                )
                shared_scheme.relative_to(root)
                shared_scheme.relative_to(verified_container)
            except (OSError, RuntimeError, ValueError):
                shared_scheme = None
            shared_scheme_valid = (
                shared_scheme is not None
                and self._filesystem.is_file(shared_scheme)
            )
        checks.append(
            _check(
                PreflightCheckCode.SHARED_SCHEME,
                shared_scheme_valid,
            )
        )

        simulator = _field(configuration.xcode, "simulator")
        simulator_runtime = _text_field(simulator, "runtime_identifier")
        simulator_device = _text_field(simulator, "device_type_identifier")
        simulator_valid = False
        if root is not None and simulator_runtime is not None and simulator_device is not None:
            result = self._query(("xcrun", "simctl", "list", "-j"), root)
            if result is not None and result.returncode == 0:
                simulator_valid = _simulator_target_available(
                    result.stdout,
                    runtime=simulator_runtime,
                    device=simulator_device,
                )
        checks.append(
            _check(
                PreflightCheckCode.SIMULATOR,
                simulator_valid,
            )
        )

        operations_valid = _operations_are_safe(configuration.operations)
        checks.append(
            _check(
                PreflightCheckCode.OPERATIONS,
                operations_valid,
            )
        )

        e2e_flow = next(
            (
                _field(operation, "e2e_flow")
                for operation in configuration.operations
                if _field(operation, "kind") is OperationKind.SIMULATOR_E2E
            ),
            None,
        )
        e2e_valid = _e2e_contract_is_valid(
            e2e_flow,
            configuration.assertion_catalog,
        )
        checks.append(
            _check(
                PreflightCheckCode.E2E_FLOW,
                e2e_valid,
            )
        )

        artifact_paths = _field(configuration.artifacts, "collection_paths")
        artifacts_valid = root is not None and _paths_are_contained(
            self,
            root,
            artifact_paths,
            require_nonempty=True,
        )
        checks.append(
            _check(
                PreflightCheckCode.ARTIFACT_PATHS,
                artifacts_valid,
            )
        )

        prohibited_paths_valid = (
            root is not None
            and _mandatory_values_present(
                configuration.prohibited_paths,
                MANDATORY_PROHIBITED_PATHS,
            )
            and _paths_are_contained(
                self,
                root,
                configuration.prohibited_paths,
                require_nonempty=True,
            )
        )
        prohibited_operations_valid = _mandatory_values_present(
            configuration.repository.prohibited_operations,
            MANDATORY_PROHIBITED_OPERATIONS,
        )
        checks.append(
            _check(
                PreflightCheckCode.PROHIBITIONS,
                prohibited_paths_valid and prohibited_operations_valid,
            )
        )

        secret_references_valid = _secret_references_are_opaque(
            configuration.secret_references
        )
        checks.append(
            _check(
                PreflightCheckCode.SECRET_REFERENCES,
                secret_references_valid,
            )
        )

        passed = (
            shape_valid
            and resolved_base_sha is not None
            and all(check.status is PreflightStatus.PASSED for check in checks)
        )
        return RepositoryPreflightReport(
            attempt_id=attempt_id,
            configuration_id=configuration_id,
            configuration_version=configuration_version,
            configuration_digest=configuration_digest,
            status=PreflightStatus.PASSED if passed else PreflightStatus.BLOCKED,
            checks=tuple(checks),
            resolved_base_sha=resolved_base_sha,
        )

    def _query(self, argv: tuple[str, ...], root: Path) -> CommandResult | None:
        try:
            return self._commands.run(
                CommandRequest(
                    argv=argv,
                    cwd=root,
                    timeout_seconds=self._timeout_seconds,
                )
            )
        except (OSError, subprocess.TimeoutExpired, UnsafePreflightCommandError):
            return None

    def _contained_path(
        self,
        root: Path,
        configured_path: str,
        *,
        must_exist: bool,
    ) -> Path | None:
        relative = _safe_relative_path(configured_path)
        if relative is None:
            return None
        try:
            resolved = self._filesystem.resolve(
                root / relative,
                strict=must_exist,
            )
            resolved.relative_to(root)
        except (OSError, RuntimeError, ValueError):
            return None
        return resolved


def _validate_read_only_command(argv: tuple[str, ...]) -> None:
    if not argv or any(not argument or "\x00" in argument for argument in argv):
        raise UnsafePreflightCommandError("preflight command arguments must be non-empty")

    allowed = False
    for prefix in _READ_ONLY_COMMAND_PREFIXES:
        if argv[: len(prefix)] != prefix:
            continue
        if prefix in {
            ("git", "rev-parse", "--show-toplevel"),
            ("xcrun", "simctl", "list", "-j"),
        }:
            allowed = len(argv) == len(prefix)
        else:
            allowed = len(argv) == len(prefix) + 1
        if allowed:
            break

    if not allowed:
        raise UnsafePreflightCommandError("command is not allowed during repository preflight")


def _check(
    code: PreflightCheckCode,
    passed_condition: bool,
) -> PreflightCheck:
    return PreflightCheck.for_status(
        code=code,
        status=PreflightStatus.PASSED if passed_condition else PreflightStatus.BLOCKED,
    )


def _field(value: object, name: str) -> object | None:
    if isinstance(value, Mapping):
        return value.get(name)
    return getattr(value, name, None)


def _text_field(value: object, name: str) -> str | None:
    candidate = _field(value, name)
    if not isinstance(candidate, str):
        return None
    normalized = candidate.strip()
    if not normalized or len(normalized) > 1000 or any(
        ord(character) < 32 for character in normalized
    ):
        return None
    return normalized


def _enum_text(value: object | None) -> str | None:
    candidate = getattr(value, "value", value)
    if not isinstance(candidate, str):
        return None
    return candidate.strip().lower()


def _single_line(value: str) -> str | None:
    if not value or len(value) > 4096:
        return None
    lines = value.splitlines()
    if len(lines) != 1:
        return None
    normalized = lines[0].strip()
    if not normalized or any(ord(character) < 32 for character in normalized):
        return None
    return normalized


def _remote_identity(value: str) -> str | None:
    if not value or len(value) > 1000 or any(ord(character) < 32 for character in value):
        return None

    scp_match = (
        re.fullmatch(
            r"(?:(?P<user>[A-Za-z0-9._-]+)@)?"
            r"(?P<host>[A-Za-z0-9.-]+):(?P<path>[^?#]+)",
            value,
        )
        if "://" not in value
        else None
    )
    if scp_match is not None:
        user = scp_match.group("user")
        if user != "git":
            return None
        return _host_path_identity(
            scp_match.group("host"),
            scp_match.group("path"),
        )

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    https_transport = (
        parsed.scheme == "https"
        and parsed.username is None
        and parsed.password is None
        and port in {None, 443}
    )
    ssh_transport = (
        parsed.scheme == "ssh"
        and parsed.username == "git"
        and parsed.password is None
        and port in {None, 22}
    )
    if (
        hostname is None
        or not (https_transport or ssh_transport)
        or parsed.query
        or parsed.fragment
    ):
        return None
    return _host_path_identity(hostname, parsed.path)


def _host_path_identity(host: str, path: str) -> str | None:
    normalized_path = path.strip().strip("/")
    if normalized_path.endswith(".git"):
        normalized_path = normalized_path[:-4]
    if (
        not normalized_path
        or ".." in normalized_path.split("/")
        or any(ord(character) < 32 for character in normalized_path)
    ):
        return None
    return f"{host.lower()}/{normalized_path}"


def _base_reference(base_branch: str, remote_name: str) -> str | None:
    if (
        not _safe_git_ref_fragment(remote_name)
        or not _safe_git_ref_fragment(base_branch)
    ):
        return None
    remote_prefix = f"refs/remotes/{remote_name}/"
    if base_branch.startswith("refs/"):
        if not base_branch.startswith(remote_prefix):
            return None
        branch = base_branch.removeprefix(remote_prefix)
        if not branch or branch.startswith("refs/") or not _safe_git_ref_fragment(branch):
            return None
        return base_branch
    return f"refs/remotes/{remote_name}/{base_branch}"


def _safe_git_ref_fragment(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= 255
        and not value.startswith(("-", ".", "/"))
        and not value.endswith((".", "/", ".lock"))
        and ".." not in value
        and "@{" not in value
        and "//" not in value
        and all(
            ord(character) >= 32
            and character not in " ~^:?*[\\"
            for character in value
        )
    )


def _safe_relative_path(value: str) -> Path | None:
    if (
        not value
        or len(value) > 1000
        or "\\" in value
        or "\x00" in value
    ):
        return None
    candidate = Path(value)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        return None
    return candidate


def _simulator_target_available(payload: str, *, runtime: str, device: str) -> bool:
    if not payload or len(payload.encode("utf-8")) > _MAX_COMMAND_OUTPUT_BYTES:
        return False
    try:
        decoded = json.loads(payload)
    except json.JSONDecodeError:
        return False
    if not isinstance(decoded, dict):
        return False
    runtimes = decoded.get("runtimes")
    device_types = decoded.get("devicetypes")
    devices = decoded.get("devices")
    if (
        not isinstance(runtimes, list)
        or not isinstance(device_types, list)
        or not isinstance(devices, dict)
    ):
        return False
    runtime_identifier = next(
        (
            item.get("identifier")
            for item in runtimes
            if isinstance(item, dict)
            and item.get("isAvailable") is True
            and runtime in {item.get("identifier"), item.get("name")}
            and isinstance(item.get("identifier"), str)
        ),
        None,
    )
    device_type_identifier = next(
        (
            item.get("identifier")
            for item in device_types
            if isinstance(item, dict)
            and device in {item.get("identifier"), item.get("name")}
            and isinstance(item.get("identifier"), str)
        ),
        None,
    )
    if runtime_identifier is None or device_type_identifier is None:
        return False
    runtime_devices = devices.get(runtime_identifier)
    return isinstance(runtime_devices, list) and any(
        isinstance(item, dict)
        and item.get("isAvailable") is True
        and item.get("deviceTypeIdentifier") == device_type_identifier
        for item in runtime_devices
    )


def _operations_are_safe(operations: Sequence[object]) -> bool:
    if not isinstance(operations, Sequence) or isinstance(operations, (str, bytes)):
        return False
    kinds: set[str] = set()
    identifiers: set[str] = set()
    for operation in operations:
        identifier = _text_field(operation, "operation_id") or _text_field(operation, "id")
        kind = _enum_text(_field(operation, "kind"))
        argv = _field(operation, "argv")
        if (
            identifier is None
            or kind is None
            or identifier in identifiers
            or not isinstance(argv, Sequence)
            or isinstance(argv, (str, bytes))
            or not argv
            or any(not isinstance(argument, str) or not argument for argument in argv)
        ):
            return False
        executable = Path(str(argv[0])).name.lower()
        normalized_arguments = {
            str(argument).strip().lower().replace("-", "_") for argument in argv
        }
        if executable != "xcodebuild" or (
            normalized_arguments & _PROHIBITED_OPERATION_ARGUMENTS
        ):
            return False
        identifiers.add(identifier)
        kinds.add(kind)
    return _REQUIRED_OPERATION_KINDS <= kinds


def _e2e_contract_is_valid(flow: object, assertions: Sequence[object]) -> bool:
    flow_id = _text_field(flow, "flow_id")
    entry_point = _text_field(flow, "entry_point")
    terminal_state = _text_field(flow, "terminal_state")
    return (
        flow_id is not None
        and entry_point is not None
        and terminal_state is not None
        and isinstance(assertions, Sequence)
        and not isinstance(assertions, (str, bytes))
        and bool(assertions)
    )


def _paths_are_contained(
    runner: RepositoryPreflightRunner,
    root: Path,
    values: object,
    *,
    require_nonempty: bool,
) -> bool:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        return False
    if require_nonempty and not values:
        return False
    for value in values:
        candidate_value = getattr(value, "value", value)
        if not isinstance(candidate_value, str):
            return False
        if runner._contained_path(root, candidate_value, must_exist=False) is None:
            return False
    return True


def _mandatory_values_present(
    values: Sequence[object],
    required: frozenset[object],
) -> bool:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        return False
    normalized_values = {
        candidate
        for value in values
        if (candidate := _enum_text(value)) is not None
    }
    normalized_required = {
        candidate
        for value in required
        if (candidate := _enum_text(value)) is not None
    }
    return normalized_required <= normalized_values


def _secret_references_are_opaque(values: Sequence[object]) -> bool:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)) or not values:
        return False
    for value in values:
        if isinstance(value, SecretReference):
            continue
        if not isinstance(value, str):
            return False
        try:
            SecretReference.parse(value)
        except SecretReferenceError:
            return False
    return True
