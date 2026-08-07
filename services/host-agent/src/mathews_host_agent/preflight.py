"""Strictly read-only repository preflight probes.

This module deliberately exposes no generic command execution surface. The
local command probe accepts only the exact Git and Simulator inventory queries
needed by repository preflight.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import subprocess
import time
import xml.etree.ElementTree as ET
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
    AssertionCatalogEntry,
    AssertionKind,
    E2EFlow,
    ElementValueVerifier,
    LogEventVerifier,
    NavigationStateVerifier,
    NetworkResponseVerifier,
    NoCrashVerifier,
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
_MAX_PINNED_FILE_BYTES = 10_000_000
_MAX_MANIFEST_BYTES = 100_000
_MAX_FIXTURE_VALUES = 256
_GIT_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_FIXTURE_KEY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,254}\Z")
_SCHEME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}\Z")
_GIT_OBJECT_ID_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PBX_OBJECT_ID_PATTERN = re.compile(r"[A-F0-9]{24}\Z")
_BUNDLE_IDENTIFIER_PATTERN = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+\Z"
)
_VERSION_PATTERN = re.compile(r"[0-9]+(?:\.[0-9]+){0,2}\Z")
_DEVELOPMENT_TEAM_PATTERN = re.compile(r"[A-Z0-9]{10}\Z")
_TARGET_BUILD_SETTING_KEYS = frozenset(
    {
        "CLANG_ENABLE_MODULES",
        "CODE_SIGN_STYLE",
        "CURRENT_PROJECT_VERSION",
        "DEVELOPMENT_TEAM",
        "GENERATE_INFOPLIST_FILE",
        "IPHONEOS_DEPLOYMENT_TARGET",
        "MARKETING_VERSION",
        "PRODUCT_BUNDLE_IDENTIFIER",
        "PRODUCT_NAME",
        "SDKROOT",
        "SUPPORTED_PLATFORMS",
        "SWIFT_EMIT_LOC_STRINGS",
        "SWIFT_VERSION",
        "TARGETED_DEVICE_FAMILY",
        "TEST_TARGET_NAME",
    }
)
_REQUIRED_OPERATION_KINDS = frozenset(
    {"build", "integration_test", "simulator_e2e", "unit_test"}
)
_PROHIBITED_OPERATION_ARGUMENTS = frozenset(
    operation.value.lower() for operation in MANDATORY_PROHIBITED_OPERATIONS
)
_READ_ONLY_COMMAND_PREFIXES = (
    ("git", "rev-parse", "--show-toplevel"),
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

    def is_symlink(self, path: Path) -> bool:
        """Return whether ``path`` itself is a symbolic link."""

    def read_bounded(self, path: Path, *, maximum_bytes: int) -> bytes | None:
        """Read at most ``maximum_bytes`` without modifying the file."""

    def list_files_bounded(
        self,
        path: Path,
        *,
        maximum_files: int,
    ) -> tuple[Path, ...] | None:
        """List a small regular-file tree without following symlinks."""


class LocalFilesystemProbe:
    """Read-only implementation backed by ``pathlib``."""

    def resolve(self, path: Path, *, strict: bool) -> Path:
        return path.resolve(strict=strict)

    def is_dir(self, path: Path) -> bool:
        return path.is_dir()

    def is_file(self, path: Path) -> bool:
        return path.is_file()

    def is_symlink(self, path: Path) -> bool:
        return path.is_symlink()

    def read_bounded(self, path: Path, *, maximum_bytes: int) -> bytes | None:
        try:
            with path.open("rb") as source:
                content = source.read(maximum_bytes + 1)
        except OSError:
            return None
        return content if len(content) <= maximum_bytes else None

    def list_files_bounded(
        self,
        path: Path,
        *,
        maximum_files: int,
    ) -> tuple[Path, ...] | None:
        files: list[Path] = []
        try:
            for candidate in path.rglob("*", recurse_symlinks=False):
                if candidate.is_symlink():
                    return None
                if candidate.is_file():
                    files.append(candidate.resolve(strict=True))
                    if len(files) > maximum_files:
                        return None
                elif not candidate.is_dir():
                    return None
        except OSError:
            return None
        return tuple(sorted(files))


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
            self,
            root,
            resolved_base_sha,
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

    if argv[:4] == ("git", "rev-parse", "--verify", "--end-of-options"):
        if len(argv) == 5:
            revision_spec = argv[4]
            if ":" in revision_spec:
                revision, path = revision_spec.split(":", 1)
                if (
                    _GIT_OBJECT_ID_PATTERN.fullmatch(revision) is not None
                    and _safe_relative_path(path) is not None
                ):
                    return
            elif revision_spec.endswith("^{commit}"):
                revision = revision_spec.removesuffix("^{commit}")
                if revision.startswith("refs/remotes/") and _safe_git_ref_fragment(
                    revision
                ):
                    return
    if argv[:4] == ("git", "hash-object", "--no-filters", "--"):
        if len(argv) == 5 and _safe_relative_path(argv[4]) is not None:
            return
    if argv[:3] == (
        "git",
        "ls-tree",
        "--format=%(objectmode) %(objecttype) %(objectname)",
    ):
        if (
            len(argv) == 6
            and _GIT_OBJECT_ID_PATTERN.fullmatch(argv[3]) is not None
            and argv[4] == "--"
            and _safe_relative_path(argv[5]) is not None
        ):
            return
    if argv[:4] == ("git", "ls-tree", "-r", "--name-only"):
        if (
            len(argv) == 7
            and _GIT_OBJECT_ID_PATTERN.fullmatch(argv[4]) is not None
            and argv[5] == "--"
            and _safe_relative_path(argv[6]) is not None
        ):
            return

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
    if (
        hostname is None
        or not https_transport
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
        if kind == OperationKind.SIMULATOR_E2E.value.lower():
            flow = _field(operation, "e2e_flow")
            runner_test_identifier = _text_field(flow, "runner_test_identifier")
            if (
                len(argv) < 2
                or argv[1] != "test"
                or runner_test_identifier is None
                or tuple(
                    argument
                    for argument in argv
                    if isinstance(argument, str)
                    and argument.startswith(("-only-testing:", "-skip-testing:"))
                )
                != (f"-only-testing:{runner_test_identifier}",)
            ):
                return False
        identifiers.add(identifier)
        kinds.add(kind)
    return _REQUIRED_OPERATION_KINDS <= kinds


def _e2e_contract_is_valid(
    runner: RepositoryPreflightRunner,
    root: Path | None,
    resolved_base_sha: str | None,
    flow: object,
    assertions: Sequence[object],
) -> bool:
    if (
        root is None
        or resolved_base_sha is None
        or _GIT_OBJECT_ID_PATTERN.fullmatch(resolved_base_sha) is None
        or not isinstance(flow, E2EFlow)
        or not isinstance(assertions, tuple)
        or not assertions
        or any(not isinstance(assertion, AssertionCatalogEntry) for assertion in assertions)
    ):
        return False
    try:
        if E2EFlow.from_dict(flow.to_dict()) != flow or tuple(
            AssertionCatalogEntry.from_dict(assertion.to_dict())
            for assertion in assertions
        ) != assertions:
            return False
    except (AttributeError, RepositoryConfigurationError, TypeError, ValueError):
        return False

    assertions_by_id = {
        assertion.assertion_id: assertion for assertion in assertions
    }
    try:
        required = tuple(
            assertions_by_id[assertion_id]
            for assertion_id in flow.required_assertion_ids
        )
    except KeyError:
        return False
    if {assertion.kind for assertion in required} != set(AssertionKind):
        return False
    network_signals = {
        assertion.verifier.endpoint_class
        for assertion in required
        if isinstance(assertion.verifier, NetworkResponseVerifier)
    }
    log_signals = {
        assertion.verifier.event_key
        for assertion in required
        if isinstance(assertion.verifier, LogEventVerifier)
    }
    navigation_states = {
        assertion.verifier.state_id
        for assertion in required
        if isinstance(assertion.verifier, NavigationStateVerifier)
    }
    crash_bundles = {
        assertion.verifier.bundle_identifier
        for assertion in required
        if isinstance(assertion.verifier, NoCrashVerifier)
    }
    if (
        network_signals != set(flow.expected_network_signals)
        or log_signals != set(flow.expected_log_signals)
        or flow.terminal_state not in navigation_states
        or crash_bundles != {flow.app_bundle_identifier}
        or any(
            isinstance(assertion.verifier, NoCrashVerifier)
            and assertion.verifier.bundle_identifier
            != flow.app_bundle_identifier
            for assertion in assertions
        )
    ):
        return False

    pinned_contents: dict[str, bytes] = {}
    for pinned in (
        *flow.harness_files,
        flow.fixture_file,
        flow.test_account_recipe_file,
    ):
        configured_path = root / pinned.path
        path = runner._contained_path(root, pinned.path, must_exist=True)
        if (
            path is None
            or runner._filesystem.is_symlink(configured_path)
            or not runner._filesystem.is_file(path)
        ):
            return False
        content = runner._filesystem.read_bounded(
            path,
            maximum_bytes=_MAX_PINNED_FILE_BYTES,
        )
        if (
            content is None
            or f"sha256:{hashlib.sha256(content).hexdigest()}" != pinned.digest
        ):
            return False
        pinned_contents[pinned.path] = content
        base_entry = runner._query(
            (
                "git",
                "ls-tree",
                "--format=%(objectmode) %(objecttype) %(objectname)",
                resolved_base_sha,
                "--",
                pinned.path,
            ),
            root,
        )
        working_object = runner._query(
            (
                "git",
                "hash-object",
                "--no-filters",
                "--",
                pinned.path,
            ),
            root,
        )
        base_entry_line = (
            _single_line(base_entry.stdout) if base_entry is not None else None
        )
        base_entry_fields = (
            base_entry_line.split(" ") if base_entry_line is not None else []
        )
        base_object_id = (
            base_entry_fields[2] if len(base_entry_fields) == 3 else None
        )
        working_object_id = (
            _single_line(working_object.stdout)
            if working_object is not None
            else None
        )
        if (
            base_entry is None
            or base_entry.returncode != 0
            or base_entry_fields[:2] != ["100644", "blob"]
            or working_object is None
            or working_object.returncode != 0
            or base_object_id is None
            or working_object_id is None
            or _GIT_OBJECT_ID_PATTERN.fullmatch(base_object_id) is None
            or _GIT_OBJECT_ID_PATTERN.fullmatch(working_object_id) is None
            or base_object_id != working_object_id
        ):
            return False
    if not _xcode_harness_source_closure_is_valid(pinned_contents, flow):
        return False
    if not _fixture_manifest_is_valid(
        pinned_contents.get(flow.fixture_file.path),
        flow,
        assertions,
    ) or not _account_recipe_is_valid(
        pinned_contents.get(flow.test_account_recipe_file.path),
        flow,
    ):
        return False

    harness_root = runner._contained_path(
        root,
        flow.harness_source_root,
        must_exist=True,
    )
    if harness_root is None or not runner._filesystem.is_dir(harness_root):
        return False
    actual_harness_files = runner._filesystem.list_files_bounded(
        harness_root,
        maximum_files=len(flow.harness_files),
    )
    expected_harness_files: set[Path] = set()
    expected_base_harness_paths: set[str] = set()
    for pinned in flow.harness_files:
        pinned_path = runner._contained_path(root, pinned.path, must_exist=True)
        if pinned_path is not None and (
            harness_root == pinned_path or harness_root in pinned_path.parents
        ):
            expected_harness_files.add(pinned_path)
            expected_base_harness_paths.add(pinned.path)
    base_harness = runner._query(
        (
            "git",
            "ls-tree",
            "-r",
            "--name-only",
            resolved_base_sha,
            "--",
            flow.harness_source_root,
        ),
        root,
    )
    if base_harness is None or base_harness.returncode != 0:
        return False
    base_harness_lines = base_harness.stdout.splitlines()
    if any(
        not line
        or any(ord(character) < 32 for character in line)
        or _safe_relative_path(line) is None
        for line in base_harness_lines
    ):
        return False
    base_harness_paths = set(base_harness_lines)
    return (
        actual_harness_files is not None
        and set(actual_harness_files) == expected_harness_files
        and base_harness_paths == expected_base_harness_paths
    )


def _xcode_harness_source_closure_is_valid(
    pinned_contents: Mapping[str, bytes],
    flow: E2EFlow,
) -> bool:
    """Prove the selected scheme target compiles exactly the pinned Swift closure."""

    project_definition_path = f"{flow.harness_project_path}/project.pbxproj"
    scheme_paths = tuple(
        pinned.path
        for pinned in flow.harness_files
        if pinned.path.endswith(".xcscheme")
    )
    workspace_paths = tuple(
        pinned.path
        for pinned in flow.harness_files
        if pinned.path.endswith(".xcworkspace/contents.xcworkspacedata")
    )
    harness_root = Path(flow.harness_source_root)
    expected_sources = {
        pinned.path
        for pinned in flow.harness_files
        if (
            pinned.path != project_definition_path
            and harness_root in Path(pinned.path).parents
        )
    }
    if (
        len(scheme_paths) != 1
        or len(workspace_paths) != 1
        or flow.runner_source_file not in expected_sources
        or any(not path.endswith(".swift") for path in expected_sources)
    ):
        return False
    scheme_content = pinned_contents.get(scheme_paths[0])
    workspace_content = pinned_contents.get(workspace_paths[0])
    project_content = pinned_contents.get(project_definition_path)
    if (
        not _workspace_references_project(
            workspace_content,
            flow.harness_project_path,
        )
        or not _scheme_selects_harness_target(scheme_content, flow)
        or not _project_compiles_exact_sources(
            project_content,
            flow,
            expected_sources,
        )
    ):
        return False
    return True


def _bounded_xml_root(content: bytes | None) -> ET.Element | None:
    if (
        content is None
        or len(content) > _MAX_MANIFEST_BYTES
        or b"<!DOCTYPE" in content.upper()
        or b"<!ENTITY" in content.upper()
    ):
        return None
    try:
        return ET.fromstring(content)
    except (ET.ParseError, ValueError):
        return None


def _workspace_references_project(
    content: bytes | None,
    project_path: str,
) -> bool:
    root = _bounded_xml_root(content)
    if root is None or root.tag != "Workspace":
        return False
    locations = {
        location
        for node in root.iter("FileRef")
        if isinstance(location := node.attrib.get("location"), str)
    }
    return (
        f"group:{project_path}" in locations
        or f"container:{project_path}" in locations
    )


def _scheme_selects_harness_target(
    content: bytes | None,
    flow: E2EFlow,
) -> bool:
    root = _bounded_xml_root(content)
    if (
        root is None
        or root.tag != "Scheme"
        or set(root.attrib) != {"version"}
        or _VERSION_PATTERN.fullmatch(root.attrib["version"]) is None
        or any(
            (node.text is not None and node.text.strip())
            or (node.tail is not None and node.tail.strip())
            for node in root.iter()
        )
    ):
        return False
    root_children = tuple(root)
    if len(root_children) != 1 or root_children[0].tag != "TestAction":
        return False
    test_action = root_children[0]
    if test_action.attrib != {"buildConfiguration": "Debug"}:
        return False
    test_action_children = tuple(test_action)
    if len(test_action_children) != 1 or test_action_children[0].tag != "Testables":
        return False
    testables_container = test_action_children[0]
    if testables_container.attrib:
        return False
    testables = tuple(testables_container)
    if (
        len(testables) != 1
        or testables[0].tag != "TestableReference"
        or testables[0].attrib != {"skipped": "NO"}
    ):
        return False
    testable_children = tuple(testables[0])
    if len(testable_children) != 1 or testable_children[0].tag != "BuildableReference":
        return False
    buildable = testable_children[0]
    target_name = flow.runner_test_identifier.split("/", 1)[0]
    return not tuple(buildable) and buildable.attrib == {
        "BuildableIdentifier": "primary",
        "BlueprintIdentifier": flow.harness_target_identifier,
        "BuildableName": f"{target_name}.xctest",
        "BlueprintName": target_name,
        "ReferencedContainer": f"container:{flow.harness_project_path}",
    }


def _project_compiles_exact_sources(
    content: bytes | None,
    flow: E2EFlow,
    expected_sources: set[str],
) -> bool:
    if content is None or len(content) > _MAX_PINNED_FILE_BYTES:
        return False
    try:
        project = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    try:
        parsed = _OpenStepParser(project).parse()
    except ValueError:
        return False
    project_mapping = _pbx_mapping(parsed)
    objects = (
        _pbx_mapping(project_mapping.get("objects"))
        if project_mapping is not None
        else None
    )
    if project_mapping is None or objects is None:
        return False
    target = objects.get(flow.harness_target_identifier)
    target_mapping = _pbx_mapping(target)
    target_name = flow.runner_test_identifier.split("/", 1)[0]
    if (
        target_mapping is None
        or target_mapping.get("isa") != "PBXNativeTarget"
        or target_mapping.get("name") != target_name
        or target_mapping.get("productType")
        != "com.apple.product-type.bundle.ui-testing"
    ):
        return False
    for field in (
        "buildRules",
        "dependencies",
        "packageProductDependencies",
        "fileSystemSynchronizedGroups",
    ):
        values = _pbx_object_ids(target_mapping.get(field))
        if values not in {None, ()}:
            return False
    target_configuration_list = _pbx_object_id(
        target_mapping.get("buildConfigurationList")
    )
    root_object_id = _pbx_object_id(project_mapping.get("rootObject"))
    root_object = (
        _pbx_mapping(objects.get(root_object_id))
        if root_object_id is not None
        else None
    )
    if (
        target_configuration_list is None
        or root_object is None
        or root_object.get("isa") != "PBXProject"
        or flow.harness_target_identifier
        not in (_pbx_object_ids(root_object.get("targets")) or ())
        or not _build_configurations_are_closed(
            objects,
            _pbx_object_id(root_object.get("buildConfigurationList")),
            target=False,
        )
        or not _build_configurations_are_closed(
            objects,
            target_configuration_list,
            target=True,
        )
    ):
        return False
    build_phases = _pbx_object_ids(target_mapping.get("buildPhases"))
    if not build_phases:
        return False
    source_phases: list[str] = []
    for phase_id in build_phases:
        phase = _pbx_mapping(objects.get(phase_id))
        if phase is None:
            return False
        phase_kind = phase.get("isa")
        phase_files = _pbx_object_ids(phase.get("files"))
        if phase_kind == "PBXSourcesBuildPhase":
            source_phases.append(phase_id)
        elif (
            phase_kind not in {"PBXFrameworksBuildPhase", "PBXResourcesBuildPhase"}
            or phase_files not in {None, ()}
        ):
            return False
    if len(source_phases) != 1:
        return False
    source_phase = _pbx_mapping(objects[source_phases[0]])
    if source_phase is None:
        return False
    source_build_files = _pbx_object_ids(source_phase.get("files"))
    if not source_build_files:
        return False
    actual_sources: set[str] = set()
    for build_file_id in source_build_files:
        build_file = _pbx_mapping(objects.get(build_file_id))
        if (
            build_file is None
            or build_file.get("isa") != "PBXBuildFile"
            or "settings" in build_file
        ):
            return False
        file_reference_id = _pbx_object_id(build_file.get("fileRef"))
        file_reference = (
            _pbx_mapping(objects.get(file_reference_id))
            if file_reference_id is not None
            else None
        )
        if (
            file_reference is None
            or file_reference.get("isa") != "PBXFileReference"
            or file_reference.get("sourceTree") != "SOURCE_ROOT"
        ):
            return False
        source_path = file_reference.get("path")
        if (
            not isinstance(source_path, str)
            or _safe_relative_path(source_path) is None
            or not source_path.endswith(".swift")
            or source_path in actual_sources
        ):
            return False
        actual_sources.add(source_path)
    return actual_sources == expected_sources


def _build_configurations_are_closed(
    objects: Mapping[str, object],
    configuration_list_id: str | None,
    *,
    target: bool,
) -> bool:
    configuration_list = (
        _pbx_mapping(objects.get(configuration_list_id))
        if configuration_list_id is not None
        else None
    )
    configuration_ids = (
        _pbx_object_ids(configuration_list.get("buildConfigurations"))
        if configuration_list is not None
        and configuration_list.get("isa") == "XCConfigurationList"
        else None
    )
    if not configuration_ids:
        return False
    for configuration_id in configuration_ids:
        configuration = _pbx_mapping(objects.get(configuration_id))
        if (
            configuration is None
            or configuration.get("isa") != "XCBuildConfiguration"
            or "baseConfigurationReference" in configuration
        ):
            return False
        settings = _pbx_mapping(configuration.get("buildSettings"))
        if settings is None:
            return False
        if target:
            if not _target_build_settings_are_safe(settings):
                return False
        elif settings:
            return False
    return True


def _target_build_settings_are_safe(settings: Mapping[str, object]) -> bool:
    if (
        not set(settings) <= _TARGET_BUILD_SETTING_KEYS
        or settings.get("GENERATE_INFOPLIST_FILE") != "YES"
        or settings.get("PRODUCT_NAME") not in {None, "$(TARGET_NAME)"}
    ):
        return False
    for key, raw_value in settings.items():
        if not isinstance(raw_value, str):
            return False
        value = raw_value.strip()
        if value != raw_value or not value or any(ord(character) < 32 for character in value):
            return False
        if key in {
            "CLANG_ENABLE_MODULES",
            "GENERATE_INFOPLIST_FILE",
            "SWIFT_EMIT_LOC_STRINGS",
        } and value not in {"YES", "NO"}:
            return False
        if key == "CODE_SIGN_STYLE" and value not in {"Automatic", "Manual"}:
            return False
        if key in {
            "CURRENT_PROJECT_VERSION",
            "IPHONEOS_DEPLOYMENT_TARGET",
            "MARKETING_VERSION",
            "SWIFT_VERSION",
        } and _VERSION_PATTERN.fullmatch(value) is None:
            return False
        if (
            key == "DEVELOPMENT_TEAM"
            and _DEVELOPMENT_TEAM_PATTERN.fullmatch(value) is None
        ):
            return False
        if (
            key == "PRODUCT_BUNDLE_IDENTIFIER"
            and _BUNDLE_IDENTIFIER_PATTERN.fullmatch(value) is None
        ):
            return False
        if key == "PRODUCT_NAME" and value != "$(TARGET_NAME)":
            return False
        if key == "SDKROOT" and value != "iphoneos":
            return False
        if (
            key == "SUPPORTED_PLATFORMS"
            and value not in {"iphoneos", "iphonesimulator", "iphoneos iphonesimulator"}
        ):
            return False
        if key == "TARGETED_DEVICE_FAMILY" and re.fullmatch(r"[12](?:,[12])?", value) is None:
            return False
        if key == "TEST_TARGET_NAME" and _SCHEME_PATTERN.fullmatch(value) is None:
            return False
    return True


def _pbx_mapping(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict) or any(
        not isinstance(key, str) for key in value
    ):
        return None
    return cast(dict[str, object], value)


def _pbx_object_id(value: object) -> str | None:
    return (
        value
        if isinstance(value, str)
        and _PBX_OBJECT_ID_PATTERN.fullmatch(value) is not None
        else None
    )


def _pbx_object_ids(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, tuple):
        return None
    object_ids = tuple(_pbx_object_id(item) for item in value)
    return (
        cast(tuple[str, ...], object_ids)
        if all(object_id is not None for object_id in object_ids)
        else None
    )


class _OpenStepParser:
    """Complete bounded parser for the ASCII property-list subset used by PBX."""

    def __init__(self, source: str) -> None:
        self._source = source
        self._position = 0

    def parse(self) -> object:
        value = self._parse_value(depth=0)
        self._skip_ignored()
        if self._position != len(self._source):
            raise ValueError("trailing OpenStep input")
        return value

    def _parse_value(self, *, depth: int) -> object:
        if depth > 64:
            raise ValueError("OpenStep nesting is too deep")
        self._skip_ignored()
        current = self._peek()
        if current == "{":
            return self._parse_mapping(depth=depth + 1)
        if current == "(":
            return self._parse_array(depth=depth + 1)
        if current == '"':
            return self._parse_quoted_string()
        return self._parse_atom()

    def _parse_mapping(self, *, depth: int) -> dict[str, object]:
        self._consume("{")
        result: dict[str, object] = {}
        while True:
            self._skip_ignored()
            if self._peek() == "}":
                self._consume("}")
                return result
            key = self._parse_value(depth=depth)
            if not isinstance(key, str) or key in result:
                raise ValueError("OpenStep dictionary key is invalid")
            self._skip_ignored()
            self._consume("=")
            result[key] = self._parse_value(depth=depth)
            self._skip_ignored()
            self._consume(";")

    def _parse_array(self, *, depth: int) -> tuple[object, ...]:
        self._consume("(")
        result: list[object] = []
        while True:
            self._skip_ignored()
            if self._peek() == ")":
                self._consume(")")
                return tuple(result)
            result.append(self._parse_value(depth=depth))
            self._skip_ignored()
            if self._peek() == ",":
                self._consume(",")
            elif self._peek() != ")":
                raise ValueError("OpenStep array delimiter is invalid")

    def _parse_quoted_string(self) -> str:
        self._consume('"')
        result: list[str] = []
        escapes = {'"': '"', "\\": "\\", "n": "\n", "r": "\r", "t": "\t"}
        while self._position < len(self._source):
            character = self._source[self._position]
            self._position += 1
            if character == '"':
                return "".join(result)
            if character == "\\":
                if self._position >= len(self._source):
                    break
                escaped = self._source[self._position]
                self._position += 1
                replacement = escapes.get(escaped)
                if replacement is None:
                    raise ValueError("unsupported OpenStep string escape")
                result.append(replacement)
            else:
                result.append(character)
        raise ValueError("unterminated OpenStep string")

    def _parse_atom(self) -> str:
        start = self._position
        delimiters = frozenset("{}()=;,\"")
        while self._position < len(self._source):
            character = self._source[self._position]
            if character.isspace() or character in delimiters:
                break
            if self._source.startswith(("/*", "//"), self._position):
                break
            self._position += 1
        if self._position == start:
            raise ValueError("missing OpenStep atom")
        return self._source[start : self._position]

    def _skip_ignored(self) -> None:
        while True:
            while (
                self._position < len(self._source)
                and self._source[self._position].isspace()
            ):
                self._position += 1
            if self._source.startswith("/*", self._position):
                end = self._source.find("*/", self._position + 2)
                if end < 0:
                    raise ValueError("unterminated OpenStep block comment")
                self._position = end + 2
                continue
            if self._source.startswith("//", self._position):
                end = self._source.find("\n", self._position + 2)
                self._position = len(self._source) if end < 0 else end + 1
                continue
            return

    def _peek(self) -> str:
        if self._position >= len(self._source):
            raise ValueError("unexpected end of OpenStep input")
        return self._source[self._position]

    def _consume(self, expected: str) -> None:
        self._skip_ignored()
        if not self._source.startswith(expected, self._position):
            raise ValueError("unexpected OpenStep token")
        self._position += len(expected)


def _fixture_manifest_is_valid(
    content: bytes | None,
    flow: E2EFlow,
    assertions: Sequence[AssertionCatalogEntry],
) -> bool:
    manifest = _bounded_json_object(content)
    if manifest is None or set(manifest) != {
        "schema_version",
        "fixture_id",
        "fixture_version",
        "values",
    }:
        return False
    values = manifest.get("values")
    if (
        type(manifest.get("schema_version")) is not int
        or manifest.get("schema_version") != 1
        or manifest.get("fixture_id") != flow.fixture_id
        or type(manifest.get("fixture_version")) is not int
        or manifest.get("fixture_version") != flow.fixture_version
        or not isinstance(values, dict)
        or not values
        or len(values) > _MAX_FIXTURE_VALUES
    ):
        return False
    normalized_values = cast(dict[object, object], values)
    if any(
        not isinstance(key, str)
        or _FIXTURE_KEY_PATTERN.fullmatch(key) is None
        or not isinstance(value, str)
        or not value
        or len(value) > 1_024
        or "\x00" in value
        for key, value in normalized_values.items()
    ):
        return False
    expected_value_keys = {
        verifier.expected_value_fixture_key
        for assertion in assertions
        if isinstance(
            verifier := assertion.verifier,
            ElementValueVerifier,
        )
        and verifier.expected_value_fixture_key is not None
    }
    return expected_value_keys <= set(normalized_values)


def _account_recipe_is_valid(content: bytes | None, flow: E2EFlow) -> bool:
    recipe = _bounded_json_object(content)
    return (
        recipe is not None
        and set(recipe)
        == {
            "schema_version",
            "recipe_id",
            "recipe_version",
            "credential_source",
        }
        and type(recipe.get("schema_version")) is int
        and recipe.get("schema_version") == 1
        and recipe.get("recipe_id") == flow.test_account_recipe_id
        and type(recipe.get("recipe_version")) is int
        and recipe.get("recipe_version") == flow.test_account_recipe_version
        and recipe.get("credential_source") == "OPAQUE_SECRET_REFERENCE"
    )


def _bounded_json_object(content: bytes | None) -> dict[str, object] | None:
    if content is None or not content or len(content) > _MAX_MANIFEST_BYTES:
        return None
    try:
        decoded = json.loads(
            content.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(decoded, dict) or any(
        not isinstance(key, str) for key in decoded
    ):
        return None
    return cast(dict[str, object], decoded)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"unsupported JSON constant: {value}")


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
