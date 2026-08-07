"""Ephemeral, credential-safe transport for one exact Git branch push."""

from __future__ import annotations

import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

from mathews_configuration import SecretValue

_GIT_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_TOKEN = re.compile(r"[^\s\x00]{1,8192}\Z")
_BRANCH_NAME = re.compile(r"[0-9A-Za-z][0-9A-Za-z._/-]{0,250}\Z")
_MAX_OUTPUT_BYTES = 64 * 1024
_NETWORK_TIMEOUT_SECONDS = 8
_LOCAL_TIMEOUT_SECONDS = 3
_ASKPASS_SOURCE = """\
import os
import sys

prompt = sys.argv[1].lower() if len(sys.argv) == 2 else ""
if prompt.startswith("username"):
    sys.stdout.write("x-access-token\\n")
elif prompt.startswith("password"):
    descriptor = int(os.environ["MATHEWS_GIT_CREDENTIAL_FD"])
    credential = os.pread(descriptor, 8193, 0)
    os.write(sys.stdout.fileno(), credential + b"\\n")
else:
    raise SystemExit(2)
"""


class GitTransportError(RuntimeError):
    """A stable transport failure that never contains credential or Git output."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class GitPushObservation:
    before_sha: str | None
    after_sha: str
    pushed: bool


@dataclass(frozen=True, slots=True)
class _IsolatedGitRepository:
    git_directory: Path
    object_directory: Path


class GitPushTransport(Protocol):
    def push(
        self,
        *,
        workspace_path: Path,
        remote_url: str,
        branch_name: str,
        expected_sha: str,
        credential: SecretValue,
    ) -> GitPushObservation: ...


class GitCredentialPushTransport:
    """Push one explicit refspec using an inherited, anonymous credential file."""

    def __init__(self, helper_root: Path) -> None:
        if not helper_root.is_absolute():
            raise ValueError("Git credential-helper root must be absolute")
        self._helper_root = helper_root

    def push(
        self,
        *,
        workspace_path: Path,
        remote_url: str,
        branch_name: str,
        expected_sha: str,
        credential: SecretValue,
    ) -> GitPushObservation:
        if _GIT_OBJECT.fullmatch(expected_sha) is None:
            raise GitTransportError("INVALID_EXPECTED_HEAD")
        self._validate_remote_url(remote_url)
        if (
            _BRANCH_NAME.fullmatch(branch_name) is None
            or ".." in branch_name
            or "//" in branch_name
            or branch_name.endswith(("/", ".", ".lock"))
        ):
            raise GitTransportError("INVALID_BRANCH_NAME")
        token = credential.reveal()
        if _TOKEN.fullmatch(token) is None:
            raise GitTransportError("GIT_CREDENTIAL_INVALID")
        self._prepare_helper_root()
        with self._isolated_repository(workspace_path, expected_sha) as isolated:
            helper_path = self._write_askpass_helper()
            try:
                with tempfile.TemporaryFile(
                    mode="w+", encoding="utf-8"
                ) as credential_file:
                    credential_file.write(token)
                    credential_file.flush()
                    before_sha = self._remote_sha(
                        isolated=isolated,
                        remote_url=remote_url,
                        branch_name=branch_name,
                        helper_path=helper_path,
                        credential_fd=credential_file.fileno(),
                    )
                    if before_sha == expected_sha:
                        return GitPushObservation(
                            before_sha=before_sha,
                            after_sha=before_sha,
                            pushed=False,
                        )
                    result = self._run_authenticated_git(
                        isolated,
                        remote_url,
                        branch_name,
                        helper_path=helper_path,
                        credential_fd=credential_file.fileno(),
                        push=True,
                    )
                    if result.returncode == 1:
                        raise GitTransportError("GIT_PUSH_REJECTED")
                    if result.returncode != 0:
                        raise GitTransportError("GIT_TRANSPORT_UNAVAILABLE")
                    after_sha = self._remote_sha(
                        isolated=isolated,
                        remote_url=remote_url,
                        branch_name=branch_name,
                        helper_path=helper_path,
                        credential_fd=credential_file.fileno(),
                    )
                    if after_sha != expected_sha:
                        raise GitTransportError("REMOTE_HEAD_MISMATCH")
                    return GitPushObservation(
                        before_sha=before_sha,
                        after_sha=after_sha,
                        pushed=True,
                    )
            finally:
                try:
                    helper_path.unlink()
                except OSError:
                    pass

    def _remote_sha(
        self,
        *,
        isolated: _IsolatedGitRepository,
        remote_url: str,
        branch_name: str,
        helper_path: Path,
        credential_fd: int,
    ) -> str | None:
        result = self._run_authenticated_git(
            isolated,
            remote_url,
            branch_name,
            helper_path=helper_path,
            credential_fd=credential_fd,
            push=False,
        )
        if result.returncode == 2 and not result.stdout:
            return None
        if result.returncode != 0:
            raise GitTransportError("REMOTE_HEAD_UNAVAILABLE")
        fields = result.stdout.rstrip("\n").split("\t")
        expected_ref = f"refs/heads/{branch_name}"
        if (
            len(fields) != 2
            or _GIT_OBJECT.fullmatch(fields[0]) is None
            or fields[1] != expected_ref
        ):
            raise GitTransportError("REMOTE_HEAD_INVALID")
        return fields[0]

    def _run_authenticated_git(
        self,
        isolated: _IsolatedGitRepository,
        remote_url: str,
        branch_name: str,
        *,
        helper_path: Path,
        credential_fd: int,
        push: bool,
    ) -> subprocess.CompletedProcess[str]:
        operation = (
            (
                "push",
                "--porcelain",
                "--no-verify",
                "--no-follow-tags",
                "--recurse-submodules=no",
                remote_url,
                f"refs/heads/candidate:refs/heads/{branch_name}",
            )
            if push
            else (
                "ls-remote",
                "--heads",
                "--exit-code",
                remote_url,
                f"refs/heads/{branch_name}",
            )
        )
        environment = {
            "GIT_ASKPASS": str(helper_path),
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_OBJECT_DIRECTORY": str(isolated.object_directory),
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
            "MATHEWS_GIT_CREDENTIAL_FD": str(credential_fd),
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        }
        try:
            result = subprocess.run(
                (
                    "git",
                    f"--git-dir={isolated.git_directory}",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "credential.helper=",
                    "-c",
                    f"core.askPass={helper_path}",
                    "-c",
                    "http.followRedirects=false",
                    "-c",
                    "http.sslVerify=true",
                    "-c",
                    "push.followTags=false",
                    "-c",
                    "push.gpgSign=false",
                    "-c",
                    "push.recurseSubmodules=no",
                    *operation,
                ),
                check=False,
                capture_output=True,
                env=environment,
                pass_fds=(credential_fd,),
                text=True,
                timeout=_NETWORK_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise GitTransportError("GIT_TRANSPORT_UNAVAILABLE") from None
        if (
            len(result.stdout.encode("utf-8")) > _MAX_OUTPUT_BYTES
            or len(result.stderr.encode("utf-8")) > _MAX_OUTPUT_BYTES
        ):
            raise GitTransportError("GIT_TRANSPORT_OUTPUT_TOO_LARGE")
        return result

    @contextmanager
    def _isolated_repository(
        self,
        workspace_path: Path,
        expected_sha: str,
    ) -> Iterator[_IsolatedGitRepository]:
        object_directory = self._object_directory(workspace_path)
        try:
            with tempfile.TemporaryDirectory(
                prefix="repository-",
                dir=self._helper_root,
            ) as raw_directory:
                git_directory = Path(raw_directory)
                refs = git_directory / "refs" / "heads"
                refs.mkdir(mode=0o700, parents=True)
                object_format = "sha256" if len(expected_sha) == 64 else "sha1"
                repository_version = "1" if object_format == "sha256" else "0"
                config = (
                    "[core]\n"
                    f"\trepositoryformatversion = {repository_version}\n"
                    "\tbare = true\n"
                )
                if object_format == "sha256":
                    config += "[extensions]\n\tobjectformat = sha256\n"
                self._write_private_file(git_directory / "config", config)
                self._write_private_file(
                    git_directory / "HEAD",
                    "ref: refs/heads/candidate\n",
                )
                self._write_private_file(
                    refs / "candidate",
                    f"{expected_sha}\n",
                )
                yield _IsolatedGitRepository(
                    git_directory=git_directory,
                    object_directory=object_directory,
                )
        except GitTransportError:
            raise
        except OSError:
            raise GitTransportError("GIT_TRANSPORT_ISOLATION_UNAVAILABLE") from None

    def _object_directory(self, workspace_path: Path) -> Path:
        if not workspace_path.is_absolute() or not workspace_path.is_dir():
            raise GitTransportError("GIT_OBJECT_DIRECTORY_INVALID")
        environment = {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        }
        try:
            result = subprocess.run(
                (
                    "git",
                    "-C",
                    str(workspace_path),
                    "rev-parse",
                    "--path-format=absolute",
                    "--git-path",
                    "objects",
                ),
                check=False,
                capture_output=True,
                env=environment,
                text=True,
                timeout=_LOCAL_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise GitTransportError("GIT_OBJECT_DIRECTORY_INVALID") from None
        if result.returncode != 0 or len(result.stdout.encode()) > _MAX_OUTPUT_BYTES:
            raise GitTransportError("GIT_OBJECT_DIRECTORY_INVALID")
        try:
            object_directory = Path(result.stdout.rstrip("\n")).resolve(strict=True)
            directory_stat = object_directory.lstat()
        except OSError:
            raise GitTransportError("GIT_OBJECT_DIRECTORY_INVALID") from None
        if (
            not object_directory.is_absolute()
            or not stat.S_ISDIR(directory_stat.st_mode)
            or directory_stat.st_uid != os.geteuid()
        ):
            raise GitTransportError("GIT_OBJECT_DIRECTORY_INVALID")
        alternates_path = object_directory / "info" / "alternates"
        try:
            if alternates_path.exists() and alternates_path.read_bytes().strip():
                raise GitTransportError("GIT_OBJECT_ALTERNATES_PROHIBITED")
        except OSError:
            raise GitTransportError("GIT_OBJECT_DIRECTORY_INVALID") from None
        return object_directory

    @staticmethod
    def _write_private_file(path: Path, payload: str) -> None:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            encoded = payload.encode()
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    raise OSError("private Git file write did not advance")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _prepare_helper_root(self) -> None:
        try:
            self._helper_root.mkdir(mode=0o700, parents=True, exist_ok=True)
            root_stat = self._helper_root.lstat()
        except OSError:
            raise GitTransportError("GIT_CREDENTIAL_HELPER_UNAVAILABLE") from None
        if (
            not stat.S_ISDIR(root_stat.st_mode)
            or root_stat.st_uid != os.geteuid()
            or stat.S_IMODE(root_stat.st_mode) & 0o077
        ):
            raise GitTransportError("GIT_CREDENTIAL_HELPER_UNSAFE")

    @staticmethod
    def _validate_remote_url(remote_url: str) -> None:
        if (
            not isinstance(remote_url, str)
            or len(remote_url) > 1000
            or any(
                character.isspace() or character == "\x00"
                for character in remote_url
            )
        ):
            raise GitTransportError("INVALID_REMOTE_URL")
        try:
            parsed = urlsplit(remote_url)
            port = parsed.port
        except ValueError:
            raise GitTransportError("INVALID_REMOTE_URL") from None
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or port not in {None, 443}
            or not parsed.path.startswith("/")
            or parsed.path in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise GitTransportError("INVALID_REMOTE_URL")

    def _write_askpass_helper(self) -> Path:
        executable = Path(sys.executable)
        if (
            not executable.is_absolute()
            or any(character in "\x00\r\n" for character in str(executable))
            or not executable.is_file()
        ):
            raise GitTransportError("GIT_CREDENTIAL_HELPER_UNAVAILABLE")
        descriptor, raw_path = tempfile.mkstemp(
            prefix="askpass-",
            suffix=".py",
            dir=self._helper_root,
            text=True,
        )
        path = Path(raw_path)
        try:
            os.fchmod(descriptor, 0o700)
            payload = (
                "#!/bin/sh\n"
                f"exec {shlex.quote(str(executable))} -c "
                f"{shlex.quote(_ASKPASS_SOURCE)} \"$@\"\n"
            ).encode()
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("askpass helper write did not advance")
                offset += written
            os.fsync(descriptor)
        except OSError:
            try:
                path.unlink()
            except OSError:
                pass
            raise GitTransportError("GIT_CREDENTIAL_HELPER_UNAVAILABLE") from None
        finally:
            os.close(descriptor)
        return path
