"""Ephemeral, credential-safe transport for one exact Git branch push."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from mathews_configuration import SecretValue

_GIT_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_TOKEN = re.compile(r"[^\s\x00]{1,8192}\Z")
_MAX_OUTPUT_BYTES = 64 * 1024
_TIMEOUT_SECONDS = 60
_ASKPASS_SOURCE = """\
import os
import sys

prompt = sys.argv[1].lower() if len(sys.argv) == 2 else ""
if prompt.startswith("username"):
    sys.stdout.write("x-access-token\\n")
elif prompt.startswith("password"):
    descriptor = int(os.environ["MATHEWS_GIT_CREDENTIAL_FD"])
    os.lseek(descriptor, 0, os.SEEK_SET)
    with os.fdopen(os.dup(descriptor), encoding="utf-8") as credential:
        sys.stdout.write(credential.read() + "\\n")
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
        token = credential.reveal()
        if _TOKEN.fullmatch(token) is None:
            raise GitTransportError("GIT_CREDENTIAL_INVALID")
        self._prepare_helper_root()
        helper_path = self._write_askpass_helper()
        try:
            with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as credential_file:
                credential_file.write(token)
                credential_file.flush()
                before_sha = self._remote_sha(
                    workspace_path=workspace_path,
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
                    workspace_path,
                    remote_url,
                    branch_name,
                    helper_path=helper_path,
                    credential_fd=credential_file.fileno(),
                    push=True,
                )
                if result.returncode != 0:
                    raise GitTransportError("GIT_PUSH_REJECTED")
                after_sha = self._remote_sha(
                    workspace_path=workspace_path,
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
        workspace_path: Path,
        remote_url: str,
        branch_name: str,
        helper_path: Path,
        credential_fd: int,
    ) -> str | None:
        result = self._run_authenticated_git(
            workspace_path,
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
        workspace_path: Path,
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
                remote_url,
                f"HEAD:refs/heads/{branch_name}",
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
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
            "MATHEWS_GIT_CREDENTIAL_FD": str(credential_fd),
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        }
        try:
            result = subprocess.run(
                (
                    "git",
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
                    "-C",
                    str(workspace_path),
                    *operation,
                ),
                check=False,
                capture_output=True,
                env=environment,
                pass_fds=(credential_fd,),
                text=True,
                timeout=_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise GitTransportError("GIT_TRANSPORT_UNAVAILABLE") from None
        if (
            len(result.stdout.encode("utf-8")) > _MAX_OUTPUT_BYTES
            or len(result.stderr.encode("utf-8")) > _MAX_OUTPUT_BYTES
        ):
            raise GitTransportError("GIT_TRANSPORT_OUTPUT_TOO_LARGE")
        return result

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

    def _write_askpass_helper(self) -> Path:
        executable = Path(sys.executable)
        if (
            not executable.is_absolute()
            or any(character.isspace() for character in str(executable))
            or "\n" in str(executable)
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
            payload = f"#!{executable}\n{_ASKPASS_SOURCE}".encode()
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
