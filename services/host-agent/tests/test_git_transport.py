import os
import secrets
import shlex
import subprocess
from pathlib import Path

import pytest
from mathews_configuration import SecretValue
from mathews_host_agent.git_transport import (
    GitCredentialPushTransport,
    GitTransportError,
)


def _fake_git(
    tmp_path: Path,
    *,
    expected_sha: str,
    token: str,
    mode: str = "success",
) -> tuple[Path, Path]:
    binary_directory = tmp_path / "bin"
    binary_directory.mkdir()
    state_path = tmp_path / "remote-head"
    log_path = tmp_path / "git-arguments"
    object_directory = tmp_path / "objects"
    object_directory.mkdir()
    script = binary_directory / "git"
    reported_sha = "b" * 40 if mode == "divergent" else expected_sha
    push_result = {
        "push_rejected": "    exit 1",
        "transport_failure": "    exit 128",
    }.get(
        mode,
        f"    printf '{expected_sha}' > {shlex.quote(str(state_path))}",
    )
    script.write_text(
        "\n".join(
            (
                "#!/bin/sh",
                f"printf '%s\\n' \"$*\" >> {shlex.quote(str(log_path))}",
                (
                    "printf 'global=%s object=%s\\n' \"$GIT_CONFIG_GLOBAL\" "
                    f"\"$GIT_OBJECT_DIRECTORY\" >> {shlex.quote(str(log_path))}"
                ),
                "case \"$*\" in",
                "  *rev-parse*--git-path*objects*)",
                f"    printf '{object_directory}\\n'",
                "    exit 0",
                "    ;;",
                "  *ls-remote*)",
                f"    if [ -f {shlex.quote(str(state_path))} ]; then",
                f"      printf '{reported_sha}\\trefs/heads/mathews/test\\n'",
                "      exit 0",
                "    fi",
                "    exit 2",
                "    ;;",
                "  *push*)",
                "    username=$(\"$GIT_ASKPASS\" \"Username for GitHub\") || exit 3",
                "    password=$(\"$GIT_ASKPASS\" \"Password for GitHub\") || exit 4",
                '    [ "$username" = "x-access-token" ] || exit 5',
                f"    [ \"$password\" = {shlex.quote(token)} ] || exit 6",
                push_result,
                "    exit 0",
                "    ;;",
                "esac",
                "exit 7",
                "",
            )
        )
    )
    script.chmod(0o700)
    return binary_directory, log_path


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(root), *arguments),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def test_push_uses_anonymous_fd_askpass_and_is_remote_head_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_sha = "a" * 40
    token = secrets.token_urlsafe(32)
    binary_directory, log_path = _fake_git(
        tmp_path,
        expected_sha=expected_sha,
        token=token,
    )
    monkeypatch.setenv("PATH", f"{binary_directory}:/usr/bin:/bin")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    helper_root = (tmp_path / "helpers").resolve()
    transport = GitCredentialPushTransport(helper_root)

    first = transport.push(
        workspace_path=workspace,
        remote_url="https://github.com/boppuh/mathews.git",
        branch_name="mathews/test",
        expected_sha=expected_sha,
        credential=SecretValue(token),
    )
    second = transport.push(
        workspace_path=workspace,
        remote_url="https://github.com/boppuh/mathews.git",
        branch_name="mathews/test",
        expected_sha=expected_sha,
        credential=SecretValue(token),
    )

    assert first.before_sha is None
    assert first.after_sha == expected_sha
    assert first.pushed is True
    assert second.before_sha == expected_sha
    assert second.after_sha == expected_sha
    assert second.pushed is False
    logged = log_path.read_text()
    assert logged.count("push --porcelain --no-verify") == 1
    assert "refs/heads/candidate:refs/heads/mathews/test" in logged
    assert "--no-follow-tags" in logged
    assert "--recurse-submodules=no" in logged
    assert "--git-dir=" in logged
    assert "global=/dev/null" in logged
    assert " object=/" in logged
    assert "--force" not in logged
    assert token not in logged
    assert list(helper_root.iterdir()) == []


def test_isolated_transport_does_not_inherit_repository_local_configuration(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _git(workspace, "init", "-b", "main")
    (workspace / "README.md").write_text("candidate\n")
    _git(workspace, "add", "README.md")
    _git(
        workspace,
        "-c",
        "user.name=Mathews Test",
        "-c",
        "user.email=mathews@example.invalid",
        "commit",
        "-m",
        "candidate",
    )
    expected_sha = _git(workspace, "rev-parse", "HEAD")
    _git(workspace, "config", "http.proxy", "https://attacker.invalid")
    _git(workspace, "config", "push.followTags", "true")
    _git(
        workspace,
        "config",
        "url.https://attacker.invalid.insteadOf",
        "https://github.com",
    )
    helper_root = (tmp_path / "helpers").resolve()
    transport = GitCredentialPushTransport(helper_root)
    transport._prepare_helper_root()

    with transport._isolated_repository(workspace.resolve(), expected_sha) as isolated:
        environment = {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_OBJECT_DIRECTORY": str(isolated.object_directory),
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        }
        result = subprocess.run(
            (
                "git",
                f"--git-dir={isolated.git_directory}",
                "rev-parse",
                "refs/heads/candidate^{commit}",
            ),
            check=True,
            capture_output=True,
            env=environment,
            text=True,
        )
        isolated_config = (isolated.git_directory / "config").read_text()

    assert result.stdout.strip() == expected_sha
    assert "attacker.invalid" not in isolated_config
    assert "followTags" not in isolated_config
    assert list(helper_root.iterdir()) == []


def test_push_rejects_invalid_secret_before_creating_helper_material(
    tmp_path: Path,
) -> None:
    helper_root = (tmp_path / "helpers").resolve()
    transport = GitCredentialPushTransport(helper_root)

    with pytest.raises(GitTransportError, match="GIT_CREDENTIAL_INVALID"):
        transport.push(
            workspace_path=tmp_path,
            remote_url="https://github.com/boppuh/mathews.git",
            branch_name="mathews/test",
            expected_sha="a" * 40,
            credential=SecretValue("token with spaces"),
        )

    assert not helper_root.exists()


@pytest.mark.parametrize(
    ("mode", "expected_error"),
    (
        ("push_rejected", "GIT_PUSH_REJECTED"),
        ("transport_failure", "GIT_TRANSPORT_UNAVAILABLE"),
        ("divergent", "REMOTE_HEAD_MISMATCH"),
    ),
)
def test_push_failure_paths_remove_ephemeral_helper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    expected_error: str,
) -> None:
    expected_sha = "a" * 40
    token = secrets.token_urlsafe(32)
    binary_directory, _log_path = _fake_git(
        tmp_path,
        expected_sha=expected_sha,
        token=token,
        mode=mode,
    )
    monkeypatch.setenv("PATH", f"{binary_directory}:/usr/bin:/bin")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    helper_root = (tmp_path / "helpers").resolve()

    with pytest.raises(GitTransportError, match=expected_error):
        GitCredentialPushTransport(helper_root).push(
            workspace_path=workspace,
            remote_url="https://github.com/boppuh/mathews.git",
            branch_name="mathews/test",
            expected_sha=expected_sha,
            credential=SecretValue(token),
        )

    assert list(helper_root.iterdir()) == []


@pytest.mark.parametrize(
    ("remote_url", "branch_name", "expected_sha", "expected_error"),
    (
        (
            "https://github.com/boppuh/mathews.git",
            "mathews/test",
            "not-a-sha",
            "INVALID_EXPECTED_HEAD",
        ),
        (
            "--upload-pack=malicious",
            "mathews/test",
            "a" * 40,
            "INVALID_REMOTE_URL",
        ),
        (
            "https://github.com/boppuh/mathews.git",
            "--force",
            "a" * 40,
            "INVALID_BRANCH_NAME",
        ),
    ),
)
def test_transport_rejects_unsafe_inputs_before_creating_helper_material(
    tmp_path: Path,
    remote_url: str,
    branch_name: str,
    expected_sha: str,
    expected_error: str,
) -> None:
    helper_root = (tmp_path / "helpers").resolve()

    with pytest.raises(GitTransportError, match=expected_error):
        GitCredentialPushTransport(helper_root).push(
            workspace_path=tmp_path,
            remote_url=remote_url,
            branch_name=branch_name,
            expected_sha=expected_sha,
            credential=SecretValue(secrets.token_urlsafe(32)),
        )

    assert not helper_root.exists()
