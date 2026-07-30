import json
import platform
import sys
from pathlib import Path

import mathews_host_agent.agent as agent_module
import pytest
from mathews_configuration import SecretReference
from mathews_host_agent.agent import HostAgentSettings, main, probe
from mathews_host_agent.server import HostServerError


def test_probe_reports_service_identity() -> None:
    result = probe()

    assert result["service"] == "host-agent"
    assert result["status"] == "ok"
    assert result["version"] == "0.1.0"


def test_once_is_a_side_effect_free_json_probe(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["mathews-host-agent", "--once"])

    main()

    output = capsys.readouterr().out
    assert json.loads(output) == {
        "platform": platform.system().lower(),
        "service": "host-agent",
        "status": "ok",
        "version": "0.1.0",
    }


def test_service_refuses_root_before_resolving_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(agent_module, "_running_as_root", lambda: True)
    settings = HostAgentSettings(
        socket_path=tmp_path / "host.sock",
        journal_path=tmp_path / "journal.sqlite3",
        authentication_reference=SecretReference.parse(
            "keychain://com.boppuh.mathews.host-agent/control-plane-hmac-v1"
        ),
        authentication_key_id="host-control-plane-v1",
        host_id="host-1",
        launchd_socket=False,
    )

    with pytest.raises(HostServerError, match="non-root"):
        agent_module.run(settings)


def test_service_defaults_follow_shared_environment_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    socket_path = tmp_path / "configured.sock"
    journal_path = tmp_path / "configured.sqlite3"
    reference = "keychain://com.boppuh.mathews.host-agent/configured-control-plane"
    captured: list[HostAgentSettings] = []
    monkeypatch.setenv("MATHEWS_HOST_SOCKET_PATH", str(socket_path))
    monkeypatch.setenv("MATHEWS_HOST_JOURNAL_PATH", str(journal_path))
    monkeypatch.setenv("MATHEWS_HOST_AUTH_KEY_REF", reference)
    monkeypatch.setenv("MATHEWS_HOST_AUTH_KEY_ID", "configured-key-v2")
    monkeypatch.setenv("MATHEWS_HOST_ID", "configured-host")
    monkeypatch.setattr(sys, "argv", ["mathews-host-agent"])
    monkeypatch.setattr(agent_module, "run", captured.append)

    main()

    assert captured == [
        HostAgentSettings(
            socket_path=socket_path.resolve(),
            journal_path=journal_path.resolve(),
            authentication_reference=SecretReference.parse(reference),
            authentication_key_id="configured-key-v2",
            host_id="configured-host",
            launchd_socket=False,
        )
    ]


def test_explicit_cli_paths_expand_the_user_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[HostAgentSettings] = []
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "mathews-host-agent",
            "--socket-path",
            "~/runtime/host.sock",
            "--journal-path",
            "~/runtime/journal.sqlite3",
        ],
    )
    monkeypatch.setattr(agent_module, "run", captured.append)

    main()

    assert captured[0].socket_path == tmp_path / "runtime" / "host.sock"
    assert captured[0].journal_path == tmp_path / "runtime" / "journal.sqlite3"


def test_blank_host_environment_values_use_safe_defaults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[HostAgentSettings] = []
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MATHEWS_HOST_SOCKET_PATH", "")
    monkeypatch.setenv("MATHEWS_HOST_JOURNAL_PATH", "  ")
    monkeypatch.setenv("MATHEWS_HOST_AUTH_KEY_REF", "")
    monkeypatch.setattr(sys, "argv", ["mathews-host-agent"])
    monkeypatch.setattr(agent_module, "run", captured.append)

    main()

    default_directory = tmp_path / "Library" / "Application Support" / "Mathews"
    assert captured[0].socket_path == default_directory / "host-agent.sock"
    assert captured[0].journal_path == default_directory / "host-agent.sqlite3"
    assert captured[0].authentication_reference == SecretReference.parse(
        "keychain://com.boppuh.mathews.host-agent/control-plane-hmac-v1"
    )


def test_invalid_environment_host_identity_fails_before_service_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MATHEWS_HOST_ID", "invalid host identity")
    monkeypatch.setattr(sys, "argv", ["mathews-host-agent"])

    with pytest.raises(SystemExit, match="2"):
        main()
