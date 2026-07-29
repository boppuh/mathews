from mathews_host_agent.agent import probe


def test_probe_reports_service_identity() -> None:
    result = probe()

    assert result["service"] == "host-agent"
    assert result["status"] == "ok"
    assert result["version"] == "0.1.0"
