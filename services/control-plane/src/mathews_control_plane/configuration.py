import json

from mathews_control_plane.settings import Settings, get_settings


def configuration_report(settings: Settings) -> str:
    """Render deterministic, credential-free startup diagnostics."""

    return json.dumps(settings.safe_summary(), indent=2, sort_keys=True)


def main() -> None:
    current = get_settings()
    print(configuration_report(current))
    if not current.automation_ready:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
