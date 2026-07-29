import uvicorn

from mathews_control_plane.settings import settings


def main() -> None:
    uvicorn.run(
        "mathews_control_plane.app:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.environment == "local",
    )


if __name__ == "__main__":
    main()
