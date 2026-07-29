from typing import Literal

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from mathews_control_plane import __version__
from mathews_control_plane.settings import settings


class HealthResponse(BaseModel):
    service: Literal["api"]
    status: Literal["ok"]
    version: str
    environment: str


app = FastAPI(
    title="Mathews control plane",
    version=__version__,
)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_methods=["GET"],
    allow_origins=[settings.web_origin],
)


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(
        service="api",
        status="ok",
        version=__version__,
        environment=settings.environment,
    )
