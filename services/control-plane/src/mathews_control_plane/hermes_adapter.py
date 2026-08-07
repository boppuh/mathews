"""Authenticated Hermes Runs API adapter and durable worker handler."""

from __future__ import annotations

import json
import platform
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urljoin
from urllib.request import Request, urlopen
from uuid import NAMESPACE_URL, UUID, uuid5

from mathews_configuration import SecretProvider, SecretReference, SecretValue
from pydantic import BaseModel, ConfigDict, Field

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.background_jobs import (
    BackgroundJobLeaseLostError,
    LeasedJobContext,
    TerminalBackgroundJobError,
)
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    HermesRun,
    HermesRunStatus,
    ReconciliationStatus,
    ReconciliationTargetKind,
)
from mathews_control_plane.hermes import (
    HermesEventType,
    HermesProviderEvent,
    HermesRunService,
)
from mathews_control_plane.prompt_compiler import CompiledPrompt, PromptRole
from mathews_control_plane.reliability import ReconciliationObservation

_MAX_RESPONSE_BYTES = 1_000_000


class HermesRuntimeError(RuntimeError):
    """A stable Hermes boundary failure without remote response contents."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class HermesObservedStatus(StrEnum):
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class HermesObservation:
    external_run_id: str
    status: HermesObservedStatus
    payload: dict[str, object]


class HermesRuntime(Protocol):
    def start(
        self,
        *,
        idempotency_key: str,
        task_id: UUID,
        prompt: CompiledPrompt,
    ) -> str: ...

    def observe(self, external_run_id: str) -> HermesObservation: ...

    def stop(self, external_run_id: str) -> None: ...

    def reconcile(
        self,
        *,
        kind: ReconciliationTargetKind,
        target_key: str,
        expected_payload: Mapping[str, object],
    ) -> ReconciliationObservation: ...


class KeychainSecretProvider(SecretProvider):
    """Resolve a configured credential from macOS Keychain without logging it."""

    def get(self, reference: SecretReference) -> SecretValue:
        if platform.system().lower() != "darwin":
            raise HermesRuntimeError("HERMES_AUTH_UNAVAILABLE")
        try:
            completed = subprocess.run(
                (
                    "/usr/bin/security",
                    "find-generic-password",
                    "-s",
                    reference.service,
                    "-a",
                    reference.account,
                    "-w",
                ),
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            raise HermesRuntimeError("HERMES_AUTH_UNAVAILABLE") from None
        value = completed.stdout.rstrip("\r\n")
        if completed.returncode != 0 or not value:
            raise HermesRuntimeError("HERMES_AUTH_UNAVAILABLE")
        return SecretValue(value)


class HermesHttpRuntime:
    """Small client for Hermes' authenticated Runs API."""

    def __init__(
        self,
        endpoint: str,
        api_key_ref: SecretReference,
        *,
        secrets: SecretProvider,
        timeout_seconds: float = 10,
        opener: Callable[..., object] = urlopen,
    ) -> None:
        normalized = endpoint.rstrip("/") + "/"
        if not normalized.startswith(("http://", "https://")):
            raise HermesRuntimeError("HERMES_ENDPOINT_INVALID")
        self._endpoint = normalized
        self._api_key_ref = api_key_ref
        self._secrets = secrets
        self._timeout_seconds = timeout_seconds
        self._opener = opener

    def start(
        self,
        *,
        idempotency_key: str,
        task_id: UUID,
        prompt: CompiledPrompt,
    ) -> str:
        response = self._request(
            "POST",
            "v1/runs",
            payload={
                "input": prompt.content,
                "session_id": str(task_id),
            },
            idempotency_key=idempotency_key,
        )
        run_id = response.get("run_id")
        if not isinstance(run_id, str) or not run_id.strip():
            raise HermesRuntimeError("HERMES_RESPONSE_INVALID")
        return run_id.strip()

    def observe(self, external_run_id: str) -> HermesObservation:
        response = self._request(
            "GET",
            f"v1/runs/{quote(external_run_id, safe='')}",
        )
        returned_id = response.get("run_id")
        status = response.get("status")
        if returned_id != external_run_id or not isinstance(status, str):
            raise HermesRuntimeError("HERMES_RESPONSE_INVALID")
        try:
            observed_status = HermesObservedStatus(status.lower())
        except ValueError:
            raise HermesRuntimeError("HERMES_RESPONSE_INVALID") from None
        return HermesObservation(external_run_id, observed_status, response)

    def stop(self, external_run_id: str) -> None:
        response = self._request(
            "POST",
            f"v1/runs/{quote(external_run_id, safe='')}/stop",
            payload={},
            idempotency_key=f"mathews-stop:{external_run_id}",
        )
        if response.get("status") not in {"stopping", "cancelled"}:
            raise HermesRuntimeError("HERMES_RESPONSE_INVALID")

    def reconcile(
        self,
        *,
        kind: ReconciliationTargetKind,
        target_key: str,
        expected_payload: Mapping[str, object],
    ) -> ReconciliationObservation:
        if kind is not ReconciliationTargetKind.HERMES_RUN:
            raise HermesRuntimeError("HERMES_RECONCILIATION_KIND_INVALID")
        external = expected_payload.get("external_run_id")
        if not isinstance(external, str):
            raise HermesRuntimeError("HERMES_RECONCILIATION_INVALID")
        observed = self.observe(external)
        status = (
            ReconciliationStatus.CURRENT
            if observed.status
            in {
                HermesObservedStatus.STARTING,
                HermesObservedStatus.RUNNING,
                HermesObservedStatus.STOPPING,
            }
            else ReconciliationStatus.UPDATED
        )
        return ReconciliationObservation(
            status=status,
            observed_payload={
                "external_run_id": observed.external_run_id,
                "status": observed.status.value,
                "target_key": target_key,
            },
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, object] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, object]:
        try:
            secret = self._secrets.get(self._api_key_ref)
            body = None
            if payload is not None:
                body = json.dumps(payload, separators=(",", ":")).encode()
            headers = {
                "Accept": "application/json",
                "Authorization": f"Bearer {secret.reveal()}",
                "Content-Type": "application/json",
            }
            if idempotency_key is not None:
                headers["Idempotency-Key"] = idempotency_key
            request = Request(
                urljoin(self._endpoint, path),
                data=body,
                headers=headers,
                method=method,
            )
            response = self._opener(request, timeout=self._timeout_seconds)
            with cast(ProtocolResponse, response) as opened:
                content = opened.read(_MAX_RESPONSE_BYTES + 1)
        except (HTTPError, URLError, OSError, TimeoutError, HermesRuntimeError):
            raise HermesRuntimeError("HERMES_UNAVAILABLE") from None
        if len(content) > _MAX_RESPONSE_BYTES:
            raise HermesRuntimeError("HERMES_RESPONSE_INVALID")
        try:
            decoded = json.loads(content)
        except (TypeError, ValueError, UnicodeDecodeError):
            raise HermesRuntimeError("HERMES_RESPONSE_INVALID") from None
        if not isinstance(decoded, dict):
            raise HermesRuntimeError("HERMES_RESPONSE_INVALID")
        return cast(dict[str, object], decoded)


class ProtocolResponse(Protocol):
    def __enter__(self) -> ProtocolResponse: ...

    def __exit__(self, *args: object) -> None: ...

    def read(self, amount: int = -1) -> bytes: ...


class HermesJobPrompt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    task_id: UUID
    role: PromptRole
    template_id: UUID
    template_version: int = Field(gt=0)
    policy_version_id: UUID
    evaluation_label: str | None = None
    content: str = Field(min_length=1, max_length=128_000)
    evidence_ids: tuple[UUID, ...] = ()

    def compiled(self) -> CompiledPrompt:
        return CompiledPrompt(**self.model_dump())


class HermesJobInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    prompt: HermesJobPrompt
    timeout_seconds: int = Field(default=300, ge=1, le=3_600)
    poll_interval_seconds: float = Field(default=1, gt=0, le=10)


class UnavailableHermesRuntime:
    def start(self, **_kwargs: object) -> str:
        raise HermesRuntimeError("HERMES_UNCONFIGURED")

    def observe(self, _external_run_id: str) -> HermesObservation:
        raise HermesRuntimeError("HERMES_UNCONFIGURED")

    def stop(self, _external_run_id: str) -> None:
        raise HermesRuntimeError("HERMES_UNCONFIGURED")

    def reconcile(
        self,
        *,
        kind: ReconciliationTargetKind,
        target_key: str,
        expected_payload: Mapping[str, object],
    ) -> ReconciliationObservation:
        del kind, target_key, expected_payload
        return ReconciliationObservation(
            status=ReconciliationStatus.RETRY_REQUIRED,
            observed_payload={},
            error_code="HERMES_UNCONFIGURED",
        )


class HermesRunJobHandler:
    """Run one Hermes attempt under the durable worker's current lease."""

    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        runtime: HermesRuntime,
        *,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._factory = factory
        self._runs = HermesRunService(factory, artifact_store, clock=clock)
        self._runtime = runtime
        self._sleep = sleeper
        self._monotonic = monotonic

    def __call__(self, context: LeasedJobContext) -> Mapping[str, object]:
        job_input = HermesJobInput.model_validate(context.grant.input_payload)
        prompt = job_input.prompt.compiled()
        if prompt.task_id != context.grant.task_id:
            raise TerminalBackgroundJobError("HERMES_PROMPT_TASK_MISMATCH")
        run_id = uuid5(
            NAMESPACE_URL,
            f"mathews:hermes-run:{context.grant.job_id}:{context.grant.attempt}",
        )
        prepared = self._runs.prepare(context.grant, run_id=run_id, prompt=prompt)
        external_run_id = self._external_run_id(run_id)
        if prepared.status is HermesRunStatus.STARTING:
            try:
                started_id = self._runtime.start(
                    idempotency_key=f"mathews:{run_id}",
                    task_id=context.grant.task_id,
                    prompt=prompt,
                )
            except HermesRuntimeError as error:
                self._fail_dependency(context, run_id, error.code)
            self._runs.record_started(
                context.grant,
                run_id=run_id,
                external_run_id=started_id,
            )
            external_run_id = started_id
        if external_run_id is None:
            raise TerminalBackgroundJobError("HERMES_RUN_CORRELATION_MISSING")
        deadline = self._monotonic() + job_input.timeout_seconds
        while True:
            try:
                context.heartbeat(timedelta(seconds=30))
            except BackgroundJobLeaseLostError:
                self._stop_and_cancel(run_id, external_run_id)
                raise
            try:
                observation = self._runtime.observe(external_run_id)
            except HermesRuntimeError as error:
                self._fail_dependency(context, run_id, error.code)
            if observation.status is HermesObservedStatus.COMPLETED:
                event = self._terminal_event(run_id, observation, HermesEventType.COMPLETED)
                self._runs.ingest(run_id, event)
                return {"hermes_run_id": str(run_id), "status": "SUCCEEDED"}
            if observation.status is HermesObservedStatus.FAILED:
                event = self._terminal_event(run_id, observation, HermesEventType.FAILED)
                self._runs.ingest(run_id, event)
                raise TerminalBackgroundJobError("HERMES_RUN_FAILED")
            if observation.status is HermesObservedStatus.CANCELLED:
                self._runs.cancel(run_id)
                raise TerminalBackgroundJobError("HERMES_RUN_CANCELLED")
            if self._monotonic() >= deadline:
                self._runtime.stop(external_run_id)
                self._runs.fail_dependency(
                    context.grant,
                    run_id=run_id,
                    error_code="HERMES_TIMEOUT",
                    timed_out=True,
                )
                raise BackgroundJobLeaseLostError("Hermes timeout retry was scheduled")
            self._sleep(job_input.poll_interval_seconds)

    def _external_run_id(self, run_id: UUID) -> str | None:
        with self._factory() as session:
            run = session.get(HermesRun, run_id)
            return None if run is None else run.external_run_id

    def _terminal_event(
        self,
        run_id: UUID,
        observation: HermesObservation,
        event_type: HermesEventType,
    ) -> HermesProviderEvent:
        with self._factory() as session:
            run = session.get(HermesRun, run_id)
            if run is None:
                raise TerminalBackgroundJobError("HERMES_RUN_CORRELATION_MISSING")
            sequence = run.last_event_sequence + 1
        return HermesProviderEvent(
            provider_event_id=f"status:{event_type.value.lower()}:{sequence}",
            external_run_id=observation.external_run_id,
            sequence=sequence,
            event_type=event_type,
            payload=observation.payload,
        )

    def _fail_dependency(
        self,
        context: LeasedJobContext,
        run_id: UUID,
        error_code: str,
    ) -> None:
        self._runs.fail_dependency(
            context.grant,
            run_id=run_id,
            error_code=error_code,
        )
        raise BackgroundJobLeaseLostError("Hermes outage retry was scheduled")

    def _stop_and_cancel(self, run_id: UUID, external_run_id: str) -> None:
        try:
            self._runtime.stop(external_run_id)
        except HermesRuntimeError:
            pass
        try:
            self._runs.cancel(run_id)
        except RuntimeError:
            pass
