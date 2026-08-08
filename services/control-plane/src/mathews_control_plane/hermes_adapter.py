"""Authenticated Hermes Runs API adapter and durable worker handler."""

from __future__ import annotations

import json
import platform
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import NoReturn, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urljoin, urlsplit
from urllib.request import Request, urlopen
from uuid import NAMESPACE_URL, UUID, uuid5

from mathews_configuration import SecretProvider, SecretReference, SecretValue
from pydantic import BaseModel, ConfigDict, Field

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.background_jobs import (
    BackgroundJobLeaseLostError,
    BackgroundJobService,
    LeasedJobContext,
    TerminalBackgroundJobError,
)
from mathews_control_plane.code_change_execution import (
    HermesToolProposalRequest,
    ScopedCodeExecutionService,
    ScopedToolAmbiguousError,
    ScopedToolConflictError,
    ScopedToolExecutionResult,
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
_HOST_RECONCILIATION_ATTEMPTS = 3


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
    events: tuple[HermesProviderEvent, ...] = ()


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

    def submit_tool_result(
        self,
        external_run_id: str,
        result: ScopedToolExecutionResult,
    ) -> None: ...

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
        parsed = urlsplit(normalized)
        loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
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
        return HermesObservation(
            external_run_id,
            observed_status,
            _observation_payload(response),
            _provider_events(response, external_run_id),
        )

    def stop(self, external_run_id: str) -> None:
        response = self._request(
            "POST",
            f"v1/runs/{quote(external_run_id, safe='')}/stop",
            payload={},
            idempotency_key=f"mathews-stop:{external_run_id}",
        )
        if response.get("status") not in {"stopping", "cancelled"}:
            raise HermesRuntimeError("HERMES_RESPONSE_INVALID")

    def submit_tool_result(
        self,
        external_run_id: str,
        result: ScopedToolExecutionResult,
    ) -> None:
        response = self._request(
            "POST",
            f"v1/runs/{quote(external_run_id, safe='')}/tool-results",
            payload={
                "proposal_id": result.proposal_id,
                "status": result.status.value.lower(),
                "code": result.code,
                "result": result.result,
                "authorization_evidence_id": str(result.decision_evidence_id),
                "result_evidence_id": str(result.result_evidence_id),
            },
            idempotency_key=f"mathews-tool-result:{result.proposal_id}",
        )
        if response.get("accepted") is not True:
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

    def submit_tool_result(
        self,
        _external_run_id: str,
        _result: ScopedToolExecutionResult,
    ) -> None:
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
        tool_execution: ScopedCodeExecutionService | None = None,
        *,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._factory = factory
        effective_clock = clock or (lambda: datetime.now(UTC))
        self._runs = HermesRunService(factory, artifact_store, clock=effective_clock)
        self._runtime = runtime
        self._tool_execution = tool_execution
        self._jobs = BackgroundJobService(factory, artifact_store, clock=effective_clock)
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
        if prepared.status is HermesRunStatus.SUCCEEDED:
            return {"hermes_run_id": str(run_id), "status": "SUCCEEDED"}
        if prepared.status in {
            HermesRunStatus.FAILED,
            HermesRunStatus.CANCELLED,
            HermesRunStatus.TIMED_OUT,
        }:
            raise TerminalBackgroundJobError("HERMES_RUN_TERMINAL")
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
            for event in observation.events:
                ingested = self._runs.ingest(run_id, event)
                if not ingested.accepted:
                    if ingested.ignored_reason == "STALE_LEASE":
                        self._stop_and_cancel(run_id, external_run_id)
                        raise BackgroundJobLeaseLostError("Hermes tool event was fenced")
                    continue
                if event.event_type is HermesEventType.TOOL_PROPOSAL:
                    self._execute_tool_proposal(
                        context,
                        run_id=run_id,
                        external_run_id=external_run_id,
                        event=event,
                    )
            if observation.status is HermesObservedStatus.COMPLETED:
                event = self._terminal_event(run_id, observation, HermesEventType.COMPLETED)
                result = self._runs.ingest(run_id, event)
                self._require_terminal_event(result.accepted, result.ignored_reason)
                return {"hermes_run_id": str(run_id), "status": "SUCCEEDED"}
            if observation.status is HermesObservedStatus.FAILED:
                event = self._terminal_event(run_id, observation, HermesEventType.FAILED)
                result = self._runs.ingest(run_id, event)
                self._require_terminal_event(result.accepted, result.ignored_reason)
                raise TerminalBackgroundJobError("HERMES_RUN_FAILED")
            if observation.status is HermesObservedStatus.CANCELLED:
                self._runs.cancel(run_id)
                raise TerminalBackgroundJobError("HERMES_RUN_CANCELLED")
            if self._monotonic() >= deadline:
                try:
                    self._runtime.stop(external_run_id)
                except HermesRuntimeError:
                    pass
                self._runs.fail_dependency(
                    context.grant,
                    run_id=run_id,
                    error_code="HERMES_TIMEOUT",
                    timed_out=True,
                )
                raise BackgroundJobLeaseLostError("Hermes timeout retry was scheduled")
            self._sleep(job_input.poll_interval_seconds)

    def _execute_tool_proposal(
        self,
        context: LeasedJobContext,
        *,
        run_id: UUID,
        external_run_id: str,
        event: HermesProviderEvent,
    ) -> None:
        if self._tool_execution is None:
            self._stop_and_cancel(run_id, external_run_id)
            raise TerminalBackgroundJobError("HERMES_TOOL_GATEWAY_UNAVAILABLE")
        try:
            proposal = HermesToolProposalRequest.model_validate(event.payload)
        except ValueError:
            self._stop_and_cancel(run_id, external_run_id)
            raise TerminalBackgroundJobError("HERMES_TOOL_PROPOSAL_INVALID") from None
        for attempt in range(1, _HOST_RECONCILIATION_ATTEMPTS + 1):
            try:
                result = self._tool_execution.execute(
                    context.grant,
                    run_id=run_id,
                    proposal=proposal,
                )
                break
            except ScopedToolAmbiguousError:
                if attempt == _HOST_RECONCILIATION_ATTEMPTS:
                    self._stop_and_cancel(run_id, external_run_id)
                    raise TerminalBackgroundJobError(
                        "HOST_OPERATION_RECONCILIATION_REQUIRED"
                    ) from None
                try:
                    context.heartbeat(timedelta(seconds=30))
                except BackgroundJobLeaseLostError:
                    self._stop_and_cancel(run_id, external_run_id)
                    raise
                self._sleep(0.1)
            except ScopedToolConflictError:
                self._stop_and_cancel(run_id, external_run_id)
                raise TerminalBackgroundJobError("HERMES_TOOL_EXECUTION_INVALID") from None
        try:
            self._runtime.submit_tool_result(external_run_id, result)
        except HermesRuntimeError as error:
            self._fail_dependency(context, run_id, error.code)

    @staticmethod
    def _require_terminal_event(accepted: bool, ignored_reason: str | None) -> None:
        if accepted:
            return
        if ignored_reason == "STALE_LEASE":
            raise BackgroundJobLeaseLostError("Hermes terminal event was fenced")
        raise TerminalBackgroundJobError("HERMES_TERMINAL_EVENT_REJECTED")

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
    ) -> NoReturn:
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


def _observation_payload(response: Mapping[str, object]) -> dict[str, object]:
    """Project bounded run status without forwarding an unlimited response body."""

    payload: dict[str, object] = {
        "run_id": response.get("run_id"),
        "status": response.get("status"),
    }
    output = response.get("output")
    if isinstance(output, str):
        payload["output"] = output[:8_000]
        payload["output_truncated"] = len(output) > 8_000
    error = response.get("error")
    if isinstance(error, str):
        payload["error"] = error[:1_000]
    error_code = response.get("error_code")
    if isinstance(error_code, str):
        payload["error_code"] = error_code[:100]
    usage = response.get("usage")
    if isinstance(usage, dict):
        payload["usage"] = {
            key: value
            for key in ("input_tokens", "output_tokens", "total_tokens")
            if isinstance((value := usage.get(key)), (int, float))
        }
    return payload


def _provider_events(
    response: Mapping[str, object],
    external_run_id: str,
) -> tuple[HermesProviderEvent, ...]:
    raw_events = response.get("events", [])
    if not isinstance(raw_events, list) or len(raw_events) > 100:
        raise HermesRuntimeError("HERMES_RESPONSE_INVALID")
    events: list[HermesProviderEvent] = []
    for raw in raw_events:
        if not isinstance(raw, dict):
            raise HermesRuntimeError("HERMES_RESPONSE_INVALID")
        try:
            event = HermesProviderEvent.model_validate(
                {
                    "provider_event_id": raw.get("event_id"),
                    "external_run_id": external_run_id,
                    "sequence": raw.get("sequence"),
                    "event_type": raw.get("type"),
                    "payload": raw.get("payload"),
                }
            )
        except ValueError:
            raise HermesRuntimeError("HERMES_RESPONSE_INVALID") from None
        if event.event_type in {HermesEventType.COMPLETED, HermesEventType.FAILED}:
            raise HermesRuntimeError("HERMES_RESPONSE_INVALID")
        events.append(event)
    ordered = tuple(sorted(events, key=lambda event: event.sequence))
    if any(
        left.sequence == right.sequence
        for left, right in zip(ordered, ordered[1:], strict=False)
    ):
        raise HermesRuntimeError("HERMES_RESPONSE_INVALID")
    return ordered
