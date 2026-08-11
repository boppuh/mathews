"""Canonical redacted evidence capture, access, correction, and deletion."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal, cast
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Response, status
from mathews_configuration import SecretValue
from pydantic import BaseModel, ConfigDict
from sqlalchemy import exists, select
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mathews_control_plane.artifacts import ArtifactStore, ArtifactStoreError
from mathews_control_plane.authentication import (
    AuthenticatedSession,
    RecentPasswordSession,
    require_authenticated_session,
)
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    EvidenceAuditEvent,
    EvidenceDeletionRequest,
    EvidenceDerivative,
    EvidenceRecord,
    EvidenceTombstone,
    Task,
)

type JsonScalar = None | bool | int | float | str
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]

EVIDENCE_ENVELOPE_SCHEMA_VERSION = 1
EVIDENCE_REDACTION_POLICY_VERSION = "mvp-1"
MAX_EVIDENCE_BYTES = 1024 * 1024
MAX_EVIDENCE_DEPTH = 32
MAX_EVIDENCE_NODES = 100_000
MAX_EVIDENCE_REQUEST_BYTES = MAX_EVIDENCE_BYTES + 64 * 1024

_LOCAL_USER_ID = 1
_LOCAL_OWNER_ID = "local-user"
_DIGEST_PREFIX = "sha256:"
_METADATA_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]*\Z")
_ENVELOPE_KEYS = {
    "access_classification",
    "actor_id",
    "captured_at",
    "causation_id",
    "content",
    "content_hash",
    "correction_of_id",
    "evidence_id",
    "evidence_type",
    "media_type",
    "origin",
    "owner_id",
    "parent_correlation_id",
    "redaction_manifest",
    "redaction_policy_version",
    "retention_policy",
    "root_correlation_id",
    "schema_version",
    "source_kind",
    "task_id",
    "validation_run_id",
}
_DERIVATIVE_ENVELOPE_KEYS = {
    "captured_at",
    "content",
    "content_hash",
    "derivative_id",
    "derivative_type",
    "evidence_id",
    "media_type",
    "redaction_policy_version",
    "schema_version",
    "source_envelope_hash",
}
_SENSITIVE_KEY_FRAGMENTS = frozenset(
    {
        "accesstoken",
        "apikey",
        "authorization",
        "clientsecret",
        "cookie",
        "credential",
        "passphrase",
        "password",
        "privatekey",
        "pwd",
        "refreshtoken",
        "secret",
        "sessiontoken",
        "token",
    }
)
_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?"
    r"-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
    re.DOTALL,
)
_AUTHORIZATION = re.compile(r"(?i)\b((?:proxy-)?authorization\s*:\s*)[^\r\n]+")
_COOKIE = re.compile(r"(?i)\b((?:set-)?cookie\s*:\s*)[^\r\n]+")
_URL_CREDENTIALS = re.compile(
    r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^@\s/]+)@"
)
_SENSITIVE_NAME_PATTERN = (
    r"(?:access[_-]?token|api[_-]?key|client[_-]?secret|gh[_-]?token|"
    r"authorization|cookie|passphrase|password|private[_-]?key|pwd|"
    r"refresh[_-]?token|secret|session[_-]?token|token)"
)
_SENSITIVE_FIELD_PATTERN = (
    rf"(?:[A-Za-z0-9]+[_-])*{_SENSITIVE_NAME_PATTERN}"
)
_SENSITIVE_QUERY = re.compile(
    rf"(?i)([?&]{_SENSITIVE_FIELD_PATTERN}=)[^&#\s]*"
)
_AUTHORIZATION_ASSIGNMENT = re.compile(
    r"(?i)\b(((?:[A-Za-z0-9]+[_-])*authorization)\s*=\s*)[^\r\n]+"
)
_SENSITIVE_ASSIGNMENT = re.compile(
    rf"(?i)(?<![?&])\b(({_SENSITIVE_FIELD_PATTERN})"
    rf"\s*[:=]\s*)(?!\[REDACTED:)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_OPAQUE_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|"
    r"AKIA[A-Z0-9]{16})\b"
)
_JWT = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")
_PHONE = re.compile(r"(?<!\w)(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\w)")


class EvidenceSourceKind(StrEnum):
    REQUEST = "REQUEST"
    TOOL_OPERATION = "TOOL_OPERATION"
    REPOSITORY_SNAPSHOT = "REPOSITORY_SNAPSHOT"
    EXTERNAL_EVENT = "EXTERNAL_EVENT"
    RESULT = "RESULT"


class EvidenceAccessClass(StrEnum):
    TASK_OWNER = "TASK_OWNER"
    OWNER = "OWNER"
    RECENT_PASSWORD = "RECENT_PASSWORD"
    INTERNAL = "INTERNAL"


class EvidenceRetentionClass(StrEnum):
    TASK_LIFETIME = "TASK_LIFETIME"
    REPOSITORY_LIFETIME = "REPOSITORY_LIFETIME"
    AUDIT = "AUDIT"


class EvidenceAuditEventType(StrEnum):
    CAPTURED = "CAPTURED"
    METADATA_READ = "METADATA_READ"
    CONTENT_DOWNLOADED = "CONTENT_DOWNLOADED"
    CORRECTION_CREATED = "CORRECTION_CREATED"
    DELETION_REQUESTED = "DELETION_REQUESTED"
    CONTENT_DESTROYED = "CONTENT_DESTROYED"
    DERIVATIVE_REGISTERED = "DERIVATIVE_REGISTERED"


class EvidenceDeletionReason(StrEnum):
    USER_REQUEST = "USER_REQUEST"
    RETENTION_EXPIRED = "RETENTION_EXPIRED"
    SOURCE_REVOKED = "SOURCE_REVOKED"
    SECURITY_RESPONSE = "SECURITY_RESPONSE"


class EvidenceError(RuntimeError):
    """Base class for safe evidence-domain failures."""


class EvidenceNotFoundError(EvidenceError):
    """Raised when evidence is absent or intentionally not enumerable."""


class EvidenceConflictError(EvidenceError):
    """Raised when an immutable evidence operation conflicts."""


class EvidenceValidationError(EvidenceError):
    """Raised when content cannot pass the fixed evidence policy."""


@dataclass(frozen=True, slots=True)
class RedactedContent:
    """Canonical redacted content ready to enter the evidence envelope."""

    value: JsonValue
    media_type: Literal["application/json", "text/plain; charset=utf-8"]
    canonical_bytes: bytes
    content_hash: str
    manifest: dict[str, int]


@dataclass(frozen=True, slots=True)
class CapturedEvidence:
    """Persisted evidence metadata without exposing its content."""

    record: EvidenceRecord
    envelope_address: str
    content_hash: str
    redaction_manifest: dict[str, int]


@dataclass(frozen=True, slots=True)
class LoadedEvidence:
    """A verified live canonical envelope and its redacted content."""

    record: EvidenceRecord
    envelope: dict[str, JsonValue]
    content: JsonValue
    content_bytes: bytes
    media_type: str


@dataclass(frozen=True, slots=True)
class LoadedEvidenceDerivative:
    """Verified live derivative content bound to its canonical source."""

    derivative: EvidenceDerivative
    source_record: EvidenceRecord
    envelope: dict[str, JsonValue]
    content: JsonValue
    content_bytes: bytes
    media_type: str


@dataclass(frozen=True, slots=True)
class EvidenceDownload:
    content: bytes
    media_type: str
    filename: str


@dataclass(frozen=True, slots=True)
class EvidenceMetadata:
    evidence_id: UUID
    task_id: UUID | None
    validation_run_id: UUID | None
    evidence_type: str
    source_kind: str
    captured_at: datetime
    access_classification: str
    retention_policy: str
    content_hash: str
    correction_of_id: UUID | None


Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return _as_utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _digest(payload: bytes) -> str:
    return f"{_DIGEST_PREFIX}{hashlib.sha256(payload).hexdigest()}"


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise EvidenceValidationError("evidence content is not canonical JSON") from None


def _required_text(value: str, *, field: str, maximum: int) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise EvidenceValidationError(f"{field} is invalid")
    return normalized


def _required_metadata_identifier(
    value: str,
    *,
    field: str,
    maximum: int,
) -> str:
    normalized = _required_text(value, field=field, maximum=maximum)
    if (
        _METADATA_IDENTIFIER.fullmatch(normalized) is None
        or "://" in normalized
        or "//" in normalized
        or ".." in normalized
        or normalized.startswith("/")
        or _OPAQUE_TOKEN.search(normalized) is not None
        or _JWT.search(normalized) is not None
        or _SENSITIVE_ASSIGNMENT.search(normalized) is not None
    ):
        raise EvidenceValidationError(f"{field} is invalid")
    return normalized


def _increment(counts: dict[str, int], rule: str, amount: int = 1) -> None:
    if amount:
        counts[rule] = counts.get(rule, 0) + amount


def _replace_pattern(
    pattern: re.Pattern[str],
    value: str,
    replacement: str | Callable[[re.Match[str]], str],
    *,
    rule: str,
    counts: dict[str, int],
) -> str:
    replaced, count = pattern.subn(replacement, value)
    _increment(counts, rule, count)
    return replaced


def _redact_text(
    value: str,
    *,
    secrets: Sequence[SecretValue],
    counts: dict[str, int],
) -> str:
    redacted = value.replace("\r\n", "\n").replace("\r", "\n")
    secret_values = sorted(
        {secret.reveal() for secret in secrets},
        key=len,
        reverse=True,
    )
    for secret in secret_values:
        occurrences = redacted.count(secret)
        if occurrences:
            redacted = redacted.replace(secret, "[REDACTED:KNOWN_SECRET]")
            _increment(counts, "known-secret", occurrences)
    redacted = _replace_pattern(
        _PEM_PRIVATE_KEY,
        redacted,
        "[REDACTED:PRIVATE_KEY]",
        rule="private-key",
        counts=counts,
    )
    redacted = _replace_pattern(
        _AUTHORIZATION,
        redacted,
        lambda match: f"{match.group(1)}[REDACTED:AUTHORIZATION]",
        rule="authorization",
        counts=counts,
    )
    redacted = _replace_pattern(
        _AUTHORIZATION_ASSIGNMENT,
        redacted,
        lambda match: f"{match.group(1)}[REDACTED:AUTHORIZATION]",
        rule="authorization-assignment",
        counts=counts,
    )
    redacted = _replace_pattern(
        _COOKIE,
        redacted,
        lambda match: f"{match.group(1)}[REDACTED:COOKIE]",
        rule="cookie",
        counts=counts,
    )
    redacted = _replace_pattern(
        _URL_CREDENTIALS,
        redacted,
        lambda match: f"{match.group(1)}[REDACTED:CREDENTIALS]@",
        rule="url-credentials",
        counts=counts,
    )
    redacted = _replace_pattern(
        _SENSITIVE_QUERY,
        redacted,
        lambda match: f"{match.group(1)}[REDACTED:QUERY_SECRET]",
        rule="query-secret",
        counts=counts,
    )
    redacted = _replace_pattern(
        _SENSITIVE_ASSIGNMENT,
        redacted,
        lambda match: f"{match.group(1)}[REDACTED:ASSIGNED_SECRET]",
        rule="assigned-secret",
        counts=counts,
    )
    redacted = _replace_pattern(
        _OPAQUE_TOKEN,
        redacted,
        "[REDACTED:OPAQUE_TOKEN]",
        rule="opaque-token",
        counts=counts,
    )
    redacted = _replace_pattern(
        _JWT,
        redacted,
        "[REDACTED:JWT]",
        rule="jwt",
        counts=counts,
    )
    redacted = _replace_pattern(
        _EMAIL,
        redacted,
        "[REDACTED:EMAIL]",
        rule="email",
        counts=counts,
    )
    return _replace_pattern(
        _PHONE,
        redacted,
        "[REDACTED:PHONE]",
        rule="phone",
        counts=counts,
    )


def _sensitive_key(key: str) -> bool:
    normalized = "".join(character.lower() for character in key if character.isalnum())
    return any(fragment in normalized for fragment in _SENSITIVE_KEY_FRAGMENTS)


def _redact_json_value(
    value: object,
    *,
    secrets: Sequence[SecretValue],
    counts: dict[str, int],
    depth: int,
    nodes: list[int],
) -> JsonValue:
    if depth > MAX_EVIDENCE_DEPTH:
        raise EvidenceValidationError("evidence content exceeds the nesting limit")
    nodes[0] += 1
    if nodes[0] > MAX_EVIDENCE_NODES:
        raise EvidenceValidationError("evidence content exceeds the node limit")

    if isinstance(value, SecretValue):
        _increment(counts, "secret-value")
        return "[REDACTED:KNOWN_SECRET]"
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise EvidenceValidationError("evidence content contains a non-finite number")
        return value
    if isinstance(value, str):
        return _redact_text(value, secrets=secrets, counts=counts)
    if isinstance(value, Mapping):
        result: dict[str, JsonValue] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise EvidenceValidationError("evidence object keys must be strings")
            if key in result:
                raise EvidenceValidationError("evidence object contains a duplicate key")
            if _sensitive_key(key):
                result[key] = "[REDACTED:SENSITIVE_FIELD]"
                _increment(counts, "sensitive-field")
            else:
                result[key] = _redact_json_value(
                    child,
                    secrets=secrets,
                    counts=counts,
                    depth=depth + 1,
                    nodes=nodes,
                )
        return result
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray | str):
        return [
            _redact_json_value(
                child,
                secrets=secrets,
                counts=counts,
                depth=depth + 1,
                nodes=nodes,
            )
            for child in value
        ]
    raise EvidenceValidationError("evidence content uses an unsupported value type")


def redact_evidence_content(
    payload: object,
    *,
    media_type: Literal["application/json", "text/plain; charset=utf-8"],
    secrets: Sequence[SecretValue] = (),
) -> RedactedContent:
    """Apply the fixed deterministic policy before any persistent operation."""

    counts: dict[str, int] = {}
    if media_type == "application/json":
        value = _redact_json_value(
            payload,
            secrets=secrets,
            counts=counts,
            depth=0,
            nodes=[0],
        )
        canonical_bytes = _canonical_json_bytes(value)
    else:
        if isinstance(payload, SecretValue):
            _increment(counts, "secret-value")
            value = "[REDACTED:KNOWN_SECRET]"
        elif isinstance(payload, bytes):
            try:
                decoded = payload.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                raise EvidenceValidationError(
                    "text evidence must contain valid UTF-8"
                ) from None
            value = _redact_text(decoded, secrets=secrets, counts=counts)
        elif isinstance(payload, str):
            value = _redact_text(payload, secrets=secrets, counts=counts)
        else:
            raise EvidenceValidationError("text evidence must be text or UTF-8 bytes")
        canonical_bytes = value.encode("utf-8")

    if len(canonical_bytes) > MAX_EVIDENCE_BYTES:
        raise EvidenceValidationError("evidence content exceeds the size limit")
    return RedactedContent(
        value=value,
        media_type=media_type,
        canonical_bytes=canonical_bytes,
        content_hash=_digest(canonical_bytes),
        manifest=dict(sorted(counts.items())),
    )


def capture_evidence(
    session: Session,
    artifact_store: ArtifactStore,
    *,
    payload: object,
    media_type: Literal["application/json", "text/plain; charset=utf-8"],
    source_kind: EvidenceSourceKind,
    evidence_type: str,
    origin: str,
    access_classification: EvidenceAccessClass,
    retention_policy: EvidenceRetentionClass,
    owner_id: str,
    actor_id: str,
    root_correlation_id: UUID,
    task_id: UUID | None = None,
    validation_run_id: UUID | None = None,
    causation_id: UUID | None = None,
    parent_correlation_id: UUID | None = None,
    correction_of_id: UUID | None = None,
    evidence_id: UUID | None = None,
    captured_at: datetime | None = None,
    secrets: Sequence[SecretValue] = (),
) -> CapturedEvidence:
    """Redact, envelope, store, and stage one immutable evidence record."""

    normalized_owner = _required_metadata_identifier(
        owner_id,
        field="owner id",
        maximum=255,
    )
    normalized_actor = _required_metadata_identifier(
        actor_id,
        field="actor id",
        maximum=255,
    )
    normalized_type = _required_metadata_identifier(
        evidence_type,
        field="evidence type",
        maximum=100,
    )
    normalized_origin = _required_metadata_identifier(
        origin,
        field="origin",
        maximum=500,
    )
    if correction_of_id is not None:
        original = session.scalar(
            select(EvidenceRecord)
            .where(EvidenceRecord.id == correction_of_id)
            .with_for_update()
        )
        if (
            original is None
            or original.deleted_at is not None
            or evidence_id == correction_of_id
            or session.scalar(
                select(
                    exists().where(
                        EvidenceDeletionRequest.evidence_id == correction_of_id
                    )
                )
            )
            or session.scalar(
                select(exists().where(EvidenceRecord.correction_of_id == correction_of_id))
            )
            or original.task_id != task_id
            or original.validation_run_id != validation_run_id
            or original.evidence_type != normalized_type
            or original.owner_id != normalized_owner
            or original.access_classification != access_classification.value
            or original.retention_policy != retention_policy.value
        ):
            raise EvidenceConflictError("evidence correction lineage is invalid")
        loaded_original = load_evidence(session, artifact_store, original)
        if (
            loaded_original.media_type != media_type
            or loaded_original.envelope.get("source_kind") != source_kind.value
        ):
            raise EvidenceConflictError("evidence correction format is invalid")
    prepared = redact_evidence_content(payload, media_type=media_type, secrets=secrets)
    record_id = evidence_id or uuid4()
    capture_time = _as_utc(captured_at or _utc_now())
    envelope: dict[str, object] = {
        "schema_version": EVIDENCE_ENVELOPE_SCHEMA_VERSION,
        "evidence_id": str(record_id),
        "source_kind": source_kind.value,
        "evidence_type": normalized_type,
        "origin": normalized_origin,
        "captured_at": _timestamp(capture_time),
        "task_id": None if task_id is None else str(task_id),
        "validation_run_id": (
            None if validation_run_id is None else str(validation_run_id)
        ),
        "owner_id": normalized_owner,
        "actor_id": normalized_actor,
        "root_correlation_id": str(root_correlation_id),
        "causation_id": None if causation_id is None else str(causation_id),
        "parent_correlation_id": (
            None if parent_correlation_id is None else str(parent_correlation_id)
        ),
        "correction_of_id": (
            None if correction_of_id is None else str(correction_of_id)
        ),
        "access_classification": access_classification.value,
        "retention_policy": retention_policy.value,
        "media_type": prepared.media_type,
        "redaction_policy_version": EVIDENCE_REDACTION_POLICY_VERSION,
        "redaction_manifest": prepared.manifest,
        "content_hash": prepared.content_hash,
        "content": prepared.value,
    }
    artifact = artifact_store.put_bytes(_canonical_json_bytes(envelope))
    record = EvidenceRecord(
        id=record_id,
        task_id=task_id,
        validation_run_id=validation_run_id,
        evidence_type=normalized_type,
        origin=normalized_origin,
        content_hash=artifact.address,
        content_address=artifact.address,
        captured_at=capture_time,
        access_classification=access_classification.value,
        retention_policy=retention_policy.value,
        correction_of_id=correction_of_id,
        owner_id=normalized_owner,
        actor_id=normalized_actor,
        root_correlation_id=root_correlation_id,
        causation_id=causation_id,
        parent_correlation_id=parent_correlation_id,
    )
    session.add(record)
    session.flush()
    if correction_of_id is not None and normalized_type == "task-request":
        if task_id is None:
            raise EvidenceConflictError("task request correction lacks a task")
        task = session.scalar(
            select(Task).where(Task.id == task_id).with_for_update()
        )
        if task is None or task.raw_request != f"evidence://{correction_of_id}":
            raise EvidenceConflictError("task request projection is not current")
        task.raw_request = f"evidence://{record.id}"
        task.summary = "Corrected task request"
    _append_event(
        session,
        record=record,
        event_type=EvidenceAuditEventType.CAPTURED,
        actor_id=normalized_actor,
        occurred_at=capture_time,
        details={
            "media_type": prepared.media_type,
            "source_kind": source_kind.value,
        },
    )
    return CapturedEvidence(
        record=record,
        envelope_address=artifact.address,
        content_hash=prepared.content_hash,
        redaction_manifest=prepared.manifest,
    )


def _decode_json_object(payload: bytes) -> dict[str, JsonValue]:
    def reject_duplicates(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise EvidenceValidationError("evidence envelope is invalid") from None
    if not isinstance(value, dict):
        raise EvidenceValidationError("evidence envelope is invalid")
    return cast(dict[str, JsonValue], value)


def _optional_uuid(value: JsonValue) -> UUID | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise EvidenceValidationError("evidence envelope metadata is invalid")
    try:
        return UUID(value)
    except ValueError:
        raise EvidenceValidationError("evidence envelope metadata is invalid") from None


def _canonical_content_bytes(media_type: str, content: JsonValue) -> bytes:
    if media_type == "application/json":
        return _canonical_json_bytes(content)
    if media_type == "text/plain; charset=utf-8" and isinstance(content, str):
        return content.encode("utf-8")
    raise EvidenceValidationError("evidence envelope media type is invalid")


def load_evidence(
    session: Session,
    artifact_store: ArtifactStore,
    record: EvidenceRecord,
) -> LoadedEvidence:
    """Verify and decode a live canonical envelope for an internal caller."""

    if (
        record.content_address is None
        or record.deleted_at is not None
        or session.scalar(
            select(exists().where(EvidenceDeletionRequest.evidence_id == record.id))
        )
    ):
        raise EvidenceNotFoundError("evidence is unavailable")
    try:
        payload = artifact_store.get_bytes(record.content_address)
    except (ArtifactStoreError, ValueError):
        raise EvidenceNotFoundError("evidence is unavailable") from None
    envelope = _decode_json_object(payload)
    if (
        set(envelope) != _ENVELOPE_KEYS
        or envelope.get("schema_version") != EVIDENCE_ENVELOPE_SCHEMA_VERSION
        or envelope.get("redaction_policy_version")
        != EVIDENCE_REDACTION_POLICY_VERSION
        or _canonical_json_bytes(envelope) != payload
        or record.content_hash != record.content_address
        or record.content_hash != _digest(payload)
        or envelope.get("evidence_id") != str(record.id)
        or envelope.get("evidence_type") != record.evidence_type
        or envelope.get("origin") != record.origin
        or envelope.get("captured_at") != _timestamp(record.captured_at)
        or _optional_uuid(envelope.get("task_id")) != record.task_id
        or _optional_uuid(envelope.get("validation_run_id"))
        != record.validation_run_id
        or envelope.get("owner_id") != record.owner_id
        or envelope.get("actor_id") != record.actor_id
        or envelope.get("root_correlation_id") != str(record.root_correlation_id)
        or _optional_uuid(envelope.get("causation_id")) != record.causation_id
        or _optional_uuid(envelope.get("parent_correlation_id"))
        != record.parent_correlation_id
        or _optional_uuid(envelope.get("correction_of_id"))
        != record.correction_of_id
        or envelope.get("access_classification") != record.access_classification
        or envelope.get("retention_policy") != record.retention_policy
    ):
        raise EvidenceValidationError("evidence envelope metadata is invalid")
    media_type = envelope.get("media_type")
    content = envelope.get("content")
    content_hash = envelope.get("content_hash")
    if not isinstance(media_type, str) or not isinstance(content_hash, str):
        raise EvidenceValidationError("evidence envelope content metadata is invalid")
    content_bytes = _canonical_content_bytes(media_type, content)
    if content_hash != _digest(content_bytes):
        raise EvidenceValidationError("evidence envelope content hash is invalid")
    return LoadedEvidence(
        record=record,
        envelope=envelope,
        content=content,
        content_bytes=content_bytes,
        media_type=media_type,
    )


def load_evidence_derivative(
    session: Session,
    artifact_store: ArtifactStore,
    derivative: EvidenceDerivative,
) -> LoadedEvidenceDerivative:
    """Verify a live derivative and its binding to a live canonical source."""

    if derivative.content_address is None or derivative.deleted_at is not None:
        raise EvidenceNotFoundError("evidence derivative is unavailable")
    source = _live_record(session, derivative.evidence_id, for_update=False)
    try:
        payload = artifact_store.get_bytes(derivative.content_address)
    except (ArtifactStoreError, ValueError):
        raise EvidenceNotFoundError("evidence derivative is unavailable") from None
    envelope = _decode_json_object(payload)
    if (
        set(envelope) != _DERIVATIVE_ENVELOPE_KEYS
        or envelope.get("schema_version") != 1
        or envelope.get("redaction_policy_version")
        != EVIDENCE_REDACTION_POLICY_VERSION
        or _canonical_json_bytes(envelope) != payload
        or derivative.content_hash != derivative.content_address
        or derivative.content_hash != _digest(payload)
        or envelope.get("derivative_id") != str(derivative.id)
        or envelope.get("evidence_id") != str(derivative.evidence_id)
        or envelope.get("derivative_type") != derivative.derivative_type
        or envelope.get("captured_at") != _timestamp(derivative.captured_at)
        or envelope.get("source_envelope_hash") != source.content_hash
    ):
        raise EvidenceValidationError("evidence derivative metadata is invalid")
    media_type = envelope.get("media_type")
    content = envelope.get("content")
    content_hash = envelope.get("content_hash")
    if not isinstance(media_type, str) or not isinstance(content_hash, str):
        raise EvidenceValidationError("evidence derivative content metadata is invalid")
    content_bytes = _canonical_content_bytes(media_type, content)
    if content_hash != _digest(content_bytes):
        raise EvidenceValidationError("evidence derivative content hash is invalid")
    return LoadedEvidenceDerivative(
        derivative=derivative,
        source_record=source,
        envelope=envelope,
        content=content,
        content_bytes=content_bytes,
        media_type=media_type,
    )


def destroy_evidence_derivative(
    artifact_store: ArtifactStore,
    derivative: EvidenceDerivative,
    *,
    deleted_at: datetime,
) -> bool:
    """Destroy rebuildable derivative bytes and retain a minimal deletion marker."""

    if derivative.deleted_at is not None:
        return False
    address = derivative.content_address
    if address is not None:
        artifact_store.delete_bytes(address)
    derivative.content_address = None
    derivative.deleted_at = _as_utc(deleted_at)
    return True


def _append_event(
    session: Session,
    *,
    record: EvidenceRecord,
    event_type: EvidenceAuditEventType,
    actor_id: str,
    occurred_at: datetime,
    details: Mapping[str, object],
    session_id: UUID | None = None,
) -> EvidenceAuditEvent:
    event = EvidenceAuditEvent(
        evidence_id=record.id,
        event_type=event_type.value,
        session_id=session_id,
        occurred_at=_as_utc(occurred_at),
        details=dict(details),
        owner_id=record.owner_id,
        actor_id=actor_id,
        root_correlation_id=record.root_correlation_id,
        causation_id=record.id,
        parent_correlation_id=record.parent_correlation_id,
    )
    session.add(event)
    session.flush()
    return event


def _principal(authentication: AuthenticatedSession, *, now: datetime) -> str:
    if (
        authentication.user_id != _LOCAL_USER_ID
        or _as_utc(authentication.expires_at) <= now
        or _as_utc(authentication.absolute_expires_at) <= now
    ):
        raise EvidenceNotFoundError("evidence is unavailable")
    return _LOCAL_OWNER_ID


def _authorize(
    session: Session,
    record: EvidenceRecord,
    authentication: AuthenticatedSession,
    *,
    now: datetime,
) -> str:
    principal = _principal(authentication, now=now)
    try:
        access = EvidenceAccessClass(record.access_classification)
    except ValueError:
        raise EvidenceNotFoundError("evidence is unavailable") from None
    if access is EvidenceAccessClass.INTERNAL or record.owner_id != principal:
        raise EvidenceNotFoundError("evidence is unavailable")
    if access is EvidenceAccessClass.RECENT_PASSWORD and not (
        authentication.recent_password_verified
        and _as_utc(authentication.reauthenticated_until) > now
    ):
        raise EvidenceNotFoundError("evidence is unavailable")
    if access is EvidenceAccessClass.TASK_OWNER:
        if record.task_id is None:
            raise EvidenceNotFoundError("evidence is unavailable")
        task_owner = session.scalar(select(Task.owner_id).where(Task.id == record.task_id))
        if task_owner != principal:
            raise EvidenceNotFoundError("evidence is unavailable")
    return principal


def normalize_evidence_timestamp(value: datetime) -> datetime:
    """Normalize a persisted evidence timestamp to an aware UTC value."""

    return _as_utc(value)


def resolve_evidence_principal(
    authentication: AuthenticatedSession,
    *,
    now: datetime,
) -> str:
    """Resolve the local evidence principal without revealing auth failures."""

    return _principal(authentication, now=now)


def authorize_evidence_access(
    session: Session,
    record: EvidenceRecord,
    authentication: AuthenticatedSession,
    *,
    now: datetime,
) -> str:
    """Enforce one canonical evidence record's original access class."""

    return _authorize(session, record, authentication, now=now)


def append_evidence_audit_event(
    session: Session,
    *,
    record: EvidenceRecord,
    event_type: EvidenceAuditEventType,
    actor_id: str,
    occurred_at: datetime,
    details: Mapping[str, object],
    session_id: UUID | None = None,
) -> EvidenceAuditEvent:
    """Append a non-content event through the canonical evidence audit path."""

    return _append_event(
        session,
        record=record,
        event_type=event_type,
        actor_id=actor_id,
        occurred_at=occurred_at,
        details=details,
        session_id=session_id,
    )


def _live_record(
    session: Session,
    evidence_id: UUID,
    *,
    for_update: bool,
) -> EvidenceRecord:
    query = select(EvidenceRecord).where(EvidenceRecord.id == evidence_id)
    if for_update:
        query = query.with_for_update()
    record = session.scalar(query)
    if record is None or record.deleted_at is not None or session.scalar(
        select(exists().where(EvidenceDeletionRequest.evidence_id == evidence_id))
    ):
        raise EvidenceNotFoundError("evidence is unavailable")
    return record


def _source_kind(loaded: LoadedEvidence) -> EvidenceSourceKind:
    value = loaded.envelope.get("source_kind")
    if not isinstance(value, str):
        raise EvidenceValidationError("evidence source kind is invalid")
    try:
        return EvidenceSourceKind(value)
    except ValueError:
        raise EvidenceValidationError("evidence source kind is invalid") from None


def create_correction(
    session: Session,
    artifact_store: ArtifactStore,
    *,
    evidence_id: UUID,
    payload: object,
    media_type: Literal["application/json", "text/plain; charset=utf-8"],
    authentication: AuthenticatedSession,
    now: datetime,
    secrets: Sequence[SecretValue] = (),
) -> CapturedEvidence:
    """Append one successor while leaving the corrected row and bytes untouched."""

    record = _live_record(session, evidence_id, for_update=True)
    principal = _authorize(session, record, authentication, now=now)
    if not (
        authentication.recent_password_verified
        and _as_utc(authentication.reauthenticated_until) > now
    ):
        raise EvidenceNotFoundError("evidence is unavailable")
    if session.scalar(
        select(exists().where(EvidenceRecord.correction_of_id == record.id))
    ):
        raise EvidenceConflictError("evidence already has a correction")
    loaded = load_evidence(session, artifact_store, record)
    if loaded.media_type != media_type:
        raise EvidenceConflictError("a correction must preserve the media type")
    correction = capture_evidence(
        session,
        artifact_store,
        payload=payload,
        media_type=media_type,
        source_kind=_source_kind(loaded),
        evidence_type=record.evidence_type,
        origin="local-user:correction",
        access_classification=EvidenceAccessClass(record.access_classification),
        retention_policy=EvidenceRetentionClass(record.retention_policy),
        owner_id=record.owner_id,
        actor_id=principal,
        root_correlation_id=record.root_correlation_id,
        task_id=record.task_id,
        validation_run_id=record.validation_run_id,
        causation_id=record.id,
        parent_correlation_id=record.root_correlation_id,
        correction_of_id=record.id,
        captured_at=now,
        secrets=secrets,
    )
    _append_event(
        session,
        record=record,
        event_type=EvidenceAuditEventType.CORRECTION_CREATED,
        actor_id=principal,
        occurred_at=now,
        details={"correction_id": str(correction.record.id)},
        session_id=authentication.session_id,
    )
    return correction


def register_evidence_derivative(
    session: Session,
    artifact_store: ArtifactStore,
    *,
    evidence_id: UUID,
    derivative_type: str,
    payload: object,
    media_type: Literal["application/json", "text/plain; charset=utf-8"],
    actor_id: str,
    captured_at: datetime | None = None,
    secrets: Sequence[SecretValue] = (),
) -> EvidenceDerivative:
    """Register rebuildable content so source deletion can destroy it."""

    record = _live_record(session, evidence_id, for_update=True)
    now = _as_utc(captured_at or _utc_now())
    normalized_actor = _required_metadata_identifier(
        actor_id,
        field="actor id",
        maximum=255,
    )
    prepared = redact_evidence_content(payload, media_type=media_type, secrets=secrets)
    derivative_id = uuid4()
    derivative_envelope = {
        "schema_version": 1,
        "derivative_id": str(derivative_id),
        "evidence_id": str(record.id),
        "derivative_type": _required_metadata_identifier(
            derivative_type,
            field="derivative type",
            maximum=100,
        ),
        "captured_at": _timestamp(now),
        "source_envelope_hash": record.content_hash,
        "media_type": media_type,
        "redaction_policy_version": EVIDENCE_REDACTION_POLICY_VERSION,
        "content_hash": prepared.content_hash,
        "content": prepared.value,
    }
    artifact = artifact_store.put_bytes(_canonical_json_bytes(derivative_envelope))
    derivative = EvidenceDerivative(
        id=derivative_id,
        evidence_id=record.id,
        derivative_type=derivative_envelope["derivative_type"],
        content_hash=artifact.address,
        content_address=artifact.address,
        captured_at=now,
        owner_id=record.owner_id,
        actor_id=normalized_actor,
        root_correlation_id=record.root_correlation_id,
        causation_id=record.id,
        parent_correlation_id=record.parent_correlation_id,
    )
    session.add(derivative)
    session.flush()
    _append_event(
        session,
        record=record,
        event_type=EvidenceAuditEventType.DERIVATIVE_REGISTERED,
        actor_id=normalized_actor,
        occurred_at=now,
        details={
            "derivative_id": str(derivative.id),
            "derivative_type": derivative.derivative_type,
        },
    )
    return derivative


def _stage_deletion_request(
    session: Session,
    *,
    record: EvidenceRecord,
    actor_id: str,
    reason: EvidenceDeletionReason,
    now: datetime,
    session_id: UUID | None,
) -> EvidenceDeletionRequest:
    existing = session.scalar(
        select(EvidenceDeletionRequest).where(
            EvidenceDeletionRequest.evidence_id == record.id
        )
    )
    if existing is not None:
        return existing
    request = EvidenceDeletionRequest(
        evidence_id=record.id,
        reason_code=reason.value,
        requested_at=now,
        owner_id=record.owner_id,
        actor_id=actor_id,
        root_correlation_id=record.root_correlation_id,
        causation_id=record.id,
        parent_correlation_id=record.parent_correlation_id,
    )
    session.add(request)
    session.flush()
    _append_event(
        session,
        record=record,
        event_type=EvidenceAuditEventType.DELETION_REQUESTED,
        actor_id=actor_id,
        occurred_at=now,
        details={
            "deletion_request_id": str(request.id),
            "reason_code": reason.value,
        },
        session_id=session_id,
    )
    return request


def _request_deletion(
    session: Session,
    *,
    evidence_id: UUID,
    authentication: AuthenticatedSession,
    reason: EvidenceDeletionReason,
    now: datetime,
) -> EvidenceDeletionRequest:
    record = session.scalar(
        select(EvidenceRecord)
        .where(EvidenceRecord.id == evidence_id)
        .with_for_update()
    )
    if record is None or record.deleted_at is not None:
        raise EvidenceNotFoundError("evidence is unavailable")
    principal = _authorize(session, record, authentication, now=now)
    if not (
        authentication.recent_password_verified
        and _as_utc(authentication.reauthenticated_until) > now
    ):
        raise EvidenceNotFoundError("evidence is unavailable")
    return _stage_deletion_request(
        session,
        record=record,
        actor_id=principal,
        reason=reason,
        now=now,
        session_id=authentication.session_id,
    )


def _request_internal_deletion(
    session: Session,
    *,
    evidence_id: UUID,
    actor_id: str,
    reason: EvidenceDeletionReason,
    now: datetime,
) -> EvidenceDeletionRequest:
    """Fence INTERNAL evidence for a trusted retention/security worker."""

    record = session.scalar(
        select(EvidenceRecord)
        .where(EvidenceRecord.id == evidence_id)
        .with_for_update()
    )
    if (
        record is None
        or record.deleted_at is not None
        or record.access_classification != EvidenceAccessClass.INTERNAL.value
    ):
        raise EvidenceNotFoundError("internal evidence is unavailable")
    return _stage_deletion_request(
        session,
        record=record,
        actor_id=_required_metadata_identifier(
            actor_id,
            field="actor id",
            maximum=255,
        ),
        reason=reason,
        now=now,
        session_id=None,
    )


def _finalize_deletion(
    session: Session,
    artifact_store: ArtifactStore,
    *,
    deletion_request_id: UUID,
    now: datetime,
) -> EvidenceTombstone:
    request = session.scalar(
        select(EvidenceDeletionRequest)
        .where(EvidenceDeletionRequest.id == deletion_request_id)
        .with_for_update()
    )
    if request is None:
        raise EvidenceNotFoundError("evidence deletion request is unavailable")
    existing = session.scalar(
        select(EvidenceTombstone).where(
            EvidenceTombstone.deletion_request_id == request.id
        )
    )
    if existing is not None:
        return existing
    record = session.scalar(
        select(EvidenceRecord)
        .where(EvidenceRecord.id == request.evidence_id)
        .with_for_update()
    )
    if record is None:
        raise EvidenceNotFoundError("evidence is unavailable")
    derivatives = list(
        session.scalars(
            select(EvidenceDerivative)
            .where(
                EvidenceDerivative.evidence_id == record.id,
                EvidenceDerivative.deleted_at.is_(None),
            )
            .with_for_update()
        )
    )
    for derivative in derivatives:
        destroy_evidence_derivative(
            artifact_store,
            derivative,
            deleted_at=now,
        )

    if record.evidence_type == "task-request" and record.task_id is not None:
        task = session.scalar(
            select(Task).where(Task.id == record.task_id).with_for_update()
        )
        if task is not None and task.raw_request == f"evidence://{record.id}":
            task.raw_request = f"deleted-evidence://{record.id}"
            task.summary = "Deleted task request"

    if record.content_address is not None:
        another_live_reference = session.scalar(
            select(
                exists().where(
                    EvidenceRecord.id != record.id,
                    EvidenceRecord.content_address == record.content_address,
                    ~exists().where(
                        EvidenceDeletionRequest.evidence_id == EvidenceRecord.id
                    ),
                )
            )
        )
        if not another_live_reference:
            artifact_store.delete_bytes(record.content_address)

    tombstone = EvidenceTombstone(
        evidence_id=record.id,
        deletion_request_id=request.id,
        reason_code=request.reason_code,
        deleted_at=now,
        removed_derivative_count=len(derivatives),
        owner_id=record.owner_id,
        actor_id=request.actor_id,
        root_correlation_id=record.root_correlation_id,
        causation_id=request.id,
        parent_correlation_id=record.parent_correlation_id,
    )
    session.add(tombstone)
    session.flush()
    _append_event(
        session,
        record=record,
        event_type=EvidenceAuditEventType.CONTENT_DESTROYED,
        actor_id=request.actor_id,
        occurred_at=now,
        details={
            "deletion_request_id": str(request.id),
            "removed_derivative_count": len(derivatives),
            "tombstone_id": str(tombstone.id),
        },
    )
    return tombstone


class EvidenceService:
    """Committed transaction boundary used by authenticated API routes."""

    def __init__(
        self,
        factory: SessionFactory,
        artifact_store: ArtifactStore,
        *,
        clock: Clock = _utc_now,
    ) -> None:
        self._factory = factory
        self._artifact_store = artifact_store
        self._clock = clock

    def metadata(
        self,
        evidence_id: UUID,
        authentication: AuthenticatedSession,
    ) -> EvidenceMetadata:
        now = _as_utc(self._clock())
        with self._factory.begin() as session:
            record = _live_record(session, evidence_id, for_update=True)
            principal = _authorize(session, record, authentication, now=now)
            loaded = load_evidence(session, self._artifact_store, record)
            _append_event(
                session,
                record=record,
                event_type=EvidenceAuditEventType.METADATA_READ,
                actor_id=principal,
                occurred_at=now,
                details={},
                session_id=authentication.session_id,
            )
            return EvidenceMetadata(
                evidence_id=record.id,
                task_id=record.task_id,
                validation_run_id=record.validation_run_id,
                evidence_type=record.evidence_type,
                source_kind=_source_kind(loaded).value,
                captured_at=_as_utc(record.captured_at),
                access_classification=record.access_classification,
                retention_policy=record.retention_policy,
                content_hash=cast(str, loaded.envelope["content_hash"]),
                correction_of_id=record.correction_of_id,
            )

    def download(
        self,
        evidence_id: UUID,
        authentication: AuthenticatedSession,
    ) -> EvidenceDownload:
        now = _as_utc(self._clock())
        with self._factory.begin() as session:
            record = _live_record(session, evidence_id, for_update=True)
            principal = _authorize(session, record, authentication, now=now)
            loaded = load_evidence(session, self._artifact_store, record)
            _append_event(
                session,
                record=record,
                event_type=EvidenceAuditEventType.CONTENT_DOWNLOADED,
                actor_id=principal,
                occurred_at=now,
                details={},
                session_id=authentication.session_id,
            )
            extension = "json" if loaded.media_type == "application/json" else "txt"
            return EvidenceDownload(
                content=loaded.content_bytes,
                media_type=loaded.media_type,
                filename=f"evidence-{record.id}.{extension}",
            )

    def correct(
        self,
        evidence_id: UUID,
        payload: object,
        media_type: Literal["application/json", "text/plain; charset=utf-8"],
        authentication: AuthenticatedSession,
    ) -> CapturedEvidence:
        with self._factory.begin() as session:
            return create_correction(
                session,
                self._artifact_store,
                evidence_id=evidence_id,
                payload=payload,
                media_type=media_type,
                authentication=authentication,
                now=_as_utc(self._clock()),
            )

    def delete(
        self,
        evidence_id: UUID,
        authentication: AuthenticatedSession,
        reason: EvidenceDeletionReason,
    ) -> EvidenceTombstone:
        now = _as_utc(self._clock())
        with self._factory.begin() as session:
            request = _request_deletion(
                session,
                evidence_id=evidence_id,
                authentication=authentication,
                reason=reason,
                now=now,
            )
            request_id = request.id
        with self._factory.begin() as session:
            return _finalize_deletion(
                session,
                self._artifact_store,
                deletion_request_id=request_id,
                now=now,
            )

    def resume_pending_deletions(self, *, limit: int = 100) -> int:
        if limit < 1 or limit > 1000:
            raise ValueError("deletion reconciliation limit is invalid")
        with self._factory() as session:
            pending_ids = list(
                session.scalars(
                    select(EvidenceDeletionRequest.id)
                    .where(
                        ~exists().where(
                            EvidenceTombstone.deletion_request_id
                            == EvidenceDeletionRequest.id
                        )
                    )
                    .order_by(EvidenceDeletionRequest.requested_at)
                    .limit(limit)
                )
            )
        completed = 0
        for request_id in pending_ids:
            with self._factory.begin() as session:
                _finalize_deletion(
                    session,
                    self._artifact_store,
                    deletion_request_id=request_id,
                    now=_as_utc(self._clock()),
                )
            completed += 1
        return completed

    def delete_internal(
        self,
        evidence_id: UUID,
        *,
        actor_id: str,
        reason: EvidenceDeletionReason,
    ) -> EvidenceTombstone:
        """Delete INTERNAL evidence without creating a browser access path."""

        now = _as_utc(self._clock())
        with self._factory.begin() as session:
            request = _request_internal_deletion(
                session,
                evidence_id=evidence_id,
                actor_id=actor_id,
                reason=reason,
                now=now,
            )
            request_id = request.id
        with self._factory.begin() as session:
            return _finalize_deletion(
                session,
                self._artifact_store,
                deletion_request_id=request_id,
                now=now,
            )


AuthenticatedEvidenceSession = Annotated[
    AuthenticatedSession,
    Depends(require_authenticated_session),
]


class EvidenceBodyLimitMiddleware:
    """Bound evidence mutation bodies before request parsing buffers them."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        maximum_bytes: int = MAX_EVIDENCE_REQUEST_BYTES,
    ) -> None:
        self._app = app
        self._maximum_bytes = maximum_bytes

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        path = scope.get("path", "")
        method = scope.get("method", "")
        bounded = (
            scope["type"] == "http"
            and isinstance(path, str)
            and path.startswith("/api/evidence/")
            and (
                (method == "POST" and path.endswith("/corrections"))
                or method == "DELETE"
            )
        )
        if not bounded:
            await self._app(scope, receive, send)
            return

        content_length = self._content_length(scope)
        if content_length is not None and content_length > self._maximum_bytes:
            await self._send_too_large(scope, receive, send)
            return

        received_bytes = 0
        captured_messages: list[Message] = []
        while True:
            message = await receive()
            captured_messages.append(message)
            if message["type"] == "http.disconnect":
                break
            if message["type"] != "http.request":
                continue
            received_bytes += len(message.get("body", b""))
            if received_bytes > self._maximum_bytes:
                await self._send_too_large(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        message_index = 0

        async def replay_receive() -> Message:
            nonlocal message_index
            if message_index < len(captured_messages):
                message = captured_messages[message_index]
                message_index += 1
                return message
            return await receive()

        await self._app(scope, replay_receive, send)

    @staticmethod
    def _content_length(scope: Scope) -> int | None:
        for name, value in scope["headers"]:
            if name.lower() != b"content-length":
                continue
            try:
                parsed = int(value)
            except ValueError:
                return None
            return max(0, parsed)
        return None

    @staticmethod
    async def _send_too_large(
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        response = JSONResponse(
            {"detail": "evidence request body too large"},
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )
        await response(scope, receive, send)


class EvidenceMetadataResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    evidence_id: UUID
    task_id: UUID | None
    validation_run_id: UUID | None
    evidence_type: str
    source_kind: str
    captured_at: datetime
    access_classification: str
    retention_policy: str
    content_hash: str
    correction_of_id: UUID | None


class EvidenceCorrectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    media_type: Literal["application/json", "text/plain; charset=utf-8"]
    content: JsonValue


class EvidenceCorrectionResponse(BaseModel):
    evidence_id: UUID


class EvidenceDeletionRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    reason: EvidenceDeletionReason


def _http_error(error: EvidenceError) -> HTTPException:
    if isinstance(error, EvidenceConflictError):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="evidence operation conflicts with immutable state",
        )
    if isinstance(error, EvidenceValidationError):
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="evidence content is invalid",
        )
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="evidence not found",
    )


def create_evidence_router(service: EvidenceService) -> APIRouter:
    router = APIRouter(prefix="/api/evidence", tags=["evidence"])

    @router.get("/{evidence_id}", response_model=EvidenceMetadataResponse)
    def metadata(
        evidence_id: UUID,
        authentication: AuthenticatedEvidenceSession,
    ) -> EvidenceMetadataResponse:
        try:
            result = service.metadata(evidence_id, authentication)
        except EvidenceError as error:
            raise _http_error(error) from None
        return EvidenceMetadataResponse.model_validate(result)

    @router.get("/{evidence_id}/download")
    def download(
        evidence_id: UUID,
        authentication: AuthenticatedEvidenceSession,
    ) -> Response:
        try:
            result = service.download(evidence_id, authentication)
        except EvidenceError as error:
            raise _http_error(error) from None
        return Response(
            content=result.content,
            media_type=result.media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{result.filename}"',
                "X-Content-Type-Options": "nosniff",
            },
        )

    @router.post(
        "/{evidence_id}/corrections",
        response_model=EvidenceCorrectionResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def correct(
        evidence_id: UUID,
        body: EvidenceCorrectionRequest,
        authentication: RecentPasswordSession,
    ) -> EvidenceCorrectionResponse:
        try:
            result = service.correct(
                evidence_id,
                body.content,
                body.media_type,
                authentication,
            )
        except EvidenceError as error:
            raise _http_error(error) from None
        return EvidenceCorrectionResponse(evidence_id=result.record.id)

    @router.delete("/{evidence_id}", status_code=status.HTTP_204_NO_CONTENT)
    def delete(
        evidence_id: UUID,
        body: EvidenceDeletionRequestBody,
        authentication: RecentPasswordSession,
    ) -> Response:
        try:
            service.delete(evidence_id, authentication, body.reason)
        except EvidenceError as error:
            raise _http_error(error) from None
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return router
