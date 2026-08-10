"""Immutable repository-configuration persistence and preflight readiness."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast
from uuid import UUID, uuid4

from mathews_configuration import (
    RepositoryConfiguration as ValidatedRepositoryConfiguration,
)
from mathews_configuration import (
    RepositoryConfigurationError as SharedRepositoryConfigurationError,
)
from mathews_configuration import (
    RepositoryPreflightReport as ValidatedRepositoryPreflightReport,
)
from sqlalchemy import Select, exists, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.domain_models import EvidenceRecord
from mathews_control_plane.domain_models import (
    RepositoryConfiguration as RepositoryConfigurationRecord,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceError,
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
    load_evidence,
)

_PREFLIGHT_SCHEMA_VERSION = 1
_PREFLIGHT_EVIDENCE_TYPE = "repository-preflight"
_PREFLIGHT_ORIGIN = "host-agent:repository-preflight"
_PREFLIGHT_REQUEST_EVIDENCE_TYPE = "repository-preflight-request"
_PREFLIGHT_REQUEST_ORIGIN = "control-plane:repository-preflight-request"
_PREFLIGHT_ACCESS_CLASSIFICATION = EvidenceAccessClass.INTERNAL
_PREFLIGHT_RETENTION_POLICY = EvidenceRetentionClass.REPOSITORY_LIFETIME
_DIGEST_PREFIX = "sha256:"
_PREFLIGHT_KEYS = {
    "schema_version",
    "attempt_id",
    "configuration_id",
    "repository_key",
    "configuration_version",
    "configuration_digest",
    "status",
    "checks",
    "resolved_base_sha",
}
_PREFLIGHT_REQUEST_KEYS = {
    "schema_version",
    "attempt_id",
    "configuration_id",
    "repository_key",
    "configuration_version",
    "configuration_digest",
}


class RepositoryConfigurationError(RuntimeError):
    """Base class for repository-configuration service failures."""


class RepositoryConfigurationConflictError(RepositoryConfigurationError):
    """A concurrent writer claimed the next repository version."""


class RepositoryConfigurationNotFoundError(RepositoryConfigurationError):
    """The requested repository configuration does not exist."""


class RepositoryPreflightBindingError(RepositoryConfigurationError):
    """A host report does not bind to the authoritative configuration."""


class RepositoryPreflightNotReadyError(RepositoryConfigurationError):
    """The authoritative repository configuration is not safe to execute."""


@dataclass(frozen=True, slots=True)
class RepositoryPreflightBinding:
    """Exact immutable values that authorize work against one base revision."""

    configuration_id: UUID
    repository_key: str
    configuration_version: int
    configuration_digest: str
    resolved_base_sha: str


@dataclass(frozen=True, slots=True)
class CapturedRepositoryPreflightBinding:
    """Exact report binding, which may lack a base SHA when blocked."""

    attempt_id: UUID
    configuration_id: UUID
    repository_key: str
    configuration_version: int
    configuration_digest: str
    resolved_base_sha: str | None


@dataclass(frozen=True, slots=True)
class CapturedRepositoryPreflight:
    """Metadata for a persisted canonical host preflight report."""

    binding: CapturedRepositoryPreflightBinding
    status: str
    evidence_id: UUID
    evidence_address: str


@dataclass(frozen=True, slots=True)
class RepositoryPreflightAttempt:
    """Control-plane-issued attempt that fences delayed or replayed reports."""

    attempt_id: UUID
    configuration_id: UUID
    repository_key: str
    configuration_version: int
    configuration_digest: str
    evidence_address: str


@dataclass(frozen=True, slots=True)
class RepositoryPreflightReadiness:
    """Verified authorization to create a workspace for an exact binding."""

    binding: RepositoryPreflightBinding
    evidence_id: UUID
    evidence_address: str


def create_repository_configuration(
    session: Session,
    *,
    repository_key: str,
    repository_settings: Mapping[str, object],
    git_settings: Mapping[str, object],
    xcode_settings: Mapping[str, object],
    operations: Sequence[object],
    e2e_assertions: Sequence[object],
    artifact_settings: Mapping[str, object],
    prohibited_paths: Sequence[object],
    secret_references: Sequence[object],
    owner_id: str,
    actor_id: str,
    root_correlation_id: UUID,
    causation_id: UUID | None = None,
    parent_correlation_id: UUID | None = None,
) -> RepositoryConfigurationRecord:
    """Allocate and persist the next immutable version for a repository."""

    normalized_repository_key = _required_text(
        repository_key,
        field="repository key",
        maximum=500,
    )
    normalized_owner_id = _required_text(owner_id, field="owner id", maximum=255)
    normalized_actor_id = _required_text(actor_id, field="actor id", maximum=255)

    latest = _latest_query(normalized_repository_key, for_update=True)
    predecessor = session.scalar(latest)
    configuration_id = uuid4()
    version = 1 if predecessor is None else predecessor.version + 1
    validated = ValidatedRepositoryConfiguration.from_dict(
        configuration_id,
        {
            "repository_key": normalized_repository_key,
            "version": version,
            "repository_settings": repository_settings,
            "git_settings": git_settings,
            "xcode_settings": xcode_settings,
            "operations": operations,
            "e2e_assertions": e2e_assertions,
            "artifact_settings": artifact_settings,
            "prohibited_paths": prohibited_paths,
            "secret_references": secret_references,
        },
    )
    persisted = validated.to_dict()
    configuration = RepositoryConfigurationRecord(
        id=configuration_id,
        repository_key=validated.repository_key,
        version=validated.version,
        predecessor_id=None if predecessor is None else predecessor.id,
        repository_settings=cast(dict[str, object], persisted["repository_settings"]),
        git_settings=cast(dict[str, object], persisted["git_settings"]),
        xcode_settings=cast(dict[str, object], persisted["xcode_settings"]),
        operations=cast(list[object], persisted["operations"]),
        e2e_assertions=cast(list[object], persisted["e2e_assertions"]),
        artifact_settings=cast(dict[str, object], persisted["artifact_settings"]),
        prohibited_paths=cast(list[object], persisted["prohibited_paths"]),
        secret_references=cast(list[object], persisted["secret_references"]),
        owner_id=normalized_owner_id,
        actor_id=normalized_actor_id,
        root_correlation_id=root_correlation_id,
        causation_id=causation_id,
        parent_correlation_id=parent_correlation_id,
    )

    try:
        with session.begin_nested():
            session.add(configuration)
            session.flush()
    except IntegrityError:
        raise RepositoryConfigurationConflictError(
            "repository configuration version allocation conflicted; retry the transaction"
        ) from None

    return configuration


def get_latest_repository_configuration(
    session: Session,
    repository_key: str,
    *,
    for_update: bool = False,
) -> RepositoryConfigurationRecord | None:
    """Return the authoritative highest version, regardless of its readiness."""

    normalized_repository_key = _required_text(
        repository_key,
        field="repository key",
        maximum=500,
    )
    return session.scalar(
        _latest_query(normalized_repository_key, for_update=for_update)
    )


def repository_configuration_digest(configuration: RepositoryConfigurationRecord) -> str:
    """Hash the host/control-plane canonical execution-configuration payload."""

    return _validated_configuration(configuration).digest


def validated_repository_configuration(
    configuration: RepositoryConfigurationRecord,
) -> ValidatedRepositoryConfiguration:
    """Return the canonical shared configuration for a persisted version."""

    return _validated_configuration(configuration)


def get_repository_preflight_report(
    session: Session,
    artifact_store: ArtifactStore,
    configuration: RepositoryConfigurationRecord,
) -> ValidatedRepositoryPreflightReport | None:
    """Return the attached completed report, or ``None`` for no active report."""

    if configuration.preflight_evidence_id is None:
        return None
    evidence, payload = _load_attached_evidence(session, artifact_store, configuration)
    if evidence.evidence_type == _PREFLIGHT_REQUEST_EVIDENCE_TYPE:
        return None
    repository_key, report = _decode_canonical_report(payload)
    if repository_key != configuration.repository_key:
        raise RepositoryPreflightNotReadyError(
            "preflight evidence repository does not match the configuration"
        )
    _validated_report_binding(configuration, report)
    return report


def _validated_configuration(
    configuration: RepositoryConfigurationRecord,
) -> ValidatedRepositoryConfiguration:
    return ValidatedRepositoryConfiguration.from_dict(
        configuration.id,
        {
            "repository_key": configuration.repository_key,
            "version": configuration.version,
            "repository_settings": configuration.repository_settings,
            "git_settings": configuration.git_settings,
            "xcode_settings": configuration.xcode_settings,
            "operations": configuration.operations,
            "e2e_assertions": configuration.e2e_assertions,
            "artifact_settings": configuration.artifact_settings,
            "prohibited_paths": configuration.prohibited_paths,
            "secret_references": configuration.secret_references,
        },
    )


def begin_preflight_attempt(
    session: Session,
    artifact_store: ArtifactStore,
    *,
    configuration_id: UUID,
    owner_id: str,
    actor_id: str,
    root_correlation_id: UUID,
    requested_at: datetime | None = None,
    causation_id: UUID | None = None,
    parent_correlation_id: UUID | None = None,
) -> RepositoryPreflightAttempt:
    """Issue and persist the only attempt currently allowed to report."""

    configuration = session.scalar(
        select(RepositoryConfigurationRecord)
        .where(RepositoryConfigurationRecord.id == configuration_id)
        .with_for_update()
    )
    if configuration is None:
        raise RepositoryConfigurationNotFoundError("repository configuration not found")
    latest = session.scalar(_latest_query(configuration.repository_key, for_update=True))
    if latest is None or latest.id != configuration.id:
        raise RepositoryPreflightBindingError(
            "preflight attempt must target the authoritative latest configuration"
        )

    configuration_digest = repository_configuration_digest(configuration)
    attempt_id = uuid4()
    request_payload = {
        "schema_version": _PREFLIGHT_SCHEMA_VERSION,
        "attempt_id": str(attempt_id),
        "configuration_id": str(configuration.id),
        "repository_key": configuration.repository_key,
        "configuration_version": configuration.version,
        "configuration_digest": configuration_digest,
    }
    captured = capture_evidence(
        session,
        artifact_store,
        payload=request_payload,
        media_type="application/json",
        source_kind=EvidenceSourceKind.REQUEST,
        evidence_type=_PREFLIGHT_REQUEST_EVIDENCE_TYPE,
        origin=_PREFLIGHT_REQUEST_ORIGIN,
        access_classification=_PREFLIGHT_ACCESS_CLASSIFICATION,
        retention_policy=_PREFLIGHT_RETENTION_POLICY,
        evidence_id=attempt_id,
        task_id=None,
        validation_run_id=None,
        captured_at=_captured_at(requested_at),
        owner_id=_required_text(owner_id, field="owner id", maximum=255),
        actor_id=_required_text(actor_id, field="actor id", maximum=255),
        root_correlation_id=root_correlation_id,
        causation_id=causation_id,
        parent_correlation_id=parent_correlation_id,
    )
    evidence = captured.record
    configuration.preflight_evidence_id = evidence.id
    session.flush()
    return RepositoryPreflightAttempt(
        attempt_id=attempt_id,
        configuration_id=configuration.id,
        repository_key=configuration.repository_key,
        configuration_version=configuration.version,
        configuration_digest=configuration_digest,
        evidence_address=captured.envelope_address,
    )


def capture_preflight_report(
    session: Session,
    artifact_store: ArtifactStore,
    *,
    report: ValidatedRepositoryPreflightReport | Mapping[str, object],
    owner_id: str,
    actor_id: str,
    root_correlation_id: UUID,
    captured_at: datetime | None = None,
    causation_id: UUID | None = None,
    parent_correlation_id: UUID | None = None,
) -> CapturedRepositoryPreflight:
    """Persist and attach one canonical host report to the latest config."""

    validated_report = _validated_preflight_report(report)
    configuration_id = validated_report.configuration_id
    configuration = session.scalar(
        select(RepositoryConfigurationRecord)
        .where(RepositoryConfigurationRecord.id == configuration_id)
        .with_for_update()
    )
    if configuration is None:
        raise RepositoryConfigurationNotFoundError("repository configuration not found")

    latest = session.scalar(_latest_query(configuration.repository_key, for_update=True))
    if latest is None or latest.id != configuration.id:
        raise RepositoryPreflightBindingError(
            "preflight report must target the authoritative latest configuration"
        )

    binding = _validated_report_binding(configuration, validated_report)
    canonical_report: dict[str, object] = {
        "schema_version": _PREFLIGHT_SCHEMA_VERSION,
        "repository_key": binding.repository_key,
        **validated_report.to_dict(),
    }
    payload = _canonical_json_bytes(canonical_report)

    if configuration.preflight_evidence_id is None:
        raise RepositoryPreflightBindingError(
            "preflight report has no active control-plane-issued attempt"
        )
    existing = _load_attached_evidence(session, artifact_store, configuration)
    if existing[0].evidence_type == _PREFLIGHT_EVIDENCE_TYPE:
        if existing[1] == payload:
            return CapturedRepositoryPreflight(
                binding=binding,
                status=validated_report.status.value,
                evidence_id=existing[0].id,
                evidence_address=cast(str, existing[0].content_address),
            )
        raise RepositoryPreflightBindingError(
            "preflight report is stale or conflicts with the captured attempt"
        )
    if existing[0].evidence_type != _PREFLIGHT_REQUEST_EVIDENCE_TYPE:
        raise RepositoryPreflightBindingError(
            "active preflight attempt evidence is invalid"
        )
    request_binding = _decode_preflight_request(existing[1])
    expected_request_binding = {
        "attempt_id": str(validated_report.attempt_id),
        "configuration_id": str(configuration.id),
        "repository_key": configuration.repository_key,
        "configuration_version": configuration.version,
        "configuration_digest": repository_configuration_digest(configuration),
    }
    if (
        existing[0].id != validated_report.attempt_id
        or request_binding != expected_request_binding
    ):
        raise RepositoryPreflightBindingError(
            "preflight report does not match the active issued attempt"
        )

    captured = capture_evidence(
        session,
        artifact_store,
        payload=canonical_report,
        media_type="application/json",
        source_kind=EvidenceSourceKind.RESULT,
        evidence_type=_PREFLIGHT_EVIDENCE_TYPE,
        origin=_PREFLIGHT_ORIGIN,
        access_classification=_PREFLIGHT_ACCESS_CLASSIFICATION,
        retention_policy=_PREFLIGHT_RETENTION_POLICY,
        task_id=None,
        validation_run_id=None,
        captured_at=_captured_at(captured_at),
        owner_id=_required_text(owner_id, field="owner id", maximum=255),
        actor_id=_required_text(actor_id, field="actor id", maximum=255),
        root_correlation_id=root_correlation_id,
        causation_id=causation_id,
        parent_correlation_id=parent_correlation_id,
    )
    evidence = captured.record
    configuration.preflight_evidence_id = evidence.id
    session.flush()

    return CapturedRepositoryPreflight(
        binding=binding,
        status=validated_report.status.value,
        evidence_id=evidence.id,
        evidence_address=captured.envelope_address,
    )


def require_preflight_ready(
    session: Session,
    artifact_store: ArtifactStore,
    *,
    repository_key: str,
    configuration_id: UUID,
    configuration_version: int,
    configuration_digest: str,
    resolved_base_sha: str,
) -> RepositoryPreflightReadiness:
    """Lock and verify the latest exact binding for the caller's transaction.

    The caller must keep this transaction open through the mutation gate. A
    concurrent configuration writer uses the same latest-row lock and therefore
    cannot supersede the authorization until the transaction ends.
    """

    try:
        normalized_repository_key = _required_text(
            repository_key,
            field="repository key",
            maximum=500,
        )
    except ValueError:
        raise RepositoryPreflightNotReadyError(
            "requested repository key is invalid"
        ) from None
    configuration = session.scalar(
        _latest_query(normalized_repository_key, for_update=True)
    )
    if configuration is None:
        raise RepositoryPreflightNotReadyError(
            "repository has no authoritative configuration"
        )

    try:
        expected = RepositoryPreflightBinding(
            configuration_id=configuration_id,
            repository_key=configuration.repository_key,
            configuration_version=_positive_version(configuration_version),
            configuration_digest=_digest(configuration_digest),
            resolved_base_sha=_git_object_id(resolved_base_sha),
        )
        actual_digest = repository_configuration_digest(configuration)
    except (RepositoryPreflightBindingError, ValueError):
        raise RepositoryPreflightNotReadyError(
            "requested or persisted repository configuration binding is invalid"
        ) from None
    if (
        configuration.id != expected.configuration_id
        or configuration.version != expected.configuration_version
        or actual_digest != expected.configuration_digest
    ):
        raise RepositoryPreflightNotReadyError(
            "requested binding is not the authoritative latest configuration"
        )

    evidence, payload = _load_attached_evidence(session, artifact_store, configuration)
    if evidence.evidence_type != _PREFLIGHT_EVIDENCE_TYPE:
        raise RepositoryPreflightNotReadyError(
            "authoritative repository preflight attempt has not completed"
        )
    evidence_repository_key, validated_report = _decode_canonical_report(payload)
    if evidence_repository_key != configuration.repository_key:
        raise RepositoryPreflightNotReadyError(
            "preflight evidence repository does not match the configuration"
        )
    try:
        report_binding = _validated_report_binding(configuration, validated_report)
    except (RepositoryPreflightBindingError, ValueError):
        raise RepositoryPreflightNotReadyError(
            "preflight evidence binding is invalid"
        ) from None
    if not validated_report.ready:
        raise RepositoryPreflightNotReadyError(
            "authoritative repository preflight did not pass"
        )
    verified_report_binding = RepositoryPreflightBinding(
        configuration_id=report_binding.configuration_id,
        repository_key=report_binding.repository_key,
        configuration_version=report_binding.configuration_version,
        configuration_digest=report_binding.configuration_digest,
        resolved_base_sha=cast(str, report_binding.resolved_base_sha),
    )
    if verified_report_binding != expected:
        raise RepositoryPreflightNotReadyError(
            "preflight evidence does not match the exact requested binding"
        )

    return RepositoryPreflightReadiness(
        binding=expected,
        evidence_id=evidence.id,
        evidence_address=cast(str, evidence.content_address),
    )


def _latest_query(
    repository_key: str,
    *,
    for_update: bool = False,
) -> Select[tuple[RepositoryConfigurationRecord]]:
    statement = (
        select(RepositoryConfigurationRecord)
        .where(RepositoryConfigurationRecord.repository_key == repository_key)
        .order_by(RepositoryConfigurationRecord.version.desc())
        .limit(1)
    )
    return statement.with_for_update() if for_update else statement


def _validated_preflight_report(
    report: ValidatedRepositoryPreflightReport | Mapping[str, object],
) -> ValidatedRepositoryPreflightReport:
    value: object = report.to_dict() if isinstance(
        report, ValidatedRepositoryPreflightReport
    ) else report
    try:
        return ValidatedRepositoryPreflightReport.from_dict(value)
    except (SharedRepositoryConfigurationError, ValueError):
        raise RepositoryPreflightBindingError(
            "preflight report is invalid or contains unnormalized fields"
        ) from None


def _validated_report_binding(
    configuration: RepositoryConfigurationRecord,
    report: ValidatedRepositoryPreflightReport,
) -> CapturedRepositoryPreflightBinding:
    binding = CapturedRepositoryPreflightBinding(
        attempt_id=report.attempt_id,
        configuration_id=report.configuration_id,
        repository_key=configuration.repository_key,
        configuration_version=report.configuration_version,
        configuration_digest=report.configuration_digest,
        resolved_base_sha=report.resolved_base_sha,
    )
    if (
        binding.configuration_id != configuration.id
        or binding.configuration_version != configuration.version
        or binding.configuration_digest != repository_configuration_digest(configuration)
    ):
        raise RepositoryPreflightBindingError(
            "preflight report binding does not match the persisted configuration"
        )
    return binding


def _load_attached_evidence(
    session: Session,
    artifact_store: ArtifactStore,
    configuration: RepositoryConfigurationRecord,
) -> tuple[EvidenceRecord, bytes]:
    if configuration.preflight_evidence_id is None:
        raise RepositoryPreflightNotReadyError(
            "authoritative repository configuration has no preflight evidence"
        )
    evidence = session.scalar(
        select(EvidenceRecord)
        .where(EvidenceRecord.id == configuration.preflight_evidence_id)
        .with_for_update()
    )
    valid_type_and_origin = evidence is not None and (
        (
            evidence.evidence_type == _PREFLIGHT_EVIDENCE_TYPE
            and evidence.origin == _PREFLIGHT_ORIGIN
        )
        or (
            evidence.evidence_type == _PREFLIGHT_REQUEST_EVIDENCE_TYPE
            and evidence.origin == _PREFLIGHT_REQUEST_ORIGIN
        )
    )
    if (
        evidence is None
        or evidence.deleted_at is not None
        or evidence.task_id is not None
        or evidence.validation_run_id is not None
        or evidence.correction_of_id is not None
        or not valid_type_and_origin
        or evidence.access_classification != _PREFLIGHT_ACCESS_CLASSIFICATION.value
        or evidence.retention_policy != _PREFLIGHT_RETENTION_POLICY.value
        or evidence.content_address is None
        or evidence.content_hash != evidence.content_address
        or session.scalar(
            select(exists().where(EvidenceRecord.correction_of_id == evidence.id))
        )
    ):
        raise RepositoryPreflightNotReadyError(
            "attached repository preflight evidence is invalid"
        )
    try:
        loaded = load_evidence(session, artifact_store, evidence)
        expected_source = (
            EvidenceSourceKind.RESULT.value
            if evidence.evidence_type == _PREFLIGHT_EVIDENCE_TYPE
            else EvidenceSourceKind.REQUEST.value
        )
        if loaded.envelope.get("source_kind") != expected_source:
            raise EvidenceError("attached evidence source is invalid")
        payload = loaded.content_bytes
    except EvidenceError:
        raise RepositoryPreflightNotReadyError(
            "attached repository preflight artifact is unavailable or invalid"
        ) from None
    return evidence, payload


def _decode_canonical_report(
    payload: bytes,
) -> tuple[str, ValidatedRepositoryPreflightReport]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        decoded = json.loads(payload, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise RepositoryPreflightNotReadyError(
            "attached repository preflight artifact is not canonical JSON"
        ) from None
    if (
        not isinstance(decoded, dict)
        or set(decoded) != _PREFLIGHT_KEYS
        or decoded.get("schema_version") != _PREFLIGHT_SCHEMA_VERSION
        or _canonical_json_bytes(decoded) != payload
    ):
        raise RepositoryPreflightNotReadyError(
            "attached repository preflight artifact is not canonical"
        )
    repository_key = decoded["repository_key"]
    if not isinstance(repository_key, str):
        raise RepositoryPreflightNotReadyError(
            "attached repository preflight artifact has an invalid repository key"
        )
    report_payload = {
        key: value
        for key, value in decoded.items()
        if key not in {"schema_version", "repository_key"}
    }
    try:
        report = ValidatedRepositoryPreflightReport.from_dict(report_payload)
    except (SharedRepositoryConfigurationError, ValueError):
        raise RepositoryPreflightNotReadyError(
            "attached repository preflight report is invalid"
        ) from None
    return repository_key, report


def _decode_preflight_request(payload: bytes) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        decoded = json.loads(payload, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise RepositoryPreflightBindingError(
            "active preflight request is not canonical JSON"
        ) from None
    if (
        not isinstance(decoded, dict)
        or set(decoded) != _PREFLIGHT_REQUEST_KEYS
        or decoded.get("schema_version") != _PREFLIGHT_SCHEMA_VERSION
        or _canonical_json_bytes(decoded) != payload
    ):
        raise RepositoryPreflightBindingError(
            "active preflight request is not canonical"
        )
    try:
        attempt_id = UUID(cast(str, decoded["attempt_id"]))
        configuration_id = UUID(cast(str, decoded["configuration_id"]))
        repository_key = _required_text(
            cast(str, decoded["repository_key"]),
            field="repository key",
            maximum=500,
        )
        configuration_version = _positive_version(decoded["configuration_version"])
        configuration_digest = _digest(decoded["configuration_digest"])
    except (AttributeError, TypeError, ValueError):
        raise RepositoryPreflightBindingError(
            "active preflight request binding is invalid"
        ) from None
    result: dict[str, object] = {
        "attempt_id": str(attempt_id),
        "configuration_id": str(configuration_id),
        "repository_key": repository_key,
        "configuration_version": configuration_version,
        "configuration_digest": configuration_digest,
    }
    if any(decoded[key] != value for key, value in result.items()):
        raise RepositoryPreflightBindingError(
            "active preflight request binding is not canonical"
        )
    return result


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
        raise ValueError("value must be canonical JSON data") from None


def _digest(value: object) -> str:
    if not isinstance(value, str):
        raise RepositoryPreflightBindingError("configuration digest must be text")
    if (
        len(value) != len(_DIGEST_PREFIX) + 64
        or not value.startswith(_DIGEST_PREFIX)
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise RepositoryPreflightBindingError(
            "configuration digest must be a canonical SHA-256 address"
        )
    return value


def _git_object_id(value: object) -> str:
    if not isinstance(value, str):
        raise RepositoryPreflightBindingError("resolved base SHA must be text")
    if len(value) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise RepositoryPreflightBindingError(
            "resolved base SHA must be an exact lowercase Git object ID"
        )
    return value


def _positive_version(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RepositoryPreflightBindingError(
            "configuration version must be a positive integer"
        )
    return value


def _captured_at(value: datetime | None) -> datetime:
    captured_at = datetime.now(UTC) if value is None else value
    if captured_at.tzinfo is None or captured_at.utcoffset() is None:
        raise ValueError("captured at must include a timezone")
    return captured_at


def _required_text(value: str, *, field: str, maximum: int) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field} must not be empty")
    if len(normalized) > maximum:
        raise ValueError(f"{field} must not exceed {maximum} characters")
    return normalized
