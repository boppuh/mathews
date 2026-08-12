"""Human-only policy activation audit and immutable rollback."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mathews_control_plane.authentication import (
    AuthenticatedSession,
    require_authenticated_session,
)
from mathews_control_plane.database import SessionFactory
from mathews_control_plane.domain_models import (
    PolicyActivation,
    PolicyActivationKind,
    PolicyVersion,
    PolicyVersionPromptTemplate,
    PolicyVersionReviewRule,
)
from mathews_control_plane.principals import LOCAL_OWNER_ID

MAX_ACTIVATION_CLOCK_SKEW = timedelta(minutes=1)
MAX_POLICY_ACTIVATION_BODY_BYTES = 32 * 1024
AuthenticatedPolicySession = Annotated[
    AuthenticatedSession,
    Depends(require_authenticated_session),
]


class PolicyActivationError(RuntimeError):
    """Base class for stable controlled-policy failures."""


class PolicyActivationNotFoundError(PolicyActivationError):
    """An exact policy input is unavailable."""


class PolicyActivationConflictError(PolicyActivationError):
    """The requested activation conflicts with durable policy state."""


class PolicyActivationAuthorizationError(PolicyActivationError):
    """The activation was not authorized by the local human owner."""


@dataclass(frozen=True, slots=True)
class PolicyRollbackResult:
    source_policy_version_id: UUID
    restored_policy_version_id: UUID
    restored_policy_version: int
    restored_from_policy_version_id: UUID
    rollback_policy_version_id: UUID
    activation_id: UUID
    activated_at: datetime
    replayed: bool = False


class PolicyRollbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    activation_id: UUID
    restored_policy_version_id: UUID
    restore_from_policy_version_id: UUID
    activation_time: datetime


class PolicyRollbackResponse(BaseModel):
    source_policy_version_id: UUID
    restored_policy_version_id: UUID
    restored_policy_version: int
    restored_from_policy_version_id: UUID
    rollback_policy_version_id: UUID
    activation_id: UUID
    activated_at: datetime
    replayed: bool


def require_human_policy_authorization(authentication: AuthenticatedSession) -> str:
    if authentication.user_id != 1:
        raise PolicyActivationAuthorizationError("human policy authorization is unavailable")
    if not authentication.recent_password_verified:
        raise PolicyActivationAuthorizationError("recent password authentication required")
    return LOCAL_OWNER_ID


def canonical_fingerprint(value: Mapping[str, object]) -> str:
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    except (TypeError, ValueError):
        raise PolicyActivationConflictError("policy activation evidence is invalid") from None
    return hashlib.sha256(payload).hexdigest()


def activation_time(value: datetime, *, now: datetime) -> datetime:
    normalized = _as_utc(value)
    current = _as_utc(now)
    if abs(normalized - current) > MAX_ACTIVATION_CLOCK_SKEW:
        raise PolicyActivationConflictError("policy activation time is stale or future-dated")
    return normalized


def active_policy(
    session: Session,
    *,
    owner_id: str,
    lineage_key: str,
    now: datetime,
    for_update: bool = False,
) -> PolicyVersion:
    query = (
        select(PolicyVersion)
        .where(
            PolicyVersion.owner_id == owner_id,
            PolicyVersion.lineage_key == lineage_key,
            PolicyVersion.approved_at <= _as_utc(now),
        )
        .order_by(PolicyVersion.version.desc())
        .limit(1)
    )
    if for_update:
        query = query.with_for_update()
    policy = session.scalar(query)
    if policy is None:
        raise PolicyActivationNotFoundError("active policy is unavailable")
    return policy


def lock_policy_promotion(session: Session, lineage_key: str) -> None:
    """Serialize policy version allocation across prompt, rule, and rollback paths."""
    if session.get_bind().dialect.name != "postgresql":
        return
    digest = hashlib.sha256(f"mathews:policy-promotion:{lineage_key}".encode()).digest()
    lock_key = int.from_bytes(digest[:8], byteorder="big", signed=True)
    session.execute(select(func.pg_advisory_xact_lock(lock_key)))


def copy_policy_memberships(
    session: Session,
    *,
    source: PolicyVersion,
    target: PolicyVersion,
    actor_id: str,
    occurred_at: datetime,
) -> None:
    context = {
        "owner_id": target.owner_id,
        "actor_id": actor_id,
        "root_correlation_id": target.root_correlation_id,
        "causation_id": target.causation_id,
        "parent_correlation_id": source.id,
        "created_at": occurred_at,
        "updated_at": occurred_at,
    }
    for rule_membership in session.scalars(
        select(PolicyVersionReviewRule)
        .where(PolicyVersionReviewRule.policy_version_id == source.id)
        .order_by(PolicyVersionReviewRule.position)
    ):
        session.add(
            PolicyVersionReviewRule(
                policy_version_id=target.id,
                review_rule_id=rule_membership.review_rule_id,
                position=rule_membership.position,
                **context,
            )
        )
    for prompt_membership in session.scalars(
        select(PolicyVersionPromptTemplate)
        .where(PolicyVersionPromptTemplate.policy_version_id == source.id)
        .order_by(PolicyVersionPromptTemplate.position)
    ):
        session.add(
            PolicyVersionPromptTemplate(
                policy_version_id=target.id,
                prompt_template_version_id=prompt_membership.prompt_template_version_id,
                prompt_promoted=True,
                position=prompt_membership.position,
                **context,
            )
        )


def policy_fingerprint(session: Session, policy: PolicyVersion) -> str:
    rules = [
        str(value)
        for value in session.scalars(
            select(PolicyVersionReviewRule.review_rule_id)
            .where(PolicyVersionReviewRule.policy_version_id == policy.id)
            .order_by(PolicyVersionReviewRule.position)
        )
    ]
    prompts = [
        str(value)
        for value in session.scalars(
            select(PolicyVersionPromptTemplate.prompt_template_version_id)
            .where(PolicyVersionPromptTemplate.policy_version_id == policy.id)
            .order_by(PolicyVersionPromptTemplate.position)
        )
    ]
    return canonical_fingerprint(
        {
            "lineage_key": policy.lineage_key,
            "policy_version_id": str(policy.id),
            "policy_version": policy.version,
            "prompts": prompts,
            "review_rules": rules,
            "workflow_thresholds": policy.workflow_thresholds,
        }
    )


def record_policy_activation(
    session: Session,
    *,
    activation_id: UUID,
    policy: PolicyVersion,
    source_policy: PolicyVersion,
    rollback_policy: PolicyVersion,
    kind: PolicyActivationKind,
    subject_type: str,
    subject_id: UUID,
    subject_version: int | None,
    subject_fingerprint: str,
    evaluation_contract_version_id: UUID | None,
    threshold_evidence: Mapping[str, object],
    evidence_ids: Sequence[UUID],
    approved_by: str,
    activated_at: datetime,
) -> PolicyActivation:
    if len(subject_fingerprint) != 64:
        raise PolicyActivationConflictError("policy activation subject is invalid")
    evidence_values = [str(value) for value in evidence_ids]
    if len(evidence_values) != len(set(evidence_values)):
        raise PolicyActivationConflictError("policy activation evidence is invalid")
    payload: dict[str, object] = {
        "activation_id": str(activation_id),
        "activation_kind": kind.value,
        "activated_at": _as_utc(activated_at).isoformat(),
        "approved_by": approved_by,
        "evaluation_contract_version_id": (
            None
            if evaluation_contract_version_id is None
            else str(evaluation_contract_version_id)
        ),
        "evidence_ids": evidence_values,
        "policy_version_id": str(policy.id),
        "rollback_policy_version_id": str(rollback_policy.id),
        "source_policy_version_id": str(source_policy.id),
        "subject_fingerprint": subject_fingerprint,
        "subject_id": str(subject_id),
        "subject_type": subject_type,
        "subject_version": subject_version,
        "threshold_evidence": dict(threshold_evidence),
    }
    activation = PolicyActivation(
        id=activation_id,
        policy_version_id=policy.id,
        source_policy_version_id=source_policy.id,
        rollback_policy_version_id=rollback_policy.id,
        activation_kind=kind,
        subject_type=subject_type,
        subject_id=subject_id,
        subject_version=subject_version,
        subject_fingerprint=subject_fingerprint,
        evaluation_contract_version_id=evaluation_contract_version_id,
        threshold_evidence=dict(threshold_evidence),
        evidence_ids=evidence_values,
        regression_reviewed=True,
        approved_by=approved_by,
        activated_at=_as_utc(activated_at),
        activation_fingerprint=canonical_fingerprint(payload),
        owner_id=policy.owner_id,
        actor_id=approved_by,
        root_correlation_id=policy.root_correlation_id,
        causation_id=subject_id,
        parent_correlation_id=source_policy.id,
        created_at=_as_utc(activated_at),
        updated_at=_as_utc(activated_at),
    )
    session.add(activation)
    return activation


class PolicyActivationService:
    def __init__(
        self,
        factory: SessionFactory,
        *,
        active_policy_lineage: str = "mvp",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._factory = factory
        self._lineage = active_policy_lineage
        self._clock = clock or (lambda: datetime.now(UTC))

    def rollback(
        self,
        source_policy_version_id: UUID,
        *,
        activation_id: UUID,
        restored_policy_version_id: UUID,
        restore_from_policy_version_id: UUID,
        activation_time_value: datetime,
        authentication: AuthenticatedSession,
    ) -> PolicyRollbackResult:
        approver = require_human_policy_authorization(authentication)
        activated_at = activation_time(activation_time_value, now=self._clock())
        try:
            with self._factory.begin() as session:
                _begin_serialized(session)
                lock_policy_promotion(session, self._lineage)
                existing = session.get(PolicyActivation, activation_id)
                existing_policy = session.get(PolicyVersion, restored_policy_version_id)
                if existing is not None or existing_policy is not None:
                    return self._replayed_rollback(
                        session,
                        source_policy_version_id=source_policy_version_id,
                        activation_id=activation_id,
                        restored_policy_version_id=restored_policy_version_id,
                        restore_from_policy_version_id=restore_from_policy_version_id,
                        activated_at=activated_at,
                        approved_by=approver,
                    )
                source = active_policy(
                    session,
                    owner_id=approver,
                    lineage_key=self._lineage,
                    now=activated_at,
                    for_update=True,
                )
                if source.id != source_policy_version_id:
                    raise PolicyActivationConflictError("active policy changed")
                if source.rollback_policy_version_id != restore_from_policy_version_id:
                    raise PolicyActivationConflictError("rollback target is not the active target")
                restore_from = session.scalar(
                    select(PolicyVersion)
                    .where(
                        PolicyVersion.id == restore_from_policy_version_id,
                        PolicyVersion.owner_id == approver,
                        PolicyVersion.lineage_key == self._lineage,
                        PolicyVersion.approved_at <= activated_at,
                    )
                    .with_for_update()
                )
                if restore_from is None:
                    raise PolicyActivationNotFoundError("rollback target is unavailable")
                next_version = (
                    session.scalar(
                        select(func.max(PolicyVersion.version)).where(
                            PolicyVersion.lineage_key == self._lineage,
                            PolicyVersion.owner_id == approver,
                        )
                    )
                    or 0
                ) + 1
                restored = PolicyVersion(
                    id=restored_policy_version_id,
                    lineage_key=self._lineage,
                    version=next_version,
                    predecessor_id=source.id,
                    workflow_thresholds=restore_from.workflow_thresholds,
                    approved_by=approver,
                    approved_at=activated_at,
                    rollback_policy_version_id=source.id,
                    owner_id=approver,
                    actor_id=approver,
                    root_correlation_id=source.root_correlation_id,
                    causation_id=activation_id,
                    parent_correlation_id=source.id,
                    created_at=activated_at,
                    updated_at=activated_at,
                )
                session.add(restored)
                session.flush()
                copy_policy_memberships(
                    session,
                    source=restore_from,
                    target=restored,
                    actor_id=approver,
                    occurred_at=activated_at,
                )
                session.flush()
                record_policy_activation(
                    session,
                    activation_id=activation_id,
                    policy=restored,
                    source_policy=source,
                    rollback_policy=source,
                    kind=PolicyActivationKind.ROLLBACK,
                    subject_type="POLICY_VERSION",
                    subject_id=restore_from.id,
                    subject_version=restore_from.version,
                    subject_fingerprint=policy_fingerprint(session, restore_from),
                    evaluation_contract_version_id=None,
                    threshold_evidence={
                        "schema_version": 1,
                        "restored_immutable_policy": True,
                    },
                    evidence_ids=(),
                    approved_by=approver,
                    activated_at=activated_at,
                )
                session.flush()
                return PolicyRollbackResult(
                    source_policy_version_id=source.id,
                    restored_policy_version_id=restored.id,
                    restored_policy_version=restored.version,
                    restored_from_policy_version_id=restore_from.id,
                    rollback_policy_version_id=source.id,
                    activation_id=activation_id,
                    activated_at=activated_at,
                )
        except IntegrityError:
            raise PolicyActivationConflictError("policy rollback conflicts") from None

    @staticmethod
    def _replayed_rollback(
        session: Session,
        *,
        source_policy_version_id: UUID,
        activation_id: UUID,
        restored_policy_version_id: UUID,
        restore_from_policy_version_id: UUID,
        activated_at: datetime,
        approved_by: str,
    ) -> PolicyRollbackResult:
        activation = session.get(PolicyActivation, activation_id)
        restored = session.get(PolicyVersion, restored_policy_version_id)
        restore_from = session.get(PolicyVersion, restore_from_policy_version_id)
        if (
            activation is None
            or restored is None
            or restore_from is None
            or activation.policy_version_id != restored.id
            or activation.source_policy_version_id != source_policy_version_id
            or activation.rollback_policy_version_id != source_policy_version_id
            or activation.activation_kind is not PolicyActivationKind.ROLLBACK
            or activation.subject_id != restore_from_policy_version_id
            or activation.subject_version != restore_from.version
            or activation.subject_fingerprint != policy_fingerprint(session, restore_from)
            or activation.approved_by != approved_by
            or _as_utc(activation.activated_at) != activated_at
            or restored.predecessor_id != source_policy_version_id
            or restored.rollback_policy_version_id != source_policy_version_id
            or restored.approved_by != approved_by
            or _as_utc(restored.approved_at) != activated_at
            or restored.workflow_thresholds != restore_from.workflow_thresholds
        ):
            raise PolicyActivationConflictError("policy rollback ids conflict")
        return PolicyRollbackResult(
            source_policy_version_id=source_policy_version_id,
            restored_policy_version_id=restored.id,
            restored_policy_version=restored.version,
            restored_from_policy_version_id=restore_from_policy_version_id,
            rollback_policy_version_id=source_policy_version_id,
            activation_id=activation.id,
            activated_at=_as_utc(activation.activated_at),
            replayed=True,
        )


class PolicyActivationBodyLimitMiddleware:
    """Bound promotion and rollback payloads before request parsing."""

    def __init__(
        self,
        app: ASGIApp,
        maximum_bytes: int = MAX_POLICY_ACTIVATION_BODY_BYTES,
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
        bounded = (
            scope["type"] == "http"
            and scope.get("method") == "POST"
            and isinstance(path, str)
            and (
                (path.startswith("/api/prompts/") and path.endswith("/promotions"))
                or (path.startswith("/api/policies/") and path.endswith("/rollback"))
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
                return max(0, int(value))
            except ValueError:
                return None
        return None

    @staticmethod
    async def _send_too_large(
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        response = JSONResponse(
            {"detail": "policy activation body too large"},
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )
        await response(scope, receive, send)


def create_policy_activation_router(service: PolicyActivationService) -> APIRouter:
    router = APIRouter(prefix="/api/policies", tags=["policies"])

    @router.post(
        "/{source_policy_version_id}/rollback",
        response_model=PolicyRollbackResponse,
    )
    def rollback(
        source_policy_version_id: UUID,
        body: PolicyRollbackRequest,
        authentication: AuthenticatedPolicySession,
        response: Response,
    ) -> PolicyRollbackResponse:
        response.headers["Cache-Control"] = "no-store"
        try:
            return PolicyRollbackResponse.model_validate(
                service.rollback(
                    source_policy_version_id,
                    activation_id=body.activation_id,
                    restored_policy_version_id=body.restored_policy_version_id,
                    restore_from_policy_version_id=body.restore_from_policy_version_id,
                    activation_time_value=body.activation_time,
                    authentication=authentication,
                ),
                from_attributes=True,
            )
        except PolicyActivationNotFoundError as error:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="policy rollback target is unavailable",
            ) from error
        except PolicyActivationAuthorizationError as error:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=str(error),
            ) from error
        except PolicyActivationConflictError as error:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="policy rollback changed",
            ) from error
    return router


def _begin_serialized(session: Session) -> None:
    if session.get_bind().dialect.name == "sqlite":
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
