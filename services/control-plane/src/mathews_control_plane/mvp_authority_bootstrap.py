"""Idempotent creation of the initial MVP authority records."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import NoReturn
from uuid import UUID, uuid5

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from mathews_control_plane.database import (
    SessionFactory,
    create_database_engine,
    create_session_factory,
)
from mathews_control_plane.domain_models import (
    ApprovalRequest,
    ApprovalStatus,
    PolicyVersion,
    PolicyVersionPromptTemplate,
    PolicyVersionReviewRule,
    PromptTemplateVersion,
    ReviewRule,
    RuleCandidate,
    RuleCandidateStatus,
    Task,
    TaskState,
)
from mathews_control_plane.policy_activation import (
    canonical_fingerprint,
    lock_policy_promotion,
    policy_fingerprint,
)
from mathews_control_plane.principals import (
    LOCAL_OWNER_ID,
    MVP_AUTHORITY_BOOTSTRAP_ACTOR,
)
from mathews_control_plane.prompt_compiler import PromptRole, StructuredPromptTemplate
from mathews_control_plane.review_rule_contract import executable_review_rule
from mathews_control_plane.settings import Settings, settings

BOOTSTRAP_ACTOR = MVP_AUTHORITY_BOOTSTRAP_ACTOR
BOOTSTRAP_APPROVED_AT = datetime(2026, 8, 12, tzinfo=UTC)
BOOTSTRAP_POLICY_LINEAGE = "mvp"
BOOTSTRAP_NAMESPACE = UUID("b6bc2975-7883-41f7-83d7-efdb7a2f9bd5")

_PROMPT_ROLES = (
    PromptRole.PLANNER,
    PromptRole.IMPLEMENTER,
    PromptRole.VALIDATOR,
    PromptRole.PR_WRITER,
    PromptRole.REVIEWER,
)
_REVIEW_EVIDENCE = (
    "github-webhook",
    "review-repair-candidate",
    "validation-decision",
    "draft-pull-request-proof",
)


class MvpAuthorityBootstrapError(RuntimeError):
    """Base class for non-secret bootstrap failures."""


class MvpAuthorityBootstrapConflictError(MvpAuthorityBootstrapError):
    """Durable authority differs from the expected initial definition."""


@dataclass(frozen=True, slots=True)
class PromptDefinition:
    id: UUID
    lineage_key: str
    role: PromptRole
    template: StructuredPromptTemplate

    @property
    def fingerprint(self) -> str:
        return canonical_fingerprint(
            {
                "id": str(self.id),
                "lineage_key": self.lineage_key,
                "role": self.role.value,
                "version": 1,
                "structured_template": self.template.model_dump(mode="json"),
                "evaluation_score": 1.0,
                "evaluation_threshold_passed": True,
                "regression_reviewed": True,
                "promoted": True,
                "approved_by": LOCAL_OWNER_ID,
                "approved_at": BOOTSTRAP_APPROVED_AT.isoformat(),
                "owner_id": LOCAL_OWNER_ID,
                "actor_id": BOOTSTRAP_ACTOR,
            }
        )


@dataclass(frozen=True, slots=True)
class MvpAuthorityDefinition:
    repository: str
    audit_task_id: UUID
    candidate_id: UUID
    approval_request_id: UUID
    approval_decision_id: UUID
    review_rule_id: UUID
    review_rule_membership_id: UUID
    policy_id: UUID
    prompt_membership_ids: tuple[UUID, ...]
    prompts: tuple[PromptDefinition, ...]
    workflow_thresholds: dict[str, object]
    review_scope: dict[str, object]
    review_matcher: dict[str, object]
    review_provenance: dict[str, object]

    @property
    def proposed_rule(self) -> str:
        return (
            "Permit one formatter-labeled repair to the acceptance app's "
            "ContentView.swift file only."
        )

    @property
    def false_positive_risks(self) -> list[str]:
        return ["A formatting classification could conceal a broader requested change."]

    @property
    def candidate_evaluation(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "eligible": True,
            "source": "MVP_RELEASE_GATE_RUNBOOK.md",
            "review_rule": {
                "lineage_key": "mvp-format-content-view",
                "scope": self.review_scope,
                "matcher": self.review_matcher,
                "permitted_action": "repair.format",
                "risk_class": "LOW",
                "evidence_requirements": list(_REVIEW_EVIDENCE),
            },
        }

    @property
    def request_fingerprint(self) -> str:
        return canonical_fingerprint(
            {
                "candidate_id": str(self.candidate_id),
                "repository": self.repository,
                "review_rule_fingerprint": self.review_rule_fingerprint,
            }
        )

    @property
    def precondition_fingerprint(self) -> str:
        return canonical_fingerprint(
            {
                "policy_lineage": BOOTSTRAP_POLICY_LINEAGE,
                "expected_version": 1,
                "existing_policy": None,
            }
        )

    @property
    def decision_fingerprint(self) -> str:
        return canonical_fingerprint(
            {
                "request_fingerprint": self.request_fingerprint,
                "decision": "APPROVE",
                "decided_by": LOCAL_OWNER_ID,
                "decided_at": BOOTSTRAP_APPROVED_AT.isoformat(),
            }
        )

    @property
    def review_rule_fingerprint(self) -> str:
        return canonical_fingerprint(
            {
                "id": str(self.review_rule_id),
                "lineage_key": "mvp-format-content-view",
                "version": 1,
                "candidate_id": str(self.candidate_id),
                "approval_request_id": str(self.approval_request_id),
                "scope": self.review_scope,
                "matcher": self.review_matcher,
                "permitted_action": "repair.format",
                "risk_class": "LOW",
                "evidence_requirements": list(_REVIEW_EVIDENCE),
                "provenance": self.review_provenance,
                "approved_by": LOCAL_OWNER_ID,
                "approved_at": BOOTSTRAP_APPROVED_AT.isoformat(),
            }
        )

    @property
    def definition_fingerprint(self) -> str:
        return canonical_fingerprint(
            {
                "schema_version": 1,
                "repository": self.repository,
                "policy": {
                    "id": str(self.policy_id),
                    "lineage_key": BOOTSTRAP_POLICY_LINEAGE,
                    "version": 1,
                    "workflow_thresholds": self.workflow_thresholds,
                },
                "prompts": [
                    {"id": str(prompt.id), "fingerprint": prompt.fingerprint}
                    for prompt in self.prompts
                ],
                "review_rule": {
                    "id": str(self.review_rule_id),
                    "fingerprint": self.review_rule_fingerprint,
                },
                "memberships": {
                    "prompt": [str(value) for value in self.prompt_membership_ids],
                    "review_rule": str(self.review_rule_membership_id),
                },
                "audit": {
                    "task_id": str(self.audit_task_id),
                    "candidate_id": str(self.candidate_id),
                    "approval_request_id": str(self.approval_request_id),
                    "approval_decision_id": str(self.approval_decision_id),
                },
                "approved_by": LOCAL_OWNER_ID,
                "approved_at": BOOTSTRAP_APPROVED_AT.isoformat(),
                "actor": BOOTSTRAP_ACTOR,
            }
        )


@dataclass(frozen=True, slots=True)
class MvpAuthoritySnapshot:
    definition: MvpAuthorityDefinition
    operation: str
    policy_fingerprint: str

    def safe_dict(self) -> dict[str, object]:
        definition = self.definition
        return {
            "schema_version": 1,
            "operation": self.operation,
            "repository": definition.repository,
            "definition_fingerprint": definition.definition_fingerprint,
            "policy": {
                "id": str(definition.policy_id),
                "lineage": BOOTSTRAP_POLICY_LINEAGE,
                "version": 1,
                "fingerprint": self.policy_fingerprint,
            },
            "prompts": [
                {
                    "id": str(prompt.id),
                    "lineage": prompt.lineage_key,
                    "role": prompt.role.value,
                    "version": 1,
                    "fingerprint": prompt.fingerprint,
                }
                for prompt in definition.prompts
            ],
            "review_rule": {
                "id": str(definition.review_rule_id),
                "lineage": "mvp-format-content-view",
                "version": 1,
                "fingerprint": definition.review_rule_fingerprint,
            },
            "memberships": {
                "prompt_membership_ids": [str(value) for value in definition.prompt_membership_ids],
                "prompt_ids": [str(prompt.id) for prompt in definition.prompts],
                "review_rule_membership_ids": [str(definition.review_rule_membership_id)],
                "review_rule_ids": [str(definition.review_rule_id)],
            },
            "audit": {
                "task_id": str(definition.audit_task_id),
                "candidate_id": str(definition.candidate_id),
                "approval_request_id": str(definition.approval_request_id),
                "approval_decision_id": str(definition.approval_decision_id),
                "owner": LOCAL_OWNER_ID,
                "actor": BOOTSTRAP_ACTOR,
                "approved_at": BOOTSTRAP_APPROVED_AT.isoformat(),
            },
        }


def mvp_authority_definition(repository: str) -> MvpAuthorityDefinition:
    prompts = tuple(
        PromptDefinition(
            id=_stable_id(f"prompt:{role.value}:v1"),
            lineage_key=f"mvp-{role.value}",
            role=role,
            template=_prompt_template(role),
        )
        for role in _PROMPT_ROLES
    )
    definition = MvpAuthorityDefinition(
        repository=repository,
        audit_task_id=_stable_id("audit-task:v1"),
        candidate_id=_stable_id("review-rule-candidate:v1"),
        approval_request_id=_stable_id("review-rule-approval:v1"),
        approval_decision_id=_stable_id("review-rule-approval-decision:v1"),
        review_rule_id=_stable_id("review-rule:mvp-format-content-view:v1"),
        review_rule_membership_id=_stable_id("membership:review-rule:1"),
        policy_id=_stable_id("policy:mvp:v1"),
        prompt_membership_ids=tuple(
            _stable_id(f"membership:prompt:{position}") for position in range(1, len(prompts) + 1)
        ),
        prompts=prompts,
        workflow_thresholds=_workflow_thresholds(repository),
        review_scope={
            "path_prefixes": ["mathews-ios-acceptance/ContentView.swift"],
            "max_files": 1,
        },
        review_matcher={
            "categories": ["formatting"],
            "required_labels": ["formatter"],
        },
        review_provenance={
            "schema_version": 1,
            "source": "MVP_RELEASE_GATE_RUNBOOK.md",
            "repository": repository,
            "bootstrap_actor": BOOTSTRAP_ACTOR,
            "human_approved": True,
            "regression_reviewed": True,
            "reviewed_at": BOOTSTRAP_APPROVED_AT.isoformat(),
            "review_period_days": 90,
            "revocation": "immutable-policy-successor-or-rollback",
        },
    )
    executable_review_rule(
        scope=definition.review_scope,
        matcher=definition.review_matcher,
        risk_class="LOW",
        evidence_requirements=_REVIEW_EVIDENCE,
    )
    return definition


class MvpAuthorityBootstrapService:
    def __init__(self, factory: SessionFactory, *, repository: str) -> None:
        self._factory = factory
        self._definition = mvp_authority_definition(repository)

    def dry_run(self) -> MvpAuthoritySnapshot:
        return MvpAuthoritySnapshot(
            definition=self._definition,
            operation="dry-run",
            policy_fingerprint=_expected_policy_fingerprint(self._definition),
        )

    def inspect(self) -> MvpAuthoritySnapshot:
        with self._factory() as session:
            return replace(self._verify(session), operation="inspected")

    def bootstrap(self) -> MvpAuthoritySnapshot:
        try:
            with self._factory() as session, session.begin():
                _serialize_initial_policy(session)
                policy = session.scalar(
                    select(PolicyVersion).where(
                        PolicyVersion.lineage_key == BOOTSTRAP_POLICY_LINEAGE,
                        PolicyVersion.version == 1,
                    )
                )
                if policy is None:
                    if (
                        session.scalar(
                            select(PolicyVersion.id)
                            .where(PolicyVersion.lineage_key == BOOTSTRAP_POLICY_LINEAGE)
                            .limit(1)
                        )
                        is not None
                    ):
                        raise MvpAuthorityBootstrapConflictError(
                            "the mvp policy lineage exists without version 1"
                        )
                    self._create(session)
                    session.flush()
                    return replace(self._verify(session), operation="created")
                return replace(self._verify(session), operation="replayed")
        except IntegrityError as error:
            raise MvpAuthorityBootstrapConflictError(
                "initial MVP authority conflicts with durable state"
            ) from error

    def _create(self, session: Session) -> None:
        definition = self._definition
        expected_ids = (
            definition.audit_task_id,
            definition.candidate_id,
            definition.approval_request_id,
            definition.review_rule_id,
            definition.policy_id,
            *(prompt.id for prompt in definition.prompts),
        )
        if any(_id_exists(session, value) for value in expected_ids):
            raise MvpAuthorityBootstrapConflictError(
                "deterministic bootstrap identifiers already exist"
            )
        context = _record_context(definition.audit_task_id)
        task = Task(
            id=definition.audit_task_id,
            repository=definition.repository,
            base_revision="0" * 40,
            requester=LOCAL_OWNER_ID,
            raw_request="authority-bootstrap://mvp/v1",
            summary="Initial MVP authority bootstrap audit context",
            state=TaskState.INTAKE,
            retry_count=0,
            **context,
        )
        session.add(task)
        session.flush()

        candidate = RuleCandidate(
            id=definition.candidate_id,
            task_id=task.id,
            proposed_rule=definition.proposed_rule,
            cited_evidence_ids=[],
            recurrence_assessment="Initial release-gate control; no recurrence claim.",
            severity_assessment="LOW",
            false_positive_risks=definition.false_positive_risks,
            evaluation_result=definition.candidate_evaluation,
            status=RuleCandidateStatus.APPROVED,
            **_record_context(definition.audit_task_id, causation_id=task.id),
        )
        session.add(candidate)
        session.flush()

        approval = ApprovalRequest(
            id=definition.approval_request_id,
            task_id=task.id,
            request_type="REVIEW_RULE",
            subject_type="RULE_CANDIDATE",
            subject_id=candidate.id,
            reason="Approve the exact initial low-risk release-gate review rule.",
            options=["APPROVE", "REJECT"],
            supporting_evidence_ids=[],
            requesting_state=TaskState.INTAKE,
            expires_at=None,
            status=ApprovalStatus.APPROVED,
            request_fingerprint=definition.request_fingerprint,
            precondition_fingerprint=definition.precondition_fingerprint,
            resume_state=TaskState.INTAKE,
            blocked_operation={
                "operation": "bootstrap-review-rule",
                "definition_fingerprint": definition.review_rule_fingerprint,
            },
            retry_history=[],
            decision="APPROVE",
            decision_id=definition.approval_decision_id,
            decision_fingerprint=definition.decision_fingerprint,
            decided_by=LOCAL_OWNER_ID,
            decided_at=BOOTSTRAP_APPROVED_AT,
            **_record_context(definition.audit_task_id, causation_id=candidate.id),
        )
        session.add(approval)
        session.flush()

        rule = ReviewRule(
            id=definition.review_rule_id,
            lineage_key="mvp-format-content-view",
            version=1,
            predecessor_id=None,
            candidate_id=candidate.id,
            approval_request_id=approval.id,
            approval_status=ApprovalStatus.APPROVED,
            approval_request_type="REVIEW_RULE",
            approval_subject_type="RULE_CANDIDATE",
            scope=definition.review_scope,
            matcher=definition.review_matcher,
            permitted_action="repair.format",
            risk_class="LOW",
            evidence_requirements=list(_REVIEW_EVIDENCE),
            provenance=definition.review_provenance,
            approved_by=LOCAL_OWNER_ID,
            approved_at=BOOTSTRAP_APPROVED_AT,
            **_record_context(definition.audit_task_id, causation_id=approval.id),
        )
        session.add(rule)

        prompt_rows: list[PromptTemplateVersion] = []
        for prompt_definition in definition.prompts:
            row = PromptTemplateVersion(
                id=prompt_definition.id,
                lineage_key=prompt_definition.lineage_key,
                role=prompt_definition.role.value,
                version=1,
                predecessor_id=None,
                structured_template=prompt_definition.template.model_dump(mode="json"),
                evaluation_evidence_id=None,
                evaluation_score=1.0,
                evaluation_threshold_passed=True,
                regression_reviewed=True,
                promoted=True,
                approved_by=LOCAL_OWNER_ID,
                approved_at=BOOTSTRAP_APPROVED_AT,
                **_record_context(definition.audit_task_id, causation_id=approval.id),
            )
            session.add(row)
            prompt_rows.append(row)

        policy = PolicyVersion(
            id=definition.policy_id,
            lineage_key=BOOTSTRAP_POLICY_LINEAGE,
            version=1,
            predecessor_id=None,
            workflow_thresholds=definition.workflow_thresholds,
            approved_by=LOCAL_OWNER_ID,
            approved_at=BOOTSTRAP_APPROVED_AT,
            rollback_policy_version_id=None,
            **_record_context(definition.audit_task_id, causation_id=approval.id),
        )
        session.add(policy)
        session.flush()

        for position, (membership_id, prompt_row) in enumerate(
            zip(definition.prompt_membership_ids, prompt_rows, strict=True),
            start=1,
        ):
            session.add(
                PolicyVersionPromptTemplate(
                    id=membership_id,
                    policy_version_id=policy.id,
                    prompt_template_version_id=prompt_row.id,
                    prompt_promoted=True,
                    position=position,
                    **_record_context(definition.audit_task_id, causation_id=policy.id),
                )
            )
        session.add(
            PolicyVersionReviewRule(
                id=definition.review_rule_membership_id,
                policy_version_id=policy.id,
                review_rule_id=rule.id,
                position=1,
                **_record_context(definition.audit_task_id, causation_id=policy.id),
            )
        )

    def _verify(self, session: Session) -> MvpAuthoritySnapshot:
        definition = self._definition
        task = session.get(Task, definition.audit_task_id)
        candidate = session.get(RuleCandidate, definition.candidate_id)
        approval = session.get(ApprovalRequest, definition.approval_request_id)
        rule = session.get(ReviewRule, definition.review_rule_id)
        policy = session.get(PolicyVersion, definition.policy_id)
        if not _support_records_match(definition, task, candidate, approval):
            _conflict("bootstrap audit records differ from the expected definition")
        if not _review_rule_matches(definition, rule):
            _conflict("bootstrap review rule differs from the expected definition")
        if not _policy_matches(definition, policy):
            _conflict("mvp policy version 1 differs from the expected definition")

        prompt_rows = tuple(
            session.get(PromptTemplateVersion, value.id) for value in definition.prompts
        )
        if any(
            not _prompt_matches(expected, actual)
            for expected, actual in zip(definition.prompts, prompt_rows, strict=True)
        ):
            _conflict("bootstrap prompts differ from the expected definition")
        prompt_memberships = tuple(
            session.scalars(
                select(PolicyVersionPromptTemplate)
                .where(PolicyVersionPromptTemplate.policy_version_id == definition.policy_id)
                .order_by(PolicyVersionPromptTemplate.position)
            )
        )
        review_memberships = tuple(
            session.scalars(
                select(PolicyVersionReviewRule)
                .where(PolicyVersionReviewRule.policy_version_id == definition.policy_id)
                .order_by(PolicyVersionReviewRule.position)
            )
        )
        if [
            (row.id, row.prompt_template_version_id, row.prompt_promoted, row.position)
            for row in prompt_memberships
        ] != [
            (membership_id, prompt.id, True, position)
            for position, (membership_id, prompt) in enumerate(
                zip(definition.prompt_membership_ids, definition.prompts, strict=True),
                start=1,
            )
        ]:
            _conflict("bootstrap prompt memberships differ from the expected order")
        if [(row.id, row.review_rule_id, row.position) for row in review_memberships] != [
            (definition.review_rule_membership_id, definition.review_rule_id, 1)
        ]:
            _conflict("bootstrap review-rule membership differs from the expected order")
        assert policy is not None
        return MvpAuthoritySnapshot(
            definition=definition,
            operation="replayed",
            policy_fingerprint=policy_fingerprint(session, policy),
        )


def _prompt_template(role: PromptRole) -> StructuredPromptTemplate:
    common = (
        "Use only the supplied task context and verified evidence identifiers; "
        "never invent or infer missing evidence.",
        "Stay inside the accepted brief, configured repository, active policy, "
        "and exact version bindings.",
        "Use only control-plane-mediated tools; never request credentials, direct "
        "host access, arbitrary shell authority, merge, release, deployment, or "
        "signing actions.",
        "Stop and report the smallest blocker when evidence, authority, scope, or "
        "exact-head bindings are missing or conflicting.",
    )
    specific: dict[PromptRole, tuple[str, ...]] = {
        PromptRole.PLANNER: (
            "Produce a bounded plan, explicit exclusions, typed acceptance criteria, "
            "risks, and a validation plan without authorizing implementation.",
        ),
        PromptRole.IMPLEMENTER: (
            "Implement only the approved paths and actions, keep changes minimal, "
            "and leave validation and workflow decisions to the control plane.",
        ),
        PromptRole.VALIDATOR: (
            "Evaluate every required operation and typed assertion against the exact "
            "candidate commit and cite only direct evidence.",
        ),
        PromptRole.PR_WRITER: (
            "Describe only the verified diff, validation results, limitations, and "
            "draft pull-request context without claiming merge or release readiness.",
        ),
        PromptRole.REVIEWER: (
            "Classify review feedback conservatively; do not treat classification as "
            "authorization and escalate unmatched or scope-expanding repairs.",
        ),
    }
    return StructuredPromptTemplate(
        role=role,
        instructions=(*common, *specific[role]),
        evidence_limit=8,
        max_prompt_characters=16_000,
    )


def _workflow_thresholds(repository: str) -> dict[str, object]:
    return {
        "repository_authority": {
            "schema_version": 1,
            "repository": repository,
        },
        "brief_approval_policy": {
            "schema_version": 1,
            "preallowed_operations": ["inspect", "edit", "test"],
            "sensitive_path_prefixes": [
                ".github",
                "mathews-ios-acceptance.xcodeproj",
                "mathews-ios-acceptanceTests",
                "mathews-ios-acceptanceUITests",
                "Fixtures",
                "scripts",
            ],
            "approval_lifetime_hours": 24,
        },
        "hermes_tool_policy": {
            "schema_version": 1,
            "tools": {
                "workspace.list_files": "inspect",
                "workspace.read_file": "inspect",
                "workspace.search": "inspect",
                "workspace.diff": "inspect",
                "git.apply_patch": "edit",
            },
        },
        "validation_repair_policy": {
            "max_attempts": 2,
            "approval_lifetime_seconds": 86_400,
        },
        "review_resolution_policy": {
            "max_attempts": 1,
            "approval_lifetime_seconds": 86_400,
        },
        "prompt_promotion_policy": {
            "schema_version": 1,
            "minimum_run_count": 3,
            "minimum_quality_score": 0.9,
            "maximum_average_cost_microusd": 1_000_000,
            "minimum_regression_pass_rate": 1.0,
            "regression_review_required": True,
            "human_approval_required": True,
        },
    }


def _support_records_match(
    definition: MvpAuthorityDefinition,
    task: Task | None,
    candidate: RuleCandidate | None,
    approval: ApprovalRequest | None,
) -> bool:
    return bool(
        task is not None
        and task.repository == definition.repository
        and task.base_revision == "0" * 40
        and task.requester == LOCAL_OWNER_ID
        and task.raw_request == "authority-bootstrap://mvp/v1"
        and task.state is TaskState.INTAKE
        and task.owner_id == LOCAL_OWNER_ID
        and task.actor_id == BOOTSTRAP_ACTOR
        and candidate is not None
        and candidate.task_id == task.id
        and candidate.proposed_rule == definition.proposed_rule
        and candidate.cited_evidence_ids == []
        and candidate.recurrence_assessment == "Initial release-gate control; no recurrence claim."
        and candidate.severity_assessment == "LOW"
        and candidate.false_positive_risks == definition.false_positive_risks
        and candidate.evaluation_result == definition.candidate_evaluation
        and candidate.status is RuleCandidateStatus.APPROVED
        and candidate.owner_id == LOCAL_OWNER_ID
        and candidate.actor_id == BOOTSTRAP_ACTOR
        and approval is not None
        and approval.task_id == task.id
        and approval.subject_id == candidate.id
        and approval.request_type == "REVIEW_RULE"
        and approval.subject_type == "RULE_CANDIDATE"
        and approval.reason == "Approve the exact initial low-risk release-gate review rule."
        and approval.options == ["APPROVE", "REJECT"]
        and approval.supporting_evidence_ids == []
        and approval.requesting_state is TaskState.INTAKE
        and approval.expires_at is None
        and approval.status is ApprovalStatus.APPROVED
        and approval.request_fingerprint == definition.request_fingerprint
        and approval.precondition_fingerprint == definition.precondition_fingerprint
        and approval.resume_state is TaskState.INTAKE
        and approval.blocked_operation
        == {
            "operation": "bootstrap-review-rule",
            "definition_fingerprint": definition.review_rule_fingerprint,
        }
        and approval.retry_history == []
        and approval.decision == "APPROVE"
        and approval.decision_id == definition.approval_decision_id
        and approval.decision_fingerprint == definition.decision_fingerprint
        and approval.decided_by == LOCAL_OWNER_ID
        and _as_utc(approval.decided_at) == BOOTSTRAP_APPROVED_AT
        and approval.owner_id == LOCAL_OWNER_ID
        and approval.actor_id == BOOTSTRAP_ACTOR
    )


def _review_rule_matches(
    definition: MvpAuthorityDefinition,
    rule: ReviewRule | None,
) -> bool:
    return bool(
        rule is not None
        and rule.lineage_key == "mvp-format-content-view"
        and rule.version == 1
        and rule.predecessor_id is None
        and rule.candidate_id == definition.candidate_id
        and rule.approval_request_id == definition.approval_request_id
        and rule.approval_status is ApprovalStatus.APPROVED
        and rule.approval_request_type == "REVIEW_RULE"
        and rule.approval_subject_type == "RULE_CANDIDATE"
        and rule.scope == definition.review_scope
        and rule.matcher == definition.review_matcher
        and rule.permitted_action == "repair.format"
        and rule.risk_class == "LOW"
        and rule.evidence_requirements == list(_REVIEW_EVIDENCE)
        and rule.provenance == definition.review_provenance
        and rule.approved_by == LOCAL_OWNER_ID
        and _as_utc(rule.approved_at) == BOOTSTRAP_APPROVED_AT
        and rule.owner_id == LOCAL_OWNER_ID
        and rule.actor_id == BOOTSTRAP_ACTOR
    )


def _prompt_matches(
    definition: PromptDefinition,
    prompt: PromptTemplateVersion | None,
) -> bool:
    return bool(
        prompt is not None
        and prompt.lineage_key == definition.lineage_key
        and prompt.role == definition.role.value
        and prompt.version == 1
        and prompt.predecessor_id is None
        and prompt.structured_template == definition.template.model_dump(mode="json")
        and prompt.evaluation_evidence_id is None
        and prompt.evaluation_score == 1.0
        and prompt.evaluation_threshold_passed is True
        and prompt.regression_reviewed is True
        and prompt.promoted is True
        and prompt.approved_by == LOCAL_OWNER_ID
        and _as_utc(prompt.approved_at) == BOOTSTRAP_APPROVED_AT
        and prompt.owner_id == LOCAL_OWNER_ID
        and prompt.actor_id == BOOTSTRAP_ACTOR
    )


def _policy_matches(
    definition: MvpAuthorityDefinition,
    policy: PolicyVersion | None,
) -> bool:
    return bool(
        policy is not None
        and policy.lineage_key == BOOTSTRAP_POLICY_LINEAGE
        and policy.version == 1
        and policy.predecessor_id is None
        and policy.rollback_policy_version_id is None
        and policy.workflow_thresholds == definition.workflow_thresholds
        and policy.approved_by == LOCAL_OWNER_ID
        and _as_utc(policy.approved_at) == BOOTSTRAP_APPROVED_AT
        and policy.owner_id == LOCAL_OWNER_ID
        and policy.actor_id == BOOTSTRAP_ACTOR
    )


def _record_context(root_id: UUID, *, causation_id: UUID | None = None) -> dict[str, object]:
    return {
        "owner_id": LOCAL_OWNER_ID,
        "actor_id": BOOTSTRAP_ACTOR,
        "root_correlation_id": root_id,
        "causation_id": causation_id,
        "parent_correlation_id": root_id if causation_id is not None else None,
        "created_at": BOOTSTRAP_APPROVED_AT,
        "updated_at": BOOTSTRAP_APPROVED_AT,
    }


def _serialize_initial_policy(session: Session) -> None:
    if session.get_bind().dialect.name == "sqlite":
        # This must remain the bootstrap transaction's first database statement.
        # Keeping BEGIN IMMEDIATE local avoids changing every SQLite reader into
        # an eager writer while concurrent bootstrap calls wait for this lock.
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")
    lock_policy_promotion(session, BOOTSTRAP_POLICY_LINEAGE)


def _id_exists(session: Session, identifier: UUID) -> bool:
    model_types = (
        Task,
        RuleCandidate,
        ApprovalRequest,
        ReviewRule,
        PolicyVersion,
        PromptTemplateVersion,
    )
    return any(session.get(model, identifier) is not None for model in model_types)


def _stable_id(name: str) -> UUID:
    return uuid5(BOOTSTRAP_NAMESPACE, name)


def _expected_policy_fingerprint(definition: MvpAuthorityDefinition) -> str:
    return canonical_fingerprint(
        {
            "lineage_key": BOOTSTRAP_POLICY_LINEAGE,
            "policy_version_id": str(definition.policy_id),
            "policy_version": 1,
            "prompts": [str(prompt.id) for prompt in definition.prompts],
            "review_rules": [str(definition.review_rule_id)],
            "workflow_thresholds": definition.workflow_thresholds,
        }
    )


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _conflict(message: str) -> NoReturn:
    raise MvpAuthorityBootstrapConflictError(message)


def _repository_from_settings(current_settings: Settings) -> str:
    if current_settings.github_repository is None:
        raise MvpAuthorityBootstrapError("MATHEWS_GITHUB_REPOSITORY is required")
    return current_settings.github_repository


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create or inspect the immutable initial MVP authority records"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Show the intended digests only")
    mode.add_argument(
        "--inspect", action="store_true", help="Verify stored records without writing"
    )
    args = parser.parse_args()
    repository = _repository_from_settings(settings)
    engine = None
    try:
        if args.dry_run:
            definition = mvp_authority_definition(repository)
            snapshot = MvpAuthoritySnapshot(
                definition=definition,
                operation="dry-run",
                policy_fingerprint=_expected_policy_fingerprint(definition),
            )
        else:
            engine = create_database_engine(settings.database_url)
            service = MvpAuthorityBootstrapService(
                create_session_factory(engine), repository=repository
            )
            snapshot = service.inspect() if args.inspect else service.bootstrap()
        print(json.dumps(snapshot.safe_dict(), indent=2, sort_keys=True))
    except MvpAuthorityBootstrapError as error:
        parser.exit(2, f"mathews-bootstrap-mvp-authority: {error}\n")
    except SQLAlchemyError:
        parser.exit(2, "mathews-bootstrap-mvp-authority: database operation failed\n")
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    main()
