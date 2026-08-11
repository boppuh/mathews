from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from mathews_control_plane.database import (
    Base,
    create_database_engine,
    create_session_factory,
    session_scope,
)
from mathews_control_plane.domain_models import (
    TASK_STATE_VALUES,
    ApprovalRequest,
    ApprovalStatus,
    BackgroundJob,
    BackgroundJobLease,
    Brief,
    BriefApprovalDecision,
    BriefDecisionDisposition,
    EvidenceRecord,
    PolicyVersion,
    PolicyVersionPromptTemplate,
    PolicyVersionReviewRule,
    PromptTemplateVersion,
    RepositoryConfiguration,
    ReviewRule,
    RuleCandidate,
    RuleCandidateStatus,
    Task,
    TaskEvent,
    TaskState,
    ValidationContract,
    ValidationOutcome,
    ValidationRun,
    WebhookDelivery,
)
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError

EXPECTED_DOMAIN_TABLES = {
    "approval_requests",
    "background_job_checkpoints",
    "background_job_effects",
    "background_job_fencing_counter",
    "background_job_leases",
    "background_job_task_transitions",
    "background_jobs",
    "brief_approval_decisions",
    "briefs",
    "evidence_audit_events",
    "evidence_deletion_requests",
    "evidence_derivatives",
    "evidence_records",
    "evidence_tombstones",
    "hermes_tool_decisions",
    "hermes_tool_proposals",
    "hermes_tool_results",
    "policy_version_prompt_templates",
    "policy_version_review_rules",
    "policy_versions",
    "prompt_template_versions",
    "repository_configurations",
    "retrieval_index_chunks",
    "retrieval_index_generations",
    "review_rules",
    "rule_candidates",
    "task_events",
    "task_event_evidence_references",
    "tasks",
    "validation_contracts",
    "validation_runs",
    "webhook_deliveries",
}


def _record_context(root_correlation_id: UUID) -> dict[str, object]:
    return {
        "owner_id": "local-user",
        "actor_id": "local-user",
        "root_correlation_id": root_correlation_id,
    }


def _task(root_correlation_id: UUID, *, summary: str = "Define schema") -> Task:
    return Task(
        repository="boppuh/mathews",
        base_revision="a" * 40,
        requester="local-user",
        raw_request=summary,
        summary=summary,
        state=TaskState.BRIEFING,
        **_record_context(root_correlation_id),
    )


def _repository_configuration(
    repository_key: str,
    version: int,
    root_correlation_id: UUID,
) -> RepositoryConfiguration:
    return RepositoryConfiguration(
        repository_key=repository_key,
        version=version,
        repository_settings={"root": "."},
        git_settings={"remote": "origin"},
        xcode_settings={"scheme": "Mathews"},
        operations=[],
        e2e_assertions=[],
        artifact_settings={},
        prohibited_paths=[],
        secret_references=[],
        **_record_context(root_correlation_id),
    )


def _brief(task_id: UUID, version: int, root_correlation_id: UUID) -> Brief:
    return Brief(
        task_id=task_id,
        version=version,
        scope={},
        exclusions=[],
        acceptance_criteria=[],
        risks=[],
        affected_flow={},
        test_plan=[],
        **_record_context(root_correlation_id),
    )


def test_domain_metadata_contains_every_mvp_record(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'domain.sqlite3'}")
    try:
        Base.metadata.create_all(engine)
        table_names = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()

    assert EXPECTED_DOMAIN_TABLES <= table_names
    assert {
        "authentication_state",
        "local_users",
        "auth_sessions",
    } <= table_names
    for table in Base.metadata.tables.values():
        constraint_names = [
            constraint.name for constraint in table.constraints if constraint.name is not None
        ]
        assert len(constraint_names) == len(set(constraint_names)), table.name


def test_task_state_values_are_canonical_and_ordered() -> None:
    assert TASK_STATE_VALUES == (
        "INTAKE",
        "BRIEFING",
        "BRIEF_PENDING_APPROVAL",
        "IMPLEMENTING",
        "VALIDATING",
        "REPAIRING",
        "PR_ACTIVE",
        "READY_FOR_HUMAN_MERGE",
        "HANDED_OFF",
        "ESCALATED",
        "FAILED",
        "CANCELLED",
    )


def test_complete_domain_graph_round_trip(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'domain.sqlite3'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    now = datetime.now(UTC)
    root_correlation_id = uuid4()
    context = _record_context(root_correlation_id)

    try:
        with session_scope(factory) as session:
            task = _task(root_correlation_id)
            session.add(task)
            session.flush()

            repository_configuration = RepositoryConfiguration(
                repository_key="boppuh/mathews",
                version=1,
                repository_settings={"root": "."},
                git_settings={"remote": "origin"},
                xcode_settings={"scheme": "Mathews"},
                operations=[{"id": "test"}],
                e2e_assertions=[{"type": "text"}],
                artifact_settings={"root": ".mathews/artifacts"},
                prohibited_paths=[".env"],
                secret_references=["github-app"],
                **context,
            )
            brief = Brief(
                task_id=task.id,
                version=1,
                scope={"summary": "Define the persistence schema"},
                exclusions=["workflow behavior"],
                acceptance_criteria=[{"id": "schema", "type": "database"}],
                risks=["migration drift"],
                affected_flow={"name": "task intake"},
                test_plan=[{"operation": "pytest"}],
                **context,
            )
            session.add_all([repository_configuration, brief])
            session.flush()

            validation_contract = ValidationContract(
                task_id=task.id,
                version=1,
                brief_id=brief.id,
                repository_configuration_id=repository_configuration.id,
                required_operations=[{"id": "check"}],
                simulator_setup={"runtime": "iOS"},
                clean_state_setup={"reset": True},
                e2e_flow={"id": "primary"},
                typed_assertions=[{"type": "text", "expected": "ready"}],
                evidence_requirements=[{"type": "test-log"}],
                timeouts={"check_seconds": 1200},
                outcome_rules={"pass": "all"},
                **context,
            )
            candidate = RuleCandidate(
                task_id=task.id,
                proposed_rule="Retry deterministic formatting failures once.",
                cited_evidence_ids=[],
                recurrence_assessment="repeated",
                severity_assessment="low",
                false_positive_risks=[],
                evaluation_result={"passed": True},
                status=RuleCandidateStatus.APPROVED,
                **context,
            )
            session.add_all([validation_contract, candidate])
            session.flush()

            approval_request = ApprovalRequest(
                task_id=task.id,
                request_type="REVIEW_RULE",
                subject_type="RULE_CANDIDATE",
                subject_id=candidate.id,
                reason="Approve exact rule candidate",
                options=["approve", "reject"],
                supporting_evidence_ids=[],
                requesting_state=TaskState.REPAIRING,
                status=ApprovalStatus.APPROVED,
                decision="approve",
                decided_by="local-user",
                decided_at=now,
                **context,
            )
            session.add(approval_request)
            session.flush()

            brief_decision = BriefApprovalDecision(
                task_id=task.id,
                brief_id=brief.id,
                disposition=BriefDecisionDisposition.HUMAN_APPROVAL_REQUIRED,
                evaluator_id="brief-policy",
                reason="Human approval recorded",
                ambiguity_flags=[],
                human_response="approve",
                decided_at=now,
                **context,
            )
            session.add(brief_decision)
            session.flush()

            review_rule = ReviewRule(
                lineage_key="format-repair",
                version=1,
                candidate_id=candidate.id,
                approval_request_id=approval_request.id,
                scope={"check": "format"},
                matcher={"exit_code": 1},
                permitted_action="run formatter",
                risk_class="low",
                evidence_requirements=["command-result"],
                provenance={"task_id": str(task.id)},
                approved_by="local-user",
                approved_at=now,
                **context,
            )
            prompt = PromptTemplateVersion(
                lineage_key="implementer",
                role="implementer",
                version=1,
                structured_template={"instructions": ["follow the accepted brief"]},
                evaluation_score=1.0,
                evaluation_threshold_passed=True,
                regression_reviewed=True,
                promoted=True,
                approved_by="local-user",
                approved_at=now,
                **context,
            )
            policy = PolicyVersion(
                lineage_key="default",
                version=1,
                workflow_thresholds={"validation_retries": 2},
                approved_by="local-user",
                approved_at=now,
                **context,
            )
            session.add_all([review_rule, prompt, policy])
            session.flush()
            session.add_all(
                [
                    PolicyVersionReviewRule(
                        policy_version_id=policy.id,
                        review_rule_id=review_rule.id,
                        position=1,
                        **context,
                    ),
                    PolicyVersionPromptTemplate(
                        policy_version_id=policy.id,
                        prompt_template_version_id=prompt.id,
                        position=1,
                        **context,
                    ),
                ]
            )

            validation_run = ValidationRun(
                task_id=task.id,
                validation_contract_id=validation_contract.id,
                repository_configuration_id=repository_configuration.id,
                commit_sha="a" * 40,
                tree_sha="b" * 40,
                configured_test_plan=[{"operation": "check"}],
                operation_results=[{"operation": "check", "passed": True}],
                simulator_target={"runtime": "iOS"},
                outcome=ValidationOutcome.PASSED,
                duration_ms=1250,
                acceptance_criterion_results=[{"id": "schema", "passed": True}],
                **context,
            )
            session.add(validation_run)
            session.flush()

            evidence = EvidenceRecord(
                task_id=task.id,
                validation_run_id=validation_run.id,
                evidence_type="test-log",
                origin="validator",
                content_hash=f"sha256:{'c' * 64}",
                content_address=f"sha256:{'c' * 64}",
                captured_at=now,
                access_classification="TASK_OWNER",
                retention_policy="TASK_LIFETIME",
                **context,
            )
            session.add(evidence)
            session.flush()
            validation_run.log_evidence_id = evidence.id
            repository_configuration.preflight_evidence_id = evidence.id

            task.accepted_brief_id = brief.id
            task.brief_approval_decision_id = brief_decision.id
            task.repository_configuration_id = repository_configuration.id
            task.validation_contract_id = validation_contract.id
            task.state = TaskState.VALIDATING

            task_event = TaskEvent(
                task_id=task.id,
                sequence=1,
                event_type="VALIDATION_PASSED",
                payload={"validation_run_id": str(validation_run.id)},
                occurred_at=now,
                **context,
            )
            job = BackgroundJob(
                task_id=task.id,
                job_type="validate",
                idempotency_key=f"validate:{task.id}:1",
                attempt_count=1,
                checkpoint={"operation": "complete"},
                **context,
            )
            session.add_all([task_event, job])
            session.flush()
            session.add(
                BackgroundJobLease(
                    job_id=job.id,
                    lease_owner="worker-1",
                    attempt=1,
                    fencing_token=1,
                    idempotency_key=f"validate:{task.id}:1:lease:1",
                    heartbeat_at=now,
                    expires_at=now + timedelta(minutes=1),
                    checkpoint={"operation": "complete"},
                    **context,
                )
            )
            session.add(
                WebhookDelivery(
                    provider="github",
                    provider_delivery_id="delivery-1",
                    installation_id="installation-1",
                    repository_id="repository-1",
                    pull_request_number=5,
                    head_sha="a" * 40,
                    signature_verified=True,
                    payload_evidence_id=evidence.id,
                    processing_result={"status": "correlated"},
                    received_at=now,
                    processed_at=now,
                    **context,
                )
            )
            task_id = task.id
            validation_run_id = validation_run.id

        with factory() as session:
            persisted_task = session.get(Task, task_id)
            persisted_run = session.get(ValidationRun, validation_run_id)
            policy_rule = session.scalar(select(PolicyVersionReviewRule))

        assert persisted_task is not None
        assert persisted_task.accepted_brief_id == brief.id
        assert persisted_task.state is TaskState.VALIDATING
        assert persisted_run is not None
        assert persisted_run.validation_contract_id == validation_contract.id
        assert persisted_run.repository_configuration_id == repository_configuration.id
        assert persisted_run.commit_sha == "a" * 40
        assert persisted_run.tree_sha == "b" * 40
        assert policy_rule is not None
        assert policy_rule.review_rule_id == review_rule.id
        assert "rule_candidate_id" not in PolicyVersionReviewRule.__table__.columns
    finally:
        engine.dispose()


def test_database_enforces_ordering_and_idempotency_keys(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'constraints.sqlite3'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    root_correlation_id = uuid4()
    context = _record_context(root_correlation_id)
    now = datetime.now(UTC)

    try:
        with session_scope(factory) as session:
            task = _task(root_correlation_id)
            session.add(task)
            session.flush()
            task_id = task.id
            session.add(
                TaskEvent(
                    task_id=task_id,
                    sequence=1,
                    event_type="CREATED",
                    payload={},
                    occurred_at=now,
                    **context,
                )
            )

        with pytest.raises(IntegrityError):
            with session_scope(factory) as session:
                session.add(
                    TaskEvent(
                        task_id=task_id,
                        sequence=1,
                        event_type="DUPLICATE",
                        payload={},
                        occurred_at=now,
                        **context,
                    )
                )

        with session_scope(factory) as session:
            session.add(
                BackgroundJob(
                    task_id=task_id,
                    job_type="validate",
                    idempotency_key="task-1:validate",
                    **context,
                )
            )

        with pytest.raises(IntegrityError):
            with session_scope(factory) as session:
                session.add(
                    BackgroundJob(
                        task_id=task_id,
                        job_type="validate",
                        idempotency_key="task-1:validate",
                        **context,
                    )
                )

        with session_scope(factory) as session:
            session.add(
                WebhookDelivery(
                    provider="github",
                    provider_delivery_id="delivery-1",
                    installation_id="installation-1",
                    repository_id="repository-1",
                    signature_verified=True,
                    received_at=now,
                    **context,
                )
            )

        with pytest.raises(IntegrityError):
            with session_scope(factory) as session:
                session.add(
                    WebhookDelivery(
                        provider="github",
                        provider_delivery_id="delivery-1",
                        installation_id="installation-1",
                        repository_id="repository-1",
                        signature_verified=True,
                        received_at=now,
                        **context,
                    )
                )
    finally:
        engine.dispose()


def test_database_rejects_cross_aggregate_authority_bindings(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'authority.sqlite3'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    now = datetime.now(UTC)
    root_a = uuid4()
    root_b = uuid4()
    context_a = _record_context(root_a)
    context_b = _record_context(root_b)

    try:
        with session_scope(factory) as session:
            task_a = _task(root_a, summary="Task A")
            task_b = _task(root_b, summary="Task B")
            task_b.repository = "other/repository"
            session.add_all([task_a, task_b])
            session.flush()

            brief_a = _brief(task_a.id, 1, root_a)
            brief_b = _brief(task_b.id, 1, root_b)
            repository_a = _repository_configuration("boppuh/mathews", 1, root_a)
            repository_a_v2 = _repository_configuration("boppuh/mathews", 2, root_a)
            repository_b = _repository_configuration("other/repository", 1, root_b)
            session.add_all(
                [
                    brief_a,
                    brief_b,
                    repository_a,
                    repository_a_v2,
                    repository_b,
                ]
            )
            session.flush()

            contract_a = ValidationContract(
                task_id=task_a.id,
                version=1,
                brief_id=brief_a.id,
                repository_configuration_id=repository_a.id,
                required_operations=[],
                simulator_setup={},
                clean_state_setup={},
                e2e_flow={},
                typed_assertions=[],
                evidence_requirements=[],
                timeouts={},
                outcome_rules={},
                **context_a,
            )
            pending_candidate = RuleCandidate(
                task_id=task_a.id,
                proposed_rule="Pending candidate",
                cited_evidence_ids=[],
                recurrence_assessment="once",
                severity_assessment="low",
                false_positive_risks=[],
                **context_a,
            )
            candidate_a = RuleCandidate(
                task_id=task_a.id,
                proposed_rule="Candidate A",
                cited_evidence_ids=[],
                recurrence_assessment="repeated",
                severity_assessment="low",
                false_positive_risks=[],
                status=RuleCandidateStatus.APPROVED,
                **context_a,
            )
            candidate_b = RuleCandidate(
                task_id=task_a.id,
                proposed_rule="Candidate B",
                cited_evidence_ids=[],
                recurrence_assessment="repeated",
                severity_assessment="low",
                false_positive_risks=[],
                status=RuleCandidateStatus.APPROVED,
                **context_a,
            )
            session.add_all(
                [
                    contract_a,
                    pending_candidate,
                    candidate_a,
                    candidate_b,
                ]
            )
            session.flush()

            pending_approval = ApprovalRequest(
                task_id=task_a.id,
                request_type="REVIEW_RULE",
                subject_type="RULE_CANDIDATE",
                subject_id=pending_candidate.id,
                reason="Review proposed executable rule",
                options=["approve", "reject"],
                supporting_evidence_ids=[],
                requesting_state=TaskState.REPAIRING,
                status=ApprovalStatus.PENDING,
                **context_a,
            )
            wrong_type_approval = ApprovalRequest(
                task_id=task_a.id,
                request_type="BRIEF",
                subject_type="RULE_CANDIDATE",
                subject_id=candidate_a.id,
                reason="Wrong approval type",
                options=["approve", "reject"],
                supporting_evidence_ids=[],
                requesting_state=TaskState.REPAIRING,
                status=ApprovalStatus.APPROVED,
                decision="approve",
                decided_by="local-user",
                decided_at=now,
                **context_a,
            )
            exact_approval = ApprovalRequest(
                task_id=task_a.id,
                request_type="REVIEW_RULE",
                subject_type="RULE_CANDIDATE",
                subject_id=candidate_a.id,
                reason="Approve candidate A",
                options=["approve", "reject"],
                supporting_evidence_ids=[],
                requesting_state=TaskState.REPAIRING,
                status=ApprovalStatus.APPROVED,
                decision="approve",
                decided_by="local-user",
                decided_at=now,
                **context_a,
            )
            unpromoted_prompt = PromptTemplateVersion(
                lineage_key="implementer",
                role="implementer",
                version=1,
                structured_template={},
                **context_a,
            )
            policy = PolicyVersion(
                lineage_key="default",
                version=1,
                workflow_thresholds={},
                approved_by="local-user",
                approved_at=now,
                **context_a,
            )
            session.add_all(
                [
                    pending_approval,
                    wrong_type_approval,
                    exact_approval,
                    unpromoted_prompt,
                    policy,
                ]
            )
            session.flush()
            ids = {
                "task_a": task_a.id,
                "task_b": task_b.id,
                "brief_a": brief_a.id,
                "brief_b": brief_b.id,
                "repository_a": repository_a.id,
                "repository_a_v2": repository_a_v2.id,
                "contract_a": contract_a.id,
                "pending_approval": pending_approval.id,
                "wrong_type_approval": wrong_type_approval.id,
                "exact_approval": exact_approval.id,
                "pending_candidate": pending_candidate.id,
                "candidate_a": candidate_a.id,
                "candidate_b": candidate_b.id,
                "unpromoted_prompt": unpromoted_prompt.id,
                "policy": policy.id,
            }

        with pytest.raises(IntegrityError):
            with session_scope(factory) as session:
                task = session.get_one(Task, ids["task_a"])
                task.accepted_brief_id = ids["brief_b"]

        with pytest.raises(IntegrityError):
            with session_scope(factory) as session:
                session.add(
                    ValidationContract(
                        task_id=ids["task_a"],
                        version=2,
                        brief_id=ids["brief_b"],
                        repository_configuration_id=ids["repository_a"],
                        required_operations=[],
                        simulator_setup={},
                        clean_state_setup={},
                        e2e_flow={},
                        typed_assertions=[],
                        evidence_requirements=[],
                        timeouts={},
                        outcome_rules={},
                        **context_a,
                    )
                )

        with pytest.raises(IntegrityError):
            with session_scope(factory) as session:
                session.add(
                    ValidationRun(
                        task_id=ids["task_a"],
                        validation_contract_id=ids["contract_a"],
                        repository_configuration_id=ids["repository_a_v2"],
                        commit_sha="a" * 40,
                        tree_sha="b" * 40,
                        configured_test_plan=[],
                        operation_results=[],
                        outcome=ValidationOutcome.PASSED,
                        duration_ms=1,
                        acceptance_criterion_results=[],
                        **context_a,
                    )
                )

        with pytest.raises(IntegrityError):
            with session_scope(factory) as session:
                session.add(
                    ReviewRule(
                        lineage_key="pending-rule",
                        version=1,
                        candidate_id=ids["pending_candidate"],
                        approval_request_id=ids["pending_approval"],
                        scope={},
                        matcher={},
                        permitted_action="none",
                        risk_class="low",
                        evidence_requirements=[],
                        provenance={},
                        approved_by="local-user",
                        approved_at=now,
                        **context_a,
                    )
                )

        with pytest.raises(IntegrityError):
            with session_scope(factory) as session:
                session.add(
                    ReviewRule(
                        lineage_key="wrong-type-rule",
                        version=1,
                        candidate_id=ids["candidate_a"],
                        approval_request_id=ids["wrong_type_approval"],
                        scope={},
                        matcher={},
                        permitted_action="none",
                        risk_class="low",
                        evidence_requirements=[],
                        provenance={},
                        approved_by="local-user",
                        approved_at=now,
                        **context_a,
                    )
                )

        with pytest.raises(IntegrityError):
            with session_scope(factory) as session:
                session.add(
                    ReviewRule(
                        lineage_key="reused-approval-rule",
                        version=1,
                        candidate_id=ids["candidate_b"],
                        approval_request_id=ids["exact_approval"],
                        scope={},
                        matcher={},
                        permitted_action="none",
                        risk_class="low",
                        evidence_requirements=[],
                        provenance={},
                        approved_by="local-user",
                        approved_at=now,
                        **context_a,
                    )
                )

        with pytest.raises(IntegrityError):
            with session_scope(factory) as session:
                session.add(
                    PolicyVersionPromptTemplate(
                        policy_version_id=ids["policy"],
                        prompt_template_version_id=ids["unpromoted_prompt"],
                        position=1,
                        **context_a,
                    )
                )

        with pytest.raises(IntegrityError):
            with session_scope(factory) as session:
                session.add(
                    Brief(
                        task_id=ids["task_b"],
                        version=2,
                        predecessor_id=ids["brief_a"],
                        scope={},
                        exclusions=[],
                        acceptance_criteria=[],
                        risks=[],
                        affected_flow={},
                        test_plan=[],
                        **context_b,
                    )
                )
    finally:
        engine.dispose()
