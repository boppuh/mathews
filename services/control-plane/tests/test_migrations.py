import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from mathews_control_plane.approvals import ApprovalService, BlockedOperation
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.background_jobs import (
    BackgroundJobService,
    EffectExecutionResult,
    RetryPolicy,
)
from mathews_control_plane.database import (
    Base,
    create_database_engine,
    create_session_factory,
    create_task_record,
)
from mathews_control_plane.domain_models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalRequestType,
    BackgroundJob,
    BackgroundJobStatus,
    DependencyService,
    EvidenceRecord,
    PolicyVersion,
    ReconciliationTargetKind,
    TaskEvent,
    TaskState,
)
from mathews_control_plane.reliability import CancellationService
from mathews_control_plane.task_state_machine import (
    TaskTransitionKind,
    TaskTransitionService,
)
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.exc import IntegrityError

EXPECTED_HEAD_TABLES = {
    "agent_run_evaluations",
    "alembic_version",
    "approval_requests",
    "auth_sessions",
    "authentication_state",
    "background_job_checkpoints",
    "background_job_effects",
    "background_job_fencing_counter",
    "background_job_ignored_results",
    "background_job_leases",
    "background_job_task_transitions",
    "background_job_tool_grants",
    "background_jobs",
    "brief_approval_decisions",
    "briefs",
    "evidence_audit_events",
    "evidence_deletion_requests",
    "evidence_derivatives",
    "evidence_derivative_citations",
    "evidence_records",
    "evidence_tombstones",
    "evaluation_contract_versions",
    "hermes_run_events",
    "hermes_runs",
    "hermes_tool_decisions",
    "hermes_tool_proposals",
    "hermes_tool_results",
    "dependency_outage_attempts",
    "local_users",
    "policy_version_prompt_templates",
    "policy_version_review_rules",
    "policy_versions",
    "prompt_template_versions",
    "repository_configurations",
    "retrieval_index_chunks",
    "retrieval_index_generations",
    "reconciliation_targets",
    "review_rules",
    "rule_candidate_citations",
    "rule_candidates",
    "task_events",
    "task_event_evidence_references",
    "task_cancellations",
    "tasks",
    "validation_contracts",
    "validation_runs",
    "webhook_deliveries",
    "owned_host_processes",
    "policy_activations",
}
RELIABILITY_TABLES = {
    "background_job_ignored_results",
    "background_job_tool_grants",
    "dependency_outage_attempts",
    "owned_host_processes",
    "reconciliation_targets",
    "task_cancellations",
}
HERMES_TABLES = {
    "hermes_run_events",
    "hermes_runs",
    "hermes_tool_decisions",
    "hermes_tool_proposals",
    "hermes_tool_results",
}
RETRIEVAL_INDEX_TABLES = {
    "retrieval_index_chunks",
    "retrieval_index_generations",
}
EVALUATION_TELEMETRY_TABLES = {
    "agent_run_evaluations",
    "evaluation_contract_versions",
}
CANDIDATE_LEARNING_TABLES = {
    "evidence_derivative_citations",
    "rule_candidate_citations",
}
CONTROLLED_POLICY_TABLES = {"policy_activations"}


def _migration_config(database_url: str) -> Config:
    service_root = Path(__file__).parents[1]
    config = Config(str(service_root / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


def _table_names(database_url: str) -> set[str]:
    engine = create_engine(database_url)
    try:
        return set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def test_migrations_are_repeatable_from_clean_database(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)

    command.upgrade(config, "head")
    command.upgrade(config, "head")

    assert _table_names(database_url) == EXPECTED_HEAD_TABLES


def test_controlled_policy_activation_audit_is_append_only(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)
    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    source_policy_id = uuid4()
    active_policy_id = uuid4()
    activation_id = uuid4()
    correlation_id = uuid4()
    subject_id = uuid4()
    try:
        with engine.begin() as connection:
            for policy_id, version, predecessor_id, rollback_id in (
                (source_policy_id, 1, None, None),
                (active_policy_id, 2, source_policy_id, source_policy_id),
            ):
                connection.execute(
                    text(
                        "INSERT INTO policy_versions ("
                        "id, lineage_key, version, predecessor_id, workflow_thresholds, "
                        "approved_by, approved_at, rollback_policy_version_id, owner_id, "
                        "actor_id, root_correlation_id) VALUES ("
                        ":id, 'mvp', :version, :predecessor_id, '{}', 'local-user', "
                        "CURRENT_TIMESTAMP, :rollback_id, 'local-user', 'local-user', "
                        ":correlation_id)"
                    ),
                    {
                        "id": policy_id.hex,
                        "version": version,
                        "predecessor_id": (
                            None if predecessor_id is None else predecessor_id.hex
                        ),
                        "rollback_id": None if rollback_id is None else rollback_id.hex,
                        "correlation_id": correlation_id.hex,
                    },
                )
            connection.execute(
                text(
                    "INSERT INTO policy_activations ("
                    "id, policy_version_id, source_policy_version_id, "
                    "rollback_policy_version_id, activation_kind, subject_type, "
                    "subject_id, subject_version, subject_fingerprint, "
                    "threshold_evidence, evidence_ids, regression_reviewed, approved_by, "
                    "activated_at, activation_fingerprint, owner_id, actor_id, "
                    "root_correlation_id) VALUES ("
                    ":id, :policy_id, :source_id, :source_id, 'ROLLBACK', "
                    "'POLICY_VERSION', :subject_id, 1, :subject_fingerprint, '{}', '[]', "
                    "1, 'local-user', CURRENT_TIMESTAMP, :activation_fingerprint, "
                    "'local-user', 'local-user', :correlation_id)"
                ),
                {
                    "id": activation_id.hex,
                    "policy_id": active_policy_id.hex,
                    "source_id": source_policy_id.hex,
                    "subject_id": subject_id.hex,
                    "subject_fingerprint": "a" * 64,
                    "activation_fingerprint": "b" * 64,
                    "correlation_id": correlation_id.hex,
                },
            )
        with pytest.raises(IntegrityError, match="append-only"):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE policy_activations SET approved_by = 'rewritten' "
                        "WHERE id = :id"
                    ),
                    {"id": activation_id.hex},
                )
        with pytest.raises(IntegrityError, match="append-only"):
            with engine.begin() as connection:
                connection.execute(
                    text("DELETE FROM policy_activations WHERE id = :id"),
                    {"id": activation_id.hex},
                )
    finally:
        engine.dispose()
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            trigger_names = set(
                connection.execute(
                    text(
                        "SELECT name FROM sqlite_master "
                        "WHERE type = 'trigger' AND tbl_name = 'hermes_run_events'"
                    )
                ).scalars()
            )
        assert trigger_names == {
            "hermes_run_events_no_delete",
            "hermes_run_events_no_update",
        }
    finally:
        engine.dispose()


def test_migrations_can_rebuild_schema_after_downgrade(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)

    command.upgrade(config, "head")
    command.downgrade(config, "base")
    assert _table_names(database_url) == {"alembic_version"}

    command.upgrade(config, "head")
    assert _table_names(database_url) == EXPECTED_HEAD_TABLES


def test_authentication_revision_can_downgrade_without_removing_tasks(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)

    command.upgrade(config, "head")
    command.downgrade(config, "0001")

    assert _table_names(database_url) == {"alembic_version", "tasks"}

    command.upgrade(config, "head")
    assert _table_names(database_url) == EXPECTED_HEAD_TABLES


def test_domain_revision_preserves_legacy_task_and_authentication_rows(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)
    task_id = "12345678123456781234567812345678"
    brief_id = "87654321876543218765432187654321"

    command.upgrade(config, "0002")
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text("INSERT INTO tasks (id, summary) VALUES (:id, :summary)"),
                {"id": task_id, "summary": "Legacy durable task"},
            )
            connection.execute(
                text("INSERT INTO local_users (id, password_hash) VALUES (1, :password_hash)"),
                {"password_hash": "argon2id-test-hash"},
            )
    finally:
        engine.dispose()

    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO briefs ("
                    "id, task_id, version, scope, exclusions, acceptance_criteria, "
                    "risks, affected_flow, test_plan, owner_id, actor_id, "
                    "root_correlation_id"
                    ") VALUES ("
                    ":id, :task_id, 1, '{}', '[]', '[]', '[]', '{}', '[]', "
                    "'legacy-local-user', 'legacy-local-user', :task_id"
                    ")"
                ),
                {"id": brief_id, "task_id": task_id},
            )
            connection.execute(
                text("UPDATE tasks SET accepted_brief_id = :brief_id WHERE id = :task_id"),
                {"brief_id": brief_id, "task_id": task_id},
            )
            task_row = connection.execute(
                text(
                    "SELECT summary, owner_id, actor_id, state, raw_request "
                    "FROM tasks WHERE id = :id"
                ),
                {"id": task_id},
            ).one()
            local_user_count = connection.execute(
                text("SELECT count(*) FROM local_users WHERE id = 1")
            ).scalar_one()

            assert task_row == (
                "Legacy task requires re-intake",
                "legacy-local-user",
                "legacy-local-user",
                "ESCALATED",
                "legacy-request-fenced",
            )
            assert local_user_count == 1
    finally:
        engine.dispose()

    command.downgrade(config, "0002")
    assert _table_names(database_url) == {
        "alembic_version",
        "auth_sessions",
        "authentication_state",
        "local_users",
        "tasks",
    }

    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT summary FROM tasks WHERE id = :id"),
                    {"id": task_id},
                ).scalar_one()
                == "Legacy task requires re-intake"
            )
            assert (
                connection.execute(
                    text("SELECT count(*) FROM local_users WHERE id = 1")
                ).scalar_one()
                == 1
            )
    finally:
        engine.dispose()


def test_migrations_match_declared_model_metadata(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)
    command.upgrade(config, "head")
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(
                connection,
                opts={"compare_type": True},
            )
            assert compare_metadata(context, Base.metadata) == []
    finally:
        engine.dispose()


def test_approval_revision_migrates_legacy_rows_and_guards_provenance(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)
    request_id = uuid4()
    command.upgrade(config, "0006")
    engine = create_database_engine(database_url)
    store = ArtifactStore(tmp_path / "artifacts")
    factory = create_session_factory(engine)
    try:
        with factory.begin() as session:
            task = create_task_record(
                session,
                store,
                repository="boppuh/mathews",
                base_revision="1" * 40,
                requester="local-user",
                raw_request="Migrate one legacy approval",
                summary="Migrate approval",
                owner_id="local-user",
                actor_id="local-user",
            )
            task_id = task.id
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO approval_requests ("
                    "id, task_id, request_type, subject_type, reason, options, "
                    "supporting_evidence_ids, requesting_state, status, "
                    "owner_id, actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, :task_id, 'BRIEF', 'BRIEF', 'LEGACY_APPROVAL', "
                    ":options, :evidence, 'INTAKE', 'PENDING', "
                    "'local-user', 'local-user', :task_id"
                    ")"
                ),
                {
                    "id": request_id.hex,
                    "task_id": task_id.hex,
                    "options": json.dumps(["APPROVE", "CANCEL"]),
                    "evidence": json.dumps([]),
                },
            )
    finally:
        engine.dispose()

    command.upgrade(config, "head")
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            migrated = connection.execute(
                text(
                    "SELECT request_fingerprint, precondition_fingerprint, "
                    "resume_state, blocked_operation, retry_history, status, "
                    "decision, decision_id, decision_fingerprint, decided_by "
                    "FROM approval_requests WHERE id = :id"
                ),
                {"id": request_id.hex},
            ).one()
        assert migrated == (
            "0" * 64,
            "0" * 64,
            None,
            None,
            "[]",
            "CANCELLED",
            "CANCEL",
            request_id.hex,
            "0" * 64,
            "migration-0007-legacy-fence",
        )
    finally:
        engine.dispose()

    command.downgrade(config, "0006")
    engine = create_engine(database_url)
    try:
        assert "request_fingerprint" not in {
            column["name"]
            for column in inspect(engine).get_columns("approval_requests")
        }
        with engine.connect() as connection:
            restored = connection.execute(
                text(
                    "SELECT status, decision, decided_by, decided_at "
                    "FROM approval_requests WHERE id = :id"
                ),
                {"id": request_id.hex},
            ).one()
        assert restored == ("PENDING", None, None, None)
    finally:
        engine.dispose()

    command.upgrade(config, "head")
    engine = create_engine(database_url)
    provenance_request_id = uuid4()
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO approval_requests ("
                    "id, task_id, request_type, subject_type, reason, options, "
                    "supporting_evidence_ids, requesting_state, expires_at, "
                    "status, request_fingerprint, precondition_fingerprint, "
                    "retry_history, owner_id, actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, :task_id, 'BRIEF', 'BRIEF', 'NEW_APPROVAL', "
                    ":options, :evidence, 'INTAKE', '2026-08-01 00:00:00', "
                    "'PENDING', :request_fingerprint, :precondition_fingerprint, "
                    ":retry_history, 'local-user', 'local-user', :task_id"
                    ")"
                ),
                {
                    "id": provenance_request_id.hex,
                    "task_id": task_id.hex,
                    "options": json.dumps(["APPROVE", "CANCEL"]),
                    "evidence": json.dumps([]),
                    "request_fingerprint": "a" * 64,
                    "precondition_fingerprint": "b" * 64,
                    "retry_history": json.dumps([]),
                },
            )
    finally:
        engine.dispose()

    with pytest.raises(
        RuntimeError,
        match="durable approval provenance",
    ):
        command.downgrade(config, "0006")


def test_approval_revision_enforces_append_only_terminal_projection(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)
    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    store = ArtifactStore(tmp_path / "artifacts")
    factory = create_session_factory(engine)
    request_id = uuid4()
    decision_id = uuid4()
    try:
        with factory.begin() as session:
            task = create_task_record(
                session,
                store,
                repository="boppuh/mathews",
                base_revision="1" * 40,
                requester="local-user",
                raw_request="Protect approval provenance",
                summary="Protect approval",
                owner_id="local-user",
                actor_id="local-user",
            )
            task_id = task.id
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO approval_requests ("
                    "id, task_id, request_type, subject_type, reason, options, "
                    "supporting_evidence_ids, requesting_state, expires_at, "
                    "status, request_fingerprint, precondition_fingerprint, "
                    "resume_state, blocked_operation, retry_history, "
                    "owner_id, actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, :task_id, 'UNSAFE_ACTION', 'BLOCKED_OPERATION', "
                    "'UNSAFE_ACTION_REQUIRED', :options, :evidence, "
                    "'IMPLEMENTING', '2026-08-01 00:00:00', 'PENDING', "
                    ":request_fingerprint, :precondition_fingerprint, "
                    "'IMPLEMENTING', :blocked_operation, :retry_history, "
                    "'local-user', 'control-plane', :task_id"
                    ")"
                ),
                {
                    "id": request_id.hex,
                    "task_id": task_id.hex,
                    "options": json.dumps(["APPROVE", "DENY", "CANCEL"]),
                    "evidence": json.dumps([]),
                    "request_fingerprint": "a" * 64,
                    "precondition_fingerprint": "b" * 64,
                    "blocked_operation": json.dumps(
                        {
                            "checkpoint_evidence_id": None,
                            "idempotency_key": "operation-1",
                            "input_fingerprint": "c" * 64,
                            "operation_name": "host.mutate",
                        }
                    ),
                    "retry_history": json.dumps([]),
                },
            )

        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE approval_requests SET reason = 'REWRITTEN' "
                        "WHERE id = :id"
                    ),
                    {"id": request_id.hex},
                )
        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE approval_requests SET status = 'APPROVED' "
                        "WHERE id = :id"
                    ),
                    {"id": request_id.hex},
                )

        with engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE approval_requests SET "
                    "status = 'APPROVED', decision = 'APPROVE', "
                    "decision_id = :decision_id, "
                    "decision_fingerprint = :fingerprint, "
                    "decided_by = 'local-user', "
                    "decided_at = '2026-07-30 12:00:00' "
                    "WHERE id = :id"
                ),
                {
                    "decision_id": decision_id.hex,
                    "fingerprint": "d" * 64,
                    "id": request_id.hex,
                },
            )
        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE approval_requests SET decision = 'DENY' "
                        "WHERE id = :id"
                    ),
                    {"id": request_id.hex},
                )
        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "DELETE FROM approval_requests WHERE id = :id"
                    ),
                    {"id": request_id.hex},
                )
    finally:
        engine.dispose()


def test_approval_service_operates_through_migrated_triggers(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)
    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    store = ArtifactStore(tmp_path / "artifacts")
    factory = create_session_factory(engine)
    now = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
    try:
        with factory.begin() as session:
            task = create_task_record(
                session,
                store,
                repository="boppuh/mathews",
                base_revision="1" * 40,
                requester="local-user",
                raw_request="Exercise migrated approval triggers",
                summary="Exercise approval",
                owner_id="local-user",
                actor_id="local-user",
            )
            session.add(
                PolicyVersion(
                    lineage_key="mvp",
                    version=1,
                    workflow_thresholds={},
                    approved_by="local-user",
                    approved_at=now,
                    owner_id=task.owner_id,
                    actor_id="local-user",
                    root_correlation_id=task.root_correlation_id,
                )
            )
            session.flush()
            evidence_id = session.scalar(
                select(EvidenceRecord.id).where(
                    EvidenceRecord.task_id == task.id
                )
            )
            assert evidence_id is not None
            task_id = task.id
        TaskTransitionService(
            factory,
            store,
            clock=lambda: now,
        ).transition(
            task_id,
            transition_id=uuid4(),
            expected_state=TaskState.INTAKE,
            kind=TaskTransitionKind.START_BRIEFING,
            reason_code="START_BRIEFING",
            evidence_ids=(evidence_id,),
        )
        service = ApprovalService(
            factory,
            store,
            clock=lambda: now,
        )
        request = service.request(
            task_id,
            request_id=uuid4(),
            expected_state=TaskState.BRIEFING,
            request_type=ApprovalRequestType.UNSAFE_ACTION,
            reason_code="UNSAFE_ACTION_REQUIRED",
            subject_type="BLOCKED_OPERATION",
            subject_id=None,
            blocked_operation=BlockedOperation(
                operation_name="host.mutate",
                idempotency_key="operation-1",
                input_fingerprint="a" * 64,
            ),
            evidence_ids=(evidence_id,),
            expires_at=now + timedelta(hours=1),
        )
        decision = service.decide(
            request.request_id,
            decision_id=uuid4(),
            decision=ApprovalDecision.DENY,
            actor_id="local-user",
        )

        assert request.task_state is TaskState.ESCALATED
        assert decision.task_state is TaskState.FAILED
    finally:
        engine.dispose()


def test_job_loop_migrates_nonempty_legacy_jobs_without_stranding_them(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)
    command.upgrade(config, "0005")
    engine = create_database_engine(database_url)
    store = ArtifactStore(tmp_path / "artifacts")
    factory = create_session_factory(engine)
    runnable_id = uuid4()
    legacy_lease_id = uuid4()
    taskless_id = uuid4()
    exhausted_id = uuid4()
    correlation_id = uuid4()
    try:
        with factory.begin() as session:
            task = create_task_record(
                session,
                store,
                repository="boppuh/mathews",
                base_revision="1" * 40,
                requester="local-user",
                raw_request="Migrate legacy jobs",
                summary="Migrate legacy jobs",
                owner_id="local-user",
                actor_id="local-user",
            )
            task_id = task.id
        with engine.begin() as connection:
            for parameters in (
                {
                    "id": runnable_id.hex,
                    "task_id": task_id.hex,
                    "key": "legacy:runnable",
                    "attempts": 6,
                },
                {
                    "id": taskless_id.hex,
                    "task_id": None,
                    "key": "legacy:taskless",
                    "attempts": 1,
                },
                {
                    "id": exhausted_id.hex,
                    "task_id": task_id.hex,
                    "key": "legacy:over-budget",
                    "attempts": 101,
                },
            ):
                connection.execute(
                    text(
                        "INSERT INTO background_jobs ("
                        "id, task_id, job_type, status, idempotency_key, "
                        "attempt_count, owner_id, actor_id, root_correlation_id"
                        ") VALUES ("
                        ":id, :task_id, 'legacy-action', 'RUNNING', :key, "
                        ":attempts, 'local-user', 'legacy-worker', :correlation_id)"
                    ),
                    {**parameters, "correlation_id": correlation_id.hex},
                )
            connection.execute(
                text(
                    "INSERT INTO background_job_leases ("
                    "id, job_id, lease_owner, attempt, fencing_token, "
                    "idempotency_key, heartbeat_at, expires_at, owner_id, "
                    "actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, :job_id, 'legacy-worker', 6, 77, "
                    "'legacy:runnable:lease:6', CURRENT_TIMESTAMP, "
                    "datetime(CURRENT_TIMESTAMP, '+1 hour'), 'local-user', "
                    "'legacy-worker', :correlation_id)"
                ),
                {
                    "id": legacy_lease_id.hex,
                    "job_id": runnable_id.hex,
                    "correlation_id": correlation_id.hex,
                },
            )
    finally:
        engine.dispose()

    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    try:
        with engine.connect() as connection:
            rows = {
                row.id: row
                for row in connection.execute(
                    text(
                        "SELECT id, status, attempt_count, max_attempts, "
                        "available_at, last_error_code "
                        "FROM background_jobs"
                    )
                ).mappings()
            }
            legacy_lease = connection.execute(
                text(
                    "SELECT fencing_token, lease_protocol_version "
                    "FROM background_job_leases WHERE id = :id"
                ),
                {"id": legacy_lease_id.hex},
            ).one()
            next_token = connection.execute(
                text("SELECT next_token FROM background_job_fencing_counter WHERE id = 1")
            ).scalar_one()
        runnable = rows[runnable_id.hex]
        taskless = rows[taskless_id.hex]
        exhausted = rows[exhausted_id.hex]
        assert runnable.status == "QUEUED"
        assert runnable.attempt_count == 6
        assert runnable.max_attempts == 7
        assert runnable.available_at is not None
        assert taskless.status == "FAILED"
        assert taskless.last_error_code == "LEGACY_TASK_BINDING_MISSING"
        assert exhausted.status == "FAILED"
        assert exhausted.attempt_count == 100
        assert exhausted.max_attempts == 100
        assert exhausted.last_error_code == "LEGACY_ATTEMPT_BUDGET_EXCEEDED"
        assert legacy_lease == (77, 0)
        assert next_token == 78
    finally:
        engine.dispose()

    command.downgrade(config, "0005")
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            preserved = connection.execute(
                text("SELECT job_id, fencing_token FROM background_job_leases WHERE id = :id"),
                {"id": legacy_lease_id.hex},
            ).one()
        assert preserved == (runnable_id.hex, 77)
    finally:
        engine.dispose()


def test_job_loop_migration_installs_declared_checks_and_defaults(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)
    command.upgrade(config, "head")
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        lease_checks = {
            check["name"] for check in inspector.get_check_constraints("background_job_leases")
        }
        lease_columns = {
            column["name"]: column for column in inspector.get_columns("background_job_leases")
        }
        counter_columns = {
            column["name"]: column
            for column in inspector.get_columns("background_job_fencing_counter")
        }
        with engine.connect() as connection:
            job_triggers = set(
                connection.execute(
                    text(
                        "SELECT name FROM sqlite_master "
                        "WHERE type = 'trigger' AND tbl_name = 'background_jobs'"
                    )
                ).scalars()
            )
    finally:
        engine.dispose()

    assert {
        "background_jobs_validate_insert",
        "background_jobs_validate_update",
        "background_jobs_no_delete",
    } <= job_triggers
    assert {
        "ck_background_job_leases_checkpoint_version_non_negative",
        "ck_background_job_leases_expires_after_heartbeat",
        "ck_background_job_leases_release_shape",
    } <= lease_checks
    assert lease_columns["lease_protocol_version"]["default"] is not None
    assert counter_columns["next_token"]["default"] is not None


def test_job_loop_downgrade_refuses_unclaimed_new_command(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)
    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    factory = create_session_factory(engine)
    store = ArtifactStore(tmp_path / "artifacts")
    try:
        with factory.begin() as session:
            task = create_task_record(
                session,
                store,
                repository="boppuh/mathews",
                base_revision="1" * 40,
                requester="local-user",
                raw_request="Guard a new queued command",
                summary="Guard queued command",
                owner_id="local-user",
                actor_id="local-user",
            )
            task_id = task.id
        BackgroundJobService(factory, store).schedule(
            task_id=task_id,
            job_type="migration-check",
            idempotency_key="migration-check:queued",
            input_payload={"operation": "verify"},
        )
    finally:
        engine.dispose()

    with pytest.raises(
        RuntimeError,
        match="fenced background job provenance",
    ):
        command.downgrade(config, "0005")


def test_job_loop_migration_enforces_fenced_provenance_and_guarded_downgrade(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)
    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    factory = create_session_factory(engine)
    store = ArtifactStore(tmp_path / "artifacts")
    now = datetime.now(UTC)
    try:
        with factory.begin() as session:
            task = create_task_record(
                session,
                store,
                repository="boppuh/mathews",
                base_revision="1" * 40,
                requester="local-user",
                raw_request="Exercise the migrated job loop",
                summary="Exercise job loop",
                owner_id="local-user",
                actor_id="local-user",
            )
            task_id = task.id
        service = BackgroundJobService(factory, store, clock=lambda: now)
        scheduled = service.schedule(
            task_id=task_id,
            job_type="migration-check",
            idempotency_key="migration-check:1",
            input_payload={"operation": "verify"},
        )
        grant = service.claim_next(
            worker_id="migration-worker",
            lease_duration=timedelta(seconds=60),
        )
        assert grant is not None and grant.job_id == scheduled.job_id
        checkpoint = service.checkpoint(
            grant,
            expected_version=0,
            idempotency_key="migration-checkpoint:1",
            payload={"step": "prepared"},
        )
        effect = service.prepare_effect(
            grant,
            effect_key="publish",
            effect_type="git.push",
            request_payload={"branch": "task"},
        )
        service.record_effect_result(
            grant,
            effect_id=effect.effect_id,
            result=EffectExecutionResult(
                succeeded=True,
                payload={"remote_sha": "a" * 40},
            ),
            expected_checkpoint_version=checkpoint.sequence,
            checkpoint_idempotency_key="migration-checkpoint:2",
            checkpoint_payload={"step": "published"},
        )

        with pytest.raises(IntegrityError, match="invalid background job projection"):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE background_jobs SET checkpoint_version = 1, "
                        "last_fencing_token = :token WHERE id = :job_id"
                    ),
                    {
                        "job_id": scheduled.job_id.hex,
                        "token": grant.fencing_token,
                    },
                )
        with pytest.raises(IntegrityError, match="cannot heartbeat"):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE background_job_leases "
                        "SET expires_at = datetime(expires_at, '+60 seconds') "
                        "WHERE id = :lease_id"
                    ),
                    {"lease_id": grant.lease_id.hex},
                )
        with pytest.raises(IntegrityError, match="not fenced"):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE background_jobs "
                        "SET checkpoint_version = checkpoint_version + 1, "
                        "last_fencing_token = :stale "
                        "WHERE id = :job_id"
                    ),
                    {
                        "job_id": scheduled.job_id.hex,
                        "stale": grant.fencing_token + 1,
                    },
                )
        with pytest.raises(IntegrityError, match="append-only"):
            with engine.begin() as connection:
                connection.execute(
                    text("DELETE FROM background_job_checkpoints WHERE id = :checkpoint_id"),
                    {"checkpoint_id": checkpoint.checkpoint_id.hex},
                )
        service.complete(
            grant,
            expected_checkpoint_version=2,
        )
        realtime_service = BackgroundJobService(factory, store)
        exhausted_job = realtime_service.schedule(
            task_id=task_id,
            job_type="migration-expiry",
            idempotency_key="migration-expiry:1",
            input_payload={"operation": "expire"},
            retry_policy=RetryPolicy(max_attempts=1),
        )
        exhausted_grant = realtime_service.claim_next(
            worker_id="migration-expiry-worker",
            lease_duration=timedelta(seconds=1),
            job_types=("migration-expiry",),
        )
        assert exhausted_grant is not None
        time.sleep(1.1)
        assert (
            realtime_service.claim_next(
                worker_id="migration-expiry-reconciler",
                lease_duration=timedelta(seconds=1),
                job_types=("migration-expiry",),
            )
            is None
        )
        with engine.connect() as connection:
            exhausted_status = connection.execute(
                text("SELECT status, last_error_code FROM background_jobs WHERE id = :job_id"),
                {"job_id": exhausted_job.job_id.hex},
            ).one()
        assert exhausted_status == (
            "FAILED",
            "LEASE_EXPIRED_ATTEMPTS_EXHAUSTED",
        )
        with pytest.raises(IntegrityError, match="cannot be deleted"):
            with engine.begin() as connection:
                connection.execute(
                    text("DELETE FROM background_jobs WHERE id = :job_id"),
                    {"job_id": scheduled.job_id.hex},
                )
    finally:
        engine.dispose()

    with pytest.raises(
        RuntimeError,
        match="fenced background job provenance",
    ):
        command.downgrade(config, "0005")
    assert _table_names(database_url) == (
        EXPECTED_HEAD_TABLES
        - RELIABILITY_TABLES
        - HERMES_TABLES
        - RETRIEVAL_INDEX_TABLES
        - EVALUATION_TELEMETRY_TABLES
        - CANDIDATE_LEARNING_TABLES
        - CONTROLLED_POLICY_TABLES
    )


def test_cancellation_revision_fences_queued_and_running_jobs(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)
    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    factory = create_session_factory(engine)
    store = ArtifactStore(tmp_path / "artifacts")
    now = datetime.now(UTC)
    try:
        with factory.begin() as session:
            task = create_task_record(
                session,
                store,
                repository="boppuh/mathews",
                base_revision="1" * 40,
                requester="local-user",
                raw_request="Cancel migrated durable jobs",
                summary="Cancel durable jobs",
                owner_id="local-user",
                actor_id="local-user",
            )
            session.add(
                PolicyVersion(
                    lineage_key="mvp",
                    version=1,
                    predecessor_id=None,
                    workflow_thresholds={},
                    approved_by="local-user",
                    approved_at=now,
                    owner_id=task.owner_id,
                    actor_id="local-user",
                    root_correlation_id=task.root_correlation_id,
                )
            )
            task_id = task.id
        jobs = BackgroundJobService(factory, store, clock=lambda: now)
        running = jobs.schedule(
            task_id=task_id,
            job_type="running-cancellation",
            idempotency_key="running-cancellation:1",
            input_payload={"state": "running"},
        )
        grant = jobs.claim_next(
            worker_id="migration-worker",
            lease_duration=timedelta(seconds=60),
            job_types=("running-cancellation",),
        )
        assert grant is not None
        queued = jobs.schedule(
            task_id=task_id,
            job_type="queued-cancellation",
            idempotency_key="queued-cancellation:1",
            input_payload={"state": "queued"},
        )
        realtime_jobs = BackgroundJobService(factory, store)
        expired = realtime_jobs.schedule(
            task_id=task_id,
            job_type="expired-recovery",
            idempotency_key="expired-recovery:1",
            input_payload={"state": "expired"},
            retry_policy=RetryPolicy(max_attempts=2),
        )
        expired_grant = realtime_jobs.claim_next(
            worker_id="expired-recovery-worker",
            lease_duration=timedelta(seconds=1),
            job_types=("expired-recovery",),
        )
        assert expired_grant is not None
        time.sleep(1.1)
        ignored = realtime_jobs.record_ignored_result(
            expired_grant,
            idempotency_key="expired-recovery:late-result",
            effect_id=None,
            result=EffectExecutionResult(
                succeeded=True,
                payload={"result": "late"},
            ),
        )
        assert ignored.reason_code == "FENCED"
        assert realtime_jobs.reconcile_expired_leases() == (expired.job_id,)
        jobs.register_reconciliation_target(
            grant,
            kind=ReconciliationTargetKind.BRANCH_HEAD,
            target_key="branch-head:migration-cancellation",
            expected_payload={"head": "a" * 40},
        )

        cancellation_id = uuid4()
        cancellation_service = CancellationService(
            factory,
            store,
            clock=lambda: now,
        )
        cancelled = cancellation_service.cancel_task(
            task_id,
            cancellation_id=cancellation_id,
            expected_state=TaskState.INTAKE,
            reason_code="USER_CANCELLED",
        )

        assert cancelled.cleanup_complete is True
        replayed = cancellation_service.cancel_task(
            task_id,
            cancellation_id=cancellation_id,
            expected_state=TaskState.INTAKE,
            reason_code="USER_CANCELLED",
        )
        assert replayed.replayed is True
        assert replayed.cleanup_complete is True
        with factory() as session:
            running_row = session.get(BackgroundJob, running.job_id)
            queued_row = session.get(BackgroundJob, queued.job_id)
        assert running_row is not None and queued_row is not None
        states = {
            running.job_id: running_row.status,
            queued.job_id: queued_row.status,
        }
        assert states == {
            running.job_id: BackgroundJobStatus.CANCELLED,
            queued.job_id: BackgroundJobStatus.CANCELLED,
        }
        with pytest.raises(
            IntegrityError,
            match="task cancellation completion",
        ):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE task_cancellations "
                        "SET reason_code = 'REWRITTEN' WHERE id = :id"
                    ),
                    {"id": cancellation_id.hex},
                )
        with pytest.raises(
            IntegrityError,
            match="reliability provenance cannot be deleted",
        ):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "DELETE FROM task_cancellations WHERE id = :id"
                    ),
                    {"id": cancellation_id.hex},
                )
    finally:
        engine.dispose()

    with pytest.raises(
        RuntimeError,
        match="cancellation or outage provenance",
    ):
        command.downgrade(config, "0007")
    assert _table_names(database_url) == (
        EXPECTED_HEAD_TABLES
        - HERMES_TABLES
        - RETRIEVAL_INDEX_TABLES
        - EVALUATION_TELEMETRY_TABLES
        - CANDIDATE_LEARNING_TABLES
        - CONTROLLED_POLICY_TABLES
    )


def test_outage_escalation_and_resume_operate_through_migrated_guards(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)
    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    factory = create_session_factory(engine)
    store = ArtifactStore(tmp_path / "artifacts")
    now = datetime.now(UTC)
    try:
        with factory.begin() as session:
            task = create_task_record(
                session,
                store,
                repository="boppuh/mathews",
                base_revision="1" * 40,
                requester="local-user",
                raw_request="Exercise migrated outage semantics",
                summary="Exercise outage semantics",
                owner_id="local-user",
                actor_id="local-user",
            )
            session.add(
                PolicyVersion(
                    lineage_key="mvp",
                    version=1,
                    predecessor_id=None,
                    workflow_thresholds={},
                    approved_by="local-user",
                    approved_at=now,
                    owner_id=task.owner_id,
                    actor_id="local-user",
                    root_correlation_id=task.root_correlation_id,
                )
            )
            task_id = task.id
        jobs = BackgroundJobService(factory, store, clock=lambda: now)
        scheduled = jobs.schedule(
            task_id=task_id,
            job_type="github-outage",
            idempotency_key="github-outage:1",
            input_payload={"operation": "publish"},
            retry_policy=RetryPolicy(max_attempts=1),
        )
        grant = jobs.claim_next(
            worker_id="migration-worker",
            lease_duration=timedelta(seconds=60),
        )
        assert grant is not None
        jobs.checkpoint(
            grant,
            expected_version=0,
            idempotency_key="github-outage:checkpoint",
            payload={"head": "a" * 40},
        )

        exhausted = jobs.fail_dependency_attempt(
            grant,
            service=DependencyService.GITHUB,
            error_code="GITHUB_UNAVAILABLE",
        )

        assert exhausted.escalation_request_id is not None
        with factory() as session:
            request = session.get(
                ApprovalRequest,
                exhausted.escalation_request_id,
            )
        assert request is not None
        ApprovalService(factory, store, clock=lambda: now).decide(
            request.id,
            decision_id=uuid4(),
            decision=ApprovalDecision.RETRY,
            actor_id="local-user",
        )
        assert len(jobs.reconcile_outage_decisions()) == 1
        with factory() as session:
            generations = tuple(
                session.scalars(
                    select(BackgroundJob)
                    .where(BackgroundJob.task_id == task_id)
                    .order_by(BackgroundJob.created_at)
                )
            )
        assert len(generations) == 2
        assert generations[0].id == scheduled.job_id
        assert generations[0].status is BackgroundJobStatus.FAILED
        assert generations[1].status is BackgroundJobStatus.QUEUED
        assert generations[1].checkpoint == {"head": "a" * 40}
    finally:
        engine.dispose()


def test_evidence_revision_explicitly_fences_revision_0003_preflight_rows(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)
    evidence_id = "11111111111111111111111111111111"
    configuration_id = "22222222222222222222222222222222"
    correlation_id = "33333333333333333333333333333333"
    command.upgrade(config, "0003")
    engine = create_database_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO evidence_records ("
                    "id, evidence_type, origin, content_hash, content_address, "
                    "captured_at, access_classification, retention_policy, "
                    "owner_id, actor_id, root_correlation_id, deletion_actor_id, "
                    "deletion_reason"
                    ") VALUES ("
                    ":id, 'repository-preflight', 'host-agent:repository-preflight', "
                    ":hash, :hash, CURRENT_TIMESTAMP, 'internal', "
                    "'repository-configuration', 'local-user', 'host-agent', "
                    ":correlation_id, 'ghp_legacy_deletion_actor_secret', "
                    "'password=legacy-deletion-reason-secret')"
                ),
                {
                    "id": evidence_id,
                    "hash": f"sha256:{'a' * 64}",
                    "correlation_id": correlation_id,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO repository_configurations ("
                    "id, repository_key, version, repository_settings, git_settings, "
                    "xcode_settings, operations, e2e_assertions, artifact_settings, "
                    "prohibited_paths, secret_references, preflight_evidence_id, "
                    "owner_id, actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, 'boppuh/mathews', 1, '{}', '{}', '{}', '[]', '[]', "
                    "'{}', '[]', '[]', :evidence_id, 'local-user', 'local-user', "
                    ":correlation_id)"
                ),
                {
                    "id": configuration_id,
                    "evidence_id": evidence_id,
                    "correlation_id": correlation_id,
                },
            )
    finally:
        engine.dispose()

    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    try:
        with engine.connect() as connection:
            pointer = connection.execute(
                text("SELECT preflight_evidence_id FROM repository_configurations WHERE id = :id"),
                {"id": configuration_id},
            ).scalar_one()
            migrated = connection.execute(
                text(
                    "SELECT access_classification, retention_policy, evidence_type, "
                    "origin, owner_id, actor_id, deletion_actor_id, deletion_reason "
                    "FROM evidence_records WHERE id = :id"
                ),
                {"id": evidence_id},
            ).one()
    finally:
        engine.dispose()

    assert pointer is None
    assert migrated == (
        "INTERNAL",
        "REPOSITORY_LIFETIME",
        "legacy-evidence",
        "legacy:fenced",
        "local-user",
        "legacy-fenced",
        None,
        None,
    )


def test_evidence_revision_downgrade_fences_canonical_preflight_rows(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)
    evidence_id = "66666666666666666666666666666666"
    configuration_id = "77777777777777777777777777777777"
    correlation_id = "88888888888888888888888888888888"
    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO evidence_records ("
                    "id, evidence_type, origin, content_hash, content_address, "
                    "captured_at, access_classification, retention_policy, "
                    "owner_id, actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, 'repository-preflight', 'host-agent:preflight', "
                    ":hash, :hash, CURRENT_TIMESTAMP, 'INTERNAL', "
                    "'REPOSITORY_LIFETIME', 'local-user', 'host-agent', "
                    ":correlation_id)"
                ),
                {
                    "id": evidence_id,
                    "hash": f"sha256:{'c' * 64}",
                    "correlation_id": correlation_id,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO repository_configurations ("
                    "id, repository_key, version, repository_settings, git_settings, "
                    "xcode_settings, operations, e2e_assertions, artifact_settings, "
                    "prohibited_paths, secret_references, preflight_evidence_id, "
                    "owner_id, actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, 'boppuh/mathews', 1, '{}', '{}', '{}', '[]', '[]', "
                    "'{}', '[]', '[]', :evidence_id, 'local-user', 'local-user', "
                    ":correlation_id)"
                ),
                {
                    "id": configuration_id,
                    "evidence_id": evidence_id,
                    "correlation_id": correlation_id,
                },
            )
    finally:
        engine.dispose()

    command.downgrade(config, "0003")
    engine = create_database_engine(database_url)
    try:
        with engine.connect() as connection:
            pointer = connection.execute(
                text("SELECT preflight_evidence_id FROM repository_configurations WHERE id = :id"),
                {"id": configuration_id},
            ).scalar_one()
            labels = connection.execute(
                text(
                    "SELECT access_classification, retention_policy "
                    "FROM evidence_records WHERE id = :id"
                ),
                {"id": evidence_id},
            ).one()
    finally:
        engine.dispose()

    assert pointer is None
    assert labels == ("internal", "repository-configuration")


def test_migrated_evidence_audit_records_are_database_append_only(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)
    command.upgrade(config, "head")
    evidence_id = "44444444444444444444444444444444"
    correlation_id = "55555555555555555555555555555555"
    engine = create_database_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO evidence_records ("
                    "id, evidence_type, origin, content_hash, content_address, "
                    "captured_at, access_classification, retention_policy, "
                    "owner_id, actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, 'result', 'validator', :hash, :hash, CURRENT_TIMESTAMP, "
                    "'OWNER', 'AUDIT', 'local-user', 'validator', :correlation_id)"
                ),
                {
                    "id": evidence_id,
                    "hash": f"sha256:{'b' * 64}",
                    "correlation_id": correlation_id,
                },
            )

        with pytest.raises(IntegrityError, match="append-only"):
            with engine.begin() as connection:
                connection.execute(
                    text("UPDATE evidence_records SET origin = 'rewritten' WHERE id = :id"),
                    {"id": evidence_id},
                )
        with pytest.raises(IntegrityError, match="append-only"):
            with engine.begin() as connection:
                connection.execute(
                    text("DELETE FROM evidence_records WHERE id = :id"),
                    {"id": evidence_id},
                )
    finally:
        engine.dispose()


def test_migrated_task_lifecycle_requires_matching_append_only_audit(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)
    command.upgrade(config, "head")
    task_id = "99999999999999999999999999999999"
    policy_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    evidence_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    event_id = "cccccccccccccccccccccccccccccccc"
    transition_id = "dddddddddddddddddddddddddddddddd"
    reference_id = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    correlation_id = "ffffffffffffffffffffffffffffffff"
    global_evidence_id = "abababababababababababababababab"
    escalation_event_id = "ac" * 16
    escalation_transition_id = "ad" * 16
    escalation_reference_id = "ae" * 16
    illegal_event_id = "bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc"
    illegal_transition_id = "bdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbd"
    illegal_reference_id = "bebebebebebebebebebebebebebebebe"
    prompt_id = "cfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcf"
    prompt_membership_id = "de" * 16
    second_prompt_id = "df" * 16
    second_prompt_membership_id = "ef" * 16
    engine = create_database_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO tasks ("
                    "id, repository, base_revision, requester, raw_request, summary, "
                    "state, owner_id, actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, 'boppuh/mathews', :base_revision, 'local-user', "
                    "'evidence://request', 'Task', 'INTAKE', 'local-user', "
                    "'local-user', :correlation_id)"
                ),
                {
                    "id": task_id,
                    "base_revision": "1" * 40,
                    "correlation_id": correlation_id,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO evidence_records ("
                    "id, task_id, evidence_type, origin, content_hash, content_address, "
                    "captured_at, access_classification, retention_policy, owner_id, "
                    "actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, NULL, 'repository-policy', 'control-plane', :hash, :hash, "
                    "CURRENT_TIMESTAMP, 'INTERNAL', 'AUDIT', "
                    "'local-user', 'local-user', :correlation_id)"
                ),
                {
                    "id": global_evidence_id,
                    "hash": f"sha256:{'5' * 64}",
                    "correlation_id": correlation_id,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO prompt_template_versions ("
                    "id, lineage_key, role, version, structured_template, "
                    "evaluation_threshold_passed, regression_reviewed, promoted, "
                    "approved_by, approved_at, owner_id, actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, 'task-state', 'control-plane', 1, '{}', 1, 1, 1, "
                    "'local-user', CURRENT_TIMESTAMP, 'local-user', "
                    "'control-plane', :correlation_id)"
                ),
                {"id": prompt_id, "correlation_id": correlation_id},
            )
            connection.execute(
                text(
                    "INSERT INTO policy_versions ("
                    "id, lineage_key, version, workflow_thresholds, approved_by, "
                    "approved_at, owner_id, actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, 'mvp', 1, '{}', 'local-user', CURRENT_TIMESTAMP, "
                    "'local-user', 'local-user', :correlation_id)"
                ),
                {"id": policy_id, "correlation_id": correlation_id},
            )
            connection.execute(
                text(
                    "INSERT INTO policy_version_prompt_templates ("
                    "id, policy_version_id, prompt_template_version_id, "
                    "prompt_promoted, position, owner_id, actor_id, "
                    "root_correlation_id"
                    ") VALUES ("
                    ":id, :policy_id, :prompt_id, 1, 1, 'local-user', "
                    "'control-plane', :correlation_id)"
                ),
                {
                    "id": prompt_membership_id,
                    "policy_id": policy_id,
                    "prompt_id": prompt_id,
                    "correlation_id": correlation_id,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO evidence_records ("
                    "id, task_id, evidence_type, origin, content_hash, content_address, "
                    "captured_at, access_classification, retention_policy, owner_id, "
                    "actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, :task_id, 'request', 'control-plane', :hash, :hash, "
                    "CURRENT_TIMESTAMP, 'TASK_OWNER', 'TASK_LIFETIME', "
                    "'local-user', 'local-user', :correlation_id)"
                ),
                {
                    "id": evidence_id,
                    "task_id": task_id,
                    "hash": f"sha256:{'1' * 64}",
                    "correlation_id": correlation_id,
                },
            )

        with pytest.raises(IntegrityError, match="matching audit"):
            with engine.begin() as connection:
                connection.execute(
                    text("UPDATE tasks SET state = 'BRIEFING' WHERE id = :id"),
                    {"id": task_id},
                )

        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO task_events ("
                    "id, task_id, sequence, event_type, payload, occurred_at, "
                    "transition_id, transition_fingerprint, transition_kind, "
                    "transition_from_state, transition_to_state, "
                    "transition_reason_code, policy_lineage_key, policy_version_id, "
                    "owner_id, actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, :task_id, 1, 'TASK_STATE_TRANSITION', '{}', "
                    "CURRENT_TIMESTAMP, :transition_id, :fingerprint, "
                    "'START_BRIEFING', 'INTAKE', 'BRIEFING', 'REQUEST_ACCEPTED', "
                    "'mvp', :policy_id, 'local-user', "
                    "'control-plane', :correlation_id)"
                ),
                {
                    "id": event_id,
                    "task_id": task_id,
                    "transition_id": transition_id,
                    "fingerprint": "2" * 64,
                    "policy_id": policy_id,
                    "correlation_id": correlation_id,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO task_event_evidence_references ("
                    "id, task_id, task_event_id, evidence_id, position, owner_id, "
                    "actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, :task_id, :event_id, :evidence_id, 1, 'local-user', "
                    "'control-plane', :correlation_id)"
                ),
                {
                    "id": reference_id,
                    "task_id": task_id,
                    "event_id": event_id,
                    "evidence_id": evidence_id,
                    "correlation_id": correlation_id,
                },
            )
            connection.execute(
                text("UPDATE tasks SET state = 'BRIEFING' WHERE id = :id"),
                {"id": task_id},
            )

        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO prompt_template_versions ("
                    "id, lineage_key, role, version, structured_template, "
                    "evaluation_threshold_passed, regression_reviewed, promoted, "
                    "approved_by, approved_at, owner_id, actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, 'task-state-next', 'control-plane', 1, '{}', 1, 1, 1, "
                    "'local-user', CURRENT_TIMESTAMP, 'local-user', "
                    "'control-plane', :correlation_id)"
                ),
                {
                    "id": second_prompt_id,
                    "correlation_id": correlation_id,
                },
            )
        with pytest.raises(IntegrityError, match="append-only"):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE prompt_template_versions "
                        "SET structured_template = '{\"changed\"\\:true}' "
                        "WHERE id = :id"
                    ),
                    {"id": second_prompt_id},
                )
        with pytest.raises(IntegrityError, match="membership is sealed"):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO policy_version_prompt_templates ("
                        "id, policy_version_id, prompt_template_version_id, "
                        "prompt_promoted, position, owner_id, actor_id, "
                        "root_correlation_id"
                        ") VALUES ("
                        ":id, :policy_id, :prompt_id, 1, 2, 'local-user', "
                        "'control-plane', :correlation_id)"
                    ),
                    {
                        "id": second_prompt_membership_id,
                        "policy_id": policy_id,
                        "prompt_id": second_prompt_id,
                        "correlation_id": correlation_id,
                    },
                )
        with pytest.raises(IntegrityError, match="append-only"):
            with engine.begin() as connection:
                connection.execute(
                    text("UPDATE task_events SET payload = '{}' WHERE id = :id"),
                    {"id": event_id},
                )
        with pytest.raises(IntegrityError, match="append-only"):
            with engine.begin() as connection:
                connection.execute(
                    text("DELETE FROM task_event_evidence_references WHERE id = :id"),
                    {"id": reference_id},
                )
        with pytest.raises(IntegrityError, match="append-only"):
            with engine.begin() as connection:
                connection.execute(
                    text("UPDATE policy_versions SET approved_by = 'rewritten' WHERE id = :id"),
                    {"id": policy_id},
                )
        with pytest.raises(IntegrityError, match="append-only"):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE prompt_template_versions "
                        "SET structured_template = '{\"changed\"\\:true}' "
                        "WHERE id = :id"
                    ),
                    {"id": prompt_id},
                )
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO task_events ("
                    "id, task_id, sequence, event_type, payload, occurred_at, "
                    "transition_id, transition_fingerprint, transition_kind, "
                    "transition_from_state, transition_to_state, "
                    "transition_reason_code, policy_lineage_key, policy_version_id, "
                    "owner_id, actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, :task_id, 2, 'TASK_STATE_TRANSITION', '{}', "
                    "CURRENT_TIMESTAMP, :transition_id, :fingerprint, 'ESCALATE', "
                    "'BRIEFING', 'ESCALATED', 'DEPENDENCY_OUTAGE', 'mvp', "
                    ":policy_id, 'local-user', "
                    "'control-plane', :correlation_id)"
                ),
                {
                    "id": escalation_event_id,
                    "task_id": task_id,
                    "transition_id": escalation_transition_id,
                    "fingerprint": "6" * 64,
                    "policy_id": policy_id,
                    "correlation_id": correlation_id,
                },
            )
        with pytest.raises(IntegrityError, match="belong to task"):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO task_event_evidence_references ("
                        "id, task_id, task_event_id, evidence_id, position, owner_id, "
                        "actor_id, root_correlation_id"
                        ") VALUES ("
                        "'afafafafafafafafafafafafafafafaf', :task_id, :event_id, "
                        ":evidence_id, 1, 'local-user', 'control-plane', "
                        ":correlation_id)"
                    ),
                    {
                        "task_id": task_id,
                        "event_id": escalation_event_id,
                        "evidence_id": global_evidence_id,
                        "correlation_id": correlation_id,
                    },
                )
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO task_event_evidence_references ("
                    "id, task_id, task_event_id, evidence_id, position, owner_id, "
                    "actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, :task_id, :event_id, :evidence_id, 1, 'local-user', "
                    "'control-plane', :correlation_id)"
                ),
                {
                    "id": escalation_reference_id,
                    "task_id": task_id,
                    "event_id": escalation_event_id,
                    "evidence_id": evidence_id,
                    "correlation_id": correlation_id,
                },
            )
        with pytest.raises(
            IntegrityError,
            match=r"lifecycle projection|matching audit",
        ):
            with engine.begin() as connection:
                connection.execute(
                    text("UPDATE tasks SET state = 'ESCALATED' WHERE id = :id"),
                    {"id": task_id},
                )
        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO task_events ("
                        "id, task_id, sequence, event_type, payload, occurred_at, "
                        "transition_id, transition_fingerprint, transition_kind, "
                        "transition_from_state, transition_to_state, "
                        "transition_reason_code, policy_lineage_key, "
                        "policy_version_id, gate_head_sha, owner_id, actor_id, "
                        "root_correlation_id"
                        ") VALUES ("
                        "'fafafafafafafafafafafafafafafafa', :task_id, 3, "
                        "'TASK_STATE_TRANSITION', '{}', CURRENT_TIMESTAMP, "
                        "'fbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfb', :fingerprint, "
                        "'ACKNOWLEDGE_HANDOFF', 'BRIEFING', 'HANDED_OFF', "
                        "'INVALID_HEAD', 'mvp', :policy_id, :head_sha, "
                        "'local-user', 'control-plane', :correlation_id)"
                    ),
                    {
                        "task_id": task_id,
                        "fingerprint": "9" * 64,
                        "policy_id": policy_id,
                        "head_sha": "z" * 40,
                        "correlation_id": correlation_id,
                    },
                )
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO task_events ("
                    "id, task_id, sequence, event_type, payload, occurred_at, "
                    "transition_id, transition_fingerprint, transition_kind, "
                    "transition_from_state, transition_to_state, "
                    "transition_reason_code, policy_lineage_key, policy_version_id, "
                    "gate_head_sha, owner_id, actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, :task_id, 3, 'TASK_STATE_TRANSITION', '{}', "
                    "CURRENT_TIMESTAMP, :transition_id, :fingerprint, "
                    "'ACKNOWLEDGE_HANDOFF', 'BRIEFING', 'HANDED_OFF', "
                    "'FORGED_HANDOFF', 'mvp', :policy_id, :head_sha, 'local-user', "
                    "'control-plane', :correlation_id)"
                ),
                {
                    "id": illegal_event_id,
                    "task_id": task_id,
                    "transition_id": illegal_transition_id,
                    "fingerprint": "7" * 64,
                    "policy_id": policy_id,
                    "head_sha": "8" * 40,
                    "correlation_id": correlation_id,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO task_event_evidence_references ("
                    "id, task_id, task_event_id, evidence_id, position, owner_id, "
                    "actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, :task_id, :event_id, :evidence_id, 1, 'local-user', "
                    "'control-plane', :correlation_id)"
                ),
                {
                    "id": illegal_reference_id,
                    "task_id": task_id,
                    "event_id": illegal_event_id,
                    "evidence_id": evidence_id,
                    "correlation_id": correlation_id,
                },
            )
        with pytest.raises(
            IntegrityError,
            match=r"illegal task lifecycle edge|matching audit",
        ):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE tasks SET state = 'HANDED_OFF', "
                        "terminal_outcome = 'AUTOMATION_HANDED_OFF' WHERE id = :id"
                    ),
                    {"id": task_id},
                )
        with pytest.raises(IntegrityError, match="cannot be deleted"):
            with engine.begin() as connection:
                connection.execute(
                    text("DELETE FROM tasks WHERE id = :id"),
                    {"id": task_id},
                )
        with pytest.raises(IntegrityError, match="begin in INTAKE"):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO tasks ("
                        "id, repository, base_revision, requester, raw_request, "
                        "summary, state, owner_id, actor_id, root_correlation_id"
                        ") VALUES ("
                        "'12121212121212121212121212121212', 'boppuh/mathews', "
                        ":base_revision, 'local-user', 'evidence://request', "
                        "'Invalid', 'READY_FOR_HUMAN_MERGE', 'local-user', "
                        "'local-user', '13131313131313131313131313131313')"
                    ),
                    {"base_revision": "3" * 40},
                )
    finally:
        engine.dispose()


def test_task_transition_revision_scrubs_legacy_task_events(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)
    task_id = "14141414141414141414141414141414"
    event_id = "15151515151515151515151515151515"
    correlation_id = "16161616161616161616161616161616"
    command.upgrade(config, "0004")
    engine = create_database_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO tasks ("
                    "id, repository, base_revision, requester, raw_request, summary, "
                    "state, owner_id, actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, 'boppuh/mathews', :base_revision, 'local-user', "
                    "'evidence://request', 'Task', 'INTAKE', 'local-user', "
                    "'local-user', :correlation_id)"
                ),
                {
                    "id": task_id,
                    "base_revision": "4" * 40,
                    "correlation_id": correlation_id,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO task_events ("
                    "id, task_id, sequence, event_type, payload, occurred_at, "
                    "owner_id, actor_id, root_correlation_id"
                    ") VALUES ("
                    ":id, :task_id, 1, 'USER_MESSAGE', :payload, CURRENT_TIMESTAMP, "
                    "'secret-owner', 'ghp_legacy_actor_secret', :correlation_id)"
                ),
                {
                    "id": event_id,
                    "task_id": task_id,
                    "payload": '{"password":"legacy-event-secret"}',
                    "correlation_id": correlation_id,
                },
            )
    finally:
        engine.dispose()

    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    try:
        with engine.connect() as connection:
            event = connection.execute(
                text(
                    "SELECT event_type, payload, owner_id, actor_id FROM task_events WHERE id = :id"
                ),
                {"id": event_id},
            ).one()
    finally:
        engine.dispose()

    assert event[0] == "LEGACY_EVENT_FENCED"
    assert json.loads(event[1]) == {"legacy_event_fenced": True}
    assert event[2:] == ("local-user", "legacy-fenced")


def test_task_transition_revision_refuses_to_discard_accepted_provenance(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite:///{tmp_path / 'migrations.sqlite3'}"
    config = _migration_config(database_url)
    command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    factory = create_session_factory(engine)
    store = ArtifactStore(tmp_path / "artifacts")
    now = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
    try:
        with factory.begin() as session:
            task = create_task_record(
                session,
                store,
                repository="boppuh/mathews",
                base_revision="9" * 40,
                requester="local-user",
                raw_request="Preserve transition provenance",
                summary="Preserve transition provenance",
                owner_id="local-user",
                actor_id="control-plane",
            )
            session.add(
                PolicyVersion(
                    lineage_key="mvp",
                    version=1,
                    workflow_thresholds={},
                    approved_by="local-user",
                    approved_at=now,
                    owner_id="local-user",
                    actor_id="control-plane",
                    root_correlation_id=task.root_correlation_id,
                )
            )
            session.flush()
            evidence_id = session.scalar(
                select(EvidenceRecord.id).where(EvidenceRecord.task_id == task.id)
            )
            assert evidence_id is not None
            task_id = task.id

        result = TaskTransitionService(
            factory,
            store,
            clock=lambda: now,
        ).transition(
            task_id,
            transition_id=uuid4(),
            expected_state=TaskState.INTAKE,
            kind=TaskTransitionKind.START_BRIEFING,
            reason_code="REQUEST_ACCEPTED",
            evidence_ids=(evidence_id,),
        )

        with pytest.raises(RuntimeError, match="audited task transitions"):
            command.downgrade(config, "0004")

        with factory() as session:
            event = session.get(TaskEvent, result.event_id)
        assert event is not None
        assert event.transition_reason_code == "REQUEST_ACCEPTED"
        assert event.policy_version_id is not None
    finally:
        engine.dispose()


def test_offline_postgres_migration_sql_hides_database_password(
    capsys: pytest.CaptureFixture[str],
) -> None:
    password = "database-password-that-must-not-leak"
    config = _migration_config(f"postgresql+psycopg://mathews:{password}@127.0.0.1:5432/mathews")

    command.upgrade(config, "head", sql=True)

    captured = capsys.readouterr()
    assert "CREATE TABLE tasks" in captured.out
    assert "CREATE TABLE authentication_state" in captured.out
    assert "CREATE TABLE local_users" in captured.out
    assert "CREATE TABLE auth_sessions" in captured.out
    assert "CREATE TABLE validation_contracts" in captured.out
    assert "CREATE TABLE webhook_deliveries" in captured.out
    assert "IF TG_OP = 'UPDATE' THEN" in captured.out
    assert "IF TG_OP = 'UPDATE' AND" not in captured.out
    assert "migration-0007-legacy-fence" in captured.out
    assert password not in captured.out
    assert password not in captured.err
