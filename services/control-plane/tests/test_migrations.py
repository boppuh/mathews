import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.database import (
    Base,
    create_database_engine,
    create_session_factory,
    create_task_record,
)
from mathews_control_plane.domain_models import (
    EvidenceRecord,
    PolicyVersion,
    TaskEvent,
    TaskState,
)
from mathews_control_plane.task_state_machine import (
    TaskTransitionKind,
    TaskTransitionService,
)
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.exc import IntegrityError

EXPECTED_HEAD_TABLES = {
    "alembic_version",
    "approval_requests",
    "auth_sessions",
    "authentication_state",
    "background_job_leases",
    "background_jobs",
    "brief_approval_decisions",
    "briefs",
    "evidence_audit_events",
    "evidence_deletion_requests",
    "evidence_derivatives",
    "evidence_records",
    "evidence_tombstones",
    "local_users",
    "policy_version_prompt_templates",
    "policy_version_review_rules",
    "policy_versions",
    "prompt_template_versions",
    "repository_configurations",
    "review_rules",
    "rule_candidates",
    "task_events",
    "task_event_evidence_references",
    "tasks",
    "validation_contracts",
    "validation_runs",
    "webhook_deliveries",
}


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
                text(
                    "SELECT preflight_evidence_id FROM repository_configurations "
                    "WHERE id = :id"
                ),
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
                text(
                    "SELECT preflight_evidence_id FROM repository_configurations "
                    "WHERE id = :id"
                ),
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
                    text(
                        "UPDATE evidence_records SET origin = 'rewritten' "
                        "WHERE id = :id"
                    ),
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
                    text(
                        "UPDATE task_events SET payload = '{}' WHERE id = :id"
                    ),
                    {"id": event_id},
                )
        with pytest.raises(IntegrityError, match="append-only"):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "DELETE FROM task_event_evidence_references WHERE id = :id"
                    ),
                    {"id": reference_id},
                )
        with pytest.raises(IntegrityError, match="append-only"):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE policy_versions SET approved_by = 'rewritten' "
                        "WHERE id = :id"
                    ),
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
                    "SELECT event_type, payload, owner_id, actor_id "
                    "FROM task_events WHERE id = :id"
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
                select(EvidenceRecord.id).where(
                    EvidenceRecord.task_id == task.id
                )
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
    assert password not in captured.out
    assert password not in captured.err
