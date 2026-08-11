import hashlib
import os
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from typing import TypedDict
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from mathews_configuration import (
    AssertionKind,
    OperationKind,
    PreflightCheck,
    PreflightCheckCode,
    PreflightStatus,
    ProhibitedOperation,
    RepositoryConfiguration,
    RepositoryPreflightReport,
)
from mathews_control_plane.approvals import ApprovalService, BlockedOperation
from mathews_control_plane.artifacts import ArtifactStore
from mathews_control_plane.authentication import (
    AuthenticationService,
    BootstrapAlreadyCompletedError,
    IssuedSession,
    generate_bootstrap_token,
)
from mathews_control_plane.background_jobs import (
    BackgroundJobLeaseLostError,
    BackgroundJobService,
    JobLeaseGrant,
)
from mathews_control_plane.database import (
    create_database_engine,
    create_session_factory,
    create_task_record,
    get_task_record,
    session_scope,
)
from mathews_control_plane.domain_models import (
    ApprovalDecision,
    ApprovalRequestType,
    BackgroundJob,
    BackgroundJobStatus,
    EvidenceRecord,
    PolicyVersion,
    Task,
    TaskEvent,
    TaskState,
)
from mathews_control_plane.evidence import (
    EvidenceAccessClass,
    EvidenceRetentionClass,
    EvidenceSourceKind,
    capture_evidence,
)
from mathews_control_plane.reliability import CancellationService
from mathews_control_plane.repository_configuration import (
    begin_preflight_attempt,
    capture_preflight_report,
    create_repository_configuration,
    repository_configuration_digest,
    require_preflight_ready,
)
from mathews_control_plane.task_state_machine import (
    TaskTransitionConflictError,
    TaskTransitionKind,
    TaskTransitionResult,
    TaskTransitionService,
)
from sqlalchemy import inspect, select, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import DBAPIError, IntegrityError

_DATABASE_URL_ENV = "POSTGRES_TEST_DATABASE_URL"


class _RepositoryConfigurationArguments(TypedDict):
    repository_key: str
    repository_settings: dict[str, object]
    git_settings: dict[str, object]
    xcode_settings: dict[str, object]
    operations: list[object]
    e2e_assertions: list[object]
    artifact_settings: dict[str, object]
    prohibited_paths: list[object]
    secret_references: list[object]


def _repository_configuration_arguments(
    root: Path,
) -> _RepositoryConfigurationArguments:
    test_account = "keychain://mathews-tests/primary-account"
    e2e_flow = {
        "flow_id": "primary_journey",
        "version": 1,
        "entry_point": "app.launch",
        "terminal_state": "task.completed",
        "fixture_id": "primary_fixture",
        "fixture_version": 1,
        "fixture_digest": f"sha256:{'1' * 64}",
        "test_account_recipe_id": "primary_account",
        "test_account_recipe_version": 1,
        "test_account_recipe_digest": f"sha256:{'2' * 64}",
        "test_account": test_account,
        "runner_test_identifier": ("MathewsUITests/PrimaryJourneyTests/testPrimaryJourney"),
        "app_bundle_identifier": "com.boppuh.mathews",
        "harness_source_root": "MathewsUITests",
        "harness_project_path": "MathewsHarness.xcodeproj",
        "harness_target_identifier": "AAAAAAAAAAAAAAAAAAAAAAAA",
        "runner_source_file": "MathewsUITests/PrimaryJourneyTests.swift",
        "harness_files": [
            {
                "path": "Mathews.xcworkspace/contents.xcworkspacedata",
                "digest": f"sha256:{'3' * 64}",
            },
            {
                "path": ("Mathews.xcworkspace/xcshareddata/xcschemes/Mathews.xcscheme"),
                "digest": f"sha256:{'4' * 64}",
            },
            {
                "path": ("MathewsHarness.xcodeproj/project.pbxproj"),
                "digest": f"sha256:{'5' * 64}",
            },
            {
                "path": "MathewsUITests/PrimaryJourneyTests.swift",
                "digest": f"sha256:{'6' * 64}",
            },
        ],
        "fixture_file": {
            "path": "Fixtures/primary.json",
            "digest": f"sha256:{'1' * 64}",
        },
        "test_account_recipe_file": {
            "path": "Fixtures/primary-account.json",
            "digest": f"sha256:{'2' * 64}",
        },
        "required_assertion_ids": [
            "task-title",
            "terminal-state",
            "network-response",
            "log-event",
            "no-crash",
        ],
        "clean_state_before_each_run": True,
        "locale_identifier": "en_US_POSIX",
        "time_zone_identifier": "UTC",
        "clean_state_steps": [
            "SHUTDOWN",
            "ERASE",
            "BOOT",
            "INSTALL_CANDIDATE",
        ],
        "expected_network_signals": ["task.created"],
        "expected_log_signals": ["task.completed"],
        "acceptable_warnings": [],
    }
    operations: list[object] = []
    for kind in OperationKind:
        operation: dict[str, object] = {
            "operation_id": kind.value.lower(),
            "kind": kind.value,
            "argv": [
                "xcodebuild",
                "build" if kind is OperationKind.BUILD else "test",
                "-workspace",
                "Mathews.xcworkspace",
                "-scheme",
                "Mathews",
                "-destination",
                "MATHEWS_CONFIGURED_SIMULATOR",
            ],
            "timeout_seconds": 600,
            "e2e_flow": (e2e_flow if kind is OperationKind.SIMULATOR_E2E else None),
        }
        if kind is OperationKind.SIMULATOR_E2E:
            assert isinstance(operation["argv"], list)
            operation["argv"].append(
                "-only-testing:MathewsUITests/PrimaryJourneyTests/testPrimaryJourney"
            )
        operations.append(operation)
    return {
        "repository_key": "boppuh/mathews",
        "repository_settings": {
            "root": str(root),
            "prohibited_operations": [operation.value for operation in ProhibitedOperation],
        },
        "git_settings": {
            "default_base_ref": "refs/remotes/origin/main",
            "task_branch_template": "mathews/{task_id}",
            "remote_name": "origin",
            "push_credential": "keychain://mathews/git-push",
            "author": {"name": "Mathews", "email": "mathews@example.test"},
            "committer": {"name": "Mathews", "email": "mathews@example.test"},
        },
        "xcode_settings": {
            "container_kind": "WORKSPACE",
            "container_path": "Mathews.xcworkspace",
            "scheme": "Mathews",
            "simulator": {
                "runtime_identifier": ("com.apple.CoreSimulator.SimRuntime.iOS-26-0"),
                "device_type_identifier": ("com.apple.CoreSimulator.SimDeviceType.iPhone-17-Pro"),
            },
        },
        "operations": operations,
        "e2e_assertions": [
            {
                "assertion_id": "task-title",
                "kind": AssertionKind.ELEMENT_VALUE_PRESENT.value,
                "role": "FLOW_BASELINE",
                "catalog_key": "task.title",
                "verifier": {
                    "accessibility_identifier": "task.title",
                    "expected_value_fixture_key": "task.title",
                },
            },
            {
                "assertion_id": "terminal-state",
                "kind": AssertionKind.NAVIGATION_STATE_REACHED.value,
                "role": "FLOW_BASELINE",
                "catalog_key": "task.completed.state",
                "verifier": {
                    "state_id": "task.completed",
                    "marker_accessibility_identifier": "task.completed",
                },
            },
            {
                "assertion_id": "network-response",
                "kind": AssertionKind.EXPECTED_NETWORK_RESPONSE.value,
                "role": "FLOW_BASELINE",
                "catalog_key": "task.created.response",
                "verifier": {
                    "endpoint_class": "task.created",
                    "method": "POST",
                    "expected_status_code": 201,
                },
            },
            {
                "assertion_id": "log-event",
                "kind": AssertionKind.EXPECTED_LOG_EVENT.value,
                "role": "FLOW_BASELINE",
                "catalog_key": "task.completed.log",
                "verifier": {
                    "subsystem": "com.boppuh.mathews",
                    "category": "task",
                    "event_key": "task.completed",
                    "minimum_count": 1,
                },
            },
            {
                "assertion_id": "no-crash",
                "kind": AssertionKind.NO_CRASH.value,
                "role": "FLOW_BASELINE",
                "catalog_key": "app.process",
                "verifier": {"bundle_identifier": "com.boppuh.mathews"},
            },
            {
                "assertion_id": "task-title-change",
                "kind": AssertionKind.ELEMENT_VALUE_PRESENT.value,
                "role": "TASK_SELECTABLE",
                "catalog_key": "task.title.change",
                "verifier": {
                    "accessibility_identifier": "task.title",
                    "expected_value_fixture_key": "task.title",
                },
            },
        ],
        "artifact_settings": {"collection_paths": ["artifacts/test"]},
        "prohibited_paths": [
            ".git",
            "Mathews.xcworkspace/contents.xcworkspacedata",
            "Mathews.xcworkspace/xcshareddata/xcschemes/Mathews.xcscheme",
            "MathewsHarness.xcodeproj/project.pbxproj",
            "MathewsUITests",
            "Fixtures/primary.json",
            "Fixtures/primary-account.json",
        ],
        "secret_references": [test_account, "keychain://mathews/git-push"],
    }


def _migration_config(database_url: str) -> Config:
    service_root = Path(__file__).parents[1]
    config = Config(str(service_root / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


def test_postgres_repository_configuration_fixture_is_valid(tmp_path: Path) -> None:
    arguments = _repository_configuration_arguments(tmp_path)
    configuration = RepositoryConfiguration.from_dict(
        uuid4(),
        {
            "repository_key": arguments["repository_key"],
            "version": 1,
            "repository_settings": arguments["repository_settings"],
            "git_settings": arguments["git_settings"],
            "xcode_settings": arguments["xcode_settings"],
            "operations": arguments["operations"],
            "e2e_assertions": arguments["e2e_assertions"],
            "artifact_settings": arguments["artifact_settings"],
            "prohibited_paths": arguments["prohibited_paths"],
            "secret_references": arguments["secret_references"],
        },
    )

    assert configuration.repository_key == "boppuh/mathews"


def _configured_database_url() -> str:
    database_url = os.environ.get(_DATABASE_URL_ENV)
    if database_url is None:
        pytest.skip(f"{_DATABASE_URL_ENV} is required for the PostgreSQL integration test")
    return database_url


def _schema_database_url(database_url: str, schema: str) -> str:
    url = make_url(database_url).update_query_dict({"options": f"-csearch_path={schema}"})
    return url.render_as_string(hide_password=False)


def test_postgres_migrations_and_durable_storage_smoke(tmp_path: Path) -> None:
    admin_database_url = _configured_database_url()
    schema = f"mathews_test_{uuid4().hex}"
    database_url = _schema_database_url(admin_database_url, schema)
    migration_config = _migration_config(database_url)
    payload = b"\x00durable infrastructure smoke\xff"
    expected_digest = hashlib.sha256(payload).hexdigest()
    admin_engine = create_database_engine(admin_database_url)
    engine: Engine | None = None
    schema_created = False
    try:
        with admin_engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        schema_created = True

        command.upgrade(migration_config, "head")
        command.upgrade(migration_config, "head")

        engine = create_database_engine(database_url)
        factory = create_session_factory(engine)
        store = ArtifactStore(tmp_path / "artifacts")
        authentication_service = AuthenticationService(factory)
        with engine.connect() as connection:
            current_revision = MigrationContext.configure(connection).get_current_revision()
        assert ScriptDirectory.from_config(migration_config).get_heads() == ["0012"]
        assert current_revision == "0012"
        inspector = inspect(engine)
        validation_run_foreign_keys = inspector.get_foreign_keys("validation_runs")
        validation_run_foreign_tables = {
            foreign_key["referred_table"] for foreign_key in validation_run_foreign_keys
        }
        assert {
            "tasks",
            "validation_contracts",
            "evidence_records",
        } <= validation_run_foreign_tables
        assert any(
            foreign_key["constrained_columns"]
            == ["validation_contract_id", "repository_configuration_id"]
            and foreign_key["referred_table"] == "validation_contracts"
            and foreign_key["referred_columns"] == ["id", "repository_configuration_id"]
            for foreign_key in validation_run_foreign_keys
        )
        assert {
            tuple(constraint["column_names"])
            for constraint in inspector.get_unique_constraints("task_events")
        } >= {("task_id", "sequence")}
        assert {
            tuple(constraint["column_names"])
            for constraint in inspector.get_unique_constraints("background_job_leases")
        } >= {("fencing_token",), ("idempotency_key",)}
        assert {
            tuple(constraint["column_names"])
            for constraint in inspector.get_unique_constraints("webhook_deliveries")
        } >= {("provider", "provider_delivery_id")}

        with session_scope(factory) as session:
            created = create_task_record(
                session,
                store,
                repository="boppuh/mathews",
                base_revision="a" * 40,
                requester="local-user",
                raw_request="PostgreSQL and artifact durability smoke",
                summary="PostgreSQL and artifact durability smoke",
                owner_id="local-user",
                actor_id="postgres-test",
            )
            task_id = created.id
            root_correlation_id = created.root_correlation_id
            repository_configuration = create_repository_configuration(
                session,
                **_repository_configuration_arguments(tmp_path / "target-repository"),
                owner_id="local-user",
                actor_id="postgres-test",
                root_correlation_id=root_correlation_id,
            )
            repository_configuration_id = repository_configuration.id
            repository_configuration_version = repository_configuration.version
            repository_digest = repository_configuration_digest(repository_configuration)
            base_sha = "b" * 40
            preflight_attempt = begin_preflight_attempt(
                session,
                store,
                configuration_id=repository_configuration_id,
                owner_id="local-user",
                actor_id="postgres-test",
                root_correlation_id=root_correlation_id,
            )
            preflight_report = RepositoryPreflightReport(
                attempt_id=preflight_attempt.attempt_id,
                configuration_id=repository_configuration_id,
                configuration_version=repository_configuration_version,
                configuration_digest=repository_digest,
                status=PreflightStatus.PASSED,
                checks=tuple(
                    PreflightCheck.for_status(code, PreflightStatus.PASSED)
                    for code in PreflightCheckCode
                ),
                resolved_base_sha=base_sha,
            )
            captured_preflight = capture_preflight_report(
                session,
                store,
                report=preflight_report,
                owner_id="local-user",
                actor_id="postgres-test",
                root_correlation_id=root_correlation_id,
            )
            preflight_evidence_id = captured_preflight.evidence_id
            session.add(
                TaskEvent(
                    task_id=task_id,
                    sequence=1,
                    event_type="CREATED",
                    payload={},
                    occurred_at=datetime.now(UTC),
                    owner_id="local-user",
                    actor_id="postgres-test",
                    root_correlation_id=root_correlation_id,
                )
            )
            session.add(
                PolicyVersion(
                    lineage_key="mvp",
                    version=1,
                    predecessor_id=None,
                    workflow_thresholds={},
                    approved_by="local-user",
                    approved_at=datetime.now(UTC),
                    owner_id="local-user",
                    actor_id="postgres-test",
                    root_correlation_id=root_correlation_id,
                )
            )
        with engine.connect() as connection:
            request_evidence_id = connection.execute(
                text(
                    "SELECT id FROM evidence_records "
                    "WHERE task_id = :task_id AND evidence_type = 'task-request'"
                ),
                {"task_id": task_id},
            ).scalar_one()
        with pytest.raises(DBAPIError, match="append-only"):
            with engine.begin() as connection:
                connection.execute(
                    text("UPDATE evidence_records SET origin = 'rewritten' WHERE id = :id"),
                    {"id": request_evidence_id},
                )
        with pytest.raises(IntegrityError):
            with session_scope(factory) as session:
                session.add(
                    TaskEvent(
                        task_id=task_id,
                        sequence=1,
                        event_type="DUPLICATE",
                        payload={},
                        occurred_at=datetime.now(UTC),
                        owner_id="local-user",
                        actor_id="postgres-test",
                        root_correlation_id=root_correlation_id,
                    )
                )
        transition_service = TaskTransitionService(
            factory,
            store,
            principal_id="postgres-test",
        )

        def transition_concurrently(
            kind: TaskTransitionKind,
        ) -> TaskTransitionResult | TaskTransitionConflictError:
            try:
                return transition_service.transition(
                    task_id,
                    transition_id=uuid4(),
                    expected_state=TaskState.INTAKE,
                    kind=kind,
                    reason_code=kind.value,
                    evidence_ids=(request_evidence_id,),
                )
            except TaskTransitionConflictError as error:
                return error

        with ThreadPoolExecutor(max_workers=2) as executor:
            transition_results = list(
                executor.map(
                    transition_concurrently,
                    (
                        TaskTransitionKind.START_BRIEFING,
                        TaskTransitionKind.CANCEL,
                    ),
                )
            )
        accepted_transitions = [
            result for result in transition_results if isinstance(result, TaskTransitionResult)
        ]
        stale_transitions = [
            result
            for result in transition_results
            if isinstance(result, TaskTransitionConflictError)
        ]
        assert len(accepted_transitions) == 1
        assert len(stale_transitions) == 1
        with factory() as session:
            transitioned_task = session.get(Task, task_id)
        assert transitioned_task is not None
        assert transitioned_task.state in {
            TaskState.BRIEFING,
            TaskState.CANCELLED,
        }

        with session_scope(factory) as session:
            approval_task = create_task_record(
                session,
                store,
                repository="boppuh/mathews",
                base_revision="7" * 40,
                requester="local-user",
                raw_request="Exercise PostgreSQL approval triggers",
                summary="Exercise approval triggers",
                owner_id="local-user",
                actor_id="postgres-test",
            )
            session.flush()
            approval_evidence_id = session.scalar(
                select(EvidenceRecord.id).where(
                    EvidenceRecord.task_id == approval_task.id
                )
            )
            assert approval_evidence_id is not None
            approval_task_id = approval_task.id
        approval_service = ApprovalService(
            factory,
            store,
            principal_id="postgres-test",
        )
        approval = approval_service.request(
            approval_task_id,
            request_id=uuid4(),
            expected_state=TaskState.INTAKE,
            request_type=ApprovalRequestType.UNSAFE_ACTION,
            reason_code="UNSAFE_ACTION_REQUIRED",
            subject_type="BLOCKED_OPERATION",
            subject_id=None,
            blocked_operation=BlockedOperation(
                operation_name="host.mutate",
                idempotency_key="postgres-approval-operation",
                input_fingerprint="a" * 64,
            ),
            evidence_ids=(approval_evidence_id,),
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
        approval_decision = approval_service.decide(
            approval.request_id,
            decision_id=uuid4(),
            decision=ApprovalDecision.DENY,
            actor_id="local-user",
        )
        assert approval.task_state is TaskState.ESCALATED
        assert approval_decision.task_state is TaskState.FAILED

        collision_inputs: list[tuple[UUID, UUID]] = []
        with session_scope(factory) as session:
            for index in range(2):
                collision_task = create_task_record(
                    session,
                    store,
                    repository="boppuh/mathews",
                    base_revision=f"{index + 2}" * 40,
                    requester="local-user",
                    raw_request=f"Global transition collision {index}",
                    summary=f"Global transition collision {index}",
                    owner_id="local-user",
                    actor_id="postgres-test",
                )
                session.flush()
                collision_evidence_id = session.scalar(
                    select(EvidenceRecord.id).where(EvidenceRecord.task_id == collision_task.id)
                )
                assert collision_evidence_id is not None
                collision_inputs.append((collision_task.id, collision_evidence_id))
        shared_transition_id = uuid4()

        def collide_transition_id(
            task_and_evidence: tuple[UUID, UUID],
        ) -> TaskTransitionResult | TaskTransitionConflictError:
            collision_task_id, collision_evidence_id = task_and_evidence
            try:
                return transition_service.transition(
                    collision_task_id,
                    transition_id=shared_transition_id,
                    expected_state=TaskState.INTAKE,
                    kind=TaskTransitionKind.START_BRIEFING,
                    reason_code="START_BRIEFING",
                    evidence_ids=(collision_evidence_id,),
                )
            except TaskTransitionConflictError as error:
                return error

        with ThreadPoolExecutor(max_workers=2) as executor:
            collision_results = list(executor.map(collide_transition_id, collision_inputs))
        assert sum(isinstance(result, TaskTransitionResult) for result in collision_results) == 1
        assert (
            sum(isinstance(result, TaskTransitionConflictError) for result in collision_results)
            == 1
        )

        job_service = BackgroundJobService(
            factory,
            store,
            principal_id="postgres-test",
        )
        with session_scope(factory) as session:
            job_task = create_task_record(
                session,
                store,
                repository="boppuh/mathews",
                base_revision="9" * 40,
                requester="local-user",
                raw_request="Exercise PostgreSQL job leasing",
                summary="Exercise job leasing",
                owner_id="local-user",
                actor_id="postgres-test",
            )
            job_task_id = job_task.id
        scheduled_job = job_service.schedule(
            task_id=job_task_id,
            job_type="postgres-race",
            idempotency_key=f"postgres-race:{job_task_id}",
            input_payload={"operation": "verify-claim"},
        )

        def claim_job(worker_id: str) -> JobLeaseGrant | None:
            return job_service.claim_next(
                worker_id=worker_id,
                lease_duration=timedelta(seconds=1),
                job_types=("postgres-race",),
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            claim_results = list(
                executor.map(claim_job, ("postgres-worker-1", "postgres-worker-2"))
            )
        job_grants = [result for result in claim_results if result is not None]
        assert len(job_grants) == 1
        first_job_grant = job_grants[0]
        assert first_job_grant.job_id == scheduled_job.job_id

        first_checkpoint = job_service.checkpoint(
            first_job_grant,
            expected_version=0,
            idempotency_key="postgres-checkpoint:current",
            payload={"step": "claimed"},
        )
        assert first_checkpoint.sequence == 1
        with pytest.raises(DBAPIError, match="invalid background job projection"):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE background_jobs SET checkpoint_version = 0, "
                        "last_fencing_token = :token WHERE id = :job_id"
                    ),
                    {
                        "job_id": first_job_grant.job_id,
                        "token": first_job_grant.fencing_token,
                    },
                )
        time.sleep(1.1)
        recovered_job_grant = claim_job("postgres-worker-recovered")
        assert recovered_job_grant is not None
        assert recovered_job_grant.recovered is True
        assert recovered_job_grant.attempt == 2
        assert recovered_job_grant.fencing_token > first_job_grant.fencing_token
        with pytest.raises(BackgroundJobLeaseLostError):
            job_service.checkpoint(
                first_job_grant,
                expected_version=1,
                idempotency_key="postgres-stale-checkpoint",
                payload={"stale": True},
            )

        with session_scope(factory) as session:
            cancellation_task = create_task_record(
                session,
                store,
                repository="boppuh/mathews",
                base_revision="8" * 40,
                requester="local-user",
                raw_request="Exercise PostgreSQL cancellation guards",
                summary="Exercise cancellation guards",
                owner_id="local-user",
                actor_id="postgres-test",
            )
            cancellation_task_id = cancellation_task.id
        running_cancellation = job_service.schedule(
            task_id=cancellation_task_id,
            job_type="postgres-running-cancellation",
            idempotency_key=(
                f"postgres-running-cancellation:{cancellation_task_id}"
            ),
            input_payload={"state": "running"},
        )
        cancellation_grant = job_service.claim_next(
            worker_id="postgres-cancellation-worker",
            lease_duration=timedelta(seconds=30),
            job_types=("postgres-running-cancellation",),
        )
        assert cancellation_grant is not None
        queued_cancellation = job_service.schedule(
            task_id=cancellation_task_id,
            job_type="postgres-queued-cancellation",
            idempotency_key=(
                f"postgres-queued-cancellation:{cancellation_task_id}"
            ),
            input_payload={"state": "queued"},
        )
        cancellation = CancellationService(
            factory,
            store,
            principal_id="postgres-test",
        ).cancel_task(
            cancellation_task_id,
            cancellation_id=uuid4(),
            expected_state=TaskState.INTAKE,
            reason_code="USER_CANCELLED",
        )
        assert cancellation.cleanup_complete is True
        with factory() as session:
            cancelled_jobs = tuple(
                session.scalars(
                    select(BackgroundJob).where(
                        BackgroundJob.id.in_(
                            (
                                running_cancellation.job_id,
                                queued_cancellation.job_id,
                            )
                        )
                    )
                )
            )
        assert len(cancelled_jobs) == 2
        assert all(
            job.status is BackgroundJobStatus.CANCELLED
            for job in cancelled_jobs
        )

        artifact = store.put_bytes(payload)
        bootstrap_token = generate_bootstrap_token(factory)

        def bootstrap_concurrently() -> IssuedSession | BootstrapAlreadyCompletedError:
            try:
                return authentication_service.bootstrap(
                    bootstrap_token=bootstrap_token,
                    password="correct horse battery staple",
                )
            except BootstrapAlreadyCompletedError as error:
                return error

        with ThreadPoolExecutor(max_workers=2) as executor:
            bootstrap_results = list(
                executor.map(lambda _attempt: bootstrap_concurrently(), range(2))
            )
        issued_sessions = [
            result for result in bootstrap_results if isinstance(result, IssuedSession)
        ]
        rejected_bootstraps = [
            result
            for result in bootstrap_results
            if isinstance(result, BootstrapAlreadyCompletedError)
        ]
        assert len(issued_sessions) == 1
        assert len(rejected_bootstraps) == 1
        issued_session = issued_sessions[0]
        engine.dispose()
        engine = None

        recreated_engine = create_database_engine(database_url)
        engine = recreated_engine
        recreated_factory = create_session_factory(recreated_engine)
        recreated_store = ArtifactStore(store.root)
        recreated_authentication_service = AuthenticationService(recreated_factory)
        with recreated_factory() as session:
            retrieved = get_task_record(session, task_id)
            readiness = require_preflight_ready(
                session,
                recreated_store,
                repository_key="boppuh/mathews",
                configuration_id=repository_configuration_id,
                configuration_version=repository_configuration_version,
                configuration_digest=repository_digest,
                resolved_base_sha=base_sha,
            )
        authenticated = recreated_authentication_service.authenticate(issued_session.session_token)

        assert retrieved is not None
        assert retrieved.summary == "PostgreSQL and artifact durability smoke"
        assert readiness.evidence_id == preflight_evidence_id
        assert readiness.binding.resolved_base_sha == base_sha
        assert artifact.address == f"sha256:{expected_digest}"
        assert recreated_store.get_bytes(artifact.address) == payload
        assert authenticated is not None
        assert recreated_authentication_service.bootstrap_status().bootstrap_required is False

        readiness_lock_acquired = Event()
        release_readiness_lock = Event()
        writer_started = Event()
        correction_started = Event()

        def hold_readiness_lock() -> None:
            with session_scope(recreated_factory) as session:
                require_preflight_ready(
                    session,
                    recreated_store,
                    repository_key="boppuh/mathews",
                    configuration_id=repository_configuration_id,
                    configuration_version=repository_configuration_version,
                    configuration_digest=repository_digest,
                    resolved_base_sha=base_sha,
                )
                readiness_lock_acquired.set()
                if not release_readiness_lock.wait(timeout=5):
                    raise TimeoutError("test did not release the readiness lock")

        def create_next_configuration() -> int:
            writer_started.set()
            with session_scope(recreated_factory) as session:
                return create_repository_configuration(
                    session,
                    **_repository_configuration_arguments(tmp_path / "target-repository"),
                    owner_id="local-user",
                    actor_id="postgres-test",
                    root_correlation_id=uuid4(),
                ).version

        def correct_preflight_evidence() -> str:
            correction_started.set()
            with session_scope(recreated_factory) as session:
                original = session.get(EvidenceRecord, preflight_evidence_id)
                assert original is not None
                correction = capture_evidence(
                    session,
                    recreated_store,
                    payload={
                        "schema_version": 1,
                        "repository_key": "boppuh/mathews",
                        **preflight_report.to_dict(),
                    },
                    media_type="application/json",
                    source_kind=EvidenceSourceKind.RESULT,
                    evidence_type=original.evidence_type,
                    origin="control-plane:correction",
                    access_classification=EvidenceAccessClass.INTERNAL,
                    retention_policy=EvidenceRetentionClass.REPOSITORY_LIFETIME,
                    owner_id=original.owner_id,
                    actor_id="postgres-test",
                    root_correlation_id=original.root_correlation_id,
                    correction_of_id=original.id,
                )
                return str(correction.record.id)

        with ThreadPoolExecutor(max_workers=3) as executor:
            holder = executor.submit(hold_readiness_lock)
            assert readiness_lock_acquired.wait(timeout=5)
            writer = executor.submit(create_next_configuration)
            correction = executor.submit(correct_preflight_evidence)
            assert writer_started.wait(timeout=5)
            assert correction_started.wait(timeout=5)
            try:
                with pytest.raises(FutureTimeoutError):
                    writer.result(timeout=0.2)
                with pytest.raises(FutureTimeoutError):
                    correction.result(timeout=0.2)
            finally:
                release_readiness_lock.set()
            holder.result(timeout=5)
            assert writer.result(timeout=5) == 2
            assert correction.result(timeout=5)

        recreated_authentication_service.logout(authenticated)
        assert (
            AuthenticationService(recreated_factory).authenticate(issued_session.session_token)
            is None
        )
    finally:
        if engine is not None:
            engine.dispose()
        try:
            if schema_created:
                with admin_engine.begin() as connection:
                    connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        finally:
            admin_engine.dispose()
