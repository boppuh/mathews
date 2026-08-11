import {
  ACCEPTANCE_CRITERION_STATUSES,
  ACCEPTANCE_CRITERION_VERIFICATIONS,
  type AcceptanceCriterionStatus,
  type AcceptanceCriterionVerification,
  APPROVAL_STATUSES,
  type ApprovalStatus,
  EVIDENCE_DELETION_REASONS,
  type EvidenceDeletionReason,
  TASK_BLOCKER_CODES,
  TASK_EVENT_KINDS,
  TASK_EVIDENCE_CATEGORIES,
  TASK_EVIDENCE_CONTENT_ACCESS,
  TASK_EVIDENCE_STATUSES,
  TASK_GITHUB_CI_STATUSES,
  TASK_GITHUB_REVIEW_STATUSES,
  TASK_HANDOFF_MEANING,
  TASK_STATE_CONTEXT_KINDS,
  TASK_STATES,
  TASK_STEERING_IMPACTS,
  type TaskAcceptanceCriterionSummary,
  type TaskApprovalSummary,
  type TaskBlocker,
  type TaskBlockerCode,
  type TaskCancellationResponse,
  type TaskCockpitResponse,
  type TaskEventKind,
  type TaskEventSummary,
  type TaskEvidenceCategory,
  type TaskEvidenceContentAccess,
  type TaskEvidenceStatus,
  type TaskEvidenceSummary,
  type TaskGitHubCiStatus,
  type TaskGitHubReviewStatus,
  type TaskGitHubStatus,
  type TaskHandoffResponse,
  type TaskListResponse,
  type TaskState,
  type TaskStateContext,
  type TaskStateContextKind,
  type TaskSteeringClassification,
  type TaskSteeringImpact,
  type TaskSteeringResponse,
  type TaskSummary,
  VALIDATION_ASSERTION_KINDS,
} from "@mathews/contracts";

const taskStates = new Set<string>(TASK_STATES);
const blockerCodes = new Set<string>(TASK_BLOCKER_CODES);
const stateContextKinds = new Set<string>(TASK_STATE_CONTEXT_KINDS);
const eventKinds = new Set<string>(TASK_EVENT_KINDS);
const githubCiStatuses = new Set<string>(TASK_GITHUB_CI_STATUSES);
const githubReviewStatuses = new Set<string>(TASK_GITHUB_REVIEW_STATUSES);
const evidenceStatuses = new Set<string>(TASK_EVIDENCE_STATUSES);
const evidenceCategories = new Set<string>(TASK_EVIDENCE_CATEGORIES);
const evidenceContentAccess = new Set<string>(TASK_EVIDENCE_CONTENT_ACCESS);
const evidenceDeletionReasons = new Set<string>(EVIDENCE_DELETION_REASONS);
const criterionStatuses = new Set<string>(ACCEPTANCE_CRITERION_STATUSES);
const criterionVerifications = new Set<string>(ACCEPTANCE_CRITERION_VERIFICATIONS);
const validationAssertionKinds = new Set<string>(VALIDATION_ASSERTION_KINDS);
const approvalStatuses = new Set<string>(APPROVAL_STATUSES);
const steeringImpacts = new Set<string>(TASK_STEERING_IMPACTS);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const GIT_OBJECT_ID_PATTERN = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
const EVIDENCE_TYPE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isTimestamp(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function parseOptionalUuid(value: unknown): string | null {
  if (value === null) {
    return null;
  }
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) {
    throw new Error("The control plane returned an invalid evidence lineage.");
  }
  return value;
}

function parseBlocker(value: unknown): TaskBlocker {
  if (
    !isRecord(value) ||
    typeof value.code !== "string" ||
    !blockerCodes.has(value.code) ||
    typeof value.label !== "string" ||
    value.label.length === 0 ||
    !Number.isSafeInteger(value.count) ||
    Number(value.count) < 1
  ) {
    throw new Error("The control plane returned an invalid task blocker.");
  }

  return {
    code: value.code as TaskBlockerCode,
    label: value.label,
    count: Number(value.count),
  };
}

export function parseTaskSummary(value: unknown): TaskSummary {
  if (
    !isRecord(value) ||
    typeof value.id !== "string" ||
    !UUID_PATTERN.test(value.id) ||
    typeof value.summary !== "string" ||
    value.summary.length === 0 ||
    typeof value.state !== "string" ||
    !taskStates.has(value.state) ||
    typeof value.repository !== "string" ||
    value.repository.length === 0 ||
    typeof value.base_revision !== "string" ||
    !GIT_OBJECT_ID_PATTERN.test(value.base_revision) ||
    !isTimestamp(value.created_at) ||
    !isTimestamp(value.last_activity_at) ||
    !Array.isArray(value.blockers) ||
    value.cockpit_path !== `/tasks/${value.id}`
  ) {
    throw new Error("The control plane returned an invalid task.");
  }

  return {
    id: value.id,
    summary: value.summary,
    state: value.state as TaskState,
    repository: value.repository,
    base_revision: value.base_revision,
    created_at: value.created_at,
    last_activity_at: value.last_activity_at,
    blockers: value.blockers.map(parseBlocker),
    cockpit_path: value.cockpit_path,
  };
}

export function parseTaskList(value: unknown): TaskListResponse {
  if (!isRecord(value) || !Array.isArray(value.tasks)) {
    throw new Error("The control plane returned an invalid task list.");
  }
  return { tasks: value.tasks.map(parseTaskSummary) };
}

function parseUuid(value: unknown, message: string): string {
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) {
    throw new Error(message);
  }
  return value;
}

function parseNonNegativeInteger(value: unknown, message: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new Error(message);
  }
  return Number(value);
}

export function parseTaskSteeringResponse(value: unknown): TaskSteeringResponse {
  if (
    !isRecord(value) ||
    (value.classification !== "CLARIFICATION" && value.classification !== "SCOPE_CHANGE") ||
    !Array.isArray(value.impacts) ||
    !value.impacts.every((impact) => typeof impact === "string" && steeringImpacts.has(impact)) ||
    new Set(value.impacts).size !== value.impacts.length ||
    typeof value.task_state !== "string" ||
    !taskStates.has(value.task_state) ||
    typeof value.replayed !== "boolean"
  ) {
    throw new Error("The control plane returned an invalid steering result.");
  }
  if (
    (value.classification === "CLARIFICATION" && value.impacts.length !== 0) ||
    (value.classification === "SCOPE_CHANGE" && value.impacts.length === 0)
  ) {
    throw new Error("The control plane returned an inconsistent steering result.");
  }
  return {
    steering_id: parseUuid(
      value.steering_id,
      "The control plane returned invalid steering identity.",
    ),
    task_id: parseUuid(value.task_id, "The control plane returned invalid steering identity."),
    classification: value.classification as TaskSteeringClassification,
    impacts: value.impacts as TaskSteeringImpact[],
    task_state: value.task_state as TaskState,
    evidence_id: parseUuid(
      value.evidence_id,
      "The control plane returned invalid steering evidence.",
    ),
    request_evidence_id: parseUuid(
      value.request_evidence_id,
      "The control plane returned invalid steering evidence.",
    ),
    event_id: parseUuid(value.event_id, "The control plane returned invalid steering event."),
    invalidated_brief_id: parseOptionalUuid(value.invalidated_brief_id),
    invalidated_validation_contract_id: parseOptionalUuid(value.invalidated_validation_contract_id),
    revoked_lease_count: parseNonNegativeInteger(
      value.revoked_lease_count,
      "The control plane returned an invalid steering fence.",
    ),
    revoked_tool_grant_count: parseNonNegativeInteger(
      value.revoked_tool_grant_count,
      "The control plane returned an invalid steering fence.",
    ),
    replayed: value.replayed,
  };
}

export function parseTaskCancellationResponse(value: unknown): TaskCancellationResponse {
  if (
    !isRecord(value) ||
    value.task_state !== "CANCELLED" ||
    typeof value.cleanup_complete !== "boolean" ||
    typeof value.replayed !== "boolean"
  ) {
    throw new Error("The control plane returned an invalid cancellation result.");
  }
  return {
    cancellation_id: parseUuid(
      value.cancellation_id,
      "The control plane returned invalid cancellation identity.",
    ),
    task_id: parseUuid(value.task_id, "The control plane returned invalid cancellation identity."),
    task_state: value.task_state,
    partial_evidence_id: parseUuid(
      value.partial_evidence_id,
      "The control plane returned invalid cancellation evidence.",
    ),
    revoked_lease_count: parseNonNegativeInteger(
      value.revoked_lease_count,
      "The control plane returned an invalid cancellation fence.",
    ),
    revoked_tool_grant_count: parseNonNegativeInteger(
      value.revoked_tool_grant_count,
      "The control plane returned an invalid cancellation fence.",
    ),
    cleanup_complete: value.cleanup_complete,
    replayed: value.replayed,
  };
}

export function parseTaskHandoffResponse(value: unknown): TaskHandoffResponse {
  if (
    !isRecord(value) ||
    value.task_state !== "HANDED_OFF" ||
    typeof value.head_sha !== "string" ||
    !GIT_OBJECT_ID_PATTERN.test(value.head_sha) ||
    value.meaning !== TASK_HANDOFF_MEANING ||
    typeof value.replayed !== "boolean"
  ) {
    throw new Error("The control plane returned an invalid handoff result.");
  }
  return {
    handoff_id: parseUuid(value.handoff_id, "The control plane returned invalid handoff identity."),
    task_id: parseUuid(value.task_id, "The control plane returned invalid handoff identity."),
    task_state: value.task_state,
    head_sha: value.head_sha,
    acknowledgement_evidence_id: parseUuid(
      value.acknowledgement_evidence_id,
      "The control plane returned invalid handoff evidence.",
    ),
    event_id: parseUuid(value.event_id, "The control plane returned invalid handoff event."),
    meaning: value.meaning,
    replayed: value.replayed,
  };
}

function parseOptionalState(value: unknown): TaskState | null {
  if (value === null) {
    return null;
  }
  if (typeof value !== "string" || !taskStates.has(value)) {
    throw new Error("The control plane returned an invalid task state.");
  }
  return value as TaskState;
}

function parseStateContext(value: unknown): TaskStateContext {
  if (
    !isRecord(value) ||
    typeof value.kind !== "string" ||
    !stateContextKinds.has(value.kind) ||
    typeof value.label !== "string" ||
    value.label.length === 0 ||
    value.label.length > 100 ||
    typeof value.detail !== "string" ||
    value.detail.length === 0 ||
    value.detail.length > 500
  ) {
    throw new Error("The control plane returned an invalid task state context.");
  }
  return {
    kind: value.kind as TaskStateContextKind,
    label: value.label,
    detail: value.detail,
    resume_state: parseOptionalState(value.resume_state),
  };
}

export function parseTaskEvent(value: unknown): TaskEventSummary {
  if (
    !isRecord(value) ||
    typeof value.id !== "string" ||
    !UUID_PATTERN.test(value.id) ||
    !Number.isSafeInteger(value.sequence) ||
    Number(value.sequence) < 1 ||
    typeof value.kind !== "string" ||
    !eventKinds.has(value.kind) ||
    typeof value.summary !== "string" ||
    value.summary.length === 0 ||
    value.summary.length > 300 ||
    !isTimestamp(value.occurred_at) ||
    !Number.isSafeInteger(value.evidence_count) ||
    Number(value.evidence_count) < 0
  ) {
    throw new Error("The control plane returned an invalid task event.");
  }
  return {
    id: value.id,
    sequence: Number(value.sequence),
    kind: value.kind as TaskEventKind,
    summary: value.summary,
    occurred_at: value.occurred_at,
    from_state: parseOptionalState(value.from_state),
    to_state: parseOptionalState(value.to_state),
    evidence_count: Number(value.evidence_count),
  };
}

function parseEvidence(value: unknown): TaskEvidenceSummary {
  if (
    !isRecord(value) ||
    typeof value.id !== "string" ||
    !UUID_PATTERN.test(value.id) ||
    typeof value.evidence_type !== "string" ||
    !EVIDENCE_TYPE_PATTERN.test(value.evidence_type) ||
    !isTimestamp(value.captured_at) ||
    typeof value.status !== "string" ||
    !evidenceStatuses.has(value.status) ||
    typeof value.category !== "string" ||
    !evidenceCategories.has(value.category) ||
    typeof value.content_access !== "string" ||
    !evidenceContentAccess.has(value.content_access) ||
    !(
      value.deletion_reason === null ||
      (typeof value.deletion_reason === "string" &&
        evidenceDeletionReasons.has(value.deletion_reason))
    ) ||
    !(value.deleted_at === null || isTimestamp(value.deleted_at)) ||
    !(value.download_path === null || typeof value.download_path === "string")
  ) {
    throw new Error("The control plane returned invalid task evidence.");
  }
  const correctionOfId = parseOptionalUuid(value.correction_of_id);
  const correctedById = parseOptionalUuid(value.corrected_by_id);
  const expectedDownloadPath = `/api/evidence/${value.id}/download`;
  const deleted = value.status === "DELETED";
  if (
    (deleted && (value.content_access !== "DELETED" || value.download_path !== null)) ||
    (!deleted && (value.deletion_reason !== null || value.deleted_at !== null)) ||
    (value.status === "CORRECTION" && correctionOfId === null) ||
    (value.status === "SUPERSEDED" && correctedById === null) ||
    (value.content_access === "AVAILABLE" && value.download_path !== expectedDownloadPath) ||
    (value.content_access !== "AVAILABLE" && value.download_path !== null)
  ) {
    throw new Error("The control plane returned inconsistent task evidence.");
  }
  return {
    id: value.id,
    evidence_type: value.evidence_type,
    captured_at: value.captured_at,
    status: value.status as TaskEvidenceStatus,
    category: value.category as TaskEvidenceCategory,
    content_access: value.content_access as TaskEvidenceContentAccess,
    correction_of_id: correctionOfId,
    corrected_by_id: correctedById,
    deletion_reason: value.deletion_reason as EvidenceDeletionReason | null,
    deleted_at: value.deleted_at,
    download_path: value.download_path,
  };
}

function parseAcceptanceCriterion(value: unknown): TaskAcceptanceCriterionSummary {
  if (
    !isRecord(value) ||
    typeof value.id !== "string" ||
    value.id.length === 0 ||
    value.id.length > 128 ||
    typeof value.requirement !== "string" ||
    value.requirement.length === 0 ||
    value.requirement.length > 2_000 ||
    typeof value.verification !== "string" ||
    !criterionVerifications.has(value.verification) ||
    typeof value.status !== "string" ||
    !criterionStatuses.has(value.status) ||
    !(
      value.validation_run_id === null ||
      (typeof value.validation_run_id === "string" && UUID_PATTERN.test(value.validation_run_id))
    ) ||
    !(
      value.validation_contract_version === null ||
      (Number.isSafeInteger(value.validation_contract_version) &&
        Number(value.validation_contract_version) > 0)
    ) ||
    !(
      value.commit_sha === null ||
      (typeof value.commit_sha === "string" && GIT_OBJECT_ID_PATTERN.test(value.commit_sha))
    ) ||
    !(
      value.tree_sha === null ||
      (typeof value.tree_sha === "string" && GIT_OBJECT_ID_PATTERN.test(value.tree_sha))
    ) ||
    !Array.isArray(value.evidence_ids) ||
    !value.evidence_ids.every((item) => typeof item === "string" && UUID_PATTERN.test(item)) ||
    !Array.isArray(value.assertions)
  ) {
    throw new Error("The control plane returned an invalid acceptance criterion.");
  }
  const assertions = value.assertions.map((assertion) => {
    if (
      !isRecord(assertion) ||
      typeof assertion.assertion_id !== "string" ||
      assertion.assertion_id.length === 0 ||
      typeof assertion.kind !== "string" ||
      !validationAssertionKinds.has(assertion.kind) ||
      typeof assertion.verifier_catalog_key !== "string" ||
      assertion.verifier_catalog_key.length === 0 ||
      typeof assertion.status !== "string" ||
      !criterionStatuses.has(assertion.status) ||
      typeof assertion.result_code !== "string" ||
      assertion.result_code.length === 0 ||
      !Array.isArray(assertion.evidence_ids) ||
      !assertion.evidence_ids.every((item) => typeof item === "string" && UUID_PATTERN.test(item))
    ) {
      throw new Error("The control plane returned an invalid acceptance assertion.");
    }
    const assertionEvidenceIds = assertion.evidence_ids as string[];
    if (
      new Set(assertionEvidenceIds).size !== assertionEvidenceIds.length ||
      (assertion.status === "PENDING" && assertionEvidenceIds.length > 0) ||
      (assertion.status !== "PENDING" && assertionEvidenceIds.length === 0)
    ) {
      throw new Error("The control plane returned inconsistent acceptance assertion evidence.");
    }
    return {
      assertion_id: assertion.assertion_id,
      kind: assertion.kind as TaskAcceptanceCriterionSummary["assertions"][number]["kind"],
      verifier_catalog_key: assertion.verifier_catalog_key,
      status: assertion.status as AcceptanceCriterionStatus,
      result_code: assertion.result_code,
      evidence_ids: assertionEvidenceIds,
    };
  });
  const hasRun = value.validation_run_id !== null;
  const assertionEvidenceIds = new Set(assertions.flatMap((assertion) => assertion.evidence_ids));
  const aggregateEvidenceIds = new Set(value.evidence_ids as string[]);
  const assertionStatuses = new Set(assertions.map((assertion) => assertion.status));
  const expectedStatus = assertionStatuses.has("FAILED")
    ? "FAILED"
    : assertionStatuses.has("BLOCKED")
      ? "BLOCKED"
      : assertionStatuses.has("PENDING")
        ? "PENDING"
        : "PASSED";
  if (
    hasRun !== (value.validation_contract_version !== null) ||
    hasRun !== (value.commit_sha !== null) ||
    hasRun !== (value.tree_sha !== null) ||
    (!hasRun && (value.evidence_ids.length > 0 || assertions.length > 0)) ||
    (hasRun && assertions.length === 0) ||
    new Set(assertions.map((assertion) => assertion.assertion_id)).size !== assertions.length ||
    (hasRun && value.status !== expectedStatus) ||
    aggregateEvidenceIds.size !== value.evidence_ids.length ||
    assertionEvidenceIds.size !== aggregateEvidenceIds.size ||
    ![...assertionEvidenceIds].every((evidenceId) => aggregateEvidenceIds.has(evidenceId))
  ) {
    throw new Error("The control plane returned inconsistent validation evidence.");
  }
  return {
    id: value.id,
    requirement: value.requirement,
    verification: value.verification as AcceptanceCriterionVerification,
    status: value.status as AcceptanceCriterionStatus,
    validation_run_id: value.validation_run_id as string | null,
    validation_contract_version: value.validation_contract_version as number | null,
    commit_sha: value.commit_sha as string | null,
    tree_sha: value.tree_sha as string | null,
    evidence_ids: value.evidence_ids as string[],
    assertions,
  };
}

function parseApproval(value: unknown): TaskApprovalSummary {
  if (
    !isRecord(value) ||
    typeof value.id !== "string" ||
    !UUID_PATTERN.test(value.id) ||
    typeof value.type_label !== "string" ||
    value.type_label.length === 0 ||
    value.type_label.length > 100 ||
    typeof value.status !== "string" ||
    !approvalStatuses.has(value.status) ||
    typeof value.requesting_state !== "string" ||
    !taskStates.has(value.requesting_state) ||
    !isTimestamp(value.created_at) ||
    !(value.expires_at === null || isTimestamp(value.expires_at))
  ) {
    throw new Error("The control plane returned an invalid task approval.");
  }
  return {
    id: value.id,
    type_label: value.type_label,
    status: value.status as ApprovalStatus,
    requesting_state: value.requesting_state as TaskState,
    resume_state: parseOptionalState(value.resume_state),
    created_at: value.created_at,
    expires_at: value.expires_at,
  };
}

function parseGitHubStatus(value: unknown): TaskGitHubStatus {
  if (
    !isRecord(value) ||
    typeof value.linked !== "boolean" ||
    typeof value.ci_status !== "string" ||
    !githubCiStatuses.has(value.ci_status) ||
    typeof value.review_status !== "string" ||
    !githubReviewStatuses.has(value.review_status) ||
    !(value.last_updated_at === null || isTimestamp(value.last_updated_at))
  ) {
    throw new Error("The control plane returned invalid GitHub task status.");
  }
  const counts = [
    value.checks_total,
    value.checks_passed,
    value.blocking_reviews,
    value.review_comments,
  ];
  if (counts.some((count) => !Number.isSafeInteger(count) || Number(count) < 0)) {
    throw new Error("The control plane returned invalid GitHub task status.");
  }
  if (
    value.linked !== (value.ci_status !== "NOT_LINKED") ||
    value.linked !== (value.review_status !== "NOT_LINKED") ||
    (value.linked &&
      (!Number.isSafeInteger(value.pull_request_number) ||
        Number(value.pull_request_number) < 1 ||
        typeof value.task_branch !== "string" ||
        value.task_branch.length === 0 ||
        typeof value.head_sha !== "string" ||
        !GIT_OBJECT_ID_PATTERN.test(value.head_sha))) ||
    (!value.linked &&
      (value.pull_request_number !== null ||
        value.task_branch !== null ||
        value.head_sha !== null ||
        counts.some((count) => count !== 0) ||
        value.last_updated_at !== null)) ||
    Number(value.checks_passed) > Number(value.checks_total)
  ) {
    throw new Error("The control plane returned inconsistent GitHub task status.");
  }
  return {
    linked: value.linked,
    pull_request_number: value.pull_request_number as number | null,
    task_branch: value.task_branch as string | null,
    head_sha: value.head_sha as string | null,
    ci_status: value.ci_status as TaskGitHubCiStatus,
    review_status: value.review_status as TaskGitHubReviewStatus,
    checks_total: Number(value.checks_total),
    checks_passed: Number(value.checks_passed),
    blocking_reviews: Number(value.blocking_reviews),
    review_comments: Number(value.review_comments),
    last_updated_at: value.last_updated_at,
  };
}

export function parseTaskCockpit(value: unknown): TaskCockpitResponse {
  if (
    !isRecord(value) ||
    !Array.isArray(value.events) ||
    !Array.isArray(value.acceptance_criteria) ||
    !Array.isArray(value.evidence) ||
    !Array.isArray(value.approvals) ||
    !isRecord(value.github)
  ) {
    throw new Error("The control plane returned an invalid task cockpit.");
  }
  const events = value.events.map(parseTaskEvent);
  const acceptanceCriteria = value.acceptance_criteria.map(parseAcceptanceCriterion);
  for (let index = 1; index < events.length; index += 1) {
    const previous = events[index - 1];
    const current = events[index];
    if (!previous || !current || previous.sequence >= current.sequence) {
      throw new Error("The control plane returned an invalid task event order.");
    }
  }
  if (
    new Set(acceptanceCriteria.map((criterion) => criterion.id)).size !== acceptanceCriteria.length
  ) {
    throw new Error("The control plane returned duplicate acceptance criteria.");
  }
  return {
    task: parseTaskSummary(value.task),
    state_context: parseStateContext(value.state_context),
    events,
    acceptance_criteria: acceptanceCriteria,
    evidence: value.evidence.map(parseEvidence),
    approvals: value.approvals.map(parseApproval),
    github: parseGitHubStatus(value.github),
  };
}

export function shortRevision(revision: string): string {
  return revision.slice(0, 8);
}

export function mergeLoadedTasks(loaded: TaskSummary[], current: TaskSummary[]): TaskSummary[] {
  const loadedIds = new Set(loaded.map((task) => task.id));
  return [...current.filter((task) => !loadedIds.has(task.id)), ...loaded];
}
