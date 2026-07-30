import {
  APPROVAL_STATUSES,
  type ApprovalStatus,
  TASK_BLOCKER_CODES,
  TASK_EVENT_KINDS,
  TASK_EVIDENCE_STATUSES,
  TASK_STATE_CONTEXT_KINDS,
  TASK_STATES,
  type TaskApprovalSummary,
  type TaskBlocker,
  type TaskBlockerCode,
  type TaskCockpitResponse,
  type TaskEventKind,
  type TaskEventSummary,
  type TaskEvidenceStatus,
  type TaskEvidenceSummary,
  type TaskListResponse,
  type TaskState,
  type TaskStateContext,
  type TaskStateContextKind,
  type TaskSummary,
} from "@mathews/contracts";

const taskStates = new Set<string>(TASK_STATES);
const blockerCodes = new Set<string>(TASK_BLOCKER_CODES);
const stateContextKinds = new Set<string>(TASK_STATE_CONTEXT_KINDS);
const eventKinds = new Set<string>(TASK_EVENT_KINDS);
const evidenceStatuses = new Set<string>(TASK_EVIDENCE_STATUSES);
const approvalStatuses = new Set<string>(APPROVAL_STATUSES);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const GIT_OBJECT_ID_PATTERN = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
const EVIDENCE_TYPE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isTimestamp(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
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

function parseTaskEvent(value: unknown): TaskEventSummary {
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
    !evidenceStatuses.has(value.status)
  ) {
    throw new Error("The control plane returned invalid task evidence.");
  }
  return {
    id: value.id,
    evidence_type: value.evidence_type,
    captured_at: value.captured_at,
    status: value.status as TaskEvidenceStatus,
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

export function parseTaskCockpit(value: unknown): TaskCockpitResponse {
  if (
    !isRecord(value) ||
    !Array.isArray(value.events) ||
    !Array.isArray(value.evidence) ||
    !Array.isArray(value.approvals)
  ) {
    throw new Error("The control plane returned an invalid task cockpit.");
  }
  const events = value.events.map(parseTaskEvent);
  for (let index = 1; index < events.length; index += 1) {
    const previous = events[index - 1];
    const current = events[index];
    if (!previous || !current || previous.sequence >= current.sequence) {
      throw new Error("The control plane returned an invalid task event order.");
    }
  }
  return {
    task: parseTaskSummary(value.task),
    state_context: parseStateContext(value.state_context),
    events,
    evidence: value.evidence.map(parseEvidence),
    approvals: value.approvals.map(parseApproval),
  };
}

export function shortRevision(revision: string): string {
  return revision.slice(0, 8);
}

export function mergeLoadedTasks(loaded: TaskSummary[], current: TaskSummary[]): TaskSummary[] {
  const loadedIds = new Set(loaded.map((task) => task.id));
  return [...current.filter((task) => !loadedIds.has(task.id)), ...loaded];
}
