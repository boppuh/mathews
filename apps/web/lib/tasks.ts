import {
  TASK_BLOCKER_CODES,
  TASK_STATES,
  type TaskBlocker,
  type TaskBlockerCode,
  type TaskListResponse,
  type TaskState,
  type TaskSummary,
} from "@mathews/contracts";

const taskStates = new Set<string>(TASK_STATES);
const blockerCodes = new Set<string>(TASK_BLOCKER_CODES);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const GIT_OBJECT_ID_PATTERN = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;

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

export function shortRevision(revision: string): string {
  return revision.slice(0, 8);
}

export function mergeLoadedTasks(loaded: TaskSummary[], current: TaskSummary[]): TaskSummary[] {
  const loadedIds = new Set(loaded.map((task) => task.id));
  return [...current.filter((task) => !loadedIds.has(task.id)), ...loaded];
}
