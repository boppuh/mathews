export const TASK_STATES = [
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
] as const;

export type TaskState = (typeof TASK_STATES)[number];

export const TASK_BLOCKER_CODES = [
  "APPROVAL_REQUIRED",
  "DEPENDENCY_OUTAGE",
  "RECONCILIATION_REQUIRED",
] as const;

export type TaskBlockerCode = (typeof TASK_BLOCKER_CODES)[number];

export interface TaskBlocker {
  code: TaskBlockerCode;
  label: string;
  count: number;
}

export interface TaskSummary {
  id: string;
  summary: string;
  state: TaskState;
  repository: string;
  base_revision: string;
  created_at: string;
  last_activity_at: string;
  blockers: TaskBlocker[];
  cockpit_path: string;
}

export interface TaskListResponse {
  tasks: TaskSummary[];
}

export interface CreateTaskRequest {
  repository: string;
  base_revision: string;
  request: string;
}

export interface ServiceHealth {
  service: "api" | "host-agent" | "web" | "worker";
  status: "ok";
  version: string;
}
