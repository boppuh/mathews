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

export interface ServiceHealth {
  service: "api" | "host-agent" | "web" | "worker";
  status: "ok";
  version: string;
}
