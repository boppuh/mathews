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

export const TASK_STATE_CONTEXT_KINDS = [
  "ACTIVE",
  "RESUMABLE_ESCALATION",
  "TERMINAL",
  "VERIFIED_DRAFT_PR",
  "HUMAN_MERGE_READY",
  "AUTOMATION_HANDED_OFF",
] as const;

export type TaskStateContextKind = (typeof TASK_STATE_CONTEXT_KINDS)[number];

export interface TaskStateContext {
  kind: TaskStateContextKind;
  label: string;
  detail: string;
  resume_state: TaskState | null;
}

export const TASK_EVENT_KINDS = ["CREATED", "STATE_TRANSITION", "APPROVAL", "ACTIVITY"] as const;

export type TaskEventKind = (typeof TASK_EVENT_KINDS)[number];

export interface TaskEventSummary {
  id: string;
  sequence: number;
  kind: TaskEventKind;
  summary: string;
  occurred_at: string;
  from_state: TaskState | null;
  to_state: TaskState | null;
  evidence_count: number;
}

export const TASK_EVIDENCE_STATUSES = ["AVAILABLE", "CORRECTION", "SUPERSEDED", "DELETED"] as const;

export type TaskEvidenceStatus = (typeof TASK_EVIDENCE_STATUSES)[number];

export const TASK_EVIDENCE_CATEGORIES = [
  "CRITERIA",
  "CHANGE",
  "TEST",
  "LOG",
  "NETWORK",
  "PR_CI",
  "ARTIFACT",
  "OTHER",
] as const;

export type TaskEvidenceCategory = (typeof TASK_EVIDENCE_CATEGORIES)[number];

export const TASK_EVIDENCE_CONTENT_ACCESS = [
  "AVAILABLE",
  "RECENT_PASSWORD_REQUIRED",
  "DELETED",
] as const;

export type TaskEvidenceContentAccess = (typeof TASK_EVIDENCE_CONTENT_ACCESS)[number];

export const EVIDENCE_DELETION_REASONS = [
  "USER_REQUEST",
  "RETENTION_EXPIRED",
  "SOURCE_REVOKED",
  "SECURITY_RESPONSE",
] as const;

export type EvidenceDeletionReason = (typeof EVIDENCE_DELETION_REASONS)[number];

export interface TaskEvidenceSummary {
  id: string;
  evidence_type: string;
  captured_at: string;
  status: TaskEvidenceStatus;
  category: TaskEvidenceCategory;
  content_access: TaskEvidenceContentAccess;
  correction_of_id: string | null;
  corrected_by_id: string | null;
  deletion_reason: EvidenceDeletionReason | null;
  deleted_at: string | null;
  download_path: string | null;
}

export const ACCEPTANCE_CRITERION_STATUSES = ["PENDING", "PASSED", "FAILED", "BLOCKED"] as const;

export type AcceptanceCriterionStatus = (typeof ACCEPTANCE_CRITERION_STATUSES)[number];

export const ACCEPTANCE_CRITERION_VERIFICATIONS = [
  "AUTOMATED_TEST",
  "SIMULATOR_ASSERTION",
  "STATIC_CHECK",
  "HUMAN_INSPECTION",
] as const;

export type AcceptanceCriterionVerification = (typeof ACCEPTANCE_CRITERION_VERIFICATIONS)[number];

export interface TaskAcceptanceCriterionSummary {
  id: string;
  requirement: string;
  verification: AcceptanceCriterionVerification;
  status: AcceptanceCriterionStatus;
}

export const APPROVAL_STATUSES = [
  "PENDING",
  "APPROVED",
  "REJECTED",
  "EXPIRED",
  "CANCELLED",
] as const;

export type ApprovalStatus = (typeof APPROVAL_STATUSES)[number];

export interface TaskApprovalSummary {
  id: string;
  type_label: string;
  status: ApprovalStatus;
  requesting_state: TaskState;
  resume_state: TaskState | null;
  created_at: string;
  expires_at: string | null;
}

export interface TaskCockpitResponse {
  task: TaskSummary;
  state_context: TaskStateContext;
  events: TaskEventSummary[];
  acceptance_criteria: TaskAcceptanceCriterionSummary[];
  evidence: TaskEvidenceSummary[];
  approvals: TaskApprovalSummary[];
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
