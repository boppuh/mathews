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

export const VALIDATION_ASSERTION_KINDS = [
  "ELEMENT_VALUE_PRESENT",
  "NAVIGATION_STATE_REACHED",
  "EXPECTED_NETWORK_RESPONSE",
  "EXPECTED_LOG_EVENT",
  "NO_CRASH",
] as const;

export type ValidationAssertionKind = (typeof VALIDATION_ASSERTION_KINDS)[number];

export interface TaskAcceptanceAssertionSummary {
  assertion_id: string;
  kind: ValidationAssertionKind;
  verifier_catalog_key: string;
  status: AcceptanceCriterionStatus;
  result_code: string;
  evidence_ids: string[];
}

export interface TaskAcceptanceCriterionSummary {
  id: string;
  requirement: string;
  verification: AcceptanceCriterionVerification;
  status: AcceptanceCriterionStatus;
  validation_run_id: string | null;
  validation_contract_version: number | null;
  commit_sha: string | null;
  tree_sha: string | null;
  evidence_ids: string[];
  assertions: TaskAcceptanceAssertionSummary[];
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

export const TASK_GITHUB_CI_STATUSES = [
  "NOT_LINKED",
  "NOT_RUN",
  "PENDING",
  "PASSED",
  "FAILED",
] as const;

export type TaskGitHubCiStatus = (typeof TASK_GITHUB_CI_STATUSES)[number];

export const TASK_GITHUB_REVIEW_STATUSES = [
  "NOT_LINKED",
  "NOT_REVIEWED",
  "COMMENTED",
  "APPROVED",
  "CHANGES_REQUESTED",
] as const;

export type TaskGitHubReviewStatus = (typeof TASK_GITHUB_REVIEW_STATUSES)[number];

export interface TaskGitHubStatus {
  linked: boolean;
  pull_request_number: number | null;
  task_branch: string | null;
  head_sha: string | null;
  ci_status: TaskGitHubCiStatus;
  review_status: TaskGitHubReviewStatus;
  checks_total: number;
  checks_passed: number;
  blocking_reviews: number;
  review_comments: number;
  last_updated_at: string | null;
}

export interface TaskCockpitResponse {
  task: TaskSummary;
  state_context: TaskStateContext;
  events: TaskEventSummary[];
  acceptance_criteria: TaskAcceptanceCriterionSummary[];
  evidence: TaskEvidenceSummary[];
  approvals: TaskApprovalSummary[];
  github: TaskGitHubStatus;
}

export interface CreateTaskRequest {
  repository: string;
  base_revision: string;
  request: string;
}

export type RepositoryJsonValue =
  | boolean
  | number
  | string
  | null
  | RepositoryJsonValue[]
  | { [key: string]: RepositoryJsonValue };

export interface RepositorySecretStatus {
  push_credential_configured: boolean;
  e2e_test_account_configured: boolean;
  additional_reference_count: number;
}

export interface RepositoryConfigurationProjection {
  id: string;
  repository_key: string;
  version: number;
  digest: string;
  created_at: string;
  actor_id: string;
  repository_settings: Record<string, RepositoryJsonValue>;
  git_settings: Record<string, RepositoryJsonValue>;
  xcode_settings: Record<string, RepositoryJsonValue>;
  operations: RepositoryJsonValue[];
  e2e_assertions: RepositoryJsonValue[];
  artifact_settings: Record<string, RepositoryJsonValue>;
  prohibited_paths: RepositoryJsonValue[];
  secrets: RepositorySecretStatus;
}

export interface RepositoryPreflightCheck {
  code: string;
  status: "PASSED" | "BLOCKED";
  detail_code: string;
}

export interface RepositoryPreflightProjection {
  status: "NOT_RUN" | "RUNNING" | "PASSED" | "BLOCKED";
  attempt_id: string | null;
  configuration_id: string | null;
  configuration_version: number | null;
  configuration_digest: string | null;
  resolved_base_sha: string | null;
  checks: RepositoryPreflightCheck[];
}

export interface RepositoryProjection {
  repository_key: string;
  configured: boolean;
  mutation_blocked: boolean;
  configuration: RepositoryConfigurationProjection | null;
  preflight: RepositoryPreflightProjection;
  host_available: boolean;
}

export interface RepositorySecretUpdates {
  push_credential?: string;
  e2e_test_account?: string;
  additional?: string[];
}

export interface RepositoryConfigurationWriteRequest {
  repository_key: string;
  expected_configuration_version: number | null;
  repository_settings: Record<string, RepositoryJsonValue>;
  git_settings: Record<string, RepositoryJsonValue>;
  xcode_settings: Record<string, RepositoryJsonValue>;
  operations: RepositoryJsonValue[];
  e2e_assertions: RepositoryJsonValue[];
  artifact_settings: Record<string, RepositoryJsonValue>;
  prohibited_paths: RepositoryJsonValue[];
  secret_updates: RepositorySecretUpdates;
  approve_sensitive_change: boolean;
}

export const TASK_STEERING_IMPACTS = ["ACCEPTANCE_CRITERIA", "PATHS", "RISK", "TESTS"] as const;

export type TaskSteeringImpact = (typeof TASK_STEERING_IMPACTS)[number];
export type TaskSteeringClassification = "CLARIFICATION" | "SCOPE_CHANGE";

export interface TaskSteeringRequest {
  steering_id: string;
  expected_state: TaskState;
  message: string;
  impacts: TaskSteeringImpact[];
}

export interface TaskSteeringResponse {
  steering_id: string;
  task_id: string;
  classification: TaskSteeringClassification;
  impacts: TaskSteeringImpact[];
  task_state: TaskState;
  evidence_id: string;
  request_evidence_id: string;
  event_id: string;
  invalidated_brief_id: string | null;
  invalidated_validation_contract_id: string | null;
  revoked_lease_count: number;
  revoked_tool_grant_count: number;
  replayed: boolean;
}

export interface TaskCancellationRequest {
  cancellation_id: string;
  expected_state: TaskState;
  reason_code: "USER_REQUEST";
}

export interface TaskCancellationResponse {
  cancellation_id: string;
  task_id: string;
  task_state: "CANCELLED";
  partial_evidence_id: string;
  revoked_lease_count: number;
  revoked_tool_grant_count: number;
  cleanup_complete: boolean;
  replayed: boolean;
}

export interface ServiceHealth {
  service: "api" | "host-agent" | "web" | "worker";
  status: "ok";
  version: string;
}
