import { TASK_STATES, type TaskState } from "@mathews/contracts";

import { cookieValue, normalizeControlPlaneUrl } from "./auth";

const CSRF_COOKIE_NAME = "__Host-mathews-csrf";
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const FINGERPRINT_PATTERN = /^[0-9a-f]{64}$/;
const REASON_PATTERN = /^[A-Z][A-Z0-9_]{0,99}$/;
const taskStates = new Set<string>(TASK_STATES);

export const APPROVAL_DECISIONS = [
  "APPROVE",
  "REQUEST_REVISION",
  "RETRY",
  "DENY",
  "REJECT",
  "ABANDON",
  "CANCEL",
] as const;
export type ApprovalDecision = (typeof APPROVAL_DECISIONS)[number];
export type ApprovalRequestType =
  | "BRIEF"
  | "UNSAFE_ACTION"
  | "RETRY_LIMIT"
  | "REVIEW_CONFLICT"
  | "REVIEW_RULE";
export type ApprovalJsonValue =
  | string
  | number
  | boolean
  | null
  | ApprovalJsonValue[]
  | { [key: string]: ApprovalJsonValue };

export interface ApprovalTask {
  id: string;
  summary: string;
  repository: string;
  cockpit_path: string;
}

export interface BriefInboxItem {
  id: string;
  version: number;
  scope: { [key: string]: ApprovalJsonValue };
  exclusions: ApprovalJsonValue[];
  acceptance_criteria: ApprovalJsonValue[];
  risks: ApprovalJsonValue[];
  affected_flow: { [key: string]: ApprovalJsonValue };
  test_plan: ApprovalJsonValue[];
}

export interface ApprovalInboxItem {
  id: string;
  task: ApprovalTask;
  request_type: ApprovalRequestType;
  type_label: string;
  reason_code: string;
  options: ApprovalDecision[];
  requesting_state: TaskState;
  resume_state: TaskState | null;
  created_at: string;
  expires_at: string | null;
  operation_name: string | null;
  operation_fingerprint: string | null;
  operation_idempotency_key: string | null;
  operation_checkpoint_evidence_id: string | null;
  brief: BriefInboxItem | null;
  supporting_evidence_ids: string[];
  actionable: boolean;
  unavailable_reason: "BRIEF_UNAVAILABLE" | "RULE_CANDIDATE_UNAVAILABLE" | null;
}

export interface RuleInboxItem {
  candidate_id: string;
  approval_request_id: string | null;
  authority: "NON_AUTHORITATIVE";
  status: "EVALUATED";
  task: ApprovalTask;
  proposed_rule: string;
  recurrence_assessment: string;
  severity_assessment: string;
  false_positive_risks: string[];
  cited_evidence_ids: string[];
  lineage_key: string;
  permitted_action: string;
  risk_class: string;
  scope: { [key: string]: ApprovalJsonValue };
  matcher: { [key: string]: ApprovalJsonValue };
  evidence_requirements: string[];
}

export interface ApprovalInboxResponse {
  approvals: ApprovalInboxItem[];
  rule_candidates: RuleInboxItem[];
}

export interface ApprovalDecisionResponse {
  request_id: string;
  decision: ApprovalDecision;
  status: "APPROVED" | "REJECTED" | "CANCELLED";
  task_id: string;
  task_state: TaskState;
  audit_event_id: string;
}

export class ApprovalRequestError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApprovalRequestError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isTimestamp(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function isBoundedString(value: unknown, maximum = 500): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum;
}

function parseUuid(value: unknown): string {
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) {
    throw new Error("The control plane returned an invalid approval inbox.");
  }
  return value;
}

function parseStringList(value: unknown, maximum = 100): string[] {
  if (
    !Array.isArray(value) ||
    value.length > maximum ||
    value.some((item) => !isBoundedString(item))
  ) {
    throw new Error("The control plane returned an invalid approval inbox.");
  }
  return value as string[];
}

function parseUuidList(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 100) {
    throw new Error("The control plane returned an invalid approval inbox.");
  }
  const parsed = value.map(parseUuid);
  if (new Set(parsed).size !== parsed.length) {
    throw new Error("The control plane returned an invalid approval inbox.");
  }
  return parsed;
}

function parseJsonValue(value: unknown, depth = 0): ApprovalJsonValue {
  if (depth > 10) {
    throw new Error("The control plane returned an invalid approval inbox.");
  }
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > 100) {
      throw new Error("The control plane returned an invalid approval inbox.");
    }
    return value.map((item) => parseJsonValue(item, depth + 1));
  }
  if (isRecord(value)) {
    const entries = Object.entries(value);
    if (
      entries.length === 0 ||
      entries.length > 100 ||
      entries.some(([key]) => key.length === 0 || key.length > 255)
    ) {
      throw new Error("The control plane returned an invalid approval inbox.");
    }
    return Object.fromEntries(entries.map(([key, item]) => [key, parseJsonValue(item, depth + 1)]));
  }
  throw new Error("The control plane returned an invalid approval inbox.");
}

function parseJsonObject(value: unknown): { [key: string]: ApprovalJsonValue } {
  const parsed = parseJsonValue(value);
  if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new Error("The control plane returned an invalid approval inbox.");
  }
  return parsed;
}

function parseJsonArray(value: unknown): ApprovalJsonValue[] {
  const parsed = parseJsonValue(value);
  if (!Array.isArray(parsed)) {
    throw new Error("The control plane returned an invalid approval inbox.");
  }
  return parsed;
}

function parseBrief(value: unknown): BriefInboxItem {
  if (!isRecord(value) || !Number.isInteger(value.version) || Number(value.version) < 1) {
    throw new Error("The control plane returned an invalid approval inbox.");
  }
  return {
    id: parseUuid(value.id),
    version: value.version as number,
    scope: parseJsonObject(value.scope),
    exclusions: parseJsonArray(value.exclusions),
    acceptance_criteria: parseJsonArray(value.acceptance_criteria),
    risks: parseJsonArray(value.risks),
    affected_flow: parseJsonObject(value.affected_flow),
    test_plan: parseJsonArray(value.test_plan),
  };
}

function parseTask(value: unknown): ApprovalTask {
  if (!isRecord(value)) {
    throw new Error("The control plane returned an invalid approval inbox.");
  }
  const id = parseUuid(value.id);
  if (
    !isBoundedString(value.summary) ||
    !isBoundedString(value.repository) ||
    value.cockpit_path !== `/tasks/${id}`
  ) {
    throw new Error("The control plane returned an invalid approval inbox.");
  }
  return {
    id,
    summary: value.summary,
    repository: value.repository,
    cockpit_path: value.cockpit_path,
  };
}

const requestTypes = new Set<string>([
  "BRIEF",
  "UNSAFE_ACTION",
  "RETRY_LIMIT",
  "REVIEW_CONFLICT",
  "REVIEW_RULE",
]);
const decisions = new Set<string>(APPROVAL_DECISIONS);
const expectedOptions: Record<ApprovalRequestType, ApprovalDecision[]> = {
  BRIEF: ["APPROVE", "REQUEST_REVISION", "CANCEL"],
  UNSAFE_ACTION: ["APPROVE", "DENY", "CANCEL"],
  RETRY_LIMIT: ["RETRY", "ABANDON", "CANCEL"],
  REVIEW_CONFLICT: ["APPROVE", "DENY", "CANCEL"],
  REVIEW_RULE: ["APPROVE", "REJECT", "CANCEL"],
};

function parseOptionalState(value: unknown): TaskState | null {
  if (value === null) return null;
  if (typeof value !== "string" || !taskStates.has(value)) {
    throw new Error("The control plane returned an invalid approval inbox.");
  }
  return value as TaskState;
}

function parseApproval(value: unknown): ApprovalInboxItem {
  if (
    !isRecord(value) ||
    typeof value.request_type !== "string" ||
    !requestTypes.has(value.request_type) ||
    !isBoundedString(value.type_label, 100) ||
    typeof value.reason_code !== "string" ||
    !REASON_PATTERN.test(value.reason_code) ||
    !Array.isArray(value.options) ||
    value.options.some((option) => typeof option !== "string" || !decisions.has(option)) ||
    typeof value.requesting_state !== "string" ||
    !taskStates.has(value.requesting_state) ||
    !isTimestamp(value.created_at) ||
    !(value.expires_at === null || isTimestamp(value.expires_at)) ||
    typeof value.actionable !== "boolean" ||
    !(
      value.unavailable_reason === null ||
      value.unavailable_reason === "BRIEF_UNAVAILABLE" ||
      value.unavailable_reason === "RULE_CANDIDATE_UNAVAILABLE"
    ) ||
    !(
      value.operation_name === null ||
      (isBoundedString(value.operation_name, 255) &&
        typeof value.operation_fingerprint === "string" &&
        FINGERPRINT_PATTERN.test(value.operation_fingerprint) &&
        isBoundedString(value.operation_idempotency_key, 255) &&
        (value.operation_checkpoint_evidence_id === null ||
          (typeof value.operation_checkpoint_evidence_id === "string" &&
            UUID_PATTERN.test(value.operation_checkpoint_evidence_id))))
    )
  ) {
    throw new Error("The control plane returned an invalid approval inbox.");
  }
  if (
    value.operation_name === null &&
    (value.operation_fingerprint !== null ||
      value.operation_idempotency_key !== null ||
      value.operation_checkpoint_evidence_id !== null)
  ) {
    throw new Error("The control plane returned an invalid approval inbox.");
  }
  if (
    value.actionable === (value.unavailable_reason !== null) ||
    (value.unavailable_reason === "RULE_CANDIDATE_UNAVAILABLE" &&
      value.request_type !== "REVIEW_RULE") ||
    (value.unavailable_reason === "BRIEF_UNAVAILABLE" && value.request_type !== "BRIEF")
  ) {
    throw new Error("The control plane returned an invalid approval inbox.");
  }
  const requestType = value.request_type as ApprovalRequestType;
  if (
    (requestType === "BRIEF" &&
      value.brief === null &&
      value.unavailable_reason !== "BRIEF_UNAVAILABLE") ||
    (requestType !== "BRIEF" && value.brief !== null)
  ) {
    throw new Error("The control plane returned an invalid approval inbox.");
  }
  const options = value.options as ApprovalDecision[];
  if (options.join(":") !== expectedOptions[requestType].join(":")) {
    throw new Error("The control plane returned an invalid approval inbox.");
  }
  return {
    id: parseUuid(value.id),
    task: parseTask(value.task),
    request_type: requestType,
    type_label: value.type_label,
    reason_code: value.reason_code,
    options,
    requesting_state: value.requesting_state as TaskState,
    resume_state: parseOptionalState(value.resume_state),
    created_at: value.created_at,
    expires_at: value.expires_at,
    operation_name: value.operation_name,
    operation_fingerprint: value.operation_fingerprint as string | null,
    operation_idempotency_key: value.operation_idempotency_key as string | null,
    operation_checkpoint_evidence_id: value.operation_checkpoint_evidence_id as string | null,
    brief: value.brief === null ? null : parseBrief(value.brief),
    supporting_evidence_ids: parseUuidList(value.supporting_evidence_ids),
    actionable: value.actionable,
    unavailable_reason: value.unavailable_reason,
  };
}

function parseRule(value: unknown): RuleInboxItem {
  if (
    !isRecord(value) ||
    !isBoundedString(value.proposed_rule, 10_000) ||
    !isBoundedString(value.recurrence_assessment, 2_000) ||
    !isBoundedString(value.severity_assessment, 100) ||
    !isBoundedString(value.lineage_key, 255) ||
    !isBoundedString(value.permitted_action, 255) ||
    !isBoundedString(value.risk_class, 100) ||
    value.authority !== "NON_AUTHORITATIVE" ||
    value.status !== "EVALUATED"
  ) {
    throw new Error("The control plane returned an invalid approval inbox.");
  }
  return {
    candidate_id: parseUuid(value.candidate_id),
    approval_request_id:
      value.approval_request_id === null ? null : parseUuid(value.approval_request_id),
    authority: value.authority,
    status: value.status,
    task: parseTask(value.task),
    proposed_rule: value.proposed_rule,
    recurrence_assessment: value.recurrence_assessment,
    severity_assessment: value.severity_assessment,
    false_positive_risks: parseStringList(value.false_positive_risks),
    cited_evidence_ids: parseUuidList(value.cited_evidence_ids),
    lineage_key: value.lineage_key,
    permitted_action: value.permitted_action,
    risk_class: value.risk_class,
    scope: parseJsonObject(value.scope),
    matcher: parseJsonObject(value.matcher),
    evidence_requirements: parseStringList(value.evidence_requirements),
  };
}

export function parseApprovalInbox(value: unknown): ApprovalInboxResponse {
  if (
    !isRecord(value) ||
    !Array.isArray(value.approvals) ||
    !Array.isArray(value.rule_candidates)
  ) {
    throw new Error("The control plane returned an invalid approval inbox.");
  }
  const approvals = value.approvals.map(parseApproval);
  const byId = new Map(approvals.map((approval) => [approval.id, approval]));
  const ruleCandidates = value.rule_candidates.map(parseRule);
  for (const rule of ruleCandidates) {
    if (rule.approval_request_id === null) continue;
    const approval = byId.get(rule.approval_request_id);
    if (
      approval?.request_type !== "REVIEW_RULE" ||
      approval.task.id !== rule.task.id ||
      approval.task.cockpit_path !== rule.task.cockpit_path
    ) {
      throw new Error("The control plane returned an invalid approval inbox.");
    }
  }
  return { approvals, rule_candidates: ruleCandidates };
}

function parseDecision(value: unknown): ApprovalDecisionResponse {
  if (
    !isRecord(value) ||
    typeof value.decision !== "string" ||
    !decisions.has(value.decision) ||
    !["APPROVED", "REJECTED", "CANCELLED"].includes(String(value.status)) ||
    typeof value.task_state !== "string" ||
    !taskStates.has(value.task_state)
  ) {
    throw new Error("The control plane returned an invalid approval decision.");
  }
  return {
    request_id: parseUuid(value.request_id),
    decision: value.decision as ApprovalDecision,
    status: value.status as ApprovalDecisionResponse["status"],
    task_id: parseUuid(value.task_id),
    task_state: value.task_state as TaskState,
    audit_event_id: parseUuid(value.audit_event_id),
  };
}

const controlPlaneUrl = normalizeControlPlaneUrl(process.env.NEXT_PUBLIC_CONTROL_PLANE_URL);

async function request(path: string, init: RequestInit): Promise<Response> {
  const response = await fetch(`${controlPlaneUrl}${path}`, {
    ...init,
    credentials: "include",
    headers: { Accept: "application/json", ...init.headers },
  });
  if (!response.ok) {
    const message =
      response.status === 401
        ? "Your session expired. Refresh the page and sign in again."
        : response.status === 403
          ? "Re-enter your password, then try this protected decision again."
          : response.status === 404
            ? "This approval is no longer available."
            : response.status === 409
              ? "This approval changed. The inbox has been refreshed."
              : response.status === 422
                ? "That decision is not available for this approval."
                : "Unable to update the approval inbox.";
    throw new ApprovalRequestError(message, response.status);
  }
  return response;
}

function csrfHeaders(): HeadersInit {
  const token = cookieValue(document.cookie, CSRF_COOKIE_NAME);
  if (!token) {
    throw new ApprovalRequestError(
      "The security token is missing. Refresh the page and try again.",
      0,
    );
  }
  return { "Content-Type": "application/json", "X-CSRF-Token": token };
}

export const approvalClient = {
  async inbox(signal?: AbortSignal): Promise<ApprovalInboxResponse> {
    const response = await request("/api/approvals/inbox", { method: "GET", signal });
    return parseApprovalInbox(await response.json());
  },

  async decide(requestId: string, decision: ApprovalDecision): Promise<ApprovalDecisionResponse> {
    if (!UUID_PATTERN.test(requestId) || !decisions.has(decision)) {
      throw new ApprovalRequestError("That approval decision is invalid.", 0);
    }
    const response = await request(`/api/approvals/${encodeURIComponent(requestId)}/decisions`, {
      method: "POST",
      headers: csrfHeaders(),
      body: JSON.stringify({ decision }),
    });
    const parsed = parseDecision(await response.json());
    if (parsed.request_id !== requestId || parsed.decision !== decision) {
      throw new Error("The control plane returned an invalid approval decision.");
    }
    return parsed;
  },
};

export type ApprovalInboxClient = Pick<typeof approvalClient, "inbox">;

export class LatestApprovalInboxLoader {
  private generation = 0;

  invalidate(): void {
    this.generation += 1;
  }

  async load(
    signal?: AbortSignal,
    client: ApprovalInboxClient = approvalClient,
  ): Promise<ApprovalInboxResponse | undefined> {
    const requestGeneration = ++this.generation;
    try {
      const result = await client.inbox(signal);
      return requestGeneration === this.generation ? result : undefined;
    } catch (error) {
      if (requestGeneration !== this.generation) return undefined;
      throw error;
    }
  }
}
