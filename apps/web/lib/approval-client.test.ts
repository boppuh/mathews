import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ApprovalRequestError,
  approvalClient,
  LatestApprovalInboxLoader,
  parseApprovalInbox,
} from "./approval-client";

const requestId = "11111111-1111-4111-8111-111111111111";
const taskId = "22222222-2222-4222-8222-222222222222";
const candidateId = "33333333-3333-4333-8333-333333333333";
const evidenceId = "44444444-4444-4444-8444-444444444444";
const auditId = "55555555-5555-4555-8555-555555555555";

const approval = {
  id: requestId,
  task: {
    id: taskId,
    summary: "Repair formatting",
    repository: "boppuh/mathews",
    cockpit_path: `/tasks/${taskId}`,
  },
  request_type: "REVIEW_RULE",
  type_label: "Review rule",
  reason_code: "REVIEW_RULE_REQUIRED",
  options: ["APPROVE", "REJECT", "CANCEL"],
  requesting_state: "REPAIRING",
  resume_state: "REPAIRING",
  created_at: "2026-08-10T12:00:00Z",
  expires_at: "2026-08-10T13:00:00Z",
  operation_name: "host.mutate",
  operation_fingerprint: "a".repeat(64),
  supporting_evidence_ids: [evidenceId],
};

const rule = {
  candidate_id: candidateId,
  approval_request_id: requestId,
  task: approval.task,
  proposed_rule: "Retry exact formatting failures once.",
  recurrence_assessment: "Repeated",
  severity_assessment: "Low",
  false_positive_risks: [],
  cited_evidence_ids: [evidenceId],
  lineage_key: "format-repair",
  permitted_action: "repair.format",
  risk_class: "low",
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("parseApprovalInbox", () => {
  it("accepts an exact evaluated rule linked to its approval", () => {
    expect(parseApprovalInbox({ approvals: [approval], rule_candidates: [rule] })).toEqual({
      approvals: [approval],
      rule_candidates: [rule],
    });
  });

  it("rejects altered decision options and detached rule candidates", () => {
    expect(() =>
      parseApprovalInbox({
        approvals: [{ ...approval, options: ["APPROVE", "CANCEL"] }],
        rule_candidates: [rule],
      }),
    ).toThrow("invalid approval inbox");
    expect(() =>
      parseApprovalInbox({
        approvals: [approval],
        rule_candidates: [{ ...rule, approval_request_id: auditId }],
      }),
    ).toThrow("invalid approval inbox");
  });

  it("rejects a malformed exact-operation fingerprint", () => {
    expect(() =>
      parseApprovalInbox({
        approvals: [{ ...approval, operation_fingerprint: "secret" }],
        rule_candidates: [rule],
      }),
    ).toThrow("invalid approval inbox");
  });
});

describe("approvalClient", () => {
  it("loads the credentialed inbox", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ approvals: [approval], rule_candidates: [rule] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(approvalClient.inbox()).resolves.toEqual({
      approvals: [approval],
      rule_candidates: [rule],
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:8000/api/approvals/inbox",
      expect.objectContaining({ credentials: "include", method: "GET" }),
    );
  });

  it("records only the selected decision with bound CSRF", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          request_id: requestId,
          decision: "APPROVE",
          status: "APPROVED",
          task_id: taskId,
          task_state: "REPAIRING",
          audit_event_id: auditId,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("document", { cookie: "__Host-mathews-csrf=bound%2Ftoken" });

    await expect(approvalClient.decide(requestId, "APPROVE")).resolves.toMatchObject({
      request_id: requestId,
      decision: "APPROVE",
      audit_event_id: auditId,
    });
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`http://localhost:8000/api/approvals/${requestId}/decisions`);
    expect(init).toMatchObject({ credentials: "include", method: "POST" });
    expect(init.headers).toMatchObject({
      "Content-Type": "application/json",
      "X-CSRF-Token": "bound/token",
    });
    expect(JSON.parse(String(init.body))).toEqual({ decision: "APPROVE" });
  });

  it("fails before mutation without CSRF and sanitizes conflicts", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("document", { cookie: "" });
    await expect(approvalClient.decide(requestId, "APPROVE")).rejects.toBeInstanceOf(
      ApprovalRequestError,
    );
    expect(fetchMock).not.toHaveBeenCalled();

    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response(JSON.stringify({ detail: "sensitive internal state" }), { status: 409 }),
        ),
    );
    vi.stubGlobal("document", { cookie: "__Host-mathews-csrf=token" });
    await expect(approvalClient.decide(requestId, "APPROVE")).rejects.toMatchObject({
      status: 409,
      message: expect.stringContaining("changed"),
    });
  });
});

describe("LatestApprovalInboxLoader", () => {
  it("drops an older response after a newer refresh wins", async () => {
    let resolveOlder: ((value: ReturnType<typeof parseApprovalInbox>) => void) | undefined;
    const older = new Promise<ReturnType<typeof parseApprovalInbox>>((resolve) => {
      resolveOlder = resolve;
    });
    const latest = { approvals: [], rule_candidates: [] };
    const client = {
      inbox: vi.fn().mockReturnValueOnce(older).mockResolvedValueOnce(latest),
    };
    const loader = new LatestApprovalInboxLoader();

    const first = loader.load(undefined, client);
    await expect(loader.load(undefined, client)).resolves.toEqual(latest);
    resolveOlder?.(parseApprovalInbox({ approvals: [approval], rule_candidates: [rule] }));
    await expect(first).resolves.toBeUndefined();
  });

  it("drops stale failures and invalidates in-flight work on cleanup", async () => {
    let rejectOlder: ((reason: Error) => void) | undefined;
    const older = new Promise<ReturnType<typeof parseApprovalInbox>>((_resolve, reject) => {
      rejectOlder = reject;
    });
    const client = { inbox: vi.fn().mockReturnValue(older) };
    const loader = new LatestApprovalInboxLoader();

    const pending = loader.load(undefined, client);
    loader.invalidate();
    rejectOlder?.(new Error("stale failure"));
    await expect(pending).resolves.toBeUndefined();
  });
});
