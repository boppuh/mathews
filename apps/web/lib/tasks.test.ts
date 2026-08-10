import type { TaskSummary } from "@mathews/contracts";
import { describe, expect, it } from "vitest";

import {
  mergeLoadedTasks,
  parseTaskCancellationResponse,
  parseTaskCockpit,
  parseTaskEvent,
  parseTaskList,
  parseTaskSteeringResponse,
  parseTaskSummary,
  shortRevision,
} from "./tasks";

const task = {
  id: "11111111-1111-4111-8111-111111111111",
  summary: "Add offline support",
  state: "INTAKE",
  repository: "boppuh/mathews",
  base_revision: "a".repeat(40),
  created_at: "2026-07-30T12:00:00Z",
  last_activity_at: "2026-07-30T12:01:00Z",
  blockers: [
    {
      code: "APPROVAL_REQUIRED",
      label: "Approval required",
      count: 1,
    },
  ],
  cockpit_path: "/tasks/11111111-1111-4111-8111-111111111111",
} satisfies TaskSummary;

describe("task response parsing", () => {
  it("accepts the authenticated task-list contract", () => {
    expect(parseTaskList({ tasks: [task] })).toEqual({ tasks: [task] });
    expect(parseTaskSummary(task)).toEqual(task);
  });

  it.each([
    { ...task, state: "MERGED" },
    { ...task, base_revision: "main" },
    { ...task, last_activity_at: "eventually" },
    { ...task, blockers: [{ code: "RAW_ERROR", label: "secret", count: 1 }] },
    { ...task, cockpit_path: "https://example.com/phishing" },
    { ...task, cockpit_path: "/tasks/another-id" },
  ])("rejects an invalid or unsafe task projection", (value) => {
    expect(() => parseTaskSummary(value)).toThrow("invalid task");
  });

  it("rejects malformed list envelopes", () => {
    expect(() => parseTaskList([])).toThrow("invalid task list");
    expect(() => parseTaskList({ tasks: "not-an-array" })).toThrow("invalid task list");
  });
});

describe("task control response parsing", () => {
  const steering = {
    steering_id: "22222222-2222-4222-8222-222222222222",
    task_id: task.id,
    classification: "SCOPE_CHANGE",
    impacts: ["PATHS", "TESTS"],
    task_state: "BRIEFING",
    evidence_id: "33333333-3333-4333-8333-333333333333",
    request_evidence_id: "44444444-4444-4444-8444-444444444444",
    event_id: "55555555-5555-4555-8555-555555555555",
    invalidated_brief_id: "66666666-6666-4666-8666-666666666666",
    invalidated_validation_contract_id: "77777777-7777-4777-8777-777777777777",
    revoked_lease_count: 1,
    revoked_tool_grant_count: 2,
    replayed: false,
  };
  const cancellation = {
    cancellation_id: "88888888-8888-4888-8888-888888888888",
    task_id: task.id,
    task_state: "CANCELLED",
    partial_evidence_id: "99999999-9999-4999-8999-999999999999",
    revoked_lease_count: 1,
    revoked_tool_grant_count: 2,
    cleanup_complete: true,
    replayed: false,
  };

  it("accepts bounded steering and cancellation results", () => {
    expect(parseTaskSteeringResponse(steering)).toEqual(steering);
    expect(parseTaskCancellationResponse(cancellation)).toEqual(cancellation);
  });

  it.each([
    { ...steering, classification: "CLARIFICATION", impacts: ["PATHS"] },
    { ...steering, impacts: ["SHELL"] },
    { ...steering, revoked_lease_count: -1 },
    { ...steering, request_evidence_id: "not-a-uuid" },
  ])("rejects invalid steering results", (value) => {
    expect(() => parseTaskSteeringResponse(value)).toThrow("control plane returned");
  });

  it.each([
    { ...cancellation, task_state: "IMPLEMENTING" },
    { ...cancellation, cleanup_complete: "yes" },
    { ...cancellation, revoked_tool_grant_count: -1 },
  ])("rejects invalid cancellation results", (value) => {
    expect(() => parseTaskCancellationResponse(value)).toThrow("control plane returned");
  });
});

describe("task cockpit parsing", () => {
  const cockpit = {
    task,
    state_context: {
      kind: "ACTIVE",
      label: "Intake",
      detail: "The request is captured and waiting for briefing.",
      resume_state: null,
    },
    events: [
      {
        id: "22222222-2222-4222-8222-222222222222",
        sequence: 1,
        kind: "CREATED",
        summary: "Task request captured.",
        occurred_at: "2026-07-30T12:00:00Z",
        from_state: null,
        to_state: null,
        evidence_count: 1,
      },
    ],
    acceptance_criteria: [
      {
        id: "criterion-1",
        requirement: "The task can be inspected without leaving the cockpit.",
        verification: "HUMAN_INSPECTION",
        status: "PENDING",
      },
    ],
    evidence: [
      {
        id: "33333333-3333-4333-8333-333333333333",
        evidence_type: "task-request",
        captured_at: "2026-07-30T12:00:00Z",
        status: "AVAILABLE",
        category: "OTHER",
        content_access: "AVAILABLE",
        correction_of_id: null,
        corrected_by_id: null,
        deletion_reason: null,
        deleted_at: null,
        download_path: "/api/evidence/33333333-3333-4333-8333-333333333333/download",
      },
    ],
    approvals: [
      {
        id: "44444444-4444-4444-8444-444444444444",
        type_label: "Brief approval",
        status: "PENDING",
        requesting_state: "INTAKE",
        resume_state: null,
        created_at: "2026-07-30T12:00:00Z",
        expires_at: null,
      },
    ],
  };

  it("accepts a safe durable cockpit projection", () => {
    expect(parseTaskCockpit(cockpit)).toEqual(cockpit);
    expect(parseTaskEvent(cockpit.events[0])).toEqual(cockpit.events[0]);
  });

  it("accepts a legacy deletion without a structured reason", () => {
    const deletedEvidence = {
      ...cockpit.evidence[0],
      status: "DELETED",
      content_access: "DELETED",
      deleted_at: "2026-07-30T12:02:00Z",
      download_path: null,
    };

    expect(parseTaskCockpit({ ...cockpit, evidence: [deletedEvidence] }).evidence).toEqual([
      deletedEvidence,
    ]);
  });

  it.each([
    { ...cockpit, state_context: { ...cockpit.state_context, kind: "MERGED" } },
    { ...cockpit, events: [{ ...cockpit.events[0], sequence: 0 }] },
    { ...cockpit, events: [{ ...cockpit.events[0], kind: "RAW_OUTPUT" }] },
    { ...cockpit, evidence: [{ ...cockpit.evidence[0], evidence_type: "../secret" }] },
    {
      ...cockpit,
      evidence: [{ ...cockpit.evidence[0], download_path: "https://example.com/secret" }],
    },
    {
      ...cockpit,
      evidence: [{ ...cockpit.evidence[0], status: "DELETED", content_access: "DELETED" }],
    },
    {
      ...cockpit,
      acceptance_criteria: [{ ...cockpit.acceptance_criteria[0], verification: "SHELL" }],
    },
    { ...cockpit, approvals: [{ ...cockpit.approvals[0], status: "UNKNOWN" }] },
  ])("rejects unsafe cockpit projections", (value) => {
    expect(() => parseTaskCockpit(value)).toThrow("control plane returned");
  });

  it("rejects duplicate or out-of-order durable event sequences", () => {
    const duplicate = {
      ...cockpit,
      events: [cockpit.events[0], { ...cockpit.events[0], id: task.id }],
    };
    expect(() => parseTaskCockpit(duplicate)).toThrow("event order");
  });
});

describe("shortRevision", () => {
  it("uses an eight-character display projection", () => {
    expect(shortRevision("1234567890abcdef")).toBe("12345678");
  });
});

describe("mergeLoadedTasks", () => {
  it("preserves a locally created task when an older list response arrives", () => {
    const localTask = {
      ...task,
      id: "22222222-2222-4222-8222-222222222222",
      cockpit_path: "/tasks/22222222-2222-4222-8222-222222222222",
    };

    expect(mergeLoadedTasks([task], [localTask])).toEqual([localTask, task]);
    expect(mergeLoadedTasks([task], [task])).toEqual([task]);
  });
});
