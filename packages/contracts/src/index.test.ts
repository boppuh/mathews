import { describe, expect, it } from "vitest";

import {
  APPROVAL_STATUSES,
  TASK_BLOCKER_CODES,
  TASK_EVENT_KINDS,
  TASK_EVIDENCE_STATUSES,
  TASK_STATE_CONTEXT_KINDS,
  TASK_STATES,
} from "./index";

describe("TASK_STATES", () => {
  it("keeps successful handoff distinct from merge or release", () => {
    expect(TASK_STATES).toContain("HANDED_OFF");
    expect(TASK_STATES).not.toContain("COMPLETE");
  });
});

describe("task cockpit vocabularies", () => {
  it("keeps workflow boundaries explicit", () => {
    expect(TASK_STATE_CONTEXT_KINDS).toContain("RESUMABLE_ESCALATION");
    expect(TASK_STATE_CONTEXT_KINDS).toContain("AUTOMATION_HANDED_OFF");
    expect(TASK_EVENT_KINDS.join(",")).not.toContain("RAW_OUTPUT");
    expect(TASK_EVIDENCE_STATUSES).toEqual(["AVAILABLE", "CORRECTION", "DELETED"]);
    expect(APPROVAL_STATUSES).toContain("PENDING");
  });
});

describe("TASK_BLOCKER_CODES", () => {
  it("keeps work-queue blockers finite and presentation-safe", () => {
    expect(TASK_BLOCKER_CODES).toEqual([
      "APPROVAL_REQUIRED",
      "DEPENDENCY_OUTAGE",
      "RECONCILIATION_REQUIRED",
    ]);
  });
});
