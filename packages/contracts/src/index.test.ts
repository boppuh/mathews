import { describe, expect, it } from "vitest";

import { TASK_BLOCKER_CODES, TASK_STATES } from "./index";

describe("TASK_STATES", () => {
  it("keeps successful handoff distinct from merge or release", () => {
    expect(TASK_STATES).toContain("HANDED_OFF");
    expect(TASK_STATES).not.toContain("COMPLETE");
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
