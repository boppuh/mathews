import { describe, expect, it } from "vitest";

import { TASK_STATES } from "./index";

describe("TASK_STATES", () => {
  it("keeps successful handoff distinct from merge or release", () => {
    expect(TASK_STATES).toContain("HANDED_OFF");
    expect(TASK_STATES).not.toContain("COMPLETE");
  });
});
