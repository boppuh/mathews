import { describe, expect, it } from "vitest";

import { stageLabel } from "./stages";

describe("stageLabel", () => {
  it("renders canonical state names for the cockpit", () => {
    expect(stageLabel("READY_FOR_HUMAN_MERGE")).toBe("Ready For Human Merge");
    expect(stageLabel("PR_ACTIVE")).toBe("PR Active");
  });
});
