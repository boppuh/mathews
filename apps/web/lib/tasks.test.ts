import type { TaskSummary } from "@mathews/contracts";
import { describe, expect, it } from "vitest";

import { mergeLoadedTasks, parseTaskList, parseTaskSummary, shortRevision } from "./tasks";

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
