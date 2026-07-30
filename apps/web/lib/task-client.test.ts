import { afterEach, describe, expect, it, vi } from "vitest";

import { LatestTaskListLoader, TaskRequestError, taskClient } from "./task-client";

const task = {
  id: "11111111-1111-4111-8111-111111111111",
  summary: "Add offline support",
  state: "INTAKE",
  repository: "boppuh/mathews",
  base_revision: "a".repeat(40),
  created_at: "2026-07-30T12:00:00Z",
  last_activity_at: "2026-07-30T12:00:00Z",
  blockers: [],
  cockpit_path: "/tasks/11111111-1111-4111-8111-111111111111",
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("taskClient", () => {
  it("loads the credentialed work queue", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ tasks: [task] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(taskClient.list()).resolves.toEqual({ tasks: [task] });

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://localhost:8000/api/tasks");
    expect(init).toMatchObject({ credentials: "include", method: "GET" });
  });

  it("creates a credentialed task with bound CSRF and the exact input", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(task), {
        status: 201,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("document", {
      cookie: "__Host-mathews-csrf=csrf%2Ftoken; unrelated=value",
    });
    const body = {
      repository: "boppuh/mathews",
      base_revision: "a".repeat(40),
      request: "Add offline support",
    };

    await expect(taskClient.create(body)).resolves.toEqual(task);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://localhost:8000/api/tasks");
    expect(init.credentials).toBe("include");
    expect(init.method).toBe("POST");
    expect(init.headers).toMatchObject({
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-CSRF-Token": "csrf/token",
    });
    expect(JSON.parse(String(init.body))).toEqual(body);
  });

  it.each([
    [401, "Your session expired"],
    [413, "too large"],
    [422, "Check the repository"],
  ])("maps status %i without exposing response details", async (status, message) => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ detail: "sensitive backend detail" }), {
          status,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    await expect(taskClient.list()).rejects.toMatchObject({
      message: expect.stringContaining(message),
      status,
    });
  });

  it("fails before mutation when the CSRF cookie is unavailable", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("document", { cookie: "" });

    await expect(
      taskClient.create({
        repository: "boppuh/mathews",
        base_revision: "a".repeat(40),
        request: "Add offline support",
      }),
    ).rejects.toBeInstanceOf(TaskRequestError);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("LatestTaskListLoader", () => {
  it("drops an older failure after a newer list request wins", async () => {
    let rejectOlder: ((error: Error) => void) | undefined;
    const olderRequest = new Promise<never>((_resolve, reject) => {
      rejectOlder = reject;
    });
    const loader = new LatestTaskListLoader();
    const olderResult = loader.load(undefined, {
      list: vi.fn().mockReturnValue(olderRequest),
    });

    await expect(
      loader.load(undefined, {
        list: vi.fn().mockResolvedValue({ tasks: [] }),
      }),
    ).resolves.toEqual({ tasks: [] });
    rejectOlder?.(new TaskRequestError("stale failure", 503));

    await expect(olderResult).resolves.toBeUndefined();
  });

  it("surfaces the newest list failure", async () => {
    const error = new TaskRequestError("current failure", 503);
    const loader = new LatestTaskListLoader();

    await expect(
      loader.load(undefined, {
        list: vi.fn().mockRejectedValue(error),
      }),
    ).rejects.toBe(error);
  });
});
