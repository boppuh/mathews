import { afterEach, describe, expect, it, vi } from "vitest";

import {
  evidenceClient,
  evidenceDownloadUrl,
  LatestTaskDetailLoader,
  LatestTaskListLoader,
  TaskRequestError,
  taskClient,
  taskEventStreamUrl,
} from "./task-client";

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

const evidence = {
  id: "33333333-3333-4333-8333-333333333333",
  evidence_type: "test-log",
  captured_at: "2026-07-30T12:00:00Z",
  status: "AVAILABLE" as const,
  category: "LOG" as const,
  content_access: "AVAILABLE" as const,
  correction_of_id: null,
  corrected_by_id: null,
  deletion_reason: null,
  deleted_at: null,
  download_path: "/api/evidence/33333333-3333-4333-8333-333333333333/download",
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("taskClient", () => {
  it("builds the task-scoped SSE endpoint URL", () => {
    expect(taskEventStreamUrl(task.id)).toBe(`http://localhost:8000/api/tasks/${task.id}/events`);
  });

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

  it("loads a credentialed durable cockpit", async () => {
    const cockpit = {
      task,
      state_context: {
        kind: "ACTIVE",
        label: "Intake",
        detail: "The request is captured and waiting for briefing.",
        resume_state: null,
      },
      events: [],
      acceptance_criteria: [],
      evidence: [],
      approvals: [],
    };
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(cockpit), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(taskClient.detail(task.id)).resolves.toEqual(cockpit);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`http://localhost:8000/api/tasks/${task.id}`);
    expect(init).toMatchObject({ credentials: "include", method: "GET" });
  });

  it.each([
    [401, "Your session expired"],
    [404, "task is unavailable"],
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

describe("evidenceClient", () => {
  it("loads and formats credentialed redacted JSON on demand", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ result: "passed" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(evidenceClient.content(evidence)).resolves.toEqual({
      text: '{\n  "result": "passed"\n}',
      mediaType: "application/json",
    });
    expect(evidenceDownloadUrl(evidence)).toBe(`http://localhost:8000${evidence.download_path}`);
    expect(fetchMock).toHaveBeenCalledWith(
      `http://localhost:8000${evidence.download_path}`,
      expect.objectContaining({ credentials: "include", method: "GET" }),
    );
  });

  it("never requests restricted evidence or a mismatched download path", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      evidenceClient.content({ ...evidence, download_path: "/api/evidence/other/download" }),
    ).rejects.toMatchObject({ status: 404, message: "This evidence content is unavailable." });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("does not expose download error bodies", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response("sensitive backend detail", {
          status: 404,
          headers: { "Content-Type": "text/plain" },
        }),
      ),
    );

    await expect(evidenceClient.content(evidence)).rejects.toMatchObject({
      status: 404,
      message: "This evidence content is unavailable.",
    });
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

describe("LatestTaskDetailLoader", () => {
  const cockpit = {
    task,
    state_context: {
      kind: "ACTIVE" as const,
      label: "Intake",
      detail: "The request is captured and waiting for briefing.",
      resume_state: null,
    },
    events: [],
    acceptance_criteria: [],
    evidence: [],
    approvals: [],
  };

  it("drops an older cockpit response after a newer route wins", async () => {
    let resolveOlder: ((value: typeof cockpit) => void) | undefined;
    const olderRequest = new Promise<typeof cockpit>((resolve) => {
      resolveOlder = resolve;
    });
    const loader = new LatestTaskDetailLoader();
    const olderResult = loader.load(task.id, undefined, {
      detail: vi.fn().mockReturnValue(olderRequest),
    });
    const newerCockpit = {
      ...cockpit,
      task: {
        ...task,
        id: "22222222-2222-4222-8222-222222222222",
        cockpit_path: "/tasks/22222222-2222-4222-8222-222222222222",
      },
    };

    await expect(
      loader.load(newerCockpit.task.id, undefined, {
        detail: vi.fn().mockResolvedValue(newerCockpit),
      }),
    ).resolves.toEqual(newerCockpit);
    resolveOlder?.(cockpit);

    await expect(olderResult).resolves.toBeUndefined();
  });

  it("drops an older cockpit failure after a newer route wins", async () => {
    let rejectOlder: ((error: Error) => void) | undefined;
    const olderRequest = new Promise<never>((_resolve, reject) => {
      rejectOlder = reject;
    });
    const loader = new LatestTaskDetailLoader();
    const olderResult = loader.load(task.id, undefined, {
      detail: vi.fn().mockReturnValue(olderRequest),
    });

    await expect(
      loader.load(task.id, undefined, {
        detail: vi.fn().mockResolvedValue(cockpit),
      }),
    ).resolves.toEqual(cockpit);
    rejectOlder?.(new TaskRequestError("stale failure", 503));

    await expect(olderResult).resolves.toBeUndefined();
  });

  it("invalidates an in-flight cockpit response during cleanup", async () => {
    let resolveRequest: ((value: typeof cockpit) => void) | undefined;
    const request = new Promise<typeof cockpit>((resolve) => {
      resolveRequest = resolve;
    });
    const loader = new LatestTaskDetailLoader();
    const result = loader.load(task.id, undefined, {
      detail: vi.fn().mockReturnValue(request),
    });

    loader.invalidate();
    resolveRequest?.(cockpit);

    await expect(result).resolves.toBeUndefined();
  });
});
