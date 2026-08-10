import { afterEach, describe, expect, it, vi } from "vitest";

import { RepositoryRequestError, repositoryClient } from "./repository-client";

const repositoryProjection = {
  repository_key: "boppuh/mathews",
  configured: false,
  mutation_blocked: true,
  host_available: false,
  configuration: null,
  preflight: {
    status: "NOT_RUN",
    attempt_id: null,
    configuration_id: null,
    configuration_version: null,
    configuration_digest: null,
    resolved_base_sha: null,
    checks: [],
  },
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("repositoryClient", () => {
  it("loads the authenticated repository projection", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(repositoryProjection), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(repositoryClient.load()).resolves.toEqual(repositoryProjection);
    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:8000/api/repository",
      expect.objectContaining({ method: "GET", credentials: "include" }),
    );
  });

  it("sends a protected version with CSRF and exact write-only references", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(repositoryProjection), {
        status: 201,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("document", { cookie: "__Host-mathews-csrf=csrf-token" });
    const body = {
      repository_key: "boppuh/mathews",
      expected_configuration_version: 1,
      repository_settings: { root: "/tmp/mathews" },
      git_settings: {},
      xcode_settings: {},
      operations: [],
      e2e_assertions: [],
      artifact_settings: {},
      prohibited_paths: [".git"],
      secret_updates: { push_credential: "keychain://mathews/git" },
      approve_sensitive_change: true,
    };

    await repositoryClient.save(body);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://localhost:8000/api/repository/versions");
    expect(init.headers).toMatchObject({
      "Content-Type": "application/json",
      "X-CSRF-Token": "csrf-token",
    });
    expect(JSON.parse(String(init.body))).toEqual(body);
  });

  it("maps host failures to a fixed safe preflight message", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response(JSON.stringify({ detail: "private host detail" }), { status: 503 }),
        ),
    );
    vi.stubGlobal("document", { cookie: "__Host-mathews-csrf=csrf-token" });

    await expect(repositoryClient.preflight()).rejects.toEqual(
      new RepositoryRequestError("The local host is unavailable, so preflight could not run.", 503),
    );
  });

  it("rejects a protected request when the CSRF cookie is missing", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("document", { cookie: "" });

    await expect(repositoryClient.preflight()).rejects.toEqual(
      new RepositoryRequestError(
        "The security token is missing. Refresh the page and try again.",
        0,
      ),
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
