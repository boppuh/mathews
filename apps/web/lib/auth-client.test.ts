import { afterEach, describe, expect, it, vi } from "vitest";

import { BOOTSTRAP_PASSWORD_POLICY_MESSAGE } from "./auth";
import {
  AuthRequestError,
  authClient,
  LatestAuthSnapshotLoader,
  loadAuthSnapshot,
  logoutAndRefresh,
} from "./auth-client";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("loadAuthSnapshot", () => {
  it("checks the authenticated session without touching public status", async () => {
    const session = {
      authenticated: true as const,
      expires_at: "2026-08-01T12:00:00Z",
      reauthenticated_until: "2026-08-01T11:05:00Z",
    };
    const client = {
      session: vi.fn().mockResolvedValue(session),
      status: vi.fn(),
    };

    await expect(loadAuthSnapshot(undefined, client)).resolves.toEqual({
      status: { bootstrap_required: false, bootstrap_available: false },
      session,
    });
    expect(client.session).toHaveBeenCalledOnce();
    expect(client.status).not.toHaveBeenCalled();
  });

  it("falls back to public status only after session returns 401", async () => {
    const calls: string[] = [];
    const client = {
      session: vi.fn().mockImplementation(async () => {
        calls.push("session");
        throw new AuthRequestError("signed out", 401);
      }),
      status: vi.fn().mockImplementation(async () => {
        calls.push("status");
        return { bootstrap_required: true, bootstrap_available: true };
      }),
    };

    await expect(loadAuthSnapshot(undefined, client)).resolves.toEqual({
      status: { bootstrap_required: true, bootstrap_available: true },
      session: null,
    });
    expect(calls).toEqual(["session", "status"]);
  });

  it("fails closed without probing status after another session error", async () => {
    const error = new AuthRequestError("service unavailable", 503);
    const client = {
      session: vi.fn().mockRejectedValue(error),
      status: vi.fn(),
    };

    await expect(loadAuthSnapshot(undefined, client)).rejects.toBe(error);
    expect(client.status).not.toHaveBeenCalled();
  });

  it("drops an older authenticated result after a newer signed-out request wins", async () => {
    let resolveOlder:
      | ((session: {
          authenticated: true;
          expires_at: string;
          reauthenticated_until: string;
        }) => void)
      | undefined;
    const olderSession = new Promise<{
      authenticated: true;
      expires_at: string;
      reauthenticated_until: string;
    }>((resolve) => {
      resolveOlder = resolve;
    });
    const loader = new LatestAuthSnapshotLoader();

    const olderResult = loader.load(undefined, {
      session: vi.fn().mockReturnValue(olderSession),
      status: vi.fn(),
    });
    const newerResult = loader.load(undefined, {
      session: vi.fn().mockRejectedValue(new AuthRequestError("signed out", 401)),
      status: vi.fn().mockResolvedValue({ bootstrap_required: false, bootstrap_available: false }),
    });

    await expect(newerResult).resolves.toEqual({
      status: { bootstrap_required: false, bootstrap_available: false },
      session: null,
    });
    resolveOlder?.({
      authenticated: true,
      expires_at: "2026-08-01T12:00:00Z",
      reauthenticated_until: "2026-08-01T11:05:00Z",
    });
    await expect(olderResult).resolves.toBeUndefined();
  });
});

describe("logoutAndRefresh", () => {
  it("revalidates after an expired-session 401 and treats it as signed out", async () => {
    const refresh = vi.fn().mockResolvedValue({
      status: { bootstrap_required: false, bootstrap_available: false },
      session: null,
    });
    const client = {
      logout: vi.fn().mockRejectedValue(new AuthRequestError("expired", 401)),
    };

    await expect(logoutAndRefresh(refresh, client)).resolves.toEqual({
      snapshot: {
        status: { bootstrap_required: false, bootstrap_available: false },
        session: null,
      },
      error: null,
    });
    expect(refresh).toHaveBeenCalledOnce();
  });

  it("still revalidates after another logout failure", async () => {
    const error = new AuthRequestError("unavailable", 503);
    const refresh = vi.fn().mockResolvedValue({
      status: { bootstrap_required: false, bootstrap_available: false },
      session: {
        authenticated: true,
        expires_at: "2026-08-01T12:00:00Z",
        reauthenticated_until: "2026-08-01T11:05:00Z",
      },
    });

    await expect(
      logoutAndRefresh(refresh, { logout: vi.fn().mockRejectedValue(error) }),
    ).resolves.toMatchObject({ error });
    expect(refresh).toHaveBeenCalledOnce();
  });
});

describe("authClient mutation contract", () => {
  it("sends credentialed bootstrap JSON with the pre-auth CSRF cookie", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 201 }));
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("document", {
      cookie: "__Host-mathews-csrf=csrf%2Ftoken; unrelated=value",
    });

    await authClient.bootstrap("one-time-token", "a-password-with-15-characters");

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("http://localhost:8000/api/auth/bootstrap");
    expect(init.credentials).toBe("include");
    expect(init.method).toBe("POST");
    expect(init.headers).toMatchObject({
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-CSRF-Token": "csrf/token",
    });
    expect(JSON.parse(String(init.body))).toEqual({
      bootstrap_token: "one-time-token",
      password: "a-password-with-15-characters",
    });
  });

  it("maps bootstrap 422 responses to the fixed password policy message", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ detail: "do not display this backend body" }), {
        status: 422,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("document", { cookie: "__Host-mathews-csrf=csrf-token" });

    await expect(authClient.bootstrap("one-time-token", "short")).rejects.toMatchObject({
      message: BOOTSTRAP_PASSWORD_POLICY_MESSAGE,
      status: 422,
    });
  });
});
