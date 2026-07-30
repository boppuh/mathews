import { describe, expect, it } from "vitest";

import {
  authViewFor,
  BOOTSTRAP_PASSWORD_POLICY_MESSAGE,
  bootstrapPasswordError,
  cookieValue,
  meetsBootstrapPasswordMinimum,
  normalizeControlPlaneUrl,
  PASSWORD_CONFIRMATION_MESSAGE,
  parseAuthSession,
  parseAuthStatus,
  sessionRefreshDelay,
} from "./auth";

describe("parseAuthSession", () => {
  it("normalizes an ordinary authenticated session", () => {
    expect(
      parseAuthSession({
        authenticated: true,
        expires_at: "2026-08-01T12:00:00Z",
        reauthenticated_until: "2026-08-01T11:05:00Z",
      }),
    ).toEqual({
      authenticated: true,
      expires_at: "2026-08-01T12:00:00Z",
      reauthenticated_until: "2026-08-01T11:05:00Z",
    });
  });

  it("fails closed for a malformed response", () => {
    expect(() =>
      parseAuthSession({
        authenticated: true,
        expires_at: "not-a-date",
        reauthenticated_until: "2026-08-01T11:05:00Z",
      }),
    ).toThrow("invalid session response");
  });
});

describe("parseAuthStatus", () => {
  it("accepts the public bootstrap status", () => {
    expect(parseAuthStatus({ bootstrap_required: true, bootstrap_available: true })).toEqual({
      bootstrap_required: true,
      bootstrap_available: true,
    });
  });
});

describe("authViewFor", () => {
  it.each([
    [
      {
        status: { bootstrap_required: true, bootstrap_available: true },
        session: null,
      },
      "bootstrap",
    ],
    [
      {
        status: { bootstrap_required: true, bootstrap_available: false },
        session: null,
      },
      "bootstrap-unavailable",
    ],
    [
      {
        status: { bootstrap_required: false, bootstrap_available: false },
        session: null,
      },
      "login",
    ],
    [
      {
        status: { bootstrap_required: false, bootstrap_available: false },
        session: {
          authenticated: true,
          expires_at: "2026-08-01T12:00:00Z",
          reauthenticated_until: "2026-08-01T11:05:00Z",
        },
      },
      "workspace",
    ],
  ] as const)("selects %s session view", (session, expected) => {
    expect(authViewFor(session)).toBe(expected);
  });
});

describe("bootstrapPasswordError", () => {
  it("makes the minimum password length enforceable before bootstrap", () => {
    expect(bootstrapPasswordError("12345678901234", "12345678901234")).toBe(
      BOOTSTRAP_PASSWORD_POLICY_MESSAGE,
    );
    expect(bootstrapPasswordError("123456789012345", "123456789012345")).toBeNull();
    expect(meetsBootstrapPasswordMinimum("🔐".repeat(14))).toBe(false);
  });

  it("requires matching password confirmation", () => {
    expect(bootstrapPasswordError("fifteen-chars!!", "different-value")).toBe(
      PASSWORD_CONFIRMATION_MESSAGE,
    );
  });
});

describe("sessionRefreshDelay", () => {
  it("schedules just after expiry and clamps past or distant expirations", () => {
    const now = Date.parse("2026-08-01T12:00:00Z");
    expect(sessionRefreshDelay("2026-08-01T12:00:05Z", now)).toBe(5_250);
    expect(sessionRefreshDelay("2026-08-01T11:59:00Z", now)).toBe(1_000);
    expect(sessionRefreshDelay("2126-08-01T12:00:00Z", now)).toBe(2_147_483_647);
  });
});

describe("normalizeControlPlaneUrl", () => {
  it("uses the local control plane by default and removes trailing slashes", () => {
    expect(normalizeControlPlaneUrl(undefined)).toBe("http://localhost:8000");
    expect(normalizeControlPlaneUrl(" https://control.example.test/// ")).toBe(
      "https://control.example.test",
    );
  });
});

describe("cookieValue", () => {
  it("reads the exact named cookie and decodes its value", () => {
    expect(
      cookieValue(
        "other=ignore; __Host-mathews-csrf=token%2Fvalue%3D; session=secret",
        "__Host-mathews-csrf",
      ),
    ).toBe("token/value=");
    expect(cookieValue("__Host-mathews-csrf-extra=nope", "__Host-mathews-csrf")).toBeUndefined();
  });
});
