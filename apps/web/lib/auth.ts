export type AuthSession = {
  authenticated: true;
  expires_at: string;
  reauthenticated_until: string;
};

export type AuthStatus = {
  bootstrap_required: boolean;
  bootstrap_available: boolean;
};

export type AuthSnapshot = {
  status: AuthStatus;
  session: AuthSession | null;
};

export type AuthView = "bootstrap" | "bootstrap-unavailable" | "login" | "workspace";

export const BOOTSTRAP_PASSWORD_MIN_LENGTH = 15;
export const BOOTSTRAP_PASSWORD_POLICY_MESSAGE =
  "Use at least 15 characters for the workspace password.";
export const INVALID_BOOTSTRAP_REQUEST_MESSAGE =
  "The bootstrap request was invalid. Check the fields and try again.";
export const PASSWORD_CONFIRMATION_MESSAGE = "Passwords do not match.";

const DEFAULT_CONTROL_PLANE_URL = "http://localhost:8000";
const MINIMUM_SESSION_REFRESH_DELAY_MS = 1_000;
const MAXIMUM_SESSION_REFRESH_DELAY_MS = 2_147_483_647;
const SESSION_EXPIRY_SKEW_MS = 250;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function parseAuthSession(value: unknown): AuthSession {
  if (
    !isRecord(value) ||
    value.authenticated !== true ||
    typeof value.expires_at !== "string" ||
    !Number.isFinite(Date.parse(value.expires_at)) ||
    typeof value.reauthenticated_until !== "string" ||
    !Number.isFinite(Date.parse(value.reauthenticated_until))
  ) {
    throw new Error("The control plane returned an invalid session response.");
  }

  return {
    authenticated: true,
    expires_at: value.expires_at,
    reauthenticated_until: value.reauthenticated_until,
  };
}

export function parseAuthStatus(value: unknown): AuthStatus {
  if (
    !isRecord(value) ||
    typeof value.bootstrap_required !== "boolean" ||
    typeof value.bootstrap_available !== "boolean"
  ) {
    throw new Error("The control plane returned an invalid authentication status.");
  }

  return {
    bootstrap_required: value.bootstrap_required,
    bootstrap_available: value.bootstrap_available,
  };
}

export function authViewFor(snapshot: AuthSnapshot): AuthView {
  if (snapshot.status.bootstrap_required) {
    return snapshot.status.bootstrap_available ? "bootstrap" : "bootstrap-unavailable";
  }

  return snapshot.session === null ? "login" : "workspace";
}

export function meetsBootstrapPasswordMinimum(password: string): boolean {
  return Array.from(password).length >= BOOTSTRAP_PASSWORD_MIN_LENGTH;
}

export function bootstrapPasswordError(password: string, confirmation: string): string | null {
  if (!meetsBootstrapPasswordMinimum(password)) {
    return BOOTSTRAP_PASSWORD_POLICY_MESSAGE;
  }
  return password === confirmation ? null : PASSWORD_CONFIRMATION_MESSAGE;
}

export function sessionRefreshDelay(expiresAt: string, now = Date.now()): number {
  const remaining = Date.parse(expiresAt) - now + SESSION_EXPIRY_SKEW_MS;
  return Math.min(
    Math.max(remaining, MINIMUM_SESSION_REFRESH_DELAY_MS),
    MAXIMUM_SESSION_REFRESH_DELAY_MS,
  );
}

export function normalizeControlPlaneUrl(value: string | undefined): string {
  const candidate = value?.trim() || DEFAULT_CONTROL_PLANE_URL;
  return candidate.replace(/\/+$/, "");
}

export function cookieValue(cookieHeader: string, name: string): string | undefined {
  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator === -1 || part.slice(0, separator).trim() !== name) {
      continue;
    }

    const encodedValue = part.slice(separator + 1).trim();
    try {
      return decodeURIComponent(encodedValue);
    } catch {
      return encodedValue;
    }
  }

  return undefined;
}
