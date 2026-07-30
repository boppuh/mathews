import {
  type AuthSession,
  type AuthSnapshot,
  type AuthStatus,
  BOOTSTRAP_PASSWORD_POLICY_MESSAGE,
  cookieValue,
  normalizeControlPlaneUrl,
  parseAuthSession,
  parseAuthStatus,
} from "./auth";

const CSRF_COOKIE_NAME = "__Host-mathews-csrf";
const controlPlaneUrl = normalizeControlPlaneUrl(process.env.NEXT_PUBLIC_CONTROL_PLANE_URL);

export class AuthRequestError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "AuthRequestError";
  }
}

async function request(path: string, init: RequestInit, fallbackError: string): Promise<Response> {
  const response = await fetch(`${controlPlaneUrl}${path}`, {
    ...init,
    credentials: "include",
    headers: {
      Accept: "application/json",
      ...init.headers,
    },
  });

  if (!response.ok) {
    throw new AuthRequestError(fallbackError, response.status);
  }

  return response;
}

function csrfHeaders(): HeadersInit {
  const token = cookieValue(document.cookie, CSRF_COOKIE_NAME);
  if (!token) {
    throw new AuthRequestError("The security token is missing. Refresh the page and try again.", 0);
  }

  return {
    "Content-Type": "application/json",
    "X-CSRF-Token": token,
  };
}

export const authClient = {
  async status(signal?: AbortSignal): Promise<AuthStatus> {
    const response = await request(
      "/api/auth/status",
      { method: "GET", signal },
      "Unable to check the workspace authentication status.",
    );
    return parseAuthStatus(await response.json());
  },

  async session(signal?: AbortSignal): Promise<AuthSession> {
    const response = await request(
      "/api/auth/session",
      { method: "GET", signal },
      "Unable to check the current session.",
    );
    return parseAuthSession(await response.json());
  },

  async bootstrap(bootstrapToken: string, password: string): Promise<void> {
    try {
      await request(
        "/api/auth/bootstrap",
        {
          method: "POST",
          headers: csrfHeaders(),
          body: JSON.stringify({ bootstrap_token: bootstrapToken, password }),
        },
        "The bootstrap token or password was not accepted.",
      );
    } catch (error) {
      if (error instanceof AuthRequestError && error.status === 422) {
        throw new AuthRequestError(BOOTSTRAP_PASSWORD_POLICY_MESSAGE, error.status);
      }
      throw error;
    }
  },

  async login(password: string): Promise<void> {
    await request(
      "/api/auth/login",
      {
        method: "POST",
        headers: csrfHeaders(),
        body: JSON.stringify({ password }),
      },
      "The password was not accepted.",
    );
  },

  async logout(): Promise<void> {
    await request(
      "/api/auth/logout",
      {
        method: "POST",
        headers: csrfHeaders(),
      },
      "Unable to sign out.",
    );
  },

  async reauthenticate(password: string): Promise<void> {
    await request(
      "/api/auth/reauthenticate",
      {
        method: "POST",
        headers: csrfHeaders(),
        body: JSON.stringify({ password }),
      },
      "The password was not accepted.",
    );
  },
};

export function isUnauthenticated(error: unknown): boolean {
  return error instanceof AuthRequestError && error.status === 401;
}

export type SessionStatusClient = Pick<typeof authClient, "session" | "status">;

export async function loadAuthSnapshot(
  signal?: AbortSignal,
  client: SessionStatusClient = authClient,
): Promise<AuthSnapshot> {
  try {
    const session = await client.session(signal);
    return {
      status: { bootstrap_required: false, bootstrap_available: false },
      session,
    };
  } catch (error) {
    if (!isUnauthenticated(error)) {
      throw error;
    }
  }

  const status = await client.status(signal);
  return { status, session: null };
}

export class LatestAuthSnapshotLoader {
  private generation = 0;

  invalidate(): void {
    this.generation += 1;
  }

  async load(
    signal?: AbortSignal,
    client: SessionStatusClient = authClient,
  ): Promise<AuthSnapshot | undefined> {
    const requestGeneration = ++this.generation;
    try {
      const snapshot = await loadAuthSnapshot(signal, client);
      return requestGeneration === this.generation ? snapshot : undefined;
    } catch (error) {
      if (requestGeneration !== this.generation) {
        return undefined;
      }
      throw error;
    }
  }
}

type LogoutClient = Pick<typeof authClient, "logout">;

export async function logoutAndRefresh(
  refresh: () => Promise<AuthSnapshot | null>,
  client: LogoutClient = authClient,
): Promise<{ snapshot: AuthSnapshot | null; error: unknown | null }> {
  let error: unknown | null = null;
  try {
    await client.logout();
  } catch (logoutError) {
    if (!isUnauthenticated(logoutError)) {
      error = logoutError;
    }
  }

  const snapshot = await refresh();
  return { snapshot, error };
}
