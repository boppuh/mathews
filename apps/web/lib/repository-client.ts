import type { RepositoryConfigurationWriteRequest, RepositoryProjection } from "@mathews/contracts";

import { cookieValue, normalizeControlPlaneUrl } from "./auth";
import { parseRepositoryProjection } from "./repositories";

const CSRF_COOKIE_NAME = "__Host-mathews-csrf";
const controlPlaneUrl = normalizeControlPlaneUrl(process.env.NEXT_PUBLIC_CONTROL_PLANE_URL);

export class RepositoryRequestError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "RepositoryRequestError";
  }
}

function csrfHeaders(): HeadersInit {
  const token = cookieValue(document.cookie, CSRF_COOKIE_NAME);
  if (!token) {
    throw new RepositoryRequestError(
      "The security token is missing. Refresh the page and try again.",
      0,
    );
  }
  return { "Content-Type": "application/json", "X-CSRF-Token": token };
}

async function request(
  path: string,
  init: RequestInit,
  fallback: string,
): Promise<RepositoryProjection> {
  const response = await fetch(`${controlPlaneUrl}${path}`, {
    ...init,
    credentials: "include",
    headers: { Accept: "application/json", ...init.headers },
  });
  if (!response.ok) {
    const messages: Record<number, string> = {
      401: "Your session expired. Refresh the page and sign in again.",
      403: "Confirm this protected change with your password.",
      409: "The configuration changed. Reload it and try again.",
      413: "The configuration is too large to save.",
      422: "The configuration is invalid. Review every section before saving.",
      503: "The local host is unavailable, so preflight could not run.",
    };
    throw new RepositoryRequestError(messages[response.status] ?? fallback, response.status);
  }
  return parseRepositoryProjection(await response.json());
}

export const repositoryClient = {
  load(signal?: AbortSignal): Promise<RepositoryProjection> {
    return request(
      "/api/repository",
      { method: "GET", signal },
      "Unable to load repository readiness.",
    );
  },

  async save(body: RepositoryConfigurationWriteRequest): Promise<RepositoryProjection> {
    return request(
      "/api/repository/versions",
      { method: "POST", headers: csrfHeaders(), body: JSON.stringify(body) },
      "Unable to save the repository configuration.",
    );
  },

  async preflight(): Promise<RepositoryProjection> {
    return request(
      "/api/repository/preflights",
      { method: "POST", headers: csrfHeaders(), body: "{}" },
      "Unable to run repository preflight.",
    );
  },
};
