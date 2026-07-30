import type { CreateTaskRequest, TaskListResponse, TaskSummary } from "@mathews/contracts";

import { cookieValue, normalizeControlPlaneUrl } from "./auth";
import { parseTaskList, parseTaskSummary } from "./tasks";

const CSRF_COOKIE_NAME = "__Host-mathews-csrf";
const controlPlaneUrl = normalizeControlPlaneUrl(process.env.NEXT_PUBLIC_CONTROL_PLANE_URL);

export class TaskRequestError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "TaskRequestError";
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
    const message =
      response.status === 401
        ? "Your session expired. Refresh the page and sign in again."
        : response.status === 413
          ? "The task request is too large."
          : response.status === 422
            ? "Check the repository, exact base SHA, and task request."
            : fallbackError;
    throw new TaskRequestError(message, response.status);
  }
  return response;
}

function csrfHeaders(): HeadersInit {
  const token = cookieValue(document.cookie, CSRF_COOKIE_NAME);
  if (!token) {
    throw new TaskRequestError("The security token is missing. Refresh the page and try again.", 0);
  }
  return {
    "Content-Type": "application/json",
    "X-CSRF-Token": token,
  };
}

export const taskClient = {
  async list(signal?: AbortSignal): Promise<TaskListResponse> {
    const response = await request(
      "/api/tasks",
      { method: "GET", signal },
      "Unable to load tasks.",
    );
    return parseTaskList(await response.json());
  },

  async create(body: CreateTaskRequest): Promise<TaskSummary> {
    const response = await request(
      "/api/tasks",
      {
        method: "POST",
        headers: csrfHeaders(),
        body: JSON.stringify(body),
      },
      "Unable to create the task.",
    );
    return parseTaskSummary(await response.json());
  },
};
