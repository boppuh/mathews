"use client";

import type { CreateTaskRequest, TaskSummary } from "@mathews/contracts";
import Link from "next/link";
import type { FormEvent } from "react";
import { useCallback, useEffect, useRef, useState } from "react";

import { stageLabel } from "../lib/stages";
import { LatestTaskListLoader, TaskRequestError, taskClient } from "../lib/task-client";
import { mergeLoadedTasks, shortRevision } from "../lib/tasks";

type TaskListState =
  | { status: "loading" }
  | { status: "failed"; message: string }
  | { status: "ready"; tasks: TaskSummary[] };

function messageFrom(error: unknown, fallback: string): string {
  if (error instanceof TaskRequestError) {
    return error.message;
  }
  if (error instanceof Error && error.message.startsWith("The control plane returned")) {
    return error.message;
  }
  return fallback;
}

function formatActivity(timestamp: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(timestamp));
}

export function TaskWorkspace() {
  const [listState, setListState] = useState<TaskListState>({ status: "loading" });
  const [repository, setRepository] = useState("");
  const [baseRevision, setBaseRevision] = useState("");
  const [request, setRequest] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const taskListLoader = useRef<LatestTaskListLoader | null>(null);
  if (taskListLoader.current === null) {
    taskListLoader.current = new LatestTaskListLoader();
  }

  const loadTasks = useCallback(async (signal?: AbortSignal) => {
    setListState((current) => (current.status === "ready" ? current : { status: "loading" }));
    try {
      const result = await taskListLoader.current?.load(signal);
      if (!result) {
        return;
      }
      setListState((current) => {
        if (current.status !== "ready") {
          return { status: "ready", tasks: result.tasks };
        }
        return {
          status: "ready",
          tasks: mergeLoadedTasks(result.tasks, current.tasks),
        };
      });
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        return;
      }
      setListState((current) =>
        current.status === "ready"
          ? current
          : {
              status: "failed",
              message: messageFrom(error, "Unable to load tasks."),
            },
      );
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void loadTasks(controller.signal);
    return () => controller.abort();
  }, [loadTasks]);

  async function handleCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const body: CreateTaskRequest = {
      repository: repository.trim(),
      base_revision: baseRevision.trim(),
      request,
    };
    if (!body.repository || !body.base_revision || !body.request.trim()) {
      return;
    }

    setCreating(true);
    setCreateError(null);
    try {
      const created = await taskClient.create(body);
      setListState((current) => ({
        status: "ready",
        tasks:
          current.status === "ready"
            ? [created, ...current.tasks.filter((task) => task.id !== created.id)]
            : [created],
      }));
      setRequest("");
    } catch (error) {
      setCreateError(messageFrom(error, "Unable to create the task."));
    } finally {
      setCreating(false);
    }
  }

  return (
    <main className="task-workspace">
      <header className="work-header">
        <div>
          <p className="eyebrow">Local delivery queue</p>
          <h1>Work</h1>
          <p className="lede">
            Turn a plain-language request into durable, revision-bound work with visible state and
            blockers.
          </p>
        </div>
        <div className="work-count" aria-live="polite">
          <strong>{listState.status === "ready" ? listState.tasks.length : "—"}</strong>
          <span>tasks</span>
        </div>
      </header>

      <div className="work-layout">
        <section className="task-create-panel" aria-labelledby="create-task-heading">
          <div className="panel-heading">
            <p className="eyebrow">New task</p>
            <h2 id="create-task-heading">What should Mathews build?</h2>
          </div>
          <form className="task-create-form" onSubmit={handleCreate}>
            <label htmlFor="task-request">Request</label>
            <textarea
              id="task-request"
              name="task-request"
              value={request}
              onChange={(event) => setRequest(event.currentTarget.value)}
              placeholder="Describe the outcome, constraints, and what success looks like."
              maxLength={20_000}
              rows={7}
              required
            />
            <div className="task-source-grid">
              <div>
                <label htmlFor="task-repository">Repository</label>
                <input
                  id="task-repository"
                  name="task-repository"
                  value={repository}
                  onChange={(event) => setRepository(event.currentTarget.value)}
                  placeholder="owner/repository"
                  maxLength={140}
                  autoCapitalize="none"
                  required
                />
              </div>
              <div>
                <label htmlFor="task-base-revision">Exact base SHA</label>
                <input
                  id="task-base-revision"
                  name="task-base-revision"
                  value={baseRevision}
                  onChange={(event) => setBaseRevision(event.currentTarget.value)}
                  placeholder="40- or 64-character Git object ID"
                  pattern="[0-9a-fA-F]{40}([0-9a-fA-F]{24})?"
                  spellCheck={false}
                  required
                />
              </div>
            </div>
            {createError ? (
              <p className="task-error" role="alert">
                {createError}
              </p>
            ) : null}
            <div className="task-create-actions">
              <p>Request content is captured as access-controlled evidence.</p>
              <button type="submit" disabled={creating}>
                {creating ? "Creating…" : "Create task"}
              </button>
            </div>
          </form>
        </section>

        <section className="task-list-panel" aria-labelledby="task-list-heading">
          <div className="panel-heading task-list-heading">
            <div>
              <p className="eyebrow">Task list</p>
              <h2 id="task-list-heading">Recent work</h2>
            </div>
            {listState.status === "failed" ? (
              <button type="button" onClick={() => void loadTasks()}>
                Try again
              </button>
            ) : null}
          </div>

          {listState.status === "loading" ? (
            <div className="task-list-status" role="status">
              <span className="status-dot" aria-hidden="true" />
              Loading tasks…
            </div>
          ) : null}
          {listState.status === "failed" ? (
            <p className="task-error" role="alert">
              {listState.message}
            </p>
          ) : null}
          {listState.status === "ready" && listState.tasks.length === 0 ? (
            <div className="empty-tasks">
              <p className="eyebrow">Queue clear</p>
              <h3>Create the first task.</h3>
              <p>Your durable work queue will appear here.</p>
            </div>
          ) : null}
          {listState.status === "ready" && listState.tasks.length > 0 ? (
            <ol className="task-list">
              {listState.tasks.map((task) => (
                <li key={task.id}>
                  <Link href={task.cockpit_path} className="task-card">
                    <div className="task-card-topline">
                      <span className={`state-badge state-${task.state.toLowerCase()}`}>
                        {stageLabel(task.state)}
                      </span>
                      <time dateTime={task.last_activity_at}>
                        {formatActivity(task.last_activity_at)}
                      </time>
                    </div>
                    <h3>{task.summary}</h3>
                    <dl className="task-metadata">
                      <div>
                        <dt>Repository</dt>
                        <dd>{task.repository}</dd>
                      </div>
                      <div>
                        <dt>Base</dt>
                        <dd>
                          <code>{shortRevision(task.base_revision)}</code>
                        </dd>
                      </div>
                    </dl>
                    <div className="task-card-footer">
                      <div className="blocker-list">
                        {task.blockers.length === 0 ? (
                          <span className="no-blockers">No blockers</span>
                        ) : (
                          task.blockers.map((blocker) => (
                            <span className="blocker-badge" key={blocker.code}>
                              {blocker.label}
                              {blocker.count > 1 ? ` · ${blocker.count}` : ""}
                            </span>
                          ))
                        )}
                      </div>
                      <span className="open-cockpit">Open cockpit →</span>
                    </div>
                  </Link>
                </li>
              ))}
            </ol>
          ) : null}
        </section>
      </div>
    </main>
  );
}
