"use client";

import { TASK_STATES, type TaskCockpitResponse, type TaskEventKind } from "@mathews/contracts";
import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";

import { stageLabel } from "../../../lib/stages";
import {
  LatestTaskDetailLoader,
  TaskRequestError,
  taskEventStreamUrl,
} from "../../../lib/task-client";
import { parseTaskEvent, shortRevision } from "../../../lib/tasks";
import { EvidenceWorkbench } from "./evidence-workbench";
import { TaskControls } from "./task-controls";

type CockpitState =
  | { status: "loading" }
  | { status: "failed"; message: string }
  | { status: "ready"; cockpit: TaskCockpitResponse };

type LiveStatus = "connecting" | "live" | "reconnecting" | "unavailable";

const eventKindLabels: Record<TaskEventKind, string> = {
  CREATED: "Created",
  STATE_TRANSITION: "State change",
  APPROVAL: "Approval",
  ACTIVITY: "Activity",
};

function formatTimestamp(timestamp: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(timestamp));
}

function failureMessage(error: unknown): string {
  if (error instanceof TaskRequestError) {
    return error.message;
  }
  if (error instanceof Error && error.message.startsWith("The control plane returned")) {
    return error.message;
  }
  return "Unable to load the task cockpit.";
}

export function TaskCockpit({ taskId }: { taskId: string }) {
  const [state, setState] = useState<CockpitState>({ status: "loading" });
  const [liveStatus, setLiveStatus] = useState<LiveStatus>("connecting");
  const loadedEventCursor = useRef({ taskId: "", sequence: 0 });
  const detailLoader = useRef<LatestTaskDetailLoader | null>(null);
  if (detailLoader.current === null) {
    detailLoader.current = new LatestTaskDetailLoader();
  }

  const loadCockpit = useCallback(
    async (signal?: AbortSignal, background = false) => {
      if (!background) {
        setState({ status: "loading" });
      }
      try {
        const cockpit = await detailLoader.current?.load(taskId, signal);
        if (!cockpit) {
          return false;
        }
        setState({ status: "ready", cockpit });
        return true;
      } catch (error) {
        if (error instanceof Error && error.name === "AbortError") {
          return false;
        }
        if (background) {
          setLiveStatus("reconnecting");
          return false;
        }
        setState({ status: "failed", message: failureMessage(error) });
        return false;
      }
    },
    [taskId],
  );

  useEffect(() => {
    const controller = new AbortController();
    void loadCockpit(controller.signal);
    return () => {
      controller.abort();
      detailLoader.current?.invalidate();
    };
  }, [loadCockpit]);

  const readyTaskId = state.status === "ready" ? state.cockpit.task.id : null;
  const latestLoadedSequence =
    state.status === "ready" ? (state.cockpit.events.at(-1)?.sequence ?? 0) : 0;

  useEffect(() => {
    if (readyTaskId !== taskId) {
      return;
    }
    if (loadedEventCursor.current.taskId !== taskId) {
      loadedEventCursor.current = {
        taskId,
        sequence: latestLoadedSequence,
      };
      return;
    }
    loadedEventCursor.current.sequence = Math.max(
      loadedEventCursor.current.sequence,
      latestLoadedSequence,
    );
  }, [latestLoadedSequence, readyTaskId, taskId]);

  useEffect(() => {
    if (readyTaskId !== taskId) {
      return;
    }

    const refreshController = new AbortController();
    let refreshTimer: number | undefined;
    let highestObservedSequence =
      loadedEventCursor.current.taskId === taskId ? loadedEventCursor.current.sequence : 0;
    const eventSource = new EventSource(taskEventStreamUrl(taskId), {
      withCredentials: true,
    });
    setLiveStatus("connecting");

    eventSource.onopen = () => setLiveStatus("live");
    eventSource.onerror = () =>
      setLiveStatus(eventSource.readyState === EventSource.CLOSED ? "unavailable" : "reconnecting");
    const refreshFromStream = async () => {
      const refreshed = await loadCockpit(refreshController.signal, true);
      if (!refreshed && !refreshController.signal.aborted) {
        refreshTimer = window.setTimeout(() => {
          void refreshFromStream();
        }, 1_000);
      }
    };
    const handleTaskEvent = (message: MessageEvent<string>) => {
      try {
        const event = parseTaskEvent(JSON.parse(message.data));
        if (event.sequence <= highestObservedSequence) {
          return;
        }
        highestObservedSequence = event.sequence;
      } catch {
        eventSource.close();
        setLiveStatus("unavailable");
        return;
      }

      if (refreshTimer !== undefined) {
        window.clearTimeout(refreshTimer);
      }
      refreshTimer = window.setTimeout(() => {
        void refreshFromStream();
      }, 50);
    };
    eventSource.addEventListener("task-event", handleTaskEvent as EventListener);

    return () => {
      eventSource.removeEventListener("task-event", handleTaskEvent as EventListener);
      eventSource.close();
      refreshController.abort();
      if (refreshTimer !== undefined) {
        window.clearTimeout(refreshTimer);
      }
    };
  }, [loadCockpit, readyTaskId, taskId]);

  useEffect(() => {
    if (readyTaskId !== taskId) {
      return;
    }
    const controller = new AbortController();
    const refreshInterval = window.setInterval(() => {
      void loadCockpit(controller.signal, true);
    }, 30_000);
    return () => {
      window.clearInterval(refreshInterval);
      controller.abort();
    };
  }, [loadCockpit, readyTaskId, taskId]);

  if (state.status === "loading") {
    return (
      <main className="task-cockpit cockpit-centered" aria-busy="true">
        <div className="task-list-status" role="status">
          <span className="status-dot" aria-hidden="true" />
          Loading durable task history…
        </div>
      </main>
    );
  }

  if (state.status === "failed") {
    return (
      <main className="task-cockpit cockpit-centered">
        <Link href="/" className="back-link">
          ← Work
        </Link>
        <section className="cockpit-load-error" aria-labelledby="cockpit-error-heading">
          <p className="eyebrow">Task cockpit</p>
          <h1 id="cockpit-error-heading">Cockpit unavailable</h1>
          <p className="task-error" role="alert">
            {state.message}
          </p>
          <button type="button" onClick={() => void loadCockpit()}>
            Try again
          </button>
        </section>
      </main>
    );
  }

  const {
    task,
    state_context: stateContext,
    events,
    acceptance_criteria: acceptanceCriteria,
    evidence,
    approvals,
    github,
  } = state.cockpit;
  const visitedStates = new Set(
    events.flatMap((event) => [event.from_state, event.to_state]).filter(Boolean),
  );
  visitedStates.add(task.state);

  return (
    <main className="task-cockpit">
      <div className="cockpit-topline">
        <Link href="/" className="back-link">
          ← Work
        </Link>
        <nav className="cockpit-nav" aria-label="Task cockpit sections">
          <Link href="/inbox">Decision inbox</Link>
          <a href="#timeline">Timeline</a>
          <a href="#controls">Controls</a>
          <a href="#github">GitHub</a>
          <a href="#activity">Activity</a>
          <a href="#acceptance">Criteria</a>
          <a href="#evidence">Evidence</a>
          <a href="#decisions">Decisions</a>
        </nav>
      </div>

      <header className="cockpit-header">
        <div>
          <p className="eyebrow">Task cockpit · {task.repository}</p>
          <h1>{task.summary}</h1>
          <p className="cockpit-revision">
            Base <code>{shortRevision(task.base_revision)}</code> · Task{" "}
            <code>{task.id.slice(0, 8)}</code>
          </p>
        </div>
        <div className="cockpit-header-status">
          <span className={`state-badge state-${task.state.toLowerCase()}`}>
            {stageLabel(task.state)}
          </span>
          <span className={`cockpit-live-status live-${liveStatus}`} role="status">
            <i aria-hidden="true" />
            {liveStatus === "live"
              ? "Live"
              : liveStatus === "connecting"
                ? "Connecting"
                : liveStatus === "reconnecting"
                  ? "Reconnecting"
                  : "Updates unavailable"}
          </span>
        </div>
      </header>

      <section
        className={`state-context context-${stateContext.kind.toLowerCase()}`}
        aria-labelledby="state-context-heading"
      >
        <div>
          <p className="eyebrow">Current workflow boundary</p>
          <h2 id="state-context-heading">{stateContext.label}</h2>
        </div>
        <p>{stateContext.detail}</p>
      </section>

      <TaskControls task={task} onRefresh={() => loadCockpit(undefined, true)} />

      <section id="github" className="github-status-panel" aria-labelledby="github-heading">
        <div className="cockpit-section-heading">
          <div>
            <p className="eyebrow">Exact pull-request head</p>
            <h2 id="github-heading">GitHub checks & review</h2>
          </div>
          {github.linked ? (
            <span className="github-pr-number">PR #{github.pull_request_number}</span>
          ) : null}
        </div>
        {github.linked ? (
          <>
            <div className="github-status-grid">
              <div>
                <span>Continuous integration</span>
                <strong className={`github-state github-state-${github.ci_status.toLowerCase()}`}>
                  {github.ci_status.replaceAll("_", " ")}
                </strong>
                <small>
                  {github.checks_passed} of {github.checks_total}{" "}
                  {github.checks_total === 1 ? "check" : "checks"} passing
                </small>
              </div>
              <div>
                <span>Review</span>
                <strong
                  className={`github-state github-state-${github.review_status.toLowerCase()}`}
                >
                  {github.review_status.replaceAll("_", " ")}
                </strong>
                <small>
                  {github.blocking_reviews} blocking · {github.review_comments} open{" "}
                  {github.review_comments === 1 ? "comment" : "comments"}
                </small>
              </div>
            </div>
            <p className="github-binding">
              <code>{github.task_branch}</code> at{" "}
              <code>{shortRevision(github.head_sha ?? "")}</code>
              {github.last_updated_at ? (
                <> · Updated {formatTimestamp(github.last_updated_at)}</>
              ) : null}
            </p>
          </>
        ) : (
          <p className="cockpit-empty">No exact pull-request binding has been recorded yet.</p>
        )}
      </section>

      <section id="timeline" className="cockpit-section" aria-labelledby="timeline-heading">
        <div className="cockpit-section-heading">
          <div>
            <p className="eyebrow">Persistent state</p>
            <h2 id="timeline-heading">Timeline</h2>
          </div>
          <p>
            {events.length} durable {events.length === 1 ? "event" : "events"}
          </p>
        </div>
        <ol className="cockpit-timeline">
          {TASK_STATES.map((stage) => {
            const status =
              stage === task.state ? "current" : visitedStates.has(stage) ? "visited" : "pending";
            return (
              <li
                className={`timeline-${status}`}
                key={stage}
                aria-current={status === "current" ? "step" : undefined}
              >
                <span aria-hidden="true" />
                <div>
                  <strong>{stageLabel(stage)}</strong>
                  <small>{status}</small>
                </div>
              </li>
            );
          })}
        </ol>
      </section>

      <div className="cockpit-grid">
        <section id="activity" className="cockpit-panel" aria-labelledby="activity-heading">
          <div className="cockpit-section-heading">
            <div>
              <p className="eyebrow">Database history</p>
              <h2 id="activity-heading">Activity</h2>
            </div>
          </div>
          {events.length === 0 ? (
            <p className="cockpit-empty">No durable activity has been recorded.</p>
          ) : (
            <ol className="activity-feed">
              {events.map((event) => (
                <li key={event.id}>
                  <div className="activity-marker" aria-hidden="true" />
                  <div>
                    <div className="activity-meta">
                      <span>{eventKindLabels[event.kind]}</span>
                      <time dateTime={event.occurred_at}>{formatTimestamp(event.occurred_at)}</time>
                    </div>
                    <p>{event.summary}</p>
                    {event.evidence_count > 0 ? (
                      <small>
                        {event.evidence_count} linked evidence{" "}
                        {event.evidence_count === 1 ? "record" : "records"}
                      </small>
                    ) : null}
                  </div>
                </li>
              ))}
            </ol>
          )}
        </section>

        <aside className="cockpit-sidebar">
          <section id="decisions" className="cockpit-panel" aria-labelledby="decisions-heading">
            <div className="cockpit-section-heading">
              <div>
                <p className="eyebrow">Human control</p>
                <h2 id="decisions-heading">Approvals & blockers</h2>
              </div>
              <span className="decision-count">
                {task.blockers.reduce((total, blocker) => total + blocker.count, 0)}
              </span>
            </div>
            {task.blockers.length === 0 ? (
              <p className="cockpit-empty">No active blockers.</p>
            ) : (
              <ul className="cockpit-blockers">
                {task.blockers.map((blocker) => (
                  <li key={blocker.code}>
                    <strong>{blocker.label}</strong>
                    <span>{blocker.count}</span>
                  </li>
                ))}
              </ul>
            )}
            {approvals.length > 0 ? (
              <ul className="approval-list">
                {approvals.map((approval) => (
                  <li key={approval.id}>
                    <div>
                      <strong>{approval.type_label}</strong>
                      <small>Requested during {stageLabel(approval.requesting_state)}</small>
                    </div>
                    <span className={`approval-status approval-${approval.status.toLowerCase()}`}>
                      {approval.status}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="approval-clear">No human decision requests recorded.</p>
            )}
          </section>
        </aside>
      </div>
      <EvidenceWorkbench
        criteria={acceptanceCriteria}
        evidence={evidence}
        onRefresh={() => loadCockpit(undefined, true)}
      />
    </main>
  );
}
