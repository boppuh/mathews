"use client";

import { TASK_STATES, type TaskCockpitResponse, type TaskEventKind } from "@mathews/contracts";
import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";

import { stageLabel } from "../../../lib/stages";
import { LatestTaskDetailLoader, TaskRequestError } from "../../../lib/task-client";
import { shortRevision } from "../../../lib/tasks";

type CockpitState =
  | { status: "loading" }
  | { status: "failed"; message: string }
  | { status: "ready"; cockpit: TaskCockpitResponse };

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

function evidenceLabel(value: string): string {
  return value
    .split(/[-_.]/)
    .filter(Boolean)
    .map((part) => part[0]?.toUpperCase() + part.slice(1).toLowerCase())
    .join(" ");
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
  const detailLoader = useRef<LatestTaskDetailLoader | null>(null);
  if (detailLoader.current === null) {
    detailLoader.current = new LatestTaskDetailLoader();
  }

  const loadCockpit = useCallback(
    async (signal?: AbortSignal) => {
      setState({ status: "loading" });
      try {
        const cockpit = await detailLoader.current?.load(taskId, signal);
        if (!cockpit) {
          return;
        }
        setState({ status: "ready", cockpit });
      } catch (error) {
        if (error instanceof Error && error.name === "AbortError") {
          return;
        }
        setState({ status: "failed", message: failureMessage(error) });
      }
    },
    [taskId],
  );

  useEffect(() => {
    const controller = new AbortController();
    void loadCockpit(controller.signal);
    return () => controller.abort();
  }, [loadCockpit]);

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

  const { task, state_context: stateContext, events, evidence, approvals } = state.cockpit;
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
          <a href="#timeline">Timeline</a>
          <a href="#activity">Activity</a>
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
        <span className={`state-badge state-${task.state.toLowerCase()}`}>
          {stageLabel(task.state)}
        </span>
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

          <section id="evidence" className="cockpit-panel" aria-labelledby="evidence-heading">
            <div className="cockpit-section-heading">
              <div>
                <p className="eyebrow">Verification ledger</p>
                <h2 id="evidence-heading">Evidence checklist</h2>
              </div>
              <span className="decision-count">{evidence.length}</span>
            </div>
            {evidence.length === 0 ? (
              <p className="cockpit-empty">Evidence will appear as work is verified.</p>
            ) : (
              <ul className="evidence-checklist">
                {evidence.map((record) => (
                  <li key={record.id}>
                    <span
                      className={`evidence-status evidence-${record.status.toLowerCase()}`}
                      aria-hidden="true"
                    />
                    <div>
                      <strong>{evidenceLabel(record.evidence_type)}</strong>
                      <small>
                        {record.status.toLowerCase()} · {formatTimestamp(record.captured_at)}
                      </small>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </aside>
      </div>
    </main>
  );
}
