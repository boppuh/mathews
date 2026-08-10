"use client";

import {
  TASK_STEERING_IMPACTS,
  type TaskState,
  type TaskSteeringImpact,
  type TaskSummary,
} from "@mathews/contracts";
import { type FormEvent, useRef, useState } from "react";

import { AuthRequestError, authClient } from "../../../lib/auth-client";
import { TaskRequestError, taskClient } from "../../../lib/task-client";

const impactLabels: Record<TaskSteeringImpact, string> = {
  ACCEPTANCE_CRITERIA: "Acceptance criteria",
  PATHS: "Files or paths",
  RISK: "Risk",
  TESTS: "Tests",
};

const terminalStates = new Set<TaskState>(["HANDED_OFF", "FAILED", "CANCELLED"]);

interface CommandIdentity {
  id: string;
  expectedState: TaskState;
}

function controlError(error: unknown, fallback: string): string {
  return error instanceof TaskRequestError || error instanceof AuthRequestError
    ? error.message
    : fallback;
}

export function TaskControls({
  task,
  onRefresh,
}: {
  task: TaskSummary;
  onRefresh: () => Promise<boolean>;
}) {
  const [message, setMessage] = useState("");
  const [impacts, setImpacts] = useState<TaskSteeringImpact[]>([]);
  const [steeringPending, setSteeringPending] = useState(false);
  const [steeringNotice, setSteeringNotice] = useState("");
  const [steeringError, setSteeringError] = useState("");
  const [cancelConfirming, setCancelConfirming] = useState(false);
  const [cancelPending, setCancelPending] = useState(false);
  const [cancelError, setCancelError] = useState("");
  const [reauthenticationRequired, setReauthenticationRequired] = useState(false);
  const [password, setPassword] = useState("");
  const steeringCommand = useRef<CommandIdentity | null>(null);
  const cancellationCommand = useRef<CommandIdentity | null>(null);
  const disabled = terminalStates.has(task.state);

  const resetSteeringIdentity = () => {
    steeringCommand.current = null;
    setSteeringNotice("");
    setSteeringError("");
  };

  async function submitSteering(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const normalizedMessage = message.trim();
    if (!normalizedMessage || steeringPending || disabled) return;
    const command = steeringCommand.current ?? {
      id: crypto.randomUUID(),
      expectedState: task.state,
    };
    steeringCommand.current = command;
    setSteeringPending(true);
    setSteeringError("");
    setSteeringNotice("");
    try {
      const result = await taskClient.steer(task.id, {
        steering_id: command.id,
        expected_state: command.expectedState,
        message: normalizedMessage,
        impacts,
      });
      setMessage("");
      setImpacts([]);
      steeringCommand.current = null;
      setSteeringNotice(
        result.classification === "CLARIFICATION"
          ? "Clarification recorded without changing scope."
          : "Scope change recorded. Active work was fenced and the task returned to briefing.",
      );
      await onRefresh();
    } catch (error) {
      setSteeringError(controlError(error, "Unable to record this steering message."));
      if (error instanceof TaskRequestError && [404, 409].includes(error.status)) {
        steeringCommand.current = null;
        await onRefresh();
      }
    } finally {
      setSteeringPending(false);
    }
  }

  async function cancelTask(afterReauthentication = false) {
    if (cancelPending || disabled) return;
    const command = cancellationCommand.current ?? {
      id: crypto.randomUUID(),
      expectedState: task.state,
    };
    cancellationCommand.current = command;
    setCancelPending(true);
    setCancelError("");
    try {
      await taskClient.cancel(task.id, {
        cancellation_id: command.id,
        expected_state: command.expectedState,
        reason_code: "USER_REQUEST",
      });
      cancellationCommand.current = null;
      setCancelConfirming(false);
      setReauthenticationRequired(false);
      setPassword("");
      await onRefresh();
    } catch (error) {
      if (!afterReauthentication && error instanceof TaskRequestError && error.status === 403) {
        setReauthenticationRequired(true);
      } else {
        setCancelError(controlError(error, "Unable to cancel this task."));
        if (error instanceof TaskRequestError && [404, 409].includes(error.status)) {
          cancellationCommand.current = null;
          await onRefresh();
        }
      }
    } finally {
      setCancelPending(false);
    }
  }

  async function reauthenticateAndCancel(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!password || cancelPending) return;
    setCancelPending(true);
    setCancelError("");
    try {
      await authClient.reauthenticate(password);
      setPassword("");
      setReauthenticationRequired(false);
      setCancelPending(false);
      await cancelTask(true);
    } catch (error) {
      setPassword("");
      setCancelError(controlError(error, "Unable to verify your password."));
      setCancelPending(false);
    }
  }

  return (
    <section
      id="controls"
      className="cockpit-section task-controls"
      aria-labelledby="controls-heading"
    >
      <div className="cockpit-section-heading">
        <div>
          <p className="eyebrow">Human control</p>
          <h2 id="controls-heading">Steer or stop</h2>
        </div>
        <p>Every action is durable and audited.</p>
      </div>
      <div className="task-control-grid">
        <form className="steering-form" onSubmit={submitSteering}>
          <div>
            <h3>Send guidance</h3>
            <p>
              Leave all scope flags clear for a cosmetic clarification. Selecting any flag fences
              active work and requires a new brief and validation contract.
            </p>
          </div>
          <label htmlFor="task-steering-message">Message</label>
          <textarea
            id="task-steering-message"
            rows={4}
            maxLength={2_000}
            value={message}
            disabled={disabled || steeringPending}
            onChange={(event) => {
              setMessage(event.currentTarget.value);
              resetSteeringIdentity();
            }}
            placeholder="Clarify the desired behavior or describe a scoped change…"
            required
          />
          <fieldset disabled={disabled || steeringPending}>
            <legend>What changes?</legend>
            {TASK_STEERING_IMPACTS.map((impact) => (
              <label key={impact}>
                <input
                  type="checkbox"
                  checked={impacts.includes(impact)}
                  onChange={(event) => {
                    setImpacts((current) =>
                      event.currentTarget.checked
                        ? [...current, impact]
                        : current.filter((value) => value !== impact),
                    );
                    resetSteeringIdentity();
                  }}
                />
                <span>{impactLabels[impact]}</span>
              </label>
            ))}
          </fieldset>
          {steeringError ? (
            <p className="task-error" role="alert">
              {steeringError}
            </p>
          ) : null}
          {steeringNotice ? (
            <p className="task-control-notice" role="status">
              {steeringNotice}
            </p>
          ) : null}
          <button type="submit" disabled={disabled || steeringPending || !message.trim()}>
            {steeringPending
              ? "Recording…"
              : impacts.length > 0
                ? "Record scope change"
                : "Send clarification"}
          </button>
        </form>

        <div className="cancellation-control">
          <div>
            <h3>Cancel automation</h3>
            <p>
              Cancellation is terminal. Active leases and tool access are revoked, and late worker
              results cannot restart the task.
            </p>
          </div>
          {disabled ? (
            <p className="task-control-muted">This task no longer accepts active controls.</p>
          ) : !cancelConfirming ? (
            <button type="button" className="danger" onClick={() => setCancelConfirming(true)}>
              Cancel task…
            </button>
          ) : reauthenticationRequired ? (
            <form className="task-cancel-reauthentication" onSubmit={reauthenticateAndCancel}>
              <label htmlFor="task-cancel-password">Re-enter your password to confirm</label>
              <input
                id="task-cancel-password"
                type="password"
                autoComplete="current-password"
                value={password}
                disabled={cancelPending}
                onChange={(event) => setPassword(event.currentTarget.value)}
                required
              />
              <button type="submit" className="danger" disabled={cancelPending || !password}>
                {cancelPending ? "Cancelling…" : "Verify and cancel"}
              </button>
              <button
                type="button"
                className="secondary"
                disabled={cancelPending}
                onClick={() => {
                  cancellationCommand.current = null;
                  setCancelConfirming(false);
                  setReauthenticationRequired(false);
                  setPassword("");
                  setCancelError("");
                }}
              >
                Keep task active
              </button>
            </form>
          ) : (
            <div className="task-cancel-confirmation" role="alert">
              <strong>Cancel this task permanently?</strong>
              <p>The task cannot return to an active state after this action.</p>
              <button
                type="button"
                className="danger"
                disabled={cancelPending}
                onClick={() => void cancelTask()}
              >
                {cancelPending ? "Cancelling…" : "Yes, cancel task"}
              </button>
              <button
                type="button"
                className="secondary"
                disabled={cancelPending}
                onClick={() => {
                  cancellationCommand.current = null;
                  setCancelConfirming(false);
                  setCancelError("");
                }}
              >
                Keep task active
              </button>
            </div>
          )}
          {cancelError ? (
            <p className="task-error" role="alert">
              {cancelError}
            </p>
          ) : null}
        </div>
      </div>
    </section>
  );
}
