"use client";

import {
  TASK_EVIDENCE_CATEGORIES,
  type TaskAcceptanceCriterionSummary,
  type TaskEvidenceCategory,
  type TaskEvidenceSummary,
} from "@mathews/contracts";
import { useEffect, useMemo, useRef, useState } from "react";

import { AuthRequestError, authClient } from "../../../lib/auth-client";
import {
  type EvidenceContent,
  evidenceClient,
  evidenceDownloadUrl,
  TaskRequestError,
} from "../../../lib/task-client";

const categoryLabels: Record<TaskEvidenceCategory, string> = {
  CRITERIA: "Criteria",
  CHANGE: "Changes",
  TEST: "Tests",
  LOG: "Logs",
  NETWORK: "Network",
  PR_CI: "PR & CI",
  ARTIFACT: "Artifacts",
  OTHER: "Other",
};

const verificationLabels: Record<TaskAcceptanceCriterionSummary["verification"], string> = {
  AUTOMATED_TEST: "Automated test",
  SIMULATOR_ASSERTION: "Simulator assertion",
  STATIC_CHECK: "Static check",
  HUMAN_INSPECTION: "Human inspection",
};

type PreviewState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "ready"; content: EvidenceContent }
  | { status: "failed"; message: string };

type ReauthenticationState = "idle" | "submitting" | "failed" | "refresh_failed";

function title(value: string): string {
  return value
    .split(/[-_.]/)
    .filter(Boolean)
    .map((part) => `${part[0]?.toUpperCase() ?? ""}${part.slice(1).toLowerCase()}`)
    .join(" ");
}

function formatTimestamp(timestamp: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(timestamp));
}

function matchCount(content: string, query: string): number {
  const needle = query.trim().toLocaleLowerCase();
  if (!needle) {
    return 0;
  }
  const haystack = content.toLocaleLowerCase();
  let count = 0;
  let cursor = 0;
  let matchIndex = haystack.indexOf(needle, cursor);
  while (matchIndex !== -1) {
    count += 1;
    cursor = matchIndex + needle.length;
    matchIndex = haystack.indexOf(needle, cursor);
  }
  return count;
}

function previewFailure(error: unknown): string {
  if (error instanceof TaskRequestError) {
    return error.message;
  }
  return "This evidence content is unavailable.";
}

function EvidenceCard({
  record,
  onRevealEvidence,
  onReauthenticated,
}: {
  record: TaskEvidenceSummary;
  onRevealEvidence: (evidenceId: string) => void;
  onReauthenticated: () => Promise<boolean>;
}) {
  const [preview, setPreview] = useState<PreviewState>({ status: "idle" });
  const [contentQuery, setContentQuery] = useState("");
  const controller = useRef<AbortController | null>(null);
  const [password, setPassword] = useState("");
  const [reauthenticationState, setReauthenticationState] = useState<ReauthenticationState>("idle");
  const [reauthenticationError, setReauthenticationError] = useState("");
  const downloadUrl = evidenceDownloadUrl(record);

  useEffect(
    () => () => {
      const activeController = controller.current;
      controller.current = null;
      activeController?.abort();
    },
    [],
  );

  const loadPreview = () => {
    if (preview.status === "loading" || preview.status === "ready" || !downloadUrl) {
      return;
    }
    controller.current?.abort();
    const requestController = new AbortController();
    controller.current = requestController;
    setPreview({ status: "loading" });
    void evidenceClient.content(record, requestController.signal).then(
      (content) => {
        if (controller.current === requestController) {
          controller.current = null;
          setPreview({ status: "ready", content });
        }
      },
      (error: unknown) => {
        if (controller.current !== requestController) {
          return;
        }
        controller.current = null;
        if (error instanceof Error && error.name === "AbortError") {
          setPreview({ status: "idle" });
        } else {
          setPreview({ status: "failed", message: previewFailure(error) });
        }
      },
    );
  };

  const count = useMemo(
    () => (preview.status === "ready" ? matchCount(preview.content.text, contentQuery) : 0),
    [contentQuery, preview],
  );
  const refreshUnlockedEvidence = async () => {
    setReauthenticationError("");
    setReauthenticationState("submitting");
    try {
      const refreshed = await onReauthenticated();
      if (!refreshed) {
        throw new Error("cockpit refresh was not applied");
      }
      setReauthenticationState("idle");
    } catch {
      setReauthenticationState("refresh_failed");
      setReauthenticationError("Password accepted, but the evidence did not refresh.");
    }
  };
  const reauthenticate = async () => {
    if (!password || reauthenticationState === "submitting") {
      return;
    }
    setReauthenticationError("");
    setReauthenticationState("submitting");
    try {
      await authClient.reauthenticate(password);
      setPassword("");
      await refreshUnlockedEvidence();
    } catch (error) {
      setReauthenticationState("failed");
      setReauthenticationError(
        error instanceof AuthRequestError
          ? error.message
          : "Unable to unlock this evidence right now.",
      );
    }
  };

  return (
    <article
      id={`evidence-${record.id}`}
      className={`evidence-card evidence-card-${record.status.toLowerCase()}`}
    >
      <div className="evidence-card-heading">
        <div>
          <span className="evidence-category">{categoryLabels[record.category]}</span>
          <h3>{title(record.evidence_type)}</h3>
        </div>
        <span className={`evidence-pill evidence-${record.status.toLowerCase()}`}>
          {record.status.toLowerCase()}
        </span>
      </div>
      <p className="evidence-record-meta">
        EvidenceRecord <code>{record.id.slice(0, 8)}</code> ·{" "}
        <time dateTime={record.captured_at}>{formatTimestamp(record.captured_at)}</time>
      </p>

      {record.correction_of_id ? (
        <p className="evidence-lineage">
          Corrects record <code>{record.correction_of_id.slice(0, 8)}</code>
        </p>
      ) : null}
      {record.corrected_by_id ? (
        <p className="evidence-lineage">
          Superseded by{" "}
          <a
            href={`#evidence-${record.corrected_by_id}`}
            onClick={(event) => {
              event.preventDefault();
              onRevealEvidence(record.corrected_by_id ?? "");
            }}
          >
            {record.corrected_by_id.slice(0, 8)}
          </a>
        </p>
      ) : null}

      {record.content_access === "DELETED" ? (
        <div className="evidence-tombstone" role="note">
          <strong>Content removed</strong>
          <span>{title(record.deletion_reason ?? "deleted")}</span>
          <small>
            {record.deleted_at
              ? `Destroyed ${formatTimestamp(record.deleted_at)}`
              : "Deletion is fenced; cleanup is pending."}
          </small>
        </div>
      ) : record.content_access === "RECENT_PASSWORD_REQUIRED" ? (
        <form
          className="evidence-reauthentication"
          onSubmit={(event) => {
            event.preventDefault();
            if (reauthenticationState === "refresh_failed") {
              void refreshUnlockedEvidence();
            } else {
              void reauthenticate();
            }
          }}
        >
          <label>
            Re-enter your password to inspect this protected evidence.
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => {
                setPassword(event.target.value);
                setReauthenticationState("idle");
                setReauthenticationError("");
              }}
            />
          </label>
          <button
            type="submit"
            disabled={
              reauthenticationState === "submitting" ||
              (!password && reauthenticationState !== "refresh_failed")
            }
          >
            {reauthenticationState === "submitting"
              ? "Checking…"
              : reauthenticationState === "refresh_failed"
                ? "Retry refresh"
                : "Unlock evidence"}
          </button>
          {reauthenticationState === "failed" || reauthenticationState === "refresh_failed" ? (
            <p className="task-error" role="alert">
              {reauthenticationError}
            </p>
          ) : null}
        </form>
      ) : (
        <details
          className="evidence-preview"
          onToggle={(event) => event.currentTarget.open && loadPreview()}
        >
          <summary>Preview redacted content</summary>
          {preview.status === "loading" ? (
            <p className="evidence-preview-status" role="status">
              Loading redacted content…
            </p>
          ) : preview.status === "failed" ? (
            <div className="evidence-preview-error">
              <p className="task-error" role="alert">
                {preview.message}
              </p>
              <button type="button" onClick={loadPreview}>
                Try again
              </button>
            </div>
          ) : preview.status === "ready" ? (
            <div className="evidence-preview-body">
              <label>
                Search this record
                <span>
                  <input
                    type="search"
                    value={contentQuery}
                    onChange={(event) => setContentQuery(event.target.value)}
                    placeholder="Find in evidence"
                  />
                  <output>{contentQuery.trim() ? `${count} matches` : ""}</output>
                </span>
              </label>
              <pre>{preview.content.text}</pre>
            </div>
          ) : null}
        </details>
      )}

      {downloadUrl ? (
        <a className="evidence-download" href={downloadUrl} download>
          Download redacted record
        </a>
      ) : null}
    </article>
  );
}

export function EvidenceWorkbench({
  criteria,
  evidence,
  onRefresh,
}: {
  criteria: TaskAcceptanceCriterionSummary[];
  evidence: TaskEvidenceSummary[];
  onRefresh: () => Promise<boolean>;
}) {
  const [category, setCategory] = useState<TaskEvidenceCategory | "ALL">("ALL");
  const [query, setQuery] = useState("");
  const visibleEvidence = useMemo(() => {
    const normalizedQuery = query.trim().toLocaleLowerCase();
    return evidence.filter(
      (record) =>
        (category === "ALL" || record.category === category) &&
        (!normalizedQuery ||
          `${record.evidence_type} ${record.category} ${record.id}`
            .toLocaleLowerCase()
            .includes(normalizedQuery)),
    );
  }, [category, evidence, query]);
  const revealEvidence = (evidenceId: string) => {
    if (!evidenceId) {
      return;
    }
    setCategory("ALL");
    setQuery("");
    window.requestAnimationFrame(() => {
      const anchor = `evidence-${evidenceId}`;
      window.history.replaceState(null, "", `#${anchor}`);
      document.getElementById(anchor)?.scrollIntoView({ block: "center" });
    });
  };

  return (
    <section
      id="evidence"
      className="cockpit-section evidence-workbench"
      aria-labelledby="evidence-heading"
    >
      <div className="cockpit-section-heading">
        <div>
          <p className="eyebrow">Verification ledger</p>
          <h2 id="evidence-heading">Evidence & artifacts</h2>
        </div>
        <p>{evidence.length} records</p>
      </div>

      <section id="acceptance" className="criteria-panel" aria-labelledby="criteria-heading">
        <div>
          <p className="eyebrow">Definition of done</p>
          <h3 id="criteria-heading">Acceptance criteria</h3>
        </div>
        {criteria.length === 0 ? (
          <p className="cockpit-empty">
            Criteria will appear after the implementation brief is accepted.
          </p>
        ) : (
          <ol>
            {criteria.map((criterion) => (
              <li key={criterion.id}>
                <span className={`criterion-state criterion-${criterion.status.toLowerCase()}`}>
                  {criterion.status.toLowerCase()}
                </span>
                <div>
                  <strong>{criterion.requirement}</strong>
                  <small>
                    {criterion.id} · {verificationLabels[criterion.verification]}
                  </small>
                </div>
              </li>
            ))}
          </ol>
        )}
      </section>

      <div className="evidence-toolbar">
        <fieldset className="evidence-filters">
          <legend className="visually-hidden">Evidence categories</legend>
          <button
            type="button"
            aria-pressed={category === "ALL"}
            onClick={() => setCategory("ALL")}
          >
            All
          </button>
          {TASK_EVIDENCE_CATEGORIES.map((value) => (
            <button
              type="button"
              key={value}
              aria-pressed={category === value}
              onClick={() => setCategory(value)}
            >
              {categoryLabels[value]}
            </button>
          ))}
        </fieldset>
        <label className="evidence-search">
          <span>Search records</span>
          <input
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Type, category, or record ID"
          />
        </label>
      </div>

      {visibleEvidence.length === 0 ? (
        <p className="cockpit-empty evidence-empty">
          {evidence.length === 0
            ? "Evidence will appear as work is verified."
            : "No evidence matches this view."}
        </p>
      ) : (
        <div className="evidence-grid">
          {visibleEvidence.map((record) => (
            <EvidenceCard
              key={record.id}
              record={record}
              onRevealEvidence={revealEvidence}
              onReauthenticated={onRefresh}
            />
          ))}
        </div>
      )}
    </section>
  );
}
