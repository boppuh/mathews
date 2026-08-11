"use client";

import Link from "next/link";
import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";
import {
  type ApprovalDecision,
  type ApprovalInboxResponse,
  ApprovalRequestError,
  approvalClient,
  LatestApprovalInboxLoader,
} from "../../lib/approval-client";
import { AuthRequestError, authClient } from "../../lib/auth-client";
import { stageLabel } from "../../lib/stages";

type InboxState =
  | { status: "loading" }
  | { status: "failed"; message: string }
  | { status: "ready"; inbox: ApprovalInboxResponse };

const decisionLabels: Record<ApprovalDecision, string> = {
  APPROVE: "Approve",
  REQUEST_REVISION: "Request revision",
  RETRY: "Retry",
  DENY: "Deny",
  REJECT: "Reject",
  ABANDON: "Abandon",
  CANCEL: "Cancel task",
};

function timestamp(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function errorMessage(error: unknown, fallback = "Unable to load the approval inbox."): string {
  if (error instanceof ApprovalRequestError) return error.message;
  if (error instanceof Error && error.message.startsWith("The control plane returned")) {
    return error.message;
  }
  return fallback;
}

function EvidenceLinks({ taskPath, evidenceIds }: { taskPath: string; evidenceIds: string[] }) {
  return (
    <div className="inbox-evidence">
      <span>Evidence</span>
      {evidenceIds.map((id) => (
        <Link href={`${taskPath}#evidence-${id}`} key={id}>
          {id.slice(0, 8)}
        </Link>
      ))}
    </div>
  );
}

export function DecisionInbox() {
  const [state, setState] = useState<InboxState>({ status: "loading" });
  const [pendingRequest, setPendingRequest] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [reauthentication, setReauthentication] = useState<{
    requestId: string;
    decision: ApprovalDecision;
  } | null>(null);
  const [password, setPassword] = useState("");
  const [reauthenticationError, setReauthenticationError] = useState<string | null>(null);
  const inboxLoader = useRef<LatestApprovalInboxLoader | null>(null);
  if (inboxLoader.current === null) {
    inboxLoader.current = new LatestApprovalInboxLoader();
  }

  const load = useCallback(async (signal?: AbortSignal, background = false) => {
    try {
      const inbox = await inboxLoader.current?.load(signal);
      if (!inbox) return;
      setState({ status: "ready", inbox });
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") return;
      if (!background) setState({ status: "failed", message: errorMessage(error) });
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    const interval = window.setInterval(() => void load(controller.signal, true), 30_000);
    return () => {
      controller.abort();
      inboxLoader.current?.invalidate();
      window.clearInterval(interval);
    };
  }, [load]);

  async function decide(
    requestId: string,
    decision: ApprovalDecision,
    afterReauthentication = false,
  ) {
    setPendingRequest(requestId);
    setActionError(null);
    try {
      await approvalClient.decide(requestId, decision);
      await load(undefined, true);
    } catch (error) {
      if (!afterReauthentication && error instanceof ApprovalRequestError && error.status === 403) {
        setReauthentication({ requestId, decision });
        setActionError(null);
        return;
      }
      setActionError(errorMessage(error, "Unable to record the decision."));
      if (error instanceof ApprovalRequestError && [404, 409].includes(error.status)) {
        await load(undefined, true);
      }
    } finally {
      setPendingRequest(null);
    }
  }

  async function reauthenticate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!reauthentication || !password || pendingRequest !== null) return;
    const target = reauthentication;
    setPendingRequest(target.requestId);
    setReauthenticationError(null);
    try {
      await authClient.reauthenticate(password);
      setPassword("");
      setReauthentication(null);
      setPendingRequest(null);
      await decide(target.requestId, target.decision, true);
    } catch (error) {
      setPassword("");
      setReauthenticationError(
        error instanceof AuthRequestError ? error.message : "Unable to verify your password.",
      );
      setPendingRequest(null);
    }
  }

  if (state.status === "loading") {
    return (
      <main className="decision-inbox inbox-centered" aria-busy="true">
        <div className="task-list-status" role="status">
          <span className="status-dot" aria-hidden="true" />
          Loading durable decisions…
        </div>
      </main>
    );
  }

  if (state.status === "failed") {
    return (
      <main className="decision-inbox inbox-centered">
        <Link href="/" className="back-link">
          ← Work
        </Link>
        <section className="cockpit-load-error">
          <p className="eyebrow">Decision inbox</p>
          <h1>Inbox unavailable</h1>
          <p className="task-error" role="alert">
            {state.message}
          </p>
          <button type="button" onClick={() => void load()}>
            Try again
          </button>
        </section>
      </main>
    );
  }

  const projectedRuleRequestIds = new Set(
    state.inbox.rule_candidates.flatMap((rule) =>
      rule.approval_request_id === null ? [] : [rule.approval_request_id],
    ),
  );
  const approvals = state.inbox.approvals.filter(
    (approval) =>
      approval.request_type !== "REVIEW_RULE" || !projectedRuleRequestIds.has(approval.id),
  );
  const approvalById = new Map(state.inbox.approvals.map((approval) => [approval.id, approval]));
  const total = approvals.length + state.inbox.rule_candidates.length;

  return (
    <main className="decision-inbox">
      <div className="inbox-topline">
        <Link href="/" className="back-link">
          ← Work
        </Link>
        <span>
          {total} pending {total === 1 ? "item" : "items"}
        </span>
      </div>
      <header className="inbox-header">
        <div>
          <p className="eyebrow">Human control plane</p>
          <h1>Decision inbox</h1>
          <p className="lede">
            Review the exact task state, bounded operation, and evidence before work resumes.
          </p>
        </div>
        <button type="button" onClick={() => void load()} disabled={pendingRequest !== null}>
          Refresh
        </button>
      </header>

      {actionError ? (
        <p className="inbox-action-error" role="alert">
          {actionError}
        </p>
      ) : null}

      {reauthentication ? (
        <form className="inbox-reauthentication" onSubmit={reauthenticate}>
          <div>
            <strong>Confirm this protected decision</strong>
            <p>
              Re-enter your password to continue with{" "}
              {decisionLabels[reauthentication.decision].toLowerCase()}.
            </p>
          </div>
          <label htmlFor="inbox-reauthentication-password">Password</label>
          <input
            id="inbox-reauthentication-password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.currentTarget.value)}
            disabled={pendingRequest !== null}
            required
          />
          <button type="submit" disabled={!password || pendingRequest !== null}>
            {pendingRequest ? "Verifying…" : "Verify and continue"}
          </button>
          <button
            type="button"
            className="secondary"
            disabled={pendingRequest !== null}
            onClick={() => {
              setPassword("");
              setReauthentication(null);
              setReauthenticationError(null);
            }}
          >
            Keep pending
          </button>
          {reauthenticationError ? (
            <p className="inbox-action-error" role="alert">
              {reauthenticationError}
            </p>
          ) : null}
        </form>
      ) : null}

      <section className="inbox-section" aria-labelledby="approval-inbox-heading">
        <div className="inbox-section-heading">
          <div>
            <p className="eyebrow">Approval inbox</p>
            <h2 id="approval-inbox-heading">Blocked work</h2>
          </div>
          <span>{approvals.length}</span>
        </div>
        {approvals.length === 0 ? (
          <div className="inbox-empty">No task actions are waiting for approval.</div>
        ) : (
          <div className="inbox-cards">
            {approvals.map((approval) => (
              <article className="inbox-card" key={approval.id}>
                <div className="inbox-card-topline">
                  <span className="inbox-kind">{approval.type_label}</span>
                  <time dateTime={approval.created_at}>{timestamp(approval.created_at)}</time>
                </div>
                <h3>{approval.task.summary}</h3>
                <p className="inbox-repository">{approval.task.repository}</p>
                <dl className="inbox-facts">
                  <div>
                    <dt>Blocked at</dt>
                    <dd>{stageLabel(approval.requesting_state)}</dd>
                  </div>
                  <div>
                    <dt>Resumes at</dt>
                    <dd>{approval.resume_state ? stageLabel(approval.resume_state) : "—"}</dd>
                  </div>
                  <div>
                    <dt>Reason</dt>
                    <dd>
                      <code>{approval.reason_code}</code>
                    </dd>
                  </div>
                  {approval.expires_at ? (
                    <div>
                      <dt>Expires</dt>
                      <dd>{timestamp(approval.expires_at)}</dd>
                    </div>
                  ) : null}
                </dl>
                {approval.operation_name ? (
                  <div className="bounded-operation">
                    <strong>Bound operation identity</strong>
                    <span>Operation</span>
                    <code>{approval.operation_name}</code>
                    <span>Idempotency key</span>
                    <code>{approval.operation_idempotency_key}</code>
                    <span>Complete input fingerprint (SHA-256)</span>
                    <code>{approval.operation_fingerprint}</code>
                    {approval.operation_checkpoint_evidence_id ? (
                      <small>
                        Human-readable checkpoint:{" "}
                        <Link
                          href={`${approval.task.cockpit_path}#evidence-${approval.operation_checkpoint_evidence_id}`}
                        >
                          {approval.operation_checkpoint_evidence_id}
                        </Link>
                      </small>
                    ) : (
                      <small>No checkpoint evidence was captured for this operation.</small>
                    )}
                    <small>
                      The complete fingerprint binds the operation inputs without exposing secret
                      values. Inspect the checkpoint evidence before deciding.
                    </small>
                  </div>
                ) : null}
                {approval.brief ? (
                  <div className="rule-definition brief-definition">
                    <strong>Exact brief · version {approval.brief.version}</strong>
                    <div>
                      <strong>Scope</strong>
                      <pre>{JSON.stringify(approval.brief.scope, null, 2)}</pre>
                    </div>
                    <div>
                      <strong>Exclusions</strong>
                      <pre>{JSON.stringify(approval.brief.exclusions, null, 2)}</pre>
                    </div>
                    <div>
                      <strong>Acceptance criteria</strong>
                      <pre>{JSON.stringify(approval.brief.acceptance_criteria, null, 2)}</pre>
                    </div>
                    <div>
                      <strong>Risks</strong>
                      <pre>{JSON.stringify(approval.brief.risks, null, 2)}</pre>
                    </div>
                    <div>
                      <strong>Affected flow</strong>
                      <pre>{JSON.stringify(approval.brief.affected_flow, null, 2)}</pre>
                    </div>
                    <div>
                      <strong>Test plan</strong>
                      <pre>{JSON.stringify(approval.brief.test_plan, null, 2)}</pre>
                    </div>
                  </div>
                ) : null}
                <EvidenceLinks
                  taskPath={approval.task.cockpit_path}
                  evidenceIds={approval.supporting_evidence_ids}
                />
                {!approval.actionable ? (
                  <p className="inbox-unavailable" role="status">
                    {approval.unavailable_reason === "BRIEF_UNAVAILABLE"
                      ? "This brief changed or became unavailable. You can cancel the task or inspect it before creating a replacement approval request."
                      : "This rule candidate changed or became unavailable. You can cancel the task or inspect it before creating a replacement approval request."}
                  </p>
                ) : null}
                <div className="inbox-card-footer">
                  <Link href={approval.task.cockpit_path}>Open task</Link>
                  <div className="decision-actions">
                    {(approval.actionable
                      ? approval.options
                      : approval.options.filter((option) => option === "CANCEL")
                    ).map((option) => (
                      <button
                        className={option === "APPROVE" || option === "RETRY" ? "primary" : ""}
                        disabled={pendingRequest !== null}
                        key={option}
                        onClick={() => void decide(approval.id, option)}
                        type="button"
                      >
                        {pendingRequest === approval.id ? "Recording…" : decisionLabels[option]}
                      </button>
                    ))}
                  </div>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>

      <section className="inbox-section rule-inbox-section" aria-labelledby="rule-inbox-heading">
        <div className="inbox-section-heading">
          <div>
            <p className="eyebrow">Rule inbox</p>
            <h2 id="rule-inbox-heading">Evaluated candidates</h2>
          </div>
          <span>{state.inbox.rule_candidates.length}</span>
        </div>
        <p className="rule-safety-note">
          Candidates are non-authoritative and cannot change policy or prompts. A separate approval
          is required before any candidate can be promoted into a new policy version.
        </p>
        {state.inbox.rule_candidates.length === 0 ? (
          <div className="inbox-empty">No evaluated rule candidates are available.</div>
        ) : (
          <div className="inbox-cards">
            {state.inbox.rule_candidates.map((rule) => {
              const approval =
                rule.approval_request_id === null
                  ? undefined
                  : approvalById.get(rule.approval_request_id);
              if (rule.approval_request_id !== null && !approval) return null;
              return (
                <article className="inbox-card rule-card" key={rule.candidate_id}>
                  <div className="inbox-card-topline">
                    <span className="inbox-kind">
                      {approval ? "Rule for approval" : "Candidate only"} · {rule.lineage_key}
                    </span>
                    <span className="risk-chip">{rule.risk_class} risk</span>
                  </div>
                  <h3>{rule.proposed_rule}</h3>
                  <p className="inbox-repository">
                    {rule.task.repository} · {rule.task.summary}
                  </p>
                  <dl className="inbox-facts">
                    <div>
                      <dt>Recurrence</dt>
                      <dd>{rule.recurrence_assessment}</dd>
                    </div>
                    <div>
                      <dt>Severity</dt>
                      <dd>{rule.severity_assessment}</dd>
                    </div>
                    <div>
                      <dt>Permitted action</dt>
                      <dd>
                        <code>{rule.permitted_action}</code>
                      </dd>
                    </div>
                    <div>
                      <dt>False-positive risks</dt>
                      <dd>
                        {rule.false_positive_risks.length
                          ? rule.false_positive_risks.join(" · ")
                          : "None recorded"}
                      </dd>
                    </div>
                  </dl>
                  <div className="rule-definition">
                    <div>
                      <strong>Exact scope</strong>
                      <pre>{JSON.stringify(rule.scope, null, 2)}</pre>
                    </div>
                    <div>
                      <strong>Exact matcher</strong>
                      <pre>{JSON.stringify(rule.matcher, null, 2)}</pre>
                    </div>
                    <div>
                      <strong>Evidence requirements</strong>
                      <ul>
                        {rule.evidence_requirements.map((requirement) => (
                          <li key={requirement}>{requirement}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                  <EvidenceLinks
                    taskPath={rule.task.cockpit_path}
                    evidenceIds={rule.cited_evidence_ids}
                  />
                  <div className="inbox-card-footer">
                    <Link href={rule.task.cockpit_path}>Open task</Link>
                    {approval ? (
                      <div className="decision-actions">
                        {approval.options.map((option) => (
                          <button
                            className={option === "APPROVE" ? "primary" : ""}
                            disabled={pendingRequest !== null}
                            key={option}
                            onClick={() => void decide(approval.id, option)}
                            type="button"
                          >
                            {pendingRequest === approval.id ? "Recording…" : decisionLabels[option]}
                          </button>
                        ))}
                      </div>
                    ) : (
                      <span className="inbox-unavailable">
                        Non-authoritative · no approval requested
                      </span>
                    )}
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </section>
    </main>
  );
}
