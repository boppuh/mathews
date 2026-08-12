"use client";

import { useState } from "react";
import { DocNav } from "../components/doc-nav";

type Scenario = {
  id: string;
  title: string;
  trigger: string;
  risk: string;
  outcome: string;
  invariant: string;
  tone: string;
  steps: { label: string; actor: string; detail: string; status: string }[];
};

const scenarios: Scenario[] = [
  {
    id: "CANCEL",
    title: "Cancellation during active work",
    trigger: "The operator cancels while Hermes or a host operation is active.",
    risk: "A late worker or process result advances the task after authority was revoked.",
    outcome: "CANCELLED",
    invariant: "Cancellation, lease revocation, tool-grant revocation, and queued/running job cancellation commit together.",
    tone: "rose",
    steps: [
      { label: "Cancel requested", actor: "Operator", detail: "The control plane records one durable cancellation identity and the exact expected state.", status: "event" },
      { label: "Authority fenced", actor: "Control plane", detail: "Active leases and Hermes tool grants are revoked transactionally; jobs become CANCELLED.", status: "fence" },
      { label: "Owned process stopped", actor: "Host agent", detail: "The full process identity is re-observed before its owned process group is signalled exactly once.", status: "action" },
      { label: "Partial evidence retained", actor: "Evidence ledger", detail: "Bounded logs, checkpoint fingerprints, and cleanup results remain auditable and redacted.", status: "proof" },
      { label: "Late result ignored", actor: "Control plane", detail: "An old fencing token may append ignored-result evidence but cannot move a checkpoint or task state.", status: "safe" },
    ],
  },
  {
    id: "OUTAGE",
    title: "Dependency outage",
    trigger: "Hermes, the host, or GitHub is temporarily unavailable.",
    risk: "An uncertain external effect is repeated, or a transient failure is mistaken for terminal failure.",
    outcome: "RETRY OR ESCALATE",
    invariant: "Every attempt is bounded, checkpointed, and identified by service, error code, retry number, and effect identity.",
    tone: "amber",
    steps: [
      { label: "Failure classified", actor: "Worker", detail: "The adapter records service and stable error code without inventing success or losing the last checkpoint.", status: "event" },
      { label: "Bounded backoff", actor: "Durable job", detail: "The same job schedules a limited exponential retry with jitter and retains its history.", status: "wait" },
      { label: "Limit exhausted", actor: "Control plane", detail: "One deterministic RETRY_LIMIT approval is created and the task enters ESCALATED.", status: "fence" },
      { label: "Human decides", actor: "Operator", detail: "RETRY, abandon, or cancel is applied only to the exact recorded operation and preconditions.", status: "action" },
      { label: "New generation resumes", actor: "Worker", detail: "A retry creates a new immutable job generation from the durable checkpoint; old authority stays fenced.", status: "safe" },
    ],
  },
  {
    id: "RESTART",
    title: "Process restart",
    trigger: "The API, worker, or launchd host agent restarts at a documented checkpoint.",
    risk: "Prepared mutations are issued again, completed work disappears, or ownership is confused after PID reuse.",
    outcome: "RECONCILED",
    invariant: "Startup observes durable leases, journals, external targets, and full process identities before issuing a new effect.",
    tone: "cyan",
    steps: [
      { label: "Lease inventory", actor: "Startup recovery", detail: "Expired leases are released and current fencing tokens are re-established from durable state.", status: "event" },
      { label: "Effect observed", actor: "Reconciler", detail: "Prepared host, Hermes, Git, PR, and webhook effects are inspected by stable idempotency identity.", status: "proof" },
      { label: "Outcome classified", actor: "Control plane", detail: "Completed effects replay their result; absent safe effects may retry; uncertain mutations become ambiguous.", status: "fence" },
      { label: "External heads compared", actor: "Adapters", detail: "Branch and PR heads, Hermes runs, host processes, and webhook cursors are compared to durable bindings.", status: "proof" },
      { label: "Work resumes safely", actor: "Worker", detail: "Only a current lease and proven next action may continue. Missing adapters produce RETRY_REQUIRED.", status: "safe" },
    ],
  },
  {
    id: "STALE",
    title: "Stale or out-of-order result",
    trigger: "An old worker, old PR head, duplicate webhook, or delayed completion arrives after current state changed.",
    risk: "Valid-looking historical success regresses the current head or satisfies a current gate.",
    outcome: "AUDITED, NOT APPLIED",
    invariant: "Task, installation, repository, PR, head SHA, lease token, and delivery identity must all match current authority.",
    tone: "violet",
    steps: [
      { label: "Receipt verified", actor: "Boundary adapter", detail: "Signature, delivery ID, correlation keys, and immutable raw receipt are stored before processing.", status: "event" },
      { label: "Exact binding compared", actor: "Control plane", detail: "The event is matched to task, repository, PR, branch, current head, and fencing token.", status: "proof" },
      { label: "Mismatch detected", actor: "Correlation gate", detail: "Old-head, duplicate, unknown, or ambiguous input is prevented from changing current projection or state.", status: "fence" },
      { label: "Evidence retained", actor: "Evidence ledger", detail: "The stale or quarantined input remains explainable without being treated as authority.", status: "proof" },
      { label: "Current truth preserved", actor: "Task state machine", detail: "Only current exact-head facts can satisfy validation, readiness, repair, or handoff gates.", status: "safe" },
    ],
  },
  {
    id: "AMBIGUOUS",
    title: "Ambiguous external mutation",
    trigger: "A connection drops after a mutation may have occurred but before its result is durably known.",
    risk: "Blind retry creates a second commit, push, draft PR, repair, or destructive host effect.",
    outcome: "RECONCILE OR ESCALATE",
    invariant: "A possible mutation is never reissued merely because its response was lost.",
    tone: "rose",
    steps: [
      { label: "Intent already durable", actor: "Control plane", detail: "The named effect and idempotency key were committed before dispatch.", status: "event" },
      { label: "Response lost", actor: "External boundary", detail: "The operation remains PREPARED or RUNNING; timeout is not evidence that nothing happened.", status: "wait" },
      { label: "Read-only observation", actor: "Reconciler", detail: "The host journal, branch head, PR binding, or remote system is queried without repeating the mutation.", status: "proof" },
      { label: "Ambiguity fenced", actor: "Control plane", detail: "If the effect cannot be proven complete or absent, new mutation authority stays closed.", status: "fence" },
      { label: "Human-visible decision", actor: "Operator", detail: "The task exposes RETRY_REQUIRED or escalation with the smallest safe next decision.", status: "safe" },
    ],
  },
];

export default function FailureRecoveryPage() {
  const [selected, setSelected] = useState(0);
  const [step, setStep] = useState(0);
  const scenario = scenarios[selected];

  function chooseScenario(index: number) { setSelected(index); setStep(0); }

  return (
    <main className="doc-shell recovery-shell">
      <DocNav current="recovery" />
      <section className="doc-intro recovery-intro">
        <div><span className="section-number">06 / FAILURE &amp; RECOVERY</span><h1>Uncertainty never<br /><em>becomes authority.</em></h1></div>
        <p>Select a failure mode, then walk the recovery sequence. Every path preserves evidence, fences stale authority, and prevents duplicate mutation.</p>
      </section>

      <section className="recovery-lab" aria-label="Interactive recovery scenarios">
        <div className="scenario-tabs" role="group" aria-label="Failure scenarios">
          {scenarios.map((item, index) => <button key={item.id} className={selected === index ? "selected" : ""} onClick={() => chooseScenario(index)} aria-pressed={selected === index}><span>{String(index + 1).padStart(2, "0")}</span><strong>{item.title}</strong></button>)}
        </div>
        <div className={`scenario-header ${scenario.tone}`}>
          <div><span>{scenario.id}</span><h2>{scenario.title}</h2></div>
          <dl><div><dt>TRIGGER</dt><dd>{scenario.trigger}</dd></div><div><dt>PRIMARY RISK</dt><dd>{scenario.risk}</dd></div></dl>
          <strong>{scenario.outcome}</strong>
        </div>
        <div className="recovery-flow" role="group" aria-label={`${scenario.title} recovery steps`}>
          {scenario.steps.map((item, index) => <div className="recovery-step-wrap" key={item.label}><button className={`${index === step ? "selected" : ""} ${index < step ? "complete" : ""}`} onClick={() => setStep(index)} aria-pressed={index === step}><span>{String(index + 1).padStart(2, "0")}</span><i>{index < step ? "✓" : index === step ? "●" : "○"}</i><strong>{item.label}</strong><small>{item.actor}</small></button>{index < scenario.steps.length - 1 && <b aria-hidden="true">→</b>}</div>)}
        </div>
        <div className="recovery-detail" aria-live="polite"><span>STEP {String(step + 1).padStart(2, "0")} / {scenario.steps[step].actor}</span><p>{scenario.steps[step].detail}</p><button onClick={() => setStep((current) => Math.min(scenario.steps.length - 1, current + 1))} disabled={step === scenario.steps.length - 1}>Next step →</button></div>
        <div className="recovery-invariant"><span>SAFETY INVARIANT</span><p>{scenario.invariant}</p></div>
      </section>

      <section className="recovery-rules"><div className="section-heading"><span>GLOBAL RECOVERY RULES</span><h2>The fence is stronger than the retry.</h2></div><div className="recovery-rule-grid">
        <article><span>01</span><h3>Observe before acting</h3><p>After uncertainty, reconcile the durable journal and external target before authorizing another effect.</p></article>
        <article><span>02</span><h3>Resume from a checkpoint</h3><p>A retry creates a new job generation from recorded progress; it does not improvise from agent memory.</p></article>
        <article><span>03</span><h3>Retain late evidence</h3><p>Late results remain useful for audit and diagnosis while being unable to advance current state.</p></article>
        <article><span>04</span><h3>Escalate the smallest decision</h3><p>When safety cannot be proven, Mathews asks for retry, abandon, deny, or cancel—not broad authority.</p></article>
      </div></section>
      <footer className="site-footer"><span>MATHEWS / FAILURE &amp; RECOVERY</span><span>Durable state before external effect</span></footer>
    </main>
  );
}
