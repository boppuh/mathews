"use client";

import { useState } from "react";
import { DocNav } from "../components/doc-nav";

type State = {
  id: string;
  number: string;
  title: string;
  owner: string;
  tone: string;
  summary: string;
  gate: string;
  evidence: string;
};

const states: State[] = [
  { id: "INTAKE", number: "01", title: "Intake", owner: "Operator + control plane", tone: "cyan", summary: "A natural-language request is bound to the configured repository and immutable base revision.", gate: "The request is authenticated, scoped to the single configured repository, and recorded.", evidence: "Task record, requester, base revision, raw request" },
  { id: "BRIEFING", number: "02", title: "Briefing", owner: "Planner through Hermes", tone: "cyan", summary: "The request becomes a versioned brief, typed criteria, risks, affected flow, and validation plan.", gate: "Every required field is complete; ambiguity and scope expansion are made explicit.", evidence: "Versioned brief, acceptance criteria, policy evaluation" },
  { id: "BRIEF_PENDING_APPROVAL", number: "03", title: "Approval", owner: "Human operator", tone: "amber", summary: "Ambiguous, sensitive, or expanded work pauses for a decision on the exact brief version.", gate: "Only approval of the exact version permits implementation; revision returns to briefing.", evidence: "Approval request, decision, actor, exact brief fingerprint" },
  { id: "IMPLEMENTING", number: "04", title: "Implementing", owner: "Hermes + mediated host tools", tone: "lime", summary: "Hermes proposes scoped changes inside an isolated task workspace. The control plane authorizes every operation.", gate: "Valid lease, accepted brief, allowlisted operation, permitted path, active policy.", evidence: "Tool grants, operations, changed paths, candidate commit and tree" },
  { id: "VALIDATING", number: "05", title: "Validating", owner: "Host agent + control plane", tone: "lime", summary: "Tests and the configured simulator journey run against the exact clean candidate commit.", gate: "Every assertion in the active validation contract must pass with direct evidence.", evidence: "XCTest output, simulator assertions, logs, artifacts, commit and tree SHAs" },
  { id: "PR_ACTIVE", number: "06", title: "Draft PR active", owner: "Control plane + GitHub", tone: "violet", summary: "Only the verified SHA is pushed. A draft PR is opened and correlated CI and review events are observed.", gate: "Local head, remote branch, PR head, and validation decision all identify the same commit.", evidence: "Draft-PR proof, GitHub binding, CI and review events" },
  { id: "READY_FOR_HUMAN_MERGE", number: "07", title: "Ready for human merge", owner: "Control plane verifies", tone: "violet", summary: "The exact current PR head has green required checks, no blocking review, and fully authorized repairs.", gate: "Readiness is recomputed from authoritative facts and reverses if any fact changes.", evidence: "Immutable readiness assessment and exact-head proof" },
  { id: "HANDED_OFF", number: "08", title: "Handed off", owner: "Human operator", tone: "amber", summary: "A recently authenticated human accepts responsibility for merge, deployment, delivery, and release.", gate: "Exact head, fresh readiness, recent password check, and fixed acknowledgement.", evidence: "Acknowledgement, verified head, actor, handoff event" },
];

const detours = [
  { title: "Repair loop", path: "VALIDATING / PR_ACTIVE → REPAIRING → VALIDATING", text: "A bounded repair creates a new commit. The entire validation and exact-head proof must run again." },
  { title: "Resumable escalation", path: "ANY ACTIVE STATE → ESCALATED → RECORDED STATE", text: "Outages, unsafe actions, and retry exhaustion pause at a durable checkpoint until a human decision and precondition recheck." },
  { title: "Scope-changing steering", path: "PRE-HANDOFF → BRIEFING", text: "In-flight work is fenced, the prior brief and validation contract are invalidated, and the new scope is briefed explicitly." },
  { title: "Terminal outcomes", path: "NON-TERMINAL → CANCELLED / FAILED", text: "Cancellation and failure preserve partial evidence. Neither resumes in place; a new task must cite the terminal task." },
];

export default function TaskLifecyclePage() {
  const [selected, setSelected] = useState(0);
  const state = states[selected];

  return (
    <main className="doc-shell lifecycle-shell">
      <DocNav current="lifecycle" />
      <section className="doc-intro">
        <div>
          <span className="section-number">02 / TASK LIFECYCLE</span>
          <h1>From request to<br /><em>human handoff.</em></h1>
        </div>
        <p>Every transition belongs to the control plane. Agents may propose and execute bounded work; stored evidence—not prose—moves the task forward.</p>
      </section>

      <section className="lifecycle-board" aria-label="Interactive task lifecycle">
        <div className="phase-rail" role="group" aria-label="Golden path states">
          {states.map((item, index) => (
            <div className="phase-wrap" key={item.id}>
              <button
                className={`phase-node ${item.tone} ${selected === index ? "selected" : ""}`}
                onClick={() => setSelected(index)}
                aria-pressed={selected === index}
              >
                <span className="phase-number">{item.number}</span>
                <span className="phase-title">{item.title}</span>
              </button>
              {index < states.length - 1 && <span className="phase-connector" aria-hidden="true">→</span>}
            </div>
          ))}
        </div>

        <div className={`state-detail ${state.tone}`} aria-live="polite">
          <div className="detail-topline">
            <span>{state.id}</span>
            <span>AUTHORITY / {state.owner}</span>
          </div>
          <div className="detail-main">
            <h2>{state.title}</h2>
            <p>{state.summary}</p>
          </div>
          <div className="detail-facts">
            <div><span>ADVANCE GATE</span><p>{state.gate}</p></div>
            <div><span>DURABLE PROOF</span><p>{state.evidence}</p></div>
          </div>
        </div>
      </section>

      <section className="detour-section">
        <div className="section-heading">
          <span>EXCEPTIONS ARE PART OF THE MODEL</span>
          <h2>Nothing quietly falls through.</h2>
        </div>
        <div className="detour-grid">
          {detours.map((detour, index) => (
            <article className="detour-card" key={detour.title}>
              <span className="detour-index">0{index + 1}</span>
              <h3>{detour.title}</h3>
              <code>{detour.path}</code>
              <p>{detour.text}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="hard-stop">
        <span className="stop-mark">×</span>
        <div><span>RELEASE-ACTION GATE</span><h2>Always closed in the MVP.</h2></div>
        <p>Mathews cannot merge, tag a release, deploy, or use production signing credentials. Handoff ends automation authority—it does not mean released.</p>
      </section>

      <footer className="site-footer"><span>MATHEWS / TASK LIFECYCLE</span><span>Click any state to inspect its gate</span></footer>
    </main>
  );
}
