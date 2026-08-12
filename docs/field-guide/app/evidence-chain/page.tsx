"use client";

import { useMemo, useState } from "react";
import { DocNav } from "../components/doc-nav";

type Proof = {
  id: string;
  short: string;
  title: string;
  custodian: string;
  record: string;
  proves: string;
  binding: string;
  unlocks: string;
  invalidatedBy: string;
};

const proofs: Proof[] = [
  {
    id: "REQUEST",
    short: "Request",
    title: "Canonical request",
    custodian: "Operator → control plane",
    record: "Authenticated task intent, configured repository, immutable base revision, requester, and timestamp.",
    proves: "The work began from a known human request against one known repository state.",
    binding: "Task ID + repository key + base SHA",
    unlocks: "A versioned planning run",
    invalidatedBy: "Never rewritten. Later steering is appended as a new source record.",
  },
  {
    id: "BRIEF",
    short: "Brief",
    title: "Accepted brief",
    custodian: "Planner + operator/policy",
    record: "Versioned scope, typed acceptance criteria, risks, affected flow, allowed paths, and validation plan.",
    proves: "The implementation target is explicit, bounded, and accepted by the required authority.",
    binding: "Request evidence + brief version + approval disposition",
    unlocks: "Scoped implementation authority",
    invalidatedBy: "Scope-affecting steering, revision, cancellation, or a mismatched approval fingerprint.",
  },
  {
    id: "AUTHORITY",
    short: "Authority",
    title: "Versioned authority",
    custodian: "Control plane",
    record: "Active policy, promoted role prompts, repository configuration, approval lineage, and applicable review rules.",
    proves: "Every permitted action derives from a named, immutable authority—not agent confidence.",
    binding: "Policy + prompt + configuration versions and fingerprints",
    unlocks: "Mediated tool grants and named host operations",
    invalidatedBy: "Policy replacement, configuration change, expired approval, or a rule mismatch.",
  },
  {
    id: "CONTRACT",
    short: "Contract",
    title: "Validation contract",
    custodian: "Control plane",
    record: "Exact criteria, verifier kinds, assertion catalog keys, required artifacts, and repository configuration version.",
    proves: "Success has a machine-evaluable definition before the candidate is judged.",
    binding: "Accepted brief + policy + repository configuration",
    unlocks: "An authoritative validation decision",
    invalidatedBy: "Any brief, policy, repository configuration, assertion, or contract change.",
  },
  {
    id: "CANDIDATE",
    short: "Candidate",
    title: "Candidate commit",
    custodian: "macOS host agent",
    record: "Clean task workspace, changed paths, author identity, commit SHA, tree SHA, and immutable base SHA.",
    proves: "There is one exact code state to validate and publish.",
    binding: "Task branch + commit SHA + tree SHA + configuration version",
    unlocks: "Tests against clean HEAD",
    invalidatedBy: "Any content, index, worktree, commit, tree, base, or configuration change.",
  },
  {
    id: "VALIDATION",
    short: "Validation",
    title: "Validation evidence",
    custodian: "Host agent → control plane",
    record: "XCTest results, simulator assertions, logs, artifacts, result codes, and criterion-by-criterion evidence references.",
    proves: "Every active criterion passed against the exact candidate—not against a nearby workspace state.",
    binding: "Contract version + commit SHA + tree SHA + artifact hashes",
    unlocks: "Verified draft publication",
    invalidatedBy: "A new candidate, changed contract/configuration, missing evidence, failed assertion, or dirty workspace.",
  },
  {
    id: "DRAFT_PROOF",
    short: "Draft proof",
    title: "Exact-head draft proof",
    custodian: "Control plane + host + GitHub",
    record: "Clean local head, pushed remote branch, draft PR binding, and GitHub-observed PR head.",
    proves: "The code reviewed on GitHub is byte-for-byte the candidate that passed validation.",
    binding: "local HEAD = remote branch SHA = PR head SHA = validated commit",
    unlocks: "PR_ACTIVE and readiness observation",
    invalidatedBy: "Head drift, force update, non-draft state, missing binding, approval fence, or cancellation.",
  },
  {
    id: "READINESS",
    short: "Readiness",
    title: "Readiness assessment",
    custodian: "Control plane from GitHub signals",
    record: "Required checks, latest results, review status, open-thread status, repair state, and exact-head correlation.",
    proves: "The current draft head is still verified, green, unblocked, and fully authorized.",
    binding: "Draft proof + current PR head + required CI + current reviews",
    unlocks: "READY_FOR_HUMAN_MERGE",
    invalidatedBy: "Changed head, failing/incomplete CI, blocking review, open thread, unsettled repair, or PR state change.",
  },
  {
    id: "HANDOFF",
    short: "Handoff",
    title: "Human handoff",
    custodian: "Recently authenticated operator",
    record: "Fixed acknowledgement, exact verified head, human actor, idempotency key, and durable transition event.",
    proves: "Automation ended at a known head and a human accepted responsibility for every remaining action.",
    binding: "Fresh readiness assessment + exact head SHA + human acknowledgement",
    unlocks: "Human-controlled ready/merge/release decisions outside Mathews",
    invalidatedBy: "The gate is recomputed before handoff. After handoff, autonomous work is terminal.",
  },
];

const breakpoints = [
  { id: "none", label: "Complete chain", detail: "All records agree on the same intent, authority, contract, code, and pull-request head.", cut: proofs.length },
  { id: "scope", label: "Scope changes", detail: "A steering message changes acceptance criteria. The old brief, authority application, contract, and all downstream proof can no longer advance the task.", cut: 1 },
  { id: "config", label: "Configuration changes", detail: "A repository or policy version changes. The contract, candidate authorization, validation, and every publication proof must be rebuilt.", cut: 2 },
  { id: "commit", label: "Commit changes", detail: "A repair creates a new commit. Earlier intent remains, but validation and exact-head proof must run again for the new SHA.", cut: 5 },
  { id: "ci", label: "CI fails", detail: "The draft proof remains historical evidence, but current readiness is revoked and the task returns to PR_ACTIVE.", cut: 7 },
  { id: "review", label: "Review opens", detail: "A blocking review or open thread revokes readiness until the comment is classified, authorized, repaired if needed, and fully revalidated.", cut: 7 },
];

export default function EvidenceChainPage() {
  const [selected, setSelected] = useState(0);
  const [breakpoint, setBreakpoint] = useState("none");
  const scenario = useMemo(() => breakpoints.find((item) => item.id === breakpoint) ?? breakpoints[0], [breakpoint]);
  const proof = proofs[selected];

  return (
    <main className="doc-shell evidence-shell">
      <DocNav current="evidence" />
      <section className="doc-intro evidence-intro">
        <div>
          <span className="section-number">04 / EVIDENCE CHAIN</span>
          <h1>Trust travels<br /><em>with the SHA.</em></h1>
        </div>
        <p>Each link carries forward the exact facts needed by the next gate. Select a record to inspect its proof—or introduce a change to see where trust stops.</p>
      </section>

      <section className="chain-lab" aria-label="Interactive evidence chain">
        <div className="chain-controls">
          <span>INTRODUCE A CHANGE</span>
          <div role="group" aria-label="Evidence invalidation scenarios">
            {breakpoints.map((item) => (
              <button
                key={item.id}
                className={breakpoint === item.id ? "active" : ""}
                onClick={() => {
                  setBreakpoint(item.id);
                  if (item.cut < proofs.length && selected >= item.cut) setSelected(Math.max(0, item.cut - 1));
                }}
                aria-pressed={breakpoint === item.id}
              >{item.label}</button>
            ))}
          </div>
        </div>

        <div className="scenario-line" aria-live="polite">
          <span className={breakpoint === "none" ? "healthy" : "broken"}>{breakpoint === "none" ? "CHAIN INTACT" : "CHAIN INVALIDATED"}</span>
          <p>{scenario.detail}</p>
        </div>

        <div className="proof-chain" role="group" aria-label="Evidence records in order">
          {proofs.map((item, index) => {
            const invalid = index >= scenario.cut;
            const complete = !invalid && index < scenario.cut;
            return (
              <div className="proof-wrap" key={item.id}>
                <button
                  className={`proof-node ${selected === index ? "selected" : ""} ${invalid ? "invalid" : complete ? "complete" : ""}`}
                  onClick={() => setSelected(index)}
                  aria-pressed={selected === index}
                  aria-label={`${item.title}${invalid ? ", invalidated by current scenario" : ", trusted in current scenario"}`}
                >
                  <span className="proof-index">{String(index + 1).padStart(2, "0")}</span>
                  <span className="proof-status" aria-hidden="true">{invalid ? "×" : "✓"}</span>
                  <span className="proof-short">{item.short}</span>
                </button>
                {index < proofs.length - 1 && <span className={`proof-link ${index + 1 >= scenario.cut ? "invalid" : ""}`} aria-hidden="true">→</span>}
              </div>
            );
          })}
        </div>

        <article className={`proof-detail ${selected >= scenario.cut ? "invalid" : ""}`} aria-live="polite">
          <div className="proof-detail-heading">
            <span>{proof.id} / {String(selected + 1).padStart(2, "0")}</span>
            <h2>{proof.title}</h2>
            <p>{proof.custodian}</p>
          </div>
          <dl className="proof-facts">
            <div><dt>WHAT IS RECORDED</dt><dd>{proof.record}</dd></div>
            <div><dt>WHAT IT PROVES</dt><dd>{proof.proves}</dd></div>
            <div><dt>BOUND TO</dt><dd>{proof.binding}</dd></div>
            <div><dt>UNLOCKS</dt><dd>{proof.unlocks}</dd></div>
          </dl>
          <div className="proof-invalidation">
            <span>INVALIDATION RULE</span>
            <p>{proof.invalidatedBy}</p>
          </div>
        </article>
      </section>

      <section className="binding-equation" aria-label="Exact-head binding">
        <span className="equation-label">THE PUBLICATION INVARIANT</span>
        <div className="equation-flow">
          <strong>Validated commit C</strong><span>=</span><strong>Clean local HEAD</strong><span>=</span><strong>Remote branch SHA</strong><span>=</span><strong>Draft PR head SHA</strong>
        </div>
        <p>If any equality breaks, the prior pass cannot travel forward.</p>
      </section>

      <section className="evidence-principles">
        <div className="section-heading"><span>WHY THE CHAIN HOLDS</span><h2>Five rules prevent trust drift.</h2></div>
        <div className="principle-grid">
          <article><span>01</span><h3>Append, don’t overwrite</h3><p>Corrections and tombstones preserve the audit trail instead of rewriting history.</p></article>
          <article><span>02</span><h3>Bind exact versions</h3><p>Briefs, policies, prompts, configuration, contracts, commits, and evidence carry immutable identifiers.</p></article>
          <article><span>03</span><h3>Prove with direct evidence</h3><p>Agent summaries may explain a result, but only stored typed assertions can satisfy a gate.</p></article>
          <article><span>04</span><h3>Fail closed on mismatch</h3><p>Stale, ambiguous, missing, or out-of-order facts remain evidence but cannot grant authority.</p></article>
          <article><span>05</span><h3>End with a human</h3><p>Handoff records responsibility; it never claims the pull request was merged, deployed, or released.</p></article>
        </div>
      </section>

      <footer className="site-footer"><span>MATHEWS / EVIDENCE CHAIN</span><span>Select a link or introduce a change</span></footer>
    </main>
  );
}
