"use client";

import { useMemo, useState } from "react";
import { DocNav } from "../components/doc-nav";

const terms = [
  ["Acceptance criterion", "Evidence", "A typed requirement that must be PASSED, FAILED, BLOCKED, or PENDING and cites the direct evidence used to decide it."],
  ["Ambiguous effect", "Recovery", "An external mutation that may have happened but lacks a durable, trustworthy result. It must be observed or escalated, never blindly reissued."],
  ["Approval request", "Authority", "A durable, fingerprint-bound request for the smallest human decision needed to proceed, revise, retry, deny, reject, abandon, or cancel."],
  ["Artifact", "Evidence", "Content-addressed bytes—such as logs or test output—stored under an immutable SHA-256 identity and rehashed when read."],
  ["Brief", "Workflow", "The versioned translation of a request into scope, exclusions, typed criteria, risks, affected flow, allowed work, and a validation plan."],
  ["Brief approval policy", "Authority", "The versioned rule that chooses either one recorded low-risk policy bypass or exact-version human approval for a complete brief."],
  ["Candidate commit", "Git", "The host-created commit C whose clean tree is the sole code state eligible for validation and draft publication."],
  ["Cancellation fence", "Recovery", "The durable revocation of jobs, leases, tool grants, and pending authority that prevents late work from advancing a cancelled task."],
  ["Checkpoint", "Recovery", "Persisted progress from which a current job generation can safely resume after retry or restart without replaying completed effects."],
  ["Control plane", "Architecture", "The authoritative API and workflow core that owns task state, policy enforcement, tool brokerage, evidence, jobs, and GitHub correlation."],
  ["Correction", "Evidence", "An append-only successor to an evidence record. It preserves the original and its provenance instead of overwriting history."],
  ["Draft-PR proof", "Git", "Immutable evidence that clean local HEAD, remote branch SHA, draft PR head, and validated commit C are equal."],
  ["Durable job", "Recovery", "A database-backed unit of work with inputs, generation, checkpoint, retry history, lease, and stable effect identities."],
  ["Escalation", "Workflow", "A resumable pause containing the blocked operation, prior and resume state, retry history, evidence, and smallest required decision."],
  ["Evidence", "Evidence", "A canonical, redacted, hashed source record with task, actor, origin, timestamps, correlation, access, and retention metadata."],
  ["Exact-head binding", "Git", "The invariant that validation, local HEAD, remote branch, pull-request head, CI, reviews, readiness, and handoff refer to one exact commit."],
  ["Fencing token", "Recovery", "A monotonically current lease token. Only its holder may append an effect result or advance a checkpoint; older holders are stale."],
  ["HANDED_OFF", "Workflow", "A terminal autonomous-work state showing a human accepted responsibility for merge, deployment, delivery, and release. It does not mean any occurred."],
  ["Hermes", "Architecture", "The external reasoning runtime that may propose work and request mediated tools but cannot approve itself, call the host directly, commit, push, or move task state."],
  ["Host agent", "Architecture", "The narrow macOS LaunchAgent that owns named Xcode, Simulator, process, workspace, artifact, Git commit, and Git push operations."],
  ["Idempotency key", "Recovery", "A stable identity allowing an effect or transition to be retried or replayed without producing a second logical result."],
  ["Lease", "Recovery", "Time-bounded ownership of a durable job, defined by owner, expiry, heartbeat, attempt, and fencing token."],
  ["Policy bypass", "Authority", "A recorded authorization for an unambiguous, complete, low-risk brief whose operations and paths already satisfy the active versioned policy."],
  ["Policy version", "Authority", "An immutable executable authority set that binds promoted prompts, review rules, thresholds, and lineage at a specific version."],
  ["Preflight", "Operations", "A read-only verification that configuration, repository/base, host, Git safety, simulator, harness, fixtures, account recipe, and required secrets are usable."],
  ["PR_ACTIVE", "Workflow", "The state in which a verified draft PR exists and Mathews observes correlated CI and review signals. It is the core MVP delivery outcome."],
  ["READY_FOR_HUMAN_MERGE", "Workflow", "A reversible state proving the exact current draft head has valid evidence, passing required CI, no blocking review, and authorized repairs."],
  ["Reauthentication", "Authority", "A recent password verification that rotates the local session and gates sensitive configuration, approval, promotion, and terminal actions."],
  ["Reconciliation", "Recovery", "Read-only comparison of durable intent with journals and external systems before deciding whether an effect completed, is absent, or remains ambiguous."],
  ["Repository configuration", "Authority", "A versioned, digested record of repository, Git, Xcode, operation, assertion, artifact, prohibited-path, and secret-reference settings."],
  ["Review rule", "Authority", "A human-approved, immutable classifier boundary that may authorize only a narrow low-risk repair matching its exact category, action, labels, and paths."],
  ["Rule candidate", "Learning", "A cited, evaluated, explicitly non-authoritative proposal. It grants no capability until separate human-governed promotion creates executable authority."],
  ["State transition", "Workflow", "A control-plane-only movement between task states that stores actor, cause, time, policy version, and evidence references."],
  ["Steering", "Workflow", "An auditable user message. Scope-affecting steering fences active work, invalidates the prior brief and contract, and returns the task to BRIEFING."],
  ["Tombstone", "Evidence", "An append-only record explaining that source content was deleted and why, while ensuring the bytes and derived retrieval material stay unavailable."],
  ["Tool grant", "Authority", "Short-lived, task-state-bound permission for Hermes to request one scoped operation through the control plane."],
  ["Validation contract", "Evidence", "The versioned machine-evaluable definition of success: criteria, verifier kinds, assertion keys, required artifacts, and repository configuration."],
  ["Validation run", "Evidence", "A result bound to the exact candidate commit, tree, contract, configuration, operations, artifacts, and criterion-level assertions."],
  ["Webhook delivery", "Git", "A signed, durably received GitHub event identified and correlated by delivery, installation, repository, PR, branch, and exact head SHA."],
  ["Working report", "Operations", "The external, mode-0700 release-gate record used during execution. Only its completed redacted form may enter the repository."],
] as const;

const categories = ["All", ...Array.from(new Set(terms.map((term) => term[1])))] as string[];

export default function GlossaryPage() {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("All");
  const visible = useMemo(() => terms.filter(([term, group, definition]) => (category === "All" || group === category) && `${term} ${definition}`.toLowerCase().includes(query.toLowerCase().trim())), [query, category]);
  return <main className="doc-shell glossary-shell"><DocNav current="glossary" />
    <section className="doc-intro glossary-intro"><div><span className="section-number">08 / GLOSSARY</span><h1>Precise words.<br /><em>Precise authority.</em></h1></div><p>The shared language of Mathews. Search by term or meaning, or narrow the field by system domain.</p></section>
    <section className="glossary-tools" aria-label="Glossary filters"><label><span>SEARCH TERMS</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Try “exact head”, “lease”, or “approval”…" /></label><div role="group" aria-label="Glossary categories">{categories.map((item) => <button key={item} type="button" className={category === item ? "active" : ""} onClick={() => setCategory(item)} aria-pressed={category === item}>{item}</button>)}</div><p aria-live="polite"><strong>{visible.length}</strong> of {terms.length} terms</p></section>
    <section className="glossary-list">{visible.length ? visible.map(([term, group, definition], index) => <article key={term}><span>{String(index + 1).padStart(2,"0")}</span><div><small>{group}</small><h2>{term}</h2></div><p>{definition}</p></article>) : <div className="glossary-empty"><span>NO MATCH</span><p>Try a broader term or select All.</p></div>}</section>
    <section className="language-rule"><span>LANGUAGE RULE</span><p>A Mathews term names a durable record, bounded capability, explicit state, or verifiable relationship. If a word cannot be tied to one of those, it cannot satisfy a gate.</p></section>
    <footer className="site-footer"><span>MATHEWS / GLOSSARY</span><span>{terms.length} defined terms</span></footer>
  </main>;
}
