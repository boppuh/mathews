"use client";

import { useEffect, useMemo, useState } from "react";
import { DocNav } from "../components/doc-nav";

type ItemStatus = "pending" | "passed" | "blocked";
type GateItem = { id: string; title: string; instruction: string; evidence: string; stop?: string };
type Phase = { id: string; number: string; title: string; purpose: string; items: GateItem[] };
type ItemState = { status: ItemStatus; note: string };
type RunMeta = { runId: string; mathewsSha: string; acceptanceBase: string; owner: string; startedUtc: string };

const phases: Phase[] = [
  {
    id: "freeze",
    number: "0",
    title: "Freeze the run",
    purpose: "Create the external report and bind every mutable input before task intake.",
    items: [
      { id: "run-record", title: "Create the external working report", instruction: "Use a mode-0700 recording directory outside both Git worktrees. Assign gate owner, operator, recorder, and defect owner.", evidence: "Gate run ID, UTC start time, named roles, recording-directory control" },
      { id: "source-freeze", title: "Freeze source repositories", instruction: "Record clean Mathews main and acceptance-repository base commits as full SHAs. Use a disposable acceptance branch.", evidence: "Mathews SHA, repository ID/name, base branch and SHA, clean-status record", stop: "Abort if either worktree is dirty or any revision is ambiguous." },
      { id: "authority-freeze", title: "Freeze configuration and authority", instruction: "Record repository configuration ID/version/digest, active policy, promoted prompts, and evaluation-contract versions.", evidence: "IDs, versions, ordered memberships, canonical fingerprints" },
      { id: "harness-freeze", title: "Freeze the acceptance harness", instruction: "Record simulator runtime, device type, flow/fixture versions, and exact required GitHub check names.", evidence: "Runtime/device/flow IDs and required-check list", stop: "Abort if any repository-level value is unversioned, missing, ambiguous, or broader than the configured repository." },
    ],
  },
  {
    id: "readiness",
    number: "1",
    title: "Environment readiness",
    purpose: "Prove the workstation, secrets, GitHub boundary, webhook ingress, host, simulator, and local services are ready.",
    items: [
      { id: "dependencies", title: "Verify workstation dependencies", instruction: "Use Node 22+, npm 10, Python 3.13, uv, Docker Compose, Xcode, and the configured simulator runtime. Install without changing lockfiles.", evidence: "Exact tool versions and clean worktree after installation" },
      { id: "configuration", title: "Validate configuration and Keychain custody", instruction: "Run the credential-free configuration check and verify every required Keychain reference exists without printing a value.", evidence: "Successful redacted configuration report and opaque reference presence" },
      { id: "github-authority", title: "Verify least-privilege GitHub authority", instruction: "Confirm the private App targets only the acceptance repository, has the exact allowed permissions/events, and branch protection reserves merge for a human.", evidence: "Installation/repository binding, permission snapshot, event subscriptions" },
      { id: "webhook", title: "Verify temporary signed webhook ingress", instruction: "Forward only the bounded webhook path, preserve body and headers exactly, and observe one real signed GitHub delivery before intake.", evidence: "Public hostname, process identity, start time, verified delivery ID", stop: "Any changed bytes, headers, method, or path is NO-GO." },
      { id: "host-simulator", title: "Preflight host and simulator", instruction: "Verify the launchd-owned private socket, host journal, authenticated health boundary, exact base, clean simulator, pinned scheme, fixture, account recipe, and source closure.", evidence: "Host/preflight results and harness digests" },
      { id: "services", title: "Start services and authenticate", instruction: "Start PostgreSQL/migrations, API, worker, and web separately. Keep launchd as the only host agent. Confirm health and bootstrap the local operator only if needed.", evidence: "Health results, migration result, authenticated local session" },
    ],
  },
  {
    id: "baseline",
    number: "2",
    title: "Baseline verification",
    purpose: "Prove the frozen Mathews commit is healthy before it mutates the acceptance repository.",
    items: [
      { id: "check", title: "Run the complete non-build checks", instruction: "Run npm run check against the frozen Mathews SHA.", evidence: "UTC start/end, exit status, concise redacted result" },
      { id: "build", title: "Build the complete workspace", instruction: "Run npm run build without modifying the frozen worktree.", evidence: "UTC start/end, exit status, concise redacted result" },
      { id: "postgres", title: "Run the PostgreSQL integration suite", instruction: "Run npm run test:postgres against a disposable schema. A dependency-related skip does not pass.", evidence: "Server identity, disposable schema, pass/skip counts, result", stop: "Any failed or skipped required baseline command is NO-GO." },
    ],
  },
  {
    id: "golden-path",
    number: "3",
    title: "Recorded golden path",
    purpose: "Deliver one real iOS change through steering, implementation, validation, two review-repair paths, readiness, and handoff.",
    items: [
      { id: "request", title: "Create the bounded acceptance request", instruction: "Choose a small, nontrivial ordinary-app change with at least two typed criteria and the pinned simulator flow; avoid harness, dependency, signing, release, and broad refactor work.", evidence: "Redacted exact request, expected outcome, base SHA" },
      { id: "steering", title: "Exercise steering and freeze the successor brief", instruction: "Create the task, record initial brief/contract, send one scope-affecting refinement, prove predecessors are fenced, then freeze the regenerated brief and contract.", evidence: "Task/intake IDs, predecessor/successor brief and contract IDs/versions/digests, steering evidence" },
      { id: "authorization", title: "Record exactly one authorization outcome", instruction: "Bind either one exact-version human approval or one unambiguous policy bypass—never both or neither—to the accepted brief, frozen contract, and active policy.", evidence: "Approval decision or policy-bypass identity and exact bindings", stop: "A missing, duplicate, stale, or mismatched authorization is NO-GO." },
      { id: "implementation", title: "Implement through mediated tools", instruction: "Let Mathews create the owned workspace and run Hermes with bounded context. The host alone creates the candidate commit and tree.", evidence: "Workspace, job, lease, Hermes run, policy/prompt bindings, commit/tree SHAs" },
      { id: "validation", title: "Validate the exact candidate", instruction: "Run required build/tests and the clean simulator journey. If the approved deliberate failure occurs, record it and fully validate the repaired successor SHA.", evidence: "Run/attempt IDs, contract/configuration versions, assertions, artifacts, candidate/tree SHAs" },
      { id: "draft", title: "Publish one verified draft PR", instruction: "Push only the passing candidate and prove local HEAD, remote branch, and draft PR head equal the validated SHA.", evidence: "Branch, PR URL/number, local/remote/PR SHAs, webhook deliveries, required checks" },
      { id: "rule-repair", title: "Exercise the preapproved repair path", instruction: "Post one controlled comment matching the active low-risk rule. Confirm an automatic repair creates a fresh head, fully revalidates, and updates the same draft PR without human approval.", evidence: "Comment/thread, rule fingerprint, job/effect, predecessor/successor SHAs, fresh validation and CI" },
      { id: "human-repair", title: "Exercise the human one-off repair path", instruction: "Post one controlled unmatched or scope-expanding comment. Confirm exactly one REVIEW_CONFLICT blocks work until recent reauthentication and exact-fingerprint approval.", evidence: "Comment/thread, classification, approval, predecessor/successor SHAs, fresh validation and CI" },
      { id: "handoff", title: "Reach readiness and explicit handoff", instruction: "Reconcile every exact-head binding, required check, and review; reauthenticate and acknowledge handoff. Verify the final state is HANDED_OFF and the PR remains unmerged.", evidence: "Readiness assessment, acknowledgement event, exact final head, UTC handoff time", stop: "Any merge, tag, deployment, release, archive, export, or signing action is NO-GO." },
    ],
  },
  {
    id: "safety",
    number: "4",
    title: "Safety & recovery matrix",
    purpose: "Pair named automated tests with required live observations for destructive and timing-sensitive behavior.",
    items: [
      { id: "auth-evidence", title: "Authentication and evidence safety", instruction: "Prove exact-origin/CSRF controls, recent reauthentication, deterministic redaction, access classes, correction, deletion, and tombstones; complete every required live denial/retention observation.", evidence: "Individual pytest node results plus five separate live-observation rows" },
      { id: "leases", title: "Leases, fencing, restart, and duplicate effects", instruction: "Run every named lease/journal test and safely restart API/worker and launchd host only at a documented checkpoint.", evidence: "Node results, checkpoint, restart observation, proof of no duplicated external effect" },
      { id: "cancellation", title: "Cancellation", instruction: "Run the cancellation suite, then cancel disposable tasks once during Hermes activity and once during a host operation.", evidence: "Two terminal CANCELLED tasks, revoked authority, bounded partial evidence, ignored late results" },
      { id: "outages", title: "Dependency outages and resumption", instruction: "Exercise bounded Hermes, host, pre-PR GitHub, and post-PR GitHub outages; restore each and prove checkpoint resumption without duplicate effects.", evidence: "Attempts, retry counts, escalation approvals, old/new generations, recovery results" },
      { id: "webhooks", title: "Webhook ordering and ambiguity", instruction: "Run duplicate, stale, old-head, unknown, conflict, unreadable, and ambiguous delivery tests; confirm real signed events advance only with exact correlation.", evidence: "Individual node results and real delivery/correlation observation" },
      { id: "exact-head", title: "Exact-head and readiness binding", instruction: "Run every mismatch/readiness/handoff test and compare all final identifiers at readiness and handoff.", evidence: "Local, remote, PR, validation, tree, configuration, contract, policy equality" },
      { id: "review-auth", title: "Review-repair authorization", instruction: "Run every rule-bound and one-off repair test; record the two live repair cycles separately.", evidence: "Individual node results plus preapproved and human one-off live rows" },
      { id: "learning", title: "Governed learning and rollback", instruction: "Create non-authoritative learning output, prove invalid and unauthenticated promotion attempts fail, then perform one exact human promotion and immutable rollback.", evidence: "Citations, candidate/evaluation, rejection evidence, rule/policy/activation IDs, rollback successor" },
    ],
  },
  {
    id: "reconcile",
    number: "5",
    title: "Evidence reconciliation",
    purpose: "Compare the working report with durable records and GitHub. Eventual-consistency explanations do not pass.",
    items: [
      { id: "source-equality", title: "Reconcile source and candidate", instruction: "Prove frozen base equals workspace predecessor and host candidate equals clean local HEAD and validation tree.", evidence: "Base, predecessor, commit, local HEAD, tree, validation input" },
      { id: "publication-equality", title: "Reconcile publication and readiness", instruction: "Prove remote branch, draft PR head, passing validation, CI/review, readiness assessment, and handoff all bind the same final head.", evidence: "Exact final SHA across every publication/readiness dimension" },
      { id: "authority-equality", title: "Reconcile authority and governance", instruction: "Prove brief authorization, steering successor, both review repairs, learning citations, policy promotion, and rollback each bind their exact immutable inputs.", evidence: "IDs, versions, fingerprints, predecessor/successor relationships" },
      { id: "effects-equality", title: "Reconcile external effects", instruction: "Confirm exactly one intended branch, PR, repair per path, and handoff—and zero merge, tag, deployment, release, signing, archive, or export effects.", evidence: "Effect ledger and GitHub observations", stop: "Any mismatch, missing evidence, duplicate effect, or unauthorized effect is NO-GO." },
    ],
  },
  {
    id: "cleanup",
    number: "6",
    title: "Cleanup",
    purpose: "Remove temporary exposure while retaining the durable audit trail required by policy.",
    items: [
      { id: "pr-state", title: "Leave the generated PR in its observed draft state", instruction: "Do not merge it. Use only separate human cleanup decisions outside the gate when needed.", evidence: "Final draft/unmerged PR observation" },
      { id: "companions", title: "Close disposable companion work safely", instruction: "Cancel or close companion tasks through supported paths and confirm only owned workspaces/processes are cleaned.", evidence: "Terminal task states and cleanup evidence" },
      { id: "recover", title: "Restore dependencies and health", instruction: "Remove temporary blocks and confirm all Mathews and host health checks recover.", evidence: "Restored service and health results" },
      { id: "ingress", title: "Remove temporary webhook ingress", instruction: "Stop the ingress, restore the prior GitHub App webhook URL, revoke relay credentials, and prove the public URL no longer forwards.", evidence: "Stop time, restored URL, revoked relay, negative forwarding check" },
      { id: "secret-scan", title: "Verify secret-free outputs and clean worktrees", instruction: "Confirm no credential/token/cookie/key was written to repositories or report; record expected clean state in both worktrees.", evidence: "Secret review and final git status records" },
    ],
  },
];

const STORAGE_KEY = "mathews-release-gate-v1";
const blankMeta: RunMeta = { runId: "", mathewsSha: "", acceptanceBase: "", owner: "", startedUtc: "" };
const allItems = phases.flatMap((phase) => phase.items);
const itemStatuses = new Set<ItemStatus>(["pending", "passed", "blocked"]);
const knownItemIds = new Set(allItems.map((item) => item.id));

function sanitizeItems(input: unknown): Record<string, ItemState> {
  if (!input || typeof input !== "object") return {};

  const sanitized: Record<string, ItemState> = {};
  for (const [id, value] of Object.entries(input)) {
    if (!knownItemIds.has(id) || !value || typeof value !== "object") continue;
    const candidate = value as { status?: unknown; note?: unknown };
    sanitized[id] = {
      status: itemStatuses.has(candidate.status as ItemStatus) ? candidate.status as ItemStatus : "pending",
      note: typeof candidate.note === "string" ? candidate.note : "",
    };
  }
  return sanitized;
}

function sanitizeMeta(input: unknown): RunMeta {
  if (!input || typeof input !== "object") return blankMeta;
  const candidate = input as Record<string, unknown>;
  return {
    runId: typeof candidate.runId === "string" ? candidate.runId : "",
    mathewsSha: typeof candidate.mathewsSha === "string" ? candidate.mathewsSha : "",
    acceptanceBase: typeof candidate.acceptanceBase === "string" ? candidate.acceptanceBase : "",
    owner: typeof candidate.owner === "string" ? candidate.owner : "",
    startedUtc: typeof candidate.startedUtc === "string" ? candidate.startedUtc : "",
  };
}

function defaultItems() {
  return Object.fromEntries(phases.flatMap((phase) => phase.items.map((item) => [item.id, { status: "pending", note: "" } as ItemState])));
}

export default function MvpReleaseGatePage() {
  const [selectedPhase, setSelectedPhase] = useState(0);
  const [selectedItem, setSelectedItem] = useState(phases[0].items[0].id);
  const [items, setItems] = useState<Record<string, ItemState>>(defaultItems);
  const [meta, setMeta] = useState<RunMeta>(blankMeta);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    const timeout = window.setTimeout(() => {
      try {
        const stored = window.localStorage.getItem(STORAGE_KEY);
        if (stored) {
          const parsed = JSON.parse(stored) as { items?: unknown; meta?: unknown };
          if (parsed.items) setItems((current) => ({ ...current, ...sanitizeItems(parsed.items) }));
          if (parsed.meta) setMeta(sanitizeMeta(parsed.meta));
        }
      } catch {
        // A blocked local store leaves the worksheet usable for this session.
      }
      setLoaded(true);
    }, 0);
    return () => window.clearTimeout(timeout);
  }, []);

  useEffect(() => {
    if (!loaded) return;
    try { window.localStorage.setItem(STORAGE_KEY, JSON.stringify({ items, meta })); } catch { /* session-only fallback */ }
  }, [items, meta, loaded]);

  const counts = useMemo(() => allItems.reduce((sum, item) => {
    sum[items[item.id]?.status ?? "pending"] += 1;
    return sum;
  }, { pending: 0, passed: 0, blocked: 0 }), [items]);
  const metadataComplete = Object.values(meta).every((value) => value.trim().length > 0);
  const decision = counts.blocked > 0 ? "NO-GO" : counts.passed === allItems.length && metadataComplete ? "GO" : "PENDING";
  const phase = phases[selectedPhase];
  const currentItem = allItems.find((item) => item.id === selectedItem) ?? phase.items[0];
  const currentState = items[currentItem.id] ?? { status: "pending", note: "" };

  function updateItem(id: string, update: Partial<ItemState>) {
    setItems((current) => ({ ...current, [id]: { ...(current[id] ?? { status: "pending", note: "" }), ...update } }));
  }

  function choosePhase(index: number) {
    setSelectedPhase(index);
    setSelectedItem(phases[index].items[0].id);
  }

  return (
    <main className="doc-shell release-shell">
      <DocNav current="release" />
      <section className="doc-intro release-intro">
        <div>
          <span className="section-number">05 / MVP RELEASE GATE</span>
          <h1>Prove it before<br /><em>production.</em></h1>
        </div>
        <p>This worksheet follows the authoritative runbook. A single draft PR is necessary—not sufficient. Every required check and live observation must pass.</p>
      </section>

      <section className={`gate-verdict ${decision.toLowerCase()}`} aria-live="polite">
        <div className="verdict-mark"><span>{decision === "GO" ? "✓" : decision === "NO-GO" ? "×" : "…"}</span></div>
        <div className="verdict-copy"><span>CURRENT DECISION</span><strong>{decision}</strong></div>
        <div className="verdict-counts"><span><b>{counts.passed}</b> passed</span><span><b>{counts.pending}</b> pending</span><span><b>{counts.blocked}</b> blocked</span></div>
        <p>{decision === "GO" ? "Every required item passes and the frozen run identity is complete." : decision === "NO-GO" ? "At least one required item is blocked. Fix the cause and perform the runbook-required rerun." : "Complete the frozen run identity and mark every required item passed or blocked."}</p>
      </section>

      <section className="run-identity" aria-label="Frozen run identity">
        <div className="section-heading"><span>FROZEN RUN IDENTITY</span><h2>Bind the report before intake.</h2></div>
        <div className="identity-fields">
          {([
            ["runId", "Gate run ID", "mvp-YYYYMMDD-NN"],
            ["mathewsSha", "Mathews main SHA", "40-character commit"],
            ["acceptanceBase", "Acceptance base SHA", "40-character commit"],
            ["owner", "Gate owner", "Person or account"],
            ["startedUtc", "UTC start time", "YYYY-MM-DDTHH:MM:SSZ"],
          ] as const).map(([key, label, placeholder]) => (
            <label key={key}><span>{label}</span><input value={meta[key]} placeholder={placeholder} onChange={(event) => setMeta((current) => ({ ...current, [key]: event.target.value }))} /></label>
          ))}
        </div>
        <p className="local-note">Working state is stored only in this browser. The redacted acceptance report remains authoritative.</p>
      </section>

      <section className="gate-workbench" aria-label="Release gate checklist">
        <div className="gate-phase-rail" role="group" aria-label="Release gate phases">
          {phases.map((entry, index) => {
            const phaseStates = entry.items.map((item) => items[item.id]?.status ?? "pending");
            const status = phaseStates.includes("blocked") ? "blocked" : phaseStates.every((value) => value === "passed") ? "passed" : "pending";
            return <button key={entry.id} className={`${selectedPhase === index ? "selected" : ""} ${status}`} onClick={() => choosePhase(index)} aria-pressed={selectedPhase === index}><span>PHASE {entry.number}</span><strong>{entry.title}</strong><i>{status}</i></button>;
          })}
        </div>

        <div className="phase-intro"><span>PHASE {phase.number}</span><h2>{phase.title}</h2><p>{phase.purpose}</p></div>

        <div className="gate-checklist">
          <div className="checklist-list" role="group" aria-label={`${phase.title} requirements`}>
            {phase.items.map((item, index) => {
              const state = items[item.id] ?? { status: "pending", note: "" };
              return <button key={item.id} className={`${selectedItem === item.id ? "selected" : ""} ${state.status}`} onClick={() => setSelectedItem(item.id)} aria-pressed={selectedItem === item.id}><span>{String(index + 1).padStart(2, "0")}</span><strong>{item.title}</strong><i>{state.status === "passed" ? "✓" : state.status === "blocked" ? "×" : "—"}</i></button>;
            })}
          </div>

          <article className={`check-detail ${currentState.status}`}>
            <div className="check-detail-head"><span>REQUIRED CHECK</span><h3>{currentItem.title}</h3></div>
            <div className="check-instruction"><span>INSTRUCTION</span><p>{currentItem.instruction}</p></div>
            <div className="check-evidence"><span>RECORD AS EVIDENCE</span><p>{currentItem.evidence}</p></div>
            {currentItem.stop && <div className="check-stop"><span>STOP CONDITION</span><p>{currentItem.stop}</p></div>}
            <div className="status-actions" role="group" aria-label={`Status for ${currentItem.title}`}>
              {(["pending", "passed", "blocked"] as const).map((status) => <button key={status} className={currentState.status === status ? "active" : ""} onClick={() => updateItem(currentItem.id, { status })} aria-pressed={currentState.status === status}>{status}</button>)}
            </div>
            <label className="evidence-note"><span>EVIDENCE REFERENCE / REDACTED NOTE</span><textarea value={currentState.note} placeholder="Durable ID, content hash, timestamp, or redacted report reference" onChange={(event) => updateItem(currentItem.id, { note: event.target.value })} /></label>
          </article>
        </div>
      </section>

      <section className="decision-rules">
        <div className="section-heading"><span>DECISION RULE</span><h2>GO requires the whole system.</h2></div>
        <div className="decision-grid">
          <article><span>GO</span><p>All baseline commands pass; the golden task reaches HANDED_OFF; both review paths, recovery matrix, live observations, governance, reconciliation, and cleanup pass with no unexplained deviation.</p></article>
          <article><span>NO-GO</span><p>Any missing evidence, skipped required check, unresolved defect, exact-head mismatch, duplicate or unauthorized effect, secret exposure, merge, tag, signing, deployment, or release.</p></article>
          <article><span>AFTER GO</span><p>Publish only the redacted report and execution-plan update through a dedicated pull request. Production-roadmap work begins only after that PR merges.</p></article>
        </div>
      </section>

      <footer className="site-footer"><span>MATHEWS / MVP RELEASE GATE</span><span>Authoritative source: MVP_RELEASE_GATE_RUNBOOK.md</span></footer>
    </main>
  );
}
