# Autonomous iOS Delivery Workflow

## Purpose

Provide a Codex-like workspace that turns a rough idea, product-meeting note,
bug, or ad-hoc test finding into a verified iOS change and a pull request. The
system must preserve human control over scope, risky actions, merge decisions,
and changes to engineering policy.

## Product experience

The chat is the control plane. A user can describe work in natural language,
review the generated brief, redirect an active task, inspect evidence, and
make approval decisions.

The workspace also includes:

- **Work queue:** active tasks, stage, owner, blockers, and pull-request state.
- **Evidence panel:** acceptance criteria, test output, simulator artifacts,
  app and network logs, performance findings, and known risks.
- **Rule Inbox:** proposed review rules with evidence and human decisions.

### Real-time task cockpit

Chat is used to create, steer, and discuss work, but it is not the sole record
of progress. Each task has a dedicated live screen so meaningful state does not
disappear into raw logs or scattered messages.

The screen includes:

- a persistent stage timeline: Briefing, Implementation, Validation, Repair,
  Pull Request, CI and Review, Ready for Human Merge, Handoff, Merge, and
  Delivery;
- a live agent activity feed that summarizes actions in plain language while
  keeping raw output collapsed and available on demand;
- an evidence checklist that maps every acceptance criterion and required test
  to its current pass, fail, pending, or blocked result;
- a prominent approval and blocker queue; and
- focused tabs for diffs, test artifacts, app and network logs, pull-request and
  CI state, and the Rule Inbox.

Hermes event streams provide the live activity plumbing. The control plane
normalizes those events, persists them, and presents them as task-level status
and evidence rather than an unstructured transcript.

## Architecture

Use two layers.

### Hermes: agent runtime

Hermes executes agent work: conversations, tools, short-lived approvals,
subagents, streamed progress, retries, and session context. Integrate it via
its API or JSON-RPC interface; do not make its session history the source of
truth for the product.

Hermes never connects directly to a repository host, GitHub credential, secret
store, or workflow database. Every side effect passes through a control-plane
tool broker that authorizes a typed operation against the current task, role,
repository, and policy version. A Hermes approval prompt is only a transport
pause; the durable control-plane approval decision is authoritative.

### Hermes learning versus delivery learning

The system complements Hermes rather than replacing its memory or skills.

Hermes is responsible for **agent-level learning**: remembering useful operating
context, reusing procedures, searching prior sessions, and improving how an
agent carries out recurring work. This information is optimized for the agent's
own context and execution.

The control plane and Evidence Ledger are responsible for **delivery-level
learning**: preserving verified engineering outcomes across tasks. They store
the immutable links between a task, approved scope, code state, tests, logs,
pull request, CI result, review feedback, and human decision. This information
is optimized for auditability, task visibility, reproducibility, and safe
governance.

Use this boundary:

- Hermes proposes, executes, summarizes, and learns operational procedures.
- The workflow service (the control-plane state machine in the MVP) decides
  transitions, and the control-plane command path is the only writer of
  authoritative task state.
- The Evidence Ledger records raw evidence and evaluates whether derived
  knowledge improves delivery quality or token efficiency.
- A human approves any change that would become an engineering rule, policy,
  permission, or required validation step.

Do not duplicate Hermes session memory into the Evidence Ledger by default, and
do not let an Evidence Ledger retrieval result silently update Hermes memory or
skills. Exchange only scoped, verified context and human-approved rules.

### Control plane: workflow system of record

Build a small service and persistent store that owns task lifecycle and audit
history. It records:

- original request, accepted task brief, and approval disposition;
- workflow stage and transition history;
- Hermes run references and sanitized streamed events;
- diffs, commits, test results, simulator media, logs, and network evidence;
- pull-request, CI, and review-comment state;
- approvals, escalations, retry attempts, and final outcome;
- proposed and approved review rules.

Use artifact storage for large logs and media. Treat the database record as the
durable audit trail, and use GitHub webhooks to resume a task when CI or review
state changes.

### Prompt compiler: lightweight, versioned task translation

Do not build a separate prompt-engineering product initially. The control plane
contains a small prompt compiler that translates the accepted, versioned task
record into structured, role-specific instructions for Hermes.

It supplies the planner, implementer, validator, pull-request agent, and
reviewer with the information each needs: task context, repository conventions,
scope, acceptance criteria, required iOS flow, tool permissions, guardrails,
current evidence, and approved review rules. Templates are versioned and tested
like other product behavior. The task record, rather than free-form chat alone,
is the source for prompt inputs.

Hermes remains the runtime responsible for model interaction, tool execution,
memory, subagents, approvals, and streamed events. The prompt compiler improves
consistency and handoff quality without duplicating Hermes's agent runtime.

Evaluate prompt versions against representative tasks: verify that briefs are
complete, scope stays bounded, test plans are usable, and validation outcomes
match actual user-visible behavior. Promote a new template only when it improves
these outcomes without increasing unnecessary escalation or review noise.

## Workflow state machine

1. **Intake** — capture a rough task from chat, a meeting, testing, or another
   source.
2. **Briefing** — generate a versioned implementation brief: context, scope,
   acceptance criteria, risks, affected user flows, and test plan. A
   deterministic ambiguity and policy check either accepts the brief or sends
   its exact hash for human approval.
3. **Ready and host allocation** — verify repository configuration, execution
   budget, and an authorized compatible host before mutation.
4. **Implementation** — make only the scoped code changes and capture the exact
   resulting commit.
5. **Validation** — run required unit and integration tests plus the
   production-like iOS flow against that commit.
6. **Repair** — if validation finds a product defect, summarize the evidence,
   make a novel scoped fix, and return to validation within a per-class budget.
7. **Pull request** — push the validated commit and idempotently open a draft PR
   whose head SHA exactly matches the validation decision.
8. **CI and review** — ingest CI results and review comments concurrently,
   classify them, repair only policy-approved low-risk in-scope issues, and
   revalidate every changed head.
9. **Ready for human merge or handoff** — declare readiness only when the
   current head satisfies validation, CI, and review policy. A human still owns
   merge; an explicit handoff is a distinct successful outcome.
10. **Merged and delivered** — record GitHub merge and, where configured,
    repository-defined delivery evidence as separate later outcomes.

There is no ambiguous generic `Complete` state. Every transition states what
evidence caused it. `Escalated` is a durable pause with a recorded resume state
and one decision required; an unexpired decision may resume, fail, or cancel the
task after current policy is rechecked.

## iOS validation contract

Validation must prove that the user can complete the changed flow, not merely
that code compiles. The initial contract should include:

- the production-like scheme and appropriate signed build where required;
- an end-to-end simulator or device flow from entry point to successful outcome;
- unit and integration checks relevant to the change;
- application crash and error-log review;
- network request and failure review;
- performance checks relevant to the affected flow;
- a concise pass/fail report tied to each acceptance criterion.

The first delivery slice supports one configured user journey. A task may add
task-specific assertions only from the repository's versioned, typed assertion
catalog; it may not invent executable validation scripts at runtime. A request
whose user outcome is outside that coverage escalates during Briefing for a
contract or scope decision.

When a result cannot be verified, the task goes to Repair or Escalated; it must
not be marked ready or handed off.

## Guardrails

- **Scope:** changes stay tied to the accepted task brief; new product decisions pause
  for approval.
- **Retry budget:** use a small fixed repair limit. Repeated or identical
  failures escalate with evidence instead of looping indefinitely.
- **Safety:** signing, secrets, production data, release configuration,
  analytics, and remote configuration require explicit approval.
- **Testing:** no normal PR transition without the required verification result
  bound to the exact commit that will become the PR head.
- **Review:** automatically repair only factual, low-risk, in-scope comments
  allowed by the active policy; escalate conflicting, speculative, sensitive,
  or scope-expanding feedback.
- **Merge:** keep human merge approval until the process has earned trust.
- **Audit:** retain task decisions, evidence, failures, and residual risk.

## Rule Inbox and continuous improvement

The system may propose a new review rule but never activates one automatically.
Each candidate includes:

- the proposed, testable rule;
- source evidence: a reproducible defect, failing test, CI failure, incident, or
  specific review finding;
- root cause and confirmed effective fix;
- severity, intended scope, recurrence assessment, and false-positive risks.

A human reviewer can approve, edit and approve, reject, or defer the proposal.
Approved rules enter a versioned review harness with an owner and review date.
Rejected proposals become feedback to reduce future noise. Promote a rule after
one high-severity incident or two independent confirmed occurrences.

## Domain-neutral Evidence Ledger and continual learning

Pine is an inspiration for integrity mechanics, not a direct dependency for the
delivery workflow. Its current financial domain model and local storage must not
become the general knowledge system.

Use four distinct planes:

1. **Source records** are authoritative, immutable evidence: accepted requests
   and approval dispositions, code diffs and repository trees, test and CI
   artifacts, review comments, tool invocations, and task events. Each record
   stores canonical content, a content hash, origin, capture time, access
   classification, parser version, lineage, and retention policy. Corrections
   are new records or tombstones, never edits.
2. **Derived knowledge** is non-authoritative and versioned: concise summaries,
   incident patterns, proposed rules, decisions, and entities. Every item names
   its exact source evidence and derivation version, and is marked candidate,
   evaluated, approved, superseded, or revoked.
3. **Retrieval indexes** are disposable and rebuildable: chunks, embeddings,
   lexical indexes, and graph edges. They reference evidence records, preserve
   access controls and freshness, and never become the source of truth.
4. **Evaluation and approval** governs promotion. Offline evaluations measure
   citation accuracy, staleness, access-control leakage, task outcome, token
   cost, and review noise. Only human approval promotes a rule into the
   workflow control plane.

### Token-efficient retrieval

Agents retrieve a narrow, verified set of evidence using hybrid lexical and
semantic search with metadata, access, repository, and time filters. They begin
with compact, versioned summaries and expand to original source passages only
when uncertainty or decision impact requires it. Cache deterministic document,
pull-request, and CI digests by content hash; retain multi-resolution summaries.

Persist the retrieval-set identifier, chunk hashes, model and prompt versions,
token cost, and quality outcome for each run. This makes retrieval and
compression measurable and improvable. Unverified mutable notes remain working
memory only; they cannot enter the high-trust corpus or create policy.

### Adoption path

1. Keep Pine isolated for its existing financial use case.
2. Extract or reimplement only domain-neutral evidence-envelope mechanics:
   canonical records, hashing, idempotency, atomic publishing, verification, and
   quarantine.
3. Ingest delivery evidence read-only and build a rebuildable shadow index.
4. Generate summaries and rule candidates with citations and evaluation scores;
   surface them only through the Rule Inbox.
5. Move human-approved rules into the workflow control plane, where they can be
   versioned, revoked, and audited.
6. Replace local-only authority with append-only remote storage, signed
   checkpoints, and tenant-aware authorization before relying on it for
   cross-service delivery audit.

## Initial delivery slice

Start deliberately narrow:

1. One repository and one iOS simulator flow.
2. Chat intake and versioned task-brief acceptance, with human approval when the
   ambiguity or policy check requires it.
3. Hermes implementation run with streamed events persisted by the control plane.
4. One validation and repair loop with saved evidence.
5. Revision-bound draft PR creation and GitHub webhook ingestion for CI/review
   results, including one revalidation-capable review cycle.
6. A manual Rule Inbox and manual merge approval.

Only after this path is reliable should the system add more repositories,
additional agent roles, device farms, autonomous comment resolution, or broader
merge automation.

## Decision

Reuse Hermes as the agent runtime. Build the Codex-like chat experience and the
workflow control plane as a separate product layer. This preserves a flexible
UI and durable governance while avoiding the cost of rebuilding an agent runtime.
