# MVP Implementation Backlog

## Delivery order

Build the vertical slice in order. Do not begin autonomous PR work until task
state, local authentication, repository preflight, immutable evidence envelopes,
redaction, access/deletion enforcement, leases, cancellation, and approval
handling are durable and visible. A later epic may enrich evidence and
retrieval, but it must reuse this foundation rather than create a parallel
format.

## Epic 0 — Foundation and local development

### 0.1 Create the application workspace

**Outcome:** A repository with separate web UI, control-plane API, macOS host
agent, shared types, and infrastructure directories.

**Done when:** Local startup brings up the UI, API, database, and worker; lint,
type checks, and tests run from documented commands.

### 0.2 Establish configuration and secrets handling

**Outcome:** Environment-specific configuration for the single target repository,
GitHub App, Hermes endpoint, and local artifact root.

**Done when:** Secrets are absent from source control and logs; macOS-only
credentials are read from Keychain or an equivalent local secret provider.

### 0.3 Provision durable local infrastructure

**Outcome:** PostgreSQL and a content-addressed local artifact store are
available to the control plane.

**Done when:** A smoke test can write and retrieve a task record and a hashed
artifact; database migrations are repeatable.

### 0.4 Implement local user authentication

**Outcome:** The local UI and API require an authenticated user session even
when bound to loopback.

**Done when:** Password/bootstrap setup, secure session cookies, CSRF
protection, logout/session expiry, and reauthentication for secret,
repository-policy, and terminal task changes have integration coverage; an
anonymous local process cannot read tasks, artifacts, or SSE.

## Epic 1 — Task workflow control plane

### 1.1 Define the domain schema

**Outcome:** Migrations and typed models for Task, Brief/BriefApprovalDecision,
RepositoryConfiguration, TaskEvent, EvidenceRecord, ValidationContract,
ValidationRun, ApprovalRequest, RuleCandidate, ReviewRule, PolicyVersion,
PromptTemplateVersion, BackgroundJob/Lease, and WebhookDelivery.

**Done when:** Each record has ownership, timestamps, correlation identifiers,
and version/lineage semantics; a validation run is bound to contract,
repository-configuration, commit, and tree versions; an approved ReviewRule is
distinguishable from a non-executable candidate.

### 1.2 Implement the minimal evidence safety foundation

**Outcome:** Every request, tool operation, repository snapshot, external event,
and result uses one canonical immutable evidence envelope before autonomous
mutation is enabled.

**Done when:** Deterministic redaction occurs before persistence; the envelope
stores hashes, task/run/actor/origin/parent correlation, access and retention
classes; session checks protect reads/downloads; correction is append-only; and
authorized deletion destroys content/index derivatives while appending a
non-sensitive tombstone and deletion audit event.

### 1.3 Implement the task state machine

**Outcome:** The control plane alone moves tasks through `INTAKE`, `BRIEFING`,
conditional `BRIEF_PENDING_APPROVAL`, `IMPLEMENTING`, `VALIDATING`,
`REPAIRING`, `PR_ACTIVE`, `READY_FOR_HUMAN_MERGE`, `HANDED_OFF`, `ESCALATED`,
`FAILED`, and `CANCELLED`.

**Done when:** Invalid transitions are rejected; every accepted transition writes
an audit event with reason, actor, policy version, and evidence references;
`PR_ACTIVE` means a verified draft rather than completion;
`READY_FOR_HUMAN_MERGE` is evaluated against the exact current head; `HANDED_OFF`
does not imply merge/release; `FAILED` and `CANCELLED` are distinct terminal
outcomes; scope-affecting steering fences current work and returns to
`BRIEFING`; an invalidated readiness gate returns to `PR_ACTIVE`.

### 1.4 Build the leased durable background-job loop

**Outcome:** A PostgreSQL-backed worker executes scheduled task actions and
recovers safely after a local process restart.

**Done when:** Jobs have exclusive expiring leases, heartbeats, attempts,
fencing tokens, idempotency keys, and bounded retry with jitter; only the
current token may record an effect or transition state; restart reconciliation
replays from the last durable checkpoint without duplicating external effects.

### 1.5 Add approval and resumable escalation services

**Outcome:** The control plane can pause a task and wait for a human decision.

**Done when:** Brief approvals, unsafe-action approvals, retry-limit escalations,
review conflicts, and rule candidates are supported with expiry and audit
trail; escalation stores the blocked operation and prior/resume state; approval
rechecks preconditions and resumes only there; deny/abandon produces explicit
`FAILED` or `CANCELLED`, never implicit completion.

### 1.6 Implement cancellation and dependency-outage semantics

**Outcome:** User cancellation and host, Hermes, or GitHub outages stop or pause
work without corrupting task truth.

**Done when:** Cancellation durably revokes leases/tool grants, fences late
results, terminates only owned process groups, saves partial evidence, and
cleans up idempotently; bounded outage retry exhaustion creates a resumable
escalation with service, checkpoint, retry history, and a retry/cancel decision;
startup reconciles leased jobs, Hermes runs, host processes, branch/PR heads,
and webhook cursors.

## Epic 2 — Web application and task cockpit

### 2.1 Build task creation and task list

**Outcome:** Users can create a task from a plain-language request and see its
state, repository, last activity, and blockers.

**Done when:** An authenticated user can create a task; a new task persists
successfully and links to its cockpit.

### 2.2 Build the task cockpit shell

**Outcome:** A persistent timeline, activity feed, evidence checklist, and
approval/blocker region are visible for every task.

**Done when:** The UI renders historical events from the database and does not
depend on raw chat transcript reconstruction; it distinguishes resumable
escalation, terminal failure/cancellation, verified draft PR, human-merge
readiness, and handoff from merge/release.

### 2.3 Stream live task events

**Outcome:** The cockpit receives Server-Sent Events for state changes, agent
activity, validation progress, approvals, and GitHub updates.

**Done when:** A browser reconnect restores the full durable timeline and then
continues live updates without duplicating events.

### 2.4 Add evidence and artifact views

**Outcome:** Users can inspect acceptance criteria, diffs, tests, logs/network
evidence, PR/CI state, and attached artifacts without leaving the task.

**Done when:** Full redacted logs remain collapsed by default, searchable on
demand by an authorized session, and linked to their EvidenceRecord;
unauthorized/deleted artifacts cannot be read and their safe tombstone/lineage
status is visible.

### 2.5 Add Approval Inbox and Rule Inbox

**Outcome:** Human decisions are prominent and actionable outside chat.

**Done when:** A decision updates the correct task state and creates a durable
audit event; a one-off repair approval is bounded to its proposed change; rule
approval creates a versioned ReviewRule/PolicyVersion and does not silently
activate a prompt or candidate.

### 2.6 Add chat steering and cancellation control

**Outcome:** Users can steer or cancel an active task without the agent silently
widening scope.

**Done when:** Steering is durably linked to the task; changes to acceptance
criteria, paths, risk, or tests create a new brief/ValidationContract version
and return to `BRIEFING`; cosmetic in-scope clarification is classified and
audited; cancellation invokes lease revocation/fencing and shows its effect in
the timeline.

### 2.7 Build repository configuration and preflight UI

**Outcome:** An authenticated user can configure the one allowed iOS repository
and inspect readiness before starting a task.

**Done when:** The UI edits versioned non-secret settings, invokes a read-only
preflight, displays root/base SHA, Xcode target, simulator, Git identity,
operations, E2E flow, assertion vocabulary, artifacts, and prohibited/release
paths; secret values are write-only; sensitive changes require reauthentication
and approval; invalid configuration visibly blocks mutation.

## Epic 3 — Repository and macOS host integration

### 3.1 Create repository configuration

**Outcome:** One iOS repository has a validated configuration for root, base
branch, task-branch naming, remote, Git author/committer identity, Xcode
project/workspace, scheme, simulator, tests, exactly one E2E flow, typed
assertion vocabulary, artifacts, and prohibited paths/operations including
merge/release actions.

**Done when:** Invalid or missing configuration blocks execution before any
workspace is created; preflight is read-only and produces evidence tied to the
active configuration version.

### 3.2 Implement the macOS host agent

**Outcome:** A launchd-managed local service performs explicitly named,
allowlisted operations for the configured repository.

**Done when:** It is bound locally, authenticates the control plane, validates
arguments, enforces task/lease/fencing tokens, and exposes no arbitrary shell
endpoint; Hermes has neither a direct host path nor host credentials.

### 3.3 Implement workspace lifecycle operations

**Outcome:** The host agent creates a task-specific Git workspace from the
configured base revision and returns the resulting repository state.

**Done when:** The base ref is frozen to an immutable SHA, branch/workspace names
are unique and owned by the task, and cleanup is safe, idempotent, cancellation
aware, and never touches unowned workspaces.

### 3.4 Implement controlled Git branch, commit, and push operations

**Outcome:** The host, not Hermes, creates candidate commits and pushes only the
configured task branch.

**Done when:** Commit author and committer name/email come from versioned
configuration and are recorded as evidence; `HEAD`, tree, index/worktree
cleanliness, branch, remote, and base SHA are checked at each boundary;
credentials never enter prompts/artifacts; pushes are non-force and idempotent;
merge, tag, release, and unrelated refs are unavailable.

### 3.5 Implement build, test, and artifact capture operations

**Outcome:** The host agent can execute configured build/test operations and
return normalized result data plus immutable artifacts.

**Done when:** Each result includes exit status, duration, content hashes, and
captured output references, exact commit/tree SHA, contract/configuration
versions, cancellation status, and current fencing token; partial output from a
cancelled process is retained but cannot count as a pass.

## Epic 4 — Prompt compiler and Hermes execution

### 4.1 Implement structured task briefing

**Outcome:** A rough request becomes a versioned brief containing scope,
typed acceptance criteria, risks, affected user flow, and test plan while the
task is explicitly in `BRIEFING`.

**Done when:** The brief is stored separately from chat and a versioned
BriefApprovalPolicy records exactly one disposition for that version:
`AUTO_ACCEPTED_BY_POLICY` only when every required field is complete, no
ambiguity/scope-expansion flag remains, paths are non-sensitive, and operations
are preallowed/low risk; otherwise `HUMAN_APPROVAL_REQUIRED` waits for approval
of the exact version. Revision returns to `BRIEFING`; neither path can be
inferred from Hermes prose.

### 4.2 Build versioned role-specific prompts

**Outcome:** The compiler creates bounded prompts for planner, implementer,
validator, PR writer, and reviewer.

**Done when:** Prompts use structured task data and concise verified evidence;
they do not inject unlimited logs or mutable notes; a non-default prompt may run
only in a labeled evaluation, and default promotion requires a threshold pass,
regression review, human approval, immutable PolicyVersion update, and rollback
target.

### 4.3 Integrate Hermes runs

**Outcome:** The control plane can start, observe, cancel, and correlate Hermes
runs with a task.

**Done when:** Hermes events are normalized into TaskEvents, and agent prose
cannot directly advance state or satisfy a gate; run/task/attempt/lease
correlation is durable; cancellation revokes tools and fences late events;
timeouts/outages follow bounded retry and resumable-escalation semantics.

### 4.4 Implement scoped code-change execution

**Outcome:** Hermes can inspect and modify only the task workspace through the
host agent's approved operations.

**Done when:** Every Hermes tool proposal returns to the control plane for
state/brief/configuration/policy/allowlist authorization and evidence capture
before dispatch to the host; Hermes cannot call the host, Git, or Xcode
directly; resulting diff, repository revision, authorization decision, and tool
result are attached to the task.

## Epic 5 — iOS validation and bounded repair

### 5.1 Configure the single deterministic simulator flow

**Outcome:** The single MVP repository-wide, production-like simulator flow
demonstrates a real user journey, while each task supplies bounded typed
assertions mapped to its acceptance criteria.

**Done when:** It can be run repeatedly from a clean simulator state with a test
account and deterministic fixtures; the initial assertion vocabulary covers
element/value present, navigation state, expected network response, expected log
event, and no crash; no free-form agent claim can satisfy an assertion.

### 5.2 Collect validation evidence

**Outcome:** Unit/integration output, simulator artifacts, application logs,
crash/error signals, and required network/performance signals are recorded.

**Done when:** Each acceptance criterion shows pass, fail, pending, or blocked
with direct evidence references, typed assertion/result, contract version, and
exact candidate commit/tree SHA.

### 5.3 Implement validation decisioning

**Outcome:** The control plane decides whether validation passed, failed, or
requires escalation based on stored contract results.

**Done when:** Missing required evidence is treated as failure or escalation—not
as a pass; execution occurs at clean `HEAD`; any commit, tree, configuration, or
contract change invalidates the pass; a decision can be queried by exact
candidate SHA.

### 5.4 Implement the repair loop

**Outcome:** A failed validation produces a concise, evidence-backed repair
prompt and reruns validation after a scoped fix.

**Done when:** Retry count is enforced; repeated or equivalent failures escalate
with the smallest clear human decision required and stored resume state; each
repair creates a new candidate commit and reruns the complete active contract;
abandon/cancel/unrecoverable error has an explicit terminal state.

## Epic 6 — GitHub pull-request and review loop

### 6.1 Configure GitHub App authentication

**Outcome:** The system uses least-privilege, repository-scoped GitHub App
credentials.

**Done when:** Credentials are stored securely; webhook signatures are verified;
the App lacks merge, release, and unrelated-repository authority; credentials
are never sent to Hermes.

### 6.2 Open draft pull requests

**Outcome:** A verified task can create a draft PR with a summary, scope,
acceptance criteria, test evidence, and known risks.

**Done when:** A PR cannot be opened unless the active ValidationContract passes
for clean commit `C`; immediately before/after push the host proves local head,
remote branch SHA, and GitHub PR head all equal `C`; the proof is immutable
evidence before `PR_ACTIVE`; changed content or head invalidates the pass and
cannot reuse prior validation.

### 6.3 Ingest CI and review webhooks

**Outcome:** GitHub check and review changes create TaskEvents and wake the
associated workflow job.

**Done when:** Duplicate deliveries are idempotent and the cockpit shows the
current CI/review state; signature and canonical payload are stored before
processing; correlation uses installation, repository ID, PR number, task
branch, and head SHA; duplicate, stale, and out-of-order events cannot regress
gates; unknown/ambiguous events are quarantined instead of guessed.

### 6.4 Support one review-resolution cycle

**Outcome:** The system classifies actionable review comments, proposes or
makes scoped repairs after policy checks, retests, and updates the draft PR.

**Done when:** Automation occurs only when an active human-approved ReviewRule
preauthorizes a low-risk edit inside the exact brief/configured paths and retry
budget, with no dependency, schema, signing, or security change; every repair
creates a new commit and fully revalidates. Unmatched, conflicting, ambiguous,
speculative, higher-risk, or scope-expanding feedback pauses for a bounded
one-off human approval; that approval does not create a reusable rule; merging
remains technically unavailable.

### 6.5 Implement readiness and handoff gates

**Outcome:** The task lifecycle distinguishes an active verified draft PR,
readiness for human action, and completed automation handoff.

**Done when:** `READY_FOR_HUMAN_MERGE` requires a passing contract for the exact
current PR head, green required CI, no blocking review, and authorized repairs;
the system leaves draft/merge actions to the human; explicit acknowledgement
creates `HANDED_OFF` and states that it does not mean merged, deployed, or
released.

## Epic 7 — Evidence Ledger and controlled learning

### 7.1 Build verified-source projections and provenance views

**Outcome:** The canonical envelopes from 1.2 are classified into verified
source projections and navigable provenance without introducing another
evidence format or copying authoritative content.

**Done when:** Requests, repository state, tool operations, test artifacts, CI,
and review records expose source/parent/hash/verification status; corrections
and deletion tombstones propagate to projections and derived data; provenance
queries enforce the original access class.

### 7.2 Build a rebuildable retrieval index

**Outcome:** Verified evidence can be chunked and indexed with source, access,
freshness, and index-version metadata.

**Done when:** The index can be deleted and rebuilt without data loss or policy
changes; access controls filter every query; deleted sources and derivatives
are removed and cannot be reconstructed from cached chunks.

### 7.3 Record retrieval and prompt evaluation telemetry

**Outcome:** Each agent run records retrieval set, source hashes, prompt/model
versions, token cost, and quality outcome.

**Done when:** The team can compare prompt or retrieval versions against saved
tasks without relying on anecdotal agent performance; promotion thresholds and
regression cases are versioned and evaluated reproducibly.

### 7.4 Implement candidate-only learning

**Outcome:** The system can produce cited summaries and Rule Inbox candidates.

**Done when:** Derived knowledge is visibly non-authoritative and cannot change
workflow policy, prompts, or permissions without human approval.

### 7.5 Implement controlled prompt and rule promotion

**Outcome:** Evaluated prompt versions and RuleCandidates have an explicit
human-governed path to an active PolicyVersion.

**Done when:** Promotion is rejected without required threshold evidence,
regression review, exact candidate/version, approver, activation time, and
rollback target; activation is atomic and audited; Hermes and background jobs
cannot self-promote; rollback restores the prior immutable version.

## MVP release gate

Release only after automated integration coverage and one recorded manual
acceptance run prove the complete local, single-repository capability:

- Local auth protects UI/API/SSE/artifacts; repository configuration and
  read-only preflight are usable from the UI and block invalid mutation.
- Chat creation, steering, and cancellation are durable.
  `BRIEFING` produces a versioned brief/ValidationContract with exactly one
  recorded unambiguous policy bypass or exact-version human approval.
- Canonical evidence redaction, hashing, access, retention, correction,
  deletion/tombstones, durable leases, restart recovery, cancellation fencing,
  and bounded host/Hermes/GitHub outage escalation work before mutation.
- Hermes has only control-plane-mediated tools. The host freezes the base SHA,
  owns workspace/Git identity/commit/push, and validates clean candidate `C`
  with required builds/tests, the one deterministic simulator flow, and
  task-specific typed assertions.
- The system pushes only passing `C`, opens a draft PR, proves local/remote/PR
  heads equal `C`, and enters `PR_ACTIVE`. A task can alternatively demonstrate
  resumable `ESCALATED` with evidence/resume state/one decision, or a distinct,
  correctly fenced terminal `FAILED`/`CANCELLED` outcome.
- Signed webhook ingestion correctly handles duplicate, stale, out-of-order,
  unknown, and ambiguous CI/review events using installation/repository/PR/head
  correlation.
- One review cycle proves both authority paths: a preapproved low-risk in-scope
  repair fully revalidates a new head, while non-preapproved or scope-expanding
  work waits for human approval. Exact-head CI/review gates reach
  `READY_FOR_HUMAN_MERGE`; acknowledgement reaches `HANDED_OFF`; merge and
  release remain unavailable.
- Approval and Rule Inboxes work outside chat, and no review rule or default
  prompt is promoted without cited evaluation evidence and explicit human
  approval.
- The cockpit exposes brief/config/contract versions, state meaning,
  criterion evidence, exact-head proof, retries/outages, approvals, PR/CI/review,
  and handoff/terminal outcome without opening full logs or reconstructing chat.

A single happy-path verified draft PR is necessary but not sufficient for the
product release gate.
