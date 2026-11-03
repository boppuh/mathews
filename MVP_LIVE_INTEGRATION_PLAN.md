# Live MVP integration completion plan

## Current position

The 40 MVP backlog components are implemented. Their production composition is
incomplete: the default API and worker cannot yet execute a newly created task
from intake through human handoff. Completing that composition is required
before the release gate can begin. A settings report with
`automation_ready: true` alone does not establish operational readiness.

This plan follows the runtime audit on 2026-11-03 against Mathews `main` at
`eb06e63a95d1854cd2631e5be538f5563088080e`. It records preparation, not a passing
release gate. The existing gate attempt stopped before intake; a fresh gate
must freeze the revisions actually used after integration changes merge.

Verified integration gaps:

- `TaskService.create` in `services/control-plane/src/mathews_control_plane/tasks.py`
  persists intake and its evidence but schedules no workflow job.
- `BriefingService` has no production caller. Initial workspace creation,
  implementation, candidate commit, and host validation execution are not
  assembled into a runnable lifecycle.
- `ValidationEvidenceJobHandler` verifies and captures an existing collection;
  it does not drive `validation.run` or assemble host results into that
  collection.
- `VerifiedDraftPullRequestService` is not constructed by production startup.
- `build_worker` selects the conservative review classifier and requires an
  explicitly injected review-resolution handler. The default API supplies no
  approval continuation. `FullReviewValidator` is an interface without a
  production implementation.
- Startup recovery accepts external reconciliation and owned-resource cleanup
  adapters, but default startup does not compose the complete set.
- A real Hermes installation is available locally, but its Runs API is not the
  contract currently assumed by `HermesHttpRuntime`: the installed API exposes
  lifecycle events separately and has no matching `/tool-results` route. This
  is a source-audit finding for the exact provider revision below; authenticated
  live capability and run verification remain pending.
- GitHub App identifiers and secret references remain unconfigured. Account
  provisioning, installation permissions, and a real signed delivery still need
  verification.
- The current host selects Xcode 27.0 (`27A266a`), whereas the accepted contract
  pins Xcode 26.1.1 (`17B100`) and iOS 26.1 (`23B80`). The required toolchain must
  be selected or installed before its contract can pass again.

The authorities remain `MVP_RELEASE_GATE_RUNBOOK.md`, the versioned repository
configuration, and the documented host, GitHub, evidence, and policy contracts.

## Inspected Hermes provider contract

The 2026-11-03 source audit inspected installed Hermes revision
`daedf4f627c73859974e587783b7cef8ce80e19a`. The inspected
`gateway/platforms/api_server.py` had no local modifications. This identifies
the audited source; it is not a claim that a live deployment has been pinned
or accepted.

An AST inventory of that revision's HTTP route registrations at lines 4805–4809
found exactly these Runs routes:

| Method | Route |
| --- | --- |
| POST | `/v1/runs` |
| GET | `/v1/runs/{run_id}` |
| GET | `/v1/runs/{run_id}/events` |
| POST | `/v1/runs/{run_id}/approval` |
| POST | `/v1/runs/{run_id}/stop` |

There is no registered `/v1/runs/{run_id}/tool-results` route. In the same
source, `_handle_get_run` (lines 4480–4492) returns the stored status record,
while `_handle_run_events` (line 4494 onward) serves a separate SSE stream.
Mathews' client instead expects sequenced events in its polled observation
and submits authorized tool results to the missing route. Those are concrete
provider/client contract differences rather than conclusions inferred from
the Mathews client alone.

No provider service was started and no authenticated capability request or
model run was performed during this audit. PR 1 must verify the actual deployed
runtime over its authenticated boundary, prove mediated tool execution and
replay/cancellation behavior, and freeze that tested revision before intake.
Repeat the source and capability audit if the provider revision changes.

## Dependency order

Environment setup and PR 1 can proceed together. PR 2 depends on PR 1's frozen
runtime interfaces. PR 3 depends on PR 2; PR 4 depends on PR 3. PR 5 may proceed
once the lifecycle, validation, and publication interfaces are stable, but must
merge before the gate starts. PR 6 follows all runtime changes and verified
environment setup. Each PR starts from current merged `main`, passes relevant
checks and review, and merges before dependent work is finalized.

### Environment lane — real accounts and host readiness

1. Provision or identify one private GitHub App and its installation selected
   only for `boppuh/mathews-ios-acceptance`. Verify exact permissions and events
   from `services/control-plane/GITHUB_APP.md`; keep the separate repository
   transport credential distinct from the App.
2. Store the host HMAC, Hermes API authentication, App private key, webhook
   secret, Git transport token, and simulator account credential in their
   documented Keychain items. Set only non-secret values and opaque references
   in local configuration. Verify resolution without printing values.
3. Install the launchd host agent using `services/host-agent/LAUNCHD.md`; verify
   private paths, authenticated health, durable journal, and repository
   preflight. Retain existing journals and artifacts.
4. Restore the pinned Xcode 26.1.1/iOS 26.1 environment where possible. Do not
   treat Xcode 27 as equivalent or silently change the accepted contract. Any
   toolchain change requires its own contract/configuration version, acceptance
   CI proof, and reviewed trust promotion before use.
5. Deploy the compatible Hermes runtime from PR 1. Verify its authenticated
   capability and mediated execution contracts before enabling task intake.
6. Set up the temporary ingress described in the release runbook, preserving
   raw signed request bytes and forwarding only the bounded webhook route.
   Record and restore the previous App URL during cleanup.

Account secrets and passwords never enter this document, source control,
terminal arguments, agent prompts, or release evidence. Local setup completion
must be recorded from observations; a configured reference is not proof that a
credential resolves or has the required scope.

### PR 1 — freeze and implement the real Hermes execution boundary

Define the provider contract before changing broad orchestration. Inventory
the pinned Hermes revision's actual API and executable tool permissions. Choose
a reviewed adapter or bridge that makes all repository operations go through
`ScopedCodeExecutionService`; the installation's general agent tools cannot
become an alternate path to the acceptance worktree or credentials.

Required interfaces:

- `HermesRuntime.start`: version-bound prompt, task/session correlation, and a
  stable idempotency key produce one external run identity.
- `observe`: normalized status plus ordered, replayable events with stable
  event identities; explicitly adapt polling versus the actual event stream.
- Tool proposal/result exchange: the five existing workspace/patch tools,
  bounded typed arguments, control-plane decision and result evidence, and a
  reliable response path back to the suspended agent. Lifecycle progress
  notifications alone do not satisfy a tool proposal contract.
- `stop` and `reconcile`: bounded cancellation, retained partial evidence, and
  unambiguous observation after disconnect/restart. Lost starts must be
  reconciled rather than issuing a duplicate run.
- Typed planner output and bounded review classification must be validated
  before their outputs can be used by the later composition.
- A non-secret capability check reports protocol version, mediated tool
  support, authentication availability, and correlation/replay support. Missing
  capabilities block work even when every settings field is present.

Acceptance: exercise a real authenticated Hermes run that proposes an allowed
read and a scoped patch through Mathews, receives the mediated results, and
completes; also exercise denial and stop/reconciliation. Freeze the tested
runtime revision and contract. Unit fixtures may test mappings, but cannot
serve as live provider evidence.

### PR 2 — wire intake, briefing, steering, and authorization

Add a shared production composition used by API and worker. It owns the
configured runtime, repository/host gateways, policy services, and durable
lifecycle scheduler; callers must not construct a parallel ad hoc workflow.

Schedule lifecycle work transactionally with task intake. Use stable job and
stage identifiers, current job leases, and the existing task transition gates.
The lifecycle loads the request evidence, creates a structured planner result,
and calls `BriefingService` to persist the immutable brief and validation
contract. Bind the repository configuration and active policy explicitly.

Resume implementation only from the accepted exact brief and its single
authorization outcome. Wire the supported approval continuation and steering
reschedule paths. Scope-changing steering revokes earlier grants and creates a
successor brief/contract; it must not leave an orphaned task or allow its old
job generation to continue.

Acceptance: create a task through the real authenticated API using its normal
request body; the default worker advances it to briefing and the expected
approval state. Exercise steering, approval, duplicate requests, and restart
using that same production composition. Tests may inject external boundaries,
but must not manually insert the jobs, briefs, grants, or transitions that
production is supposed to create.

### PR 3 — execute and validate a candidate, then publish its draft

Extend the leased lifecycle to drive the existing authenticated
`workspace.create`, scoped Hermes implementation, candidate `git.commit`, and
configured `validation.run` operations. Preserve stable effect identities and
checkpoint each stage using the durable worker APIs.

Implement one concrete full-validation adapter shared with review repair. Its
input is the task/lease, exact candidate commit/tree, frozen validation
contract, and repository configuration. Its output is captured operation
artifacts, typed criterion assertions, immutable validation evidence, and the
existing `ValidationDecisionResult`. Derive results from authenticated host
responses and pinned XCTest artifacts, not from agent claims or client pass
booleans. Run every required operation on the exact candidate.

On failure, use the existing bounded repair service and require a complete new
validation pass after each new commit. On success, construct
`VerifiedDraftPullRequestService` with the real lease-bound host, App broker,
GitHub publisher, webhook binder, and explicit required CI check names. Publish
one draft PR and retain immutable local/remote/PR proof.

Acceptance: an API-created task reaches `PR_ACTIVE` through the normal default
worker, with configured external boundaries injected only for automated tests.
Test a changed candidate, stale lease, lost push/create response, duplicate
poll, failed validation, and bounded repair. No service may reuse old-head
validation or create a second PR. Before claiming live completion, repeat the
path using real Hermes, host, simulator, App, Git transport, CI, and signed
webhooks.

### PR 4 — compose both review-repair authorization paths

Use the same shared composition in API and worker to construct
`ReviewResolutionService`, the bounded classifier, concrete full validator,
verified draft publisher, and `ReviewResolutionJobHandler`. Register the
handler before enabling automatic classification. Dispatch approved one-off
review decisions through `resume_approved` with exact event fingerprints.

Treat classifier output as a proposal; existing policy rules and supported
human decisions remain the authority. Unmatched or unsafe comments must remain
blocked. Publish each successor only after fresh complete validation, then
refresh signed CI/review observations and readiness.

Acceptance: two distinct authenticated review events on successive heads
exercise automatic rule authorization and recently reauthenticated one-off
approval. Tests cover absence of a handler, invalid/stale classification,
duplicate comment delivery, old-head validation, and no repair before approval.
The live gate must demonstrate both paths against one real draft PR.

### PR 5 — connect restart, cancellation, and outage adapters

Provide concrete `ReconciliationAdapter` implementations for the registered
host process, Git branch, PR head, and webhook cursor target kinds in addition
to Hermes. Wire the existing owned-process terminator and owned-workspace
cleaner into cancellation and startup recovery for both API and worker.

Preserve ownership identity and lease fences across every action. Missing or
ambiguous observations retain their blocking recovery state; they cannot
authorize repeated mutation. Use supported dependency backoff and retry
continuations rather than changing rows or credentials to simulate recovery.

Acceptance: production-composition tests resume an API-created task at a saved
checkpoint, fence stale results, cancel owned work once, and reconcile an
ambiguous effect without repeating it. The runbook's controlled live restart,
cancellation, Hermes/host outages, and GitHub outages before and after PR
creation must subsequently run on real disposable tasks.

### PR 6 — verify composition and execute the fresh release gate

Run repository checks on the merged composition and complete operational
readiness: resolvable credentials, correct App scope, real signed webhook
receipt, authenticated host health, repository preflight, compatible Hermes,
and the accepted Xcode/simulator contract. Publish any needed operator-command
or diagnostics improvements through review before freezing the official run.

Create a new private external working report and freeze current Mathews and
acceptance SHAs, configuration, policy, prompt/evaluation versions, flow,
required checks, and named operator roles. Execute every phase of
`MVP_RELEASE_GATE_RUNBOOK.md` against those inputs, including steering, both
review paths, governed learning/promotion/rollback, and the individual safety
and recovery tests plus live observations.

Automated composition tests can use deterministic external adapters to verify
control flow. Required live evidence must use real services and authentic
observations; a stub runtime, manufactured webhook, manually inserted passing
record, or isolated unit-test result cannot replace it. Human reauthentication
and explicit handoff remain product interactions by the operator.

Stop on a required failure and record the defect. If code, policy, configuration,
contract, or evidence continuity changes, merge the repair separately and use
the rerun required by the runbook. Do not relax requirements to obtain a pass.

After evidence reconciliation and cleanup, record the actual `GO` or `NO-GO`.
Publish only the redacted report and supported execution-plan update in a
dedicated report PR. A `GO` and merged report are prerequisites for starting
production-roadmap work.

## Completion definition

Integration is complete when the normal authenticated task API and default
worker execute the complete recorded workflow with the real external
integrations and every release-gate requirement passes. Individual component
tests, a green acceptance repository, and configuration completeness are
necessary inputs, but do not independently establish that outcome.
