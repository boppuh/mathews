# MVP Release-Gate Runbook

## Purpose

This runbook is the authoritative procedure for accepting the Mathews MVP after
all implementation tasks have merged. It proves that one real iOS delivery can
reach explicit human handoff while the trust, evidence, recovery, and
exact-version boundaries continue to fail closed.

Passing this gate accepts the MVP for its documented scope. It does not merge
the generated pull request, tag a release, deploy software, use production
signing credentials, or authorize work from the production roadmap.

## Gate ownership

Assign these roles before starting. One person may fill more than one role, but
the operator and recorder responsibilities must both be explicit.

| Role | Responsibility |
| --- | --- |
| Gate owner | Owns the run, scope, deviations, and final go/no-go decision. |
| Operator | Performs local setup, human approvals, reauthentication, and handoff. |
| Recorder | Captures timestamps, durable IDs, exact Git objects, screenshots, and results without secrets. |
| Defect owner | Classifies failures, links fixes, and decides whether a clean rerun is required. |

Record the people or accounts filling each role in the acceptance report.

## Required outputs

The gate is complete only when all four outputs exist:

1. A passing repository verification record from the exact `main` commit used
   for the run.
2. One recorded golden-path task that reaches `HANDED_OFF` through a real host,
   Hermes, simulator, GitHub, CI, and review path.
3. A passing safety and recovery matrix backed by named automated tests and the
   live observations required by this runbook.
4. A completed acceptance report with an explicit `GO` or `NO-GO` decision and
   no unexplained deviations.

Use the report template at the end of this document. During execution, keep the
working report in a mode-`0700` recording directory outside both Git worktrees;
the frozen Mathews worktree must remain clean and checked out at the recorded
`main` SHA. After the gate, copy only the completed, redacted report into
`MVP_RELEASE_GATE_REPORT.md` in a separate dedicated-branch worktree, update
`MVP_EXECUTION_PLAN.md` there, and review both changes through a pull request.
Do not commit raw logs, credentials, cookies, installation tokens, webhook
secrets, account data, or unredacted task input.

## Non-negotiable rules

- Start from a clean, current `main` and record its full commit SHA.
- Use a dedicated acceptance iOS repository and a disposable acceptance branch.
- Use only synthetic fixtures and a dedicated non-production test account.
- Keep every credential in macOS Keychain behind its configured opaque
  `keychain://` reference.
- Do not weaken branch protection, GitHub App permissions, validation
  requirements, or policy thresholds to make the run pass.
- Do not manually edit durable task, evidence, job, validation, webhook, policy,
  or approval rows.
- Do not force-push, merge, tag, deploy, archive, export, or use production
  signing credentials.
- A failed required check produces `NO-GO`. Fix the cause and rerun the affected
  check; rerun the complete golden path when exact-head or evidence continuity
  was invalidated.

## Phase 0 — Freeze the run

Create the external working report before mutating the acceptance repository,
then record:

- gate run ID in the form `mvp-YYYYMMDD-NN`;
- UTC start time;
- full Mathews `main` commit SHA;
- acceptance repository numeric ID and canonical `owner/repository` name;
- acceptance repository base branch and full base commit SHA;
- repository-configuration ID, version, and digest;
- active policy-version ID and version;
- active prompt/evaluation-contract versions used by the run;
- configured simulator runtime, device type, flow ID, and flow version;
- required GitHub check names; and
- names of the gate owner, operator, recorder, and defect owner.

Abort before intake if any repository-level value is missing, ambiguous,
mutable without a version, or broader than the single configured repository.
The task-specific validation contract does not exist yet and is deliberately
frozen after final briefing in Phase 3.2.

## Phase 1 — Environment readiness

### 1.1 Workstation and dependencies

Confirm the workstation has Node.js 22+, npm 10, Python 3.13, `uv`, Docker
Compose, Xcode, and the configured simulator runtime. Install workspace
dependencies without changing lockfiles:

```bash
npm ci
uv sync --all-packages --locked
node --version
npm --version
uv --version
uv run python --version
```

The working tree must remain clean after installation. Record the exact Node.js,
npm, uv, and Python versions in the report.

### 1.2 Configuration and credential custody

Create `.env` from `.env.example` when needed. Configure:

- the local PostgreSQL connection and artifact root;
- an absolute `MATHEWS_TARGET_REPOSITORY_ROOT`;
- the Hermes endpoint;
- the exact GitHub App, installation, and repository numeric IDs;
- the private host socket and journal paths; and
- only opaque Keychain references for Hermes, host authentication, GitHub App,
  webhook, Git transport, and simulator-account credentials.

Verify the credential-free configuration report:

```bash
uv run --package mathews-control-plane mathews-config-check
```

The command must exit successfully and must not print credential values.
Verify each required Keychain item exists with `mathews-keychain-check`; never
copy its value into the report or terminal command.

Follow the exact setup authorities in:

- [`README.md`](README.md);
- [`services/control-plane/GITHUB_APP.md`](services/control-plane/GITHUB_APP.md);
- [`services/host-agent/LAUNCHD.md`](services/host-agent/LAUNCHD.md); and
- [`libraries/configuration/SIMULATOR_FLOW.md`](libraries/configuration/SIMULATOR_FLOW.md).

### 1.3 GitHub authority

Before startup, verify the private GitHub App:

- is installed on only the acceptance repository;
- has Checks read, Metadata read, and Pull requests read/write;
- has no Contents, Actions, Administration, Deployments, Environments,
  Secrets, or Workflows permission;
- subscribes only to `check_run`, `pull_request`, `pull_request_review`, and
  `pull_request_review_comment`; and
- is not suspended.

Verify branch protection still reserves readiness and merge for a human. The
separate Git transport credential may push the exact candidate branch, but it
must be restricted to the acceptance repository and must not be exposed to
Hermes or the browser.

### 1.4 Temporary webhook ingress

Provision one gate-owned, time-bounded HTTPS ingress before creating the task.
It must forward only `POST /api/github/webhooks` to
`http://127.0.0.1:8000/api/github/webhooks`, preserve the request body and all
`X-GitHub-*` headers byte-for-byte, reject every other method and path, and
enforce a maximum body size of 1 MiB. The tunnel or relay credential, if any,
must remain outside the repository and report.

Set the GitHub App webhook URL to the temporary HTTPS endpoint ending exactly
in `/api/github/webhooks`. Start the ingress only for the live gate, record its
non-secret public hostname, process/service identity, UTC start time, and
configuration owner, and verify one real signed GitHub delivery is accepted
and durably recorded before continuing. A locally fabricated request is not an
ingress check. If the relay changes bytes, headers, method, or path, the gate is
`NO-GO`.

The recorder must retain the prior App webhook URL so cleanup can restore it.
The ingress must be stopped and its temporary URL removed from the GitHub App
in Phase 6.

### 1.5 Host and simulator

Install or verify the per-user LaunchAgent as documented. Confirm:

- the runtime directory is mode `0700`;
- the socket is private and launchd-owned for the gate run;
- the host journal is retained across restart tests;
- the side-effect-free process probe succeeds;
- the authenticated `host.health` boundary succeeds through Mathews;
- repository preflight resolves the exact clean base commit;
- the configured simulator runtime and device are available; and
- the pinned harness, scheme, fixture, account recipe, source closure, and
  digests pass preflight.

No simulator state from a prior run may be reused. The configured journey must
perform shutdown, erase, boot, candidate installation, and the pinned XCTest.

### 1.6 Services and authentication

Start PostgreSQL and apply migrations:

```bash
docker compose -f infra/compose.yaml up -d --wait postgres
npm run db:migrate
```

Then start only the API, worker, and web processes, with each command in its own
dedicated terminal:

```bash
npm run dev:api
```

```bash
npm run dev:worker
```

```bash
npm run dev:web
```

Keep all three application processes running for the live gate. Do not run
`npm run dev`: that command also starts a self-binding development host agent
and conflicts with the launchd-owned host agent verified in Phase 1.5.

Confirm the API and web health endpoints pass. Bootstrap the local operator
only if no account exists:

```bash
npm run auth:bootstrap-token
```

Use the token once in the browser and do not retain it. Use
`http://localhost:3000` for the browser so strict same-site cookies remain
valid.

## Phase 2 — Baseline verification

Run these commands against the frozen Mathews commit:

```bash
npm run check
npm run build
npm run test:postgres
```

All commands must pass. Record command, UTC start/end time, exit status, and a
short redacted result. For the Python suite, record pass/skip counts. Do not
paste complete logs into the report; retain content-addressed evidence or a CI
URL when available.

Set `POSTGRES_TEST_DATABASE_URL` to a PostgreSQL database on which the test user
may create and drop schemas before running `test:postgres`. The PostgreSQL test
must execute and pass; a dependency-related skip does not satisfy this gate.
Record only the database's non-secret server identity and disposable schema
name.

## Phase 3 — Recorded golden-path task

### 3.1 Acceptance request

Choose one small but nontrivial change to the dedicated iOS acceptance
repository. It must:

- touch ordinary application code but no prohibited validation-harness path;
- have at least two typed acceptance criteria;
- exercise the pinned simulator flow;
- be reviewable without production data or credentials;
- be capable of producing a safe, deliberate first validation failure followed
  by one bounded repair, when the gate owner has approved that scenario; and
- avoid dependency, signing, deployment, release, and broad refactoring work.

Place the exact request and expected outcome in the report after applying the
same redaction standard as Mathews. Record the base SHA before intake.

### 3.2 Intake and briefing

In the web UI:

1. Sign in as the local operator.
2. Create the task against the exact acceptance repository and base revision.
3. Record the task ID and intake-event ID.
4. Inspect the stored request evidence and confirm secrets or sensitive forms
   are redacted before persistence.
5. Review and record the initial versioned brief and validation-contract IDs,
   versions, and digests, but do not approve them yet.
6. In chat, send one bounded, scope-affecting steering instruction that refines
   an acceptance criterion without adding a prohibited path or unsafe action.
   Record the steering event and evidence IDs. Confirm any active authority is
   fenced, the prior brief and validation contract are invalidated, and the
   task returns to `BRIEFING`.
7. Review the regenerated brief, exclusions, typed criteria, risks, affected
   flow, and validation plan. Record the successor brief and validation-contract
   IDs, versions, and digests, and prove neither predecessor can authorize work.
8. Freeze that successor validation contract for the rest of the task. Any
   later brief change or contract replacement invalidates the run and requires
   a clean golden-path rerun.
9. Require exactly one durable authorization outcome for the exact displayed
   brief: either a human approval-decision ID or an unambiguous policy-bypass ID
   and version. Never record both or neither.
10. Confirm that the selected authorization binds the accepted brief ID/version,
    frozen validation-contract version, and active policy ID/version. For a
    human approval, reauthenticate before approving.

Pass only when the accepted brief and its single authorization outcome are
durable, exact-version bound, and visible in the task cockpit. The same
authorization identity must remain visible and bound to the accepted brief at
readiness and handoff; otherwise the task may not reach `HANDED_OFF`.

### 3.3 Workspace and implementation

Allow Mathews to create the task-owned workspace and run Hermes. Record:

- workspace ID or durable ownership record;
- frozen base SHA;
- background-job and lease IDs;
- Hermes run ID and version-bound prompt/policy identifiers;
- candidate commit SHA and tree SHA; and
- redacted implementation evidence references.

Confirm that Hermes receives bounded context and mediated tools only. It must
not receive host socket paths, credential values, arbitrary shell authority, or
GitHub installation tokens.

### 3.4 Validation and bounded repair

Run the configured build/test operations and the pinned simulator journey
against the exact candidate SHA. Record:

- validation-attempt and validation-run IDs;
- validation-contract ID/version/digest;
- repository-configuration ID/version/digest;
- candidate commit and tree SHAs;
- each operation result and artifact evidence ID;
- criterion-by-criterion typed assertion results; and
- simulator runtime/device plus flow/fixture versions.

If the planned first attempt fails, verify that the failure evidence is
redacted and exact-SHA bound, then permit only the configured bounded repair.
Record the repair decision, new candidate SHA, and complete fresh validation.
Prior validation must not authorize the new head.

Pass only when the final candidate has one complete passing validation record
whose exact inputs match the current candidate.

### 3.5 Draft pull request, CI, and review

Allow Mathews to push only its recorded candidate branch and create or update
one draft pull request. Record:

- remote branch name and exact remote head SHA;
- draft PR number and URL;
- PR head SHA and tree SHA;
- required check names and final conclusions;
- webhook delivery IDs for relevant PR, check, and review updates; and
- every blocking review thread plus its resolution or authorized repair.

Confirm the GitHub App token is repository-scoped and revoked after each
bounded operation. The generated PR must remain a draft unless a human changes
it outside Mathews.

Exercise both review-repair authorization paths; neither is optional:

1. On the first verified PR head, have the designated acceptance reviewer post
   one controlled, low-risk, in-scope comment that exactly matches a
   preapproved active `ReviewRule`. Confirm Mathews records the comment and rule
   fingerprint, performs the repair without a human approval decision, creates
   one new head, reruns the complete frozen validation contract, updates the
   same draft PR, and invalidates every readiness fact from the prior head.
2. After CI passes on that new head, have the reviewer post one controlled
   unmatched or scope-expanding comment. Confirm Mathews creates exactly one
   bounded `REVIEW_CONFLICT` approval and performs no repair before a decision.
   Reauthenticate, approve only the exact displayed review fingerprint, and
   confirm the one-off repair creates another new head, reruns the complete
   frozen validation contract, updates the same draft PR, and again invalidates
   all prior-head readiness evidence.

Record for both paths the source comment/thread, classification, authorization
outcome, active-policy version, repair job/effect, predecessor and successor
SHAs, fresh validation run, remote/PR head, CI results, and final thread state.
A rule match plus a human approval, neither authorization, a reused old-head
validation, a duplicate repair, or a second PR is `NO-GO`.

### 3.6 Readiness and handoff

Wait until the current PR head has passing validation, all required CI checks,
and no blocking review. Confirm that local candidate, remote branch, PR head,
validated commit, tree, repository configuration, validation contract, and
policy bindings all agree.

Reauthenticate, acknowledge the exact handoff, and record:

- readiness-assessment ID;
- handoff acknowledgement/audit-event ID;
- exact PR head SHA at handoff;
- UTC handoff time; and
- final task state `HANDED_OFF`.

Verify that handoff does not merge the PR and does not create a tag, deployment,
release, archive, export, or signing action.

## Phase 4 — Security, recovery, and edge-case matrix

The complete repository suite is the normative proof for destructive and
timing-sensitive cases. Record the named tests below as a matrix, together with
the exact Mathews SHA and test-run result. Live checks are additive and must use
the acceptance task or a disposable companion task.

Every automated-test bullet below is an exact pytest node ID. First prove that
pytest collects it, then execute it individually:

```bash
uv run pytest --collect-only -q <node-id>
uv run pytest -q <node-id>
```

Collection must identify exactly the requested test, and execution must pass.
A missing, deselected, xfailed, or skipped required test fails the gate. Add one
report row for every node ID and one separate row for every required live
observation; each row records the exact Mathews SHA, command or observation,
result, and evidence reference.

### 4.1 Authentication and evidence safety

Required automated coverage:

- `services/control-plane/tests/test_authentication.py::test_bootstrap_requires_exact_origin_and_preauthentication_csrf`
- `services/control-plane/tests/test_authentication.py::test_authenticated_mutations_require_exact_origin_and_bound_csrf`
- `services/control-plane/tests/test_authentication.py::test_reauthentication_rotates_session_and_gates_three_sensitive_mutations`
- `services/control-plane/tests/test_evidence.py::test_redaction_is_deterministic_and_precedes_persistence`
- `services/control-plane/tests/test_evidence.py::test_correction_is_a_single_append_only_successor`
- `services/control-plane/tests/test_evidence.py::test_deletion_fences_reads_destroys_derivatives_and_appends_tombstone`
- `services/control-plane/tests/test_evidence_projections.py::test_browser_views_preserve_each_original_access_class`
- `services/control-plane/tests/test_evidence_projections.py::test_provenance_navigation_omits_inaccessible_related_nodes`

Required live observations:

- an anonymous inbox/task/evidence request is denied;
- one sensitive action requires recent password verification;
- an unauthorized evidence read is denied without exposing metadata or bytes;
- one synthetic evidence item is corrected, the prior version remains visible
  as provenance, deletion fences its content, and a tombstone remains; and
- neither UI, logs, evidence, nor the report contains a credential value.

### 4.2 Leases, fencing, restart, and duplicate effects

Required automated coverage:

- `services/control-plane/tests/test_background_jobs.py::test_expired_takeover_recovers_checkpoint_and_fences_old_worker`
- `services/control-plane/tests/test_background_jobs.py::test_effect_intent_result_and_checkpoint_are_fenced_and_idempotent`
- `services/control-plane/tests/test_background_jobs.py::test_restart_reconciles_prepared_effect_without_duplicate_execution`
- `services/control-plane/tests/test_background_jobs.py::test_ambiguous_prepared_effect_is_never_reissued`
- `services/control-plane/tests/test_host_gateway.py::test_control_plane_lease_survives_host_restart_and_fences_stale_worker`
- `services/host-agent/tests/test_journal.py::test_takeover_fences_old_completion_and_reconciles_crash_as_ambiguous`
- `services/host-agent/tests/test_journal.py::test_concurrent_logical_duplicates_reserve_exactly_once`

Required live observation:

- restart the API/worker and separately restart the launchd host agent only at a
  documented safe checkpoint; verify the task resumes from durable state and
  no completed host, Git, Hermes, or GitHub effect is duplicated.

Do not kill a process during an unbounded or unidentified mutation. If the
checkpoint cannot be identified, rely on automated fault coverage and record
the live restart check as blocked, which produces `NO-GO` until resolved.

### 4.3 Cancellation

Required automated coverage:

- `services/control-plane/tests/test_reliability.py::test_cancellation_fences_jobs_grants_and_late_results`
- `services/control-plane/tests/test_reliability.py::test_cancellation_closes_pending_approval_before_resource_fence`
- `services/control-plane/tests/test_hermes.py::test_out_of_order_and_cancelled_events_are_durably_fenced`
- `services/control-plane/tests/test_hermes.py::test_cancellation_cannot_overwrite_a_timed_out_run`
- `services/host-agent/tests/test_processes.py::test_exact_owned_group_is_terminated_once_and_replayed`

Required live observations on disposable companion tasks:

- cancel once while Hermes is active; and
- cancel once while a configured host operation is active.

Each task must reach `CANCELLED`, revoke its active authority, retain bounded
partial evidence, ignore late results for progression, and clean up only its
owned workspace/processes.

### 4.4 Dependency outages and resumption

Required automated coverage:

- `services/control-plane/tests/test_hermes.py::test_hermes_outage_uses_bounded_background_job_retry`
- `services/control-plane/tests/test_code_change_execution.py::test_host_outage_is_evidenced_as_ambiguous_before_retry`
- `services/control-plane/tests/test_background_jobs.py::test_worker_escalates_exhausted_dependency_outage`
- `services/control-plane/tests/test_reliability.py::test_outage_exhaustion_escalates_and_retry_creates_new_job_generation`
- `services/control-plane/tests/test_reliability.py::test_startup_recovers_expired_lease_and_all_external_target_kinds`
- `services/control-plane/tests/test_draft_pull_requests.py::test_publisher_reconciles_an_ambiguous_create_without_duplication`

Required live observations, using bounded and reversible dependency blocking:

1. Make Hermes unavailable for a disposable task until retry-limit escalation,
   restore it, approve `RETRY`, and confirm a new job generation resumes from
   the durable checkpoint.
2. Make the host socket unavailable for a disposable task, restore the
   LaunchAgent, and confirm the same resumable behavior without duplicate host
   mutation.
3. Make GitHub unavailable at a pre-PR checkpoint, restore it, and confirm
   reconciliation creates exactly one draft PR and one corresponding durable
   effect.
4. Make GitHub unavailable at a post-PR observation checkpoint, restore it, and
   confirm reconciliation finds the existing draft PR and its one corresponding
   durable effect without creating another PR or effect.

Record outage-attempt IDs, retry counts, escalation approval IDs, old/new job
generation IDs, and recovery result. Never simulate an outage by corrupting a
credential or changing durable rows.

### 4.5 Webhook ordering and ambiguity

Required automated coverage:

- `services/control-plane/tests/test_github_webhooks.py::test_duplicate_delivery_replays_without_duplicate_event_or_job`
- `services/control-plane/tests/test_github_webhooks.py::test_stale_and_old_head_deliveries_are_audited_without_regression`
- `services/control-plane/tests/test_github_webhooks.py::test_review_updates_cockpit_and_unknown_events_are_quarantined`
- `services/control-plane/tests/test_github_webhooks.py::test_reused_delivery_id_with_different_body_is_a_conflict`
- `services/control-plane/tests/test_github_webhooks.py::test_ambiguous_exact_correlation_is_quarantined`
- `services/control-plane/tests/test_github_webhooks.py::test_unreadable_committed_receipt_is_quarantined_without_blocking_drain`
- `services/control-plane/tests/test_github_webhooks.py::test_synchronized_pr_head_wakes_reconciliation_and_invalidates_projection`

Required live observation:

- confirm real signed GitHub deliveries advance the acceptance task only when
  their exact repository, PR, and head bindings match. Redelivery may be used
  to demonstrate idempotency. Synthetic stale, unknown, out-of-order, and
  ambiguous payloads remain automated-test evidence unless the gate owner has a
  documented signed-fixture procedure that cannot affect a real PR.

### 4.6 Exact-head and readiness binding

Required automated coverage:

- `services/control-plane/tests/test_repository_configuration.py::test_capture_rejects_any_inexact_host_binding_before_writing_artifact`
- `services/control-plane/tests/test_validation_evidence.py::test_rejects_mismatched_host_head_without_partial_records`
- `services/control-plane/tests/test_draft_pull_requests.py::test_immutable_gate_reloads_exact_passing_run_and_all_four_heads`
- `services/control-plane/tests/test_task_state_machine.py::test_verified_draft_gate_rejects_every_mismatched_dimension`
- `services/control-plane/tests/test_task_state_machine.py::test_readiness_requires_every_current_head_gate`
- `services/control-plane/tests/test_readiness.py::test_head_change_discards_prior_check_success`
- `services/control-plane/tests/test_readiness.py::test_handoff_is_explicit_idempotent_and_never_means_merged`

Required live observation:

- compare the recorded local candidate, remote branch, PR head, validated
  commit, tree, configuration, contract, and policy identifiers at readiness
  and again at handoff. Every value must match the final immutable proof.

### 4.7 Review-repair authorization

Required automated coverage:

- `services/control-plane/tests/test_review_resolution.py::test_automatic_repair_closes_for_every_non_low_risk_boundary`
- `services/control-plane/tests/test_review_resolution.py::test_exact_low_risk_in_scope_classification_is_eligible`
- `services/control-plane/tests/test_review_resolution.py::test_schedule_builds_exact_rule_bound_repair_job`
- `services/control-plane/tests/test_review_resolution.py::test_unsafe_review_requests_bounded_one_off_approval_without_rule`
- `services/control-plane/tests/test_review_resolution.py::test_approved_one_off_resumes_the_exact_review_event`
- `services/control-plane/tests/test_review_resolution.py::test_handler_commits_new_head_fully_revalidates_and_updates_only_draft_pr`
- `services/control-plane/tests/test_review_resolution.py::test_handler_refuses_to_publish_without_current_full_validation`

Required live observations:

- the preapproved, low-risk, in-scope repair in Phase 3.5 completes without a
  human approval and fully validates its fresh head; and
- the unmatched or scope-expanding repair in Phase 3.5 remains blocked until
  the recently reauthenticated human approves its exact fingerprint, then fully
  validates a different fresh head.

Record these as two separate live-observation rows in addition to their
individual automated-test rows.

### 4.8 Candidate learning and governed promotion

Required automated coverage:

- `services/control-plane/tests/test_candidate_learning.py::test_cited_summary_is_redacted_non_authoritative_and_replayable`
- `services/control-plane/tests/test_candidate_learning.py::test_rule_candidate_cannot_create_authority_or_approval`
- `services/control-plane/tests/test_candidate_learning.py::test_authenticated_api_creates_candidate_learning_outputs`
- `services/control-plane/tests/test_candidate_learning.py::test_rule_inbox_skips_candidate_with_missing_source_artifact`
- `services/control-plane/tests/test_approvals.py::test_authenticated_inboxes_expose_bounded_decisions_and_record_audit`
- `services/control-plane/tests/test_approvals.py::test_policy_and_terminal_decisions_require_recent_password`
- `services/control-plane/tests/test_approvals.py::test_rule_promotion_rejects_changed_or_unbound_candidate_evidence`
- `services/control-plane/tests/test_approvals.py::test_rule_promotion_rejects_missing_threshold_evidence`
- `services/control-plane/tests/test_approvals.py::test_rule_promotion_uses_current_policy_and_preserves_lineage_position`
- `services/control-plane/tests/test_prompt_compiler.py::test_prompt_promotion_rejects_worker_or_stale_human_authorization`

Required live observations after the golden-path handoff:

1. From current, readable evidence belonging to the acceptance task, create one
   cited, redacted, explicitly non-authoritative learning summary and one
   evaluated review-rule candidate. Record their IDs, exact source-evidence IDs
   and hashes, definition fingerprint, evaluation result, and Rule Inbox entry.
   Confirm creation changes no approval, executable rule, policy, prompt, task
   state, or host authority.
2. Attempt review or promotion with a missing, changed, or insufficient
   citation/threshold binding and confirm it is rejected without changing the
   active policy. Separately attempt promotion without recent human
   authentication and confirm it is rejected with no authority-bearing effect.
3. Use a candidate that satisfies the documented severity or distinct
   validation-run threshold. In the Rule Inbox, inspect the exact citations,
   evaluation, risks, regression-review attestation, prior active policy, and
   rollback target. Reauthenticate and approve that exact candidate. Confirm
   one immutable `ReviewRule`, one successor `PolicyVersion`, and one activation
   record are created atomically and remain distinct from the golden task's
   frozen policy binding.
4. Through the supported human-only rollback path, restore the prior policy
   memberships as another immutable successor and record both activation IDs.
   No policy row, rule, prompt, evidence record, or prior activation may be
   edited or deleted.

Use separate report rows for candidate creation/inbox visibility,
citation-threshold rejection, unauthorized-promotion rejection, human
promotion, and rollback.

## Phase 5 — Evidence reconciliation

Before deciding the gate, reconcile the report against the product's durable
records and GitHub:

| Dimension | Required equality |
| --- | --- |
| Source | Frozen acceptance base equals the workspace predecessor. |
| Candidate | Host-created commit equals local clean `HEAD`. |
| Tree | Candidate tree equals the validation input tree. |
| Push | Remote task branch head equals the validated candidate. |
| Pull request | Draft PR head equals the remote task branch head. |
| Validation | Passing run binds the final commit, tree, contract, configuration, and assertions. |
| CI | Required checks are passing for the final PR head. |
| Review | No blocking review remains for the final PR head. |
| Readiness | Assessment binds the same final PR head and durable proof. |
| Handoff | Acknowledgement binds the readiness assessment and final PR head. |
| Authority | Human decisions show recent authentication and the active policy/version. |
| Steering | Successor brief and contract supersede the steered predecessors. |
| Review repairs | Both authorization paths bind their own comment, policy, predecessor, successor, and fresh validation. |
| Governance | Candidate citations, rejection evidence, promotion, successor policy, and rollback are exact and immutable. |
| Effects | No duplicate branch, commit, push, PR, repair, handoff, tag, deployment, or release exists. |

Any mismatch is a `NO-GO`; do not explain it away as eventual consistency.
Wait for reconciliation or fix the defect and rerun.

## Phase 6 — Cleanup

After evidence reconciliation:

1. Leave the generated PR unmerged and in its observed draft state unless the
   gate owner separately chooses a human-only cleanup action.
2. Cancel or close disposable companion tasks through supported product paths.
3. Confirm Mathews cleaned only task-owned workspaces and processes.
4. Retain the host journal, database audit records, evidence tombstones, and
   content-addressed release evidence according to their policies.
5. Remove temporary dependency blocks and confirm all health checks recover.
6. Stop the temporary webhook ingress, restore the prior GitHub App webhook URL,
   revoke any relay credential, and prove the temporary public URL no longer
   forwards traffic.
7. Verify no plaintext secret, bootstrap token, session cookie, private key,
   webhook secret, Git token, or test-account credential was written to the
   repository or report.
8. Run `git status --short` in both Mathews and the acceptance repository and
   record the expected clean state or explicitly owned acceptance artifacts.

## Go/no-go decision

The gate owner records `GO` only when:

- all Phase 2 commands pass on the frozen Mathews SHA;
- the golden-path task reaches `HANDED_OFF` with the exact proof chain intact;
- the recorded task demonstrates scope-affecting steering and a regenerated,
  frozen brief and validation contract;
- both mandatory review-repair authorization paths pass on separate fresh
  heads;
- candidate learning, Rule Inbox review, fail-closed governance checks, human
  promotion, and immutable rollback all pass;
- every required safety/recovery matrix row passes;
- every required live observation is completed;
- all defects are closed or explicitly proven non-gating by the documented MVP
  scope;
- there are no unexplained deviations;
- no secret exposure or unauthorized effect occurred; and
- Mathews did not merge, release, deploy, tag, sign, archive, or export.

Any missing evidence, skipped required live check, unresolved defect, exact-head
mismatch, unauthorized effect, or secret exposure is `NO-GO`.

After a `GO`, update [`MVP_EXECUTION_PLAN.md`](MVP_EXECUTION_PLAN.md) to mark the
release gate complete. Production-roadmap implementation may begin only after
that update and the acceptance-report pull request are merged.

After recording the decision in the external working report, create a separate
Git worktree and dedicated report branch from the frozen Mathews `main` SHA.
Copy only the redacted report into that worktree as
`MVP_RELEASE_GATE_REPORT.md`. For `GO`, update the execution plan to mark the
gate complete; for `NO-GO`, leave it active and link the required rerun. Commit
and merge the report and plan through one pull request. Never switch or modify
the original frozen worktree during this publication step.

## Acceptance report template

Copy this template to the external working report for the actual run. Publish
the redacted result as `MVP_RELEASE_GATE_REPORT.md` only after the decision, as
described above.

```markdown
# MVP Release-Gate Report

## Decision

- Gate run ID:
- Decision: PENDING | GO | NO-GO
- Decision time (UTC):
- Gate owner:
- Operator:
- Recorder:
- Defect owner:

## Frozen inputs

- Mathews commit SHA:
- Acceptance repository ID and name:
- Base branch and commit SHA:
- Repository configuration ID/version/digest:
- Starting active policy ID/version:
- Prompt/evaluation contract versions:
- Simulator runtime/device/flow version:
- Required GitHub checks:
- Node.js/npm/uv/Python versions:
- Temporary webhook hostname and service/process identity:
- Temporary webhook start time and verified delivery ID:

## Baseline verification

| Command | Started (UTC) | Ended (UTC) | Result | Evidence/URL |
| --- | --- | --- | --- | --- |
| `npm run check` | | | | |
| `npm run build` | | | | |
| `npm run test:postgres` | | | | |

## Golden-path task

- Redacted acceptance request:
- Task ID:
- Intake event/evidence IDs:
- Initial brief and validation-contract IDs/versions/digests:
- Steering event/evidence IDs and redacted instruction:
- Steering fence/invalidation evidence:
- Accepted successor brief ID/version:
- Frozen successor validation-contract ID/version/digest:
- Authorization outcome type: APPROVAL | POLICY_BYPASS
- Approval decision ID, when selected:
- Policy bypass ID/version, when selected:
- Authorization's brief, validation-contract, and policy bindings:
- Workspace and lease IDs:
- Hermes run ID and version bindings:
- Candidate commit/tree SHAs:
- Validation attempt/run IDs:
- Repair decision and successor SHA, if used:
- Remote branch/head:
- Draft PR number/URL/head:
- CI conclusions:
- Readiness assessment ID:
- Handoff acknowledgement/event ID:
- Final state:
- Proof that no merge/release/deployment occurred:

## Mandatory review-repair cycles

| Path | Comment/thread and classification | Authorization | Predecessor/successor SHAs | Fresh validation and CI | Final thread state | Result |
| --- | --- | --- | --- | --- | --- | --- |
| PREAPPROVED_RULE | | | | | | |
| HUMAN_ONE_OFF | | | | | | |

## Governed learning

- Learning summary ID/fingerprint and exact citations:
- Rule candidate ID/fingerprint/evaluation and inbox entry:
- Citation or threshold rejection evidence:
- Unauthorized-promotion rejection evidence:
- Human reauthentication and promotion decision:
- Created review-rule, policy-successor, and activation IDs:
- Immutable rollback successor and activation IDs:
- Proof that candidate creation granted no authority:

## Safety and recovery evidence

Add one row for every required automated test node ID and every required live
observation. Do not combine rows.

| Evidence type | Exact test node ID or live observation | Mathews SHA | Command/time | Result | Evidence/defect |
| --- | --- | --- | --- | --- | --- |
| AUTOMATED_TEST | | | | | |
| LIVE_OBSERVATION | | | | | |

## Exact-proof reconciliation

| Dimension | Expected | Observed | Result |
| --- | --- | --- | --- |
| Base/workspace predecessor | | | |
| Candidate/local HEAD | | | |
| Candidate/validation tree | | | |
| Candidate/remote branch | | | |
| Remote branch/PR head | | | |
| PR head/CI and review | | | |
| PR head/readiness/handoff | | | |
| Validation contract ID/version/digest | | | |
| Repository configuration ID/version/digest | | | |
| Policy and prompt bindings | | | |
| Accepted brief/single authorization outcome | | | |
| Steering predecessor/successor invalidation | | | |
| Preapproved-rule repair and fresh head | | | |
| Human one-off repair and fresh head | | | |
| Learning citations and candidate non-authority | | | |
| Promotion rejection/successor/rollback | | | |
| Recent authentication for protected decisions | | | |
| Duplicate or unauthorized effects | | | |

## Deviations and defects

| ID/link | Description | Impact | Resolution | Rerun evidence |
| --- | --- | --- | --- | --- |

## Cleanup

- Companion tasks closed through supported paths:
- Task-owned workspaces/processes cleaned:
- Dependency blocks removed and health restored:
- Temporary webhook stopped and prior App URL restored:
- Temporary webhook URL no longer forwards:
- Durable audit evidence retained:
- Secret scan/review result:
- Final repository states:
- Report branch/worktree and pull request:

## Sign-off

- Gate owner conclusion:
- Scope accepted:
- Known non-gating limitations:
- Production-roadmap authorization: NOT AUTHORIZED | AUTHORIZED AFTER MERGE
```
