# Review resolution

Task 6.4 adds one policy-gated repair cycle for a verified GitHub pull-request
review comment. It deliberately stops at updating a draft pull request. No
component in this flow exposes a merge operation.

## Trust boundary

Only an open `pull_request_review_comment` event correlated by installation,
repository, pull-request number, task branch, and exact head SHA is eligible.
The comment's own commit must equal the current bound pull-request head. Raw
signed webhook evidence remains the source; the review assessment is derived,
task-bound audit evidence.

Classifier output is strictly typed but is not authorization. It records a
disposition, category, permitted action, risk, labels, proposed paths, and
explicit dependency, schema, signing, and security-change flags. Invalid or
unbounded classifier output fails closed.

## Authorization

Automatic repair requires exactly one ReviewRule in the active policy version.
The rule must be human-approved, low-risk, match the category, labels, action,
path prefixes, file count, and declare only evidence types that this pipeline
can produce. The proposed paths must remain inside the accepted brief and
outside repository-prohibited paths. The task's configured repair budget also
applies.

Informational comments are recorded and ignored. Unmatched, conflicting,
ambiguous, speculative, higher-risk, forbidden-change, scope-expanding, or
budget-exhausted comments create a bounded `REVIEW_CONFLICT` approval request.
Approval authorizes only the exact review fingerprint, including comment,
head, classification, policy, validation contract, and repository
configuration. It never creates or modifies a RuleCandidate or ReviewRule.

## Repair cycle

The durable `review-resolution` job rechecks authorization while holding the
task transition lock, then:

1. transitions the exact `PR_ACTIVE` task to `REPAIRING`;
2. runs the implementer through the existing Hermes and scoped-tool boundary;
3. commits against the original PR head and requires a clean, new commit whose
   changed paths are all authorized;
4. records immutable candidate evidence and transitions to `VALIDATING`;
5. requires a complete, current passing validation decision for the new commit,
   tree, contract version, and repository-configuration version; and
6. uses the verified draft-PR service to push, prove, and bind that exact head
   before returning to `PR_ACTIVE`.

All transition IDs, evidence IDs, host effects, approval requests, and job
inputs are deterministic or idempotent. Replays cannot create a second repair
commit or reuse validation from an older head. Policy replacement,
cancellation, pending approval, exhausted automatic retry budget, stale task
state, or changed bindings prevent the repair from starting.

## Integration contracts

`ReviewResolutionService` accepts a `ReviewClassifier` and schedules the
durable job. `ReviewResolutionJobHandler` accepts the existing Hermes handler,
an authenticated host gateway, a `FullReviewValidator`, and the verified draft
PR publisher. Production composition must register the handler under
`review-resolution`; `build_worker` accepts that handler explicitly, registers
it under the same job type, and refuses to enable a configured automatic
classifier without it. The API approval composition accepts the same
`ReviewResolutionService` as its approval continuation so an approved one-off
repair deterministically reschedules its original review event. Tests can
inject deterministic adapters at each boundary.
