# Validation decisioning

Task 5.3 turns one fully collected validation run into an immutable,
fail-closed decision for an exact candidate commit and tree. The decision is
made by the control plane from stored contract results and evidence; host-agent
prose cannot declare a pass.

## Exact candidate binding

Decisioning locks the validation run and task, then verifies that all of these
still identify the same active attempt:

- the latest `BEGIN_VALIDATION` or `REVALIDATE` transition and its attempt ID;
- the candidate commit SHA and tree SHA;
- the task's active validation contract and repository configuration; and
- the contract and configuration versions copied into every operation and
  criterion result.

A change to the attempt, candidate, active contract, active configuration, or
task validation state produces a `BLOCKED` decision with
`VALIDATION_BINDING_STALE`. Previously stored decisions remain queryable for
audit, but their `is_current` projection becomes false when one of these exact
bindings changes.

## Fail-closed outcomes

The MVP supports the contract rule `{ "all_required": true }`. Decisioning uses
the following precedence:

1. a cancelled task produces `CANCELLED`;
2. stale candidate or contract bindings produce `BLOCKED`;
3. unsupported outcome rules, incomplete or invalid typed results, missing or
   unreadable evidence, corrected evidence, and blocked or pending assertions
   produce `ESCALATED`;
4. any required failed operation, assertion, or acceptance criterion produces
   `FAILED`; and
5. only complete, internally consistent, all-passed required results with all
   required immutable evidence produce `PASSED`.

The service reloads every evidence object through content-address verification,
checks the manifest against the exact run bindings, checks all result evidence
references, and rejects duplicate or unexpected evidence types. Missing or
corrupt evidence can therefore never degrade into a pass.

## Immutable decision record

One `VALIDATION_DECIDED` task event and one `validation-decision` evidence
record are written for each run. The evidence includes the exact attempt,
contract, configuration, commit, tree, outcome, stable reason code, source
evidence IDs, decision time, and a deterministic fingerprint. Replaying the
same run verifies and returns that stored decision instead of producing a
second event.

The final write is protected by the background job's current lease and fencing
token. The validation-evidence worker renews its lease after collection and
invokes decisioning immediately, so a reclaimed worker cannot publish a late
outcome.

## Exact-SHA query

Authenticated control-plane consumers query:

`GET /api/validation-decisions/{task_id}/{commit_sha}/{tree_sha}`

The endpoint returns only a decision whose task, commit SHA, and tree SHA match
exactly. The response includes all immutable binding IDs and versions, the
outcome and reason code, its decision evidence ID, decision time, and
`is_current`. Invalid, unknown, incomplete, or integrity-invalid decisions are
reported uniformly as unavailable and are never substituted with the latest
decision for another candidate.
