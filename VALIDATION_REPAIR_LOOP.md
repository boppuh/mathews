# Bounded validation repair loop

Task 5.4 connects a failed exact-SHA validation decision to one scoped repair,
a new host-owned candidate commit, and a complete revalidation request. The
loop is durable and fail-closed: Hermes can propose code edits, but it cannot
advance task state, create commits, declare validation success, or expand the
accepted scope.

## Scheduling a repair

After validation decisioning records `FAILED`, the validation worker asks
`ValidationRepairService` to schedule the run. Scheduling reloads and verifies
the immutable decision and manifest evidence, confirms that the failed run is
still the current attempt, and compiles the active implementer prompt with only
those two bounded evidence records.

The durable `validation-repair` job carries the exact failed run, commit and
tree, active contract and configuration IDs and versions, failure fingerprint,
decision/manifest evidence IDs, and compiled prompt provenance. Repeating the
same scheduling command returns the original job.

## Retry and equivalent-failure bounds

The active policy may define:

```json
{
  "validation_repair_policy": {
    "max_attempts": 2,
    "approval_lifetime_seconds": 86400
  }
}
```

If omitted, the same values are the bounded MVP defaults. `BEGIN_REPAIR`
increments the task retry count, and a job cannot start once that count reaches
the policy maximum.

The control plane fingerprints only the stable failed operation, assertion,
criterion, result-code, and contract identity—not candidate SHAs, run IDs, or
evidence UUIDs. The same effective failure on a later candidate therefore
escalates instead of looping.

An exhausted budget or equivalent failure creates a `RETRY_LIMIT` approval
with the exact failure evidence and stored resume state `VALIDATING`. The inbox
offers only `RETRY`, `ABANDON`, and `CANCEL`:

- `RETRY` authorizes exactly one additional repair job, and that decision ID is
  consumed by that job;
- `ABANDON` ends the task as `FAILED`; and
- `CANCEL` ends it as `CANCELLED`.

No approval changes the policy or grants an unbounded retry sequence.

## Scoped repair execution

The repair worker performs these fenced steps:

1. It verifies the current failed run and records `BEGIN_REPAIR` with the
   decision and manifest evidence.
2. It runs the compiled implementer prompt through the existing lease-bound
   Hermes adapter. Every inspection or patch still passes through the
   control-plane tool policy and host allowlist.
3. It asks the host—not Hermes—to create a new candidate commit. For repairs,
   the host replaces the previous host-owned candidate with a new clean commit
   whose parent remains the frozen task base. External or unowned heads remain
   rejected.
4. It records immutable `validation-repair-candidate` evidence containing the
   new commit/tree, changed paths, failed candidate, Hermes run, and active
   contract/configuration bindings.
5. It issues `REVALIDATE` with the new exact commit/tree pair.

Lease and fencing checks protect every transition and evidence write. A host
dependency outage uses the existing bounded outage retry and resumable
escalation path. Cancellation revokes the job lease and tools. A deterministic
unrecoverable repair error transitions the task explicitly to `FAILED`.

## Complete-contract revalidation

After `REVALIDATE`, the worker records immutable `validation-rerun-request`
evidence and a `VALIDATION_RERUN_REQUESTED` task event. That request contains
the complete active contract: every required operation, typed assertion,
evidence requirement, clean/simulator setup, flow, timeout, and outcome rule,
all bound to the new candidate and active configuration versions.

The validation execution/collection boundary consumes that request exactly as
it consumes an initial validation attempt. No result or pass from the failed
candidate is copied forward; the new candidate must collect fresh evidence and
pass Task 5.3 decisioning independently.
