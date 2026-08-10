# Validation evidence collection

Task 5.2 introduces the durable collection boundary between configured host
operations and validation decisioning. It records what happened; task 5.3 will
decide whether the complete run passes, fails, or escalates.

## Exact binding

A collection is accepted only while the task is `VALIDATING` and all of these
stored relationships still agree:

- task, accepted brief, and the brief's recorded approval decision;
- task and active validation contract;
- validation contract, brief, and repository configuration; and
- every configured operation result, validation-contract version, repository
  configuration version, candidate commit SHA, and candidate tree SHA.

One collection ID identifies one immutable input. Reusing that ID with changed
artifact metadata, operation output, assertion output, or Git bindings is a
conflict. An exact replay returns the original run without duplicating evidence.

## Evidence envelope

The bounded MVP evidence vocabulary is:

- unit-test output;
- integration-test output;
- simulator artifact;
- application log;
- crash signal;
- error signal;
- network signal; and
- performance signal.

The active validation contract declares which types are required. Every
reported source artifact has a unique evidence key and UUID, a canonical
SHA-256 host content address, byte size, role, origin, and optional source path.
The control plane records a redacted immutable descriptor for each source and
an aggregate validation manifest in the evidence ledger. The source artifact's
host address remains content-addressed; credentials and raw agent prose are not
accepted as verifier results.

## Typed results

Each configured operation records its operation kind, exit status, duration,
cancellation/output-limit state, repository-state check, exact configuration
and contract versions, candidate commit/tree, and direct evidence references.
The simulator E2E result also records the resolved device ID, configured device
type and runtime, locale, and time zone.

Each assertion result must exactly match an assertion ID, kind, and verifier
catalog key in the active contract. Its status is one of `PENDING`, `PASSED`,
`FAILED`, or `BLOCKED`. Every non-pending result has direct evidence references;
a pending result cannot claim evidence.

Criterion status is derived deterministically from its bound assertions:

1. any failed assertion makes the criterion failed;
2. otherwise, any blocked assertion makes it blocked;
3. otherwise, any pending assertion keeps it pending; and
4. only all-passed assertions make it passed.

The persisted criterion record contains the typed assertion results, direct
evidence UUIDs, validation-contract version, and exact candidate commit/tree.
The task cockpit renders the same fields and links evidence UUIDs to the
evidence ledger. A collected `ValidationRun` remains `PENDING` until task 5.3
evaluates completeness and the contract's outcome rules.
