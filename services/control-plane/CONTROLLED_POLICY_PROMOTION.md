# Controlled policy promotion

Task 7.5 closes the authority boundary between evaluated candidates and the
active policy. Candidate generation and evaluation remain non-authoritative;
only a recently reauthenticated local human can activate a successor
`PolicyVersion` or roll one back.

## Prompt promotion

`POST /api/prompts/{candidate_id}/promotions` binds the decision to all of the
following inputs:

- the exact prompt candidate UUID and integer version;
- one active immutable evaluation-contract version;
- one exact retrieval, verifier, model, and model-version comparison group;
- every immutable agent-run evaluation in that group;
- a completed human regression review;
- the currently active policy as the explicit rollback target; and
- caller-supplied activation, promoted-prompt, and policy UUIDs plus an
  activation timestamp within the bounded clock-skew window.

The service recomputes the frozen thresholds in the activation transaction.
Evaluation writers take the same policy-lineage lock and reject new rows after
that candidate has an activation record, so the comparison group cannot change
while promotion is committing.
It rejects missing, ineligible, cross-policy, stale, ambiguous, or changed
inputs. A successful transaction creates the promoted immutable prompt, copies
the remaining active policy memberships, creates the successor policy, and
writes its `PolicyActivation` audit record atomically.

## Rule promotion

Rule promotion remains part of the exact `REVIEW_RULE` approval flow. Approval
requires a recently reauthenticated local human. Immediately before activation
the service reloads and locks the candidate and cited evidence, verifies the
stored evaluation and approval fingerprints, and records the exact candidate
fingerprint, citations, explicit passing regression-review attestation and its
fingerprint, activation time, and prior active policy in the same transaction as
the approved `ReviewRule` and policy successor. The inbox requires the human to
confirm that review for the exact displayed candidate before approval.
Eligibility requires high severity or at least two distinct cited validation-run
identities; producer names do not count as occurrences. The approved rule provenance also
records its review time, 90-day review policy, and policy-rollback revocation
path.

Hermes, evaluation workers, and background jobs can create telemetry and
candidate records, but neither promotion route accepts their principals. They
cannot mint a browser authentication session or satisfy recent password
verification, and there is no worker route that activates policy.

## Immutable rollback

`POST /api/policies/{active_policy_id}/rollback` accepts only the rollback
target already recorded on the exact active policy. It never edits either
policy. The service creates a new successor, copies the target's ordered prompt
and rule memberships and workflow thresholds, and records a human-authorized
`ROLLBACK` activation. The policy being replaced becomes the new successor's
rollback target, so recovery remains reversible without mutating history.

All activation commands are idempotent by caller-supplied UUIDs and conflict if
the same IDs are replayed with different inputs. Exact replays remain valid
after the initial clock-skew window. The bounded caller timestamp is immutable
audit data; the server transaction time is the successor policy's effective
approval time. PostgreSQL advisory locking
serializes prompt, rule, and rollback version allocation. Request bodies are
bounded before parsing, and authenticated unsafe routes retain the normal
trusted-origin and CSRF protections.
