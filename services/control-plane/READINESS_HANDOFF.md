# Pull-request readiness and handoff

Task 6.5 turns the state-machine readiness contracts into an authoritative,
durable workflow. It distinguishes three states that intentionally have
different meanings:

- `PR_ACTIVE` means an exact-head verified draft pull request exists, but one
  or more current readiness signals may still be missing.
- `READY_FOR_HUMAN_MERGE` means every gate is true for the current PR head. It
  does not change the pull request from draft or offer a merge operation.
- `HANDED_OFF` means a recently authenticated human explicitly accepted
  responsibility for the remaining merge, deployment, delivery, and release
  decisions. It does not assert that any of those actions happened.

## Authoritative readiness facts

Each durable GitHub webhook wake-up reevaluates readiness from canonical task
state while the eventual transition is protected by the task lock. Review
comments are classified or escalated before that reconciliation. Opening the
verified draft also triggers reconciliation after the task enters `PR_ACTIVE`,
so webhook signals received during publication are not stranded. A head is
ready only when all of these facts agree:

1. the latest `OPEN_VERIFIED_DRAFT_PR` transition has readable immutable proof
   for a complete passing validation contract;
2. the current GitHub binding, verified draft proof, validation result, local
   branch, remote branch, and pull-request head identify the same commit;
3. every required check named by the binding is present and the most recently
   updated run for each name has a passing or neutral terminal result on that
   head;
4. no current reviewer has requested changes and no review thread is open;
5. no review-resolution job is queued or running, and every still-open review
   comment is classified as informational on that exact head;
6. the pull request remains draft; and
7. no approval or cancellation fence invalidates the verified draft proof.

The service stores the fact set and blocker codes as immutable
`pull-request-readiness-assessment` evidence. The transition evaluator derives
the facts again inside the locked transaction and requires an exact match with
that evidence before entering `READY_FOR_HUMAN_MERGE`.

Only live, unsuperseded assessments created by the control plane can settle an
open informational review comment. User corrections remain visible evidence,
but cannot grant or revoke readiness authority. When no bounded production
classifier is configured, review text fails closed to a human approval instead
of being treated as informational or safe to repair.

## Invalidation

Readiness is reversible until handoff. Any later webhook for a changed head,
failed or incomplete required check, blocking review, open thread, unsettled
repair, or non-draft PR state records a new assessment and transitions the task
back to `PR_ACTIVE`. Success from an older head is never carried across a head
change.

## Explicit handoff

The cockpit offers handoff only in `READY_FOR_HUMAN_MERGE` and displays the
exact verified head. The API requires:

- an authenticated local owner with a recent password check;
- a client-generated idempotency UUID;
- the exact current head SHA; and
- the full fixed acknowledgement that merge, deployment, delivery, and release
  remain human responsibilities.

The acknowledgement is durable audit evidence. Its gate recomputes readiness
inside the transition lock, binds the evidence to the same exact head, and
then records `ACKNOWLEDGE_HANDOFF`. Replays return the original transition.
There is no GitHub ready-for-review, merge, deployment, delivery, or release
method in this service or request contract.
