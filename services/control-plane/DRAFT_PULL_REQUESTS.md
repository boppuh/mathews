# Verified draft pull requests

Task 6.2 publishes a pull request only for the exact clean Git candidate that
passed the task's current validation contract. The control plane treats draft
publication as an audited state transition, not as an unverified GitHub side
effect.

## Publication sequence

`VerifiedDraftPullRequestService.open` performs the following fenced sequence:

1. Load the task's accepted brief, active validation contract, and immutable
   repository configuration while the task is `VALIDATING`.
2. Require a current `PASSED` validation decision for exact commit `C` and its
   exact tree, contract version, and repository configuration version.
3. Ask the authenticated host, under a current task lease, to prove that the
   task branch is clean and its local head and tree equal the validated objects.
4. Push only expected head `C`. The host independently rejects a changed,
   unowned, dirty, incorrectly parented, or path-invalid candidate and reports
   the observed remote branch head.
5. Reconcile or create one draft pull request for the exact task branch using a
   repository-scoped `pull_requests:write` GitHub App token. More than one open
   branch PR, a non-draft PR, or any GitHub head other than `C` closes the gate.
6. Inspect the local branch again, observe the PR again from GitHub, and recheck
   the current validation decision and task bindings.
7. Capture immutable `draft-pull-request-proof` evidence containing the exact
   validation, local, remote, and PR identities plus a digest of the rendered PR
   content.
8. Bind the PR's installation, repository ID, number, branch, head, and required
   checks for webhook correlation, then transition `VALIDATING` to `PR_ACTIVE`.

The transition gate reloads and verifies the immutable proof inside the locked
state transaction. It also verifies the persisted passing validation run,
current brief/contract/configuration bindings, and the absence of an unresolved
approval or cancellation fence. Callers cannot submit gate booleans.

## Pull-request content

The draft body is derived from persisted, accepted inputs and contains:

- the task summary;
- the accepted scope;
- acceptance criteria;
- the contract's required operations, typed assertions, and evidence
  requirements; and
- known risks.

The proof stores a SHA-256 digest of the exact title and body. It does not store
GitHub credentials or host filesystem paths.

## Invalidation and retry behavior

Validation is bound to both commit and tree. A changed file, tree, commit, task
binding, local branch, remote branch, or GitHub PR head prevents `PR_ACTIVE` and
requires a new complete validation pass. A prior pass cannot be applied to a
new candidate.

The GitHub publisher first queries by exact owner, task branch, base branch, and
open state. A retry reuses the single matching draft and refuses ambiguous
matches, preventing duplicate pull requests. Host push operations use the task
transition ID in their idempotency keys. Every minted GitHub installation token
is revoked after the bounded GitHub operation, including error paths.

## Required production wiring

Construct the service with:

- `ValidationDecisionService`;
- `LeaseBoundDraftPullRequestHost` backed by `LocalHostGateway`;
- `GitHubDraftPullRequestPublisher` backed by the repository's
  `GitHubAppCredentialBroker`;
- `GitHubWebhookService` as the pull-request binder; and
- the configured GitHub installation and repository IDs.

The caller supplies a current durable job-lease grant for every host boundary.
The service deliberately does not accept a raw PR body, repository name,
branch, or validation outcome from an external client. Candidate SHA inputs are
never trusted: they must match the current validation decision and every host,
remote, and GitHub observation.
