# Candidate-only learning

Task 7.4 keeps learning outputs outside every authority-bearing plane. It can
produce compact cited summaries and evaluated Rule Inbox candidates, but it
cannot create an approval, review rule, active policy version, prompt version,
permission, or workflow transition.

## Cited summaries

A summary is a rebuildable evidence derivative, not a source record. Its
canonical redacted payload always declares `NON_AUTHORITATIVE` and binds:

- the exact task;
- the compact summary;
- every cited source-evidence UUID and current canonical envelope hash; and
- a deterministic fingerprint of the complete claim and citation set.

Every citation must be live, readable, task-owned, unsuperseded, and free of a
pending deletion request. A correction, deletion request, missing artifact, or
hash mismatch makes the summary unavailable for subsequent candidate creation.
Exact lineage is stored for every source, so deleting any citation destroys the
summary bytes and removes any unapproved candidate derived from it.

## Rule candidates

An evaluated `RuleCandidate` may be created only from a current cited summary.
It copies the summary's exact source UUIDs, records the summary UUID in its
lineage, and stores a bounded structured evaluation containing scope, matcher,
permitted action, risk class, and evidence requirements. Candidate creation is
idempotent by caller-provided UUID and conflicts on changed content.

`RuleCandidate` remains non-executable. This service has no dependency on the
approval, prompt-promotion, policy, transition, or host-operation services. A
separate human-governed promotion flow must revalidate all cited evidence and
the exact evaluated definition before creating any authority-bearing record.

## Production ingestion

Authenticated control-plane clients submit bounded learning drafts through the
task-scoped `learning-summaries` and `rule-candidates` API routes. The routes
invoke the same idempotent service boundary and always attribute writes to the
fixed `candidate-learning-api` actor. Authentication and CSRF enforcement, a
candidate-specific 192 KiB body limit, deterministic redaction, exact runtime-rule
validation, and evidence integrity checks all apply before an output can appear
in the Rule Inbox.
