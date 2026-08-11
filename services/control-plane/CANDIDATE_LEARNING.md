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
The first cited source anchors the derivative so normal evidence deletion also
removes its stored bytes.

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
