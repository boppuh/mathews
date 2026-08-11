# Verified evidence projections and provenance

Task 7.1 adds read-time views over the canonical evidence envelopes from Task
1.2. A projection is not another evidence record, artifact, cache, or storage
format. It is derived from the existing immutable envelope after its artifact
address, envelope metadata, and content hash have been verified.

## Projection vocabulary

Every live source is classified as one of:

- request;
- repository state;
- tool operation;
- test artifact;
- CI;
- review;
- result; or
- external event.

The view exposes the canonical evidence UUID, source kind, origin, actor,
task/validation bindings, root/causation/parent lineage, envelope hash, content
hash, verification state, access class, retention policy, corrections,
rebuildable derivatives, and task-event references. It never returns the
envelope content.

CI and review events enter the ledger as signed, internal GitHub webhook
evidence. Their task association comes from the existing ordered
`TaskEventEvidenceReference`, so the projection does not rewrite or copy the
webhook. Trusted workers use the internal service view for these records; the
browser API cannot enumerate `INTERNAL` evidence.

## Access and verification

The authenticated browser endpoints are:

- `GET /api/evidence/tasks/{task_id}/projections`; and
- `GET /api/evidence/{evidence_id}/provenance`.

Both endpoints are bounded to at most 200 results, disable browser caching, and
apply the original access classification to every returned record. A root that
is not accessible returns the same not-found response as absent evidence.
Related provenance nodes are independently authorized, preventing a visible
parent from revealing an internal or recent-password child. Recent-password
evidence only appears while the session's reauthentication window is active.

Before a live record is projected, the service reloads its canonical artifact
and verifies:

1. the content-addressed envelope bytes;
2. record-to-envelope identity, ownership, access, retention, and lineage;
3. the envelope hash; and
4. the redacted content hash.

A verification failure fails the whole query instead of presenting unverified
metadata as trusted evidence. Each returned node also creates the existing
non-content `METADATA_READ` audit event.

## Corrections, deletion, and provenance

Corrections remain append-only evidence. The original projection becomes
`SUPERSEDED`, links to its successor, and the provenance graph adds a directed
`CORRECTS` edge. Evidence whose parent correlation resolves to another evidence
UUID adds a directed `PARENT` edge. Traversal is bounded and returns a
`truncated` marker when more authorized nodes exist.

A deletion request immediately changes the projection to
`DELETION_PENDING`, before content destruction. A completed tombstone changes
it to `DELETED`, reports the durable reason and timestamp, and reflects deleted
derivatives. The original envelope artifact is not reopened after either
deletion fence, so its content hash is no longer projected. The retained
envelope address continues to identify the destroyed source without retaining
or reconstructing its content.

These rules let Task 7.2 build a disposable retrieval index from verified
sources while preserving the ledger as the only authority. Index entries must
retain the evidence UUID, source hash, access class, and deletion state from
this service and must never weaken its per-record authorization.
