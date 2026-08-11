# Rebuildable retrieval index

Task 7.2 adds a deterministic lexical retrieval layer over the verified
evidence projections from Task 7.1. The index is disposable and never becomes
an evidence source, workflow authority, or access-control authority.

## Storage boundary

Chunk content is stored only as a registered `EvidenceDerivative` artifact.
The canonical evidence record remains the source of truth. Each derivative is
bound to one source envelope hash and uses a task-scoped derivative type so a
taskless GitHub source may safely participate in more than one task index.
The database stores one explicit current generation per task plus a non-content
lexical projection whose term keys are salted hashes scoped to that generation.

Every chunk carries:

- source evidence UUID, envelope hash, and redacted content hash;
- original access classification and source capture time;
- projection class and exact character span;
- chunk hash and ordinal;
- task-scoped generation UUID;
- index, chunker, and verifier versions; and
- index timestamp.

The fixed MVP chunker is `mvp-char-v1`: 1,000 Unicode characters with 100
characters of overlap. JSON sources use their deterministic sorted compact
representation; text sources retain their verified redacted text. A build is
bounded to 1,000 sources and 5,000 chunks.

## Rebuild and deletion

`RetrievalIndexService.rebuild_task_index_internal` enumerates the internal
Task 7.1 projection pages. It accepts only live, verified, current-lineage
sources, then reloads and verifies every canonical envelope before creating a
chunk derivative. It never indexes deletion-pending, deleted, superseded, or
integrity-failed evidence.

Rebuilding locks the task and atomically retires the prior generation while
installing exactly one new current generation. A database uniqueness fence
prevents two live generations for the same task. Once that transaction commits,
the retired derivative artifacts are destroyed. Deleting an index clears its
lexical projections, removes the derivative artifacts, and marks its generation,
chunk, and derivative rows deleted while leaving canonical evidence untouched.
A later rebuild reads the canonical sources again, so losing the entire index
loses no source data or policy state.

Canonical evidence deletion uses the existing derivative destruction path.
Consequently its retrieval bytes disappear in the same deletion operation and
cannot be recovered by searching or rebuilding. Deleted derivative rows retain
only non-content tombstone metadata.

## Query authorization and freshness

The authenticated browser endpoint is:

- `GET /api/retrieval/tasks/{task_id}/search?q={query}&limit={1..50}`.

Responses disable browser caching. The service selects the task's explicit
current generation and ranks the non-content lexical projections before opening
a bounded candidate window. It then reauthorizes every candidate against the
original evidence record. `INTERNAL` sources are never returned to the browser;
`RECENT_PASSWORD` sources require an active reauthentication window; and
task-owner evidence rechecks task ownership. A cached access field is compared
to the immutable source record but is never trusted to grant access.

Before scoring, the service verifies the live canonical source, derivative
artifact address, source-envelope binding, source/content/chunk hashes,
timestamps, character span, and all version metadata. A corrected source's old
chunks are excluded immediately, even before the next rebuild. A deleted source
or derivative is absent from the candidate query and its bytes no longer exist.
Every source whose chunk content is returned receives the canonical
`CONTENT_DOWNLOADED` audit event without persisting the raw query.

The MVP ranker is deterministic lexical occurrence scoring. Task 7.3 will
persist the selected retrieval set, versions, cost, and outcome telemetry; Task
7.2 intentionally does not turn a search result into durable evidence or
learning state.
