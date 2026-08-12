# MVP authority bootstrap

`mathews-bootstrap-mvp-authority` creates the initial immutable authority needed
by the MVP release gate. It uses the control plane's configured database and
canonical `MATHEWS_GITHUB_REPOSITORY`; it does not accept credentials or prompt
text as command-line input.

The command creates policy lineage `mvp` version 1, promoted version 1 prompts
for planner, implementer, validator, pull-request writer, and reviewer, and one
human-approved low-risk review rule. The rule can match only a formatter-labeled
`repair.format` classification for the single ordinary application source file
`mathews-ios-acceptance/ContentView.swift`. Dependency, project configuration,
CI, signing, security, schema, migration, release, deployment, test-harness,
fixture, and account-recipe paths remain outside its scope. The review pipeline
continues to route forbidden change classes and unmatched or scope-expanding
feedback to `REVIEW_CONFLICT`.

## Authority and audit identity

The initial trust anchor is attributed to local owner `local-user` and actor
`mathews-bootstrap-mvp-authority`, with the versioned approval time
`2026-08-12T00:00:00Z`. The command also creates a deterministic audit-context
task, evaluated rule candidate, and approved review-rule request because the
existing executable-rule schema requires that complete approval lineage. These
records are support evidence; they do not authorize repository mutation by
themselves.

All record and membership IDs are deterministic for this bootstrap version.
Canonical SHA-256 fingerprints cover the intended definition. The first run is
transactional. Exact replay verifies and returns the same records without
inserting anything. A changed repository, threshold, prompt, rule, membership,
approval, or audit binding fails closed. PostgreSQL advisory locking and the
SQLite write lock serialize concurrent first-run attempts.

## Operator procedure

Apply migrations and confirm the canonical repository first:

```bash
npm run db:migrate
uv run --package mathews-control-plane mathews-config-check
```

Preview the exact non-secret definition without connecting to or writing the
database:

```bash
uv run --package mathews-control-plane \
  mathews-bootstrap-mvp-authority --dry-run
```

Create or exactly replay the authority:

```bash
uv run --package mathews-control-plane mathews-bootstrap-mvp-authority
```

Verify existing records without writing:

```bash
uv run --package mathews-control-plane \
  mathews-bootstrap-mvp-authority --inspect
```

The JSON output contains only the canonical repository name, operation
(`dry-run`, `created`, `replayed`, or `inspected`), record IDs, lineages, roles,
versions, ordered membership IDs, actors, approval time, and canonical
fingerprints. It deliberately omits prompt bodies, evidence contents, database
URLs, Keychain references, credentials, and tokens. A representative shape is:

```json
{
  "operation": "created",
  "definition_fingerprint": "<64 lowercase hex characters>",
  "policy": {
    "id": "<uuid>",
    "lineage": "mvp",
    "version": 1,
    "fingerprint": "<64 lowercase hex characters>"
  },
  "prompts": [
    {
      "id": "<uuid>",
      "lineage": "mvp-planner",
      "role": "planner",
      "version": 1,
      "fingerprint": "<64 lowercase hex characters>"
    }
  ],
  "review_rule": {
    "id": "<uuid>",
    "lineage": "mvp-format-content-view",
    "version": 1,
    "fingerprint": "<64 lowercase hex characters>"
  },
  "memberships": {
    "prompt_membership_ids": ["<five ordered uuids>"],
    "review_rule_membership_ids": ["<one uuid>"]
  }
}
```

Record the real output IDs and fingerprints in Phase 0 of the release-gate
working report. Do not copy database connection details or any credential value
into that report.
