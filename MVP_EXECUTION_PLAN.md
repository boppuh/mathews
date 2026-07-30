# MVP Execution Plan

## Purpose

This document turns the authoritative
[`MVP_IMPLEMENTATION_BACKLOG.md`](MVP_IMPLEMENTATION_BACKLOG.md) into the
fastest safe execution sequence. The backlog defines outcomes and completion
criteria; this plan defines dependency order, parallel lanes, integration
gates, and current progress.

Update the current position after every merged task or wave. Do not mark a task
complete here unless its backlog definition of done is satisfied on `main`.

## Current position

- Completed: `0.1` application workspace, `0.2` configuration and secrets,
  `0.3` durable local infrastructure, `0.4` local authentication, `1.1` domain
  schema, `1.2` minimal evidence safety foundation, and `1.3` audited task state
  machine, and `1.4` leased durable background-job loop, plus `3.1` validated
  repository configuration and read-only preflight, `5.1` deterministic
  simulator-flow contracts, and `6.1` least-privilege GitHub App authentication.
- Remaining: 29 of 40 MVP tasks.
- Active next wave: Wave 3, durable workflow core.
- Next completion target: `3.2`.

## Operating model

Use four concurrent agent slots:

1. The primary agent owns the critical path, shared contracts, integration, and
   final validation.
2. Three parallel lanes own isolated implementation areas.
3. One designated owner controls migrations, dependency files, shared settings,
   and protocol schemas in each wave.
4. Every lane starts from the current merged `main`, stays narrowly scoped, and
   merges as soon as it passes focused and repository-wide checks.

At the start of each wave, land or freeze the typed interfaces needed by all
lanes. Parallel work may implement behind those interfaces, but it must not
invent competing evidence formats, state transitions, migration histories, or
host protocols.

## Critical path

`0.3 → 0.4 → 1.1 → 1.2/1.3/1.4 → 1.5/1.6 → 3.3–3.5 + 4.3–4.4 → 5.2–5.4 → 6.2/6.4/6.5 → MVP release gate`

Work outside this path should proceed in parallel only when its required
contracts are stable. No autonomous repository mutation may begin before local
authentication, repository preflight, evidence safety, leases, cancellation,
and approval handling are durable and integrated.

## Execution waves

### Wave 1 — Durable local infrastructure

Parallel lanes:

- PostgreSQL connection/session infrastructure and repeatable migrations.
- Content-addressed artifact storage with atomic writes, hash verification,
  retrieval, corruption checks, and path-safety tests.
- Authentication interface and test preparation without merging persistence
  changes ahead of the database lane.

Exit gate:

- Complete `0.3`.
- A combined smoke test writes and retrieves a task record and a hashed
  artifact.
- Migrations can be applied repeatedly from a clean database.

### Wave 2 — Trust boundary and durable schemas

Parallel lanes:

- Critical lane, sequentially: `0.4` local authentication, then `1.1` domain
  schema. This lane exclusively owns migrations.
- `3.1` repository configuration and read-only preflight, integrating
  persistence after `1.1` lands.
- `5.1` deterministic simulator flow and typed assertion vocabulary.
- `6.1` least-privilege GitHub App authentication and webhook verification.

Exit gate:

- Complete `0.4`, `1.1`, `3.1`, `5.1`, and `6.1`.
- Authentication, domain, repository, simulator, and GitHub contracts are
  versioned and frozen for downstream work.

### Wave 3 — Durable workflow core

Parallel lanes:

- `1.2` canonical evidence envelope, redaction, access, retention, correction,
  deletion, and tombstones.
- `1.3` pure task-transition engine and audited transition service.
- `1.4` leased durable job loop, fencing, retries, idempotency, and restart
  reconciliation.
- `3.2` authenticated, allowlisted macOS host-agent protocol.

Exit gate:

- Complete `1.2`, `1.3`, `1.4`, and `3.2`.
- State transitions, jobs, evidence, and host calls pass an integrated
  fencing/restart test.

### Wave 4 — User control and orchestration

Parallel lanes:

- Critical reliability lane, sequentially: `1.5` approvals and resumable
  escalation, then `1.6` cancellation and dependency-outage handling.
- Product lane: `2.1` task creation/list, `2.2` cockpit shell, and `2.3` durable
  Server-Sent Events.
- Host lane: `3.3` task-owned workspace lifecycle.
- Agent lane: `4.1` structured briefing and `4.2` versioned role prompts.

Exit gate:

- Complete `1.5`, `1.6`, `2.1–2.3`, `3.3`, and `4.1–4.2`.
- An authenticated user can create, observe, steer, approve, cancel, and resume
  a durable task without repository mutation.

### Wave 5 — Controlled execution adapters

Parallel lanes:

- Host lane: `3.4` controlled Git operations and `3.5` build, test, and artifact
  capture.
- Agent lane: `4.3` Hermes run integration and `4.4` control-plane-authorized
  scoped code changes.
- Product lane: `2.4–2.7` evidence, approvals, steering, cancellation, and
  repository-preflight interfaces.
- GitHub lane: `6.3` signed, idempotent CI and review webhook ingestion.

Implementing `6.3` before opening automated pull requests is intentional:
signed fixtures can prove webhook ordering and idempotency before the first
real automated PR exists.

Exit gate:

- Complete `2.4–2.7`, `3.4–3.5`, `4.3–4.4`, and `6.3`.
- One controlled candidate commit can be created at an exact SHA with complete
  immutable evidence.

### Wave 6 — Validation, repair, and evidence intelligence

Parallel lanes:

- Validation lane, sequentially: `5.2` evidence collection, `5.3` exact-SHA
  decisioning, and `5.4` bounded repair.
- Evidence lane: `7.1` verified projections and `7.2` rebuildable retrieval
  index.
- Evaluation lane: `7.3` retrieval and prompt telemetry against frozen
  versions.
- Integration lane: cockpit and failure-path verification across host, Hermes,
  validation, and evidence components.

Exit gate:

- Complete `5.2–5.4` and `7.1–7.3`.
- An exact candidate SHA either passes its complete active validation contract
  or reaches a correct terminal or resumable escalation state.

### Wave 7 — Pull request, review, and controlled learning

Parallel lanes:

- Delivery lane, sequentially: `6.2` verified draft PR creation, `6.4` one
  review-resolution cycle, and `6.5` exact-head readiness and handoff.
- Learning lane, sequentially: `7.4` candidate-only learning and `7.5`
  human-governed prompt/rule promotion.
- Integration lane: complete task-cockpit and evidence-ledger acceptance flows.

Exit gate:

- Complete `6.2`, `6.4–6.5`, and `7.4–7.5`.
- The system can reach `READY_FOR_HUMAN_MERGE`, record an explicit handoff, and
  demonstrate that neither state implies merge, deployment, or release.

## Parallel delivery rules

- Do not run concurrent migrations. Use one migration owner and linear revision
  history.
- Do not let multiple lanes edit `pyproject.toml`, `uv.lock`, shared settings,
  or protocol definitions without explicit ownership.
- Prefer new modules and focused tests over edits to shared entry points.
- Rebase each lane onto the latest parent before final validation.
- Run focused checks during implementation and `npm run check` after every
  integration merge.
- Keep `main` green. A later wave may prepare against frozen interfaces, but it
  must not merge before its dependency gate.
- Do not begin production-roadmap implementation before the MVP release gate.

## MVP release gate

After Wave 7, run one recorded end-to-end acceptance task through:

`intake → briefing/approval → workspace → Hermes implementation → validation/repair → verified draft PR → CI/review → readiness → handoff`

The release evidence must also cover:

- anonymous access denial and reauthentication;
- redaction, access enforcement, correction, deletion, and tombstones;
- lease expiry, restart reconciliation, fencing, and duplicate-effect
  prevention;
- cancellation during host and Hermes activity;
- resumable host, Hermes, and GitHub outage escalation;
- duplicate, stale, out-of-order, unknown, and ambiguous webhooks;
- exact local, remote-branch, PR-head, validation-contract, configuration, and
  tree-SHA binding.
