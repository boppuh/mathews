# Mathews

Mathews is an evidence-first workspace for turning an iOS engineering request
into a validated draft pull request while preserving human control over scope,
policy, sensitive actions, and merge.

This repository currently implements the MVP foundation described in
`MVP_ENGINEERING_SPEC.md`.

## Workspace

| Path | Responsibility |
| --- | --- |
| `apps/web` | Next.js task cockpit and local operator UI |
| `services/control-plane` | FastAPI control-plane API and durable worker entry point |
| `services/host-agent` | Narrow macOS host-agent process |
| `libraries/configuration` | Shared secret-reference and redaction contracts |
| `packages/contracts` | Shared TypeScript task and service contracts |
| `infra` | Local PostgreSQL infrastructure |
| `scripts` | Cross-service development orchestration |

## Prerequisites

- Node.js 22 and npm 10
- Python 3.13
- [uv](https://docs.astral.sh/uv/)
- Docker Desktop or another Docker Compose-compatible runtime

## Bootstrap

```bash
cp .env.example .env
npm install
uv sync --all-packages
```

No GitHub or Hermes credential value belongs in `.env`. Integration settings use
opaque Keychain references and credential values remain on the macOS host.

## Configuration and secrets

The control plane validates environment values as typed settings. A complete
automation configuration includes one absolute repository root, the Hermes
endpoint, GitHub App, installation, and exact repository identifiers, and these
opaque references:

| Setting | Keychain reference |
| --- | --- |
| `MATHEWS_HOST_AUTH_KEY_REF` | Dedicated host/control-plane HMAC key (at least 32 bytes) |
| `MATHEWS_HERMES_API_KEY_REF` | Hermes API credential |
| `MATHEWS_GITHUB_PRIVATE_KEY_REF` | GitHub App private key |
| `MATHEWS_GITHUB_WEBHOOK_SECRET_REF` | GitHub webhook secret |

References use `keychain://<service>/<account>`. Create generic-password items in
macOS Keychain Access whose service and account match the reference. Never place
the corresponding values in source files, environment files, command arguments,
or logs.

Inspect the credential-free configuration report:

```bash
uv run --package mathews-control-plane mathews-config-check
```

The command exits with status 2 until every required integration setting is
present. It reports only redaction markers and opaque provider status.

Verify that a Keychain item exists without printing its value:

```bash
uv run --package mathews-host-agent mathews-keychain-check \
  keychain://com.boppuh.mathews.github-app/private-key
```

Register the repository-scoped App and its exact permissions using
[`services/control-plane/GITHUB_APP.md`](services/control-plane/GITHUB_APP.md).
Configure the single pinned XCTest journey and its typed assertion catalog
using
[`libraries/configuration/SIMULATOR_FLOW.md`](libraries/configuration/SIMULATOR_FLOW.md).

The host agent listens only on the configured Unix socket. In production it
must be started by a per-user launchd LaunchAgent with `--launchd-socket`; the
control plane and host agent must resolve the same
`MATHEWS_HOST_AUTH_KEY_REF`, while Hermes receives neither the socket path nor
the credential. See
[`services/host-agent/LAUNCHD.md`](services/host-agent/LAUNCHD.md) for the
installation and lifecycle procedure.

## Durable local infrastructure

Local startup applies the control-plane migrations before starting the API and
worker. Apply the same repeatable migration explicitly with:

```bash
npm run db:migrate
```

Artifacts are stored beneath `MATHEWS_ARTIFACT_ROOT` using immutable
`sha256:<digest>` addresses. Writes are atomic, duplicate content is
deduplicated, and stored bytes are rehashed on every read.

The default test suite exercises database transactions and migrations without
requiring a local PostgreSQL server. CI additionally runs the combined
task-record and artifact smoke test against PostgreSQL 17. To run that test
locally, set `POSTGRES_TEST_DATABASE_URL` to a PostgreSQL database on which the
test user may create and drop schemas, then run:

```bash
npm run test:postgres
```

The integration test creates a uniquely named disposable schema, applies the
migration chain only inside that schema, and drops the schema during cleanup.

## Approvals and resumable escalation

The control plane persists brief, unsafe-action, retry-limit, review-conflict,
and review-rule decisions through the approval service. A pending escalation
stores the exact prior/resume state, a non-secret blocked-operation identity,
bounded retry history, supporting evidence references, an expiry, and immutable
request/precondition fingerprints.

Approving or retrying rechecks those durable preconditions and resumes only the
recorded state. Revision returns an exact brief to `BRIEFING`; deny or abandon
produces `FAILED`; cancel produces `CANCELLED`; expiry is audited and produces
`FAILED`. Request and decision transitions are idempotent, append task events,
and cannot be rewritten or deleted through the database. Startup reconciles
expired pending requests before serving traffic. Migration `0007` explicitly
fences pending approvals from earlier schema revisions as cancelled; any
remaining zero-fingerprint legacy rows are excluded from automatic expiry and
execution.

## Local authentication

After applying migrations, issue the one-time bootstrap token:

```bash
npm run auth:bootstrap-token
```

The command prints the raw token once and stores only its digest. Do not save the
token in `.env`, shell history, logs, or source control. Open the web UI at
`http://localhost:3000`, paste the token, and choose the local operator password.
The bootstrap token is consumed atomically when the password is created.

Mathews stores an Argon2id password hash and hashed, server-side session tokens
in PostgreSQL. Browser sessions use Secure, host-only, SameSite cookies; unsafe
requests also require an exact trusted origin and a session-bound CSRF token.
Use `localhost` for the browser and browser-facing API URL even though the API
process binds to `127.0.0.1`, because mixing those hostnames breaks strict
same-site cookie behavior.

This boundary protects the loopback HTTP interface from anonymous processes and
hostile websites. A process already running as the same operating-system user
may be able to inspect that user's environment, browser profile, or database;
use a separate OS account or sandbox when that stronger local boundary is
required.

## Run locally

```bash
npm run dev
```

The command starts PostgreSQL, the API, worker, host agent, and web application:

- Web: http://localhost:3000
- API: http://127.0.0.1:8000
- API health: http://127.0.0.1:8000/health
- Web health: http://localhost:3000/api/health

Set `MATHEWS_SKIP_POSTGRES=1` only when PostgreSQL is already managed outside
the workspace.

## Checks

```bash
npm run lint
npm run typecheck
npm test
npm run build
```

Run the complete non-build validation suite with:

```bash
npm run check
```

## Design documents

- `PRODUCT_WORKFLOW_ARCHITECTURE.md`
- `MVP_ENGINEERING_SPEC.md`
- `MVP_IMPLEMENTATION_BACKLOG.md`
- `MVP_EXECUTION_PLAN.md`
- `PRODUCTION_ENGINEERING_SPEC.md`
- `PRODUCTION_IMPLEMENTATION_BACKLOG.md`
