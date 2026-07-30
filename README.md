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
endpoint, GitHub App and installation identifiers, and these opaque references:

| Setting | Keychain reference |
| --- | --- |
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
