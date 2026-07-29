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

No value in `.env` should contain a production credential. MVP 0.2 adds the
Keychain-backed secret-provider boundary.

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
- `PRODUCTION_ENGINEERING_SPEC.md`
- `PRODUCTION_IMPLEMENTATION_BACKLOG.md`
