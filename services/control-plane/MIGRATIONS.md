# Control-plane database migrations

Run all commands from the repository root. The migration environment reads
`MATHEWS_DATABASE_URL` through the normal control-plane settings.

Apply all pending migrations:

```sh
uv run --package mathews-control-plane alembic \
  -c services/control-plane/alembic.ini upgrade head
```

Verify that applying the migration target again is a no-op:

```sh
uv run --package mathews-control-plane alembic \
  -c services/control-plane/alembic.ini upgrade head
```

Create the next migration after changing SQLAlchemy metadata:

```sh
uv run --package mathews-control-plane alembic \
  -c services/control-plane/alembic.ini revision --autogenerate \
  -m "describe the schema change"
```

Inspect the current database revision:

```sh
uv run --package mathews-control-plane alembic \
  -c services/control-plane/alembic.ini current
```

The URL must be supplied through configuration rather than placed in
`alembic.ini` or command-line arguments so credentials do not enter source
control or shell history.

Revision `0008` adds cancellation, dependency-outage, owned-process, and
startup-reconciliation provenance. Its downgrade is intentionally refused once
any of those records exist; removing the tables would discard the evidence
needed to prove a cancellation fence or safely resume an outage.
