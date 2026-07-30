# Local authentication

The control plane has one local operator account. Loopback binding is not used
as an authentication mechanism: every route is denied by default except the
exact public allowlist (`GET /health`, `GET /api/auth/status`,
`POST /api/auth/bootstrap`, and `POST /api/auth/login`). API documentation is
disabled.

## First-run bootstrap

Apply migrations, then generate the one-time setup claim:

```sh
npm run db:migrate
npm run auth:bootstrap-token
```

The second command writes only a SHA-256 digest to PostgreSQL and prints the
256-bit raw token once. Deliver that token directly to the local setup UI; do
not put it in `.env`, command arguments, logs, or source control. Running the
command again rotates the token only while no user exists. Once setup succeeds,
the digest is consumed in the same transaction that creates the user, and token
generation is permanently refused.

The setup password must contain at least 15 characters and at most 1024 UTF-8
bytes. Only its Argon2id hash is stored.

## Browser contract

- The browser accesses the API through `localhost`; the process may still bind
  its listener to `127.0.0.1`.
- `GET /api/auth/status` returns `bootstrap_required` and
  `bootstrap_available`, and establishes a pre-authentication CSRF cookie when
  needed.
- Bootstrap and login require the exact configured web `Origin`, plus the
  readable `__Host-mathews-csrf` cookie repeated in `X-CSRF-Token`.
- Successful bootstrap, login, and reauthentication rotate both credentials.
  The opaque `__Host-mathews-session` value is never stored directly; only its
  SHA-256 digest is durable.
- Both cookies use `Secure`, `SameSite=Strict`, `Path=/`, and no `Domain`.
  The session cookie is `HttpOnly`; the CSRF cookie is intentionally readable
  so the UI can populate the header.
- `GET /api/auth/session` returns `authenticated`, `expires_at`, and
  `reauthenticated_until`. If the readable cookie was evicted, this endpoint
  rotates and repairs its server-bound CSRF value.
- All authentication and protected responses use `Cache-Control: no-store`.

Sessions have durable idle and absolute expiration timestamps. Logout revokes
the server-side session. Expired and revoked records are cleaned as new
sessions are issued and can also be cleaned explicitly by the authentication
service. Failed logins use a durable, bounded progressive throttle and always
return the same public error.

Every unsafe authenticated request requires both the exact trusted `Origin`
and a CSRF cookie/header value whose digest belongs to that session.
`require_recent_password` is the reusable dependency for secret changes,
repository-policy changes, and terminal task actions. Ordinary reads and
non-sensitive mutations require authentication and CSRF but not recent
password entry.

Future SSE handlers remain covered at connection time by the default-deny
middleware, but a long-lived stream must also call
`AuthenticationService.authenticate` periodically and close immediately after
revocation, idle expiry, or absolute expiry.
