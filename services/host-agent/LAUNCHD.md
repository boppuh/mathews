# macOS host agent

The host agent is a per-user, non-root LaunchAgent. It accepts exactly one
length-prefixed authenticated request per connection on a private Unix domain
socket. There is no TCP listener or generic command endpoint.

Task worktrees live beneath the journal directory's private `workspaces`
registry. The `workspace.create`, `workspace.inspect`, and `workspace.cleanup`
operations require signed task-lease authority. Creation freezes the configured
base ref to a commit SHA; cleanup revalidates the signed repository
configuration and removes only a path with the exact task/configuration
ownership record. Cancellation cleanup also requires a canonical cancellation
identifier.

Controlled Git operations are limited to `git.inspect`, `git.commit`, and
`git.push`. Commit identity is read from the signed versioned repository
configuration. Push resolves the configuration's opaque Keychain reference only
inside the host process, supplies the value to Git through an anonymous file
descriptor and ephemeral askpass helper, and sends only the durably recorded
host-created candidate to the exact task branch. The authenticated transport
uses a temporary, sanitized Git directory so repository-local proxy, CA, URL
rewrite, follow-tag, and push-recursion settings are not trusted. No force, tag,
merge, or release operation is available. Candidate staging also uses a
sanitized Git directory, and repositories that configure external Git clean,
process, or smudge filters are rejected before workspace inspection or commit.

## Prerequisites

1. Create the runtime directory with mode `0700`:

   ```bash
   install -d -m 700 "$HOME/Library/Application Support/Mathews"
   ```

2. In Keychain Access, create a generic-password item with service
   `com.boppuh.mathews.host-agent` and account `control-plane-hmac-v1`. Generate
   at least 32 random bytes for its value. This MVP resolves the item through
   macOS `security(1)`: it keeps the value out of files and process arguments,
   but it does not claim isolation from another hostile process already running
   as the same user in the unlocked login session. The production roadmap adds
   signed host identity and stronger credential isolation.

3. Create a second, distinct generic-password item for the repository's
   `git_settings.push_credential` reference. For this repository, use service
   `com.boppuh.mathews.git` and account `mathews-push`, and store a fine-grained
   token selected for only the configured repository with repository Contents
   read/write permission and no unrelated permissions. Include the opaque
   reference in the repository configuration's `secret_references`. Do not
   reuse the host HMAC, GitHub App, webhook, or E2E account credential.

4. Configure the repository's effective fetch and push remote as credential-free
   HTTPS, for example `https://github.com/boppuh/mathews.git`. SSH/SCP remotes,
   embedded credentials, queries, and fragments fail preflight. Re-point an
   existing SSH remote before deployment.

5. Configure the control plane with the host HMAC reference and socket path:

   ```dotenv
   MATHEWS_HOST_AUTH_KEY_REF=keychain://com.boppuh.mathews.host-agent/control-plane-hmac-v1
   MATHEWS_HOST_AUTH_KEY_ID=host-control-plane-v1
   MATHEWS_HOST_SOCKET_PATH="/Users/<you>/Library/Application Support/Mathews/host-agent.sock"
   ```

The credential value must never be placed in an environment file, plist,
command argument, log, prompt, or artifact.

## Render and install

After `uv sync --all-packages`, render the fixed plist using absolute paths:

```bash
uv run --package mathews-host-agent mathews-host-agent-plist \
  --executable "$PWD/.venv/bin/mathews-host-agent" \
  --socket-path "$HOME/Library/Application Support/Mathews/host-agent.sock" \
  --journal-path "$HOME/Library/Application Support/Mathews/host-agent.sqlite3" \
  --auth-reference keychain://com.boppuh.mathews.host-agent/control-plane-hmac-v1 \
  --auth-key-id host-control-plane-v1 \
  --host-id local-macos-host \
  > "$HOME/Library/LaunchAgents/com.boppuh.mathews.host-agent.plist"
```

Inspect the generated plist, then load it into the current GUI user domain:

```bash
launchctl bootstrap "gui/$(id -u)" \
  "$HOME/Library/LaunchAgents/com.boppuh.mathews.host-agent.plist"
```

launchd owns the listening socket and starts the process on demand. The process
requires the launchd descriptor when `--launchd-socket` is present and fails
closed instead of falling back to a self-bound listener.

For explicit development only, omit `--launchd-socket` and run
`mathews-host-agent` directly; the same private-path, authentication, framing,
allowlist, journal, and fencing checks still apply.

## Health and removal

`mathews-host-agent --once` prints a side-effect-free process probe. The
authenticated `host.health` operation tests the actual socket boundary.

Unload the agent before replacing its executable or plist:

```bash
launchctl bootout "gui/$(id -u)/com.boppuh.mathews.host-agent"
```

The durable journal is intentionally retained across restarts and upgrades so
that completed operations replay and ambiguous in-flight work is never
silently executed twice.

Task-scoped mutations are serialized with durable fence advancement. Every
mutating allowlist handler must perform each narrow side effect through the
host authorization guard, which rechecks the current lease immediately around
the effect. A higher fencing token cannot take over while that effect is in
progress. Lease renewal may proceed between effects. Once an effect attempt
starts, any later handler, result-validation, or journal-finalization failure
leaves the operation `RUNNING` and reports `AMBIGUOUS`; it is never durably
misreported as a clean failure. Read-only operations do not require the
mutation guard.

On SIGTERM, the server stops accepting connections, closes active transports,
and gives handlers a bounded grace period. A handler that does not cooperate
cannot keep the LaunchAgent process alive indefinitely; its reserved operation
remains `RUNNING` in the journal and is therefore reconciled as ambiguous after
restart. Control-plane connection deadlines are separate from response
deadlines, and repository preflight receives a bounded 30-second response
budget for its sequential probes. Controlled push transport uses one bounded
local object-store probe plus at most three eight-second network operations;
`git.push` therefore receives its own 30-second response budget.

An interrupted task operation remains `AMBIGUOUS`; the control plane may inspect
it with `operation.reconcile` but must not rerun a possible mutation. The
read-only repository preflight is repository-scoped, so a lost in-flight
preflight is abandoned and retried as a new preflight attempt with a new
idempotency key.
