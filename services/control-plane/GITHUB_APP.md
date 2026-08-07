# GitHub App setup

Mathews uses one private GitHub App installation for the configured MVP
repository. The control plane verifies this manifest before relying on the
installation and mints a new repository-scoped token for each bounded
operation.

## Registration

Configure the App with **Only select repositories** and select exactly the
target repository. Do not install the App for all repositories.

Repository permissions must be exactly:

| Permission | Access |
| --- | --- |
| Checks | Read |
| Metadata | Read |
| Pull requests | Read and write |

Do not grant Contents, Actions, Administration, Deployments, Environments,
Secrets, or Workflows permission. GitHub requires Contents write for its merge
and release endpoints, so excluding it makes those actions unavailable to this
App. Repository branch protection must continue to reserve merge for a human.

Subscribe only to:

- `check_run`
- `pull_request`
- `pull_request_review`
- `pull_request_review_comment`

Set a high-entropy webhook secret of at least 16 random bytes and use JSON
payload delivery. Mathews accepts
only an exact lowercase `X-Hub-Signature-256` value and verifies HMAC-SHA256
over the untouched, size-bounded request body before parsing or persistence.

## Local credential custody

Store the App private key and webhook secret as separate generic-password items
in macOS Keychain. Configure only their opaque references:

```dotenv
MATHEWS_GITHUB_PRIVATE_KEY_REF=keychain://com.boppuh.mathews.github-app/private-key
MATHEWS_GITHUB_WEBHOOK_SECRET_REF=keychain://com.boppuh.mathews.github-app/webhook-secret
```

Also configure the numeric App, installation, and repository IDs:

```dotenv
MATHEWS_GITHUB_APP_ID=123
MATHEWS_GITHUB_INSTALLATION_ID=456
MATHEWS_GITHUB_REPOSITORY_ID=789
```

Do not put the PEM private key, webhook secret, or installation token in
`.env`, command arguments, logs, task evidence, or prompts.

## Runtime authority

`GitHubAppCredentialBroker.verify_installation()` fails closed unless the App
ID, installation ID, selected-repository mode, repository binding, exact
permission snapshot, exact event subscriptions, and suspension state all match.

Operational installation-token requests always include the one configured
numeric repository ID and one purpose-specific permission set:

| Purpose | Token permissions |
| --- | --- |
| Observe checks and PR state | Checks read, Pull requests read |
| Create or update a draft PR | Pull requests write |

The broker rejects tokens whose returned repository, permissions, or lifetime
is broader than requested and revokes every syntactically valid rejected token.
To prove that the App-wide private key has no other repository authority, the
readiness audit is the sole exception: it mints one unscoped, metadata-only
installation token, requires GitHub's complete returned repository set to
contain exactly the configured repository, then revokes that token. Revocation
uses up to three bounded attempts; a long server-directed delay or unresolved
cleanup becomes an explicit blocking error rather than an early retry or a
ready result. Token values are opaque and redacted; only repository ID and
canonical `owner/repository` context may cross the future Hermes prompt
boundary.

Task `3.4` defines a separate repository- and host-bound Git transport
credential. The GitHub App cannot supply it because Contents write would also
authorize merge and release APIs. The host resolves the versioned
configuration's opaque Keychain reference and consumes the value through an
anonymous file descriptor plus an ephemeral credential helper; it never becomes
an agent tool argument or host result. The transport reads objects through a
temporary sanitized Git directory, binds pushes to the host's durable candidate
record, and ignores repository-local transport and follow-tag configuration.
Draft-PR and observation calls remain inside the GitHub adapter. For the current
repository, the operator creates a
generic-password Keychain item with service `com.boppuh.mathews.git` and account
`mathews-push`. Its value is a fine-grained token selected for only the
configured repository with repository Contents read/write permission and no
unrelated permissions. The matching
`keychain://com.boppuh.mathews.git/mathews-push` reference must be both
`git_settings.push_credential` and an entry in the configuration's
`secret_references`. Existing configuration versions that predate this field
remain readable, but `git.push` rejects them until an operator creates a new
version with an explicitly selected credential.
