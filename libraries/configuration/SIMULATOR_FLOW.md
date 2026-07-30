# Deterministic simulator-flow contract

Task 5.1 freezes the configuration contract for the one MVP simulator journey.
It does not execute Xcode or decide whether validation passed. Execution belongs
to task 3.5, evidence/result capture belongs to task 5.2, and exact-SHA
decisioning belongs to task 5.3.

## Repository-owned flow

One `RepositoryConfiguration` contains exactly one `SIMULATOR_E2E` operation
and one `E2EFlow`. The operation:

- invokes `xcodebuild test` directly;
- is bound to the configured workspace, shared scheme, and simulator;
- contains exactly one `-only-testing:<target/class/test>` selector matching the
  flow's `runner_test_identifier`;
- contains no `-skip-testing` selector or runtime-authored command; and
- cannot archive, export, provision, deploy, merge, tag, release, or run a
  shell.

The selected XCTest owns the deliberately narrow, production-like action
sequence. Mathews does not accept a runtime UI-action DSL or an agent-authored
test script.

## Repeatable setup

Every invocation must apply the fixed sequence:

1. `SHUTDOWN`
2. `ERASE`
3. `BOOT`
4. `INSTALL_CANDIDATE`

`clean_state_before_each_run` is required to be `true`. Re-running the
operation therefore starts another complete clean-state cycle; a prior
simulator or application state is never reused.

The flow also binds:

- a fixture ID, version, repository path, and SHA-256 digest;
- a test-account recipe ID, version, repository path, and SHA-256 digest;
- an opaque Keychain reference for the account secret;
- the fixed `en_US_POSIX` locale and `UTC` time zone;
- the launched application's bundle identifier; and
- a prohibited XCTest source root plus every harness/control file by repository
  path and SHA-256 digest.

Harness pins include the shared scheme, workspace definition, exactly one
dedicated harness-project definition, the selected runner source, and all
repository-owned XCTest/verifier Swift sources. The workspace form is
mandatory so ordinary application-project changes remain available to tasks
while the validation target remains isolated and prohibited from mutation.
The flow records the harness project path, target PBX object identifier, and
runner source path.

Preflight parses the pinned workspace and a deliberately restricted scheme.
The scheme contains only a `Debug` `TestAction`, one unskipped
`TestableReference`, and its exact `BuildableReference`; build actions, test
plans, selected/skipped-test lists, launch/profile/archive actions, macro
expansions, arguments, environments, and unknown execution children or
attributes fail closed. This proves that the workspace references the harness
project and the test action selects the configured project, target identifier,
and XCTest target name. Preflight then
parses the complete OpenStep project document rather than searching text for
PBX-shaped fragments. Object text inside comments cannot act as a decoy. The
target's Swift file references must equal the pinned source set exactly and use
repository-contained paths. Scheme execution actions, command-line arguments,
environment overrides, external `.xcconfig` references, build-file settings,
unknown target build settings, target/package dependencies, synchronized
source groups, build rules, shell phases, and nonempty resource/framework
phases fail closed. Project-level build settings must be empty; target settings
use a small non-path allowlist and require generated Info.plist metadata. A
same-named source, unrelated project, response file, bridging header, compiler
plugin, or linker input therefore cannot bypass the pinned closure.

All non-control harness files must remain under the prohibited source root, so
a task cannot add an automatically discovered test helper beside the pinned
sources. Preflight also requires the source root's regular-file set to equal
the pinned source-file set exactly. Every pinned harness, fixture, and recipe
path is also a prohibited task-change path. Read-only host preflight resolves
each path within the repository and rehashes its bytes. A missing, extra,
escaped, oversized, or changed file blocks the `E2E_FLOW` check.

Preflight also proves that every pin is a `100644 blob` at the resolved base
commit and that its raw working-tree bytes are identical to that blob.
Executable entries, symlinks, submodules, and other tree-entry types fail
closed. It compares the base blob object ID with
`git hash-object --no-filters` for the working file; Git attributes,
line-ending normalization, text conversion, and custom clean/process filters
cannot stand in for byte equality. The harness-root file set must be identical
in the resolved tree and working tree. This is readiness evidence, not reusable
validation evidence: task 3.5 must repeat the same containment, exact-file-set,
tree-entry, and digest checks after proving clean `HEAD` and tree equal
candidate `C`, immediately before launch.

The account recipe contains no credential value. Task 3.5 will resolve the
opaque Keychain reference only inside the host trust boundary and make the
recipe and deterministic fixture available to the pinned XCTest.

Preflight parses both pinned JSON files with bounded, exact schemas. The fixture
manifest is:

```json
{
  "schema_version": 1,
  "fixture_id": "primary",
  "fixture_version": 1,
  "values": {
    "task.title": "Deterministic title"
  }
}
```

`values` contains at most 256 bounded string values, and every element
verifier's expected-value key must resolve. The account recipe is:

```json
{
  "schema_version": 1,
  "recipe_id": "primary-account",
  "recipe_version": 1,
  "credential_source": "OPAQUE_SECRET_REFERENCE"
}
```

Unknown fields fail closed, so a credential value cannot be added to the
repository recipe.

## Typed baseline assertions

The repository catalog must cover all five MVP kinds. Each entry has an enum
kind, an explicit `FLOW_BASELINE` or `TASK_SELECTABLE` role, and a matching
structured verifier payload:

| Kind | Deterministic verifier configuration |
| --- | --- |
| `ELEMENT_VALUE_PRESENT` | accessibility identifier and optional expected-value fixture key |
| `NAVIGATION_STATE_REACHED` | state ID and marker accessibility identifier |
| `EXPECTED_NETWORK_RESPONSE` | endpoint class, HTTP method, and expected status code |
| `EXPECTED_LOG_EVENT` | subsystem, category, event key, and minimum count |
| `NO_CRASH` | launched application bundle identifier |

The flow's required baseline assertion IDs must resolve only to
`FLOW_BASELINE` entries and cover every kind. Its terminal state, network
signals, log signals, and bundle identifier must match the structured verifier
fields, not merely a friendly catalog alias. Required signals cannot also be
acceptable warnings. Task criteria can select only `TASK_SELECTABLE` entries.
A criterion may explicitly require its own `NO_CRASH` entry in addition to the
universal baseline; every baseline and task-selectable no-crash verifier must
name the launched application bundle.

Catalog keys identify pinned repository-owned verifier implementations. They
cannot contain scripts, predicates, regular expressions, prose, or result
claims.

## Task-specific assertion contract

`TaskAssertionContract` binds one task to:

- the exact accepted brief ID, version, and digest;
- the exact persisted brief-approval decision ID;
- the accepted brief's complete criterion-ID set;
- the exact repository configuration ID, version, and digest;
- the exact flow and fixture IDs, versions, and digests;
- the flow-wide baseline assertion IDs;
- the accepted brief's exact required task-selectable assertion IDs for every
  acceptance criterion; and
- the matching catalog assertion selections.

Compilation copies each assertion kind and verifier catalog key from the
immutable repository catalog. Unknown assertions, omitted criteria, duplicated
bindings, baseline substitutions, weaker/extra selections, configuration drift,
brief drift, and extra serialized fields fail closed. A direct constructor
cannot mint an accepted-brief projection or task-contract digest.

`AcceptedBriefAssertionSource.from_approval_record` consumes a typed
`PersistedBriefApprovalRecord` and rejects every disposition except
`ACCEPTED`. The record object is a transport projection, not proof that storage
was queried. Task 4.1's control-plane persistence adapter exclusively owns
loading that projection by decision ID and checking its task, brief, version,
digest, disposition, and criterion requirements. Task 5.2 must reload and
revalidate the same decision-to-brief binding before accepting results; callers
must not treat construction of an in-memory record as persistence authority.

Flow-wide baseline assertions remain separate from task-specific criterion
bindings. This avoids falsely attributing a universal safeguard or required
logging to an unrelated product criterion while still allowing an accepted
criterion to demand its own typed no-crash assertion.

There is intentionally no assertion-result, pass flag, evidence reference,
free-form claim, or executable predicate in this contract. Those records are
introduced only by tasks 5.2 and 5.3, where deterministic verifier output and
direct evidence become authoritative.
