"use client";

import type {
  RepositoryConfigurationProjection,
  RepositoryConfigurationWriteRequest,
  RepositoryJsonValue,
  RepositoryProjection,
} from "@mathews/contracts";
import Link from "next/link";
import type { FormEvent } from "react";
import { useCallback, useEffect, useMemo, useState } from "react";

import { AuthRequestError, authClient } from "../../lib/auth-client";
import { formatConfigurationJson } from "../../lib/repositories";
import { RepositoryRequestError, repositoryClient } from "../../lib/repository-client";

type LoadState =
  | { status: "loading" }
  | { status: "failed"; message: string }
  | { status: "ready"; repository: RepositoryProjection };

type Draft = {
  repositorySettings: string;
  gitSettings: string;
  xcodeSettings: string;
  operations: string;
  assertions: string;
  artifactSettings: string;
  prohibitedPaths: string;
  pushCredential: string;
  e2eTestAccount: string;
  additionalSecrets: string;
};

const emptyDraft: Draft = {
  repositorySettings:
    '{\n  "root": "/absolute/path/to/repository",\n  "prohibited_operations": []\n}',
  gitSettings:
    '{\n  "default_base_ref": "refs/remotes/origin/main",\n  "task_branch_template": "codex/{task_id}",\n  "remote_name": "origin",\n  "author": { "name": "", "email": "" },\n  "committer": { "name": "", "email": "" }\n}',
  xcodeSettings:
    '{\n  "container_path": "",\n  "container_kind": "WORKSPACE",\n  "scheme": "",\n  "simulator": {\n    "runtime_identifier": "",\n    "device_type_identifier": ""\n  }\n}',
  operations: "[]",
  assertions: "[]",
  artifactSettings: '{\n  "collection_paths": []\n}',
  prohibitedPaths: '[\n  ".git"\n]',
  pushCredential: "",
  e2eTestAccount: "",
  additionalSecrets: "",
};

const labels: Record<string, string> = {
  CONFIGURATION: "Configuration",
  REPOSITORY_ROOT: "Repository root",
  GIT_TOP_LEVEL: "Git top level",
  GIT_REMOTE: "Git remote",
  BASE_REVISION: "Base revision",
  XCODE_CONTAINER: "Xcode container",
  SHARED_SCHEME: "Shared scheme",
  SIMULATOR: "Simulator",
  OPERATIONS: "Operations",
  E2E_FLOW: "E2E flow",
  ARTIFACT_PATHS: "Artifact paths",
  PROHIBITIONS: "Prohibitions",
  SECRET_REFERENCES: "Secret references",
};

function messageFrom(error: unknown, fallback: string): string {
  if (error instanceof RepositoryRequestError || error instanceof AuthRequestError) {
    return error.message;
  }
  if (error instanceof Error) return error.message;
  return fallback;
}

function draftFrom(configuration: RepositoryConfigurationProjection | null): Draft {
  if (!configuration) return emptyDraft;
  return {
    repositorySettings: formatConfigurationJson(configuration.repository_settings),
    gitSettings: formatConfigurationJson(configuration.git_settings),
    xcodeSettings: formatConfigurationJson(configuration.xcode_settings),
    operations: formatConfigurationJson(configuration.operations),
    assertions: formatConfigurationJson(configuration.e2e_assertions),
    artifactSettings: formatConfigurationJson(configuration.artifact_settings),
    prohibitedPaths: formatConfigurationJson(configuration.prohibited_paths),
    pushCredential: "",
    e2eTestAccount: "",
    additionalSecrets: "",
  };
}

function parseObject(value: string, label: string): Record<string, RepositoryJsonValue> {
  const parsed: unknown = JSON.parse(value);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${label} must be a JSON object.`);
  }
  return parsed as Record<string, RepositoryJsonValue>;
}

function parseArray(value: string, label: string): RepositoryJsonValue[] {
  const parsed: unknown = JSON.parse(value);
  if (!Array.isArray(parsed)) throw new Error(`${label} must be a JSON list.`);
  return parsed as RepositoryJsonValue[];
}

function writeRequest(
  draft: Draft,
  repositoryKey: string,
  expectedConfigurationVersion: number | null,
): RepositoryConfigurationWriteRequest {
  const additional = draft.additionalSecrets
    .split("\n")
    .map((value) => value.trim())
    .filter(Boolean);
  return {
    repository_key: repositoryKey,
    expected_configuration_version: expectedConfigurationVersion,
    repository_settings: parseObject(draft.repositorySettings, "Repository settings"),
    git_settings: parseObject(draft.gitSettings, "Git settings"),
    xcode_settings: parseObject(draft.xcodeSettings, "Xcode settings"),
    operations: parseArray(draft.operations, "Operations"),
    e2e_assertions: parseArray(draft.assertions, "Assertion catalog"),
    artifact_settings: parseObject(draft.artifactSettings, "Artifact settings"),
    prohibited_paths: parseArray(draft.prohibitedPaths, "Prohibited paths"),
    secret_updates: {
      ...(draft.pushCredential ? { push_credential: draft.pushCredential.trim() } : {}),
      ...(draft.e2eTestAccount ? { e2e_test_account: draft.e2eTestAccount.trim() } : {}),
      ...(additional.length > 0 ? { additional } : {}),
    },
    approve_sensitive_change: true,
  };
}

function textValue(value: RepositoryJsonValue | undefined): string {
  return typeof value === "string" ? value : "Not configured";
}

function objectValue(value: RepositoryJsonValue | undefined): Record<string, RepositoryJsonValue> {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value : {};
}

function shortDigest(value: string): string {
  return value.length > 22 ? `${value.slice(0, 15)}...${value.slice(-6)}` : value;
}

function ConfigurationSummary({
  configuration,
}: {
  configuration: RepositoryConfigurationProjection;
}) {
  const git = configuration.git_settings;
  const xcode = configuration.xcode_settings;
  const simulator = objectValue(xcode.simulator);
  const author = objectValue(git.author);
  const committer = objectValue(git.committer);
  const e2eOperation = configuration.operations.find(
    (operation) => objectValue(operation).kind === "SIMULATOR_E2E",
  );
  const e2e = objectValue(objectValue(e2eOperation).e2e_flow);
  const artifacts = configuration.artifact_settings.collection_paths;

  return (
    <div className="repository-details">
      <section className="repository-facts" aria-labelledby="source-heading">
        <div className="repository-section-heading">
          <p className="eyebrow">Source and target</p>
          <h2 id="source-heading">Execution boundary</h2>
        </div>
        <dl className="repository-fact-grid">
          <div>
            <dt>Repository root</dt>
            <dd>
              <code>{textValue(configuration.repository_settings.root)}</code>
            </dd>
          </div>
          <div>
            <dt>Base reference</dt>
            <dd>
              <code>{textValue(git.default_base_ref)}</code>
            </dd>
          </div>
          <div>
            <dt>Xcode target</dt>
            <dd>{textValue(xcode.scheme)}</dd>
            <small>{textValue(xcode.container_path)}</small>
          </div>
          <div>
            <dt>Simulator</dt>
            <dd>{textValue(simulator.device_type_identifier)}</dd>
            <small>{textValue(simulator.runtime_identifier)}</small>
          </div>
          <div>
            <dt>Git author</dt>
            <dd>{textValue(author.name)}</dd>
            <small>{textValue(author.email)}</small>
          </div>
          <div>
            <dt>Git committer</dt>
            <dd>{textValue(committer.name)}</dd>
            <small>{textValue(committer.email)}</small>
          </div>
        </dl>
      </section>

      <section className="repository-spec" aria-labelledby="operations-heading">
        <div className="repository-section-heading">
          <p className="eyebrow">Allowed work</p>
          <h2 id="operations-heading">Operations and E2E</h2>
        </div>
        <div className="repository-split">
          <div>
            <h3>Operations</h3>
            <ul className="operation-list">
              {configuration.operations.map((operation) => {
                const item = objectValue(operation);
                return (
                  <li key={textValue(item.operation_id)}>
                    <strong>{textValue(item.kind).replaceAll("_", " ")}</strong>
                    <span>{textValue(item.operation_id)}</span>
                    <small>{String(item.timeout_seconds ?? "?")} seconds</small>
                  </li>
                );
              })}
            </ul>
          </div>
          <div className="e2e-summary">
            <h3>E2E flow</h3>
            <dl>
              <div>
                <dt>Flow</dt>
                <dd>{textValue(e2e.flow_id)}</dd>
              </div>
              <div>
                <dt>Entry</dt>
                <dd>{textValue(e2e.entry_point)}</dd>
              </div>
              <div>
                <dt>Terminal state</dt>
                <dd>{textValue(e2e.terminal_state)}</dd>
              </div>
              <div>
                <dt>Runner</dt>
                <dd>{textValue(e2e.runner_test_identifier)}</dd>
              </div>
            </dl>
          </div>
        </div>
      </section>

      <section className="repository-spec" aria-labelledby="evidence-heading">
        <div className="repository-section-heading">
          <p className="eyebrow">Evidence contract</p>
          <h2 id="evidence-heading">Assertions and artifacts</h2>
        </div>
        <div className="repository-split">
          <div>
            <h3>Assertion vocabulary</h3>
            <div className="assertion-grid">
              {configuration.e2e_assertions.map((assertion) => {
                const item = objectValue(assertion);
                return (
                  <div key={textValue(item.assertion_id)}>
                    <strong>{textValue(item.assertion_id)}</strong>
                    <span>{textValue(item.kind).replaceAll("_", " ")}</span>
                    <small>{textValue(item.role).replaceAll("_", " ")}</small>
                  </div>
                );
              })}
            </div>
          </div>
          <div>
            <h3>Artifact paths</h3>
            <pre className="path-block">{formatConfigurationJson(artifacts ?? [])}</pre>
            <h3>Prohibited and release paths</h3>
            <pre className="path-block">
              {formatConfigurationJson(configuration.prohibited_paths)}
            </pre>
          </div>
        </div>
      </section>
    </div>
  );
}

function JsonField({
  id,
  label,
  value,
  rows,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  rows: number;
  onChange: (value: string) => void;
}) {
  return (
    <div className="repository-json-field">
      <label htmlFor={id}>{label}</label>
      <textarea
        id={id}
        value={value}
        rows={rows}
        onChange={(event) => onChange(event.currentTarget.value)}
        spellCheck={false}
        required
      />
    </div>
  );
}

export function RepositoryWorkspace() {
  const [state, setState] = useState<LoadState>({ status: "loading" });
  const [draft, setDraft] = useState<Draft>(emptyDraft);
  const [editorOpen, setEditorOpen] = useState(false);
  const [pending, setPending] = useState<"save" | "preflight" | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [confirmationOpen, setConfirmationOpen] = useState(false);
  const [approved, setApproved] = useState(false);
  const [password, setPassword] = useState("");

  const load = useCallback(async (signal?: AbortSignal) => {
    try {
      const repository = await repositoryClient.load(signal);
      setState({ status: "ready", repository });
      setDraft(draftFrom(repository.configuration));
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") return;
      setState({
        status: "failed",
        message: messageFrom(error, "Unable to load repository readiness."),
      });
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const parsedDraft = useMemo(() => {
    if (state.status !== "ready") return null;
    try {
      return writeRequest(
        draft,
        state.repository.repository_key,
        state.repository.configuration?.version ?? null,
      );
    } catch {
      return null;
    }
  }, [draft, state]);

  function update(field: keyof Draft, value: string) {
    setDraft((current) => ({ ...current, [field]: value }));
    setValidationError(null);
  }

  function beginSave(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (state.status !== "ready") return;
    try {
      writeRequest(
        draft,
        state.repository.repository_key,
        state.repository.configuration?.version ?? null,
      );
      setValidationError(null);
      setActionError(null);
      setApproved(false);
      setPassword("");
      setConfirmationOpen(true);
    } catch (error) {
      setValidationError(messageFrom(error, "The configuration JSON is invalid."));
    }
  }

  async function confirmSave(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!parsedDraft || !approved || !password || pending !== null) return;
    setPending("save");
    setActionError(null);
    try {
      await authClient.reauthenticate(password);
      const repository = await repositoryClient.save(parsedDraft);
      setState({ status: "ready", repository });
      setDraft(draftFrom(repository.configuration));
      setConfirmationOpen(false);
      setApproved(false);
      setPassword("");
      setEditorOpen(false);
    } catch (error) {
      setPassword("");
      setActionError(messageFrom(error, "Unable to save the protected change."));
    } finally {
      setPending(null);
    }
  }

  async function runPreflight() {
    if (pending !== null) return;
    setPending("preflight");
    setActionError(null);
    try {
      const repository = await repositoryClient.preflight();
      setState({ status: "ready", repository });
    } catch (error) {
      setActionError(messageFrom(error, "Unable to run repository preflight."));
    } finally {
      setPending(null);
    }
  }

  if (state.status === "loading") {
    return (
      <main className="repository-workspace repository-centered" aria-busy="true">
        <div className="task-list-status" role="status">
          Loading repository readiness...
        </div>
      </main>
    );
  }

  if (state.status === "failed") {
    return (
      <main className="repository-workspace repository-centered">
        <section className="repository-load-error">
          <p className="eyebrow">Repository unavailable</p>
          <h1>Readiness could not load</h1>
          <p>{state.message}</p>
          <button type="button" onClick={() => void load()}>
            Try again
          </button>
        </section>
      </main>
    );
  }

  const { repository } = state;
  const configuration = repository.configuration;
  const preflight = repository.preflight;
  const statusLabel = preflight.status.replaceAll("_", " ");

  return (
    <main className="repository-workspace">
      <nav className="repository-nav" aria-label="Workspace">
        <Link href="/">Work</Link>
        <Link href="/inbox">Decision inbox</Link>
        <span aria-current="page">Repository</span>
      </nav>

      <header className="repository-header">
        <div>
          <p className="eyebrow">Repository readiness</p>
          <h1>{repository.repository_key}</h1>
          <p className="lede">
            Configure the single trusted iOS source and prove that its local toolchain is ready
            before any task can mutate it.
          </p>
        </div>
        <div className={`readiness-seal readiness-${preflight.status.toLowerCase()}`}>
          <span>Mutation gate</span>
          <strong>{repository.mutation_blocked ? "Blocked" : "Ready"}</strong>
          <small>{statusLabel}</small>
        </div>
      </header>

      {actionError ? (
        <p className="repository-action-error" role="alert">
          {actionError}
        </p>
      ) : null}

      <section className="preflight-panel" aria-labelledby="preflight-heading">
        <div className="preflight-overview">
          <div>
            <p className="eyebrow">Read-only preflight</p>
            <h2 id="preflight-heading">
              {preflight.status === "PASSED"
                ? "The repository is ready"
                : preflight.status === "BLOCKED"
                  ? "The repository is blocked"
                  : "Readiness has not been proven"}
            </h2>
            <p>
              {preflight.resolved_base_sha
                ? `Base SHA ${preflight.resolved_base_sha}`
                : "Run preflight to resolve the exact base SHA and inspect every boundary."}
            </p>
          </div>
          <button
            type="button"
            onClick={() => void runPreflight()}
            disabled={!repository.configured || !repository.host_available || pending !== null}
          >
            {pending === "preflight" ? "Running preflight..." : "Run preflight"}
          </button>
        </div>
        {!repository.host_available ? (
          <p className="preflight-host-warning">The authenticated local host is unavailable.</p>
        ) : null}
        {preflight.checks.length > 0 ? (
          <div className="preflight-checks">
            {preflight.checks.map((check) => (
              <div key={check.code} className={`check-${check.status.toLowerCase()}`}>
                <strong>{labels[check.code] ?? check.code.replaceAll("_", " ")}</strong>
                <span>{check.status === "PASSED" ? "Passed" : "Blocked"}</span>
                <small>{check.detail_code.replaceAll(".", " ")}</small>
              </div>
            ))}
          </div>
        ) : (
          <div className="preflight-empty">No preflight evidence is attached to this version.</div>
        )}
      </section>

      {configuration ? (
        <>
          <div className="configuration-version-line">
            <div>
              <span>Active configuration</span>
              <strong>Version {configuration.version}</strong>
            </div>
            <code title={configuration.digest}>{shortDigest(configuration.digest)}</code>
            <time dateTime={configuration.created_at}>
              {new Intl.DateTimeFormat(undefined, {
                dateStyle: "medium",
                timeStyle: "short",
              }).format(new Date(configuration.created_at))}
            </time>
          </div>
          <ConfigurationSummary configuration={configuration} />
        </>
      ) : (
        <section className="repository-empty">
          <p className="eyebrow">Configuration required</p>
          <h2>No trusted repository version exists</h2>
          <p>Complete every configuration section, then approve the first protected version.</p>
        </section>
      )}

      <section className="repository-editor" aria-labelledby="editor-heading">
        <button
          type="button"
          className="editor-toggle"
          aria-expanded={editorOpen}
          onClick={() => setEditorOpen((current) => !current)}
        >
          <span>
            <small>Versioned settings</small>
            <strong id="editor-heading">
              {configuration ? "Edit configuration" : "Create configuration"}
            </strong>
          </span>
          <span aria-hidden="true">{editorOpen ? "Close" : "Open"}</span>
        </button>

        {editorOpen ? (
          <form className="repository-form" onSubmit={beginSave}>
            <div className="repository-form-intro">
              <p>
                Every save creates a new immutable version. JSON must match the bounded repository
                contract exactly.
              </p>
            </div>
            <div className="repository-form-grid">
              <JsonField
                id="repository-settings"
                label="Repository settings"
                value={draft.repositorySettings}
                rows={8}
                onChange={(value) => update("repositorySettings", value)}
              />
              <JsonField
                id="git-settings"
                label="Git identity and branch settings"
                value={draft.gitSettings}
                rows={12}
                onChange={(value) => update("gitSettings", value)}
              />
              <JsonField
                id="xcode-settings"
                label="Xcode target and simulator"
                value={draft.xcodeSettings}
                rows={12}
                onChange={(value) => update("xcodeSettings", value)}
              />
              <JsonField
                id="operations"
                label="Build, test, and E2E operations"
                value={draft.operations}
                rows={18}
                onChange={(value) => update("operations", value)}
              />
              <JsonField
                id="assertions"
                label="Assertion vocabulary"
                value={draft.assertions}
                rows={18}
                onChange={(value) => update("assertions", value)}
              />
              <JsonField
                id="artifacts"
                label="Artifact settings"
                value={draft.artifactSettings}
                rows={7}
                onChange={(value) => update("artifactSettings", value)}
              />
              <JsonField
                id="prohibited-paths"
                label="Prohibited and release paths"
                value={draft.prohibitedPaths}
                rows={10}
                onChange={(value) => update("prohibitedPaths", value)}
              />
            </div>

            <fieldset className="secret-reference-fields">
              <legend>Write-only secret references</legend>
              <p>
                Leave a field blank to preserve its current value. Saved references are never shown
                again.
              </p>
              <div>
                <label htmlFor="push-credential">Git push credential reference</label>
                <input
                  id="push-credential"
                  type="password"
                  autoComplete="off"
                  value={draft.pushCredential}
                  onChange={(event) => update("pushCredential", event.currentTarget.value)}
                  placeholder={
                    configuration?.secrets.push_credential_configured
                      ? "Configured, leave blank to preserve"
                      : "Opaque reference required"
                  }
                />
              </div>
              <div>
                <label htmlFor="test-account">E2E test account reference</label>
                <input
                  id="test-account"
                  type="password"
                  autoComplete="off"
                  value={draft.e2eTestAccount}
                  onChange={(event) => update("e2eTestAccount", event.currentTarget.value)}
                  placeholder={
                    configuration?.secrets.e2e_test_account_configured
                      ? "Configured, leave blank to preserve"
                      : "Opaque reference required"
                  }
                />
              </div>
              <div className="secret-reference-wide">
                <label htmlFor="additional-secrets">
                  Additional secret references, one per line
                </label>
                <textarea
                  id="additional-secrets"
                  rows={4}
                  value={draft.additionalSecrets}
                  onChange={(event) => update("additionalSecrets", event.currentTarget.value)}
                  placeholder={
                    configuration?.secrets.additional_reference_count
                      ? `${configuration.secrets.additional_reference_count} configured, leave blank to preserve`
                      : "Optional opaque references"
                  }
                />
              </div>
            </fieldset>

            {validationError ? (
              <p className="repository-action-error" role="alert">
                {validationError}
              </p>
            ) : null}
            <div className="repository-form-actions">
              <p>Invalid settings cannot create a version or unlock mutation.</p>
              <button type="submit" disabled={pending !== null}>
                Review protected save
              </button>
            </div>
          </form>
        ) : null}
      </section>

      {confirmationOpen ? (
        <div className="confirmation-backdrop" role="presentation">
          <section
            className="confirmation-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-heading"
          >
            <p className="eyebrow">Protected change</p>
            <h2 id="confirm-heading">Approve a new execution boundary</h2>
            <p>
              This configuration controls repository access, Git identity, Xcode execution, tests,
              artifacts, and prohibited paths.
            </p>
            <form onSubmit={confirmSave}>
              <label className="confirmation-check">
                <input
                  type="checkbox"
                  checked={approved}
                  onChange={(event) => setApproved(event.currentTarget.checked)}
                />
                <span>I reviewed these settings and approve creating a new immutable version.</span>
              </label>
              <label htmlFor="configuration-password">Current password</label>
              <input
                id="configuration-password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.currentTarget.value)}
                required
              />
              {actionError ? (
                <p className="repository-action-error" role="alert">
                  {actionError}
                </p>
              ) : null}
              <div className="confirmation-actions">
                <button
                  type="button"
                  onClick={() => {
                    setConfirmationOpen(false);
                    setPassword("");
                    setActionError(null);
                  }}
                  disabled={pending !== null}
                >
                  Go back
                </button>
                <button type="submit" disabled={!approved || !password || pending !== null}>
                  {pending === "save" ? "Saving version..." : "Approve and save"}
                </button>
              </div>
            </form>
          </section>
        </div>
      ) : null}
    </main>
  );
}
