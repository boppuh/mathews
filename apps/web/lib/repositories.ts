import type {
  RepositoryConfigurationProjection,
  RepositoryJsonValue,
  RepositoryPreflightCheck,
  RepositoryPreflightProjection,
  RepositoryProjection,
  RepositorySecretStatus,
} from "@mathews/contracts";

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`The control plane returned an invalid ${label}.`);
  }
  return value as Record<string, unknown>;
}

function text(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`The control plane returned an invalid ${label}.`);
  }
  return value;
}

function nullableText(value: unknown, label: string): string | null {
  return value === null ? null : text(value, label);
}

function integer(value: unknown, label: string, minimum = 0): number {
  if (!Number.isInteger(value) || (value as number) < minimum) {
    throw new Error(`The control plane returned an invalid ${label}.`);
  }
  return value as number;
}

function boolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") {
    throw new Error(`The control plane returned an invalid ${label}.`);
  }
  return value;
}

function jsonValue(value: unknown, label: string, depth = 0): RepositoryJsonValue {
  if (depth > 16) throw new Error(`The control plane returned an invalid ${label}.`);
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) {
    return value.map((item) => jsonValue(item, label, depth + 1));
  }
  const source = record(value, label);
  return Object.fromEntries(
    Object.entries(source).map(([key, item]) => [key, jsonValue(item, label, depth + 1)]),
  );
}

function jsonObject(value: unknown, label: string): Record<string, RepositoryJsonValue> {
  const parsed = jsonValue(value, label);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`The control plane returned an invalid ${label}.`);
  }
  return parsed;
}

function jsonArray(value: unknown, label: string): RepositoryJsonValue[] {
  const parsed = jsonValue(value, label);
  if (!Array.isArray(parsed)) throw new Error(`The control plane returned an invalid ${label}.`);
  return parsed;
}

function secretStatus(value: unknown): RepositorySecretStatus {
  const source = record(value, "secret status");
  return {
    push_credential_configured: boolean(
      source.push_credential_configured,
      "push credential status",
    ),
    e2e_test_account_configured: boolean(source.e2e_test_account_configured, "E2E account status"),
    additional_reference_count: integer(source.additional_reference_count, "secret count"),
  };
}

function configuration(value: unknown): RepositoryConfigurationProjection {
  const source = record(value, "repository configuration");
  return {
    id: text(source.id, "configuration id"),
    repository_key: text(source.repository_key, "repository key"),
    version: integer(source.version, "configuration version", 1),
    digest: text(source.digest, "configuration digest"),
    created_at: text(source.created_at, "configuration timestamp"),
    actor_id: text(source.actor_id, "configuration actor"),
    repository_settings: jsonObject(source.repository_settings, "repository settings"),
    git_settings: jsonObject(source.git_settings, "Git settings"),
    xcode_settings: jsonObject(source.xcode_settings, "Xcode settings"),
    operations: jsonArray(source.operations, "operations"),
    e2e_assertions: jsonArray(source.e2e_assertions, "assertions"),
    artifact_settings: jsonObject(source.artifact_settings, "artifact settings"),
    prohibited_paths: jsonArray(source.prohibited_paths, "prohibited paths"),
    secrets: secretStatus(source.secrets),
  };
}

function preflightCheck(value: unknown): RepositoryPreflightCheck {
  const source = record(value, "preflight check");
  const status = text(source.status, "preflight check status");
  if (status !== "PASSED" && status !== "BLOCKED") {
    throw new Error("The control plane returned an invalid preflight check status.");
  }
  return {
    code: text(source.code, "preflight check code"),
    status,
    detail_code: text(source.detail_code, "preflight detail code"),
  };
}

function preflight(value: unknown): RepositoryPreflightProjection {
  const source = record(value, "repository preflight");
  const status = text(source.status, "preflight status");
  if (!["NOT_RUN", "RUNNING", "PASSED", "BLOCKED"].includes(status)) {
    throw new Error("The control plane returned an invalid preflight status.");
  }
  if (!Array.isArray(source.checks)) {
    throw new Error("The control plane returned invalid preflight checks.");
  }
  return {
    status: status as RepositoryPreflightProjection["status"],
    attempt_id: nullableText(source.attempt_id, "preflight attempt id"),
    configuration_id: nullableText(source.configuration_id, "preflight configuration id"),
    configuration_version:
      source.configuration_version === null
        ? null
        : integer(source.configuration_version, "preflight configuration version", 1),
    configuration_digest: nullableText(
      source.configuration_digest,
      "preflight configuration digest",
    ),
    resolved_base_sha: nullableText(source.resolved_base_sha, "resolved base SHA"),
    checks: source.checks.map(preflightCheck),
  };
}

export function parseRepositoryProjection(value: unknown): RepositoryProjection {
  const source = record(value, "repository response");
  return {
    repository_key: text(source.repository_key, "repository key"),
    configured: boolean(source.configured, "configuration status"),
    mutation_blocked: boolean(source.mutation_blocked, "mutation status"),
    configuration: source.configuration === null ? null : configuration(source.configuration),
    preflight: preflight(source.preflight),
    host_available: boolean(source.host_available, "host status"),
  };
}

export function formatConfigurationJson(value: RepositoryJsonValue): string {
  return JSON.stringify(value, null, 2);
}
