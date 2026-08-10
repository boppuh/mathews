import { describe, expect, it } from "vitest";

import { parseRepositoryProjection } from "./repositories";

const repositoryProjection = {
  repository_key: "boppuh/mathews",
  configured: true,
  mutation_blocked: true,
  host_available: true,
  configuration: {
    id: "11111111-1111-4111-8111-111111111111",
    repository_key: "boppuh/mathews",
    version: 3,
    digest: `sha256:${"a".repeat(64)}`,
    created_at: "2026-08-10T12:00:00Z",
    actor_id: "local-user",
    repository_settings: { root: "/tmp/mathews", prohibited_operations: ["MERGE"] },
    git_settings: { default_base_ref: "refs/remotes/origin/main" },
    xcode_settings: { scheme: "Mathews" },
    operations: [{ operation_id: "build", kind: "BUILD" }],
    e2e_assertions: [{ assertion_id: "ready", kind: "NAVIGATION_STATE_REACHED" }],
    artifact_settings: { collection_paths: ["artifacts/test.log"] },
    prohibited_paths: [".git"],
    secrets: {
      push_credential_configured: true,
      e2e_test_account_configured: true,
      additional_reference_count: 2,
    },
  },
  preflight: {
    status: "NOT_RUN",
    attempt_id: null,
    configuration_id: null,
    configuration_version: null,
    configuration_digest: null,
    resolved_base_sha: null,
    checks: [],
  },
};

describe("repository response parsing", () => {
  it("accepts the bounded redacted projection", () => {
    expect(parseRepositoryProjection(repositoryProjection)).toEqual(repositoryProjection);
  });

  it.each([
    { ...repositoryProjection, mutation_blocked: "yes" },
    { ...repositoryProjection, preflight: { ...repositoryProjection.preflight, status: "READY" } },
    {
      ...repositoryProjection,
      configuration: { ...repositoryProjection.configuration, version: 0 },
    },
    {
      ...repositoryProjection,
      configuration: {
        ...repositoryProjection.configuration,
        operations: [Number.POSITIVE_INFINITY],
      },
    },
  ])("rejects malformed repository evidence", (value) => {
    expect(() => parseRepositoryProjection(value)).toThrow("control plane returned");
  });
});
