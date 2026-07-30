import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { TASK_STATES } from "./index";

const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));
const pythonExecutable = fileURLToPath(new URL("../../../.venv/bin/python", import.meta.url));

function pythonTaskStates(): unknown {
  const output = execFileSync(
    pythonExecutable,
    [
      "-c",
      [
        "import json",
        "from mathews_control_plane.domain_models import TASK_STATE_VALUES",
        "print(json.dumps(TASK_STATE_VALUES))",
      ].join("; "),
    ],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
    },
  );

  return JSON.parse(output);
}

describe("TaskState contract parity", () => {
  it("matches the Python domain model exactly and in canonical order", () => {
    expect(pythonTaskStates()).toEqual(TASK_STATES);
  });
});
