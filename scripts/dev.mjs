import { spawn, spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

if (process.env.MATHEWS_SKIP_POSTGRES !== "1") {
  const database = spawnSync(
    "docker",
    [
      "compose",
      "--project-directory",
      workspaceRoot,
      "-f",
      path.join(workspaceRoot, "infra/compose.yaml"),
      "up",
      "-d",
      "--wait",
      "postgres",
    ],
    {
      cwd: workspaceRoot,
      stdio: "inherit",
    },
  );

  if (database.error?.code === "ENOENT") {
    console.error(
      "Docker is required for the default local startup. " +
        "Install Docker Desktop or set MATHEWS_SKIP_POSTGRES=1 when PostgreSQL is already running.",
    );
    process.exit(1);
  }

  if (database.status !== 0) {
    process.exit(database.status ?? 1);
  }
}

const services = [
  {
    name: "web",
    command: "npm",
    args: ["run", "dev", "--workspace", "@mathews/web"],
  },
  {
    name: "api",
    command: "uv",
    args: [
      "run",
      "--package",
      "mathews-control-plane",
      "uvicorn",
      "mathews_control_plane.app:app",
      "--reload",
      "--host",
      "127.0.0.1",
      "--port",
      "8000",
    ],
  },
  {
    name: "worker",
    command: "uv",
    args: ["run", "--package", "mathews-control-plane", "mathews-worker"],
  },
  {
    name: "host-agent",
    command: "uv",
    args: ["run", "--package", "mathews-host-agent", "mathews-host-agent"],
  },
];

const children = new Map();
let shuttingDown = false;

function shutdown(signal = "SIGTERM", exitCode = 0) {
  if (shuttingDown) {
    return;
  }

  shuttingDown = true;
  for (const child of children.values()) {
    child.kill(signal);
  }
  process.exitCode = exitCode;
  setTimeout(() => process.exit(exitCode), 250);
}

for (const service of services) {
  const child = spawn(service.command, service.args, {
    cwd: workspaceRoot,
    env: {
      ...process.env,
      PYTHONUNBUFFERED: "1",
    },
    stdio: "inherit",
  });

  children.set(service.name, child);
  child.on("error", (error) => {
    console.error(`[${service.name}] failed to start: ${error.message}`);
    shutdown("SIGTERM", 1);
  });
  child.on("exit", (code, signal) => {
    children.delete(service.name);
    if (!shuttingDown) {
      console.error(`[${service.name}] exited unexpectedly (${signal ?? code ?? "unknown"}).`);
      shutdown("SIGTERM", code ?? 1);
    }
  });
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
