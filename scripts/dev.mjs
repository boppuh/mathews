import { spawn, spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";

const workspaceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const isWindows = process.platform === "win32";
const environmentFile = path.join(workspaceRoot, ".env");
const fileEnvironment = existsSync(environmentFile)
  ? parseEnv(readFileSync(environmentFile, "utf8"))
  : {};
const hostEnvironment = Object.fromEntries(
  [
    "MATHEWS_HOST_AUTH_KEY_ID",
    "MATHEWS_HOST_AUTH_KEY_REF",
    "MATHEWS_HOST_ID",
    "MATHEWS_HOST_JOURNAL_PATH",
    "MATHEWS_HOST_SOCKET_PATH",
  ]
    .filter((name) => process.env[name] === undefined && fileEnvironment[name] !== undefined)
    .map((name) => [name, fileEnvironment[name]]),
);

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

const migrations = spawnSync(
  "uv",
  [
    "run",
    "--package",
    "mathews-control-plane",
    "alembic",
    "-c",
    "services/control-plane/alembic.ini",
    "upgrade",
    "head",
  ],
  {
    cwd: workspaceRoot,
    env: process.env,
    stdio: "inherit",
  },
);

if (migrations.error?.code === "ENOENT") {
  console.error("uv is required to apply control-plane database migrations.");
  process.exit(1);
}

if (migrations.status !== 0) {
  process.exit(migrations.status ?? 1);
}

const services = [
  {
    name: "web",
    command: isWindows ? (process.env.ComSpec ?? "cmd.exe") : "npm",
    args: isWindows
      ? ["/d", "/s", "/c", "npm.cmd", "run", "dev", "--workspace", "@mathews/web"]
      : ["run", "dev", "--workspace", "@mathews/web"],
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
    environment: hostEnvironment,
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
      ...service.environment,
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
      shutdown("SIGTERM", code === 0 ? 1 : (code ?? 1));
    }
  });
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
