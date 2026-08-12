import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const routes = [
  "/task-lifecycle",
  "/authority-matrix",
  "/evidence-chain",
  "/mvp-release-gate",
  "/failure-recovery",
  "/operator-runbook",
  "/glossary",
];

async function render(pathname = "/") {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request(`http://localhost${pathname}`, {
      headers: { accept: "text/html" },
    }),
    {
      ASSETS: {
        fetch: async () => new Response("Not found", { status: 404 }),
      },
    },
    {
      waitUntil() {},
      passThroughOnException() {},
    },
  );
}

test("server-renders the complete field-guide index", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>Mathews System Field Guide<\/title>/i);
  assert.match(html, /8 guides/i);
  assert.match(html, /40 \/ 40 MVP tasks/i);
  assert.match(html, /href="\/mathews-architecture\.html"/i);

  for (const route of routes) {
    assert.match(html, new RegExp(`href="${route}"`, "i"));
  }
});

test("server-renders every interactive guide", async () => {
  for (const route of routes) {
    const response = await render(route);
    assert.equal(response.status, 200, route);
    assert.match(
      response.headers.get("content-type") ?? "",
      /^text\/html\b/i,
      route,
    );
    assert.match(await response.text(), /MATHEWS/i, route);
  }
});

test("preserves the reviewed architecture artifact byte-for-byte", async () => {
  const source = await readFile(
    new URL("../public/mathews-architecture.html", import.meta.url),
  );
  const digest = createHash("sha256").update(source).digest("hex");
  const html = source.toString("utf8");

  assert.equal(
    digest,
    "5f55690b6a9663775cbd3b56e630f748e76b98ecb48434a14f4a97fcd95f68a6",
  );
  assert.match(html, /sandbox="allow-scripts"/);
  assert.doesNotMatch(html, /sandbox="[^"]*allow-same-origin/);
  assert.equal((html.match(/integrity=&quot;sha256-/g) ?? []).length, 3);
  assert.equal((html.match(/crossorigin=&quot;anonymous&quot;/g) ?? []).length, 3);
});
