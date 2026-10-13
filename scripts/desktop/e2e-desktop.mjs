#!/usr/bin/env node
// Drive a packaged Rogue Agent build end to end through its HTTP API:
// start the bundled runtime, configure Ghidra, open a binary, wait for
// analysis, list functions, decompile, and shut down cleanly.
//
//   node scripts/desktop/e2e-desktop.mjs --package out/RogueAgent-win-x64 \
//     --target sqlite3.exe --ghidra <GHIDRA_INSTALL_DIR> [--java <JAVA_HOME>]

import { spawn } from "node:child_process";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";

const { values } = parseArgs({
  options: {
    package: { type: "string" },
    target: { type: "string" },
    ghidra: { type: "string" },
    java: { type: "string" },
    timeout: { type: "string", default: "900" },
  },
});
for (const name of ["package", "target", "ghidra"])
  if (values[name] === undefined) throw new Error(`--${name} is required`);
const packageRoot = resolve(values.package);
const node = join(
  packageRoot,
  "runtime",
  process.platform === "win32" ? "node.exe" : "node",
);
const entry = join(packageRoot, "app", "scripts", "rogue-agent-desktop.mjs");
const deadline = Date.now() + Number(values.timeout) * 1000;
const step = (message) => process.stdout.write(`• ${message}\n`);

const child = spawn(
  process.platform === "win32" ? node : process.execPath,
  [entry, "--exit-with-stdin", "--port", "0"],
  { stdio: ["pipe", "pipe", "inherit"], windowsHide: true },
);
const ready = await new Promise((resolveReady, reject) => {
  let buffered = "";
  child.stdout.on("data", (chunk) => {
    buffered += chunk;
    const line = buffered
      .split("\n")
      .find((value) => value.startsWith("ROGUE_AGENT_READY "));
    if (line !== undefined)
      resolveReady(JSON.parse(line.slice("ROGUE_AGENT_READY ".length)));
  });
  child.once("exit", (code) =>
    reject(new Error(`server exited early (${code})`)),
  );
  setTimeout(() => reject(new Error("server did not report ready")), 60_000);
});
step(`server ready on port ${ready.port}`);

const base = `http://127.0.0.1:${ready.port}`;
const api = async (path, body) => {
  const response = await fetch(`${base}${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      "x-rogue-token": ready.token,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const payload = await response.json();
  if (!response.ok)
    throw new Error(`${path}: ${response.status} ${JSON.stringify(payload)}`);
  return payload;
};

let failed = false;
try {
  const unauthorized = await fetch(`${base}/api/state`);
  if (unauthorized.status !== 401)
    throw new Error("API accepted a request without the token");
  const environment = await api("/api/environment");
  step(
    `engine v${environment.version}; detected Ghidra: ${environment.ghidra.map((g) => g.version).join(", ") || "none"}`,
  );
  await api("/api/settings", {
    ghidraInstallDir: resolve(values.ghidra),
    ...(values.java === undefined ? {} : { javaHome: resolve(values.java) }),
    decompileTimeoutSeconds: 120,
  });
  const opened = Date.now();
  await api("/api/open", { path: resolve(values.target) });
  let state;
  for (;;) {
    ({ state } = await api("/api/state"));
    if (state.phase === "ready" || state.phase === "error") break;
    if (Date.now() > deadline)
      throw new Error(`analysis did not finish (phase ${state.phase})`);
    await new Promise((wait) => setTimeout(wait, 1000));
  }
  if (state.phase !== "ready")
    throw new Error(`analysis failed: ${JSON.stringify(state.error)}`);
  step(
    `analysis ready in ${((Date.now() - opened) / 1000).toFixed(1)} s: ${state.functionCount} functions`,
  );
  const { functions } = await api("/api/functions");
  const internal = functions.filter((f) => !f.external && !f.thunk);
  const main =
    internal.find((f) => /^(main|_main|wmain)$/u.test(f.name)) ?? internal[0];
  const first = await api(
    `/api/decompile?fn=${encodeURIComponent(main.address)}`,
  );
  if (typeof first.pseudocode !== "string" || first.pseudocode.length < 20)
    throw new Error(`no pseudocode for ${main.name}`);
  step(
    `decompiled ${main.name} in ${first.elapsedMs.toFixed(0)} ms (${first.pseudocode.split("\n").length} lines)`,
  );
  const again = await api(
    `/api/decompile?fn=${encodeURIComponent(main.address)}`,
  );
  step(`repeat view of ${main.name}: ${again.elapsedMs.toFixed(1)} ms`);
  const references = await api(
    `/api/references?fn=${encodeURIComponent(main.address)}`,
  );
  step(
    `${main.name}: ${references.callers.length} callers, ${references.callees.length} callees`,
  );
  const assembly = await api(
    `/api/disassembly?fn=${encodeURIComponent(main.address)}`,
  );
  if (assembly.text.length === 0) throw new Error("empty disassembly");
  const { strings } = await api("/api/strings");
  const { results } = await api(
    `/api/search?kind=functions&q=${encodeURIComponent("sqlite3_open")}`,
  );
  step(
    `${strings.length} strings; search sqlite3_open → ${results.length} matches`,
  );
  if (strings.length > 0) {
    const { usages } = await api(
      `/api/usages?addr=${encodeURIComponent(strings[0].address)}`,
    );
    step(`first string used by ${usages.length} functions`);
  }
} catch (error) {
  failed = true;
  process.stderr.write(
    `E2E failed: ${error instanceof Error ? error.message : String(error)}\n`,
  );
} finally {
  await api("/api/shutdown", {}).catch(() => undefined);
  child.stdin.end();
  const exitCode = await Promise.race([
    child.exitCode === null
      ? new Promise((done) => child.once("exit", (code) => done(code)))
      : Promise.resolve(child.exitCode),
    new Promise((done) => setTimeout(() => done(undefined), 30_000)),
  ]);
  if (exitCode === undefined) {
    child.kill();
    process.stderr.write("server did not exit after shutdown\n");
    failed = true;
  } else if (exitCode !== 0) {
    process.stderr.write(`server exited with code ${exitCode}\n`);
    failed = true;
  } else step("server shut down cleanly");
}
process.exitCode = failed ? 1 : 0;
