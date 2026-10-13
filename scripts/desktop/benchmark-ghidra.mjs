#!/usr/bin/env node
// Measure Ghidra-backed decompilation through an engine's compiled `dist/`.
//
//   node scripts/desktop/benchmark-ghidra.mjs --target sqlite3.exe \
//     [--engine <repo root>] [--label fork] [--functions 120] [--out result.json]
//
// --engine may point at any checkout with the same dist layout (for example
// upstream morluto/rea) so both are measured with identical requests. Extra
// environment for the engine: --env KEY=VALUE (repeatable).

import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const { values } = parseArgs({
  options: {
    engine: { type: "string", default: root },
    target: { type: "string" },
    label: { type: "string", default: "engine" },
    functions: { type: "string", default: "120" },
    singles: { type: "string", default: "12" },
    names: { type: "string", default: "40" },
    out: { type: "string" },
    env: { type: "string", multiple: true, default: [] },
  },
});
if (values.target === undefined) throw new Error("--target is required");
const engine = resolve(values.engine);
const load = (path) => import(pathToFileURL(join(engine, "dist", path)).href);
const [{ parseConfig }, { createBinarySession }, { silentLogger }, errors] =
  await Promise.all([
    load("config/parseConfig.js"),
    load("composition/binary.js"),
    load("logger.js"),
    load("domain/analysisErrorProjection.js"),
  ]);

const environment = { ...process.env, REA_ANALYSIS_PROVIDER: "ghidra" };
for (const pair of values.env) {
  const separator = pair.indexOf("=");
  environment[pair.slice(0, separator)] = pair.slice(separator + 1);
}
const config = parseConfig(environment);
if (!config.ok)
  throw new Error(errors.projectAnalysisError(config.error).message);
const session = createBinarySession(config.value, silentLogger, environment);
const now = () => performance.now();
const run = async (operation, parameters) => {
  const result = await session.execute(operation, parameters);
  if (!result.ok) {
    const projected = errors.projectAnalysisError(result.error);
    throw Object.assign(new Error(projected.message), { code: projected.code });
  }
  return result.value.result;
};
const digest = (text) =>
  createHash("sha256")
    .update(text ?? "<null>")
    .digest("hex")
    .slice(0, 16);

const report = { label: values.label, engine, target: resolve(values.target) };
try {
  let started = now();
  const opened = await session.open(resolve(values.target), {
    providerId: "ghidra",
  });
  if (!opened.ok)
    throw new Error(errors.projectAnalysisError(opened.error).message);
  report.openMs = now() - started;

  started = now();
  const [document] = await run("list_documents", {});
  report.startupAndAnalysisMs = now() - started;

  started = now();
  const procedures = await run("list_procedures", { document });
  report.listProceduresMs = now() - started;
  const internal = procedures
    .filter(
      (item) =>
        item.procedure?.external !== true && item.procedure?.thunk !== true,
    )
    .sort((left, right) => (left.address < right.address ? -1 : 1));
  report.functionCount = procedures.length;
  report.internalFunctionCount = internal.length;

  // Deterministic, evenly spaced samples so every engine sees the same work.
  const sample = (count, offset) =>
    Array.from(
      { length: Math.min(count, internal.length) },
      (_, index) =>
        internal[
          Math.floor(((index + offset) * internal.length) / (count + 1))
        ],
    ).filter(Boolean);
  const batch = sample(Number(values.functions), 0.5);
  const singles = sample(Number(values.singles), 0.25).filter(
    (item) => !batch.includes(item),
  );

  // 1. Fan-out batch: every request issued together (batch_decompile, export).
  started = now();
  const batchResults = await Promise.all(
    batch.map((item) =>
      run("procedure_pseudo_code", { document, procedure: item.address }).then(
        (code) => ({ address: item.address, digest: digest(code), ok: true }),
        (error) => ({
          address: item.address,
          error: error.code ?? error.message,
          ok: false,
        }),
      ),
    ),
  );
  report.batch = {
    functions: batch.length,
    ms: now() - started,
    failures: batchResults.filter((result) => !result.ok).length,
  };
  report.batch.perFunctionMs = report.batch.ms / Math.max(1, batch.length);
  report.digests = Object.fromEntries(
    batchResults.map((result) => [
      result.address,
      result.ok ? result.digest : `error:${result.error}`,
    ]),
  );

  // 2. Repeat views of the same functions (navigation back and forth).
  started = now();
  await Promise.all(
    batch.map((item) =>
      run("procedure_pseudo_code", { document, procedure: item.address }),
    ),
  );
  report.repeatMs = now() - started;

  // 3. Cold single clicks: one request at a time, each awaited.
  const singleTimes = [];
  for (const item of singles) {
    const begin = now();
    await run("procedure_pseudo_code", {
      document,
      procedure: item.address,
    }).catch(() => null);
    singleTimes.push(now() - begin);
  }
  report.singleClick = {
    functions: singleTimes.length,
    avgMs:
      singleTimes.reduce((sum, value) => sum + value, 0) /
      Math.max(1, singleTimes.length),
    maxMs: Math.max(0, ...singleTimes),
  };

  // 4. Name resolution (decompile by symbol, xrefs by name, batch identity).
  const named = sample(Number(values.names), 0.75).filter(
    (item) => !/^FUN_/u.test(item.value),
  );
  started = now();
  for (const item of named)
    await run("procedure_address", { document, procedure: item.value }).catch(
      () => null,
    );
  report.nameLookup = {
    lookups: named.length,
    avgMs: (now() - started) / Math.max(1, named.length),
  };
} finally {
  const started = now();
  await session.close();
  report.closeMs = now() - started;
}

const rounded = JSON.parse(
  JSON.stringify(report, (key, value) =>
    typeof value === "number" && !Number.isInteger(value)
      ? Math.round(value * 10) / 10
      : value,
  ),
);
process.stdout.write(
  `${JSON.stringify({ ...rounded, digests: undefined }, null, 2)}\n`,
);
if (values.out !== undefined)
  await writeFile(values.out, `${JSON.stringify(rounded, null, 2)}\n`);
