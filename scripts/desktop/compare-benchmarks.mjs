#!/usr/bin/env node
// Summarise benchmark JSON files as a Markdown table and check that every
// engine produced identical pseudocode for the shared function sample.
//   node scripts/desktop/compare-benchmarks.mjs baseline.json fork.json [...]

import { readFile } from "node:fs/promises";

const reports = await Promise.all(
  process.argv
    .slice(2)
    .map(async (path) => JSON.parse(await readFile(path, "utf8"))),
);
if (reports.length === 0)
  throw new Error("pass one or more benchmark JSON files");
const [baseline] = reports;
const seconds = (ms) =>
  ms === undefined ? "—" : `${(ms / 1000).toFixed(2)} s`;
const millis = (ms) => (ms === undefined ? "—" : `${ms.toFixed(1)} ms`);
const speedup = (base, value) =>
  base === undefined || value === undefined || value === 0
    ? ""
    : ` (${(base / value).toFixed(1)}×)`;

const rows = [
  ["Startup + auto-analysis", (r) => r.startupAndAnalysisMs, seconds],
  ["Reopen same binary (new session)", (r) => r.reopenStartupMs, seconds],
  ["List functions", (r) => r.listProceduresMs, millis],
  ["Batch decompile (all at once)", (r) => r.batch?.ms, seconds],
  ["  per function", (r) => r.batch?.perFunctionMs, millis],
  ["Repeat views of the batch", (r) => r.repeatMs, millis],
  ["Single click (cold, avg)", (r) => r.singleClick?.avgMs, millis],
  ["Name lookup (avg)", (r) => r.nameLookup?.avgMs, millis],
  ["Largest functions (all at once)", (r) => r.largest?.ms, seconds],
  ["Close", (r) => r.closeMs, millis],
];
const lines = [
  `Target: \`${baseline.target}\` — ${baseline.functionCount} functions (${baseline.internalFunctionCount} internal), batch of ${baseline.batch?.functions}, ${baseline.largest?.functions ?? 0} largest functions`,
  "",
  `| Measurement | ${reports.map((r) => r.label).join(" | ")} |`,
  `| --- | ${reports.map(() => "---:").join(" | ")} |`,
  ...rows.map(
    ([name, pick, format]) =>
      `| ${name} | ${reports
        .map(
          (report, index) =>
            `${format(pick(report))}${index === 0 ? "" : speedup(pick(baseline), pick(report))}`,
        )
        .join(" | ")} |`,
  ),
];
// A reopen that reused the stored analysis must reproduce the first run.
let reopenMismatches = 0;
for (const report of reports)
  if (report.reopen?.reusedAnalysis === true)
    reopenMismatches += report.reopen.mismatches;
let mismatches = 0;
// Ghidra's auto-analysis can vary between runs of one engine. A function whose
// output differs across engines is attributed to that variation only when an
// engine's own independent analyses disagree on it, or when one engine's
// second analysis reproduces the other's output.
const varies = new Set();
for (const report of reports.slice(1)) {
  for (const [address, value] of Object.entries(baseline.digests ?? {})) {
    const other = report.digests?.[address];
    if (other === value) continue;
    const explained =
      baseline.analysisVariance?.includes(address) === true ||
      report.analysisVariance?.includes(address) === true ||
      baseline.independentDigests?.[address] === other ||
      report.independentDigests?.[address] === value;
    if (explained) varies.add(address);
    else mismatches++;
  }
}
const sampled = Object.keys(baseline.digests ?? {}).length;
lines.push(
  "",
  mismatches === 0
    ? `Pseudocode identical across engines for ${sampled - varies.size} of ${sampled} sampled functions.`
    : `**${mismatches} sampled functions produced different pseudocode across engines.**`,
);
if (reopenMismatches > 0)
  lines.push(
    "",
    `**${reopenMismatches} sampled functions decompiled differently after reopening from the stored analysis.**`,
  );
if (varies.size > 0)
  lines.push(
    "",
    `${varies.size} sampled ${varies.size === 1 ? "function differs" : "functions differ"} between independent Ghidra analyses of the same engine, so ${varies.size === 1 ? "it is" : "they are"} not compared: ${[...varies].join(", ")}.`,
  );
process.stdout.write(`${lines.join("\n")}\n`);
if (mismatches > 0 || reopenMismatches > 0) process.exitCode = 1;
