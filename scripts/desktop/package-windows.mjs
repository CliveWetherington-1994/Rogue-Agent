#!/usr/bin/env node
// Assemble the portable Windows build of Rogue Agent:
//
//   RogueAgent-win-x64/
//     RogueAgent.exe            native WebView2 window (desktop/launcher)
//     WebView2Loader.dll        only for MinGW-built launchers
//     rea.cmd                   CLI / MCP entry for agents (`rea.cmd mcp`)
//     runtime/node.exe          pinned Node.js runtime (SHA-256 verified)
//     app/                      compiled engine, bridge, UI, production deps
//
// Run after `npm run build` and `npm run build:windows-native`. Works on Linux
// (cross-build) and Windows. Usage:
//   node scripts/desktop/package-windows.mjs --launcher <RogueAgent.exe> [--out out] [--zip]

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import {
  Uint8ArrayReader,
  Uint8ArrayWriter,
  ZipReader,
  ZipWriter,
} from "@zip.js/zip.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const { values } = parseArgs({
  options: {
    launcher: { type: "string" },
    out: { type: "string", default: join(root, "out") },
    node: { type: "string" },
    "node-cache": {
      type: "string",
      default: join(root, ".cache", "node-runtime"),
    },
    zip: { type: "boolean", default: false },
  },
});

const packageJson = JSON.parse(
  await readFile(join(root, "package.json"), "utf8"),
);
const nodeVersion = (
  values.node ?? (await readFile(join(root, ".nvmrc"), "utf8"))
)
  .trim()
  .replace(/^v/u, "");
const staging = join(resolve(values.out), "RogueAgent-win-x64");
const app = join(staging, "app");

const fail = (message) => {
  process.stderr.write(`package-windows: ${message}\n`);
  process.exit(1);
};
const exists = async (path) => {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
};
const log = (message) => process.stdout.write(`${message}\n`);

// ------------------------------------------------------------------ inputs

const launcher =
  values.launcher ??
  [
    "desktop/launcher/target/x86_64-pc-windows-msvc/release/RogueAgent.exe",
    "desktop/launcher/target/x86_64-pc-windows-gnu/release/RogueAgent.exe",
    "desktop/launcher/target/release/RogueAgent.exe",
  ]
    .map((path) => join(root, path))
    .find((path) => existsSync(path));
if (launcher === undefined || !(await exists(launcher)))
  fail(
    "RogueAgent.exe not found; build desktop/launcher first or pass --launcher",
  );
for (const required of [
  "dist/desktop-runtime/desktop.js",
  "dist/mcp/main.js",
  "dist/cli-runtime/cli.js",
  "skills/reverse-engineer-anything/SKILL.md",
])
  if (!(await exists(join(root, required))))
    fail(`${required} is missing; run \`npm run build\` first`);
const nativeManifest = join(root, "native/windows/build/manifest.json");
if (!(await exists(nativeManifest)))
  fail(
    "native/windows/build is missing; run `npm run build:windows-native` (Ghidra on Windows needs it)",
  );
const nativeVersion = JSON.parse(
  await readFile(nativeManifest, "utf8"),
).packageVersion;
if (nativeVersion !== packageJson.version)
  fail(
    `native add-on was built for ${nativeVersion}, package is ${packageJson.version}; rebuild it`,
  );

// ------------------------------------------------------------ node runtime

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const download = async (url) => {
  const response = await fetch(url);
  if (!response.ok) fail(`download failed (${response.status}): ${url}`);
  return new Uint8Array(await response.arrayBuffer());
};

const nodeArchiveName = `node-v${nodeVersion}-win-x64.zip`;
const nodeArchivePath = join(values["node-cache"], nodeArchiveName);
await mkdir(values["node-cache"], { recursive: true });
const sums = new TextDecoder().decode(
  await download(`https://nodejs.org/dist/v${nodeVersion}/SHASUMS256.txt`),
);
const expected = sums
  .split("\n")
  .map((line) => line.trim().split(/\s+/u))
  .find(([, name]) => name === nodeArchiveName)?.[0];
if (expected === undefined)
  fail(`no checksum published for ${nodeArchiveName}`);
let archive = (await exists(nodeArchivePath))
  ? new Uint8Array(await readFile(nodeArchivePath))
  : undefined;
if (archive === undefined || sha256(archive) !== expected) {
  log(`downloading Node.js ${nodeVersion} for win-x64`);
  archive = await download(
    `https://nodejs.org/dist/v${nodeVersion}/${nodeArchiveName}`,
  );
  if (sha256(archive) !== expected)
    fail(`${nodeArchiveName} failed SHA-256 verification`);
  await writeFile(nodeArchivePath, archive);
}

// ------------------------------------------------------------------ staging

await rm(staging, { recursive: true, force: true });
await mkdir(join(staging, "runtime"), { recursive: true });
await mkdir(app, { recursive: true });

const reader = new ZipReader(new Uint8ArrayReader(archive));
const prefix = `node-v${nodeVersion}-win-x64/`;
for (const entry of await reader.getEntries()) {
  if (entry.directory) continue;
  const name = entry.filename.startsWith(prefix)
    ? entry.filename.slice(prefix.length)
    : entry.filename;
  if (name !== "node.exe" && name !== "LICENSE") continue;
  await writeFile(
    join(staging, "runtime", name),
    await entry.getData(new Uint8ArrayWriter()),
  );
}
await reader.close();
if (!(await exists(join(staging, "runtime", "node.exe"))))
  fail("node.exe missing from the runtime archive");

log("copying launcher and application");
await cp(launcher, join(staging, "RogueAgent.exe"));
const importsLoader = (await readFile(launcher)).includes(
  Buffer.from("WebView2Loader.dll"),
);
if (importsLoader) {
  const loader = [
    join(dirname(launcher), "WebView2Loader.dll"),
    ...(await readdir(join(dirname(launcher), "build")).catch(() => []))
      .filter((name) => name.startsWith("webview2-com-sys-"))
      .map((name) =>
        join(
          dirname(launcher),
          "build",
          name,
          "out",
          "x64",
          "WebView2Loader.dll",
        ),
      ),
  ].find((path) => existsSync(path));
  if (loader === undefined)
    fail("launcher imports WebView2Loader.dll but no x64 copy was found");
  await cp(loader, join(staging, "WebView2Loader.dll"));
}

const copyIntoApp = async (path, options = {}) => {
  if (!(await exists(join(root, path)))) return;
  await mkdir(dirname(join(app, path)), { recursive: true });
  await cp(join(root, path), join(app, path), { recursive: true, ...options });
};
for (const path of [
  "dist",
  "skills",
  "desktop/ui",
  "native/windows/build/manifest.json",
  "native/windows/build/rea-windows-x64.node",
  "LICENSE",
  "THIRD_PARTY_NOTICES.md",
  "DISCLAIMER.md",
  "licenses",
  "scripts/rea.mjs",
  "scripts/rogue-agent-desktop.mjs",
  "scripts/rea-android-workspace-guardian.mjs",
  "scripts/electron-active-hook.cjs",
  "scripts/electron-active-hook-boundaries.cjs",
])
  await copyIntoApp(path);
// Only the Windows-capable bridges; Hopper, Swift, LLDB and pwntools stay out.
for (const path of (await readdir(join(root, "bridge/ghidra"))).filter((name) =>
  name.endsWith(".java"),
))
  await copyIntoApp(join("bridge/ghidra", path));
await copyIntoApp("bridge/android/ReaJadxBridge.java");

const appPackage = { ...packageJson };
delete appPackage.devDependencies;
delete appPackage.scripts;
delete appPackage.optionalDependencies;
delete appPackage.allowScripts;
appPackage.private = true;
await writeFile(
  join(app, "package.json"),
  `${JSON.stringify(appPackage, null, 2)}\n`,
);

log("installing production dependencies for win32-x64");
const install = await mkdtemp(join(tmpdir(), "rogue-agent-deps-"));
try {
  await cp(join(root, "package.json"), join(install, "package.json"));
  await cp(join(root, "package-lock.json"), join(install, "package-lock.json"));
  await cp(join(root, ".npmrc"), join(install, ".npmrc")).catch(
    () => undefined,
  );
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  execFileSync(
    npm,
    [
      "ci",
      "--omit=dev",
      "--omit=optional",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--os=win32",
      "--cpu=x64",
    ],
    { cwd: install, stdio: "inherit", shell: process.platform === "win32" },
  );
  await cp(join(install, "node_modules"), join(app, "node_modules"), {
    recursive: true,
  });
} finally {
  await rm(install, { recursive: true, force: true });
}

// Drop files a runtime never reads: docs, tests, type declarations, maps.
const removable = (name) =>
  /\.(?:md|markdown|map|ts|mts|cts|tsbuildinfo)$/iu.test(name) &&
  !/\.d\.ts$/iu.test(name)
    ? true
    : /\.d\.(?:ts|mts|cts)$/iu.test(name) ||
      [
        "test",
        "tests",
        "__tests__",
        "docs",
        "example",
        "examples",
        ".github",
      ].includes(name);
const prune = async (directory) => {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (
      removable(entry.name) &&
      !/^(?:license|licence|notice)/iu.test(entry.name)
    ) {
      await rm(path, { recursive: true, force: true });
      continue;
    }
    if (entry.isDirectory()) await prune(path);
  }
};
// npm's .bin shims are POSIX symlinks here and unused by the app on Windows.
await rm(join(app, "node_modules", ".bin"), { recursive: true, force: true });
await prune(join(app, "node_modules"));

await writeFile(
  join(staging, "rea.cmd"),
  '@echo off\r\n"%~dp0runtime\\node.exe" "%~dp0app\\scripts\\rea.mjs" %*\r\n',
);
await writeFile(
  join(staging, "README.txt"),
  [
    "Rogue Agent",
    "===========",
    "",
    "Start RogueAgent.exe. On first run, open Settings and choose your Ghidra 12.1.x",
    "folder (https://github.com/NationalSecurityAgency/ghidra/releases) and a JDK 21+",
    "(https://adoptium.net/). Both are detected automatically when installed in the",
    "usual places.",
    "",
    "Agents can use the same engine over MCP:  rea.cmd mcp",
    "Command line:                             rea.cmd --help",
    "",
    "Logs: %LOCALAPPDATA%\\RogueAgent\\logs   Settings: %APPDATA%\\RogueAgent",
    "",
  ].join("\r\n"),
);

const sizeOf = async (path) => {
  const info = await lstat(path);
  if (!info.isDirectory()) return info.size;
  let total = 0;
  for (const entry of await readdir(path))
    total += await sizeOf(join(path, entry));
  return total;
};
log(
  `staged ${staging} (${((await sizeOf(staging)) / 1024 / 1024).toFixed(1)} MiB)`,
);

if (values.zip) {
  const zipPath = join(
    resolve(values.out),
    `RogueAgent-${packageJson.version}-win-x64.zip`,
  );
  const writer = new ZipWriter(new Uint8ArrayWriter(), { level: 6 });
  const add = async (path) => {
    const info = await lstat(path);
    if (info.isSymbolicLink()) return;
    const name = `RogueAgent/${relative(staging, path).split("\\").join("/")}`;
    if (info.isDirectory()) {
      for (const entry of await readdir(path)) await add(join(path, entry));
      return;
    }
    await writer.add(
      name,
      new Uint8ArrayReader(new Uint8Array(await readFile(path))),
      {
        lastModDate: info.mtime,
      },
    );
  };
  await add(staging);
  const bytes = await writer.close();
  await writeFile(zipPath, bytes);
  await writeFile(
    `${zipPath}.sha256`,
    `${sha256(bytes)}  ${basename(zipPath)}\n`,
  );
  log(`wrote ${zipPath} (${(bytes.length / 1024 / 1024).toFixed(1)} MiB)`);
}
