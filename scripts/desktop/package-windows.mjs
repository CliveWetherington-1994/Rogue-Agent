#!/usr/bin/env node
// Assemble the portable Windows build of Rogue Agent:
//
//   RogueAgent-win-x64/
//     RogueAgent.exe            native WebView2 window (desktop/launcher)
//     WebView2Loader.dll        only for MinGW-built launchers
//     rea.cmd                   CLI / MCP entry for agents (`rea.cmd mcp`)
//     runtime/node.exe          pinned Node.js runtime (SHA-256 verified)
//     app/                      compiled engine, bridge, UI, production deps
//     ghidra/                   bundled Ghidra release (SHA-256 verified)
//     jdk/                      bundled Temurin JDK for Ghidra (SHA-256 verified)
//
// Run after `npm run build` and `npm run build:windows-native`. Works on Linux
// (cross-build) and Windows. Usage:
//   node scripts/desktop/package-windows.mjs --launcher <RogueAgent.exe> [--out out] [--zip]
//     [--no-bundled-tools] [--tools-cache <dir>]
//
// Ghidra and the JDK are pinned in desktop/packaging/bundled-tools.json. Parts
// the app never reads (documentation, uninstalled extensions, source archives,
// non-Windows native binaries, JDK jmods) are left out.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import {
  createReadStream,
  createWriteStream,
  existsSync,
  openAsBlob,
} from "node:fs";
import { tmpdir } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
} from "node:path";
import { Readable, Writable } from "node:stream";
import { finished, pipeline } from "node:stream/promises";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import {
  BlobReader,
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
    "no-bundled-tools": { type: "boolean", default: false },
    "tools-cache": {
      type: "string",
      default: join(root, ".cache", "bundled-tools"),
    },
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

// ----------------------------------------------------------- bundled tools

const sha256File = (path) =>
  new Promise((resolveDigest, reject) => {
    const hash = createHash("sha256");
    createReadStream(path)
      .on("data", (chunk) => hash.update(chunk))
      .on("error", reject)
      .on("end", () => resolveDigest(hash.digest("hex")));
  });

/** The pinned archive from the cache, downloading and verifying it if needed. */
const fetchVerified = async (tool) => {
  await mkdir(values["tools-cache"], { recursive: true });
  const path = join(
    values["tools-cache"],
    `${tool.sha256}-${basename(new URL(tool.url).pathname)}`,
  );
  if ((await exists(path)) && (await sha256File(path)) === tool.sha256)
    return path;
  log(`downloading ${tool.name} ${tool.version}`);
  const response = await fetch(tool.url);
  if (!response.ok || response.body === null)
    fail(`download failed (${response.status}): ${tool.url}`);
  const partial = `${path}.partial`;
  await pipeline(Readable.fromWeb(response.body), createWriteStream(partial));
  if ((await sha256File(partial)) !== tool.sha256) {
    await rm(partial, { force: true });
    fail(`${tool.name} ${tool.version} failed SHA-256 verification`);
  }
  await rename(partial, path);
  return path;
};

/** Extract the archive's release directory into `destination`, minus exclusions. */
const unpackTool = async (tool, archive, destination) => {
  const excluded = tool.exclude.map((pattern) => new RegExp(pattern, "u"));
  const reader = new ZipReader(new BlobReader(await openAsBlob(archive)));
  let files = 0;
  for (const entry of await reader.getEntries()) {
    if (entry.directory) continue;
    if (!entry.filename.startsWith(tool.root))
      fail(`${tool.name} archive has an unexpected entry: ${entry.filename}`);
    const name = entry.filename.slice(tool.root.length);
    if (name === "" || excluded.some((pattern) => pattern.test(name))) continue;
    const target = join(destination, ...name.split("/"));
    const inside = relative(destination, target);
    if (inside.startsWith("..") || isAbsolute(inside))
      fail(`${tool.name} archive entry escapes its directory: ${name}`);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, await entry.getData(new Uint8ArrayWriter()));
    files++;
  }
  await reader.close();
  return files;
};

const bundledTools = values["no-bundled-tools"]
  ? undefined
  : JSON.parse(
      await readFile(
        join(root, "desktop/packaging/bundled-tools.json"),
        "utf8",
      ),
    );
const toolArchives = {};
if (bundledTools !== undefined)
  for (const [key, tool] of Object.entries(bundledTools))
    toolArchives[key] = await fetchVerified(tool);

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
  [
    "@echo off",
    "setlocal",
    // The bundled Ghidra and JDK serve unless the caller chose a Ghidra.
    'if not defined GHIDRA_INSTALL_DIR if exist "%~dp0ghidra\\support\\analyzeHeadless.bat" (',
    '  set "GHIDRA_INSTALL_DIR=%~dp0ghidra"',
    '  if exist "%~dp0jdk\\bin\\javac.exe" set "JAVA_HOME=%~dp0jdk"',
    ")",
    '"%~dp0runtime\\node.exe" "%~dp0app\\scripts\\rea.mjs" %*',
    "",
  ].join("\r\n"),
);
await writeFile(
  join(staging, "README.txt"),
  [
    "Rogue Agent",
    "===========",
    "",
    "Start RogueAgent.exe and open a binary. Ghidra and a JDK are included",
    "(ghidra\\ and jdk\\); to use your own instead, choose their folders in",
    "Settings. Builds made with --no-bundled-tools need Ghidra 12.1.x and JDK 21+",
    "installed; both are detected automatically in the usual places.",
    "",
    "Agents can use the same engine over MCP:  rea.cmd mcp",
    "Command line:                             rea.cmd --help",
    "",
    "Logs: %LOCALAPPDATA%\\RogueAgent\\logs   Settings: %APPDATA%\\RogueAgent",
    "",
  ].join("\r\n"),
);

if (bundledTools !== undefined) {
  for (const [key, tool] of Object.entries(bundledTools)) {
    log(`bundling ${tool.name} ${tool.version}`);
    const files = await unpackTool(
      tool,
      toolArchives[key],
      join(staging, tool.directory),
    );
    log(`  ${files} files in ${tool.directory}\\`);
  }
  for (const required of [
    "ghidra/support/analyzeHeadless.bat",
    "ghidra/Ghidra/application.properties",
    "ghidra/Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe",
    "ghidra/LICENSE",
    "jdk/bin/java.exe",
    "jdk/bin/javac.exe",
    "jdk/release",
    "jdk/legal",
  ])
    if (!(await exists(join(staging, required))))
      fail(`bundled tools are incomplete: ${required} is missing`);
}

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
  // Streamed to disk: with Ghidra and the JDK the archive is several hundred MB.
  const output = createWriteStream(zipPath);
  const writer = new ZipWriter(Writable.toWeb(output), { level: 6 });
  const add = async (path) => {
    const info = await lstat(path);
    if (info.isSymbolicLink()) return;
    const name = `RogueAgent/${relative(staging, path).split("\\").join("/")}`;
    if (info.isDirectory()) {
      for (const entry of await readdir(path)) await add(join(path, entry));
      return;
    }
    await writer.add(name, new BlobReader(await openAsBlob(path)), {
      lastModDate: info.mtime,
    });
  };
  await add(staging);
  await writer.close();
  await finished(output);
  await writeFile(
    `${zipPath}.sha256`,
    `${await sha256File(zipPath)}  ${basename(zipPath)}\n`,
  );
  log(
    `wrote ${zipPath} (${((await stat(zipPath)).size / 1024 / 1024).toFixed(1)} MiB)`,
  );
}
