#!/usr/bin/env node

import { access } from "node:fs/promises";

// Start the Rogue Agent desktop server: the native window (desktop/launcher)
// runs this with `--exit-with-stdin`; `--browser` opens the UI in the default
// browser for development or hosts without WebView2.
const { default: packageJson } = await import("../package.json", {
  with: { type: "json" },
});
process.env.REA_PACKAGE_VERSION = packageJson.version;

// Windows home lookup throws for an empty USERPROFILE (see scripts/rea.mjs).
if (process.platform === "win32" && process.env.USERPROFILE === "") {
  delete process.env.USERPROFILE;
}

const bundled = new URL("../dist/desktop-runtime/desktop.js", import.meta.url);
const unbundled = new URL("../dist/desktopMain.js", import.meta.url);
const exists = (url) =>
  access(url).then(
    () => true,
    () => false,
  );
const entry = (await exists(bundled))
  ? bundled
  : (await exists(unbundled))
    ? unbundled
    : undefined;
if (entry === undefined) {
  process.stderr.write(
    "Rogue Agent's compiled runtime is missing. Run `npm ci && npm run build` first.\n",
  );
  process.exitCode = 1;
} else {
  const { runDesktop } = await import(entry.href);
  const code = await runDesktop(process.argv.slice(2));
  if (code !== 0) process.exitCode = code;
}
