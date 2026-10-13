#!/usr/bin/env node

import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import pino from "pino";

import { PACKAGE_METADATA } from "./generatedPackageMetadata.js";
import { parseLogLevel } from "./logger.js";
import { snapshotEnvironment } from "./process/snapshotEnvironment.js";
import {
  DesktopSettingsStore,
  desktopConfigDirectory,
} from "./desktop/DesktopSettings.js";
import { DesktopWorkspace } from "./desktop/DesktopWorkspace.js";
import { startDesktopServer } from "./desktop/DesktopServer.js";

/** Line prefix the native launcher waits for on stdout. */
export const DESKTOP_READY_PREFIX = "ROGUE_AGENT_READY ";

const openInBrowser = (url: string): void => {
  const [command, args] =
    process.platform === "win32"
      ? ["rundll32.exe", ["url.dll,FileProtocolHandler", url]]
      : process.platform === "darwin"
        ? ["open", [url]]
        : ["xdg-open", [url]];
  const child = spawn(command, args, { detached: true, stdio: "ignore" });
  child.on("error", () => undefined);
  child.unref();
};

/** Start the desktop server and keep one analysis session warm until shutdown. */
export const runDesktop = async (argv: readonly string[]): Promise<number> => {
  const { values } = parseArgs({
    args: [...argv],
    options: {
      port: { type: "string" },
      token: { type: "string" },
      open: { type: "string" },
      "app-dir": { type: "string" },
      browser: { type: "boolean", default: false },
      "exit-with-stdin": { type: "boolean", default: false },
    },
    strict: true,
  });
  const environment = snapshotEnvironment(process.env);
  const configDirectory = desktopConfigDirectory(environment);
  mkdirSync(configDirectory, { recursive: true });
  const level = parseLogLevel(environment.REA_LOG_LEVEL ?? "info");
  const logger = pino(
    {
      level: level.ok ? level.value : "info",
      base: { application: "rogue-agent" },
    },
    // Synchronous: the log is low-volume, and an asynchronous file is not
    // ready if shutdown arrives right after startup (pino then throws).
    pino.destination({
      dest: join(configDirectory, "desktop.log"),
      sync: true,
      mkdir: true,
    }),
  );
  const settings = await DesktopSettingsStore.load(
    join(configDirectory, "settings.json"),
  );
  const workspace = new DesktopWorkspace({
    environment,
    logger,
    settings: () => settings.current,
  });
  let stopping: Promise<void> | undefined;
  const shutdown = (): Promise<void> => {
    stopping ??= (async () => {
      logger.info("desktop shutdown");
      await workspace.close().catch(() => undefined);
      await handle.close().catch(() => undefined);
      logger.flush();
      process.exit(0);
    })();
    return stopping;
  };
  const port = values.port === undefined ? 0 : Number(values.port);
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    process.stderr.write("--port must be an integer between 0 and 65535\n");
    return 2;
  }
  const applicationDirectory =
    values["app-dir"] !== undefined && isAbsolute(values["app-dir"])
      ? values["app-dir"]
      : undefined;
  const handle = await startDesktopServer({
    workspace,
    settings,
    environment,
    uiRoot: resolve(fileURLToPath(new URL("../desktop/ui/", import.meta.url))),
    ...(applicationDirectory === undefined ? {} : { applicationDirectory }),
    version: PACKAGE_METADATA.version,
    port,
    ...(values.token === undefined ? {} : { token: values.token }),
    onShutdown: () => void shutdown(),
  });
  process.once("SIGINT", () => void shutdown());
  process.once("SIGTERM", () => void shutdown());
  if (values["exit-with-stdin"]) {
    // The native launcher holds our stdin; its exit, even a crash, ends us.
    process.stdin.resume();
    process.stdin.once("end", () => void shutdown());
    process.stdin.once("close", () => void shutdown());
  }
  process.stdout.write(
    `${DESKTOP_READY_PREFIX}${JSON.stringify({ url: handle.url, port: handle.port, token: handle.token })}\n`,
  );
  logger.info({ port: handle.port }, "desktop server ready");
  workspace.preload();
  if (values.browser) openInBrowser(handle.url);
  if (values.open !== undefined && isAbsolute(values.open))
    void workspace.open(values.open).catch(() => undefined);
  return 0;
};

if (
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  runDesktop(process.argv.slice(2)).then(
    (code) => {
      if (code !== 0) process.exitCode = code;
    },
    (cause: unknown) => {
      process.stderr.write(
        `Rogue Agent failed to start: ${cause instanceof Error ? cause.message : String(cause)}\n`,
      );
      process.exitCode = 1;
    },
  );
}
