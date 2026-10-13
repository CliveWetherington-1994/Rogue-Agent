import { execFile } from "node:child_process";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";
import { extname, isAbsolute, join, normalize, sep } from "node:path";

import { z } from "zod";

import {
  discoverGhidraInstallations,
  discoverJavaHomes,
  inspectGhidraDirectory,
  inspectJavaHome,
} from "./DesktopDiscovery.js";
import {
  desktopSettingsPatchSchema,
  type DesktopSettingsStore,
} from "./DesktopSettings.js";
import {
  DesktopError,
  type DesktopState,
  type DesktopWorkspace,
} from "./DesktopWorkspace.js";

const MAX_BODY_BYTES = 64 * 1024;

const CONTENT_TYPES: Readonly<Record<string, string>> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".png": "image/png",
};

const SECURITY_HEADERS = {
  "Content-Security-Policy":
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cache-Control": "no-store",
} as const;

const addressSchema = z
  .string()
  .min(1)
  .max(256)
  .regex(/^[\w:.$@?<>~-]+$/u, "Invalid procedure selector");

/** Options for one desktop HTTP server. */
export interface DesktopServerOptions {
  readonly workspace: DesktopWorkspace;
  readonly settings: DesktopSettingsStore;
  readonly environment: Readonly<NodeJS.ProcessEnv>;
  /** Directory holding index.html, app.js and app.css. */
  readonly uiRoot: string;
  /** Directory the application was installed to, searched for a bundled Ghidra. */
  readonly applicationDirectory?: string;
  readonly version: string;
  readonly port?: number;
  readonly token?: string;
  readonly onShutdown: () => void;
}

/** Running server coordinates printed for the native launcher. */
export interface DesktopServerHandle {
  readonly port: number;
  readonly token: string;
  readonly url: string;
  close(): Promise<void>;
}

const sameSecret = (
  expected: string,
  supplied: string | undefined,
): boolean => {
  if (supplied === undefined) return false;
  const left = Buffer.from(expected);
  const right = Buffer.from(supplied);
  return left.length === right.length && timingSafeEqual(left, right);
};

const sendJson = (
  response: ServerResponse,
  status: number,
  body: unknown,
): void => {
  const encoded = JSON.stringify(body);
  response.writeHead(status, {
    ...SECURITY_HEADERS,
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(encoded),
  });
  response.end(encoded);
};

const readJsonBody = async (request: IncomingMessage): Promise<unknown> => {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    size += buffer.length;
    if (size > MAX_BODY_BYTES)
      throw new DesktopError(
        "payload_too_large",
        "Request body is too large",
        413,
      );
    chunks.push(buffer);
  }
  if (size === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch (cause: unknown) {
    void cause;
    throw new DesktopError("invalid_json", "Request body is not JSON", 400);
  }
};

const parseOrThrow = <Schema extends z.ZodType>(
  schema: Schema,
  value: unknown,
): z.infer<Schema> => {
  const parsed = schema.safeParse(value);
  if (!parsed.success)
    throw new DesktopError(
      "invalid_request",
      parsed.error.issues.map((issue) => issue.message).join("; "),
      400,
    );
  return parsed.data;
};

/** Ask the OS for a file path when the native window cannot. */
const pickFileWithShell = (
  mode: "open" | "save",
  suggested: string | undefined,
): Promise<string | null> => {
  if (process.platform !== "win32")
    return new Promise((resolve) => {
      execFile(
        "zenity",
        mode === "open"
          ? ["--file-selection", "--title=Open binary"]
          : [
              "--file-selection",
              "--save",
              "--confirm-overwrite",
              ...(suggested === undefined ? [] : [`--filename=${suggested}`]),
            ],
        { timeout: 600_000 },
        (error, stdout) => {
          resolve(error === null ? stdout.trim() || null : null);
        },
      );
    });
  const dialog = mode === "open" ? "OpenFileDialog" : "SaveFileDialog";
  const script = [
    "Add-Type -AssemblyName System.Windows.Forms",
    `$d = New-Object System.Windows.Forms.${dialog}`,
    mode === "open"
      ? "$d.Filter = 'Programs and libraries (*.exe;*.dll;*.sys;*.so;*.elf;*.bin)|*.exe;*.dll;*.sys;*.so;*.elf;*.bin|All files (*.*)|*.*'"
      : "$d.Filter = 'C source (*.c)|*.c|All files (*.*)|*.*'",
    ...(suggested === undefined
      ? []
      : [`$d.FileName = '${suggested.replaceAll("'", "''")}'`]),
    "if ($d.ShowDialog() -eq 'OK') { [Console]::Out.Write($d.FileName) }",
  ].join("; ");
  return new Promise((resolve) => {
    execFile(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-STA", "-Command", script],
      { timeout: 600_000, windowsHide: true },
      (error, stdout) => {
        resolve(error === null ? stdout.trim() || null : null);
      },
    );
  });
};

/** Start the loopback-only API and UI server for the desktop app. */
export const startDesktopServer = async (
  options: DesktopServerOptions,
): Promise<DesktopServerHandle> => {
  const token = options.token ?? randomBytes(32).toString("hex");
  const { workspace, settings } = options;
  const eventStreams = new Set<ServerResponse>();
  const exportState = {
    running: false,
    completed: 0,
    total: 0,
    path: null as string | null,
    error: null as string | null,
  };
  const broadcast = (event: string, data: unknown): void => {
    const frame = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const stream of eventStreams) stream.write(frame);
  };
  const unsubscribe = workspace.subscribe((state: DesktopState) =>
    broadcast("state", state),
  );
  let port = 0;

  const serveStatic = async (
    pathname: string,
    response: ServerResponse,
  ): Promise<void> => {
    const relative = pathname === "/" ? "index.html" : pathname.slice(1);
    const resolved = normalize(join(options.uiRoot, relative));
    if (
      !resolved.startsWith(normalize(options.uiRoot) + sep) ||
      CONTENT_TYPES[extname(resolved)] === undefined
    ) {
      sendJson(response, 404, {
        error: { code: "not_found", message: "Not found" },
      });
      return;
    }
    try {
      const body = await readFile(resolved);
      response.writeHead(200, {
        ...SECURITY_HEADERS,
        "Content-Type": CONTENT_TYPES[extname(resolved)],
        "Content-Length": body.length,
      });
      response.end(body);
    } catch (cause: unknown) {
      void cause;
      sendJson(response, 404, {
        error: { code: "not_found", message: "Not found" },
      });
    }
  };

  const environmentReport = async () => ({
    platform: process.platform,
    version: options.version,
    settings: settings.current,
    ghidra: await discoverGhidraInstallations(
      options.environment,
      options.applicationDirectory === undefined
        ? {}
        : { applicationDirectory: options.applicationDirectory },
    ),
    java: await discoverJavaHomes(options.environment),
  });

  const absolutePathBody = z.strictObject({
    path: z.string().min(1).refine(isAbsolute, "Path must be absolute"),
  });

  const streamEvents = (
    request: IncomingMessage,
    response: ServerResponse,
  ): void => {
    response.writeHead(200, {
      ...SECURITY_HEADERS,
      "Content-Type": "text/event-stream; charset=utf-8",
      Connection: "keep-alive",
    });
    response.write(
      `event: state\ndata: ${JSON.stringify(workspace.state)}\n\n`,
    );
    eventStreams.add(response);
    const keepAlive = setInterval(
      () => response.write(": keep-alive\n\n"),
      15_000,
    );
    request.on("close", () => {
      clearInterval(keepAlive);
      eventStreams.delete(response);
    });
  };

  const updateSettings = async (body: unknown) => {
    const patch = parseOrThrow(desktopSettingsPatchSchema, body);
    if (
      typeof patch.ghidraInstallDir === "string" &&
      (await inspectGhidraDirectory(patch.ghidraInstallDir)) === undefined
    )
      throw new DesktopError(
        "invalid_ghidra",
        "That folder is not a Ghidra release (support/analyzeHeadless and Ghidra/application.properties were not found).",
        400,
      );
    if (
      typeof patch.javaHome === "string" &&
      (await inspectJavaHome(patch.javaHome)) === undefined
    )
      throw new DesktopError(
        "invalid_java",
        "That folder is not a full JDK (bin/javac and release were not found).",
        400,
      );
    return { settings: await settings.update(patch) };
  };

  const startExport = (body: unknown) => {
    const { path } = parseOrThrow(absolutePathBody, body);
    if (exportState.running)
      throw new DesktopError("busy", "An export is already running", 409);
    Object.assign(exportState, {
      running: true,
      completed: 0,
      total: 0,
      path,
      error: null,
    });
    broadcast("export", exportState);
    void workspace
      .exportAll((completed, total) => {
        Object.assign(exportState, { completed, total });
        broadcast("export", exportState);
      })
      .then((listing) => writeFile(path, listing, "utf8"))
      .catch((cause: unknown) => {
        exportState.error =
          cause instanceof Error ? cause.message : String(cause);
      })
      .finally(() => {
        exportState.running = false;
        broadcast("export", exportState);
      });
    return { export: exportState };
  };

  /** JSON routes: each returns the response body for a 200 (or 202) reply. */
  type RouteContext = {
    readonly url: URL;
    readonly body: () => Promise<unknown>;
  };
  const selector =
    (name: string) =>
    ({ url }: RouteContext): string =>
      parseOrThrow(addressSchema, url.searchParams.get(name) ?? undefined);
  const fn = selector("fn");
  const routes: Readonly<Record<string, (context: RouteContext) => unknown>> = {
    "GET /api/state": () => ({ state: workspace.state, export: exportState }),
    "GET /api/environment": () => environmentReport(),
    "POST /api/settings": async ({ body }) => updateSettings(await body()),
    "POST /api/open": async ({ body }) => {
      const { path } = parseOrThrow(absolutePathBody, await body());
      await settings.remember(path);
      return { state: await workspace.open(path) };
    },
    "POST /api/close": async () => {
      await workspace.close();
      return { state: workspace.state };
    },
    "POST /api/pick-file": async ({ body }) => {
      const request = parseOrThrow(
        z.strictObject({
          mode: z.enum(["open", "save"]).default("open"),
          suggested: z.string().optional(),
        }),
        await body(),
      );
      return { path: await pickFileWithShell(request.mode, request.suggested) };
    },
    "GET /api/functions": async () => ({
      functions: await workspace.functions(),
    }),
    "GET /api/decompile": (context) => workspace.decompile(fn(context)),
    "GET /api/disassembly": async (context) => ({
      text: await workspace.disassembly(fn(context)),
    }),
    "GET /api/info": async (context) => ({
      info: await workspace.info(fn(context)),
    }),
    "GET /api/references": (context) => workspace.references(fn(context)),
    "GET /api/usages": async (context) => ({
      usages: await workspace.usages(selector("addr")(context)),
    }),
    "GET /api/strings": async () => ({ strings: await workspace.strings() }),
    "GET /api/imports": async () => ({ imports: await workspace.imports() }),
    "GET /api/search": async ({ url }) => {
      const kind = parseOrThrow(
        z.enum(["functions", "strings"]),
        url.searchParams.get("kind") ?? "functions",
      );
      const pattern = parseOrThrow(
        z.string().min(1).max(1000),
        url.searchParams.get("q") ?? undefined,
      );
      return {
        results: await workspace.search(
          kind,
          pattern,
          url.searchParams.get("regex") === "1",
        ),
      };
    },
    "POST /api/export": async ({ body }) => startExport(await body()),
    "POST /api/shutdown": () => {
      setImmediate(options.onShutdown);
      return { shutdown: true };
    },
  };

  const route = async (
    request: IncomingMessage,
    response: ServerResponse,
    url: URL,
  ): Promise<void> => {
    const key = `${request.method ?? "GET"} ${url.pathname}`;
    if (key === "GET /api/events") {
      streamEvents(request, response);
      return;
    }
    const handler = routes[key];
    if (handler === undefined)
      throw new DesktopError("not_found", `No route for ${key}`, 404);
    const result = await handler({ url, body: () => readJsonBody(request) });
    sendJson(response, key === "POST /api/export" ? 202 : 200, result);
  };

  const server: Server = createServer((request, response) => {
    const host = request.headers.host ?? "";
    // Reject DNS-rebinding and other hosts: only the loopback origin we serve.
    if (
      host !== `127.0.0.1:${String(port)}` &&
      host !== `localhost:${String(port)}`
    ) {
      sendJson(response, 421, {
        error: { code: "misdirected", message: "Unexpected host" },
      });
      return;
    }
    const url = new URL(request.url ?? "/", `http://${host}`);
    if (!url.pathname.startsWith("/api/")) {
      if (request.method !== "GET") {
        sendJson(response, 405, {
          error: { code: "method", message: "Method not allowed" },
        });
        return;
      }
      void serveStatic(url.pathname, response);
      return;
    }
    const supplied =
      (request.headers["x-rogue-token"] as string | undefined) ??
      (url.pathname === "/api/events"
        ? (url.searchParams.get("token") ?? undefined)
        : undefined);
    if (!sameSecret(token, supplied)) {
      sendJson(response, 401, {
        error: { code: "unauthorized", message: "Missing or invalid token" },
      });
      return;
    }
    route(request, response, url).catch((cause: unknown) => {
      if (response.headersSent) {
        response.end();
        return;
      }
      const failure =
        cause instanceof DesktopError
          ? cause
          : new DesktopError(
              "unexpected",
              cause instanceof Error ? cause.message : String(cause),
            );
      sendJson(response, failure.status, {
        error: { code: failure.code, message: failure.message },
      });
    });
  });
  server.keepAliveTimeout = 60_000;

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  port = (server.address() as AddressInfo).port;
  return {
    port,
    token,
    url: `http://127.0.0.1:${String(port)}/#token=${token}`,
    close: async () => {
      unsubscribe();
      for (const stream of eventStreams) stream.end();
      eventStreams.clear();
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      });
    },
  };
};
