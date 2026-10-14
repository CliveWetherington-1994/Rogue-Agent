import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  startDesktopServer,
  type DesktopServerHandle,
} from "./DesktopServer.js";
import { DesktopSettingsStore } from "./DesktopSettings.js";
import {
  DesktopError,
  type DesktopState,
  type DesktopWorkspace,
} from "./DesktopWorkspace.js";

const idleState: DesktopState = {
  phase: "idle",
  provider: "ghidra",
  target: null,
  document: null,
  functionCount: null,
  progress: null,
  error: null,
  timings: { openMs: null, analysisMs: null },
};

const fakeWorkspace = (): DesktopWorkspace & { decompiled: string[] } => {
  const decompiled: string[] = [];
  const workspace = {
    decompiled,
    state: idleState,
    subscribe: () => () => undefined,
    preload: () => undefined,
    open: async () => idleState,
    close: async () => undefined,
    functions: async () => [
      { address: "0x401000", name: "main", external: false, thunk: false },
    ],
    decompile: async (address: string) => {
      decompiled.push(address);
      if (address === "0xdead")
        throw new DesktopError("not_found", "No procedure exists", 422);
      return {
        address,
        pseudocode: "int main(void) { return 0; }",
        elapsedMs: 1,
      };
    },
    disassembly: async () => "PUSH EBP",
    info: async () => ({ name: "main" }),
    references: async () => ({ callers: [], callees: [] }),
    usages: async () => [],
    strings: async () => [],
    imports: async () => [],
    search: async () => [],
    exportAll: async () => "",
  };
  return workspace as unknown as DesktopWorkspace & { decompiled: string[] };
};

interface Reply {
  readonly status: number;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  readonly body: string;
}

const call = (
  handle: DesktopServerHandle,
  path: string,
  options: {
    readonly method?: string;
    readonly token?: string | null;
    readonly host?: string;
    readonly body?: unknown;
  } = {},
): Promise<Reply> =>
  new Promise((resolve, reject) => {
    const body =
      options.body === undefined ? undefined : JSON.stringify(options.body);
    const outgoing = request(
      {
        host: "127.0.0.1",
        port: handle.port,
        path,
        method: options.method ?? (body === undefined ? "GET" : "POST"),
        headers: {
          host: options.host ?? `127.0.0.1:${String(handle.port)}`,
          ...(options.token === null
            ? {}
            : { "x-rogue-token": options.token ?? handle.token }),
          ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () =>
          resolve({
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          }),
        );
      },
    );
    outgoing.on("error", reject);
    outgoing.end(body);
  });

describe("desktop server", () => {
  const cleanups: (() => Promise<void>)[] = [];
  afterEach(async () => {
    for (const cleanup of cleanups.splice(0)) await cleanup();
  });

  const start = async () => {
    const root = await mkdtemp(join(tmpdir(), "rogue-desktop-"));
    const uiRoot = join(root, "ui");
    await mkdir(uiRoot);
    await writeFile(
      join(uiRoot, "index.html"),
      "<!doctype html><title>ok</title>",
    );
    await writeFile(join(root, "secret.txt"), "outside the UI root");
    const settings = await DesktopSettingsStore.load(
      join(root, "settings.json"),
    );
    const workspace = fakeWorkspace();
    const handle = await startDesktopServer({
      workspace,
      settings,
      environment: {},
      uiRoot,
      version: "test",
      onShutdown: () => undefined,
    });
    cleanups.push(async () => {
      await handle.close();
      await rm(root, { recursive: true, force: true });
    });
    return { handle, workspace, root };
  };

  it("serves the UI with a restrictive content security policy", async () => {
    const { handle } = await start();
    const reply = await call(handle, "/", { token: null });
    expect(reply.status).toBe(200);
    expect(reply.body).toContain("<title>ok</title>");
    expect(String(reply.headers["content-security-policy"])).toContain(
      "default-src 'none'",
    );
  });

  it("never serves files outside the UI directory", async () => {
    const { handle } = await start();
    for (const path of [
      "/../secret.txt",
      "/%2e%2e/secret.txt",
      "/..%2fsecret.txt",
    ])
      expect((await call(handle, path, { token: null })).status).toBe(404);
  });

  it("requires the per-launch token for every API route", async () => {
    const { handle } = await start();
    expect((await call(handle, "/api/state", { token: null })).status).toBe(
      401,
    );
    expect(
      (await call(handle, "/api/state", { token: "0".repeat(64) })).status,
    ).toBe(401);
    expect((await call(handle, "/api/state")).status).toBe(200);
  });

  it("rejects requests addressed to another host name", async () => {
    const { handle } = await start();
    const reply = await call(handle, "/api/state", {
      host: `attacker.example:${String(handle.port)}`,
    });
    expect(reply.status).toBe(421);
  });

  it("validates selectors and maps engine failures to JSON errors", async () => {
    const { handle, workspace } = await start();
    const ok = await call(handle, "/api/decompile?fn=0x401000");
    expect(ok.status).toBe(200);
    expect(JSON.parse(ok.body)).toMatchObject({
      pseudocode: expect.stringContaining("main"),
    });
    expect((await call(handle, "/api/decompile")).status).toBe(400);
    expect((await call(handle, "/api/decompile?fn=a%20b")).status).toBe(400);
    const failed = await call(handle, "/api/decompile?fn=0xdead");
    expect(failed.status).toBe(422);
    expect(JSON.parse(failed.body)).toEqual({
      error: { code: "not_found", message: "No procedure exists" },
    });
    expect(workspace.decompiled).toEqual(["0x401000", "0xdead"]);
  });

  it("refuses a Ghidra folder that is not a release and persists valid settings", async () => {
    const { handle, root } = await start();
    const rejected = await call(handle, "/api/settings", {
      body: { ghidraInstallDir: root },
    });
    expect(rejected.status).toBe(400);
    expect(JSON.parse(rejected.body).error.code).toBe("invalid_ghidra");
    const saved = await call(handle, "/api/settings", {
      body: { decompileTimeoutSeconds: 30, prefetchCallees: false },
    });
    expect(saved.status).toBe(200);
    expect(JSON.parse(saved.body).settings).toMatchObject({
      decompileTimeoutSeconds: 30,
      prefetchCallees: false,
    });
    const reloaded = await DesktopSettingsStore.load(
      join(root, "settings.json"),
    );
    expect(reloaded.current.decompileTimeoutSeconds).toBe(30);
  });

  it("requires absolute paths to open", async () => {
    const { handle } = await start();
    const reply = await call(handle, "/api/open", {
      body: { path: "relative.exe" },
    });
    expect(reply.status).toBe(400);
  });

  it("streams state over server-sent events with the token in the query", async () => {
    const { handle } = await start();
    const frame = await new Promise<string>((resolve, reject) => {
      const outgoing = request(
        {
          host: "127.0.0.1",
          port: handle.port,
          path: `/api/events?token=${handle.token}`,
          headers: { host: `127.0.0.1:${String(handle.port)}` },
        },
        (response) => {
          response.once("data", (chunk: Buffer) => {
            resolve(chunk.toString("utf8"));
            outgoing.destroy();
          });
        },
      );
      outgoing.on("error", reject);
      outgoing.end();
    });
    expect(frame).toContain("event: state");
    expect(frame).toContain('"phase":"idle"');
  });
});
