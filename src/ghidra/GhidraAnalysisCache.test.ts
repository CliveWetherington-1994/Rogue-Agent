import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readdir,
  rm,
  utimes,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  GHIDRA_ANALYSIS_CACHE_SCRIPT,
  defaultGhidraAnalysisCacheDirectory,
  findGhidraAnalysis,
  ghidraAnalysisCacheKey,
  ghidraAnalysisCacheSettings,
  planGhidraAnalysisCache,
  pruneGhidraAnalysisCache,
} from "./GhidraAnalysisCache.js";
import { ghidraHeadlessArguments } from "./GhidraLauncher.js";

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});
const temporary = async (prefix: string): Promise<string> => {
  const root = await mkdtemp(join(tmpdir(), prefix));
  roots.push(root);
  return root;
};

const store = async (
  directory: string,
  key: string,
  bytes: Buffer,
  sha256 = createHash("sha256").update(bytes).digest("hex"),
) => {
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, `${key}.gzf`), bytes);
  await writeFile(
    join(directory, `${key}.json`),
    `${JSON.stringify({
      format: "rea-ghidra-analysis-cache-v1",
      key,
      sha256,
      bytes: bytes.length,
      program_name: "target.exe",
      created_at: new Date().toISOString(),
    })}\n`,
  );
};

const keyInputs = async () => {
  const bridge = await temporary("rea-bridge-");
  await writeFile(join(bridge, "ReaGhidraBridge.java"), "class A {}");
  return {
    targetSha256: "a".repeat(64),
    profileDigest: "b".repeat(64),
    providerVersion: "12.1.4",
    analyzeHeadlessPath: "/opt/ghidra/support/analyzeHeadless",
    bridgeDirectory: bridge,
    platform: "linux" as const,
    importOptions: { disabled_analyzers: [] },
  };
};

describe("Ghidra analysis cache", () => {
  it("keys analyses by target, profile, options and bridge scripts", async () => {
    const inputs = await keyInputs();
    const key = await ghidraAnalysisCacheKey(inputs);
    expect(key).toMatch(/^[a-f0-9]{64}$/u);
    expect(await ghidraAnalysisCacheKey({ ...inputs })).toBe(key);
    expect(
      await ghidraAnalysisCacheKey({ ...inputs, targetSha256: "c".repeat(64) }),
    ).not.toBe(key);
    expect(
      await ghidraAnalysisCacheKey({
        ...inputs,
        importOptions: { disabled_analyzers: ["Stack"] },
      }),
    ).not.toBe(key);
    const changedBridge = await temporary("rea-bridge-");
    await writeFile(join(changedBridge, "ReaGhidraBridge.java"), "class B {}");
    expect(
      await ghidraAnalysisCacheKey({
        ...inputs,
        bridgeDirectory: changedBridge,
      }),
    ).not.toBe(key);
  });

  it("reuses only entries whose digest matches the manifest", async () => {
    const directory = await temporary("rea-cache-");
    const settings = { directory, maxBytes: 1024 ** 3 };
    const good = "1".repeat(64);
    const tampered = "2".repeat(64);
    await store(directory, good, Buffer.from("packed program"));
    await store(
      directory,
      tampered,
      Buffer.from("changed bytes"),
      "0".repeat(64),
    );
    expect(await findGhidraAnalysis(settings, good)).toBe(
      join(directory, `${good}.gzf`),
    );
    expect(await findGhidraAnalysis(settings, tampered)).toBeUndefined();
    expect((await readdir(directory)).sort()).toEqual([
      `${good}.gzf`,
      `${good}.json`,
    ]);
    expect(await findGhidraAnalysis(settings, "3".repeat(64))).toBeUndefined();
  });

  it("plans a store on a miss and a hit once stored", async () => {
    const directory = await temporary("rea-cache-");
    const settings = { directory, maxBytes: 1024 ** 3 };
    const key = "4".repeat(64);
    expect(await planGhidraAnalysisCache(settings, key)).toEqual({
      kind: "store",
      key,
      directory,
    });
    await store(directory, key, Buffer.from("analysis"));
    expect(await planGhidraAnalysisCache(settings, key)).toEqual({
      kind: "hit",
      key,
      packedPath: join(directory, `${key}.gzf`),
    });
  });

  it("evicts least recently used entries and abandoned partial files", async () => {
    const directory = await temporary("rea-cache-");
    const old = "5".repeat(64);
    const recent = "6".repeat(64);
    await store(directory, old, Buffer.alloc(600));
    await store(directory, recent, Buffer.alloc(600));
    const past = new Date(Date.now() - 3 * 60 * 60 * 1000);
    await utimes(join(directory, `${old}.json`), past, past);
    await writeFile(join(directory, `${old}.run.partial`), "interrupted");
    await utimes(join(directory, `${old}.run.partial`), past, past);
    await writeFile(join(directory, `${recent}.live.partial`), "in progress");
    await pruneGhidraAnalysisCache({ directory, maxBytes: 1000 });
    expect((await readdir(directory)).sort()).toEqual(
      [`${recent}.gzf`, `${recent}.json`, `${recent}.live.partial`].sort(),
    );
  });

  it("resolves settings and per-platform default directories", () => {
    expect(
      ghidraAnalysisCacheSettings({
        enabled: false,
        directory: undefined,
        maxMegabytes: undefined,
        environment: {},
      }),
    ).toBeUndefined();
    expect(
      ghidraAnalysisCacheSettings({
        enabled: true,
        directory: "/cache",
        maxMegabytes: 128,
        environment: {},
      }),
    ).toEqual({ directory: "/cache", maxBytes: 128 * 1024 ** 2 });
    expect(
      defaultGhidraAnalysisCacheDirectory(
        { LOCALAPPDATA: "C:\\Users\\a\\AppData\\Local" },
        "win32",
      ),
    ).toMatch(/rea[\\/]ghidra-analysis$/u);
    expect(
      defaultGhidraAnalysisCacheDirectory({ XDG_CACHE_HOME: "/xdg" }, "linux"),
    ).toBe("/xdg/rea/ghidra-analysis");
  });
});

describe("Ghidra headless arguments with the analysis cache", () => {
  const base = {
    platform: "linux" as const,
    projectRoot: "/rt/project",
    targetPath: "/rt/target.exe",
    bridgeScriptPath: "/pkg/bridge/ghidra/ReaGhidraBridge.java",
    descriptorPath: "/rt/session.json",
    ghidraLogPath: "/rt/ghidra.log",
    scriptLogPath: "/rt/script.log",
    disabledAnalyzers: ["Stack"],
  };

  it("imports a stored analysis without re-running import or analysis scripts", () => {
    expect(
      ghidraHeadlessArguments({
        ...base,
        analysisCache: { kind: "hit", packedPath: "/cache/k.gzf" },
      }),
    ).toEqual([
      "/rt/project",
      "rea-project",
      "-import",
      "/cache/k.gzf",
      "-loader",
      "GzfLoader",
      "-noanalysis",
      "-readOnly",
      "-deleteProject",
      "-log",
      "/rt/ghidra.log",
      "-scriptlog",
      "/rt/script.log",
      "-scriptPath",
      "/pkg/bridge/ghidra",
      "-postScript",
      "/pkg/bridge/ghidra/ReaGhidraBridge.java",
      "/rt/session.json",
    ]);
  });

  it("stores the repaired Program after analysis and before the bridge", () => {
    const argv = ghidraHeadlessArguments({
      ...base,
      analysisCache: {
        kind: "store",
        directory: "/cache",
        key: "k".repeat(64),
        runId: "run-1",
      },
    });
    const save = argv.indexOf(
      `/pkg/bridge/ghidra/${GHIDRA_ANALYSIS_CACHE_SCRIPT}`,
    );
    const noReturn = argv.indexOf(
      "/pkg/bridge/ghidra/ReaGhidraNoReturnFix.java",
    );
    const bridge = argv.indexOf("/pkg/bridge/ghidra/ReaGhidraBridge.java");
    expect(noReturn).toBeGreaterThan(0);
    expect(save).toBeGreaterThan(noReturn);
    expect(bridge).toBeGreaterThan(save);
    expect(argv.slice(save, save + 4)).toEqual([
      `/pkg/bridge/ghidra/${GHIDRA_ANALYSIS_CACHE_SCRIPT}`,
      "/cache",
      "k".repeat(64),
      "run-1",
    ]);
    expect(argv).toContain("-import");
    expect(argv).toContain("/rt/target.exe");
    expect(argv).not.toContain("-noanalysis");
  });
});
