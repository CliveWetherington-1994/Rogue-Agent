import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readdir, readFile, rm, stat, utimes } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";

import { z } from "zod";

/** Bridge post-script that stores the analyzed Program in the cache. */
export const GHIDRA_ANALYSIS_CACHE_SCRIPT = "ReaGhidraSaveAnalysis.java";
const CACHE_FORMAT = "rea-ghidra-analysis-cache-v1";
const DEFAULT_MAX_BYTES = 4 * 1024 ** 3;
/** Partial files older than this are leftovers from an interrupted store. */
const STALE_PARTIAL_MS = 60 * 60 * 1000;

/** Where analyzed Programs are kept and how much space they may use. */
export interface GhidraAnalysisCacheSettings {
  readonly directory: string;
  readonly maxBytes: number;
}

/** Launch decision for one session: reuse a stored analysis or store this one. */
export type GhidraAnalysisCachePlan =
  | { readonly kind: "hit"; readonly key: string; readonly packedPath: string }
  | {
      readonly kind: "store";
      readonly key: string;
      readonly directory: string;
    };

const manifestSchema = z.strictObject({
  format: z.literal(CACHE_FORMAT),
  key: z.string().regex(/^[a-f0-9]{64}$/u),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  bytes: z.number().int().min(1),
  program_name: z.string().min(1),
  created_at: z.string(),
});

/** Default per-user cache directory for the current platform. */
export const defaultGhidraAnalysisCacheDirectory = (
  environment: Readonly<NodeJS.ProcessEnv>,
  platform: NodeJS.Platform = process.platform,
): string => {
  if (platform === "win32") {
    const local = environment.LOCALAPPDATA;
    return join(
      local !== undefined && isAbsolute(local)
        ? local
        : join(homedir(), "AppData", "Local"),
      "rea",
      "ghidra-analysis",
    );
  }
  if (platform === "darwin")
    return join(homedir(), "Library", "Caches", "rea", "ghidra-analysis");
  const cacheHome = environment.XDG_CACHE_HOME;
  return join(
    cacheHome !== undefined && isAbsolute(cacheHome)
      ? cacheHome
      : join(homedir(), ".cache"),
    "rea",
    "ghidra-analysis",
  );
};

/** Resolve cache settings from the engine configuration values. */
export const ghidraAnalysisCacheSettings = (options: {
  readonly enabled: boolean;
  readonly directory: string | undefined;
  readonly maxMegabytes: number | undefined;
  readonly environment: Readonly<NodeJS.ProcessEnv>;
  readonly platform?: NodeJS.Platform;
}): GhidraAnalysisCacheSettings | undefined =>
  options.enabled
    ? {
        directory:
          options.directory ??
          defaultGhidraAnalysisCacheDirectory(
            options.environment,
            options.platform,
          ),
        maxBytes:
          options.maxMegabytes === undefined
            ? DEFAULT_MAX_BYTES
            : options.maxMegabytes * 1024 ** 2,
      }
    : undefined;

const scriptDigests = new Map<string, Promise<string>>();

/** Digest of every bridge script; any script change invalidates the cache. */
const bridgeScriptsDigest = (bridgeDirectory: string): Promise<string> => {
  let digest = scriptDigests.get(bridgeDirectory);
  if (digest === undefined) {
    digest = (async () => {
      const hash = createHash("sha256");
      const names = (await readdir(bridgeDirectory))
        .filter((name) => name.endsWith(".java"))
        .sort();
      for (const name of names) {
        hash.update(name);
        hash.update("\0");
        hash.update(await readFile(join(bridgeDirectory, name)));
        hash.update("\0");
      }
      return hash.digest("hex");
    })();
    scriptDigests.set(bridgeDirectory, digest);
    digest.catch(() => scriptDigests.delete(bridgeDirectory));
  }
  return digest;
};

/**
 * Key one analysis: the admitted bytes, the committed profile, every import
 * and analysis option the launcher applies, the Ghidra installation and the
 * exact bridge scripts. Equal keys mean an equal starting database.
 */
export const ghidraAnalysisCacheKey = async (inputs: {
  readonly targetSha256: string;
  readonly profileDigest: string;
  readonly providerVersion: string;
  readonly analyzeHeadlessPath: string;
  readonly bridgeDirectory: string;
  readonly platform: NodeJS.Platform;
  readonly importOptions: unknown;
}): Promise<string> =>
  createHash("sha256")
    .update(
      JSON.stringify({
        format: CACHE_FORMAT,
        target_sha256: inputs.targetSha256,
        profile_digest: inputs.profileDigest,
        provider_version: inputs.providerVersion,
        analyze_headless: inputs.analyzeHeadlessPath,
        platform: inputs.platform,
        bridge_scripts: await bridgeScriptsDigest(inputs.bridgeDirectory),
        import_options: inputs.importOptions ?? null,
      }),
    )
    .digest("hex");

const sha256File = (path: string): Promise<string> =>
  new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    createReadStream(path)
      .on("data", (chunk) => hash.update(chunk))
      .on("error", reject)
      .on("end", () => resolve(hash.digest("hex")));
  });

const removeEntry = async (directory: string, key: string): Promise<void> => {
  await Promise.all(
    [`${key}.json`, `${key}.gzf`].map((name) =>
      rm(join(directory, name), { force: true }),
    ),
  );
};

/**
 * Return the stored analysis for a key when its manifest and digest verify.
 * A corrupt or tampered entry is removed and treated as a miss.
 */
export const findGhidraAnalysis = async (
  settings: GhidraAnalysisCacheSettings,
  key: string,
): Promise<string | undefined> => {
  const manifestPath = join(settings.directory, `${key}.json`);
  const packedPath = join(settings.directory, `${key}.gzf`);
  let manifest: z.infer<typeof manifestSchema>;
  try {
    const parsed = manifestSchema.safeParse(
      JSON.parse(await readFile(manifestPath, "utf8")),
    );
    if (!parsed.success || parsed.data.key !== key) {
      await removeEntry(settings.directory, key);
      return undefined;
    }
    manifest = parsed.data;
  } catch (cause: unknown) {
    void cause;
    return undefined;
  }
  try {
    const info = await stat(packedPath);
    if (
      info.size !== manifest.bytes ||
      (await sha256File(packedPath)) !== manifest.sha256
    ) {
      await removeEntry(settings.directory, key);
      return undefined;
    }
    // Recency for least-recently-used eviction.
    const now = new Date();
    await utimes(manifestPath, now, now).catch(() => undefined);
    return packedPath;
  } catch (cause: unknown) {
    void cause;
    await removeEntry(settings.directory, key);
    return undefined;
  }
};

/**
 * Keep the cache within its size budget, oldest entries first, and remove
 * partial files abandoned by interrupted stores. Never throws.
 */
export const pruneGhidraAnalysisCache = async (
  settings: GhidraAnalysisCacheSettings,
  keep?: string,
): Promise<void> => {
  let names: string[];
  try {
    names = await readdir(settings.directory);
  } catch (cause: unknown) {
    void cause;
    return;
  }
  const entries: { key: string; bytes: number; used: number }[] = [];
  const now = Date.now();
  for (const name of names) {
    const path = join(settings.directory, name);
    try {
      const info = await stat(path);
      if (name.includes(".partial")) {
        if (now - info.mtimeMs > STALE_PARTIAL_MS)
          await rm(path, { force: true });
        continue;
      }
      const match = /^([a-f0-9]{64})\.json$/u.exec(name);
      if (match?.[1] === undefined) continue;
      const packed = await stat(
        join(settings.directory, `${match[1]}.gzf`),
      ).catch(() => undefined);
      entries.push({
        key: match[1],
        bytes: info.size + (packed?.size ?? 0),
        used: info.mtimeMs,
      });
    } catch (cause: unknown) {
      void cause;
    }
  }
  let total = entries.reduce((sum, entry) => sum + entry.bytes, 0);
  for (const entry of entries.sort((left, right) => left.used - right.used)) {
    if (total <= settings.maxBytes) break;
    if (entry.key === keep) continue;
    await removeEntry(settings.directory, entry.key).catch(() => undefined);
    total -= entry.bytes;
  }
};

/** Decide whether this launch reuses a stored analysis or stores its own. */
export const planGhidraAnalysisCache = async (
  settings: GhidraAnalysisCacheSettings,
  key: string,
): Promise<GhidraAnalysisCachePlan> => {
  const packedPath = await findGhidraAnalysis(settings, key);
  await pruneGhidraAnalysisCache(settings, key);
  return packedPath === undefined
    ? { kind: "store", key, directory: settings.directory }
    : { kind: "hit", key, packedPath };
};
