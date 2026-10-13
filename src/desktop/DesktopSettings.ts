import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";

import { z } from "zod";

/** Name used for the per-user settings and cache directories. */
export const DESKTOP_APPLICATION_DIRECTORY = "RogueAgent";

/** Provider the desktop app binds a target to. */
export const desktopProviderSchema = z.enum(["ghidra", "ida"]);

const absolutePath = z
  .string()
  .min(1)
  .refine(isAbsolute, "Path must be absolute");

/** Persisted desktop preferences; every field is optional on disk. */
export const desktopSettingsSchema = z.strictObject({
  provider: desktopProviderSchema.default("ghidra"),
  ghidraInstallDir: absolutePath.nullable().default(null),
  javaHome: absolutePath.nullable().default(null),
  idaMcpConfigPath: absolutePath.nullable().default(null),
  /** Per-function decompile deadline; 0 waits indefinitely. */
  decompileTimeoutSeconds: z.number().int().min(0).max(86_400).default(120),
  /** Decompile a function's callees in the background after it opens. */
  prefetchCallees: z.boolean().default(true),
  /** Reuse a binary's stored Ghidra analysis when it is opened again. */
  analysisCache: z.boolean().default(true),
  recentFiles: z.array(absolutePath).max(10).default([]),
});
export type DesktopSettings = z.infer<typeof desktopSettingsSchema>;

/** Editable subset accepted from the UI. */
export const desktopSettingsPatchSchema = desktopSettingsSchema
  .omit({ recentFiles: true })
  .partial();
export type DesktopSettingsPatch = z.infer<typeof desktopSettingsPatchSchema>;

/** Per-user configuration directory for the current platform. */
export const desktopConfigDirectory = (
  environment: Readonly<NodeJS.ProcessEnv>,
  platform: NodeJS.Platform = process.platform,
): string => {
  if (platform === "win32") {
    const appData =
      environment.APPDATA ?? join(homedir(), "AppData", "Roaming");
    return join(appData, DESKTOP_APPLICATION_DIRECTORY);
  }
  if (platform === "darwin")
    return join(
      homedir(),
      "Library",
      "Application Support",
      DESKTOP_APPLICATION_DIRECTORY,
    );
  const configHome = environment.XDG_CONFIG_HOME;
  return join(
    configHome !== undefined && isAbsolute(configHome)
      ? configHome
      : join(homedir(), ".config"),
    DESKTOP_APPLICATION_DIRECTORY.toLowerCase(),
  );
};

/** Load, update and atomically persist desktop settings. */
export class DesktopSettingsStore {
  readonly path: string;
  #current: DesktopSettings;

  private constructor(path: string, current: DesktopSettings) {
    this.path = path;
    this.#current = current;
  }

  /** Read settings, falling back to defaults when the file is absent or invalid. */
  static async load(path: string): Promise<DesktopSettingsStore> {
    let raw: unknown = {};
    try {
      raw = JSON.parse(await readFile(path, "utf8"));
    } catch (cause: unknown) {
      void cause;
    }
    const parsed = desktopSettingsSchema.safeParse(raw);
    return new DesktopSettingsStore(
      path,
      parsed.success ? parsed.data : desktopSettingsSchema.parse({}),
    );
  }

  get current(): DesktopSettings {
    return this.#current;
  }

  async update(patch: DesktopSettingsPatch): Promise<DesktopSettings> {
    const next = desktopSettingsSchema.parse({ ...this.#current, ...patch });
    await this.#persist(next);
    return next;
  }

  /** Move a file to the front of the recent list. */
  async remember(path: string): Promise<DesktopSettings> {
    const recentFiles = [
      path,
      ...this.#current.recentFiles.filter((entry) => entry !== path),
    ].slice(0, 10);
    const next = { ...this.#current, recentFiles };
    await this.#persist(next);
    return next;
  }

  async #persist(next: DesktopSettings): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const temporary = `${this.path}.${String(process.pid)}.tmp`;
    await writeFile(temporary, `${JSON.stringify(next, null, 2)}\n`, "utf8");
    await rename(temporary, this.path);
    this.#current = next;
  }
}
