import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  discoverGhidraInstallations,
  inspectGhidraDirectory,
  inspectJavaHome,
} from "./DesktopDiscovery.js";
import {
  desktopEngineEnvironment,
  desktopFailureMessage,
} from "./DesktopWorkspace.js";
import { desktopSettingsSchema } from "./DesktopSettings.js";

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});

const fakeGhidra = async (root: string, version: string): Promise<string> => {
  const install = join(root, `ghidra_${version}_PUBLIC`);
  await mkdir(join(install, "support"), { recursive: true });
  await mkdir(join(install, "Ghidra"), { recursive: true });
  await writeFile(
    join(
      install,
      "support",
      process.platform === "win32" ? "analyzeHeadless.bat" : "analyzeHeadless",
    ),
    "",
  );
  await writeFile(
    join(install, "Ghidra", "application.properties"),
    `application.name=Ghidra\napplication.version=${version}\napplication.release.name=PUBLIC\n`,
  );
  return install;
};

describe("desktop discovery", () => {
  it("recognises Ghidra releases and the verified release line", async () => {
    const root = await mkdtemp(join(tmpdir(), "rogue-discovery-"));
    roots.push(root);
    const current = await fakeGhidra(root, "12.1.4");
    const older = await fakeGhidra(root, "11.3.2");
    expect(await inspectGhidraDirectory(current)).toEqual({
      path: current,
      version: "12.1.4",
      supported: true,
    });
    expect(await inspectGhidraDirectory(older)).toMatchObject({
      supported: false,
    });
    expect(await inspectGhidraDirectory(root)).toBeUndefined();
    expect(await inspectGhidraDirectory("relative")).toBeUndefined();
  });

  it("lists an explicitly configured installation first", async () => {
    const root = await mkdtemp(join(tmpdir(), "rogue-discovery-"));
    roots.push(root);
    const older = await fakeGhidra(root, "11.3.2");
    const found = await discoverGhidraInstallations({
      GHIDRA_INSTALL_DIR: older,
    });
    expect(found[0]).toMatchObject({ path: older, version: "11.3.2" });
  });

  it("reads JDK homes from their release file", async () => {
    const root = await mkdtemp(join(tmpdir(), "rogue-jdk-"));
    roots.push(root);
    await mkdir(join(root, "bin"));
    await writeFile(
      join(root, "bin", process.platform === "win32" ? "javac.exe" : "javac"),
      "",
    );
    await writeFile(join(root, "release"), 'JAVA_VERSION="21.0.5"\n');
    expect(await inspectJavaHome(root)).toEqual({
      path: root,
      version: "21.0.5",
      major: 21,
    });
  });
});

describe("desktop engine mapping", () => {
  it("translates settings into the engine's configuration variables", () => {
    const settings = desktopSettingsSchema.parse({
      ghidraInstallDir: "/opt/ghidra",
      javaHome: "/opt/jdk",
      decompileTimeoutSeconds: 45,
    });
    expect(desktopEngineEnvironment({ PATH: "/bin" }, settings)).toMatchObject({
      PATH: "/bin",
      REA_ANALYSIS_PROVIDER: "ghidra",
      GHIDRA_INSTALL_DIR: "/opt/ghidra",
      JAVA_HOME: "/opt/jdk",
      REA_GHIDRA_DECOMPILE_TIMEOUT_SECONDS: "45",
    });
  });

  it("explains provider rejections in terms of the settings", () => {
    const projected = {
      code: "provider_unavailable",
      message: "The selected analysis provider is unavailable.",
      details: {
        rejections: [
          {
            provider_id: "ghidra",
            code: "not_configured",
            reason: "Set GHIDRA_INSTALL_DIR",
          },
        ],
      },
    } as unknown as Parameters<typeof desktopFailureMessage>[0];
    expect(desktopFailureMessage(projected, "ghidra")).toMatch(/Settings/u);
    const broken = {
      ...projected,
      details: {
        rejections: [
          {
            provider_id: "ghidra",
            code: "version_unsupported",
            reason: "Ghidra 11.3 is not supported",
            diagnostics: {
              checks: [
                { name: "version", ok: false, detail: "11.3.2" },
                { name: "java", ok: true, detail: "21" },
              ],
            },
          },
        ],
      },
    } as unknown as Parameters<typeof desktopFailureMessage>[0];
    expect(desktopFailureMessage(broken, "ghidra")).toBe(
      "Ghidra 11.3 is not supported — version: 11.3.2",
    );
  });
});
