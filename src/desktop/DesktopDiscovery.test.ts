import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  discoverGhidraInstallations,
  discoverJavaHomes,
  findBundledTools,
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

const fakeGhidra = async (
  root: string,
  version: string,
  name = `ghidra_${version}_PUBLIC`,
): Promise<string> => {
  const install = join(root, name);
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

const fakeJdk = async (home: string, version: string): Promise<string> => {
  await mkdir(join(home, "bin"), { recursive: true });
  await writeFile(
    join(home, "bin", process.platform === "win32" ? "javac.exe" : "javac"),
    "",
  );
  await writeFile(join(home, "release"), `JAVA_VERSION="${version}"\n`);
  return home;
};

describe("bundled Ghidra and JDK", () => {
  it("finds the tools shipped beside the application and lists them first", async () => {
    const app = await mkdtemp(join(tmpdir(), "rogue-app-"));
    roots.push(app);
    const ghidra = await fakeGhidra(app, "12.1.4", "ghidra");
    const jdk = await fakeJdk(join(app, "jdk"), "21.0.12.1");
    const other = await mkdtemp(join(tmpdir(), "rogue-other-"));
    roots.push(other);
    const configured = await fakeGhidra(other, "12.1.3");
    expect(await findBundledTools(app)).toEqual({
      ghidra: {
        path: ghidra,
        version: "12.1.4",
        supported: true,
        bundled: true,
      },
      java: { path: jdk, version: "21.0.12.1", major: 21, bundled: true },
    });
    const found = await discoverGhidraInstallations(
      { GHIDRA_INSTALL_DIR: configured },
      { applicationDirectory: app },
    );
    expect(found.slice(0, 2)).toEqual([
      { path: ghidra, version: "12.1.4", supported: true, bundled: true },
      { path: configured, version: "12.1.3", supported: true },
    ]);
    expect(found.filter(({ path }) => path === ghidra)).toHaveLength(1);
    expect(
      (await discoverJavaHomes({}, { applicationDirectory: app }))[0],
    ).toMatchObject({ path: jdk, bundled: true });
  });

  it("ignores missing, partial or too old bundled tools", async () => {
    const app = await mkdtemp(join(tmpdir(), "rogue-app-"));
    roots.push(app);
    expect(await findBundledTools(app)).toEqual({});
    expect(await findBundledTools(undefined)).toEqual({});
    await mkdir(join(app, "ghidra"));
    await fakeJdk(join(app, "jdk"), "17.0.9");
    expect(await findBundledTools(app)).toEqual({});
  });
});

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

  it("uses the bundled tools unless Settings name other folders", () => {
    const bundled = { ghidra: "/app/ghidra", java: "/app/jdk" };
    const unset = desktopSettingsSchema.parse({});
    expect(
      desktopEngineEnvironment(
        { GHIDRA_INSTALL_DIR: "/env/ghidra", JAVA_HOME: "/env/jdk" },
        unset,
        bundled,
      ),
    ).toMatchObject({
      GHIDRA_INSTALL_DIR: "/app/ghidra",
      JAVA_HOME: "/app/jdk",
    });
    const chosen = desktopSettingsSchema.parse({
      ghidraInstallDir: "/opt/ghidra",
      javaHome: "/opt/jdk",
    });
    expect(desktopEngineEnvironment({}, chosen, bundled)).toMatchObject({
      GHIDRA_INSTALL_DIR: "/opt/ghidra",
      JAVA_HOME: "/opt/jdk",
    });
    expect(
      desktopEngineEnvironment({ JAVA_HOME: "/env/jdk" }, unset),
    ).toMatchObject({ JAVA_HOME: "/env/jdk" });
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
