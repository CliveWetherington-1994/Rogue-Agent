import { readdir, readFile, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";

import { SUPPORTED_GHIDRA_VERSION } from "../ghidra/GhidraInstallationPolicy.js";
import { parseGhidraJavaProperties } from "../ghidra/GhidraJavaProperties.js";

/** One Ghidra release directory found on this machine. */
export interface DiscoveredGhidra {
  readonly path: string;
  readonly version: string;
  /** Same major.minor line as the bridge's verified release. */
  readonly supported: boolean;
  /** Shipped inside the application folder. */
  readonly bundled?: true;
}

/** One JDK home found on this machine. */
export interface DiscoveredJava {
  readonly path: string;
  readonly version: string;
  readonly major: number;
  /** Shipped inside the application folder. */
  readonly bundled?: true;
}

/** Ghidra and the JDK the Windows package ships beside RogueAgent.exe. */
export interface BundledTools {
  readonly ghidra?: DiscoveredGhidra;
  readonly java?: DiscoveredJava;
}

/** Folder names of the bundled tools inside the application directory. */
const BUNDLED_GHIDRA = "ghidra";
const BUNDLED_JAVA = "jdk";

const exists = async (path: string): Promise<boolean> => {
  try {
    await stat(path);
    return true;
  } catch (cause: unknown) {
    void cause;
    return false;
  }
};

const children = async (directory: string): Promise<string[]> => {
  try {
    const entries = await readdir(directory, { withFileTypes: true });
    return entries
      .filter((entry) => entry.isDirectory())
      .map((entry) => join(directory, entry.name));
  } catch (cause: unknown) {
    void cause;
    return [];
  }
};

const versionKey = (version: string): number[] =>
  version
    .split(/[^0-9]+/u)
    .filter(Boolean)
    .map(Number);

const compareVersionsDescending = (left: string, right: string): number => {
  const a = versionKey(left);
  const b = versionKey(right);
  for (let index = 0; index < Math.max(a.length, b.length); index++) {
    const difference = (b[index] ?? 0) - (a[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
};

const verifiedLine = SUPPORTED_GHIDRA_VERSION.split(".").slice(0, 2).join(".");

/** Read a Ghidra release directory, or undefined when it is not one. */
export const inspectGhidraDirectory = async (
  path: string,
  platform: NodeJS.Platform = process.platform,
): Promise<DiscoveredGhidra | undefined> => {
  if (!isAbsolute(path)) return undefined;
  const headless = join(
    path,
    "support",
    platform === "win32" ? "analyzeHeadless.bat" : "analyzeHeadless",
  );
  if (!(await exists(headless))) return undefined;
  try {
    const parsed = parseGhidraJavaProperties(
      await readFile(join(path, "Ghidra", "application.properties"), "latin1"),
    );
    if (!parsed.ok) return undefined;
    const version = parsed.value.get("application.version");
    if (version === undefined) return undefined;
    return {
      path,
      version,
      supported:
        version === verifiedLine || version.startsWith(`${verifiedLine}.`),
    };
  } catch (cause: unknown) {
    void cause;
    return undefined;
  }
};

const ghidraSearchRoots = (
  environment: Readonly<NodeJS.ProcessEnv>,
  platform: NodeJS.Platform,
  applicationDirectory: string | undefined,
): string[] => {
  const home = homedir();
  const roots = [
    ...(applicationDirectory === undefined ? [] : [applicationDirectory]),
    home,
    join(home, "Downloads"),
    join(home, "Tools"),
    join(home, "tools"),
    join(home, "Applications"),
  ];
  if (platform === "win32") {
    for (const drive of ["C:\\", "D:\\"])
      roots.push(drive, join(drive, "Tools"));
    for (const variable of ["ProgramFiles", "ProgramW6432", "LOCALAPPDATA"]) {
      const value = environment[variable];
      if (value !== undefined && isAbsolute(value)) roots.push(value);
    }
    const localAppData = environment.LOCALAPPDATA;
    if (localAppData !== undefined && isAbsolute(localAppData))
      roots.push(join(localAppData, "Programs"));
    roots.push(join(home, "scoop", "apps", "ghidra"));
    roots.push(
      join("C:\\", "ProgramData", "chocolatey", "lib", "ghidra", "tools"),
    );
  } else {
    roots.push("/opt", "/usr/local", "/usr/share", "/Applications");
  }
  return roots;
};

/**
 * Find Ghidra releases in the places people usually unpack them. The bundled
 * release is listed first, then explicit configuration (`GHIDRA_INSTALL_DIR`),
 * then others, newest first.
 */
export const discoverGhidraInstallations = async (
  environment: Readonly<NodeJS.ProcessEnv>,
  options: {
    readonly platform?: NodeJS.Platform;
    readonly applicationDirectory?: string;
  } = {},
): Promise<DiscoveredGhidra[]> => {
  const platform = options.platform ?? process.platform;
  const candidates = new Set<string>();
  const configured = environment.GHIDRA_INSTALL_DIR;
  if (configured !== undefined && isAbsolute(configured))
    candidates.add(configured);
  for (const root of ghidraSearchRoots(
    environment,
    platform,
    options.applicationDirectory,
  )) {
    for (const child of await children(root)) {
      const name = child.slice(dirname(child).length + 1).toLowerCase();
      if (!name.startsWith("ghidra") && name !== "current") continue;
      candidates.add(child);
      // Release zips often unpack to ghidra_X/ghidra_X_PUBLIC.
      for (const nested of await children(child))
        if (nested.toLowerCase().includes("ghidra")) candidates.add(nested);
    }
  }
  const found: DiscoveredGhidra[] = [];
  for (const candidate of candidates) {
    const inspected = await inspectGhidraDirectory(candidate, platform);
    if (inspected !== undefined) found.push(inspected);
  }
  const { ghidra: bundled } = await findBundledTools(
    options.applicationDirectory,
    platform,
  );
  const explicit = found.filter(
    ({ path }) => path === configured && path !== bundled?.path,
  );
  const others = found
    .filter(({ path }) => path !== configured && path !== bundled?.path)
    .sort(
      (left, right) =>
        Number(right.supported) - Number(left.supported) ||
        compareVersionsDescending(left.version, right.version),
    );
  return [...(bundled === undefined ? [] : [bundled]), ...explicit, ...others];
};

/** Read a JDK home's `release` file, or undefined when it is not a JDK. */
export const inspectJavaHome = async (
  path: string,
  platform: NodeJS.Platform = process.platform,
): Promise<DiscoveredJava | undefined> => {
  if (!isAbsolute(path)) return undefined;
  const javac = join(path, "bin", platform === "win32" ? "javac.exe" : "javac");
  if (!(await exists(javac))) return undefined;
  try {
    const release = await readFile(join(path, "release"), "utf8");
    const match = /^JAVA_VERSION="([^"]+)"/mu.exec(release);
    if (match?.[1] === undefined) return undefined;
    const version = match[1];
    const major = Number(version.split(".")[0]);
    return Number.isInteger(major) ? { path, version, major } : undefined;
  } catch (cause: unknown) {
    void cause;
    return undefined;
  }
};

/**
 * The Ghidra and JDK shipped in the application directory, when present and
 * usable. Settings that name other folders take precedence over them.
 */
export const findBundledTools = async (
  applicationDirectory: string | undefined,
  platform: NodeJS.Platform = process.platform,
): Promise<BundledTools> => {
  if (applicationDirectory === undefined || !isAbsolute(applicationDirectory))
    return {};
  const ghidra = await inspectGhidraDirectory(
    join(applicationDirectory, BUNDLED_GHIDRA),
    platform,
  );
  const java = await inspectJavaHome(
    join(applicationDirectory, BUNDLED_JAVA),
    platform,
  );
  return {
    ...(ghidra === undefined ? {} : { ghidra: { ...ghidra, bundled: true } }),
    ...(java === undefined || java.major < 21
      ? {}
      : { java: { ...java, bundled: true } }),
  };
};

/**
 * Find full JDKs (Ghidra 12 needs 21+): the bundled JDK, then the configured
 * JAVA_HOME, then others, newest first.
 */
export const discoverJavaHomes = async (
  environment: Readonly<NodeJS.ProcessEnv>,
  options: {
    readonly platform?: NodeJS.Platform;
    readonly applicationDirectory?: string;
  } = {},
): Promise<DiscoveredJava[]> => {
  const platform = options.platform ?? process.platform;
  const home = homedir();
  const vendorRoots =
    platform === "win32"
      ? [
          "Eclipse Adoptium",
          "Java",
          "Microsoft",
          "Zulu",
          "Amazon Corretto",
          "BellSoft",
          "OpenJDK",
        ].flatMap((vendor) =>
          ["ProgramFiles", "ProgramW6432"]
            .map((variable) => environment[variable])
            .filter(
              (value): value is string =>
                value !== undefined && isAbsolute(value),
            )
            .map((root) => join(root, vendor)),
        )
      : platform === "darwin"
        ? ["/Library/Java/JavaVirtualMachines"]
        : ["/usr/lib/jvm", "/opt/java", "/opt"];
  const candidates = new Set<string>();
  const configured = environment.JAVA_HOME;
  if (configured !== undefined && isAbsolute(configured))
    candidates.add(configured);
  for (const root of [...vendorRoots, join(home, ".jdks")])
    for (const child of await children(root)) {
      candidates.add(child);
      if (platform === "darwin")
        candidates.add(join(child, "Contents", "Home"));
    }
  const { java: bundled } = await findBundledTools(
    options.applicationDirectory,
    platform,
  );
  const found: DiscoveredJava[] = [];
  for (const candidate of candidates) {
    if (candidate === bundled?.path) continue;
    const inspected = await inspectJavaHome(candidate, platform);
    if (inspected !== undefined && inspected.major >= 21) found.push(inspected);
  }
  found.sort(
    (left, right) =>
      Number(right.path === configured) - Number(left.path === configured) ||
      compareVersionsDescending(left.version, right.version),
  );
  return bundled === undefined ? found : [bundled, ...found];
};
