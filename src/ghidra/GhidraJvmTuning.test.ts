import { describe, expect, it } from "vitest";

import { ghidraJvmTuning } from "./GhidraJvmTuning.js";
import { ghidraHeadlessJavaOptions } from "./GhidraLauncher.js";

const GIB = 1024 ** 3;

describe("Ghidra JVM tuning", () => {
  it("sizes heap and thread counts from the host", () => {
    expect(
      ghidraJvmTuning({}, { cpus: 12, totalMemoryBytes: 32 * GIB }),
    ).toEqual({
      maxHeap: "8G",
      options: ["-XX:ParallelGCThreads=8", "-XX:CICompilerCount=6"],
    });
  });

  it("keeps Ghidra's floor on small hosts", () => {
    expect(ghidraJvmTuning({}, { cpus: 1, totalMemoryBytes: 4 * GIB })).toEqual(
      {
        maxHeap: "2G",
        options: ["-XX:ParallelGCThreads=2", "-XX:CICompilerCount=2"],
      },
    );
  });

  it("caps heap and threads on very large hosts", () => {
    expect(
      ghidraJvmTuning({}, { cpus: 128, totalMemoryBytes: 512 * GIB }),
    ).toEqual({
      maxHeap: "16G",
      options: ["-XX:ParallelGCThreads=8", "-XX:CICompilerCount=8"],
    });
  });

  it("honours an explicit heap from Ghidra's own variables", () => {
    const host = { cpus: 8, totalMemoryBytes: 64 * GIB };
    expect(ghidraJvmTuning({ GHIDRA_MAXMEM: "3G" }, host).maxHeap).toBe("3G");
    expect(
      ghidraJvmTuning(
        { GHIDRA_MAXMEM: "3G", GHIDRA_HEADLESS_MAXMEM: "5G" },
        host,
      ).maxHeap,
    ).toBe("5G");
  });

  it("restores Ghidra's launch defaults when tuning is off", () => {
    expect(
      ghidraJvmTuning(
        { REA_GHIDRA_JVM_TUNING: "off" },
        { cpus: 32, totalMemoryBytes: 128 * GIB },
      ),
    ).toEqual({
      maxHeap: "2G",
      options: ["-XX:ParallelGCThreads=2", "-XX:CICompilerCount=2"],
    });
  });

  it("forwards tuning through analyzeHeadless.bat variables on Windows", () => {
    expect(
      ghidraHeadlessJavaOptions("C:\\rt\\home", "C:\\rt\\tmp", "win32", {
        maxHeap: "6G",
        options: ["-XX:ParallelGCThreads=6", "-XX:CICompilerCount=3"],
      }),
    ).toEqual({
      JDK_JAVA_OPTIONS:
        '"-Duser.home=C:\\rt\\home" "-Djava.io.tmpdir=C:\\rt\\tmp" "-XX:-UsePerfData"',
      GHIDRA_HEADLESS_JAVA_OPTIONS:
        "-XX:ParallelGCThreads=6 -XX:CICompilerCount=3",
      GHIDRA_HEADLESS_MAXMEM: "6G",
    });
  });

  it("rejects tuning flags the batch launcher could reinterpret", () => {
    expect(() =>
      ghidraHeadlessJavaOptions("C:\\rt\\home", "C:\\rt\\tmp", "win32", {
        maxHeap: "2G",
        options: ["-XX:ParallelGCThreads=2 & calc"],
      }),
    ).toThrow(/not admissible/u);
  });

  it("keeps POSIX tuning on argv instead of the environment", () => {
    expect(
      ghidraHeadlessJavaOptions("/rt/home", "/rt/tmp", "linux", {
        maxHeap: "6G",
        options: ["-XX:ParallelGCThreads=6"],
      }),
    ).toEqual({ JDK_JAVA_OPTIONS: "", GHIDRA_HEADLESS_JAVA_OPTIONS: "" });
  });
});
