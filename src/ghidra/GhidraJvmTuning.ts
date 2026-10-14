import { availableParallelism, totalmem } from "node:os";

/** Host facts that size the long-lived headless Ghidra JVM. */
export interface GhidraJvmHost {
  readonly cpus: number;
  readonly totalMemoryBytes: number;
}

/** Heap ceiling and HotSpot thread flags for one headless Ghidra launch. */
export interface GhidraJvmTuning {
  /** `-Xmx` value without the flag prefix, such as `4G`. */
  readonly maxHeap: string;
  /** HotSpot flags placed after Ghidra's own launch defaults so they win. */
  readonly options: readonly string[];
}

const GIB = 1024 ** 3;
const MIN_HEAP_GIB = 2;
const MAX_HEAP_GIB = 16;
const MAX_GC_THREADS = 8;
const MAX_JIT_THREADS = 8;

const clamp = (value: number, minimum: number, maximum: number): number =>
  Math.min(maximum, Math.max(minimum, value));

/** Detect the CPU and memory budget of the current host. */
export const currentGhidraJvmHost = (): GhidraJvmHost => ({
  cpus: availableParallelism(),
  totalMemoryBytes: totalmem(),
});

/**
 * Size the analysis JVM from the host instead of Ghidra's fixed launch
 * defaults (2G heap, two GC threads, two JIT compiler threads).
 *
 * Auto-analysis and decompilation are long-running, allocation-heavy and
 * JIT-bound, so the defaults leave most cores idle and GC frequently on large
 * binaries. The heap ceiling is a quarter of physical memory, kept between
 * 2G and 16G; the JVM only commits what it uses. An explicit
 * `GHIDRA_HEADLESS_MAXMEM` or `GHIDRA_MAXMEM` always wins, and
 * `REA_GHIDRA_JVM_TUNING=off` restores Ghidra's launch defaults.
 */
export const ghidraJvmTuning = (
  environment: Readonly<NodeJS.ProcessEnv>,
  host: GhidraJvmHost = currentGhidraJvmHost(),
): GhidraJvmTuning => {
  const configuredHeap =
    environment.GHIDRA_HEADLESS_MAXMEM || environment.GHIDRA_MAXMEM || "";
  if (environment.REA_GHIDRA_JVM_TUNING === "off")
    return {
      maxHeap:
        configuredHeap === "" ? `${String(MIN_HEAP_GIB)}G` : configuredHeap,
      options: ["-XX:ParallelGCThreads=2", "-XX:CICompilerCount=2"],
    };
  const cpus = Number.isFinite(host.cpus)
    ? Math.max(1, Math.floor(host.cpus))
    : 1;
  const memoryGib = Number.isFinite(host.totalMemoryBytes)
    ? host.totalMemoryBytes / GIB
    : MIN_HEAP_GIB * 4;
  const heapGib = clamp(Math.floor(memoryGib / 4), MIN_HEAP_GIB, MAX_HEAP_GIB);
  // Tiered compilation requires at least two compiler threads.
  const jitThreads = clamp(Math.ceil(cpus / 2), 2, MAX_JIT_THREADS);
  const gcThreads = clamp(cpus, 2, MAX_GC_THREADS);
  return {
    maxHeap: configuredHeap === "" ? `${String(heapGib)}G` : configuredHeap,
    options: [
      `-XX:ParallelGCThreads=${String(gcThreads)}`,
      `-XX:CICompilerCount=${String(jitThreads)}`,
    ],
  };
};
