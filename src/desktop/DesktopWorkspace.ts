import { open as openFile } from "node:fs/promises";

import type { Logger } from "pino";

import type { BinarySession } from "../application/binary/BinarySession.js";
import type { AnalysisOperation } from "../application/AnalysisProvider.js";
import type { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type { DesktopSettings } from "./DesktopSettings.js";

/** Lifecycle of the one target the desktop app keeps warm. */
export type DesktopPhase = "idle" | "opening" | "analyzing" | "ready" | "error";

/** One row of the function list. */
export interface DesktopFunction {
  readonly address: string;
  readonly name: string;
  readonly external: boolean;
  readonly thunk: boolean;
}

/** Caller-visible failure with the engine's stable error code. */
export class DesktopError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, message: string, status = 500) {
    super(message);
    this.name = "DesktopError";
    this.code = code;
    this.status = status;
  }
}

/** Snapshot pushed to the UI whenever the workspace changes. */
export interface DesktopState {
  readonly phase: DesktopPhase;
  readonly provider: string;
  readonly target: {
    readonly path: string;
    readonly sha256: string;
    readonly format: string;
    readonly architecture: string | null;
  } | null;
  readonly document: string | null;
  readonly functionCount: number | null;
  readonly progress: {
    readonly message: string;
    readonly percent: number | null;
  } | null;
  readonly error: { readonly code: string; readonly message: string } | null;
  readonly timings: {
    readonly openMs: number | null;
    readonly analysisMs: number | null;
  };
}

type Listener = (state: DesktopState) => void;

const record = (value: JsonValue): Readonly<Record<string, JsonValue>> =>
  value !== null && typeof value === "object" && !Array.isArray(value)
    ? value
    : {};

const text = (value: JsonValue | undefined): string =>
  typeof value === "string" ? value : "";

const CALLEE_PREFETCH_LIMIT = 16;
const USAGE_LIMIT = 64;
const EXPORT_CHUNK = 256;

/** Environment handed to the engine's configuration parser for one session. */
export const desktopEngineEnvironment = (
  base: Readonly<NodeJS.ProcessEnv>,
  settings: DesktopSettings,
): NodeJS.ProcessEnv => {
  const environment: NodeJS.ProcessEnv = {
    ...base,
    REA_ANALYSIS_PROVIDER: settings.provider,
    REA_GHIDRA_DECOMPILE_TIMEOUT_SECONDS: String(
      settings.decompileTimeoutSeconds,
    ),
    REA_GHIDRA_ANALYSIS_CACHE: settings.analysisCache ? "on" : "off",
  };
  if (settings.ghidraInstallDir !== null)
    environment.GHIDRA_INSTALL_DIR = settings.ghidraInstallDir;
  if (settings.javaHome !== null) environment.JAVA_HOME = settings.javaHome;
  if (settings.idaMcpConfigPath !== null)
    environment.REA_IDA_MCP_CONFIG = settings.idaMcpConfigPath;
  return environment;
};

/**
 * The analysis engine (every provider, schema and contract) loads on first
 * use so the window and API come up immediately; `preload` starts it early.
 */
const loadEngine = async () => {
  const [composition, config, errors, progress] = await Promise.all([
    import("../composition/binary.js"),
    import("../config/parseConfig.js"),
    import("../domain/analysisErrorProjection.js"),
    import("../application/ProgressReporter.js"),
  ]);
  return {
    createBinarySession: composition.createBinarySession,
    parseConfig: config.parseConfig,
    projectAnalysisError: errors.projectAnalysisError,
    createProgressReporter: progress.createProgressReporter,
  };
};
type Engine = Awaited<ReturnType<typeof loadEngine>>;

const settingsFingerprint = (settings: DesktopSettings): string =>
  JSON.stringify([
    settings.provider,
    settings.ghidraInstallDir,
    settings.javaHome,
    settings.idaMcpConfigPath,
    settings.decompileTimeoutSeconds,
    settings.analysisCache,
  ]);

/**
 * One warm analysis session behind the desktop UI.
 *
 * Opening a file starts the provider (for Ghidra: import, auto-analysis and the
 * bridge) once; every later view reuses that process. Results for the bound
 * document are memoised by the engine's snapshot cache, the bridge keeps a
 * decompile cache, and queued pseudocode requests are decompiled in parallel.
 */
export class DesktopWorkspace {
  readonly #environment: Readonly<NodeJS.ProcessEnv>;
  readonly #logger: Logger;
  readonly #settings: () => DesktopSettings;
  readonly #listeners = new Set<Listener>();
  #engine: Promise<Engine> | undefined;
  #loadedEngine: Engine | undefined;
  #session: BinarySession | undefined;
  #sessionFingerprint: string | undefined;
  #generation = 0;
  #functions: DesktopFunction[] | undefined;
  #functionsByAddress = new Map<string, DesktopFunction>();
  #state: DesktopState = {
    phase: "idle",
    provider: "ghidra",
    target: null,
    document: null,
    functionCount: null,
    progress: null,
    error: null,
    timings: { openMs: null, analysisMs: null },
  };

  constructor(options: {
    readonly environment: Readonly<NodeJS.ProcessEnv>;
    readonly logger: Logger;
    readonly settings: () => DesktopSettings;
  }) {
    this.#environment = options.environment;
    this.#logger = options.logger;
    this.#settings = options.settings;
  }

  get state(): DesktopState {
    return this.#state;
  }

  /** Begin loading the analysis engine without waiting for it. */
  preload(): void {
    void this.#getEngine().catch(() => undefined);
  }

  #getEngine(): Promise<Engine> {
    this.#engine ??= loadEngine().then((engine) => {
      this.#loadedEngine = engine;
      return engine;
    });
    return this.#engine;
  }

  subscribe(listener: Listener): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  #update(patch: Partial<DesktopState>): void {
    this.#state = { ...this.#state, ...patch };
    for (const listener of this.#listeners) listener(this.#state);
  }

  async #sessionFor(settings: DesktopSettings): Promise<BinarySession> {
    const fingerprint = settingsFingerprint(settings);
    if (this.#session !== undefined && this.#sessionFingerprint === fingerprint)
      return this.#session;
    await this.#closeSession();
    const engine = await this.#getEngine();
    const environment = desktopEngineEnvironment(this.#environment, settings);
    const config = engine.parseConfig(environment);
    if (!config.ok)
      throw new DesktopError(
        "configuration",
        engine.projectAnalysisError(config.error).message,
        400,
      );
    this.#session = engine.createBinarySession(
      config.value,
      this.#logger,
      environment,
    );
    this.#sessionFingerprint = fingerprint;
    return this.#session;
  }

  async #closeSession(): Promise<void> {
    const session = this.#session;
    this.#session = undefined;
    this.#sessionFingerprint = undefined;
    if (session === undefined) return;
    const closed = await session.close();
    if (!closed.ok)
      this.#logger.warn(
        { error: (await this.#getEngine()).projectAnalysisError(closed.error) },
        "desktop session close failed",
      );
  }

  /**
   * Bind a file and start analysis in the background. Resolves once the file
   * is accepted; progress and completion arrive through `subscribe`.
   */
  async open(path: string): Promise<DesktopState> {
    const settings = this.#settings();
    const generation = ++this.#generation;
    this.#functions = undefined;
    this.#functionsByAddress = new Map();
    this.#update({
      phase: "opening",
      provider: settings.provider,
      target: null,
      document: null,
      functionCount: null,
      progress: { message: "Reading file", percent: null },
      error: null,
      timings: { openMs: null, analysisMs: null },
    });
    const started = performance.now();
    try {
      const handle = await openFile(path, "r");
      await handle.close();
      const session = await this.#sessionFor(settings);
      const opened = await session.open(path, {
        providerId: settings.provider,
      });
      if (!opened.ok) throw this.#analysisFailure(opened.error);
      if (generation !== this.#generation) return this.#state;
      const target = opened.value;
      this.#update({
        phase: "analyzing",
        target: {
          path: target.path,
          sha256: target.sha256,
          format: target.format,
          architecture:
            "architecture" in target && typeof target.architecture === "string"
              ? target.architecture
              : null,
        },
        progress: { message: "Starting analysis", percent: null },
        timings: { openMs: performance.now() - started, analysisMs: null },
      });
      void this.#analyze(session, generation, performance.now());
    } catch (cause: unknown) {
      if (generation === this.#generation) this.#fail(cause);
      throw cause instanceof DesktopError
        ? cause
        : new DesktopError("open_failed", errorMessage(cause), 400);
    }
    return this.#state;
  }

  async #analyze(
    session: BinarySession,
    generation: number,
    started: number,
  ): Promise<void> {
    try {
      const engine = await this.#getEngine();
      const progress = engine.createProgressReporter(async (update) => {
        if (generation !== this.#generation) return;
        this.#update({
          progress: {
            message: update.message,
            percent:
              update.total === null || update.total === 0
                ? null
                : Math.round((100 * update.completed) / update.total),
          },
        });
      });
      const documents = await session.withAdmittedAnalysis(
        "list_documents",
        undefined,
        (analysis) => analysis.execute("list_documents", {}, { progress }),
      );
      if (!documents.ok) throw this.#analysisFailure(documents.error);
      if (!documents.value.ok)
        throw this.#analysisFailure(documents.value.error);
      if (generation !== this.#generation) return;
      const listed = documents.value.value.result;
      const document =
        Array.isArray(listed) && typeof listed[0] === "string"
          ? listed[0]
          : null;
      this.#update({
        document,
        progress: { message: "Listing functions", percent: null },
      });
      const functions = await this.functions();
      if (generation !== this.#generation) return;
      this.#update({
        phase: "ready",
        functionCount: functions.length,
        progress: null,
        timings: {
          ...this.#state.timings,
          analysisMs: performance.now() - started,
        },
      });
    } catch (cause: unknown) {
      if (generation === this.#generation) this.#fail(cause);
    }
  }

  #fail(cause: unknown): void {
    const projected =
      cause instanceof DesktopError
        ? { code: cause.code, message: cause.message }
        : { code: "unexpected", message: errorMessage(cause) };
    this.#update({ phase: "error", progress: null, error: projected });
  }

  #analysisFailure(
    error: Parameters<typeof projectAnalysisError>[0],
  ): DesktopError {
    // A session exists only once the engine loaded, so this stays synchronous.
    if (this.#loadedEngine === undefined)
      return new DesktopError("unexpected", error.message, 500);
    const projected = this.#loadedEngine.projectAnalysisError(error);
    return new DesktopError(
      projected.code,
      desktopFailureMessage(projected, this.#settings().provider),
      422,
    );
  }

  #requireSession(): BinarySession {
    if (this.#session === undefined || this.#state.target === null)
      throw new DesktopError("no_target", "Open a binary first", 409);
    return this.#session;
  }

  /** Parameters scoped to the analyzed document so results are memoised. */
  #scoped(
    parameters: Readonly<Record<string, JsonValue>>,
  ): Readonly<Record<string, JsonValue>> {
    // IDA identifies the target implicitly and rejects other document values.
    return this.#state.document === null || this.#state.provider === "ida"
      ? parameters
      : { ...parameters, document: this.#state.document };
  }

  async #run(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>> = {},
  ): Promise<JsonValue> {
    const session = this.#requireSession();
    const executed = await session.execute(operation, this.#scoped(parameters));
    if (!executed.ok) throw this.#analysisFailure(executed.error);
    return executed.value.result;
  }

  async functions(): Promise<DesktopFunction[]> {
    if (this.#functions !== undefined) return this.#functions;
    const listed = await this.#run("list_procedures");
    const rows: DesktopFunction[] = (Array.isArray(listed) ? listed : []).map(
      (entry) => {
        const item = record(entry);
        const procedure = record(item.procedure ?? null);
        return {
          address: text(item.address),
          name: text(item.value),
          external: procedure.external === true,
          thunk: procedure.thunk === true,
        };
      },
    );
    this.#functions = rows;
    this.#functionsByAddress = new Map(rows.map((row) => [row.address, row]));
    return rows;
  }

  async decompile(address: string): Promise<{
    readonly address: string;
    readonly pseudocode: string | null;
    readonly elapsedMs: number;
  }> {
    const started = performance.now();
    const result = await this.#run("procedure_pseudo_code", {
      procedure: address,
    });
    const elapsedMs = performance.now() - started;
    if (this.#settings().prefetchCallees) void this.#prefetchCallees(address);
    return {
      address,
      pseudocode: typeof result === "string" ? result : null,
      elapsedMs,
    };
  }

  /** Warm the likely next clicks: one parallel window over the callees. */
  async #prefetchCallees(address: string): Promise<void> {
    try {
      const callees = await this.#run("procedure_callees", {
        procedure: address,
      });
      if (!Array.isArray(callees)) return;
      const targets = callees
        .filter((callee): callee is string => typeof callee === "string")
        .filter((callee) => {
          const row = this.#functionsByAddress.get(callee);
          return row !== undefined && !row.external;
        })
        .slice(0, CALLEE_PREFETCH_LIMIT);
      await Promise.allSettled(
        targets.map((callee) =>
          this.#run("procedure_pseudo_code", { procedure: callee }),
        ),
      );
    } catch (cause: unknown) {
      this.#logger.debug(
        { cause: errorMessage(cause) },
        "callee prefetch skipped",
      );
    }
  }

  async disassembly(address: string): Promise<string> {
    return text(await this.#run("procedure_assembly", { procedure: address }));
  }

  async info(address: string): Promise<JsonValue> {
    return this.#run("procedure_info", { procedure: address });
  }

  async references(address: string): Promise<{
    readonly callers: readonly DesktopFunction[];
    readonly callees: readonly DesktopFunction[];
  }> {
    const name = (callee: JsonValue): DesktopFunction => {
      const key = text(callee);
      return (
        this.#functionsByAddress.get(key) ?? {
          address: key,
          name: key,
          external: false,
          thunk: false,
        }
      );
    };
    const [callers, callees] = await Promise.all([
      this.#run("procedure_callers", { procedure: address }),
      this.#run("procedure_callees", { procedure: address }),
    ]);
    return {
      callers: (Array.isArray(callers) ? callers : []).map(name),
      callees: (Array.isArray(callees) ? callees : []).map(name),
    };
  }

  /**
   * Functions that reference an address (a string, global or import), found
   * from its cross references and each reference's containing function.
   */
  async usages(address: string): Promise<readonly DesktopFunction[]> {
    const references = await this.#run("xrefs", { address });
    const sources = (Array.isArray(references) ? references : [])
      .filter((source): source is string => typeof source === "string")
      .slice(0, USAGE_LIMIT);
    const owners = await Promise.allSettled(
      sources.map((source) =>
        this.#run("resolve_containing_procedure", { address: source }),
      ),
    );
    const found = new Map<string, DesktopFunction>();
    for (const owner of owners) {
      if (owner.status !== "fulfilled") continue;
      const result = record(owner.value);
      if (result.found !== true) continue;
      const procedure = record(result.procedure ?? null);
      const key = text(procedure.address);
      if (key === "" || found.has(key)) continue;
      found.set(
        key,
        this.#functionsByAddress.get(key) ?? {
          address: key,
          name: text(procedure.name) || key,
          external: false,
          thunk: false,
        },
      );
    }
    return [...found.values()];
  }

  async strings(): Promise<
    readonly { readonly address: string; readonly value: string }[]
  > {
    const listed = await this.#run("list_strings");
    return (Array.isArray(listed) ? listed : []).map((entry) => {
      const item = record(entry);
      return { address: text(item.address), value: text(item.value) };
    });
  }

  async imports(): Promise<
    readonly { readonly address: string; readonly name: string }[]
  > {
    if (this.#state.provider === "ida")
      return (await this.functions())
        .filter((row) => row.external)
        .map(({ address, name }) => ({ address, name }));
    const listed = await this.#run("list_names");
    return (Array.isArray(listed) ? listed : [])
      .map(record)
      .filter((item) => record(item.symbol ?? null).external === true)
      .map((item) => ({ address: text(item.address), name: text(item.value) }));
  }

  async search(
    kind: "functions" | "strings",
    pattern: string,
    regex: boolean,
  ): Promise<readonly { readonly address: string; readonly value: string }[]> {
    const found = await this.#run(
      kind === "functions" ? "search_procedures" : "search_strings",
      {
        pattern,
        mode: regex ? "regex" : "literal",
        case_sensitive: false,
      },
    );
    return (Array.isArray(found) ? found : []).map((entry) => {
      const item = record(entry);
      return { address: text(item.address), value: text(item.value) };
    });
  }

  /**
   * Decompile every internal function and return one C listing. Requests are
   * issued together so the engine decompiles them in parallel windows.
   */
  async exportAll(
    onProgress: (completed: number, total: number) => void,
  ): Promise<string> {
    const functions = (await this.functions()).filter((row) => !row.external);
    const parts: string[] = [];
    let completed = 0;
    for (let start = 0; start < functions.length; start += EXPORT_CHUNK) {
      const chunk = functions.slice(start, start + EXPORT_CHUNK);
      const results = await Promise.allSettled(
        chunk.map((row) =>
          this.#run("procedure_pseudo_code", { procedure: row.address }),
        ),
      );
      results.forEach((result, index) => {
        const row = chunk[index];
        if (row === undefined) return;
        parts.push(
          `/* ${row.name} @ ${row.address} */\n${
            result.status === "fulfilled" && typeof result.value === "string"
              ? result.value
              : `/* decompilation unavailable: ${
                  result.status === "rejected"
                    ? errorMessage(result.reason)
                    : "no body"
                } */\n`
          }`,
        );
      });
      completed += chunk.length;
      onProgress(completed, functions.length);
    }
    const target = this.#state.target;
    return `/* ${target?.path ?? "target"} (sha256 ${target?.sha256 ?? "unknown"}) */\n\n${parts.join("\n")}`;
  }

  async close(): Promise<void> {
    this.#generation++;
    await this.#closeSession();
    this.#update({
      phase: "idle",
      target: null,
      document: null,
      functionCount: null,
      progress: null,
    });
  }
}

/**
 * Explain a provider rejection in terms of the desktop settings instead of the
 * engine's environment variables.
 */
export const desktopFailureMessage = (
  projected: ReturnType<typeof projectAnalysisError>,
  provider: string,
): string => {
  const details = record((projected.details ?? null) as JsonValue);
  const rejections = Array.isArray(details.rejections)
    ? details.rejections
    : [];
  const rejection = rejections
    .map(record)
    .find((entry) => entry.provider_id === provider);
  if (rejection === undefined) return projected.message;
  if (rejection.code === "not_configured")
    return provider === "ida"
      ? "IDA is not configured. Open Settings and choose your ida-pro-mcp configuration file."
      : "Ghidra is not configured. Open Settings and choose your Ghidra 12.1.x folder.";
  const checks = record(rejection.diagnostics ?? null).checks;
  const failed = (Array.isArray(checks) ? checks : [])
    .map(record)
    .filter((check) => check.ok === false)
    .map((check) => `${text(check.name)}: ${text(check.detail)}`);
  return [text(rejection.reason) || projected.message, ...failed].join(" — ");
};

const errorMessage = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);
