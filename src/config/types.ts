import type { LogLevel } from "../logger.js";
import type { ReferenceSourcePolicy } from "../domain/referenceSourcePolicy.js";
import type { AnalysisProviderSelector } from "../contracts/providerSelection.js";

import type { GhidraLanguageOverride } from "./ghidraLanguageOverride.js";
import type { McpInputSchemaProfile } from "./mcpInputSchemaProfile.js";

export interface AppConfig {
  readonly mcpMaxResponseBytes?: number;
  readonly mcpInputSchemaProfile?: McpInputSchemaProfile;
  readonly analysisProvider: AnalysisProviderSelector;
  readonly idaMcpConfigPath?: string;
  readonly ghidraInstallDir: string | undefined;
  readonly ghidraJavaHome: string | undefined;
  readonly ghidraStartupTimeoutMs: number;
  readonly ghidraLanguageOverride?: GhidraLanguageOverride;
  readonly ghidraDisabledAnalyzers?: readonly string[];
  readonly ghidraSeedFile?: string;
  readonly ghidraNativeAotJar?: string;
  /** Stored analyses reused across sessions; absent behaves as disabled. */
  readonly ghidraAnalysisCache?: {
    readonly enabled: boolean;
    readonly directory?: string;
    readonly maxMegabytes?: number;
  };
  /** False disables coalescing queued pseudocode into parallel windows. */
  readonly ghidraParallelDecompile?: false;
  /** Per-function decompile deadline in seconds; absent or 0 waits forever. */
  readonly ghidraDecompileTimeoutSeconds?: number;
  readonly ilspyCmdPath: string | undefined;
  readonly hopperLauncherPath: string;
  readonly hopperStartupTimeoutMs: number;
  readonly hopperTargetPath: string | undefined;
  readonly hopperTargetKind: "executable" | "database";
  readonly hopperLoaderArgs: readonly string[];
  readonly logLevel: LogLevel;
  readonly referenceSourcePolicy: ReferenceSourcePolicy;
}
