import type { JsonValue } from "../domain/jsonValue.js";

/** One wire request as seen by the Program request queue. */
export interface GhidraPlannedRequest {
  readonly method: string;
  readonly parameters: JsonValue;
}

/**
 * Decide whether to send an extra request ahead of the queue head. The planned
 * request shares the head's active slot; its outcome never replaces the head's.
 */
export interface GhidraRequestPlanner {
  plan(
    head: GhidraPlannedRequest,
    pending: readonly GhidraPlannedRequest[],
  ): GhidraPlannedRequest | undefined;
  /** Forget planning state when a new Program session starts. */
  reset(): void;
}

/** Bridge method that decompiles selectors in parallel into its cache. */
export const GHIDRA_PSEUDOCODE_PREFETCH_METHOD = "prefetch_pseudo_code";
/** Selectors decompiled together; bounds how long one head waits. */
export const GHIDRA_PSEUDOCODE_PREFETCH_WINDOW = 64;
const PREFETCHED_KEY_LIMIT = 8192;

const pseudocodeSelector = (
  request: GhidraPlannedRequest,
): { readonly document: JsonValue; readonly procedure: string } | undefined => {
  if (request.method !== "procedure_pseudo_code") return undefined;
  const parameters = request.parameters;
  if (
    parameters === null ||
    typeof parameters !== "object" ||
    Array.isArray(parameters)
  )
    return undefined;
  const procedure = parameters.procedure;
  if (typeof procedure !== "string") return undefined;
  const document = parameters.document ?? null;
  if (document !== null && typeof document !== "string") return undefined;
  return { document, procedure };
};

/**
 * Coalesce queued `procedure_pseudo_code` requests into one parallel prefetch.
 *
 * The bridge answers one request at a time, so `batch_decompile` and other
 * fan-out callers would otherwise decompile functions one after another. When
 * the head and at least one queued request ask for pseudocode in the same
 * document, the planner first sends a prefetch for that window; the bridge
 * decompiles it with its pooled Ghidra decompilers and the queued requests are
 * then served from its cache. Results still flow through the unchanged
 * per-request contract. A selector already covered by an earlier window does
 * not trigger another prefetch, so one window is decompiled at a time.
 */
export const createGhidraPseudocodePrefetchPlanner =
  (): GhidraRequestPlanner => {
    const prefetched = new Set<string>();
    const keyOf = (document: JsonValue, procedure: string): string =>
      `${document === null ? "" : String(document)}\u0000${procedure}`;
    return {
      plan(head, pending) {
        const selected = pseudocodeSelector(head);
        if (selected === undefined) return undefined;
        if (prefetched.has(keyOf(selected.document, selected.procedure)))
          return undefined;
        const procedures = [selected.procedure];
        const seen = new Set(procedures);
        for (const request of pending) {
          if (procedures.length >= GHIDRA_PSEUDOCODE_PREFETCH_WINDOW) break;
          const candidate = pseudocodeSelector(request);
          if (
            candidate === undefined ||
            candidate.document !== selected.document ||
            seen.has(candidate.procedure)
          )
            continue;
          seen.add(candidate.procedure);
          procedures.push(candidate.procedure);
        }
        if (procedures.length < 2) return undefined;
        if (prefetched.size + procedures.length > PREFETCHED_KEY_LIMIT)
          prefetched.clear();
        for (const procedure of procedures)
          prefetched.add(keyOf(selected.document, procedure));
        return {
          method: GHIDRA_PSEUDOCODE_PREFETCH_METHOD,
          parameters: { document: selected.document, procedures },
        };
      },
      reset() {
        prefetched.clear();
      },
    };
  };
