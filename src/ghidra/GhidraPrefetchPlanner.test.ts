import { describe, expect, it } from "vitest";

import { err, ok } from "../domain/result.js";
import {
  GHIDRA_PSEUDOCODE_PREFETCH_METHOD,
  GHIDRA_PSEUDOCODE_PREFETCH_WINDOW,
  createGhidraPseudocodePrefetchPlanner,
} from "./GhidraPrefetchPlanner.js";
import { GhidraRequestQueue } from "./GhidraRequestQueue.js";
import { bindGhidraSessionFailure } from "./GhidraSessionError.js";

const pseudocode = (procedure: string, document: string | null = "a.exe") => ({
  method: "procedure_pseudo_code",
  parameters: { document, procedure },
});

const failure = bindGhidraSessionFailure(() => ({
  target_path: "/tmp/prefetch-fixture",
}));

describe("Ghidra pseudocode prefetch planner", () => {
  it("coalesces queued pseudocode requests for the head's document", () => {
    const planner = createGhidraPseudocodePrefetchPlanner();
    expect(
      planner.plan(pseudocode("main"), [
        pseudocode("helper"),
        { method: "procedure_assembly", parameters: { procedure: "x" } },
        pseudocode("main"),
        pseudocode("other", "b.exe"),
        pseudocode("0x401000"),
      ]),
    ).toEqual({
      method: GHIDRA_PSEUDOCODE_PREFETCH_METHOD,
      parameters: {
        document: "a.exe",
        procedures: ["main", "helper", "0x401000"],
      },
    });
  });

  it("does not prefetch a lone request or other methods", () => {
    const planner = createGhidraPseudocodePrefetchPlanner();
    expect(planner.plan(pseudocode("main"), [])).toBeUndefined();
    expect(
      planner.plan({ method: "list_procedures", parameters: {} }, [
        pseudocode("main"),
        pseudocode("helper"),
      ]),
    ).toBeUndefined();
  });

  it("plans one window at a time and resets with the session", () => {
    const planner = createGhidraPseudocodePrefetchPlanner();
    const queued = Array.from(
      { length: GHIDRA_PSEUDOCODE_PREFETCH_WINDOW + 5 },
      (_, index) => pseudocode(`fn_${String(index)}`),
    );
    const [head, ...rest] = queued;
    if (head === undefined) throw new Error("fixture");
    const first = planner.plan(head, rest);
    expect(first?.parameters).toMatchObject({
      procedures: queued
        .slice(0, GHIDRA_PSEUDOCODE_PREFETCH_WINDOW)
        .map((request) => request.parameters.procedure),
    });
    // Requests already inside the first window are served from the cache.
    expect(planner.plan(queued[1] ?? head, queued.slice(2))).toBeUndefined();
    // The first request beyond the window starts the next window.
    const next = queued[GHIDRA_PSEUDOCODE_PREFETCH_WINDOW];
    if (next === undefined) throw new Error("fixture");
    expect(
      planner.plan(next, queued.slice(GHIDRA_PSEUDOCODE_PREFETCH_WINDOW + 1))
        ?.parameters,
    ).toMatchObject({
      procedures: queued
        .slice(GHIDRA_PSEUDOCODE_PREFETCH_WINDOW)
        .map((request) => request.parameters.procedure),
    });
    planner.reset();
    expect(planner.plan(head, rest)).toBeDefined();
  });
});

describe("Ghidra request queue planned requests", () => {
  it("sends the planned prefetch ahead of the head and keeps per-request results", async () => {
    const executed: string[] = [];
    let release: (() => void) | undefined;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const queue = new GhidraRequestQueue(
      async (method, parameters) => {
        executed.push(method);
        if (method === "list_documents") await blocked;
        return ok({ method, parameters });
      },
      failure,
      () => Promise.resolve(),
      createGhidraPseudocodePrefetchPlanner(),
    );
    const warmup = queue.run("list_documents", {}, {});
    const results = [
      queue.run("procedure_pseudo_code", pseudocode("a").parameters, {}),
      queue.run("procedure_pseudo_code", pseudocode("b").parameters, {}),
      queue.run("procedure_pseudo_code", pseudocode("c").parameters, {}),
    ];
    release?.();
    await warmup;
    const settled = await Promise.all(results);
    expect(executed).toEqual([
      "list_documents",
      GHIDRA_PSEUDOCODE_PREFETCH_METHOD,
      "procedure_pseudo_code",
      "procedure_pseudo_code",
      "procedure_pseudo_code",
    ]);
    expect(settled.map((result) => result.ok)).toEqual([true, true, true]);
    expect(settled[0]).toEqual(
      ok({
        method: "procedure_pseudo_code",
        parameters: pseudocode("a").parameters,
      }),
    );
  });

  it("still runs the head when the planned request fails", async () => {
    const executed: string[] = [];
    let release: (() => void) | undefined;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const queue = new GhidraRequestQueue(
      async (method) => {
        executed.push(method);
        if (method === "list_documents") await blocked;
        if (method === GHIDRA_PSEUDOCODE_PREFETCH_METHOD)
          return err(failure("remote", "Bridge method is unavailable"));
        if (method === "procedure_pseudo_code" && executed.length === 3)
          throw new TypeError("unexpected");
        return ok(method);
      },
      failure,
      () => Promise.resolve(),
      createGhidraPseudocodePrefetchPlanner(),
    );
    const warmup = queue.run("list_documents", {}, {});
    const first = queue.run(
      "procedure_pseudo_code",
      pseudocode("a").parameters,
      {},
    );
    const second = queue.run(
      "procedure_pseudo_code",
      pseudocode("b").parameters,
      {},
    );
    release?.();
    await warmup;
    await expect(first).resolves.toMatchObject({
      ok: false,
      error: { kind: "protocol" },
    });
    await expect(second).resolves.toEqual(ok("procedure_pseudo_code"));
    expect(executed).toEqual([
      "list_documents",
      GHIDRA_PSEUDOCODE_PREFETCH_METHOD,
      "procedure_pseudo_code",
      "procedure_pseudo_code",
    ]);
  });
});
