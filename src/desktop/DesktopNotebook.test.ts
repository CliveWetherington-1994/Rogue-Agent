import {
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { DesktopNotebookStore, renderModPlan } from "./DesktopNotebook.js";

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});
const directory = async (): Promise<string> => {
  const root = await mkdtemp(join(tmpdir(), "rogue-notebook-"));
  roots.push(root);
  return join(root, "notebooks");
};
const SHA = "b".repeat(64);

describe("desktop notebook", () => {
  it("saves names and notes per binary and reloads them", async () => {
    const path = await directory();
    const store = new DesktopNotebookStore(path);
    expect((await store.load(SHA, "C:\\games\\demo.exe")).entries).toEqual({});
    await store.update(SHA, "C:\\games\\demo.exe", {
      address: "0x401000",
      label: "start_game",
    });
    await store.update(SHA, "C:\\games\\demo.exe", {
      address: "0x401000",
      note: "Called once at boot.",
    });
    const reloaded = await new DesktopNotebookStore(path).load(SHA, "demo.exe");
    expect(reloaded.entries["0x401000"]).toMatchObject({
      label: "start_game",
      note: "Called once at boot.",
    });
    expect(await readdir(path)).toEqual([`${SHA}.json`]);
  });

  it("removes an entry once both its name and note are cleared", async () => {
    const store = new DesktopNotebookStore(await directory());
    await store.update(SHA, "demo.exe", { address: "0x10", label: "x" });
    const cleared = await store.update(SHA, "demo.exe", {
      address: "0x10",
      label: null,
    });
    expect(cleared.entries).toEqual({});
  });

  it("keeps an unreadable notebook aside instead of overwriting it", async () => {
    const path = await directory();
    await mkdir(path, { recursive: true });
    await writeFile(join(path, `${SHA}.json`), "{ not json");
    const store = new DesktopNotebookStore(path);
    expect((await store.load(SHA, "demo.exe")).entries).toEqual({});
    await store.update(SHA, "demo.exe", { address: "0x10", label: "fresh" });
    const names = (await readdir(path)).sort();
    expect(names).toHaveLength(2);
    const kept = names.find((name) => name.includes(".unreadable-"));
    expect(kept).toBeDefined();
    expect(await readFile(join(path, kept ?? ""), "utf8")).toBe("{ not json");
  });

  it("rejects names with control characters and invalid hashes", async () => {
    const store = new DesktopNotebookStore(await directory());
    await expect(
      store.update(SHA, "demo.exe", { address: "0x10", label: "a\u0007b" }),
    ).rejects.toThrow();
    await expect(store.load("not-a-hash", "demo.exe")).rejects.toThrow();
  });
});

describe("mod plan", () => {
  const target = {
    path: "C:\\games\\demo.exe",
    sha256: SHA,
    format: "pe",
    architecture: "x86_64",
  };

  it("describes each annotated function with its location and code", () => {
    const plan = renderModPlan({
      target,
      generatedAt: "2026-10-14T00:00:00.000Z",
      entries: [
        {
          address: "0x401000",
          originalName: "FUN_00401000",
          label: "update_health",
          note: "Subtracts damage from HP.",
          fileOffset: 0x400,
          callers: ["game_tick"],
          callees: [],
          pseudocode: "void f(void) { /* ``` */ }",
        },
        {
          address: "0x405000",
          originalName: null,
          label: "player_hp",
          note: "",
          fileOffset: null,
          callers: [],
          callees: [],
          pseudocode: null,
        },
      ],
    });
    expect(plan).toContain("# Mod plan: demo.exe");
    expect(plan).toContain("## update_health");
    expect(plan).toContain("(Ghidra: `FUN_00401000`)");
    expect(plan).toContain("- File offset: `0x400`");
    expect(plan).toContain("- Called by: `game_tick`");
    expect(plan).toContain("Subtracts damage from HP.");
    // Backticks in the code lengthen the fence so it cannot close early.
    expect(plan).toContain("````c\nvoid f(void) { /* ``` */ }\n````");
    expect(plan).toContain("## player_hp");
    expect(plan).toContain("- File offset: none (no bytes in the file)");
    expect(plan).not.toContain(
      "player_hp\n\n- Address: `0x405000`\n- File offset: none (no bytes in the file)\n- Called by",
    );
  });

  it("explains how to start when nothing is annotated", () => {
    expect(
      renderModPlan({ target, generatedAt: "now", entries: [] }),
    ).toContain("No functions are named or annotated yet.");
  });
});
