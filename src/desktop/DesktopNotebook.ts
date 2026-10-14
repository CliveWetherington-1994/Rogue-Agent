import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { z } from "zod";

/**
 * The analyst's own names and notes for one binary, kept beside the desktop
 * settings and keyed by the binary's SHA-256. They are a display overlay: the
 * binary and Ghidra's analysis are never changed.
 */

const FORMAT = "rogue-agent-notebook-v1";
const sha256Schema = z.string().regex(/^[a-f0-9]{64}$/u);
/** Same selector shape the desktop API accepts for addresses. */
export const notebookAddressSchema = z
  .string()
  .min(1)
  .max(256)
  .regex(/^[\w:.$@?<>~-]+$/u, "Invalid address");
const labelSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[^\p{Cc}]+$/u, "Names cannot contain control characters");
const noteSchema = z.string().max(8000);

const entrySchema = z.strictObject({
  label: labelSchema.nullable(),
  note: noteSchema,
  updated_at: z.string(),
});
const notebookSchema = z.strictObject({
  format: z.literal(FORMAT),
  sha256: sha256Schema,
  target_name: z.string(),
  entries: z.record(notebookAddressSchema, entrySchema),
});

/** Names and notes for one binary. */
export type DesktopNotebook = z.infer<typeof notebookSchema>;
export type DesktopNotebookEntry = z.infer<typeof entrySchema>;

/** One change from the UI; an empty name clears it, an omitted field keeps it. */
export const notebookPatchSchema = z.strictObject({
  address: notebookAddressSchema,
  label: z
    .string()
    .max(128)
    .transform((value) => value.trim())
    .pipe(z.union([z.literal(""), labelSchema]))
    .nullable()
    .optional(),
  note: noteSchema.optional(),
});
export type DesktopNotebookPatch = z.infer<typeof notebookPatchSchema>;

/** File name of a Windows or POSIX path, whichever platform reads it. */
const fileName = (path: string): string => path.split(/[\\/]/u).pop() ?? path;

const emptyNotebook = (
  sha256: string,
  targetName: string,
): DesktopNotebook => ({
  format: FORMAT,
  sha256,
  target_name: targetName,
  entries: {},
});

/** Notebooks on disk: `<directory>/<sha256>.json`, written atomically. */
export class DesktopNotebookStore {
  readonly #directory: string;
  readonly #cache = new Map<string, DesktopNotebook>();
  /** Files that exist but do not parse; kept aside before the first write. */
  readonly #unreadable = new Set<string>();
  #writes: Promise<unknown> = Promise.resolve();

  constructor(directory: string) {
    this.#directory = directory;
  }

  #path(sha256: string): string {
    return join(this.#directory, `${sha256}.json`);
  }

  async load(sha256: string, targetPath: string): Promise<DesktopNotebook> {
    if (!sha256Schema.safeParse(sha256).success)
      throw new Error("A notebook needs the binary's SHA-256");
    const cached = this.#cache.get(sha256);
    if (cached !== undefined) return cached;
    let notebook = emptyNotebook(sha256, fileName(targetPath));
    try {
      const parsed = notebookSchema.safeParse(
        JSON.parse(await readFile(this.#path(sha256), "utf8")),
      );
      if (parsed.success && parsed.data.sha256 === sha256)
        notebook = parsed.data;
      else this.#unreadable.add(sha256);
    } catch (cause: unknown) {
      const missing =
        cause instanceof Error && "code" in cause && cause.code === "ENOENT";
      if (!missing) this.#unreadable.add(sha256);
    }
    this.#cache.set(sha256, notebook);
    return notebook;
  }

  /** Apply one change and persist the notebook. */
  async update(
    sha256: string,
    targetPath: string,
    patch: DesktopNotebookPatch,
  ): Promise<DesktopNotebook> {
    const current = await this.load(sha256, targetPath);
    const previous = current.entries[patch.address];
    const label =
      patch.label === undefined
        ? (previous?.label ?? null)
        : patch.label === null || patch.label === ""
          ? null
          : labelSchema.parse(patch.label);
    const note = patch.note ?? previous?.note ?? "";
    const entries = { ...current.entries };
    if (label === null && note.trim() === "") delete entries[patch.address];
    else
      entries[patch.address] = {
        label,
        note,
        updated_at: new Date().toISOString(),
      };
    const next: DesktopNotebook = { ...current, entries };
    this.#cache.set(sha256, next);
    const write = this.#writes.then(() => this.#persist(next));
    this.#writes = write.catch(() => undefined);
    await write;
    return next;
  }

  async #persist(notebook: DesktopNotebook): Promise<void> {
    await mkdir(this.#directory, { recursive: true });
    const path = this.#path(notebook.sha256);
    if (this.#unreadable.delete(notebook.sha256))
      // Never overwrite notes we could not read; keep them for the user.
      await rename(
        path,
        join(
          this.#directory,
          `${notebook.sha256}.unreadable-${Date.now()}.json`,
        ),
      ).catch(() => undefined);
    const partial = `${path}.${process.pid}.partial`;
    await writeFile(partial, `${JSON.stringify(notebook, null, 2)}\n`, "utf8");
    await rename(partial, path);
  }
}

/** One function or value described in a mod plan. */
export interface ModPlanEntry {
  readonly address: string;
  /** Ghidra's name; null when the address is not a known function. */
  readonly originalName: string | null;
  readonly label: string | null;
  readonly note: string;
  readonly fileOffset: number | null;
  readonly callers: readonly string[];
  readonly callees: readonly string[];
  readonly pseudocode: string | null;
}

export interface ModPlanTarget {
  readonly path: string;
  readonly sha256: string;
  readonly format: string;
  readonly architecture: string | null;
}

/** A fence that cannot be closed by backticks inside the text. */
const fence = (value: string): string => {
  const longest = Math.max(
    2,
    ...[...value.matchAll(/`+/gu)].map((run) => run[0].length),
  );
  return "`".repeat(longest + 1);
};
const inline = (value: string): string =>
  value.includes("`") ? `\`\` ${value} \`\`` : `\`${value}\``;
const hex = (value: number): string => `0x${value.toString(16)}`;

/**
 * Markdown summary of the functions an analyst named or annotated: where they
 * are in memory and in the file, how they connect, and their decompiled C.
 */
export const renderModPlan = (input: {
  readonly target: ModPlanTarget;
  readonly generatedAt: string;
  readonly entries: readonly ModPlanEntry[];
}): string => {
  const { target } = input;
  const lines = [
    `# Mod plan: ${fileName(target.path)}`,
    "",
    `- File: ${inline(target.path)}`,
    `- SHA-256: ${inline(target.sha256)}`,
    `- Format: ${target.format}${target.architecture === null ? "" : ` ${target.architecture}`}`,
    `- Generated: ${input.generatedAt} by Rogue Agent`,
    "",
    "Addresses are where Ghidra loaded each function in memory. A file offset is where the same bytes sit in the file on disk; it is absent when the address has no bytes in the file. Names are yours, shown over Ghidra's; neither the file nor the analysis was changed.",
  ];
  if (input.entries.length === 0)
    lines.push(
      "",
      "No functions are named or annotated yet. Select a function, give it a name or a note, then export again.",
    );
  for (const entry of input.entries) {
    const title = entry.label ?? entry.originalName ?? entry.address;
    lines.push("", `## ${title}`, "");
    lines.push(
      `- Address: ${inline(entry.address)}${entry.originalName !== null && entry.originalName !== title ? ` (Ghidra: ${inline(entry.originalName)})` : ""}`,
      `- File offset: ${entry.fileOffset === null ? "none (no bytes in the file)" : inline(hex(entry.fileOffset))}`,
    );
    if (entry.originalName !== null) {
      lines.push(
        `- Called by: ${entry.callers.length === 0 ? "nothing found" : entry.callers.map(inline).join(", ")}`,
        `- Calls: ${entry.callees.length === 0 ? "nothing" : entry.callees.map(inline).join(", ")}`,
      );
    }
    if (entry.note.trim() !== "") lines.push("", entry.note.trim());
    if (entry.pseudocode !== null) {
      const marker = fence(entry.pseudocode);
      lines.push("", `${marker}c`, entry.pseudocode.trimEnd(), marker);
    }
  }
  return `${lines.join("\n")}\n`;
};
