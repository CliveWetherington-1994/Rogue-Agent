import { describe, expect, it } from "vitest";

import { ghidraFunctionDossier } from "../../../src/domain/ghidraValues.fixture.js";
import { functionComparisonResultSchema } from "../../../src/domain/functionComparisonSchemas.js";
import { functionDossierSchema } from "../../../src/domain/hopperValues.js";
import { jsonValueSchema } from "../../../src/domain/jsonValue.js";
import { ok } from "../../../src/domain/result.js";
import { connectGhidraMcp, sessionEvidence } from "./ghidraMcpHarness.js";

const resolvedCallDiagnostic =
  "Only resolved Ghidra call references are returned; unresolved computed or indirect calls remain unknown, while function classifications distinguish thunks and externals.";

const compareWithItself = async (
  dossier: ReturnType<typeof functionDossierSchema.parse>,
) => {
  const harness = await connectGhidraMcp(
    "ghidra-function-comparison",
    (operation) => {
      if (operation !== "analyze_function")
        throw new Error(`Unexpected operation: ${operation}`);
      return Promise.resolve(
        ok({ value: jsonValueSchema.parse(dossier), limitations: [] }),
      );
    },
  );
  try {
    const analyzed = await harness.mcp.callTool({
      name: "analyze_function",
      arguments: { procedure: dossier.procedure.address },
    });
    expect(analyzed.isError).not.toBe(true);
    const evidence = sessionEvidence(
      harness.session,
      analyzed.structuredContent,
    );
    const compared = await harness.mcp.callTool({
      name: "compare_functions",
      arguments: {
        left: analyzed.structuredContent,
        right: analyzed.structuredContent,
      },
    });
    expect(compared.isError, JSON.stringify(compared)).not.toBe(true);
    return {
      evidence,
      comparison: sessionEvidence(harness.session, compared.structuredContent),
    };
  } finally {
    await harness.close();
  }
};

describe("Ghidra function comparison coverage", () => {
  it("establishes an unchanged self-comparison from declared empty comments and complete call coverage", async () => {
    const dossier = functionDossierSchema.parse(ghidraFunctionDossier());
    expect(dossier).toMatchObject({
      comments: [],
      callers: [],
      callees: [],
      unresolved_calls: [],
    });

    const { evidence, comparison } = await compareWithItself(dossier);

    expect(evidence.relationship_coverage).toEqual({
      status: "complete",
      diagnostics: [resolvedCallDiagnostic],
    });
    expect(comparison.normalized_result).toMatchObject({
      status: "unchanged",
    });
  });

  it("keeps calls unknown when Ghidra decodes a call without a resolved destination", async () => {
    const dossier = functionDossierSchema.parse({
      ...functionDossierSchema.parse(ghidraFunctionDossier()),
      unresolved_calls: [
        {
          address: "0x401000",
          reason:
            "Instruction decoder identifies a call but ReferenceManager supplies no call destination",
        },
      ],
    });

    const { evidence, comparison } = await compareWithItself(dossier);

    const partial =
      "Callees: Ghidra decoded 1 call instruction without a resolved destination; those callees remain unknown.";
    expect(evidence.relationship_coverage).toEqual({
      status: "partial",
      limitations: [partial],
      diagnostics: [resolvedCallDiagnostic],
    });
    const result = functionComparisonResultSchema.parse(
      comparison.normalized_result,
    );
    expect(result.status).toBe("unknown");
    const calls = result.dimensions.find(
      ({ dimension }) => dimension === "calls",
    );
    expect(calls?.status).toBe("unknown");
    expect(calls?.limitations).toEqual(
      expect.arrayContaining([
        `Left: ${partial}`,
        "Left: Unresolved call at 0x401000: Instruction decoder identifies a call but ReferenceManager supplies no call destination",
      ]),
    );
    expect(
      result.dimensions
        .filter(({ dimension }) => dimension !== "calls")
        .map(({ status }) => status),
    ).toEqual(Array(7).fill("unchanged"));
  });

  it("keeps comments unknown when Ghidra declares them unreadable", async () => {
    const dossier = functionDossierSchema.parse({
      ...functionDossierSchema.parse(ghidraFunctionDossier()),
      facet_availability: {
        comments: {
          available: false,
          reason:
            "Ghidra external functions have no local body; external-location comments are not read.",
        },
        callers: { available: true },
        callees: { available: true },
      },
    });

    const { comparison } = await compareWithItself(dossier);

    const result = functionComparisonResultSchema.parse(
      comparison.normalized_result,
    );
    expect(result.status).toBe("unknown");
    expect(
      result.dimensions.find(({ dimension }) => dimension === "comments")
        ?.status,
    ).toBe("unknown");
  });
});
