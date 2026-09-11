import { Ajv2020, type ErrorObject } from "ajv/dist/2020.js";
import schema from "../../schemas/ew-safe-package-manifest-v0.1.schema.json" with { type: "json" };
import { routeAllowed } from "./policy.js";
import type { AllowedRoute, Classification } from "./types.js";

const ajv = new Ajv2020({ allErrors: true, strict: true });
const validate = ajv.compile(schema);

export function assertValidManifest(manifest: unknown): void {
  if (!validate(manifest)) throw new Error(`Manifest schema validation failed: ${formatErrors(validate.errors)}`);
  assertManifestSemantics(manifest as unknown as ManifestSemantics);
}

interface ManifestSemantics {
  policy_version: string;
  dictionary: { version: string; sha256: string };
  classification: Classification;
  allowed_route: AllowedRoute;
  sources: {
    source_id: string;
    source_format: "txt" | "markdown" | "csv" | "tsv" | "docx" | "xlsx" | "pptx";
    derivative_path: string;
    derivative_sha256: string;
    derivatives: { path: string; sha256: string }[];
  }[];
  finding_counts: {
    by_type: Record<string, number>;
    by_severity: Record<string, number>;
    by_action: Record<string, number>;
  };
  residual_risk_count: number;
  package_allowlist: string[];
  second_scan: { policy_version: string; dictionary_version: string; dictionary_sha256: string };
}

function assertManifestSemantics(manifest: ManifestSemantics): void {
  if (!routeAllowed(manifest.classification, manifest.allowed_route)) throw new Error("Manifest processing route is inconsistent");
  if (manifest.second_scan.policy_version !== manifest.policy_version ||
    manifest.second_scan.dictionary_version !== manifest.dictionary.version ||
    manifest.second_scan.dictionary_sha256 !== manifest.dictionary.sha256) {
    throw new Error("Manifest second-scan binding is inconsistent");
  }
  const expected = new Set([
    ...manifest.sources.flatMap((source) => source.derivatives.map((derivative) => derivative.path)),
    "SAFE-MANIFEST.json",
    "DLP-REPORT.json",
    "README-SAFE-UPLOAD.md",
  ]);
  if (new Set(manifest.sources.map((source) => source.source_id)).size !== manifest.sources.length) {
    throw new Error("Manifest contains duplicate source IDs");
  }
  for (const source of manifest.sources) {
    const primary = source.derivatives[0];
    if (!primary || primary.path !== source.derivative_path || primary.sha256 !== source.derivative_sha256) {
      throw new Error("Manifest primary derivative is inconsistent");
    }
    const expectedExtension = source.source_format === "csv" || source.source_format === "tsv" ? source.source_format : "md";
    if (source.source_format === "xlsx") {
      const stem = /^(.+)-index\.md$/.exec(source.derivative_path)?.[1];
      if (!stem || source.derivatives.length < 2 || source.derivatives.slice(1).some((derivative, index) =>
        derivative.path !== `${stem}-sheet-${String(index + 1).padStart(3, "0")}.csv`)) {
        throw new Error("Manifest XLSX derivative set is inconsistent");
      }
    } else if (source.derivatives.length !== 1 || !source.derivative_path.endsWith(`.${expectedExtension}`)) {
      throw new Error("Manifest derivative format is inconsistent with its source");
    }
  }
  const typeTotal = sumCounts(manifest.finding_counts.by_type);
  const severityTotal = sumCounts(manifest.finding_counts.by_severity);
  const actionTotal = sumCounts(manifest.finding_counts.by_action);
  if (typeTotal !== severityTotal || typeTotal !== actionTotal) {
    throw new Error("Manifest finding-count totals are inconsistent");
  }
  if ((manifest.finding_counts.by_action.keep ?? 0) !== manifest.residual_risk_count) {
    throw new Error("Manifest residual-risk count is inconsistent");
  }
  const derivativeCount = manifest.sources.reduce((total, source) => total + source.derivatives.length, 0);
  if (expected.size !== derivativeCount + 3 || expected.size !== manifest.package_allowlist.length ||
    manifest.package_allowlist.some((entry) => !expected.has(entry))) {
    throw new Error("Manifest package allowlist is inconsistent with sources");
  }
}

function sumCounts(counts: Record<string, number>): number {
  return Object.values(counts).reduce((total, count) => total + count, 0);
}

function formatErrors(errors: ErrorObject[] | null | undefined): string {
  return (errors ?? []).map((error) => `${error.instancePath || "/"} ${error.message ?? "invalid"}`).join("; ");
}
