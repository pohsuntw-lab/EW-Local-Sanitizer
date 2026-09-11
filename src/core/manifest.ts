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
  sources: { source_id: string; source_format: "txt" | "markdown" | "csv" | "tsv"; derivative_path: string }[];
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
    ...manifest.sources.map((source) => source.derivative_path),
    "SAFE-MANIFEST.json",
    "DLP-REPORT.json",
    "README-SAFE-UPLOAD.md",
  ]);
  if (new Set(manifest.sources.map((source) => source.source_id)).size !== manifest.sources.length) {
    throw new Error("Manifest contains duplicate source IDs");
  }
  for (const source of manifest.sources) {
    const expectedExtension = source.source_format === "csv" || source.source_format === "tsv" ? source.source_format : "md";
    if (!source.derivative_path.endsWith(`.${expectedExtension}`)) throw new Error("Manifest derivative format is inconsistent with its source");
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
  if (expected.size !== manifest.sources.length + 3 || expected.size !== manifest.package_allowlist.length ||
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
