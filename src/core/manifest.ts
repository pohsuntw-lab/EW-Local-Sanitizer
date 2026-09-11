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
  sources: { derivative_path: string }[];
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
  if (expected.size !== manifest.sources.length + 3 || expected.size !== manifest.package_allowlist.length ||
    manifest.package_allowlist.some((entry) => !expected.has(entry))) {
    throw new Error("Manifest package allowlist is inconsistent with sources");
  }
}

function formatErrors(errors: ErrorObject[] | null | undefined): string {
  return (errors ?? []).map((error) => `${error.instancePath || "/"} ${error.message ?? "invalid"}`).join("; ");
}
