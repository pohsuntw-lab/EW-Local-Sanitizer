import { createHash } from "node:crypto";
import { detectText } from "./detectors.ts";
import type { Classification, PublicFinding } from "./types.ts";
import { writeStoreZip } from "./zip.ts";

interface SafePackageInput {
  outputPath: string;
  projectId: string;
  sourceId: string;
  sourceHash: string;
  sanitizedText: string;
  classification: Classification;
  allowedRoute: "cloud-approved" | "cloud-sanitized" | "local-only";
  publicFindings: PublicFinding[];
  residualRisk: number;
  tokenMapCreated: boolean;
}

export function createSafePackage(input: SafePackageInput): { packageHash: string; derivativeHash: string } {
  if (input.classification === "P3" || input.allowedRoute === "local-only") {
    throw new Error("Local-only material cannot be exported as a cloud Safe Package");
  }
  const secondScan = detectText(input.sanitizedText);
  const blocking = secondScan.filter((finding) => finding.severity === "critical" || finding.severity === "high");
  if (blocking.length > 0) throw new Error(`Second scan found ${blocking.length} blocking finding(s)`);

  const sourceName = "SAFE_SOURCE/source.md";
  const derivative = Buffer.from(input.sanitizedText, "utf8");
  const derivativeHash = sha256(derivative);
  const report = {
    schema_version: "1.0",
    project_id: input.projectId,
    source_id: input.sourceId,
    finding_counts: countFindings(input.publicFindings),
    findings: input.publicFindings,
    residual_risk_count: input.residualRisk,
    second_scan: { result: "pass", blocking_findings: 0 },
    disclaimer: "Defense-in-depth only; absence of detection is not proof of safety.",
  };
  const manifest = {
    schema_version: "1.0",
    tool: "EW Local Sanitizer",
    tool_version: "0.1.0",
    project_id: input.projectId,
    package_id: `${input.projectId}-${input.sourceId}`,
    source: { source_id: input.sourceId, sha256: input.sourceHash },
    derivative: { path: sourceName, sha256: derivativeHash },
    classification: input.classification,
    allowed_route: input.allowedRoute,
    parser_coverage: "plain-text-complete",
    token_map_created: input.tokenMapCreated,
    token_map_in_package: false,
    allowlist: [sourceName, "SAFE-MANIFEST.json", "DLP-REPORT.json", "README-SAFE-UPLOAD.md"],
  };
  const entries = [
    { name: sourceName, data: derivative },
    { name: "SAFE-MANIFEST.json", data: jsonBuffer(manifest) },
    { name: "DLP-REPORT.json", data: jsonBuffer(report) },
    {
      name: "README-SAFE-UPLOAD.md",
      data: Buffer.from(
        "# EW Safe Package\n\nUpload this package only to an enterprise-approved AI environment. Keep originals and .ewmap files local. A passed scan is not a confidentiality guarantee.\n",
        "utf8",
      ),
    },
  ];
  writeStoreZip(input.outputPath, entries);
  const packageHash = sha256(Buffer.concat(entries.flatMap((entry) => [Buffer.from(entry.name), entry.data])));
  return { packageHash, derivativeHash };
}

function jsonBuffer(value: unknown): Buffer {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function sha256(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function countFindings(findings: PublicFinding[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const finding of findings) counts[`${finding.severity}:${finding.action}`] = (counts[`${finding.severity}:${finding.action}`] || 0) + 1;
  return counts;
}

