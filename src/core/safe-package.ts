import { createHash, randomUUID } from "node:crypto";
import { readFileSync, unlinkSync } from "node:fs";
import { basename } from "node:path";
import { assertValidManifest } from "./manifest.js";
import { writeExclusiveFile } from "./exclusive-write.js";
import type { PublicFinding } from "./types.js";
import { assertVerifiedPublicOutput, verifiedPayloadForPackaging, type VerifiedExport } from "./verification.js";
import { inspectStoreZip, writeStoreZip, type ZipEntry } from "./zip.js";

export interface SafePackageResult {
  packageHash: string;
  checksumPath: string;
  receiptPath: string;
  derivativeHashes: string[];
}

export function createSafePackage(capability: VerifiedExport, outputPath: string): SafePackageResult {
  const verified = verifiedPayloadForPackaging(capability);
  const packageName = basename(outputPath);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,100}-SAFE-PACKAGE\.zip$/.test(packageName)) {
    throw new Error("Safe Package filename must use controlled characters and end with -SAFE-PACKAGE.zip");
  }
  const checksumPath = `${outputPath}.sha256`;
  const receiptPath = `${outputPath}.receipt.json`;
  const derivativeEntries: ZipEntry[] = verified.items.map((item, index) => ({
    name: `SAFE_SOURCE/source-${String(index + 1).padStart(3, "0")}.md`,
    data: Buffer.from(item.derivative.sanitizedText, "utf8"),
  }));
  const allowlist = new Set([
    ...derivativeEntries.map((entry) => entry.name),
    "SAFE-MANIFEST.json",
    "DLP-REPORT.json",
    "README-SAFE-UPLOAD.md",
  ]);
  const derivativeHashes = derivativeEntries.map((entry) => sha256(entry.data));
  const allFindings = verified.items.flatMap((item) => item.derivative.publicFindings);
  const residualRisk = verified.items.reduce((sum, item) => sum + item.derivative.residualRisk, 0);
  const manifest = {
    schema_version: "ew-safe-package-manifest-0.1",
    tool: "EW Local Sanitizer",
    tool_version: "0.1.0",
    project_id: verified.projectId,
    package_id: randomUUID(),
    created_at: verified.verifiedAt,
    policy_version: verified.items[0]?.derivative.policyVersion,
    dictionary: {
      version: verified.dictionary.version,
      sha256: verified.dictionary.hash,
    },
    classification: verified.classification,
    allowed_route: verified.allowedRoute,
    sources: verified.items.map((item, index) => ({
      source_id: item.source.sourceId,
      source_sha256: item.source.originalHash,
      derivative_path: derivativeEntries[index]?.name,
      derivative_sha256: derivativeHashes[index],
      parser_coverage: item.source.coverage,
    })),
    finding_counts: countFindings(allFindings),
    unresolved_count: 0,
    residual_risk_count: residualRisk,
    second_scan: {
      status: "pass",
      blocking_findings: verified.secondScanBlockingFindings,
      policy_version: verified.items[0]?.derivative.policyVersion,
      dictionary_version: verified.dictionary.version,
      dictionary_sha256: verified.dictionary.hash,
    },
    token_map_created: verified.tokenMapCreated,
    package_allowlist: [...allowlist],
    package_hash: { method: "sha256", location: "external-sibling-and-local-receipt" },
    integration_status: "pending-ew-enterprise-secure-knowledge-forge",
  };
  assertValidManifest(manifest);
  const report = {
    schema_version: "ew-dlp-report-0.1",
    package_id: manifest.package_id,
    finding_counts: manifest.finding_counts,
    findings: allFindings,
    unresolved_count: 0,
    residual_risk_count: residualRisk,
    second_scan: { status: "pass", blocking_findings: 0 },
    disclaimer: "Defense-in-depth only; absence of detection is not proof of safety.",
  };
  const reportBuffer = jsonBuffer(report);
  const manifestBuffer = jsonBuffer(manifest);
  const readmeBuffer = Buffer.from(
    "# EW Safe Package\n\nUpload only to an enterprise-approved AI environment. Keep originals, project dictionaries and .ewmap files local. A passed scan is not a confidentiality guarantee.\n",
    "utf8",
  );
  for (const publicOutput of [manifestBuffer, reportBuffer, readmeBuffer]) {
    assertVerifiedPublicOutput(capability, publicOutput.toString("utf8"));
  }
  const entries: ZipEntry[] = [
    ...derivativeEntries,
    { name: "SAFE-MANIFEST.json", data: manifestBuffer },
    { name: "DLP-REPORT.json", data: reportBuffer },
    { name: "README-SAFE-UPLOAD.md", data: readmeBuffer },
  ];

  const created: string[] = [];
  try {
    writeStoreZip(outputPath, entries);
    created.push(outputPath);
    const archive = readFileSync(outputPath);
    const inspected = inspectStoreZip(archive, allowlist);
    for (const derivative of derivativeEntries) {
      const stored = inspected.find((entry) => entry.name === derivative.name);
      if (!stored || sha256(stored.data) !== sha256(derivative.data)) throw new Error("ZIP derivative hash verification failed");
    }
    const packageHash = sha256(archive);
    writeExclusiveFile(checksumPath, `${packageHash}  ${packageName}\n`);
    created.push(checksumPath);
    writeExclusiveFile(receiptPath, jsonBuffer({
      schema_version: "ew-export-receipt-0.1",
      status: "verified",
      package_file: packageName,
      output_location: outputPath,
      package_sha256: packageHash,
      derivative_sha256: derivativeHashes,
      created_at: verified.verifiedAt,
    }));
    created.push(receiptPath);
    return { packageHash, checksumPath, receiptPath, derivativeHashes };
  } catch (error) {
    for (const path of created.reverse()) {
      try { unlinkSync(path); } catch { /* generated artifact cleanup is best-effort */ }
    }
    throw error;
  }
}

function jsonBuffer(value: unknown): Buffer {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function sha256(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function countFindings(findings: readonly PublicFinding[]): { by_type: Record<string, number>; by_severity: Record<string, number>; by_action: Record<string, number> } {
  const result = { by_type: {} as Record<string, number>, by_severity: {} as Record<string, number>, by_action: {} as Record<string, number> };
  for (const finding of findings) {
    result.by_type[finding.type] = (result.by_type[finding.type] ?? 0) + 1;
    result.by_severity[finding.severity] = (result.by_severity[finding.severity] ?? 0) + 1;
    result.by_action[finding.action] = (result.by_action[finding.action] ?? 0) + 1;
  }
  return result;
}
