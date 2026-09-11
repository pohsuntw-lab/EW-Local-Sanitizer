import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { detectText } from "../../src/core/detectors.js";
import { assertValidManifest } from "../../src/core/manifest.js";
import { createSafePackage } from "../../src/core/safe-package.js";
import { ProjectTokenRegistry } from "../../src/core/token-vault.js";
import { transformText } from "../../src/core/transform.js";
import type { ReasonCode } from "../../src/core/types.js";
import { verifiedPayloadForPackaging, verifyForExport, type VerifiedExport } from "../../src/core/verification.js";
import { inspectStoreZip, writeStoreZip } from "../../src/core/zip.js";
import { dictionary, transformAll, verificationRequest, writeSource } from "../helpers.js";

test("rejects manifests that do not satisfy the repository v0.1 schema", () => {
  assert.throws(() => assertValidManifest({ schema_version: "ew-safe-package-manifest-0.1" }), /schema validation failed/);
});

test("blocks export bypass, unresolved findings, high keep, P3 and missing P2 confirmation", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-verify-block-"));
  const detection = dictionary([]);
  const source = writeSource(directory, "Contact test.person@example.com");
  const findings = detectText(source.text, detection);
  const projectId = randomUUID();
  const registry = ProjectTokenRegistry.create(projectId, detection.dictionary);
  const missing = transformText(source.text, findings, [], { dictionary: detection.dictionary, tokenRegistry: registry });
  assert.equal(verifyForExport({ ...verificationRequest(source, missing, detection), projectId }).status, "blocked");
  const kept = transformText(source.text, findings, findings.map((finding) => ({ findingId: finding.findingId, action: "keep" as const, reasonCode: "OPERATIONAL_CONTEXT" as const })), { dictionary: detection.dictionary, tokenRegistry: registry });
  const keptOutcome = verifyForExport({ ...verificationRequest(source, kept, detection), projectId });
  assert.equal(keptOutcome.status, "blocked");
  if (keptOutcome.status === "blocked") assert.ok(keptOutcome.unresolved.some((item) => item.code === "HIGH_OR_CRITICAL_KEEP"));
  const deleted = transformText(source.text, findings, findings.map((finding) => ({ findingId: finding.findingId, action: "delete" as const })), { dictionary: detection.dictionary, tokenRegistry: registry });
  assert.equal(verifyForExport({ ...verificationRequest(source, deleted, detection), projectId, classification: "P3", allowedRoute: "local-only" }).status, "blocked");
  assert.equal(verifyForExport({ ...verificationRequest(source, deleted, detection), projectId, humanConfirmed: false }).status, "blocked");
  assert.throws(() => createSafePackage({ verifiedPayloadForPackaging: () => ({}) } as unknown as VerifiedExport, join(directory, "bypass-SAFE-PACKAGE.zip")), /Unverified export capability/);
});

test("binds authentic transformations to their source text and rejects forged dictionary snapshots", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-verify-binding-"));
  const detection = dictionary([]);
  const first = writeSource(directory, "First neutral source.", "first.txt");
  const second = writeSource(directory, "Second neutral source.", "second.txt");
  const { transformation } = transformAll(first, detection);
  const mismatch = verifyForExport(verificationRequest(second, transformation, detection));
  assert.equal(mismatch.status, "blocked");
  if (mismatch.status === "blocked") assert.ok(mismatch.unresolved.some((item) => item.code === "TRANSFORMATION_FAILED"));
  const crossProject = verifyForExport({ ...verificationRequest(first, transformation, detection), projectId: randomUUID() });
  assert.equal(crossProject.status, "blocked");
  if (crossProject.status === "blocked") assert.ok(crossProject.unresolved.some((item) => item.code === "TRANSFORMATION_FAILED"));
  const forgedDetection = { dictionary: { ...detection.dictionary, normalizedTerms: [] } };
  assert.throws(() => detectText("neutral", forgedDetection), /Untrusted dictionary snapshot/);
});

test("binds the same dictionary to second scan and blocks report-field injection", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-verify-dictionary-"));
  const detection = dictionary(["[PRIVATE NETWORK]"]);
  const source = writeSource(directory, "Host 10.10.2.15");
  const findings = detectText(source.text, detection);
  const registry = ProjectTokenRegistry.create(randomUUID(), detection.dictionary);
  const transformation = transformText(source.text, findings, findings.map((finding) => ({
    findingId: finding.findingId,
    action: "generalize" as const,
    generalizationRuleId: "IP_PRIVATE_NETWORK",
  })), { dictionary: detection.dictionary, tokenRegistry: registry });
  assert.equal(verifyForExport(verificationRequest(source, transformation, detection)).status, "blocked");
  const reportInjected = {
    ...transformation,
    publicFindings: [{
      finding_id: randomUUID(), type: "email" as const, severity: "low" as const, masked_preview: "masked", detector: "email",
      action: "keep" as const, reason_code: "test.person@example.com" as ReasonCode,
    }],
  };
  assert.equal(verifyForExport(verificationRequest(source, reportInjected, detection)).status, "blocked");
  const mismatched = { ...transformation, dictionaryHash: "0".repeat(64) };
  assert.equal(verifyForExport(verificationRequest(source, mismatched, detection)).status, "blocked");
});

test("blocks changed source hash and allows medium keep only with residual risk", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-verify-source-"));
  const detection = dictionary([]);
  const path = join(directory, "source.txt");
  writeFileSync(path, "host 10.10.2.15");
  const source = writeSource(directory, "host 10.10.2.15");
  const findings = detectText(source.text, detection);
  const registry = ProjectTokenRegistry.create(randomUUID(), detection.dictionary);
  const kept = transformText(source.text, findings, findings.map((finding) => ({ findingId: finding.findingId, action: "keep" as const, reasonCode: "LOW_SENSITIVITY_ACCEPTED" as const, localReasonDetail: "Synthetic local review detail" })), { dictionary: detection.dictionary, tokenRegistry: registry });
  const outcome = verifyForExport(verificationRequest(source, kept, detection));
  assert.equal(outcome.status, "verified");
  if (outcome.status === "verified") {
    assert.equal(outcome.residualRisk, 1);
    const output = join(directory, "residual-SAFE-PACKAGE.zip");
    createSafePackage(outcome.capability, output);
    assert.equal(readFileSync(output).includes(Buffer.from("Synthetic local review detail")), false);
  }
  writeFileSync(path, "changed");
  assert.equal(verifyForExport(verificationRequest(source, kept, detection)).status, "blocked");
});

test("writes allowlisted package, validates actual ZIP SHA-256 and excludes local artifacts", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-package-"));
  const detection = dictionary(["Example Foundry"]);
  const source = writeSource(directory, "Contact test.person@example.com for Example Foundry.");
  const findings = detectText(source.text, detection);
  const registry = ProjectTokenRegistry.create(randomUUID(), detection.dictionary);
  const transformed = transformText(source.text, findings, findings.map((finding) => ({ findingId: finding.findingId, action: "tokenize" as const })), { dictionary: detection.dictionary, tokenRegistry: registry });
  const outcome = verifyForExport(verificationRequest(source, transformed, detection));
  assert.equal(outcome.status, "verified");
  if (outcome.status !== "verified") return;
  const packagingData = JSON.stringify(verifiedPayloadForPackaging(outcome.capability));
  assert.equal(packagingData.includes("test.person@example.com"), false);
  assert.equal(packagingData.includes("Example Foundry"), false);
  assert.equal(packagingData.includes("normalizedTerms"), false);
  const output = join(directory, "synthetic-SAFE-PACKAGE.zip");
  const result = createSafePackage(outcome.capability, output);
  const archive = readFileSync(output);
  assert.equal(result.packageHash, createHash("sha256").update(archive).digest("hex"));
  assert.match(readFileSync(result.checksumPath, "utf8"), new RegExp(`^${result.packageHash}  synthetic-SAFE-PACKAGE\\.zip`));
  const allowlist = new Set(["SAFE_SOURCE/source-001.md", "SAFE-MANIFEST.json", "DLP-REPORT.json", "README-SAFE-UPLOAD.md"]);
  const inspected = inspectStoreZip(archive, allowlist);
  assert.deepEqual(inspected.map((entry) => entry.name), [...allowlist]);
  const manifestEntry = inspected.find((entry) => entry.name === "SAFE-MANIFEST.json");
  assert.ok(manifestEntry);
  const inconsistentManifest = JSON.parse(manifestEntry.data.toString("utf8"));
  inconsistentManifest.classification = "P1";
  inconsistentManifest.allowed_route = "cloud-approved";
  assert.throws(() => assertValidManifest(inconsistentManifest), /processing route/);
  assert.equal(archive.includes(Buffer.from("test.person@example.com")), false);
  assert.equal(archive.includes(Buffer.from("Example Foundry")), false);
  assert.equal(archive.includes(Buffer.from(".ewmap")), true);
  assert.equal([...allowlist].some((name) => name.endsWith(".ewmap") || name.endsWith(".sha256")), false);
  const conflictOutput = join(directory, "conflict-SAFE-PACKAGE.zip");
  const existingChecksum = `${conflictOutput}.sha256`;
  writeFileSync(existingChecksum, "pre-existing-safe-metadata");
  assert.throws(() => createSafePackage(outcome.capability, conflictOutput));
  assert.equal(readFileSync(existingChecksum, "utf8"), "pre-existing-safe-metadata");
  assert.equal(existsSync(conflictOutput), false);
  assert.equal(existsSync(`${conflictOutput}.receipt.json`), false);
});

test("scans the complete serialized public report before packaging", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-package-report-scan-"));
  const detection = dictionary(["ew-dlp-report-0.1"]);
  const source = writeSource(directory, "Neutral synthetic text.");
  const { transformation } = transformAll(source, detection);
  const outcome = verifyForExport({ ...verificationRequest(source, transformation, detection), classification: "P0", allowedRoute: "cloud-approved" });
  assert.equal(outcome.status, "verified");
  if (outcome.status === "verified") {
    assert.throws(() => createSafePackage(outcome.capability, join(directory, "report-SAFE-PACKAGE.zip")), /Public output second scan/);
  }
});

test("ZIP writer and post-write inspector reject duplicate, traversal, hidden, oversized and tampered entries", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-zip-policy-"));
  assert.throws(() => writeStoreZip(join(directory, "duplicate.zip"), [{ name: "SAFE-MANIFEST.json", data: Buffer.from("a") }, { name: "SAFE-MANIFEST.json", data: Buffer.from("b") }]), /Duplicate/);
  assert.throws(() => writeStoreZip(join(directory, "traversal.zip"), [{ name: "../secret", data: Buffer.from("a") }]), /Unsafe/);
  assert.throws(() => writeStoreZip(join(directory, "hidden.zip"), [{ name: "SAFE_SOURCE/.secret", data: Buffer.from("a") }]), /Unsafe/);
  assert.throws(() => writeStoreZip(join(directory, "drive.zip"), [{ name: "C:/secret", data: Buffer.from("a") }]), /Unsafe/);
  assert.throws(() => writeStoreZip(join(directory, "large.zip"), [{ name: "SAFE_SOURCE/source-001.md", data: Buffer.alloc(16 * 1024 * 1024 + 1) }]), /size policy/);
  const path = join(directory, "valid.zip");
  writeStoreZip(path, [{ name: "SAFE-MANIFEST.json", data: Buffer.from("safe") }]);
  const baseline = readFileSync(path);
  assert.throws(() => writeStoreZip(path, [{ name: "SAFE-MANIFEST.json", data: Buffer.from("replacement") }]));
  assert.deepEqual(readFileSync(path), baseline);
  const tampered = Buffer.from(readFileSync(path));
  const dataOffset = 30 + Buffer.byteLength("SAFE-MANIFEST.json");
  tampered[dataOffset] = (tampered[dataOffset] ?? 0) ^ 0xff;
  assert.throws(() => inspectStoreZip(tampered, new Set(["SAFE-MANIFEST.json"])), /CRC/);
  assert.throws(() => inspectStoreZip(readFileSync(path), new Set(["SAFE-MANIFEST.json", "DLP-REPORT.json"])), /allowlist/);
  assert.throws(() => inspectStoreZip(Buffer.concat([readFileSync(path), Buffer.from("hidden trailing bytes")]), new Set(["SAFE-MANIFEST.json"])), /trailing/);
  const comment = Buffer.concat([readFileSync(path), Buffer.from("secret")]);
  comment.writeUInt16LE(6, readFileSync(path).length - 2);
  assert.throws(() => inspectStoreZip(comment, new Set(["SAFE-MANIFEST.json"])), /comment/);
  const hiddenExtra = Buffer.from(readFileSync(path));
  hiddenExtra.writeUInt16LE(1, 28);
  assert.throws(() => inspectStoreZip(hiddenExtra, new Set(["SAFE-MANIFEST.json"])), /noncanonical/);

  const duplicatePath = join(directory, "postwrite-duplicate.zip");
  writeStoreZip(duplicatePath, [{ name: "SAFE-A", data: Buffer.from("a") }, { name: "SAFE-B", data: Buffer.from("b") }]);
  const duplicate = Buffer.from(readFileSync(duplicatePath));
  replaceAllAscii(duplicate, "SAFE-B", "SAFE-A");
  assert.throws(() => inspectStoreZip(duplicate, new Set(["SAFE-A"])), /Duplicate/);

  const traversalPath = join(directory, "postwrite-traversal.zip");
  writeStoreZip(traversalPath, [{ name: "SAFE/secret", data: Buffer.from("a") }]);
  const traversal = Buffer.from(readFileSync(traversalPath));
  replaceAllAscii(traversal, "SAFE/secret", "../x/secret");
  assert.throws(() => inspectStoreZip(traversal, new Set(["../x/secret"])), /Unsafe/);
});

function replaceAllAscii(buffer: Buffer, from: string, to: string): void {
  assert.equal(Buffer.byteLength(from), Buffer.byteLength(to));
  let offset = 0;
  while ((offset = buffer.indexOf(from, offset, "ascii")) !== -1) {
    buffer.write(to, offset, "ascii");
    offset += to.length;
  }
}

test("core workflow completes when network entry points are denied", () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (() => { throw new Error("network denied"); }) as typeof fetch;
  try {
    const directory = mkdtempSync(join(tmpdir(), "ew-offline-"));
    const detection = dictionary([]);
    const source = writeSource(directory, "Synthetic public knowledge.", "source.md");
    const { transformation } = transformAll(source, detection);
    const outcome = verifyForExport({ ...verificationRequest(source, transformation, detection), classification: "P0", allowedRoute: "cloud-approved" });
    assert.equal(outcome.status, "verified");
    if (outcome.status === "verified") createSafePackage(outcome.capability, join(directory, "offline-SAFE-PACKAGE.zip"));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
