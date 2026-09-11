import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { detectText } from "../src/core/detectors.ts";
import { createSafePackage } from "../src/core/safe-package.ts";
import { decryptTokenMap, encryptTokenMap } from "../src/core/token-vault.ts";
import { transformText } from "../src/core/transform.ts";

test("detects synthetic credentials, PII and exact enterprise data", () => {
  const text = [
    "customer Example Foundry",
    "email test.person@example.com",
    "phone 0912-345-678",
    "id A123456789",
    "host 10.10.2.15",
    "api_key = sk-abcdefghijklmnopqrstuvwxyz123456",
  ].join("\n");
  const findings = detectText(text, ["Example Foundry"]);
  const types = new Set(findings.map((finding) => finding.type));
  for (const type of ["exact-data", "email", "phone", "taiwan-id", "ip-address", "credential"]) {
    assert.ok(types.has(type as never), `missing ${type}`);
  }
});

test("forces credential deletion", () => {
  const text = "password = synthetic-password-123";
  const [finding] = detectText(text);
  assert.ok(finding);
  assert.throws(
    () => transformText(text, [finding], [{ findingId: finding.findingId, action: "tokenize" }]),
    /must be deleted/,
  );
  const result = transformText(text, [finding], [{ findingId: finding.findingId, action: "delete" }]);
  assert.equal(result.sanitizedText.includes("synthetic-password-123"), false);
});

test("tokenizes locally and encrypts token map with authenticated encryption", () => {
  const text = "Contact test.person@example.com for Example Foundry.";
  const findings = detectText(text, ["Example Foundry"]);
  const decisions = findings.map((finding) => ({ findingId: finding.findingId, action: "tokenize" as const }));
  const result = transformText(text, findings, decisions);
  assert.equal(result.unresolved.length, 0);
  assert.equal(result.sanitizedText.includes("test.person@example.com"), false);
  assert.equal(result.sanitizedText.includes("Example Foundry"), false);

  const encrypted = encryptTokenMap(result.tokenEntries, "correct horse battery staple");
  assert.equal(encrypted.includes(Buffer.from("test.person@example.com")), false);
  assert.deepEqual(decryptTokenMap(encrypted, "correct horse battery staple"), result.tokenEntries);
  assert.throws(() => decryptTokenMap(encrypted, "wrong passphrase value"));

  const tampered = Buffer.from(encrypted);
  const payload = JSON.parse(tampered.toString("utf8"));
  payload.ciphertext = `${payload.ciphertext.slice(0, -4)}AAAA`;
  assert.throws(() => decryptTokenMap(Buffer.from(JSON.stringify(payload)), "correct horse battery staple"));
});

test("builds an allowlisted Safe Package after second scan", () => {
  const original = "Contact test.person@example.com for Example Foundry.";
  const findings = detectText(original, ["Example Foundry"]);
  const transformed = transformText(
    original,
    findings,
    findings.map((finding) => ({ findingId: finding.findingId, action: "tokenize" as const })),
  );
  const directory = mkdtempSync(join(tmpdir(), "ew-sanitizer-"));
  const outputPath = join(directory, "synthetic-SAFE-PACKAGE.zip");
  createSafePackage({
    outputPath,
    projectId: "synthetic-project",
    sourceId: "SRC-001",
    sourceHash: createHash("sha256").update(original).digest("hex"),
    sanitizedText: transformed.sanitizedText,
    classification: "P2",
    allowedRoute: "cloud-sanitized",
    publicFindings: transformed.publicFindings,
    residualRisk: transformed.residualRisk,
    tokenMapCreated: true,
  });
  const archive = readFileSync(outputPath);
  const names = listLocalZipEntries(archive);
  assert.deepEqual(names, [
    "SAFE_SOURCE/source.md",
    "SAFE-MANIFEST.json",
    "DLP-REPORT.json",
    "README-SAFE-UPLOAD.md",
  ]);
  assert.equal(archive.includes(Buffer.from("test.person@example.com")), false);
  assert.equal(archive.includes(Buffer.from("Example Foundry")), false);
  assert.equal(names.some((name) => name.endsWith(".ewmap")), false);
});

test("blocks Safe Package export when second scan still finds high risk", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-sanitizer-block-"));
  assert.throws(
    () => createSafePackage({
      outputPath: join(directory, "blocked.zip"),
      projectId: "synthetic-project",
      sourceId: "SRC-002",
      sourceHash: "0".repeat(64),
      sanitizedText: "Contact remaining.person@example.com",
      classification: "P2",
      allowedRoute: "cloud-sanitized",
      publicFindings: [],
      residualRisk: 0,
      tokenMapCreated: false,
    }),
    /Second scan found/,
  );
});

test("blocks P3 and local-only cloud packages", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-sanitizer-p3-"));
  assert.throws(
    () => createSafePackage({
      outputPath: join(directory, "p3.zip"),
      projectId: "synthetic-project",
      sourceId: "SRC-003",
      sourceHash: "0".repeat(64),
      sanitizedText: "tokenized structural know-how",
      classification: "P3",
      allowedRoute: "local-only",
      publicFindings: [],
      residualRisk: 0,
      tokenMapCreated: false,
    }),
    /Local-only material/,
  );
});

function listLocalZipEntries(buffer: Buffer): string[] {
  const names: string[] = [];
  let offset = 0;
  while (offset + 4 <= buffer.length && buffer.readUInt32LE(offset) === 0x04034b50) {
    const compressedSize = buffer.readUInt32LE(offset + 18);
    const nameLength = buffer.readUInt16LE(offset + 26);
    const extraLength = buffer.readUInt16LE(offset + 28);
    names.push(buffer.subarray(offset + 30, offset + 30 + nameLength).toString("utf8"));
    offset += 30 + nameLength + extraLength + compressedSize;
  }
  return names;
}

