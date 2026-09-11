import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { intakeTabular, sourceHashStillMatches } from "../../src/core/intake.js";
import { parseTabularText } from "../../src/core/tabular.js";
import { createSafePackage } from "../../src/core/safe-package.js";
import { detectSource } from "../../src/core/source-scan.js";
import { ProjectTokenRegistry } from "../../src/core/token-vault.js";
import { transformText } from "../../src/core/transform.js";
import { inspectStoreZip } from "../../src/core/zip.js";
import { verifyForExport } from "../../src/core/verification.js";
import { dictionary, verificationRequest, writeTabularSource } from "../helpers.js";

test("CSV intake parses quoted fields, scans cells, neutralizes formulas and packages a CSV derivative", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-csv-"));
  const source = writeTabularSource(directory,
    'name,contact,note\nSynthetic,test.person@example.com,"=SUM(1,2)"\n', "input.csv");
  const detection = dictionary([]);
  const findings = detectSource(source, detection);
  assert.deepEqual(new Set(findings.map((finding) => finding.type)), new Set(["email", "spreadsheet-formula"]));
  const registry = ProjectTokenRegistry.create(detection.dictionary.projectId, detection.dictionary);
  const transformation = transformText(source.text, findings, findings.map((finding) => finding.type === "spreadsheet-formula"
    ? { findingId: finding.findingId, action: "generalize" as const, generalizationRuleId: "FORMULA_AS_LITERAL" }
    : { findingId: finding.findingId, action: "delete" as const }), { dictionary: detection.dictionary, tokenRegistry: registry });
  assert.match(transformation.sanitizedText, /"'=SUM\(1,2\)"/);
  assert.doesNotMatch(transformation.sanitizedText, /test\.person@/);
  assert.equal(sourceHashStillMatches(source), true);

  const outcome = verifyForExport(verificationRequest(source, transformation, detection));
  assert.equal(outcome.status, "verified");
  if (outcome.status !== "verified") return;
  const output = join(directory, "csv-SAFE-PACKAGE.zip");
  createSafePackage(outcome.capability, output);
  const entries = inspectStoreZip(readFileSync(output), new Set([
    "SAFE_SOURCE/source-001.csv", "SAFE-MANIFEST.json", "DLP-REPORT.json", "README-SAFE-UPLOAD.md",
  ]));
  const derivative = entries.find((entry) => entry.name === "SAFE_SOURCE/source-001.csv")!;
  assert.match(derivative.data.toString("utf8"), /"'=SUM\(1,2\)"/);
  const report = JSON.parse(entries.find((entry) => entry.name === "DLP-REPORT.json")!.data.toString("utf8"));
  assert.equal(report.finding_counts.by_type["spreadsheet-formula"], 1);
  const manifest = JSON.parse(entries.find((entry) => entry.name === "SAFE-MANIFEST.json")!.data.toString("utf8"));
  assert.equal(manifest.sources[0].source_format, "csv");
});

test("TSV scanning is cell-bounded and handles quoted embedded newlines", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-tsv-"));
  const source = writeTabularSource(directory, 'left\tright\n"first line\nsecond line"\t@command\n', "input.tsv");
  const detection = dictionary([]);
  const findings = detectSource(source, detection);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.type, "spreadsheet-formula");
  assert.equal(findings[0]?.value, "@");
});

test("tabular structural resource ceilings fail closed", () => {
  assert.throws(() => parseTabularText(`${"x\n".repeat(100_000)}x`, "csv"), /row policy/);
  assert.throws(() => parseTabularText(new Array(1_001).fill("x").join(","), "csv"), /column policy/);
  assert.throws(() => parseTabularText("x".repeat(1_000_001), "csv"), /cell exceeds/);
});

test("formula-looking cells cannot be kept, deleted or generalized with another rule", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-csv-formula-policy-"));
  const source = writeTabularSource(directory, "value\n+COMMAND\n", "input.csv");
  const detection = dictionary([]);
  const findings = detectSource(source, detection);
  const finding = findings[0]!;
  const registry = ProjectTokenRegistry.create(detection.dictionary.projectId, detection.dictionary);
  for (const decision of [
    { findingId: finding.findingId, action: "keep" as const, reasonCode: "LOW_SENSITIVITY_ACCEPTED" as const },
    { findingId: finding.findingId, action: "delete" as const },
    { findingId: finding.findingId, action: "generalize" as const, generalizationRuleId: "CONTACT_REDACTED" },
  ]) {
    assert.throws(() => transformText(source.text, findings, [decision], { dictionary: detection.dictionary, tokenRegistry: registry }), /formula prefixes/);
  }
  assert.throws(() => transformText(source.text, [], [], { dictionary: detection.dictionary, tokenRegistry: registry }), /Untrusted or mismatched findings/);
});

test("tabular intake fails closed on malformed structure, inconsistent rows, binary and invalid encoding", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-tabular-negative-"));
  const cases: Array<[string, string | Buffer, RegExp]> = [
    ["quote.csv", 'a,b\n"unterminated,b\n', /unterminated/],
    ["columns.csv", "a,b\n1\n", /inconsistent/],
    ["junk.csv", 'a,b\n"x"junk,y\n', /closing quote/],
    ["binary.csv", Buffer.from([0x61, 0x2c, 0x62, 0x0a, 0x00]), /Binary/],
    ["encoding.tsv", Buffer.from([0xc3, 0x28]), /encoding/],
  ];
  for (const [name, content, expected] of cases) {
    const path = join(directory, name);
    writeFileSync(path, content);
    assert.throws(() => intakeTabular(path), expected);
  }
  const masquerade = join(directory, "not-tabular.txt");
  writeFileSync(masquerade, "a,b\n1,2\n");
  assert.throws(() => intakeTabular(masquerade), /Unsupported tabular extension/);
});

test("CSV source mutation after verification blocks packaging and leaves no artifacts", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-csv-tamper-"));
  const source = writeTabularSource(directory, "name,value\nSynthetic,public\n", "input.csv");
  const detection = dictionary([]);
  const registry = ProjectTokenRegistry.create(detection.dictionary.projectId, detection.dictionary);
  const findings = detectSource(source, detection);
  const transformation = transformText(source.text, findings, [], { dictionary: detection.dictionary, tokenRegistry: registry });
  const outcome = verifyForExport(verificationRequest(source, transformation, detection));
  assert.equal(outcome.status, "verified");
  if (outcome.status !== "verified") return;
  writeFileSync(join(directory, "input.csv"), "name,value\nSynthetic,changed\n");
  const output = join(directory, "tampered-SAFE-PACKAGE.zip");
  assert.throws(() => createSafePackage(outcome.capability, output), /Source integrity changed/);
});
