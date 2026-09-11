import assert from "node:assert/strict";
import { copyFileSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { intakeTabular } from "../../src/core/intake.js";
import { createSafePackage } from "../../src/core/safe-package.js";
import { detectSource } from "../../src/core/source-scan.js";
import { ProjectTokenRegistry } from "../../src/core/token-vault.js";
import { transformText } from "../../src/core/transform.js";
import { verifyForExport } from "../../src/core/verification.js";
import { dictionary, verificationRequest } from "../helpers.js";

const data = join(process.cwd(), "tests/fixtures/data");

test("tabular positive fixture detects sensitive and formula cells and verifies their controlled transformations", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-tabular-positive-fixture-"));
  const path = join(directory, "positive.csv");
  copyFileSync(join(data, "tabular-positive.csv"), path);
  const source = intakeTabular(path);
  const detection = dictionary([]);
  const findings = detectSource(source, detection);
  const registry = ProjectTokenRegistry.create(detection.dictionary.projectId, detection.dictionary);
  const transformation = transformText(source.text, findings, findings.map((finding) => finding.type === "spreadsheet-formula"
    ? { findingId: finding.findingId, action: "generalize" as const, generalizationRuleId: "FORMULA_AS_LITERAL" }
    : { findingId: finding.findingId, action: "delete" as const }), { dictionary: detection.dictionary, tokenRegistry: registry });
  assert.equal(verifyForExport(verificationRequest(source, transformation, detection)).status, "verified");
});

test("tabular negative fixture remains finding-free without claiming perfect safety", () => {
  const source = intakeTabular(join(data, "tabular-negative.tsv"));
  assert.deepEqual(detectSource(source, dictionary([])), []);
});

test("tabular malformed and post-verification tamper fixtures fail closed", () => {
  assert.throws(() => intakeTabular(join(data, "tabular-malformed.csv")), /unterminated/);
  const directory = mkdtempSync(join(tmpdir(), "ew-tabular-tamper-fixture-"));
  const path = join(directory, "source.tsv");
  copyFileSync(join(data, "tabular-negative.tsv"), path);
  const source = intakeTabular(path);
  const detection = dictionary([]);
  const registry = ProjectTokenRegistry.create(detection.dictionary.projectId, detection.dictionary);
  const findings = detectSource(source, detection);
  const transformation = transformText(source.text, findings, [], { dictionary: detection.dictionary, tokenRegistry: registry });
  const outcome = verifyForExport(verificationRequest(source, transformation, detection));
  assert.equal(outcome.status, "verified");
  if (outcome.status !== "verified") return;
  writeFileSync(path, `${readFileSync(path, "utf8")}changed\n`);
  assert.throws(() => createSafePackage(outcome.capability, join(directory, "fixture-SAFE-PACKAGE.zip")), /Source integrity changed/);
});
