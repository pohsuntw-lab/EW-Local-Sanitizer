import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { intakeOffice } from "../../src/core/intake.js";
import { createSafePackage } from "../../src/core/safe-package.js";
import { detectSource } from "../../src/core/source-scan.js";
import { verifyForExport } from "../../src/core/verification.js";
import { dictionary, transformAll, verificationRequest } from "../helpers.js";
import { docxFixture, pptxFixture, xlsxFixture } from "../office-fixtures.js";

function source(directory: string, name: string, bytes: Buffer) {
  const path = join(directory, name);
  writeFileSync(path, bytes);
  return { path, value: intakeOffice(path, name.endsWith(".xlsx") ? { approveAllVisibleWorksheets: true } : {}) };
}

test("Office positive fixture matrix extracts and detects all three supported OOXML formats", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-office-positive-fixture-"));
  for (const [name, bytes] of [["positive.docx", docxFixture()], ["positive.xlsx", xlsxFixture()], ["positive.pptx", pptxFixture()]] as const) {
    const office = source(directory, name, bytes).value;
    const findings = detectSource(office, dictionary(["Example Foundry"]));
    assert.ok(findings.length > 0, `${name} should contain synthetic findings`);
    assert.ok(findings.some((finding) => finding.type.startsWith("office-") || finding.type === "email"));
  }
});

test("Office negative fixture matrix rejects extension/content mismatch and unsupported macro content", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-office-negative-fixture-"));
  assert.throws(() => source(directory, "mismatch.docx", xlsxFixture()), /content type/);
  assert.throws(() => source(directory, "macro.docx", docxFixture({ "word/vbaProject.bin": Buffer.from("synthetic") })), /Macro-enabled/);
});

test("Office tamper fixture blocks packaging after the original source changes", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-office-tamper-fixture-"));
  const office = source(directory, "tamper.docx", docxFixture());
  const detection = dictionary(["Example Foundry"]);
  const { transformation } = transformAll(office.value, detection);
  const outcome = verifyForExport(verificationRequest(office.value, transformation, detection));
  assert.equal(outcome.status, "verified");
  if (outcome.status !== "verified") return;
  writeFileSync(office.path, pptxFixture());
  assert.throws(() => createSafePackage(outcome.capability, join(directory, "tamper-SAFE-PACKAGE.zip")), /Source integrity changed/);
});
