import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { intakeOffice } from "../../src/core/intake.js";
import { openOoxmlPackage } from "../../src/core/ooxml-package.js";
import { createSafePackage } from "../../src/core/safe-package.js";
import { detectSource } from "../../src/core/source-scan.js";
import { detectText } from "../../src/core/detectors.js";
import { ProjectTokenRegistry } from "../../src/core/token-vault.js";
import { transformText } from "../../src/core/transform.js";
import { inspectStoreZip } from "../../src/core/zip.js";
import { verifyForExport } from "../../src/core/verification.js";
import { dictionary, transformAll, verificationRequest } from "../helpers.js";
import { contentTypes, docxFixture, officeZip, pptxFixture, xlsxFixture } from "../office-fixtures.js";

function writeOffice(directory: string, name: string, bytes: Buffer) {
  const path = join(directory, name);
  writeFileSync(path, bytes);
  return intakeOffice(path, name.endsWith(".xlsx") ? { approveAllVisibleWorksheets: true } : {});
}

test("DOCX extracts body, table, header/footer and removes comments, revisions, external links and metadata", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-docx-"));
  const source = writeOffice(directory, "synthetic.docx", docxFixture());
  assert.equal(source.coverage, "complete");
  const detection = dictionary(["Example Foundry"]);
  const findings = detectSource(source, detection);
  const types = new Set(findings.map((finding) => finding.type));
  for (const type of ["email", "phone", "exact-data", "office-hidden-content", "office-external-link", "office-metadata"]) assert.ok(types.has(type as never));
  const { transformation } = transformAll(source, detection);
  const outcome = verifyForExport(verificationRequest(source, transformation, detection));
  assert.equal(outcome.status, "verified");
  if (outcome.status !== "verified") return;
  const output = join(directory, "docx-SAFE-PACKAGE.zip");
  createSafePackage(outcome.capability, output);
  const archive = readFileSync(output);
  const entries = inspectStoreZip(archive, new Set(["SAFE_SOURCE/source-001.md", "SAFE-MANIFEST.json", "DLP-REPORT.json", "README-SAFE-UPLOAD.md"]));
  const derivative = entries[0]!.data.toString("utf8");
  assert.match(derivative, /DOCX derivative|Controlled footer/);
  assert.doesNotMatch(derivative, /visible\.person|comment\.person|deleted\.person|0912/);
  assert.equal(archive.includes(Buffer.from("comment.person@example.com")), false);
  assert.equal(archive.includes(Buffer.from("deleted.person@example.com")), false);
});

test("XLSX inspects visible/hidden cells, formulas, comments and exports index plus CSV per visible sheet", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-xlsx-"));
  const source = writeOffice(directory, "synthetic.xlsx", xlsxFixture());
  const detection = dictionary([]);
  const findings = detectSource(source, detection);
  const types = new Set(findings.map((finding) => finding.type));
  for (const type of ["email", "office-formula", "office-hidden-content", "office-external-link", "office-metadata"]) assert.ok(types.has(type as never));
  const { transformation } = transformAll(source, detection);
  const outcome = verifyForExport(verificationRequest(source, transformation, detection));
  assert.equal(outcome.status, "verified");
  if (outcome.status !== "verified") return;
  const output = join(directory, "xlsx-SAFE-PACKAGE.zip");
  createSafePackage(outcome.capability, output);
  const allowlist = new Set([
    "SAFE_SOURCE/source-001-index.md", "SAFE_SOURCE/source-001-sheet-001.csv",
    "SAFE-MANIFEST.json", "DLP-REPORT.json", "README-SAFE-UPLOAD.md",
  ]);
  const archive = readFileSync(output);
  const entries = inspectStoreZip(archive, allowlist);
  const csv = entries.find((entry) => entry.name.endsWith("sheet-001.csv"))!.data.toString("utf8");
  assert.doesNotMatch(csv, /sheet\.person|hidden\.|SUM/);
  assert.equal(archive.includes(Buffer.from("hidden.sheet@example.com")), false);
  assert.equal(archive.includes(Buffer.from("comment.sheet@example.com")), false);
  const manifest = JSON.parse(entries.find((entry) => entry.name === "SAFE-MANIFEST.json")!.data.toString("utf8"));
  assert.equal(manifest.sources[0].source_format, "xlsx");
  assert.equal(manifest.sources[0].derivatives.length, 2);
});

test("PPTX extracts visible slide text and removes hidden slides, notes, comments, links and metadata", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-pptx-"));
  const source = writeOffice(directory, "synthetic.pptx", pptxFixture());
  const detection = dictionary([]);
  const { findings, transformation } = transformAll(source, detection);
  assert.ok(findings.some((finding) => finding.type === "office-hidden-content"));
  const outcome = verifyForExport(verificationRequest(source, transformation, detection));
  assert.equal(outcome.status, "verified");
  if (outcome.status !== "verified") return;
  const output = join(directory, "pptx-SAFE-PACKAGE.zip");
  createSafePackage(outcome.capability, output);
  const archive = readFileSync(output);
  const entries = inspectStoreZip(archive, new Set(["SAFE_SOURCE/source-001.md", "SAFE-MANIFEST.json", "DLP-REPORT.json", "README-SAFE-UPLOAD.md"]));
  const derivative = entries[0]!.data.toString("utf8");
  assert.match(derivative, /Slide body/);
  assert.doesNotMatch(derivative, /hidden\.slide|speaker\.notes|comment\.slide|slide\.person/);
  assert.equal(archive.includes(Buffer.from("speaker.notes@example.com")), false);
});

test("Office intake fails closed on wrong content type, macros, DTDs and unsafe ZIP paths", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-office-negative-"));
  assert.throws(() => writeOffice(directory, "wrong.docx", xlsxFixture()), /content type/);
  assert.throws(() => writeOffice(directory, "macro.docx", docxFixture({
    "word/vbaProject.bin": Buffer.from("synthetic macro placeholder"),
  })), /Macro-enabled/);
  const dtd = officeZip({
    "[Content_Types].xml": `<?xml version="1.0"?><!DOCTYPE Types [<!ENTITY x "synthetic">]><Types xmlns="urn:types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`,
    "word/document.xml": `<?xml version="1.0"?><w:document xmlns:w="urn:w"><w:body/></w:document>`,
  });
  assert.throws(() => writeOffice(directory, "dtd.docx", dtd), /DTD/);
  assert.throws(() => openOoxmlPackage(officeZip({ "../unsafe.xml": "synthetic" })), /unsafe entry path/);
});

test("OOXML ZIP gate rejects duplicate names, local-header mismatch, encryption flags and expanded-size overflow", () => {
  const baseline = officeZip({ "safe-a.xml": "alpha", "safe-b.xml": "bravo" });
  const duplicate = Buffer.from(baseline);
  replaceAllAscii(duplicate, "safe-b.xml", "safe-a.xml");
  assert.throws(() => openOoxmlPackage(duplicate), /duplicate entry names/);

  const localMismatch = Buffer.from(baseline);
  const firstLocalName = localMismatch.indexOf("safe-a.xml", 0, "ascii");
  assert.ok(firstLocalName >= 0);
  localMismatch.write("safe-x.xml", firstLocalName, "ascii");
  assert.throws(() => openOoxmlPackage(localMismatch), /local and central entry names differ/);

  const encrypted = Buffer.from(baseline);
  const central = encrypted.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  assert.ok(central >= 0);
  encrypted.writeUInt16LE(encrypted.readUInt16LE(central + 8) | 1, central + 8);
  assert.throws(() => openOoxmlPackage(encrypted), /Encrypted/);

  const oversized = Buffer.from(baseline);
  const oversizedCentral = oversized.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  oversized.writeUInt32LE(16 * 1024 * 1024 + 1, oversizedCentral + 24);
  assert.throws(() => openOoxmlPackage(oversized), /expanded size policy/);
});

test("unsupported embedded media marks Office coverage incomplete and blocks export", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-office-coverage-"));
  const source = writeOffice(directory, "media.docx", docxFixture({ "word/media/image1.png": Buffer.from([1, 2, 3]) }));
  assert.equal(source.coverage, "incomplete");
  const detection = dictionary([]);
  const { transformation } = transformAll(source, detection);
  const outcome = verifyForExport(verificationRequest(source, transformation, detection, undefined, false));
  assert.equal(outcome.status, "blocked");
  if (outcome.status === "blocked") assert.ok(outcome.unresolved.some((item) => item.code === "COVERAGE_NOT_COMPLETE"));
});

test("XLSX export remains blocked until all visible worksheets are explicitly approved", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-xlsx-approval-"));
  const path = join(directory, "approval.xlsx");
  writeFileSync(path, xlsxFixture());
  const source = intakeOffice(path);
  assert.equal(source.coverage, "incomplete");
  const detection = dictionary([]);
  const { transformation } = transformAll(source, detection);
  const outcome = verifyForExport(verificationRequest(source, transformation, detection, undefined, false));
  assert.equal(outcome.status, "blocked");
  if (outcome.status === "blocked") assert.ok(outcome.unresolved.some((item) => item.code === "COVERAGE_NOT_COMPLETE"));
});

test("Office transform rejects a generic text finding set with the wrong scan profile", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-office-profile-"));
  const source = writeOffice(directory, "profile.docx", docxFixture());
  const detection = dictionary([]);
  const generic = detectText(source.text, detection);
  const registry = ProjectTokenRegistry.create(detection.dictionary.projectId, detection.dictionary);
  const transformation = transformText(source.text, generic, generic.map((finding) => ({ findingId: finding.findingId, action: "delete" as const })), {
    dictionary: detection.dictionary, tokenRegistry: registry,
  });
  const outcome = verifyForExport(verificationRequest(source, transformation, detection, undefined, false));
  assert.equal(outcome.status, "blocked");
  if (outcome.status === "blocked") assert.ok(outcome.unresolved.some((item) => item.code === "TRANSFORMATION_FAILED"));
});

test("Office core workflow completes with network entry points denied", () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (() => { throw new Error("network denied"); }) as typeof fetch;
  try {
    const directory = mkdtempSync(join(tmpdir(), "ew-office-offline-"));
    const source = writeOffice(directory, "offline.docx", docxFixture());
    const detection = dictionary(["Example Foundry"]);
    const { transformation } = transformAll(source, detection);
    const outcome = verifyForExport(verificationRequest(source, transformation, detection));
    assert.equal(outcome.status, "verified");
    if (outcome.status === "verified") createSafePackage(outcome.capability, join(directory, "offline-SAFE-PACKAGE.zip"));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("verification scans every generated XLSX index and worksheet derivative with the same dictionary", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-xlsx-second-scan-"));
  const source = writeOffice(directory, "second-scan.xlsx", xlsxFixture());
  const detection = dictionary(["Workbook index"]);
  const { transformation } = transformAll(source, detection);
  const outcome = verifyForExport(verificationRequest(source, transformation, detection, undefined, false));
  assert.equal(outcome.status, "blocked");
  if (outcome.status === "blocked") assert.ok(outcome.unresolved.some((item) => item.code === "SECOND_SCAN_BLOCKING_FINDING"));
});

function replaceAllAscii(buffer: Buffer, from: string, to: string): void {
  assert.equal(Buffer.byteLength(from), Buffer.byteLength(to));
  let offset = 0;
  while ((offset = buffer.indexOf(from, offset, "ascii")) !== -1) {
    buffer.write(to, offset, "ascii");
    offset += to.length;
  }
}
