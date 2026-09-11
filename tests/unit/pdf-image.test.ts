import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { intakeImage, intakePdf, releaseSourceResources } from "../../src/core/intake.js";
import { createSafePackage } from "../../src/core/safe-package.js";
import { detectSource } from "../../src/core/source-scan.js";
import { inspectStoreZip } from "../../src/core/zip.js";
import { dictionary, transformAll, verificationRequest } from "../helpers.js";
import { verifyForExport } from "../../src/core/verification.js";

test("PDF extracts a text layer and fails closed on image-only page coverage", async () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-pdf-"));
  const textPath = join(directory, "text.pdf");
  writeFileSync(textPath, pdfFixture("contact@example.com", false));
  const textSource = await intakePdf(textPath);
  assert.equal(textSource.coverage, "complete");
  assert.match(textSource.text, /contact@example\.com/);
  assert.ok(detectSource(textSource, dictionary()).some((finding) => finding.type === "email"));

  const imagePath = join(directory, "image.pdf");
  writeFileSync(imagePath, pdfFixture("", true));
  const imageSource = await intakePdf(imagePath);
  assert.equal(imageSource.coverage, "incomplete");
  assert.ok(detectSource(imageSource, dictionary()).some((finding) => finding.type === "pdf-image-content"));

  const activePath = join(directory, "active.pdf");
  writeFileSync(activePath, pdfFixture("public text", false, true));
  const activeSource = await intakePdf(activePath);
  assert.ok(detectSource(activeSource, dictionary()).some((finding) => finding.type === "pdf-active-content"));
});

test("local WASM OCR redacts pixels, strips PNG metadata and re-scans the derivative", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (() => { throw new Error("network denied"); }) as typeof fetch;
  const directory = mkdtempSync(join(tmpdir(), "ew-image-"));
  const sourcePath = join(directory, "synthetic.png");
  const fixture = Buffer.from(readFileSync(join(process.cwd(), "tests/fixtures/data/ocr-positive.png.base64"), "utf8").trim(), "base64");
  writeFileSync(sourcePath, withTextChunk(fixture, "Synthetic fixture only"));
  let source: Awaited<ReturnType<typeof intakeImage>> | undefined;
  try {
    source = await intakeImage(sourcePath, "eng");
    const recognized = source.text.trim();
    assert.ok(recognized.length >= 2, "synthetic digit image must produce local OCR text");
    const detection = dictionary([recognized]);
    assert.throws(() => transformAll(source!, detection, "tokenize"), /deleted|pixel deletion/);
    const { transformation } = transformAll(source, detection, "delete");
    assert.equal(transformation.scanProfile, "image");
    const outcome = verifyForExport(verificationRequest(source, transformation, detection));
    assert.equal(outcome.status, "verified");
    if (outcome.status !== "verified") return;
    const outputPath = join(directory, "OCR-SAFE-PACKAGE.zip");
    createSafePackage(outcome.capability, outputPath);
    const entries = inspectStoreZip(readFileSync(outputPath), new Set(["SAFE_SOURCE/source-001.png", "SAFE-MANIFEST.json", "DLP-REPORT.json", "README-SAFE-UPLOAD.md"]));
    const png = entries.find((entry) => entry.name === "SAFE_SOURCE/source-001.png")!.data;
    assert.ok(!png.includes(Buffer.from("tEXt")) && !png.includes(Buffer.from("eXIf")));
  } finally {
    if (source) releaseSourceResources(source);
    globalThis.fetch = originalFetch;
  }
});

test("image extension/signature mismatch fails closed", async () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-image-negative-"));
  const path = join(directory, "fake.png");
  writeFileSync(path, Buffer.from([0xff, 0xd8, 0xff, 0xd9]));
  await assert.rejects(intakeImage(path), /PNG signature mismatch/);
});

function withTextChunk(png: Buffer, text: string): Buffer {
  const iend = png.length - 12;
  const typeAndData = Buffer.concat([Buffer.from("tEXt"), Buffer.from(`Comment\0${text}`)]);
  const chunk = Buffer.alloc(12 + typeAndData.length - 4);
  chunk.writeUInt32BE(typeAndData.length - 4, 0); typeAndData.copy(chunk, 4);
  chunk.writeUInt32BE(crc32(typeAndData), chunk.length - 4);
  return Buffer.concat([png.subarray(0, iend), chunk, png.subarray(iend)]);
}

function crc32(bytes: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of bytes) { crc ^= byte; for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0); }
  return (crc ^ 0xffffffff) >>> 0;
}

function pdfFixture(text: string, imageOnly: boolean, active = false): Buffer {
  const escaped = text.replaceAll("\\", "\\\\").replaceAll("(", "\\(").replaceAll(")", "\\)");
  const content = imageOnly ? "q 100 0 0 100 72 600 cm /Im0 Do Q" : `BT /F1 18 Tf 72 720 Td (${escaped}) Tj ET`;
  const resources = imageOnly ? "<< /XObject << /Im0 5 0 R >> >>" : "<< /Font << /F1 5 0 R >> >>";
  const fifth = imageOnly ? "<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Length 3 >>\nstream\nÿÿÿ\nendstream" : "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";
  const objects = ["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources ${resources} /Contents 4 0 R${active ? " /Annots [6 0 R]" : ""} >>`,
    `<< /Length ${Buffer.byteLength(content, "latin1")} >>\nstream\n${content}\nendstream`, fifth];
  if (active) objects.push("<< /Type /Annot /Subtype /Text /Rect [10 10 20 20] /Contents (synthetic note) >>");
  let output = "%PDF-1.4\n%âãÏÓ\n"; const offsets = [0];
  for (let index = 0; index < objects.length; index += 1) { offsets.push(Buffer.byteLength(output, "latin1")); output += `${index + 1} 0 obj\n${objects[index]}\nendobj\n`; }
  const xref = Buffer.byteLength(output, "latin1"); output += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const offset of offsets.slice(1)) output += `${String(offset).padStart(10, "0")} 00000 n \n`;
  output += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(output, "latin1");
}
