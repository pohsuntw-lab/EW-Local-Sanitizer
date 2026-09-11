import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { assertSessionFileCount, assertSessionTotalBytes, intakePlainText, sourceHashStillMatches } from "../../src/core/intake.js";
import { MAX_PLAIN_TEXT_BYTES, MAX_SESSION_TOTAL_BYTES } from "../../src/core/policy.js";

test("opens source read-only and preserves mode and SHA-256", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-intake-"));
  const path = join(directory, "synthetic.md");
  writeFileSync(path, "Synthetic public note.\n", { mode: 0o640 });
  chmodSync(path, 0o640);
  const before = readFileSync(path);
  const modeBefore = statSync(path).mode & 0o777;
  const source = intakePlainText(path);
  assert.equal(source.originalHash, createHash("sha256").update(before).digest("hex"));
  assert.equal(sourceHashStillMatches(source), true);
  assert.deepEqual(readFileSync(path), before);
  assert.equal(statSync(path).mode & 0o777, modeBefore);
});

test("fails closed on source mutation after intake", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-intake-change-"));
  const path = join(directory, "synthetic.txt");
  writeFileSync(path, "before");
  const source = intakePlainText(path);
  writeFileSync(path, "after");
  assert.equal(sourceHashStillMatches(source), false);
});

test("rejects invalid encoding, binary masquerade, known binary and oversize input", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-intake-reject-"));
  const invalid = join(directory, "invalid.txt");
  writeFileSync(invalid, Buffer.from([0xc3, 0x28]));
  assert.throws(() => intakePlainText(invalid), /encoding/);
  const binary = join(directory, "binary.md");
  writeFileSync(binary, Buffer.from([0x61, 0x00, 0x62, 0x00]));
  assert.throws(() => intakePlainText(binary), /Binary/);
  const sparseControl = join(directory, "sparse-control.txt");
  writeFileSync(sparseControl, `A long otherwise textual prefix ${"a".repeat(256)}\u0001 suffix`);
  assert.throws(() => intakePlainText(sparseControl), /Binary/);
  const c1Control = join(directory, "c1-control.md");
  writeFileSync(c1Control, `Synthetic text ${String.fromCodePoint(0x85)} with a C1 control`);
  assert.throws(() => intakePlainText(c1Control), /Binary/);
  const zip = join(directory, "archive.txt");
  writeFileSync(zip, Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x00]));
  assert.throws(() => intakePlainText(zip), /binary format/);
  const oversized = join(directory, "large.txt");
  writeFileSync(oversized, Buffer.alloc(MAX_PLAIN_TEXT_BYTES + 1, 0x61));
  assert.throws(() => intakePlainText(oversized), /10 MiB/);
});

test("supports explicit UTF encodings and enforces session/extension policy", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-intake-encoding-"));
  const utf16 = join(directory, "utf16.txt");
  writeFileSync(utf16, Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from("hello", "utf16le")]));
  assert.equal(intakePlainText(utf16).encoding, "utf-16le");
  const unsupported = join(directory, "synthetic.csv");
  writeFileSync(unsupported, "plain text");
  assert.throws(() => intakePlainText(unsupported), /Unsupported/);
  assert.doesNotThrow(() => assertSessionFileCount(100));
  assert.throws(() => assertSessionFileCount(101), /100/);
  assert.doesNotThrow(() => assertSessionTotalBytes([MAX_SESSION_TOTAL_BYTES]));
  assert.throws(() => assertSessionTotalBytes([MAX_SESSION_TOTAL_BYTES, 1]), /aggregate/);
});
