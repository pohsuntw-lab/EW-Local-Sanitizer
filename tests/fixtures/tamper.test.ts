import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { ProjectTokenRegistry, decryptTokenMap, encryptTokenMap } from "../../src/core/token-vault.js";
import { inspectStoreZip, writeStoreZip } from "../../src/core/zip.js";

test("tamper fixture matrix rejects authenticated-map ciphertext and KDF header changes", () => {
  const registry = ProjectTokenRegistry.create("00000000-0000-4000-8000-000000000001", { latinCaseSensitive: false });
  registry.tokenFor("Synthetic Customer", "exact-data", "CUSTOMER");
  const encrypted = encryptTokenMap(registry, "correct horse battery staple").payload;
  const ciphertextTamper = JSON.parse(encrypted.toString("utf8"));
  ciphertextTamper.ciphertext = `${ciphertextTamper.ciphertext.slice(0, -4)}AAAA`;
  assert.throws(() => decryptTokenMap(Buffer.from(JSON.stringify(ciphertextTamper)), "correct horse battery staple"));
  const headerTamper = JSON.parse(encrypted.toString("utf8"));
  headerTamper.scrypt.N = 2;
  assert.throws(() => decryptTokenMap(Buffer.from(JSON.stringify(headerTamper)), "correct horse battery staple"), /unsafe encrypted envelope/);
  const authenticatedHeaderTamper = JSON.parse(encrypted.toString("utf8"));
  authenticatedHeaderTamper.salt = Buffer.alloc(16, 7).toString("base64");
  assert.throws(() => decryptTokenMap(Buffer.from(JSON.stringify(authenticatedHeaderTamper)), "correct horse battery staple"));
});

test("tamper fixture matrix rejects every single-byte ZIP mutation and truncation", () => {
  const directory = mkdtempSync(join(tmpdir(), "ew-zip-mutation-"));
  const path = join(directory, "baseline.zip");
  const allowlist = new Set(["SAFE-MANIFEST.json"]);
  writeStoreZip(path, [{ name: "SAFE-MANIFEST.json", data: Buffer.from("synthetic-safe-data") }]);
  const baseline = readFileSync(path);
  assert.doesNotThrow(() => inspectStoreZip(baseline, allowlist));
  for (let index = 0; index < baseline.length; index += 1) {
    const mutated = Buffer.from(baseline);
    mutated[index] = (mutated[index] ?? 0) ^ 0x01;
    assert.throws(() => inspectStoreZip(mutated, allowlist), `mutation at byte ${index} must fail closed`);
  }
  for (let length = 0; length < baseline.length; length += 1) {
    assert.throws(() => inspectStoreZip(baseline.subarray(0, length), allowlist), `truncation at byte ${length} must fail closed`);
  }
});
