import assert from "node:assert/strict";
import test from "node:test";
import { ProjectTokenRegistry, decryptTokenMap, encryptTokenMap } from "../../src/core/token-vault.js";

test("tamper fixture matrix rejects authenticated-map ciphertext and KDF header changes", () => {
  const registry = ProjectTokenRegistry.create({ latinCaseSensitive: false });
  registry.tokenFor("Synthetic Customer", "exact-data", "CUSTOMER");
  const encrypted = encryptTokenMap(registry, "correct horse battery staple");
  const ciphertextTamper = JSON.parse(encrypted.toString("utf8"));
  ciphertextTamper.ciphertext = `${ciphertextTamper.ciphertext.slice(0, -4)}AAAA`;
  assert.throws(() => decryptTokenMap(Buffer.from(JSON.stringify(ciphertextTamper)), "correct horse battery staple"));
  const headerTamper = JSON.parse(encrypted.toString("utf8"));
  headerTamper.scrypt.N = 2;
  assert.throws(() => decryptTokenMap(Buffer.from(JSON.stringify(headerTamper)), "correct horse battery staple"), /unsafe encrypted envelope/);
});
