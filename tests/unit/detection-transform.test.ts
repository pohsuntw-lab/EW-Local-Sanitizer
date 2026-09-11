import assert from "node:assert/strict";
import test from "node:test";
import { encryptEnvelope } from "../../src/core/crypto-envelope.js";
import { createDictionarySnapshot, decryptProjectDictionary, encryptProjectDictionary, type ProjectDictionary } from "../../src/core/dictionary.js";
import { detectText } from "../../src/core/detectors.js";
import { ProjectTokenRegistry, decryptTokenMap, encryptTokenMap } from "../../src/core/token-vault.js";
import { decryptLocalSession, encryptLocalSession } from "../../src/core/session-vault.js";
import { transformText } from "../../src/core/transform.js";
import type { ReasonCode } from "../../src/core/types.js";
import { dictionary } from "../helpers.js";

test("detects synthetic credentials, checksum-aware PII, commercial IDs and normalized dictionary aliases", () => {
  const projectDictionary: ProjectDictionary = {
    formatVersion: "ewdict-1", dictionaryVersion: "v1", latinCaseSensitive: false,
    entries: [{ canonical: "Example Foundry", aliases: ["Ｅｘａｍｐｌｅ   Plant"] }],
  };
  const context = { dictionary: createDictionarySnapshot(projectDictionary) };
  const text = [
    "Customer example foundry", "Alias Example Plant", "test.person@example.com", "0912-345-678", "A123456789",
    "台北市中正區測試路 123 號", "10.10.2.15", "contract CTR-SYNTH-001", "bank_account=1234 5678 9012", "api_key=sk-abcdefghijklmnopqrstuvwxyz123456",
  ].join("\n");
  const findings = detectText(text, context);
  const types = new Set(findings.map((finding) => finding.type));
  for (const type of ["exact-data", "email", "phone", "taiwan-id", "address", "ip-address", "contract-id", "bank-account", "credential"]) assert.ok(types.has(type as never), `missing ${type}`);
  assert.equal(findings.every((finding) => /^[0-9a-f-]{36}$/i.test(finding.findingId)), true);
  assert.notEqual(detectText(text, context)[0]?.findingId, findings[0]?.findingId);
});

test("NFKC grapheme normalization matches combining aliases and critical findings win overlaps", () => {
  const context = dictionary(["Café Project", "prefix password=synthetic-password-123"]);
  const text = "Cafe\u0301   Project\nprefix password=synthetic-password-123";
  const findings = detectText(text, context);
  assert.ok(findings.some((finding) => finding.type === "exact-data" && finding.value.includes("Cafe")));
  assert.ok(findings.some((finding) => finding.type === "credential" && finding.severity === "critical"));
  assert.equal(findings.filter((finding) => finding.value.includes("password")).some((finding) => finding.type === "exact-data"), false);
});

test("classifies synthetic private keys, standalone tokens, passwords and connection strings as critical", () => {
  const context = dictionary([]);
  const text = [
    "-----BEGIN PRIVATE KEY-----\nU1lOVEhFVElDLU5PVC1BLVktFWQ==\n-----END PRIVATE KEY-----",
    "sk-SYNTHETICOPENAITOKEN1234567890",
    "ghp_SYNTHETICGITHUBTOKEN1234567890",
    "password=synthetic-password-123",
    "Server=synthetic-db;Password=synthetic-connection-secret;",
  ].join("\n");
  const findings = detectText(text, context);
  assert.ok(findings.some((finding) => finding.type === "private-key"));
  assert.ok(findings.filter((finding) => finding.type === "api-token").length >= 2);
  assert.ok(findings.filter((finding) => finding.type === "credential").length >= 2);
  assert.equal(findings.every((finding) => finding.severity === "critical"), true);
});

test("encrypts dictionary and token registry with versioned authenticated headers", () => {
  const projectDictionary: ProjectDictionary = {
    formatVersion: "ewdict-1", dictionaryVersion: "v1", latinCaseSensitive: false,
    entries: [{ canonical: "Synthetic Customer", aliases: ["Synthetic Alias"] }],
  };
  const encryptedDictionary = encryptProjectDictionary(projectDictionary, "correct horse battery staple");
  assert.equal(encryptedDictionary.includes(Buffer.from("Synthetic Customer")), false);
  assert.deepEqual(decryptProjectDictionary(encryptedDictionary, "correct horse battery staple"), projectDictionary);
  assert.throws(() => decryptProjectDictionary(encryptedDictionary, "wrong passphrase value"));

  const registry = ProjectTokenRegistry.create("00000000-0000-4000-8000-000000000001", { latinCaseSensitive: false });
  const first = registry.tokenFor(" Example   Foundry ", "exact-data", "CUSTOMER");
  const second = registry.tokenFor("example foundry", "exact-data", "CUSTOMER");
  assert.equal(first.token, second.token);
  const encryptedMap = encryptTokenMap(registry, "correct horse battery staple");
  const header = JSON.parse(encryptedMap.toString("utf8"));
  assert.deepEqual(Object.keys(header).sort(), ["authentication_tag", "cipher", "ciphertext", "content_type", "format_version", "iv", "kdf", "salt", "scrypt"]);
  assert.deepEqual(header.scrypt, { N: 16384, r: 8, p: 1, key_length: 32, maxmem: 67108864 });
  assert.equal(encryptedMap.includes(Buffer.from("Example")), false);
  const restored = decryptTokenMap(encryptedMap, "correct horse battery staple");
  assert.equal(restored.projectId(), "00000000-0000-4000-8000-000000000001");
  assert.equal(restored.entries()[0]?.token, first.token);
  assert.throws(() => decryptTokenMap(encryptedMap, "wrong passphrase value"));
  const tampered = JSON.parse(encryptedMap.toString("utf8"));
  tampered.ciphertext = `${tampered.ciphertext.slice(0, -4)}AAAA`;
  assert.throws(() => decryptTokenMap(Buffer.from(JSON.stringify(tampered)), "correct horse battery staple"));
  const malformedRegistry = encryptEnvelope("ewmap", {
    schema: "ewmap-registry-2",
    project_id: "00000000-0000-4000-8000-000000000001",
    project_scope_secret: Buffer.alloc(32, 7).toString("base64"),
    latin_case_sensitive: false,
    entries: [{ token: "【CUSTOMER-AAAAAAAAAAAAAAAAAAAA】", original: "Synthetic Customer", normalizedOriginal: "synthetic customer", findingType: "exact-data" }],
  }, "correct horse battery staple");
  assert.throws(() => decryptTokenMap(malformedRegistry, "correct horse battery staple"), /integrity/);
});

test("stable tokens are unlinkable across project scope secrets", () => {
  const one = ProjectTokenRegistry.create("00000000-0000-4000-8000-000000000001", { latinCaseSensitive: false });
  const two = ProjectTokenRegistry.create("00000000-0000-4000-8000-000000000002", { latinCaseSensitive: false });
  assert.notEqual(one.tokenFor("Same Synthetic Value", "exact-data", "ENTITY").token, two.tokenFor("Same Synthetic Value", "exact-data", "ENTITY").token);
  one.dispose();
  assert.throws(() => one.tokenFor("Another Value", "exact-data", "ENTITY"), /disposed/);
});

test("optional local session persistence is authenticated and does not expose review detail in plaintext", () => {
  const session = {
    schema: "ewsession-1" as const,
    projectId: "00000000-0000-4000-8000-000000000001",
    sourceIds: ["00000000-0000-4000-8000-000000000002"],
    decisions: [{ findingId: "00000000-0000-4000-8000-000000000003", action: "keep" as const, reasonCode: "OPERATIONAL_CONTEXT" as const, localReasonDetail: "Synthetic local review detail" }],
    createdAt: "2026-09-11T00:00:00.000Z",
  };
  const encrypted = encryptLocalSession(session, "correct horse battery staple");
  assert.equal(encrypted.includes(Buffer.from("Synthetic local review detail")), false);
  assert.deepEqual(decryptLocalSession(encrypted, "correct horse battery staple"), session);
  assert.throws(() => decryptLocalSession(encrypted, "wrong passphrase value"));
});

test("forces secret deletion and rejects reason, token-label and generalization injection", () => {
  const context = dictionary([]);
  const registry = ProjectTokenRegistry.create("00000000-0000-4000-8000-000000000001", context.dictionary);
  const credentialText = "password=synthetic-password-123";
  const credential = detectText(credentialText, context)[0];
  assert.ok(credential);
  assert.throws(() => transformText(credentialText, [credential], [{ findingId: credential.findingId, action: "keep", reasonCode: "OPERATIONAL_CONTEXT" }], { dictionary: context.dictionary, tokenRegistry: registry }), /must be deleted/);

  const emailText = "test.person@example.com";
  const email = detectText(emailText, context)[0];
  assert.ok(email);
  assert.throws(() => transformText(emailText, [email], [{ findingId: email.findingId, action: "tokenize", tokenLabel: "EMAIL-sk-SYNTHETICSECRET123456789" }], { dictionary: context.dictionary, tokenRegistry: registry }), /approved/);
  assert.throws(() => transformText(emailText, [email], [{ findingId: email.findingId, action: "keep", reasonCode: "test.person@example.com" as ReasonCode }], { dictionary: context.dictionary, tokenRegistry: registry }), /reason code/);
  assert.throws(() => transformText(emailText, [email], [{ findingId: email.findingId, action: "generalize", generalizationRuleId: "test.person@example.com" }], { dictionary: context.dictionary, tokenRegistry: registry }), /approved rule/);
  assert.throws(() => transformText(emailText, [email], [{ findingId: email.findingId, action: "delete", reasonCode: "PUBLICLY_APPROVED" }], { dictionary: context.dictionary, tokenRegistry: registry }), /only valid for keep/);
});
