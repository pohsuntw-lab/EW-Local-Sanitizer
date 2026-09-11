import assert from "node:assert/strict";
import test from "node:test";
import { encryptEnvelope } from "../../src/core/crypto-envelope.js";
import { createDictionarySnapshot, decryptProjectDictionary, encryptProjectDictionary, type ProjectDictionary } from "../../src/core/dictionary.js";
import { detectText } from "../../src/core/detectors.js";
import { ProjectTokenRegistry, decryptTokenMap, encryptTokenMap } from "../../src/core/token-vault.js";
import { decryptLocalSession, encryptLocalSession } from "../../src/core/session-vault.js";
import { transformText } from "../../src/core/transform.js";
import type { Finding, ReasonCode } from "../../src/core/types.js";
import { MAX_FINDINGS_PER_FILE, MAX_SESSION_FINDINGS, assertSessionFindingCount } from "../../src/core/policy.js";
import { dictionary } from "../helpers.js";

test("detects synthetic credentials, checksum-aware PII, commercial IDs and normalized dictionary aliases", () => {
  const projectDictionary: ProjectDictionary = {
    formatVersion: "ewdict-1", projectId: "00000000-0000-4000-8000-000000000001", dictionaryVersion: "v1", latinCaseSensitive: false,
    entries: [{ canonical: "Example Foundry", aliases: ["Ｅｘａｍｐｌｅ   Plant"] }],
  };
  const context = { dictionary: createDictionarySnapshot(projectDictionary) };
  const text = [
    "Customer example foundry", "Alias Example Plant", "test.person@example.com", "0912-345-678", "+886 912 345 678", "886-912-345-678",
    "A123456789", "a123456789",
    "台北市中正區測試路 123 號", "10.10.2.15", "contract CTR-SYNTH-001", "bank_account=1234 5678 9012",
    "\"account_number\": \"9876 5432 1098\"", "api_key=sk-abcdefghijklmnopqrstuvwxyz123456",
  ].join("\n");
  const findings = detectText(text, context);
  const types = new Set(findings.map((finding) => finding.type));
  for (const type of ["exact-data", "email", "phone", "taiwan-id", "address", "ip-address", "contract-id", "bank-account", "credential"]) assert.ok(types.has(type as never), `missing ${type}`);
  assert.ok(findings.filter((finding) => finding.type === "phone").length >= 3);
  assert.ok(findings.filter((finding) => finding.type === "taiwan-id").length >= 2);
  assert.ok(findings.filter((finding) => finding.type === "bank-account").length >= 2);
  assert.equal(detectText('Documentation key "account_number": "<redacted>"', context).some((finding) => finding.type === "bank-account"), false);
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

test("exact-data trie and detector budgets fail closed on abusive input", () => {
  const invalidDictionary: ProjectDictionary = {
    formatVersion: "ewdict-1", projectId: "00000000-0000-4000-8000-000000000001", dictionaryVersion: "v1", latinCaseSensitive: false,
    entries: [{ canonical: "Synthetic Customer", aliases: Array.from({ length: 17 }, (_, index) => `Synthetic Alias ${index}`) }],
  };
  assert.throws(() => createDictionarySnapshot(invalidDictionary), /dictionary entry/);
  const context = dictionary(["aba", "ba"]);
  const overlaps = detectText("aba", context);
  assert.equal(overlaps.length, 1);
  assert.equal(overlaps[0]?.value, "aba");
  assert.throws(() => detectText("SyntheticTerm ".repeat(MAX_FINDINGS_PER_FILE + 1), dictionary(["SyntheticTerm"])), /Finding limit/);
  assert.throws(() => detectText("test.person@example.com\n".repeat(MAX_FINDINGS_PER_FILE + 1), dictionary([])), /Finding limit/);
  assert.doesNotThrow(() => assertSessionFindingCount(MAX_SESSION_FINDINGS));
  assert.throws(() => assertSessionFindingCount(MAX_SESSION_FINDINGS + 1), /50,000/);
});

test("classifies synthetic private keys, standalone tokens, passwords and connection strings as critical", () => {
  const context = dictionary([]);
  const text = [
    "-----BEGIN PRIVATE KEY-----\nU1lOVEhFVElDLU5PVC1BLVktFWQ==\n-----END PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----\nU1lOVEhFVElDLVJTQQ==\n-----END RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----\nU1lOVEhFVElDLUVD\n-----END EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----\nU1lOVEhFVElDLU9QRU5TU0g=\n-----END OPENSSH PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----\nU1lOVEhFVElDLUVORVJZUFRFRA==\n-----END ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----\nU1lOVEhFVElDLURTQQ==\n-----END DSA PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\nU1lOVEhFVElDLVBHUA==\n-----END PGP PRIVATE KEY BLOCK-----",
    "sk-SYNTHETICOPENAITOKEN1234567890",
    "ghp_SYNTHETICGITHUBTOKEN1234567890",
    "github_pat_SYNTHETIC_FINE_GRAINED_TOKEN_1234567890",
    "ghs_12345_SYNTHETICHEADER.SYNTHETICPAYLOAD.SYNTHETICSIGNATURE",
    "password=synthetic-password-123",
    "Server=synthetic-db;Password=synthetic-connection-secret;",
    "\"password\": \"synthetic pass phrase\"",
    "client_secret='synthetic secret phrase'",
  ].join("\n");
  const findings = detectText(text, context);
  assert.ok(findings.filter((finding) => finding.type === "private-key").length >= 7);
  assert.ok(findings.filter((finding) => finding.type === "api-token").length >= 4);
  assert.ok(findings.filter((finding) => finding.type === "credential").length >= 4);
  assert.equal(findings.every((finding) => finding.severity === "critical"), true);
  const mismatchedArmor = "-----BEGIN RSA PRIVATE KEY-----\nU1lOVEhFVElD\n-----END EC PRIVATE KEY-----";
  assert.equal(detectText(mismatchedArmor, context).some((finding) => finding.type === "private-key"), false);
  assert.equal(detectText("Documentation prefixes: github_pat_ and ghs_APPID_JWT", context).some((finding) => finding.type === "api-token"), false);
});

test("encrypts dictionary and token registry with versioned authenticated headers", () => {
  const projectDictionary: ProjectDictionary = {
    formatVersion: "ewdict-1", projectId: "00000000-0000-4000-8000-000000000001", dictionaryVersion: "v1", latinCaseSensitive: false,
    entries: [{ canonical: "Synthetic Customer", aliases: ["Synthetic Alias"] }],
  };
  const encryptedDictionary = encryptProjectDictionary(projectDictionary, "correct horse battery staple");
  assert.equal(encryptedDictionary.includes(Buffer.from("Synthetic Customer")), false);
  assert.deepEqual(decryptProjectDictionary(encryptedDictionary, "correct horse battery staple"), projectDictionary);
  assert.throws(() => decryptProjectDictionary(encryptedDictionary, "wrong passphrase value"));
  const otherProjectDictionary = { ...projectDictionary, projectId: "00000000-0000-4000-8000-000000000002" };
  assert.notEqual(createDictionarySnapshot(projectDictionary).dictionaryHash, createDictionarySnapshot(otherProjectDictionary).dictionaryHash);

  const registry = ProjectTokenRegistry.create("00000000-0000-4000-8000-000000000001", { latinCaseSensitive: false });
  const first = registry.tokenFor(" Example   Foundry ", "exact-data", "CUSTOMER");
  const second = registry.tokenFor("example foundry", "exact-data", "CUSTOMER");
  assert.equal(first.token, second.token);
  const encryptedMap = encryptTokenMap(registry, "correct horse battery staple").payload;
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
  assert.throws(() => encryptLocalSession({ ...session, sourceIds: [session.sourceIds[0]!, session.sourceIds[0]!] }, "correct horse battery staple"), /local session fields/);
  assert.throws(() => encryptLocalSession({ ...session, decisions: [{ ...session.decisions[0]!, tokenLabel: "EMAIL" }] }, "correct horse battery staple"), /only valid for tokenization/);
});

test("forces secret deletion and rejects reason, token-label and generalization injection", () => {
  const context = dictionary([]);
  const registry = ProjectTokenRegistry.create(context.dictionary.projectId, context.dictionary);
  const credentialText = "password=synthetic-password-123";
  const credential = detectText(credentialText, context)[0];
  assert.ok(credential);
  assert.throws(() => transformText(credentialText, [credential], [{ findingId: credential.findingId, action: "keep", reasonCode: "OPERATIONAL_CONTEXT" }], { dictionary: context.dictionary, tokenRegistry: registry }), /must be deleted/);
  const forgedCredential = { ...credential, type: "email", severity: "high" } as Finding;
  assert.throws(() => transformText(credentialText, [forgedCredential], [{ findingId: forgedCredential.findingId, action: "tokenize" }], { dictionary: context.dictionary, tokenRegistry: registry }), /Untrusted/);
  assert.throws(() => { (credential as { type: string }).type = "email"; }, /read only|Cannot assign/);

  const emailText = "test.person@example.com";
  const email = detectText(emailText, context)[0];
  assert.ok(email);
  assert.throws(() => transformText(emailText, [email], [{ findingId: email.findingId, action: "tokenize", tokenLabel: "EMAIL-sk-SYNTHETICSECRET123456789" }], { dictionary: context.dictionary, tokenRegistry: registry }), /approved/);
  assert.throws(() => transformText(emailText, [email], [{ findingId: email.findingId, action: "keep", reasonCode: "test.person@example.com" as ReasonCode }], { dictionary: context.dictionary, tokenRegistry: registry }), /reason code/);
  assert.throws(() => transformText(emailText, [email], [{ findingId: email.findingId, action: "generalize", generalizationRuleId: "test.person@example.com" }], { dictionary: context.dictionary, tokenRegistry: registry }), /approved rule/);
  assert.throws(() => transformText(emailText, [email], [{ findingId: email.findingId, action: "delete", reasonCode: "PUBLICLY_APPROVED" }], { dictionary: context.dictionary, tokenRegistry: registry }), /only valid for keep/);
  assert.throws(() => transformText(emailText, [email], [
    { findingId: email.findingId, action: "delete" },
    { findingId: "00000000-0000-4000-8000-000000000099", action: "delete" },
  ], { dictionary: context.dictionary, tokenRegistry: registry }), /current finding/);
  const otherDictionary = dictionary([], false, "dict-2");
  const otherRegistry = ProjectTokenRegistry.create(otherDictionary.dictionary.projectId, otherDictionary.dictionary);
  assert.throws(() => transformText(emailText, [email], [{ findingId: email.findingId, action: "delete" }], {
    dictionary: otherDictionary.dictionary,
    tokenRegistry: otherRegistry,
  }), /mismatched/);
  const wrongProjectRegistry = ProjectTokenRegistry.create(otherDictionary.dictionary.projectId, context.dictionary);
  assert.throws(() => transformText(emailText, [email], [{ findingId: email.findingId, action: "delete" }], {
    dictionary: context.dictionary,
    tokenRegistry: wrongProjectRegistry,
  }), /different projects/);
});
