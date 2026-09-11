import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import type { TokenEntry } from "./types.ts";

interface EncryptedMap {
  schema: "ewmap-1";
  kdf: "scrypt";
  cipher: "aes-256-gcm";
  salt: string;
  nonce: string;
  tag: string;
  ciphertext: string;
}

export function encryptTokenMap(entries: TokenEntry[], passphrase: string): Buffer {
  if (passphrase.length < 12) throw new Error("Passphrase must contain at least 12 characters");
  const salt = randomBytes(16);
  const nonce = randomBytes(12);
  const key = scryptSync(passphrase, salt, 32);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const plaintext = Buffer.from(JSON.stringify({ schema: "ewmap-1", entries }), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const payload: EncryptedMap = {
    schema: "ewmap-1",
    kdf: "scrypt",
    cipher: "aes-256-gcm",
    salt: salt.toString("base64"),
    nonce: nonce.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
  plaintext.fill(0);
  key.fill(0);
  return Buffer.from(JSON.stringify(payload), "utf8");
}

export function decryptTokenMap(payloadBuffer: Buffer, passphrase: string): TokenEntry[] {
  const payload = JSON.parse(payloadBuffer.toString("utf8")) as EncryptedMap;
  if (payload.schema !== "ewmap-1" || payload.kdf !== "scrypt" || payload.cipher !== "aes-256-gcm") {
    throw new Error("Unsupported token map format");
  }
  const salt = Buffer.from(payload.salt, "base64");
  const nonce = Buffer.from(payload.nonce, "base64");
  const tag = Buffer.from(payload.tag, "base64");
  const ciphertext = Buffer.from(payload.ciphertext, "base64");
  const key = scryptSync(passphrase, salt, 32);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  try {
    const decoded = JSON.parse(plaintext.toString("utf8")) as { schema: string; entries: TokenEntry[] };
    if (decoded.schema !== "ewmap-1" || !Array.isArray(decoded.entries)) throw new Error("Invalid token map");
    return decoded.entries;
  } finally {
    plaintext.fill(0);
    key.fill(0);
  }
}

