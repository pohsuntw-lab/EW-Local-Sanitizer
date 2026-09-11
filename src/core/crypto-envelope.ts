import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";

export const SCRYPT_PARAMETERS = Object.freeze({ N: 16_384, r: 8, p: 1, keyLength: 32, maxmem: 64 * 1024 * 1024 });

export interface EncryptedEnvelope {
  format_version: "1";
  content_type: "ewmap" | "ewdict" | "ewsession";
  kdf: "scrypt";
  scrypt: { N: number; r: number; p: number; key_length: number; maxmem: number };
  cipher: "aes-256-gcm";
  salt: string;
  iv: string;
  authentication_tag: string;
  ciphertext: string;
}

export function encryptEnvelope(contentType: EncryptedEnvelope["content_type"], value: unknown, passphrase: string): Buffer {
  if (passphrase.length < 12) throw new Error("Passphrase must contain at least 12 characters");
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  let key: Buffer | undefined;
  let plaintext: Buffer | undefined;
  try {
    key = scryptSync(passphrase, salt, SCRYPT_PARAMETERS.keyLength, SCRYPT_PARAMETERS);
    plaintext = Buffer.from(JSON.stringify(value), "utf8");
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.from(JSON.stringify({
      format_version: "1",
      content_type: contentType,
      kdf: "scrypt",
      scrypt: {
        N: SCRYPT_PARAMETERS.N,
        r: SCRYPT_PARAMETERS.r,
        p: SCRYPT_PARAMETERS.p,
        key_length: SCRYPT_PARAMETERS.keyLength,
        maxmem: SCRYPT_PARAMETERS.maxmem,
      },
      cipher: "aes-256-gcm",
      salt: salt.toString("base64"),
      iv: iv.toString("base64"),
      authentication_tag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    } satisfies EncryptedEnvelope), "utf8");
  } finally {
    plaintext?.fill(0);
    key?.fill(0);
  }
}

export function decryptEnvelope(payloadBuffer: Buffer, expectedType: EncryptedEnvelope["content_type"], passphrase: string): unknown {
  const envelope = parseEnvelope(payloadBuffer, expectedType);
  let key: Buffer | undefined;
  let plaintext: Buffer | undefined;
  try {
    const salt = decodeBase64(envelope.salt, 16, "salt");
    const iv = decodeBase64(envelope.iv, 12, "IV");
    const tag = decodeBase64(envelope.authentication_tag, 16, "authentication tag");
    const ciphertext = decodeBase64(envelope.ciphertext, undefined, "ciphertext");
    key = scryptSync(passphrase, salt, envelope.scrypt.key_length, {
      N: envelope.scrypt.N,
      r: envelope.scrypt.r,
      p: envelope.scrypt.p,
      maxmem: envelope.scrypt.maxmem,
    });
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(plaintext.toString("utf8")) as unknown;
  } finally {
    plaintext?.fill(0);
    key?.fill(0);
  }
}

function parseEnvelope(buffer: Buffer, expectedType: EncryptedEnvelope["content_type"]): EncryptedEnvelope {
  const value = JSON.parse(buffer.toString("utf8")) as Partial<EncryptedEnvelope>;
  if (
    value.format_version !== "1" || value.content_type !== expectedType || value.kdf !== "scrypt" ||
    value.cipher !== "aes-256-gcm" || !value.scrypt ||
    value.scrypt.N !== SCRYPT_PARAMETERS.N || value.scrypt.r !== SCRYPT_PARAMETERS.r ||
    value.scrypt.p !== SCRYPT_PARAMETERS.p || value.scrypt.key_length !== SCRYPT_PARAMETERS.keyLength ||
    value.scrypt.maxmem !== SCRYPT_PARAMETERS.maxmem || typeof value.salt !== "string" ||
    typeof value.iv !== "string" || typeof value.authentication_tag !== "string" || typeof value.ciphertext !== "string"
  ) throw new Error("Unsupported or unsafe encrypted envelope");
  return value as EncryptedEnvelope;
}

function decodeBase64(value: string, expectedLength: number | undefined, label: string): Buffer {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error(`Invalid ${label}`);
  const decoded = Buffer.from(value, "base64");
  if (expectedLength !== undefined && decoded.length !== expectedLength) throw new Error(`Invalid ${label} length`);
  return decoded;
}
