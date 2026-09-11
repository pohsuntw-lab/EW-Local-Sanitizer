import { createHmac, randomBytes } from "node:crypto";
import { decryptEnvelope, encryptEnvelope } from "./crypto-envelope.js";
import { normalizeSensitiveValue, type NormalizationPolicy } from "./normalization.js";
import type { FindingType, TokenEntry } from "./types.js";

interface SerializedRegistry {
  schema: "ewmap-registry-1";
  project_scope_secret: string;
  latin_case_sensitive: boolean;
  entries: TokenEntry[];
}

export class ProjectTokenRegistry {
  readonly #scopeSecret: Buffer;
  readonly #normalization: NormalizationPolicy;
  readonly #entries = new Map<string, TokenEntry>();

  private constructor(scopeSecret: Buffer, normalization: NormalizationPolicy, entries: TokenEntry[]) {
    if (scopeSecret.length !== 32) throw new Error("Invalid project scope secret");
    this.#scopeSecret = Buffer.from(scopeSecret);
    this.#normalization = normalization;
    for (const entry of entries) this.#entries.set(entry.normalizedOriginal, { ...entry });
  }

  static create(normalization: NormalizationPolicy): ProjectTokenRegistry {
    return new ProjectTokenRegistry(randomBytes(32), normalization, []);
  }

  static restore(serialized: SerializedRegistry): ProjectTokenRegistry {
    validateSerializedRegistry(serialized);
    const secret = Buffer.from(serialized.project_scope_secret, "base64");
    try {
      return new ProjectTokenRegistry(secret, { latinCaseSensitive: serialized.latin_case_sensitive }, serialized.entries);
    } finally {
      secret.fill(0);
    }
  }

  tokenFor(original: string, findingType: FindingType, label: string): TokenEntry {
    const normalizedOriginal = normalizeSensitiveValue(original, this.#normalization);
    const existing = this.#entries.get(normalizedOriginal);
    if (existing) return { ...existing };
    const identifier = createHmac("sha256", this.#scopeSecret).update(normalizedOriginal).digest("base64url").slice(0, 12).toUpperCase();
    const entry = { token: `【${label}-${identifier}】`, original, normalizedOriginal, findingType };
    this.#entries.set(normalizedOriginal, entry);
    return { ...entry };
  }

  entries(): TokenEntry[] {
    return [...this.#entries.values()].map((entry) => ({ ...entry }));
  }

  serialize(): SerializedRegistry {
    return {
      schema: "ewmap-registry-1",
      project_scope_secret: this.#scopeSecret.toString("base64"),
      latin_case_sensitive: this.#normalization.latinCaseSensitive,
      entries: this.entries(),
    };
  }

  dispose(): void {
    this.#scopeSecret.fill(0);
    this.#entries.clear();
  }
}

export function encryptTokenMap(registry: ProjectTokenRegistry, passphrase: string): Buffer {
  return encryptEnvelope("ewmap", registry.serialize(), passphrase);
}

export function decryptTokenMap(payload: Buffer, passphrase: string): ProjectTokenRegistry {
  return ProjectTokenRegistry.restore(decryptEnvelope(payload, "ewmap", passphrase) as SerializedRegistry);
}

function validateSerializedRegistry(value: SerializedRegistry): void {
  if (value.schema !== "ewmap-registry-1" || typeof value.latin_case_sensitive !== "boolean" || !Array.isArray(value.entries)) {
    throw new Error("Invalid token registry");
  }
  const secret = Buffer.from(value.project_scope_secret, "base64");
  if (secret.length !== 32) throw new Error("Invalid token registry secret");
  secret.fill(0);
  for (const entry of value.entries) {
    if (!entry || typeof entry.token !== "string" || typeof entry.original !== "string" || typeof entry.normalizedOriginal !== "string") {
      throw new Error("Invalid token registry entry");
    }
  }
}
