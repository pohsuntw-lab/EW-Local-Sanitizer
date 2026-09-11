import { createHmac, randomBytes } from "node:crypto";
import { decryptEnvelope, encryptEnvelope } from "./crypto-envelope.js";
import { normalizeSensitiveValue, type NormalizationPolicy } from "./normalization.js";
import { validateTokenLabel } from "./policy.js";
import type { FindingType, TokenEntry } from "./types.js";

interface SerializedRegistry {
  schema: "ewmap-registry-2";
  project_id: string;
  project_scope_secret: string;
  latin_case_sensitive: boolean;
  entries: TokenEntry[];
}

export class ProjectTokenRegistry {
  readonly #projectId: string;
  readonly #scopeSecret: Buffer;
  readonly #normalization: NormalizationPolicy;
  readonly #entries = new Map<string, TokenEntry>();
  #disposed = false;

  private constructor(projectId: string, scopeSecret: Buffer, normalization: NormalizationPolicy, entries: TokenEntry[]) {
    if (!isUuid(projectId)) throw new Error("Invalid token registry project ID");
    if (scopeSecret.length !== 32) throw new Error("Invalid project scope secret");
    if (typeof normalization.latinCaseSensitive !== "boolean") throw new Error("Invalid token registry normalization policy");
    this.#projectId = projectId;
    this.#scopeSecret = Buffer.from(scopeSecret);
    this.#normalization = normalization;
    for (const entry of entries) this.#entries.set(entry.normalizedOriginal, { ...entry });
  }

  static create(projectId: string, normalization: NormalizationPolicy): ProjectTokenRegistry {
    return new ProjectTokenRegistry(projectId, randomBytes(32), normalization, []);
  }

  static restore(serialized: SerializedRegistry): ProjectTokenRegistry {
    validateSerializedRegistry(serialized);
    const secret = Buffer.from(serialized.project_scope_secret, "base64");
    try {
      return new ProjectTokenRegistry(serialized.project_id, secret, { latinCaseSensitive: serialized.latin_case_sensitive }, serialized.entries);
    } finally {
      secret.fill(0);
    }
  }

  tokenFor(original: string, findingType: FindingType, label: string): TokenEntry {
    this.#assertActive();
    if (typeof original !== "string" || !original) throw new Error("Invalid token original");
    if (!isFindingType(findingType)) throw new Error("Invalid token finding type");
    validateTokenLabel(label);
    const normalizedOriginal = normalizeSensitiveValue(original, this.#normalization);
    if (!normalizedOriginal) throw new Error("Invalid empty normalized token original");
    const existing = this.#entries.get(normalizedOriginal);
    if (existing) return { ...existing };
    const identifier = createHmac("sha256", this.#scopeSecret).update(normalizedOriginal).digest("base64url").slice(0, 20).toUpperCase();
    const entry = { token: `【${label}-${identifier}】`, original, normalizedOriginal, findingType };
    this.#entries.set(normalizedOriginal, entry);
    return { ...entry };
  }

  projectId(): string {
    this.#assertActive();
    return this.#projectId;
  }

  entries(): TokenEntry[] {
    this.#assertActive();
    return [...this.#entries.values()].map((entry) => ({ ...entry }));
  }

  serialize(): SerializedRegistry {
    this.#assertActive();
    return {
      schema: "ewmap-registry-2",
      project_id: this.#projectId,
      project_scope_secret: this.#scopeSecret.toString("base64"),
      latin_case_sensitive: this.#normalization.latinCaseSensitive,
      entries: this.entries(),
    };
  }

  dispose(): void {
    this.#scopeSecret.fill(0);
    this.#entries.clear();
    this.#disposed = true;
  }

  #assertActive(): void {
    if (this.#disposed) throw new Error("Project token registry has been disposed");
  }
}

export function encryptTokenMap(registry: ProjectTokenRegistry, passphrase: string): Buffer {
  return encryptEnvelope("ewmap", registry.serialize(), passphrase);
}

export function decryptTokenMap(payload: Buffer, passphrase: string): ProjectTokenRegistry {
  return ProjectTokenRegistry.restore(decryptEnvelope(payload, "ewmap", passphrase) as SerializedRegistry);
}

function validateSerializedRegistry(value: SerializedRegistry): void {
  if (value.schema !== "ewmap-registry-2" || !isUuid(value.project_id) || typeof value.project_scope_secret !== "string" ||
    typeof value.latin_case_sensitive !== "boolean" || !Array.isArray(value.entries)) {
    throw new Error("Invalid token registry");
  }
  const secret = Buffer.from(value.project_scope_secret, "base64");
  try {
    if (secret.length !== 32) throw new Error("Invalid token registry secret");
    const normalizedSeen = new Set<string>();
    const tokenSeen = new Set<string>();
    for (const entry of value.entries) {
      const match = entry?.token?.match(/^【([A-Z][A-Z0-9_-]{1,31})-([A-Z0-9_-]{20})】$/);
      if (!entry || typeof entry.original !== "string" || typeof entry.normalizedOriginal !== "string" || !match ||
        !isFindingType(entry.findingType) || normalizeSensitiveValue(entry.original, { latinCaseSensitive: value.latin_case_sensitive }) !== entry.normalizedOriginal) {
        throw new Error("Invalid token registry entry");
      }
      validateTokenLabel(match[1] ?? "");
      const expected = createHmac("sha256", secret).update(entry.normalizedOriginal).digest("base64url").slice(0, 20).toUpperCase();
      if (match[2] !== expected || normalizedSeen.has(entry.normalizedOriginal) || tokenSeen.has(entry.token)) {
        throw new Error("Invalid token registry entry integrity");
      }
      normalizedSeen.add(entry.normalizedOriginal);
      tokenSeen.add(entry.token);
    }
  } finally {
    secret.fill(0);
  }
}

function isUuid(value: string): boolean {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function isFindingType(value: unknown): value is FindingType {
  return typeof value === "string" && new Set<FindingType>([
    "private-key", "api-token", "credential", "email", "phone", "taiwan-id", "address", "ip-address", "bank-account", "contract-id", "exact-data",
  ]).has(value as FindingType);
}
