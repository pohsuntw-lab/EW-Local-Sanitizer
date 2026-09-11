import { createHash } from "node:crypto";
import { decryptEnvelope, encryptEnvelope } from "./crypto-envelope.js";
import { normalizeSensitiveValue, type NormalizationPolicy } from "./normalization.js";

export interface DictionaryEntry {
  canonical: string;
  aliases: string[];
}

export interface ProjectDictionary {
  formatVersion: "ewdict-1";
  dictionaryVersion: string;
  latinCaseSensitive: boolean;
  entries: DictionaryEntry[];
}

export interface DictionarySnapshot extends NormalizationPolicy {
  formatVersion: "ewdict-1";
  dictionaryVersion: string;
  dictionaryHash: string;
  normalizedTerms: readonly string[];
}

export function createDictionarySnapshot(dictionary: ProjectDictionary): DictionarySnapshot {
  validateDictionary(dictionary);
  const normalization = { latinCaseSensitive: dictionary.latinCaseSensitive };
  const normalizedTerms = [...new Set(dictionary.entries.flatMap((entry) => [entry.canonical, ...entry.aliases])
    .map((value) => normalizeSensitiveValue(value, normalization)))].sort();
  const canonical = JSON.stringify({
    formatVersion: dictionary.formatVersion,
    dictionaryVersion: dictionary.dictionaryVersion,
    latinCaseSensitive: dictionary.latinCaseSensitive,
    normalizedTerms,
  });
  return Object.freeze({
    formatVersion: "ewdict-1",
    dictionaryVersion: dictionary.dictionaryVersion,
    dictionaryHash: createHash("sha256").update(canonical).digest("hex"),
    latinCaseSensitive: dictionary.latinCaseSensitive,
    normalizedTerms: Object.freeze(normalizedTerms),
  });
}

export function encryptProjectDictionary(dictionary: ProjectDictionary, passphrase: string): Buffer {
  validateDictionary(dictionary);
  return encryptEnvelope("ewdict", dictionary, passphrase);
}

export function decryptProjectDictionary(payload: Buffer, passphrase: string): ProjectDictionary {
  const value = decryptEnvelope(payload, "ewdict", passphrase) as ProjectDictionary;
  validateDictionary(value);
  return value;
}

function validateDictionary(dictionary: ProjectDictionary): void {
  if (dictionary.formatVersion !== "ewdict-1" || !/^[A-Za-z0-9._-]{1,64}$/.test(dictionary.dictionaryVersion)) {
    throw new Error("Invalid dictionary header");
  }
  if (typeof dictionary.latinCaseSensitive !== "boolean" || !Array.isArray(dictionary.entries)) throw new Error("Invalid dictionary");
  for (const entry of dictionary.entries) {
    if (typeof entry.canonical !== "string" || entry.canonical.trim().length < 2 || !Array.isArray(entry.aliases)) {
      throw new Error("Invalid dictionary entry");
    }
    if (entry.aliases.some((alias) => typeof alias !== "string" || alias.trim().length < 2)) throw new Error("Invalid dictionary alias");
  }
}
