import { createHash } from "node:crypto";
import { decryptEnvelope, encryptEnvelope } from "./crypto-envelope.js";
import { normalizeSensitiveValue, type NormalizationPolicy } from "./normalization.js";
import {
  MAX_DICTIONARY_ALIASES_PER_ENTRY,
  MAX_DICTIONARY_ENTRIES,
  MAX_DICTIONARY_TERMS,
  MAX_DICTIONARY_TERM_CHARS,
  MAX_DICTIONARY_TOTAL_CHARS,
} from "./policy.js";

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

const authenticSnapshots = new WeakSet<DictionarySnapshot>();

export function createDictionarySnapshot(dictionary: ProjectDictionary): DictionarySnapshot {
  validateDictionary(dictionary);
  const normalization = { latinCaseSensitive: dictionary.latinCaseSensitive };
  const normalizedTerms = [...new Set(dictionary.entries.flatMap((entry) => [entry.canonical, ...entry.aliases])
    .map((value) => normalizeSensitiveValue(value, normalization)))].sort();
  if (normalizedTerms.length > MAX_DICTIONARY_TERMS || normalizedTerms.some((term) => term.length > MAX_DICTIONARY_TERM_CHARS) ||
    normalizedTerms.reduce((total, term) => total + term.length, 0) > MAX_DICTIONARY_TOTAL_CHARS) {
    throw new Error("Dictionary exceeds normalized term policy limits");
  }
  const canonical = JSON.stringify({
    formatVersion: dictionary.formatVersion,
    dictionaryVersion: dictionary.dictionaryVersion,
    latinCaseSensitive: dictionary.latinCaseSensitive,
    normalizedTerms,
  });
  const snapshot = Object.freeze({
    formatVersion: "ewdict-1",
    dictionaryVersion: dictionary.dictionaryVersion,
    dictionaryHash: createHash("sha256").update(canonical).digest("hex"),
    latinCaseSensitive: dictionary.latinCaseSensitive,
    normalizedTerms: Object.freeze(normalizedTerms),
  });
  authenticSnapshots.add(snapshot);
  return snapshot;
}

export function isAuthenticDictionarySnapshot(snapshot: DictionarySnapshot): boolean {
  return authenticSnapshots.has(snapshot);
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
  if (typeof dictionary.latinCaseSensitive !== "boolean" || !Array.isArray(dictionary.entries) || dictionary.entries.length > MAX_DICTIONARY_ENTRIES) {
    throw new Error("Invalid dictionary or entry count");
  }
  let termCount = 0;
  for (const entry of dictionary.entries) {
    if (typeof entry.canonical !== "string" || entry.canonical.trim().length < 2 || entry.canonical.length > MAX_DICTIONARY_TERM_CHARS ||
      !Array.isArray(entry.aliases) || entry.aliases.length > MAX_DICTIONARY_ALIASES_PER_ENTRY) {
      throw new Error("Invalid dictionary entry");
    }
    if (entry.aliases.some((alias) => typeof alias !== "string" || alias.trim().length < 2 || alias.length > MAX_DICTIONARY_TERM_CHARS)) {
      throw new Error("Invalid dictionary alias");
    }
    termCount += 1 + entry.aliases.length;
    if (termCount > MAX_DICTIONARY_TERMS) throw new Error("Dictionary exceeds term count policy limit");
  }
}
