import { randomUUID } from "node:crypto";
import type { DictionarySnapshot } from "./dictionary.js";
import { normalizeSensitiveValue } from "./normalization.js";
import type { Finding, FindingType, Severity } from "./types.js";

interface Detector {
  name: string;
  type: FindingType;
  severity: Severity;
  pattern: RegExp;
  validate?: (value: string) => boolean;
}

const DETECTORS: readonly Detector[] = [
  { name: "private-key-block", type: "private-key", severity: "critical", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { name: "openai-style-token", type: "api-token", severity: "critical", pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  { name: "github-token", type: "api-token", severity: "critical", pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g },
  { name: "credential-assignment", type: "credential", severity: "critical", pattern: /\b(?:password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*["']?[^\s"']{8,}/gi },
  { name: "email", type: "email", severity: "high", pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi },
  { name: "taiwan-mobile", type: "phone", severity: "high", pattern: /(?<!\d)09\d{2}[- ]?\d{3}[- ]?\d{3}(?!\d)/g },
  { name: "taiwan-id-checksum", type: "taiwan-id", severity: "high", pattern: /\b[A-Z][12]\d{8}\b/g, validate: validTaiwanId },
  { name: "taiwan-address-context", type: "address", severity: "high", pattern: /(?:台灣|臺灣)?(?:台北|臺北|新北|桃園|台中|臺中|台南|臺南|高雄|基隆|新竹|嘉義|彰化|屏東|宜蘭|花蓮|台東|臺東|澎湖|金門|連江)[市縣][^\n,，]{0,32}(?:路|街|大道|巷)\s*\d{1,5}\s*號/g },
  { name: "bank-account-context", type: "bank-account", severity: "high", pattern: /\b(?:bank[_ -]?account|account[_ -]?number)\s*[:=]\s*\d[\d -]{7,20}\d\b/gi },
  { name: "contract-identifier", type: "contract-id", severity: "high", pattern: /\b(?:CONTRACT|CTR)-[A-Z0-9][A-Z0-9-]{5,31}\b/gi },
  { name: "ipv4", type: "ip-address", severity: "medium", pattern: /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g },
];

export interface DetectionContext {
  dictionary: DictionarySnapshot;
}

export function detectText(text: string, context: DetectionContext): Finding[] {
  const findings: Finding[] = [];
  for (const detector of DETECTORS) {
    detector.pattern.lastIndex = 0;
    for (const match of text.matchAll(detector.pattern)) {
      if (match.index === undefined || !match[0] || (detector.validate && !detector.validate(match[0]))) continue;
      findings.push(makeFinding(detector.type, detector.severity, match.index, match.index + match[0].length, match[0], detector.name));
    }
  }
  findings.push(...detectDictionaryTerms(text, context.dictionary));
  return removeOverlaps(findings);
}

export function maskValue(value: string): string {
  if (value.length <= 4) return "•".repeat(value.length);
  return `${value.slice(0, 2)}${"•".repeat(Math.min(8, value.length - 4))}${value.slice(-2)}`;
}

function detectDictionaryTerms(text: string, dictionary: DictionarySnapshot): Finding[] {
  const findings: Finding[] = [];
  const indexed = buildNormalizedIndex(text, dictionary);
  for (const term of dictionary.normalizedTerms) {
    let normalizedIndex = 0;
    while ((normalizedIndex = indexed.value.indexOf(term, normalizedIndex)) !== -1) {
      const start = indexed.starts[normalizedIndex];
      const end = indexed.ends[normalizedIndex + term.length - 1];
      if (start !== undefined && end !== undefined) findings.push(makeFinding("exact-data", "high", start, end, text.slice(start, end), "local-exact-data"));
      normalizedIndex += Math.max(1, term.length);
    }
  }
  return findings;
}

function buildNormalizedIndex(text: string, dictionary: DictionarySnapshot): { value: string; starts: number[]; ends: number[] } {
  const values: string[] = [];
  const starts: number[] = [];
  const ends: number[] = [];
  let offset = 0;
  let pendingSpace: { start: number; end: number } | undefined;
  for (const character of text) {
    const start = offset;
    offset += character.length;
    if (/\s/u.test(character)) {
      if (values.length > 0) pendingSpace = pendingSpace ? { start: pendingSpace.start, end: offset } : { start, end: offset };
      continue;
    }
    if (pendingSpace) {
      values.push(" ");
      starts.push(pendingSpace.start);
      ends.push(pendingSpace.end);
      pendingSpace = undefined;
    }
    const normalized = normalizeSensitiveValue(character, dictionary);
    for (const normalizedCharacter of normalized) {
      values.push(normalizedCharacter);
      starts.push(start);
      ends.push(offset);
    }
  }
  return { value: values.join(""), starts, ends };
}

function makeFinding(type: FindingType, severity: Severity, start: number, end: number, value: string, detector: string): Finding {
  return { findingId: randomUUID(), type, severity, start, end, value, maskedPreview: maskValue(value), detector };
}

function validTaiwanId(value: string): boolean {
  const letters = "ABCDEFGHJKLMNPQRSTUVXYWZIO";
  const letterValue = letters.indexOf(value[0] ?? "") + 10;
  if (letterValue < 10) return false;
  const digits = [...value.slice(1)].map(Number);
  const sum = Math.floor(letterValue / 10) + (letterValue % 10) * 9 + digits.slice(0, 8).reduce((total, digit, index) => total + digit * (8 - index), 0) + (digits[8] ?? 0);
  return sum % 10 === 0;
}

function removeOverlaps(findings: Finding[]): Finding[] {
  const rank: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };
  const ordered = [...findings].sort((a, b) => a.start - b.start || rank[b.severity] - rank[a.severity] || b.end - a.end);
  const accepted: Finding[] = [];
  for (const finding of ordered) if (!accepted.some((item) => finding.start < item.end && finding.end > item.start)) accepted.push(finding);
  return accepted.sort((a, b) => a.start - b.start);
}
