import { createHash, randomUUID } from "node:crypto";
import { isAuthenticDictionarySnapshot, type DictionarySnapshot } from "./dictionary.js";
import { normalizeSensitiveValue } from "./normalization.js";
import { MAX_DETECTION_TEXT_BYTES, MAX_FINDINGS_PER_FILE, PLAIN_TEXT_POLICY_VERSION } from "./policy.js";
import type { Finding, FindingType, Severity } from "./types.js";

interface Detector {
  name: string;
  type: FindingType;
  severity: Severity;
  pattern: RegExp;
  validate?: (value: string) => boolean;
}

const DETECTORS: readonly Detector[] = [
  {
    name: "private-key-block",
    type: "private-key",
    severity: "critical",
    pattern: /-----BEGIN ((?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----[\s\S]*?-----END \1-----/g,
  },
  { name: "openai-style-token", type: "api-token", severity: "critical", pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  { name: "github-token", type: "api-token", severity: "critical", pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g },
  { name: "github-fine-grained-token", type: "api-token", severity: "critical", pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g },
  {
    name: "github-stateless-installation-token",
    type: "api-token",
    severity: "critical",
    pattern: /\bghs_[0-9]+_[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  },
  {
    name: "credential-assignment",
    type: "credential",
    severity: "critical",
    pattern: /(?<![A-Za-z0-9_])["']?(?:password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret)["']?\s*[:=]\s*(?:"[^"\r\n]{8,}"|'[^'\r\n]{8,}'|[^\s"'`]{8,})/gi,
  },
  { name: "email", type: "email", severity: "high", pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi },
  { name: "taiwan-mobile", type: "phone", severity: "high", pattern: /(?<!\d)(?:(?:\+?886)[- ]?|0)9\d{2}[- ]?\d{3}[- ]?\d{3}(?!\d)/g },
  { name: "taiwan-id-checksum", type: "taiwan-id", severity: "high", pattern: /\b[A-Z][12]\d{8}\b/gi, validate: validTaiwanId },
  { name: "taiwan-address-context", type: "address", severity: "high", pattern: /(?:台灣|臺灣)?(?:台北|臺北|新北|桃園|台中|臺中|台南|臺南|高雄|基隆|新竹|嘉義|彰化|屏東|宜蘭|花蓮|台東|臺東|澎湖|金門|連江)[市縣][^\n,，]{0,32}(?:路|街|大道|巷)\s*\d{1,5}\s*號/g },
  {
    name: "bank-account-context",
    type: "bank-account",
    severity: "high",
    pattern: /(?<![A-Za-z0-9_])["']?(?:bank[_ -]?account|account[_ -]?number)["']?\s*[:=]\s*(?:"\d[\d -]{7,20}\d"|'\d[\d -]{7,20}\d'|\d[\d -]{7,20}\d\b)/gi,
  },
  { name: "contract-identifier", type: "contract-id", severity: "high", pattern: /\b(?:CONTRACT|CTR)-[A-Z0-9][A-Z0-9-]{5,31}\b/gi },
  { name: "ipv4", type: "ip-address", severity: "medium", pattern: /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g },
];

export interface DetectionContext {
  dictionary: DictionarySnapshot;
}

export interface DetectionSegment {
  readonly value: string;
  readonly valueStarts: readonly number[];
  readonly valueEnds: readonly number[];
  readonly formulaAware?: boolean;
  readonly structuralFinding?: {
    readonly type: FindingType;
    readonly severity: Severity;
    readonly detector: string;
  };
}

type ScanProfile = "text" | "tabular" | "office" | "pdf" | "image";
interface FindingBinding { textHash: string; projectId: string; dictionaryVersion: string; dictionaryHash: string; policyVersion: string; scanProfile: ScanProfile }
const findingBindings = new WeakMap<Finding, FindingBinding>();
const findingSetBindings = new WeakMap<readonly Finding[], FindingBinding>();

export function detectText(text: string, context: DetectionContext): Finding[] {
  if (!isAuthenticDictionarySnapshot(context.dictionary)) throw new Error("Untrusted dictionary snapshot");
  if (Buffer.byteLength(text, "utf8") > MAX_DETECTION_TEXT_BYTES) throw new Error("Detection input exceeds size policy; coverage is incomplete");
  const binding = Object.freeze({
    textHash: createHash("sha256").update(text, "utf8").digest("hex"),
    projectId: context.dictionary.projectId,
    dictionaryVersion: context.dictionary.dictionaryVersion,
    dictionaryHash: context.dictionary.dictionaryHash,
    policyVersion: PLAIN_TEXT_POLICY_VERSION,
    scanProfile: "text",
  });
  const findings: Finding[] = [];
  for (const detector of DETECTORS) {
    detector.pattern.lastIndex = 0;
    for (const match of text.matchAll(detector.pattern)) {
      if (match.index === undefined || !match[0] || (detector.validate && !detector.validate(match[0]))) continue;
      if (findings.length >= MAX_FINDINGS_PER_FILE) throw new Error("Finding limit exceeded; detection coverage is incomplete");
      findings.push(makeFinding(detector.type, detector.severity, match.index, match.index + match[0].length, match[0], detector.name, binding));
    }
  }
  findings.push(...detectDictionaryTerms(text, context.dictionary, MAX_FINDINGS_PER_FILE - findings.length, binding));
  return completeFindingSet(removeOverlaps(findings), binding);
}

export function detectTextSegments(text: string, segments: readonly DetectionSegment[], context: DetectionContext, scanProfile: Exclude<ScanProfile, "text"> = "tabular"): Finding[] {
  if (!isAuthenticDictionarySnapshot(context.dictionary)) throw new Error("Untrusted dictionary snapshot");
  if (Buffer.byteLength(text, "utf8") > MAX_DETECTION_TEXT_BYTES) throw new Error("Detection input exceeds size policy; coverage is incomplete");
  const binding = Object.freeze({
    textHash: createHash("sha256").update(text, "utf8").digest("hex"),
    projectId: context.dictionary.projectId,
    dictionaryVersion: context.dictionary.dictionaryVersion,
    dictionaryHash: context.dictionary.dictionaryHash,
    policyVersion: PLAIN_TEXT_POLICY_VERSION,
    scanProfile,
  });
  const findings: Finding[] = [];
  for (const segment of segments) {
    if (segment.valueStarts.length !== segment.value.length || segment.valueEnds.length !== segment.value.length) {
      throw new Error("Invalid tabular value-to-source mapping");
    }
    const local = detectText(segment.value, context);
    for (const finding of local) {
      if (findings.length >= MAX_FINDINGS_PER_FILE) throw new Error("Finding limit exceeded; detection coverage is incomplete");
      const start = segment.valueStarts[finding.start];
      const end = segment.valueEnds[finding.end - 1];
      if (start === undefined || end === undefined) throw new Error("Invalid tabular finding mapping");
      findings.push(makeFinding(finding.type, finding.severity, start, end, text.slice(start, end), finding.detector, binding, finding.value));
    }
    if (segment.formulaAware) {
      const match = /^\s*[=+\-@]/u.exec(segment.value);
      if (match) {
        if (findings.length >= MAX_FINDINGS_PER_FILE) throw new Error("Finding limit exceeded; detection coverage is incomplete");
        const localIndex = match[0].length - 1;
        const start = segment.valueStarts[localIndex];
        const end = segment.valueEnds[localIndex];
        if (start === undefined || end === undefined) throw new Error("Invalid tabular formula mapping");
        findings.push(makeFinding("spreadsheet-formula", "medium", start, end, text.slice(start, end), "tabular-formula-prefix", binding, match[0].slice(-1)));
      }
    }
    if (segment.structuralFinding && segment.value.length > 0) {
      if (findings.length >= MAX_FINDINGS_PER_FILE) throw new Error("Finding limit exceeded; detection coverage is incomplete");
      const start = segment.valueStarts[0];
      const end = segment.valueEnds[segment.value.length - 1];
      if (start === undefined || end === undefined) throw new Error("Invalid structural finding mapping");
      findings.push(makeFinding(segment.structuralFinding.type, segment.structuralFinding.severity, start, end,
        text.slice(start, end), segment.structuralFinding.detector, binding, `[${segment.structuralFinding.type}]`));
    }
  }
  return completeFindingSet(removeOverlaps(findings), binding);
}

export function areAuthenticFindingsFor(findings: readonly Finding[], text: string, dictionary: DictionarySnapshot): boolean {
  const textHash = createHash("sha256").update(text, "utf8").digest("hex");
  const setBinding = findingSetBindings.get(findings);
  return setBinding?.textHash === textHash && setBinding.projectId === dictionary.projectId &&
    setBinding.dictionaryVersion === dictionary.dictionaryVersion && setBinding.dictionaryHash === dictionary.dictionaryHash &&
    setBinding.policyVersion === PLAIN_TEXT_POLICY_VERSION && findings.every((finding) => {
    const binding = findingBindings.get(finding);
    return binding?.textHash === textHash && binding.projectId === dictionary.projectId && binding.dictionaryVersion === dictionary.dictionaryVersion &&
      binding.dictionaryHash === dictionary.dictionaryHash && binding.policyVersion === PLAIN_TEXT_POLICY_VERSION;
  });
}

export function authenticFindingSetProfile(findings: readonly Finding[]): ScanProfile | undefined {
  return findingSetBindings.get(findings)?.scanProfile;
}

function completeFindingSet(findings: Finding[], binding: FindingBinding): Finding[] {
  Object.freeze(findings);
  findingSetBindings.set(findings, binding);
  return findings;
}

export function maskValue(value: string): string {
  if (value.length <= 4) return "•".repeat(value.length);
  return `${value.slice(0, 2)}${"•".repeat(Math.min(8, value.length - 4))}${value.slice(-2)}`;
}

function detectDictionaryTerms(text: string, dictionary: DictionarySnapshot, remaining: number, binding: FindingBinding): Finding[] {
  const findings: Finding[] = [];
  const indexed = buildNormalizedIndex(text, dictionary);
  const nodes = buildTermTrie(dictionary.normalizedTerms);
  let state = 0;
  for (let index = 0; index < indexed.value.length; index += 1) {
    const unit = indexed.value[index] ?? "";
    while (state !== 0 && !nodes[state]?.next.has(unit)) state = nodes[state]?.fail ?? 0;
    state = nodes[state]?.next.get(unit) ?? 0;
    for (const termLength of nodes[state]?.outputs ?? []) {
      if (findings.length >= remaining) throw new Error("Finding limit exceeded; detection coverage is incomplete");
      const normalizedIndex = index - termLength + 1;
      const start = indexed.starts[normalizedIndex];
      const end = indexed.ends[index];
      if (start !== undefined && end !== undefined) {
        findings.push(makeFinding("exact-data", "high", start, end, text.slice(start, end), "local-exact-data", binding));
      }
    }
  }
  return findings;
}

interface TermTrieNode { next: Map<string, number>; fail: number; outputs: number[] }

function buildTermTrie(terms: readonly string[]): TermTrieNode[] {
  const nodes: TermTrieNode[] = [{ next: new Map(), fail: 0, outputs: [] }];
  for (const term of terms) {
    let node = 0;
    for (let index = 0; index < term.length; index += 1) {
      const unit = term[index] ?? "";
      let next = nodes[node]?.next.get(unit);
      if (next === undefined) {
        next = nodes.length;
        nodes[node]?.next.set(unit, next);
        nodes.push({ next: new Map(), fail: 0, outputs: [] });
      }
      node = next;
    }
    nodes[node]?.outputs.push(term.length);
  }
  const queue = [...(nodes[0]?.next.values() ?? [])];
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const node = queue[cursor] ?? 0;
    for (const [unit, child] of nodes[node]?.next ?? []) {
      queue.push(child);
      let fallback = nodes[node]?.fail ?? 0;
      while (fallback !== 0 && !nodes[fallback]?.next.has(unit)) fallback = nodes[fallback]?.fail ?? 0;
      const target = nodes[fallback]?.next.get(unit);
      nodes[child]!.fail = target === child || target === undefined ? 0 : target;
      nodes[child]!.outputs.push(...(nodes[nodes[child]!.fail]?.outputs ?? []));
    }
  }
  return nodes;
}

function buildNormalizedIndex(text: string, dictionary: DictionarySnapshot): { value: string; starts: number[]; ends: number[] } {
  const values: string[] = [];
  const starts: number[] = [];
  const ends: number[] = [];
  let pendingSpace: { start: number; end: number } | undefined;
  const segmenter = new Intl.Segmenter("und", { granularity: "grapheme" });
  for (const part of segmenter.segment(text)) {
    const start = part.index;
    const end = start + part.segment.length;
    if (/^\s+$/u.test(part.segment)) {
      if (values.length > 0) pendingSpace = pendingSpace ? { start: pendingSpace.start, end } : { start, end };
      continue;
    }
    if (pendingSpace) {
      values.push(" ");
      starts.push(pendingSpace.start);
      ends.push(pendingSpace.end);
      pendingSpace = undefined;
    }
    const normalized = normalizeSensitiveValue(part.segment, dictionary);
    for (let index = 0; index < normalized.length; index += 1) {
      values.push(normalized[index] ?? "");
      starts.push(start);
      ends.push(end);
    }
  }
  return { value: values.join(""), starts, ends };
}

function makeFinding(type: FindingType, severity: Severity, start: number, end: number, value: string, detector: string, binding: FindingBinding, previewValue = value): Finding {
  const finding = Object.freeze({ findingId: randomUUID(), type, severity, start, end, value, maskedPreview: maskValue(previewValue), detector });
  findingBindings.set(finding, binding);
  return finding;
}

function validTaiwanId(value: string): boolean {
  const letters = "ABCDEFGHJKLMNPQRSTUVXYWZIO";
  const letterValue = letters.indexOf((value[0] ?? "").toUpperCase()) + 10;
  if (letterValue < 10) return false;
  const digits = [...value.slice(1)].map(Number);
  const sum = Math.floor(letterValue / 10) + (letterValue % 10) * 9 + digits.slice(0, 8).reduce((total, digit, index) => total + digit * (8 - index), 0) + (digits[8] ?? 0);
  return sum % 10 === 0;
}

function removeOverlaps(findings: Finding[]): Finding[] {
  const rank: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };
  const ordered = [...findings].sort((a, b) => rank[b.severity] - rank[a.severity] || (b.end - b.start) - (a.end - a.start) || a.start - b.start);
  const accepted: Finding[] = [];
  for (const finding of ordered) if (!accepted.some((item) => finding.start < item.end && finding.end > item.start)) accepted.push(finding);
  return accepted.sort((a, b) => a.start - b.start);
}
