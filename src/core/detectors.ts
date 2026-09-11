import { createHash } from "node:crypto";
import type { Finding, FindingType, Severity } from "./types.ts";

interface Detector {
  name: string;
  type: FindingType;
  severity: Severity;
  pattern: RegExp;
}

const DETECTORS: Detector[] = [
  {
    name: "private-key-block",
    type: "private-key",
    severity: "critical",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
  },
  {
    name: "openai-style-token",
    type: "api-token",
    severity: "critical",
    pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    name: "github-token",
    type: "api-token",
    severity: "critical",
    pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
  },
  {
    name: "credential-assignment",
    type: "credential",
    severity: "critical",
    pattern: /\b(?:password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*["']?[^\s"']{8,}/gi,
  },
  {
    name: "email",
    type: "email",
    severity: "high",
    pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
  },
  {
    name: "taiwan-mobile",
    type: "phone",
    severity: "high",
    pattern: /(?<!\d)09\d{2}[- ]?\d{3}[- ]?\d{3}(?!\d)/g,
  },
  {
    name: "taiwan-id",
    type: "taiwan-id",
    severity: "high",
    pattern: /\b[A-Z][12]\d{8}\b/g,
  },
  {
    name: "ipv4",
    type: "ip-address",
    severity: "medium",
    pattern: /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g,
  },
];

function stableId(type: FindingType, start: number, value: string): string {
  return createHash("sha256")
    .update(`${type}\0${start}\0${value}`)
    .digest("hex")
    .slice(0, 16);
}

export function maskValue(value: string): string {
  if (value.length <= 4) return "•".repeat(value.length);
  return `${value.slice(0, 2)}${"•".repeat(Math.min(8, value.length - 4))}${value.slice(-2)}`;
}

export function detectText(text: string, exactData: string[] = []): Finding[] {
  const findings: Finding[] = [];
  const detectors = [...DETECTORS];

  for (const entry of exactData.filter((value) => value.length >= 2)) {
    detectors.push({
      name: "local-exact-data",
      type: "exact-data",
      severity: "high",
      pattern: new RegExp(escapeRegExp(entry), "g"),
    });
  }

  for (const detector of detectors) {
    detector.pattern.lastIndex = 0;
    for (const match of text.matchAll(detector.pattern)) {
      if (match.index === undefined || !match[0]) continue;
      findings.push({
        findingId: stableId(detector.type, match.index, match[0]),
        type: detector.type,
        severity: detector.severity,
        start: match.index,
        end: match.index + match[0].length,
        value: match[0],
        maskedPreview: maskValue(match[0]),
        detector: detector.name,
      });
    }
  }

  return removeOverlaps(findings);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function removeOverlaps(findings: Finding[]): Finding[] {
  const severityRank: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };
  const ordered = [...findings].sort(
    (a, b) => a.start - b.start || severityRank[b.severity] - severityRank[a.severity] || b.end - a.end,
  );
  const accepted: Finding[] = [];
  for (const finding of ordered) {
    if (accepted.some((item) => finding.start < item.end && finding.end > item.start)) continue;
    accepted.push(finding);
  }
  return accepted.sort((a, b) => a.start - b.start);
}

