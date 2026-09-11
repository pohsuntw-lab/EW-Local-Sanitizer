import type { Decision, Finding, PublicFinding, TokenEntry, TransformResult } from "./types.ts";

const FORCED_DELETE = new Set(["private-key", "api-token", "credential"]);

export function transformText(text: string, findings: Finding[], decisions: Decision[]): TransformResult {
  const decisionMap = new Map(decisions.map((decision) => [decision.findingId, decision]));
  const unresolved: Finding[] = [];
  const publicFindings: PublicFinding[] = [];
  const tokenEntries: TokenEntry[] = [];
  const tokenCounters = new Map<string, number>();
  let output = "";
  let cursor = 0;
  let residualRisk = 0;

  for (const finding of findings) {
    const decision = decisionMap.get(finding.findingId);
    if (!decision) {
      unresolved.push(finding);
      continue;
    }
    if (FORCED_DELETE.has(finding.type) && decision.action !== "delete") {
      throw new Error(`${finding.type} findings must be deleted`);
    }
    if (decision.action === "keep" && finding.severity !== "low" && !decision.reason?.trim()) {
      throw new Error(`Keeping ${finding.severity} finding ${finding.findingId} requires a reason`);
    }

    output += text.slice(cursor, finding.start);
    let replacement = "";
    let token: string | undefined;
    if (decision.action === "delete") {
      replacement = "[REMOVED]";
    } else if (decision.action === "tokenize") {
      const label = normalizeLabel(decision.tokenLabel || finding.type);
      const next = (tokenCounters.get(label) || 0) + 1;
      tokenCounters.set(label, next);
      token = `【${label}-${String(next).padStart(2, "0")}】`;
      replacement = token;
      tokenEntries.push({ token, original: finding.value, findingType: finding.type });
    } else if (decision.action === "generalize") {
      if (!decision.replacement?.trim()) throw new Error(`Generalize requires a replacement`);
      replacement = decision.replacement.trim();
    } else {
      replacement = finding.value;
      residualRisk += 1;
    }
    output += replacement;
    cursor = finding.end;
    publicFindings.push({
      finding_id: finding.findingId,
      type: finding.type,
      severity: finding.severity,
      masked_preview: finding.maskedPreview,
      detector: finding.detector,
      action: decision.action,
      ...(token ? { token } : {}),
      ...(decision.reason ? { reason: decision.reason } : {}),
    });
  }

  if (unresolved.length > 0) {
    return { sanitizedText: text, publicFindings: [], tokenEntries: [], unresolved, residualRisk: 0 };
  }
  output += text.slice(cursor);
  return { sanitizedText: output, publicFindings, tokenEntries, unresolved, residualRisk };
}

function normalizeLabel(value: string): string {
  const label = value.toUpperCase().replace(/[^A-Z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
  return label || "SENSITIVE";
}

