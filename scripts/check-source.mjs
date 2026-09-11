import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

const roots = ["src", "tests", "scripts"];
const forbidden = [
  /\bhttps?:\/\//,
  /\bfetch\s*\(/,
  /from\s+["'](?:node:)?(?:http|https|net|tls|dgram)["']/,
  /(?:from|import\s*\()\s*["'](?:node:)?(?:dns|http|https|net|tls|dgram|child_process|undici)["']/,
  /require\s*\(\s*["'](?:node:)?(?:dns|http|https|net|tls|dgram|child_process|undici)["']\s*\)/,
  /\b(?:WebSocket|XMLHttpRequest|EventSource)\b/,
  /\b(?:axios|telemetry|analytics|sentry)\b/i,
];
const violations = [];

for (const root of roots) walk(root);

if (violations.length) {
  console.error(violations.join("\n"));
  process.exit(1);
}
console.log("Source policy check passed: no runtime network or telemetry patterns found.");

function walk(path) {
  for (const name of readdirSync(path)) {
    const full = join(path, name);
    if (statSync(full).isDirectory()) walk(full);
    else if (full.replaceAll("\\", "/") === "scripts/check-source.mjs") continue;
    else if (/\.(?:[cm]?js|ts)$/.test(name)) {
      const text = readFileSync(full, "utf8");
      for (const pattern of forbidden) if (pattern.test(text)) violations.push(`${full}: forbidden pattern ${pattern}`);
    }
  }
}
