# AGENTS.md

## Mission

Build EW Local Sanitizer v0.1.0 as a Windows-first, local-only pre-upload document sanitization application. Read `PRODUCT.md`, `ARCHITECTURE.md` and `ACCEPTANCE.md` before editing.

## Non-negotiable security rules

- Never modify originals.
- Never add telemetry, cloud APIs, remote fonts/scripts, external OCR or automatic upload.
- Fail closed on parser or coverage failure.
- Never log or export original sensitive values or full local paths.
- Credentials and private keys must be deleted; do not allow keep/tokenize overrides.
- Build Safe Packages from an explicit allowlist.
- Keep `.ewmap` outside Safe Packages and authenticate encryption failures.
- Never claim perfect detection, anonymity, compliance certification or endpoint DLP.
- Use synthetic secrets and identities in tests; never real credentials or customer documents.

## Implementation rules

- TypeScript strict mode.
- Keep parsing, detection, policy, transformation, verification and packaging as separate modules.
- Core logic must be testable without Electron.
- UI may call the core through a narrow typed IPC layer; renderer receives masked previews only when practical.
- Pin dependencies and document each security-sensitive dependency.
- Do not silently skip unsupported document structures.
- For the current versioned content policy, accept only TXT/Markdown/CSV/TSV/DOCX/XLSX/PPTX; content/encoding validation must not rely on extension alone.
- CSV/TSV must be parsed cell-by-cell with bounded structure. Malformed or ambiguous structure fails closed, and formula-like cells require the controlled literal-text transformation before export.
- OOXML must pass bounded ZIP central/local-header validation and strict local XML parsing. Reject macros, encryption, DTD/entities and unsafe package structure; incomplete embedded-content coverage blocks export.
- Office hidden content, formulas, external links and metadata indicators are forced-delete. XLSX visible worksheets require explicit selection approval and every generated derivative must be independently allowlisted, hashed and rescanned.
- High/critical `keep` is local-review-only and remains unresolved for cloud export. P3 is always local-only.
- Packaging must consume an opaque verified result and must not expose a direct arbitrary-content export API.
- Public reports use controlled reason codes only. Token labels and generalization replacements must be controlled policy values and scanned again.
- Project dictionaries and token registries are encrypted local artifacts. No original dictionary/token value enters manifests, logs or Safe Packages.
- JavaScript memory cannot promise complete zeroization; clear owned buffers in `finally` paths and document the limitation.

## Required commands

Define and keep working:

```bash
npm run lint
npm run typecheck
npm test
npm run test:fixtures
npm run build
```

`npm run package:win` remains an intentional failing placeholder until the explicitly authorized Windows packaging phase. Do not add PDF parsing, OCR, Electron or Windows packaging during the Office slice.

## Definition of done

- Every MVP requirement maps to an acceptance test or an explicitly recorded manual test.
- Network-denied core workflow passes.
- Synthetic fixture matrix passes, including negative and tamper cases.
- Safe Package allowlist, ZIP post-write inspection, actual ZIP checksum and bound second scan pass.
- Windows installer and portable artifacts are produced.
- Public release remains blocked until Authenticode signing and user authorization.
- EW Enterprise Secure Knowledge Forge cross-project schema compatibility remains pending integration.

## Stop conditions

Stop before adding any network transmission, weakening an export block, supporting password-protected sources by bypassing protection, using real sensitive files, changing target OS, buying a signing certificate, publishing downloads or claiming regulatory compliance.
