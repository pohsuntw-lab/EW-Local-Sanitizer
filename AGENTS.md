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

## Required commands

Define and keep working:

```bash
npm run lint
npm run typecheck
npm test
npm run test:fixtures
npm run build
npm run package:win
```

## Definition of done

- Every MVP requirement maps to an acceptance test or an explicitly recorded manual test.
- Network-denied core workflow passes.
- Synthetic fixture matrix passes, including negative and tamper cases.
- Safe Package allowlist and second scan pass.
- Windows installer and portable artifacts are produced.
- Public release remains blocked until Authenticode signing and user authorization.

## Stop conditions

Stop before adding any network transmission, weakening an export block, supporting password-protected sources by bypassing protection, using real sensitive files, changing target OS, buying a signing certificate, publishing downloads or claiming regulatory compliance.

