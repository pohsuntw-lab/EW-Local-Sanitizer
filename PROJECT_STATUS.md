# Project Status

- Product: EW Local Sanitizer｜企業知識本地脫敏器
- Version: 0.1.0 MVP
- Target: Windows 10/11 x64 desktop application
- Stage: Phase 0 and phase 1 plain-text hardening implemented; review pending on `codex/plaintext-hardening-v0.1`
- GitHub: Source published to https://github.com/pohsuntw-lab/EW-Local-Sanitizer
- Public download: Blocked until tests, Windows packaging, Authenticode signing and explicit release authorization

## Next action

Review the phase 0 and phase 1 branch. Current evidence: lint, typecheck and build pass; 21 core/security tests and 4 independent positive/negative/tamper fixture tests pass. Follow-up security reviews removed public verified-capability issuance, made detector findings immutable and source/policy/dictionary-bound, bound transformations to project-scoped token registries, authenticated dictionary snapshots, prioritized critical overlap findings, minimized verified payload data, authenticated encrypted headers, added resource ceilings and linear exact-data matching, made artifact writes exclusive/cleanup-aware, strengthened saved-session/manifest semantics and rejected hidden/noncanonical ZIP data. CSV, Office, PDF, OCR, Electron and Windows packaging remain explicitly out of scope and unimplemented.
