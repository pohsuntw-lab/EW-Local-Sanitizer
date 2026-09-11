# Project Status

- Product: EW Local Sanitizer｜企業知識本地脫敏器
- Version: 0.1.0 MVP
- Target: Windows 10/11 x64 desktop application
- Stage: CSV/TSV vertical slice implemented and automated verification complete; review pending on `codex/plaintext-hardening-v0.1`
- GitHub: Source published to https://github.com/pohsuntw-lab/EW-Local-Sanitizer
- Public download: Blocked until tests, Windows packaging, Authenticode signing and explicit release authorization

## Next action

Review the CSV/TSV slice, then proceed to DOCX/XLSX/PPTX only after confirmation. The text/tabular policy is now `ew-content-policy-0.2`. Evidence: lint (including local-only source and offline dependency policy), typecheck and build pass; 31 core/unit tests and 7 independent fixture tests pass (38/38 total); npm audit reports zero known vulnerabilities. The implementation adds strict bounded CSV/TSV intake, decoded-cell scanning mapped to immutable source ranges, controlled spreadsheet-formula neutralization, matching derivative extensions, manifest source-format binding and cell-aware second scan. Office, PDF, OCR, Electron and Windows packaging remain unimplemented. Public release remains blocked.
