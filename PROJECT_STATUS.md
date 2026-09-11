# Project Status

- Product: EW Local Sanitizer｜企業知識本地脫敏器
- Version: 0.1.0 MVP
- Target: Windows 10/11 x64 desktop application
- Stage: DOCX/XLSX/PPTX vertical slice implemented and automated verification complete; review pending on `codex/plaintext-hardening-v0.1`
- GitHub: Source published to https://github.com/pohsuntw-lab/EW-Local-Sanitizer
- Public download: Blocked until tests, Windows packaging, Authenticode signing and explicit release authorization

## Next action

Review the Office slice, then proceed to PDF/image OCR only after confirmation. The versioned policy is now `ew-content-policy-0.3`. Evidence: lint (including local-only source and offline dependency policy), typecheck and build pass; 42 core/unit tests and 10 independent fixture tests pass (52/52 total); npm audit reports zero known vulnerabilities. Current work adds bounded OOXML ZIP/XML intake, DOCX/XLSX/PPTX extraction, forced removal of non-visible/active Office structures, XLSX sheet approval and multi-derivative packaging, format-aware second scans, complete finding-set capabilities and scan-profile binding. PDF, image OCR, Electron and Windows packaging remain unimplemented. Public release remains blocked.
