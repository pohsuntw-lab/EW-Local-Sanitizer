# Project Status

- Product: EW Local Sanitizer｜企業知識本地脫敏器
- Version: 0.1.0 MVP
- Target: Windows 10/11 x64 desktop application
- Stage: PDF text/risk inspection and standalone local image OCR vertical slice implemented and automated verification complete; review pending on `codex/plaintext-hardening-v0.1`
- GitHub: Source published to https://github.com/pohsuntw-lab/EW-Local-Sanitizer
- Public download: Blocked until tests, Windows packaging, Authenticode signing and explicit release authorization

## Next action

Review the PDF/image slice before authorizing the Electron UI stage. Content policy `ew-content-policy-0.4` now has passing lint, typecheck and build evidence; 45 core/unit tests and 10 independent fixture tests pass (55/55 total), including a network-denied real WASM OCR flow, and npm audit reports zero known vulnerabilities. This slice adds bounded PDF text/risk inspection plus offline WASM OCR for standalone PNG/JPEG, delete-only flattened PNG redaction, metadata omission and same-model/dictionary second scan. Image-bearing PDF raster OCR, UI/physical user-gesture binding, Windows real-machine validation, installer/portable packaging, Authenticode, cross-project integration and UAT remain incomplete. Public release remains blocked.
