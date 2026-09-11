# Project Status

- Product: EW Local Sanitizer｜企業知識本地脫敏器
- Version: 0.1.0 MVP
- Target: Windows 10/11 x64 desktop application
- Stage: Unsigned Windows x64 installer/portable artifacts produced and locally verified; real-machine Windows UAT pending
- GitHub: Source published to https://github.com/pohsuntw-lab/EW-Local-Sanitizer
- Public download: Blocked until tests, Windows packaging, Authenticode signing and explicit release authorization

## Next action

Complete the automated Windows native smoke workflow, then execute `WINDOWS_UAT.md` on standard-user Windows 10 and Windows 11 x64 test machines. Run #1 exposed and fixed the source-policy path separator; run #2 passed locked install, lint, typecheck and all tests before exposing the same separator assumption in the packaging output guard. Both guards now use platform-native normalization without weakening their allowed scope. The macOS cross-build produced exactly one NSIS installer and one portable executable, both labelled `UNSIGNED-TEST-ONLY`, plus independently calculated SHA-256 siblings and a safe build receipt. PE inspection confirmed that Authenticode certificate data is absent; packaged-runtime inspection confirmed the manifest schema and local OCR resources are present while build/publish modules, source maps and declarations are absent. Local lint, typecheck, build, dependency policy and 55 unit plus 10 fixture tests pass; `npm audit` reports zero known vulnerabilities. Signing discovery and publishing remain disabled. Physical-click/native-dialog UAT, Authenticode, public release, cross-project integration and final release authorization remain incomplete. Public release remains blocked.
