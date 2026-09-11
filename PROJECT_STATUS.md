# Project Status

- Product: EW Local Sanitizer｜企業知識本地脫敏器
- Version: 0.1.0 MVP
- Target: Windows 10/11 x64 desktop application
- Stage: Unsigned Windows x64 installer/portable artifacts produced; native Windows CI smoke passed; human Windows UAT pending
- GitHub: Source published to https://github.com/pohsuntw-lab/EW-Local-Sanitizer
- Public download: Blocked until tests, Windows packaging, Authenticode signing and explicit release authorization

## Next action

Execute `WINDOWS_UAT.md` on standard-user Windows 10 and Windows 11 x64 test machines. The native Windows CI smoke workflow passed on commit `27f0e69eba30b183a162acc8b523d9d8cdb92eb3`: locked dependency installation, lint, typecheck, all synthetic tests, unsigned Windows packaging, portable launch, per-user silent install, installed-app launch and uninstall all completed successfully ([run 34599172096](https://github.com/pohsuntw-lab/EW-Local-Sanitizer/actions/runs/34599172096)). CI does not upload its artifacts and does not replace physical-click, native-dialog, SmartScreen, network-denied or end-to-end human UAT.

The macOS cross-build produced exactly one NSIS installer and one portable executable, both labelled `UNSIGNED-TEST-ONLY`, plus independently calculated SHA-256 siblings and a safe build receipt. PE inspection confirmed that Authenticode certificate data is absent; packaged-runtime inspection confirmed the manifest schema and local OCR resources are present while build/publish modules, source maps and declarations are absent. Local lint, typecheck, build, dependency policy and 55 unit plus 10 fixture tests pass; `npm audit` reports zero known vulnerabilities. Signing discovery and publishing remain disabled. Human Windows UAT, Authenticode, public release, cross-project integration and final release authorization remain incomplete. Public release remains blocked.
