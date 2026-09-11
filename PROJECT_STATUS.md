# Project Status

- Product: EW Local Sanitizer｜企業知識本地脫敏器
- Version: 0.1.0 MVP
- Target: Windows 10/11 x64 desktop application
- Stage: Draft PR review and five-document publication preparation; native Windows CI smoke passed; human Windows UAT explicitly deferred and remains unverified
- GitHub: Source published to https://github.com/pohsuntw-lab/EW-Local-Sanitizer
- Windows download: Prohibited by current project-owner policy; no EXE, installer, portable build or binary archive will be uploaded to GitHub

## Next action

Draft PR [#1](https://github.com/pohsuntw-lab/EW-Local-Sanitizer/pull/1) is open for review. On 2026-09-11, the project owner selected proprietary source licensing with all rights reserved and directed that Windows binaries must not be published to GitHub. GitHub publication deliverables are limited to the five AI Coding documents. Human Windows UAT is explicitly deferred and remains unverified, but it is not a gate for document publication; it becomes mandatory only if the owner later changes the Windows distribution policy. See `RELEASE_READINESS.md` for the remaining document-review gates.

The native Windows CI smoke workflow passed on commit `f090963df853c3f33377a9408144b00eab69785c`: locked dependency installation, lint, typecheck, all synthetic tests, branded unsigned Windows packaging, portable launch, per-user silent install, installed-app launch and uninstall all completed successfully ([run 34604522383](https://github.com/pohsuntw-lab/EW-Local-Sanitizer/actions/runs/34604522383)). CI does not upload its artifacts and does not replace physical-click, native-dialog, SmartScreen, network-denied or end-to-end human UAT.

The project owner selected the supplied Embodied Worker elephant mark for the application icon on 2026-09-11. Its transparent icon derivative and provenance record are integrated into the Windows builder configuration; appearance on Windows remains part of deferred human UAT. Publisher metadata names `Embodied Worker Co., Ltd.`, but no verified Authenticode publisher identity exists yet.

The internal assisted installer now follows the versioned EULA pattern used by the `ewfloechart` reference project, adapted specifically for EW Local Sanitizer. Traditional Chinese and English human-maintained agreements generate NSIS text, a SHA-256 manifest and a custom acceptance gate at build time. Fresh and upgrade-assisted installs require an unselected checkbox to be explicitly accepted; silent installation requires the exact agreement version and locale hash and otherwise exits with an error. Acceptance evidence contains agreement metadata only. Visual confirmation and upgrade-path behavior on Windows remain part of deferred human UAT. The agreement text still requires qualified legal review before any external or commercial use.

The macOS cross-build produced exactly one NSIS installer and one portable executable, both labelled `UNSIGNED-TEST-ONLY`, plus independently calculated SHA-256 siblings and a safe build receipt. PE inspection confirmed that Authenticode certificate data is absent; packaged-runtime inspection confirmed the manifest schema and local OCR resources are present while build/publish modules, source maps and declarations are absent. Local lint, typecheck, build, dependency policy and 55 unit plus 10 fixture tests pass; `npm audit` reports zero known vulnerabilities. Signing discovery, artifact upload and publishing remain disabled. Human Windows UAT and Authenticode remain outside the document-publication path. Cross-project integration remains incomplete.
