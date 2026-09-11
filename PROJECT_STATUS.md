# Project Status

- Product: EW Local Sanitizer｜企業知識本地脫敏器
- Version: 0.1.0 MVP
- Target: Windows 10/11 x64 desktop application
- Stage: Sandboxed Electron/React UI and narrow typed IPC vertical slice implemented on `codex/plaintext-hardening-v0.1`; Windows UAT pending
- GitHub: Source published to https://github.com/pohsuntw-lab/EW-Local-Sanitizer
- Public download: Blocked until tests, Windows packaging, Authenticode signing and explicit release authorization

## Next action

Review the pushed Electron UI slice and then authorize the Windows packaging stage separately. The UI keeps all source paths, raw findings, dictionaries, token registries and opaque capabilities in the main process; the sandboxed renderer receives masked review data through three typed IPC operations only. Local evidence is 49 passing unit tests plus 10 passing fixture tests, with lint, typecheck, build, dependency policy and `npm audit` all passing. The initial macOS renderer preview confirmed the guided layout and visible blocked states. Windows real-machine validation, physical-click UAT, installer/portable packaging, Authenticode, cross-project integration and release authorization remain incomplete. Public release remains blocked.
