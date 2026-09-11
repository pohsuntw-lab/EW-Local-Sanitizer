# Release Readiness

Version: 0.1.0

Status: Five-document publication preparation; Windows binary publication prohibited

This document records the gates for publishing the five AI Coding documents. Under the project owner's 2026-09-11 decision, Windows executables and installers are not published to GitHub. This document does not authorize merging, uploading artifacts or creating a GitHub Release.

## Evidence available

- Draft review: [PR #1](https://github.com/pohsuntw-lab/EW-Local-Sanitizer/pull/1)
- Current development branch: `codex/plaintext-hardening-v0.1`
- Application/test baseline commit: `0510e953fb2b1862dc79645cd5aac9a133d7440b`
- Automated tests: 55 unit and 10 fixture tests passed
- Native Windows CI: branded packaging, portable launch, silent per-user install, installed-app launch and uninstall passed in [run 34604522383](https://github.com/pohsuntw-lab/EW-Local-Sanitizer/actions/runs/34604522383)
- Local unsigned setup and portable artifacts were produced with sibling SHA-256 files and a build receipt

## Document-publication gates

| Gate | Status | Required evidence or decision |
| --- | --- | --- |
| Code review | Open | Review and resolve Draft PR #1; do not merge while other release gates remain open |
| Five-document consistency | Open | Review `START_CODEX.md`, `PRODUCT.md`, `ARCHITECTURE.md`, `ACCEPTANCE.md` and `AGENTS.md` as the only GitHub publication deliverables |
| Windows 10/11 human UAT | Deferred, not a document gate | Required only if a later owner decision authorizes Windows binary distribution |
| Network-denied end-to-end UI workflow | Unverified on Windows, not a document gate | Retain as product validation evidence; do not misstate it as passed |
| Application icon | Owner-selected and integrated | The supplied Embodied Worker elephant mark is recorded in `build/ICON_PROVENANCE.md`; verify appearance during Windows human UAT |
| Publisher identity | Metadata recorded, binary release out of scope | Build metadata names `Embodied Worker Co., Ltd.`; no signing process is started under the current policy |
| Source licensing | Owner decision recorded | Proprietary rights retained in `LICENSE`; package metadata points to that notice. Obtain legal review before external binary distribution |
| Authenticode | Not applicable to document publication | Reopen only after an explicit future decision to distribute Windows binaries |
| Final document authorization | Not granted | Obtain explicit authorization before merging or presenting the five documents as final |

## Current artifact boundary

- Artifacts are named `UNSIGNED-TEST-ONLY` and may be shared only with named testers.
- CI does not upload executables or invoke publishing.
- No Windows executable, installer, portable build or packaged binary archive may be attached to a GitHub Release or otherwise published from this repository.
- Signing discovery and signing environment inputs remain disabled for the unsigned channel.
- No updater, telemetry, cloud API or automatic upload may be introduced as part of release preparation.
- A future change to binary distribution requires revised specifications and acceptance criteria before signing or release work begins; an unsigned test artifact must never be renamed into a production artifact.

## Next authorized decision

The next decision is owner review of the five AI Coding documents. Authenticode purchase, enrollment and custody work must not begin under the current no-binary-publication policy.
