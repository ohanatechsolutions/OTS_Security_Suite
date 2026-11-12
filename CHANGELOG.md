# Changelog — OTS Security Suite

All notable changes are recorded against the repository. This is an **unreleased integration preview**; entries below do not imply a signed product or public installer.

## [Unreleased] — 0.9.0 integration branch

### Added
- Native Windows 10/11 x64 WPF shell connecting RepoScan, W.H.I.T.E., and System Sanitizer without rewriting their original engines.
- User-cancellable local and remote RepoScan inspection; request-context cancellation avoids persisting abandoned scan results.
- User-cancellable bounded W.H.I.T.E. subprocess, synthetic Windows process lifecycle tests, JSON-only report export.
- Safe JSON export through a temporary file and atomic rename, with failure recovery.
- Two-vault registry that displays current and pre-rebrand encrypted quarantine files without silently migrating or deleting either location.
- Windows CI on pull requests: Go/Python/.NET checks, tests, WPF build, packaged W.H.I.T.E. CLI, Inno installer, read-only synthetic GUI smoke, local engine, URI protocol and install/uninstall smoke.
- Chrome MV3 companion uses only temporary `activeTab` access; installer includes the unpacked extension files.
- Living requirements, evidence, risk, Windows QA and release checklist documents.

### Security
- Restricted root repository URL parsing and remote archive compressed/decompressed limits, including TAR metadata.
- Authenticated loopback scanner HTTP server with origin checks and bounded connection lifetimes.
- Guarded child cancellation, stdout/stderr limits, process-tree kill requests; stderr never displayed to the UI.
- Go Windows scanner build changed to the patched Go 1.27.4 toolchain; GitHub Actions updated to maintained Node 24-compatible major versions.
- Installer smoke asserts that a synthetic user-vault canary survives uninstall.

### Known limits
- Static heuristics are not a substitute for traditional endpoint antivirus/EDR.
- Remote repository scans download a public snapshot; Git history, Git LFS and submodule objects need separate verification.
- Actual W.H.I.T.E. offline dependency CVE scanning requires a local OSV dataset not included in the suite.
- A green CI run is not a substitute for real Win10/Win11 manual DPI/Chrome/SmartScreen testing or independent security review.
- No Authenticode publisher certificate or approved public release has been supplied.

## History and compatibility
- Previously standalone RepoScan/OTS GitHub Malware Scanner, OTS W.H.I.T.E., and OTS System Sanitizer remain distinct source modules.
- Legacy Aegis Prime quarantine format and location are retained; no automatic vault conversion is performed.
- The V1 feature set and acceptance gates live in `docs/BUILD_BLUEPRINT.md` and `docs/RELEASE-GATES.md`.
