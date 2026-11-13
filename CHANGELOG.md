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

- Explicitly require a valid complete/error/checks JSON contract before classifying W.H.I.T.E. clean; reject incomplete or inconsistent reports as a success.
- Taskbar process and installed shortcuts now share a distinct Windows AppUserModelID; PNG alpha test enforces the supplied white logo's transparent background.
- Destroy-reviewed authorization binds a selected record's vault path and SHA-256, not only its GUID.
- TAR decompression hard limit reports resource exhaustion rather than silently treating it as successful EOF.
- Preserve original MIT/third-party notice text for each bundled original engine.

### Verification (not a release)

Windows CI [run 43189027296](https://github.com/ohanatechsolutions/OTS_Security_Suite/actions/runs/43189027296) **PASS** at source `a2f39b812e61116ecaa3f4813909b662d4149224` / documentation head `de277e5fa3bb2d7e1bd8b2aac362a3d9e74ff916`: Go tests/vet, 15/15 WPF audit/report/vault regressions, synthetic native UI audit, PNG transparency, MIT notice packaging and user-vault-preserving uninstall. Installer SHA-256 `8872BB5E2039C7B5F6AA13EA7AC52276CB22C80AA88B00FCDEE6271B5BC1C929`. The PR artifact upload was intentionally skipped and no publisher-signed release exists.

### Engineering hardening completed in the latest verified candidate

- Validated and size-bounded local RepoScan history: reject mismatched filenames/IDs, malformed JSON, oversized files and unsafe local history before showing/exporting; atomically save only reports within that same size budget.
- More forgiving GitHub/Bitbucket root input: accepts pasted owner/repository URLs without a scheme but canonicalizes strictly to public HTTPS root URLs; backend allowlist remains mandatory.
- Added 10 harmless Go synthetic detection/benign fixtures and 17 browser-input normalization tests.
- Bundled build manifest now fingerprints the actual Inno Setup compiler binary SHA-256; its PE version-resource field is recorded when available, not guessed.
- Current Windows CI [#43414634076](https://github.com/ohanatechsolutions/OTS_Security_Suite/actions/runs/43414634076) passed 22/22 Windows regression cases, 13/13 extension checks, 17/17 embedded browser input checks, scope-limited WHITE source/history audit and all installed-app tests. Unsigned test-build hash `826DD311F59CAD0E4BEB7A2F1353921CD5C790D90577D73B5C99C40FF4C830AA`; no signed release.

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
