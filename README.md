# OTS Security Suite — Integrated Preview 0.9.0

**Ohana Tech Solutions** · Windows 10/11 x64 · Native WPF application with offline/local scan engines

This is the first integrated development build of three OTS projects. It **is not yet approved for public release**. Source is organized for a single Windows installer; it preserves the existing component codebases and quarantine format rather than replacing them with a new unvalidated implementation.

## Latest engineering verification (unreleased)

**Last verified engineering-code commit:** `ba7562b41e7ec1abda69406fc0b1a235993e3df7` — [Windows CI #43414634076](https://github.com/ohanatechsolutions/OTS_Security_Suite/actions/runs/43414634076) **SUCCESS**, Windows runner. Actual logs: Go tests/vet and scanner build PASS; Chrome popup contracts **13/13 PASS**; embedded RepoScan URL normalization **17/17 PASS**; offline W.H.I.T.E. source/history audit **172 worktree files scanned, zero high/critical findings reported by the configured audit** (not an independent security certification); packaged WHITE checks PASS; 22/22 Windows C# process/report/quarantine tests PASS; Sanitizer tests PASS; native WPF publish PASS; Inno Setup package PASS; install/WPF UI Automation/second-launch handoff/normal close/repair/uninstall and synthetic user-vault retention PASS; source/submodule/compiler provenance manifest PASS. **Unsigned CI test installer SHA-256: `826DD311F59CAD0E4BEB7A2F1353921CD5C790D90577D73B5C99C40FF4C830AA`**. Artifact upload intentionally skipped on PR, no public signed release. Independent real-device QA, historical DPAPI recovery, Chrome clean-profile, publisher signing and final owner approval remain **NOT RUN/BLOCKED**.

Follow the [one-page owner finish line](docs/OWNER_FINISH_LINE.md) for the exact remaining non-code steps. The repo's root distribution license, trusted publisher signature and final release decision require owner authorization; do not bypass these gates.

## Modules

1. **Repository Security** — the independent Go scanner from OTS GitHub Malware Scanner v2.5. The local server is started on an ephemeral loopback port by the WPF host, is opened inside native WebView2, and is killed when the suite window closes. URL scanning retrieves public GitHub/Bitbucket snapshots; local-folder scanning requires no ScanRepo.dev backend. The Go engine has 95 heuristic rules and format-aware baseline inspection.
2. **Code and Secrets Audit** — OTS W.H.I.T.E. packaged as a dedicated Python CLI executable. Secret detection, SAST, optional history, and optional offline OSV vulnerability checks can be selected in the suite. JSON output is redacted by W.H.I.T.E. before being displayed or exported. The OSV scanner/cache is **not** bundled and must be provided separately if that option is selected.
3. **Windows Security** — OTS System Sanitizer's existing .NET 10 core provides quick/deep local inspection, Defender invocation, investigation, encrypted user-scoped quarantine, restore, and reviewed destruction. The original Sanitizer GUI is also bundled for all its existing specialist operations while the consolidated interface is expanded.
4. **Space Recovery** — Sanitizer's cleanup service, with per-file selection and explicit deletion confirmation.
5. **Chrome Extension** — uses the installed `ots-security://` custom URI handler to open the native suite, rather than depending on a fixed local port or ScanRepo.dev.

## Architecture

```text
OTS Security Suite native WPF / WebView2 host (OTSSecuritySuite.exe)
 ├─ child Go process / ephemeral 127.0.0.1 (OTSScannerEngine.exe)
 ├─ child Python audit CLI (OTSWhiteAudit.exe)
 └─ in-process System Sanitizer .NET core
       ├─ Windows threat scan / Defender
       ├─ encrypted quarantine (original DPAPI format)
       └─ cleanup & safe restore
          + optional original OTSSystemSanitizer.exe specialist window
```

The native Windows icon and title-bar icon are both set to the user's supplied shield-bug `.ico`, and the header uses the supplied transparent Ohana Tech Solutions logo. Windows may cache taskbar pins from old releases; unpin the old Chrome-hosted scanner if it remains.

### Building on Windows

You need .NET 10 SDK, Go 1.27.4+ (security-maintained toolchain), Python 3.12, PyInstaller, Inno Setup 6, Microsoft WebView2 runtime, and the two Git submodules (both public).

```powershell
git clone --recurse-submodules https://github.com/ohanatechsolutions/OTS_Security_Suite.git
cd OTS_Security_Suite
# GitHub Actions -> Windows build and integration checks -> Run workflow
```

The workflow compiles the native WPF shell, Go engine, PyInstaller CLI, and Sanitizer GUI; it then packs a per-user `OTS-Security-Suite-Setup-x64.exe` with SHA-256 checksums. The installer is **unsigned** until an OTS code-signing identity is configured. Microsoft SmartScreen reputation warnings can occur on unsigned or unfamiliar builds.

For local tests that don't need the Windows toolchain:

```bash
(cd scanner && go test ./... && go vet ./...)
python -m unittest discover -s tools -v
node --check extension/popup.js
```

### Privacy and safety boundaries

All local folder/content scans are read-only unless you explicitly request quarantine or cleanup. The repository scanner reads source, hashes files and analyzes archive entries without executing third-party repository code. The suite does not run untrusted Git hooks or package installation scripts. The local scanner session URL carries a secret and must not be written into logs. Remote repository scans still need a network connection to GitHub/Bitbucket. The W.H.I.T.E. module's offline dependency scanning requires a local OSV cache.

The Windows quarantine system is user-scoped and cannot offer kernel-level malware isolation; do not disable Microsoft Defender or other existing protections. Files reported as suspicious are not automatically proven infected. Destructive actions require explicit confirmation.

### Source provenance

- `scanner/`: OTS's independent Go malware scanner source (formerly v2.5)
- `modules/OTS_WHITE`: Git submodule containing the original OTS W.H.I.T.E. source
- `modules/OTS_System_Sanitizer`: Git submodule containing the original System Sanitizer source
- `src/OTSSecuritySuite.Desktop/`: new native suite shell
- `extension/`: locally launched repository scanner extension
- `installer/`: Inno Setup packaging

See [BUILD_BLUEPRINT](docs/BUILD_BLUEPRINT.md), [PROJECT_STATUS](docs/PROJECT_STATUS.md), [TEST_EVIDENCE](docs/TEST_EVIDENCE.md) and [RELEASE-GATES](docs/RELEASE-GATES.md). An automated Windows CI installer launch/close and uninstall smoke **passed** for the draft branch; independent Win10/Win11, Chrome, quarantine/restore and malware corpus acceptance has **not** passed. No final publisher-signed release is available.

### Draft branch build evidence — 2026-11-11 HST

- Code commit `59243e6b15c6`, [GitHub Actions run 43172812782](https://github.com/ohanatechsolutions/OTS_Security_Suite/actions/runs/43172812782): **success** for Go tests/vet, 95 rule/12 category assertions, WHITE executable synthetic success/incomplete tests, 8/8 Windows process cancellation/timeout tests, Sanitizer smoke, WPF desktop build and launch/close, installer PE/hash/URI/uninstall.
- Generated Inno Setup SHA-256: `389DBCFE20AE5CB29EAA4F17B5360DEF0DD14841FA4DE7F767301289AFABF092` for `OTS-Security-Suite-Setup-x64.exe`. **Not uploaded/published from the PR**.
- Chrome extension uses `activeTab` only and has no permanent host permissions. Manifest/JS checks passed in CI; clean Chrome profile testing remains.
- UI startup default is 1300×800 DIPs clamped to work area, but human DPI/taskbar verification still required.
- Go scanner count refers to 95 regex heuristic rules across eight categories plus four built-in detection categories; the count is not a guarantee of malware detection quality.
- **Status: integration beta, NOT approved for public release.** Existing standalone tools and encrypted quarantine remain preserved.

### Historical engineering candidate

Source `a2f39b812e61116ecaa3f4813909b662d4149224` adds true RepoScan cancel propagation; local API origin/connection/resource-limit tests; current-and-legacy encrypted quarantine registry, precise destruction-review authorization; JSON report contract checks; stable Windows taskbar AppUserModelID; PNG transparency pixel check; installed extension and license notices; WPF UI Automation; and patched Go 1.27.4. [Current Windows CI](https://github.com/ohanatechsolutions/OTS_Security_Suite/actions/runs/43189027296) **PASSED** at docs head `de277e5fa3bb2d7e1bd8b2aac362a3d9e74ff916` with 15/15 audit/vault tests, real WPF synthetic UI, logo alpha verification, Go security tests, installer/URI/uninstall and preserved vault data. Installer SHA-256 `8872BB5E2039C7B5F6AA13EA7AC52276CB22C80AA88B00FCDEE6271B5BC1C929` (CI-only, unsigned). No installer artifact from this draft PR is uploaded or released; manual Win10/11, Chrome and signing gates remain open.
