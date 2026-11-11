# OTS Security Suite — Integrated Preview 0.9.0

**Ohana Tech Solutions** · Windows 10/11 x64 · Native WPF application with offline/local scan engines

This is the first integrated development build of three OTS projects. It **is not yet approved for public release**. Source is organized for a single Windows installer; it preserves the existing component codebases and quarantine format rather than replacing them with a new unvalidated implementation.

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

You need .NET 10 SDK, Go 1.23+, Python 3.12, PyInstaller, Inno Setup 6, Microsoft WebView2 runtime, and the two Git submodules (both public).

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

See [RELEASE-GATES](docs/RELEASE-GATES.md). This integration has not yet completed a Windows installer acceptance test or independent malware testing.
