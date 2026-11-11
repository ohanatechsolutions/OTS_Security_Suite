# OTS GitHub Malware Scanner — Local Deep Inspection v2.0.0

**Publisher / project:** Ohana Tech Solutions (OTS) · **Platform:** Windows 10/11 x64 · **Release:** unsigned, testing recommended

This is an **independent OTS application**, NOT ScanRepo's original application, backend, ruleset, trade dress, or an exact clone. The public ScanRepo website is not required for local operation.

## Install and use

1. Download `OTS-GitHub-Malware-Scanner-v2-Setup.exe` from this release, or build from source. Compare its SHA-256 hash with `release/SHA256SUMS.txt`.
2. The EXE installs the application per user to `%LOCALAPPDATA%\Programs\Ohana Tech Solutions\GitHub Malware Scanner`. No administrator access is designed to be required. The app creates desktop and Start menu shortcuts and an Installed Apps uninstaller.
3. Open **GitHub Malware Scanner** from the shortcut. The standalone scanner EXE starts a local service on `127.0.0.1:48728` and opens a Chrome app window when Chrome is available. A default-browser fallback is supported. The browser displays an offline-served frontend; the scanner engine is not a hosted website.
4. Choose: public GitHub/Bitbucket URL; a full local path to one file or a folder; a browser-selected local folder; or browser-selected individual files. Click Scan.
5. Review the **file coverage audit**. Every discovered top-level regular file is counted: *complete baseline*, *partial*, or *uninspected*, with a reason. Export the JSON report for the full manifest (the UI previews a maximum of 200 matching records).
6. Local files never need to be sent to ScanRepo.dev or other cloud scanners. Public-repository scans need access to GitHub or Bitbucket to download an archive snapshot. Reports are saved locally under `os.UserConfigDir()` / `Ohana Tech Solutions/GitHub Malware Scanner/reports`.

**Windows warning:** EXEs here have **no Authenticode code signature** and have not been installation-tested on Windows in this environment. SmartScreen may show **Windows protected your PC**. A declared Publisher string in Windows Installed Apps is not publisher verification. Audit, validate checksums, run Defender, test in an isolated VM, and acquire a trusted OTS code-signing identity before distributing to others.

## New in 2.0

- **No source-extension allowlist.** Discover and baseline-inspect text, dotfiles, unknown extensions, binaries, images, documents, scripts and other regular files.
- Detect file identity using magic bytes, not extension alone, with unusual extension/signature mismatch and possible embedded executable indicators.
- **95 original text-pattern heuristic rules**, plus structure/signature checks, EICAR test string detection and basic binary-import heuristics. Rules are not validated malware signatures and no performance guarantee is implied by their count.
- Examine printable 8-bit and UTF-16 (big- and little-endian) strings in binary content.
- Parse supported ZIP/TAR/GZIP archives recursively without extracting to disk or executing contents. Flag unsafe archive paths, links, encrypted entries, VBA macro project entries and extraction limits.
- Parse PE/ELF/Mach-O headers with Go's standard library. Flag combinations of sensitive Windows imports; this is NOT a complete binary reverse-engineering or decompilation engine.
- Per-file SHA-256 hashes, actual detected type, bytes/size, inspection methods, complete/partial/uninspected state, and structured reasons. Prefix-only hashes are clearly labeled for partial scans.
- Analyze Windows local files **or folders** and browser-selected files or folders. Security-sensitive source excerpts are intentionally omitted from exported reports to reduce accidental secret disclosure.
- Warn on Git LFS pointer files and Git submodule configuration. **Actual LFS objects, submodule contents, and historical Git commits are not fetched automatically** by source snapshot scans.
- Chrome extension links the current public GitHub/Bitbucket repository to the locally running OTS app; it does not scan independently.

## Resource limits and realistic coverage

Safety limits: 25,000 entries considered for full analysis, 16 MiB full-content per-file limit, 384 MiB aggregate analyzed bytes, 60 MiB compressed remote archive, 4 nested archive levels, 192 MiB expanded bytes per archive, 240 MiB browser upload, maximum 2,500 findings and 50,000 detailed coverage records. Oversized or locked content is **never silently called clean**: it is marked partial or uninspected. The uninspected count may include symlinks or special files, which are not followed or executed.

**100% of the 12 files in the `keyboard-lock` sample layout pass the automated top-level inventory and baseline-analysis regression test.** That test uses synthetic fixture data matching the file names/types, rather than asserting that every bytes of the live GitHub repository have been examined. A live scan depends on the fetched snapshot and resource limits.

**Important security distinction:** Baseline examination means bytes were read, typed, hashed, and checked with available heuristics. It does **not** guarantee full semantic parsing, safe behavior or detection of all malware. Unsupported complex formats (e.g., RAR, 7z, protected Office files, OLE internals, some media) get universal signature/string inspection, but not all embedded content can be extracted or interpreted. Encrypted archives, highly specialized formats, vulnerabilities, runtime execution paths and novel malware can evade detection. The tool is **not antivirus** and should complement Microsoft Defender, reputation tools, sandboxing, SCA/SAST and human review.

The risk score is an original heuristic, not comparable with ScanRepo scores and not a verification of safety. Incomplete coverage marks a low-risk verdict as `INCOMPLETE ANALYSIS` rather than implying a clean pass.

## Build from source

Requires Go 1.23+; no third-party Go packages or services required to compile.

```powershell
# Windows PowerShell
.\build-windows.ps1
```

```bash
# Linux/macOS cross-compile to Windows AMD64
./build-windows.sh
```

Build results live under `release/`:

- `OTS-GitHub-Malware-Scanner-Setup.exe` — installer
- `OTS-GitHub-Malware-Scanner.exe` — portable program (starts the local engine + UI)
- `OTS-GitHub-Malware-Scanner-Uninstall.exe` — uninstall support
- `SHA256SUMS.txt` — checksums

Verification:

```bash
go test ./...
go vet ./...
node --check internal/desktop/assets/app.js
node --check extension/popup.js
```

## Chrome extension

1. Extract the `extension/` folder (or companion ZIP).
2. Chrome → `chrome://extensions` → Developer mode → Load unpacked → choose `extension/`.
3. Start the Windows desktop scanner first. On a GitHub or Bitbucket repository page, click the extension's button to open the corresponding URL in the **local** scanner.

## Privacy / network access

Local scans open files read-only, do not execute repository code and do not install repository dependencies. The UI is served from loopback with session-token authentication and same-origin POST protections. Browser folder/file uploads go to your own loopback service (not a cloud endpoint). Public URL scanning downloads the current snapshot from approved GitHub/Bitbucket archive endpoints over HTTPS, with redirect host allowlisting. Saved reports can contain file paths and findings; safeguard them accordingly.

## What must happen before a trusted public release

A native Windows installation/smoke test, antivirus and static scan of the binaries, third-party security code review, archive decompression fuzzing, false-positive and malware-corpus validation, verification of supported Bitbucket snapshots, a signed release, and clear support/update processes. See `docs/SECURITY.md` and `docs/RELEASE-CHECKLIST.md`.

**No affiliation with GitHub, Bitbucket, ScanRepo, Microsoft or Google is implied.**

## Desktop window lifecycle

The local engine automatically exits around 6 seconds after its Chrome app window is closed. Closing the window no longer requires using Quit Local Engine. For headless API usage, `--no-browser` intentionally keeps the engine running. Existing tabs outside the launched Chrome window can also send heartbeats; close them to end the session.

## Version 2.4 — Ohana Tech Solutions branding

The desktop app header uses `internal/desktop/assets/ohana-logo.png`, derived from the provided Ohana Tech Solutions white logo with the original black background removed. The unmodified original's geometry is retained, and white shapes are encoded as pixels with alpha transparency.

The Windows executable and installer use the original supplied `bug_shield_icon_aaa_sharp.ico`, copied to `branding/OTS-GitHub-Malware-Scanner.ico`. `tools/embed_pe_icon.py` injects the icon group into the PE resource section when building with `build-windows.sh` (Python 3) or `build-windows.ps1` (`py -3` installed). The Windows shortcut references that icon as well. The Chrome extension and browser favicon use PNG renditions of that same icon.

For upgrades: close existing scanner processes before running the installer to avoid Windows file-lock and localhost-port conflicts. Windows SmartScreen may still warn because this build is unsigned; branding and icon resources do not constitute a verified publisher certificate.

The 95 detection rules and scan functionality are unchanged from v2.3. Automated tests and cross-compilation are not equivalent to a Windows installation or malware-detection certification.

## v2.5 Branding/Chrome desktop-window behavior

The v2.4 web server incorrectly returned CSS for `/ohana-logo.png`. The v2.5 server now serves the original transparent PNG with the correct MIME type. Favicon and installable Chrome web-app manifest assets are also exposed. Versioned logo/favicon URLs and a versioned Windows shortcut `.ico` path help bypass prior caches.

**Windows taskbar limitation:** The executable contains the supplied icon, and the Windows desktop shortcut uses it. However the GUI is currently a Chrome `--app` browser window, not a native window owned by our executable. Chrome/Windows can display Chrome's taskbar icon or a previously cached PWA icon regardless of the EXE icon. For a guaranteed identical titlebar/taskbar icon, migrate to a dedicated native WebView2 window. Installing the scanner page as a Chrome app and pinning its own shortcut may provide the correct icon, but is not guaranteed on all Windows builds.

If the old app shortcut/taskbar icon persists: unpin the old entry, delete its old shortcut, install v2.5, launch from the refreshed desktop shortcut, and pin the new window. For a Chrome-hosted window, use Chrome's Install page as app option after signing into the local scanner. Do not bypass antivirus detections solely to change an icon.
