# Operator Guide — OTS Security Suite (pre-release)

This guide describes the **implemented draft**. The app is not authorized for broad distribution until the release gates pass. Never disable Windows security controls just to run a preview.

## Requirements and startup
- Windows 10/11 x64; per-user install; Microsoft Edge WebView2 Runtime is required for the embedded repository scanner.
- The CI-generated installer is unsigned and is **not published** by draft pull requests. Obtain a verified build only from the official approved repository release after signoff.
- Launch `OTS Security Suite` from the Start menu or desktop shortcut. The requested default window size is 1300 × 800 device-independent pixels, reduced when necessary to fit the desktop.
- No login or cloud account is required for local file scans. The embedded scanner binds an ephemeral loopback-only local session; if another app occupies a previous static scanner port, the suite does not reuse that fixed port.

## Repository Security — RepoScan
1. Enter a **root** public GitHub/Bitbucket repository URL, or choose a local path, folder upload or file upload.
2. Click the corresponding scan control; a remote URL fetch requires network access, local folder analysis does not.
3. Use **CANCEL SCAN** if a long scan is no longer wanted. The browser cancels the underlying request; a cancelled run is not saved as a completed report.
4. Inspect the score **and** the coverage details. `complete`, `partial` and `uninspected` describe how much was analyzed. A full file count is not proof of zero malware.
5. Open the history tab or export the structured JSON report if you need local records.

The engine has 95 regex-based heuristic rules in eight families plus additional built-in checks in four categories. Tests verify the counts, not perfect precision or recall. Some formats receive only universal byte/signature checks; archives, Git history, Git LFS, and submodules have practical inspection limits.

## Code & Secrets Audit — W.H.I.T.E.
1. Choose a **local repository directory**.
2. Optionally enable Git history and dependency CVEs. Dependency checks require an intentionally supplied **offline OSV cache**; a missing cache can make the audit incomplete.
3. Click **RUN CODE SECURITY AUDIT**; use **CANCEL AUDIT** for cancellation. The suite prevents overlapping audits and imposes a time and output bound.
4. Read the actual JSON `complete` flag and warnings. Incomplete checks must not be interpreted as a clean source tree.
5. Choose **EXPORT REPORT** to write validated JSON to a selected location. On errors the existing destination is preserved. The UI does not show audit stderr or raw secret strings.

## Windows Security — OTS System Sanitizer
1. **QUICK SCAN** checks selected user-writable locations; **DEEP SCAN** inspects accessible fixed drives. These are read-only heuristics, not a full antivirus engine.
2. **CANCEL SCAN** interrupts ongoing inspection. Review inaccessible paths and skipped counts as possible coverage gaps.
3. **REQUEST DEFENDER SCAN** explicitly invokes the installed Microsoft Defender integration. Antivirus availability, policy and permissions vary by device.
4. Inspect the selected finding before moving a file to encrypted quarantine. Never quarantine Windows system files or execute samples to test the scanner.

## Quarantine & Cleanup
- **QUARANTINE & CLEANUP** shows current OTS System Sanitizer vault items and existing legacy Aegis Prime vault items, if present. Both locations stay intact; no silent migration occurs.
- **REVIEW SELECTED** precedes any **DESTROY REVIEWED** action. Destruction is permanent and should be a last resort; files are not always recoverable.
- **RESTORE SELECTED** attempts to restore to the original user-profile location. Restoration fails safely if the destination is occupied or inaccessible.
- **DISCOVER OLD TEMP FILES** lists eligible files; browser caches require an opt-in checkbox. Only selected files are removed after explicit confirmation. This is permanent deletion, not recycling.
- Never delete or relocate `*.aegq` and manifest files independently. Each item has a protected per-user DPAPI key and an integrity check; preserve both vault directories and the Windows user profile if recovery is needed.

## Local data and privacy
- RepoScan report history: under Windows user configuration data (typically `%APPDATA%\Ohana Tech Solutions\GitHub Malware Scanner\reports`).
- Current encrypted quarantine: `%LOCALAPPDATA%\OTSSystemSanitizer\Quarantine`.
- Legacy encrypted quarantine: `%LOCALAPPDATA%\AegisPrime\Quarantine`.
- WebView2 browser profile: `%LOCALAPPDATA%\Ohana Tech Solutions\Security Suite\WebView2`.
- Manually exported W.H.I.T.E. reports: the location you select in the Save dialog.

Uninstalling the application is **not** a request to erase private reports, profile folders or quarantine. Backup and restore those directories with the corresponding user DPAPI context before changing Windows accounts or reinstalling the OS. The suite has no automatic cloud sync.

## Browser companion — preview only
The unpacked Chrome MV3 extension source is in the installed `extension` directory; the installer does **not** silently install a browser add-on. For a supervised beta, load it only on a test browser profile after reviewing its manifest and code. It uses `activeTab` and opens the installed application via `ots-security://`; it does not contact a fixed localhost port. An approved store-published extension and clean-profile lifecycle test are separate release gates.

## Troubleshooting and limitations
- **Repository pane empty:** check WebView2 Runtime availability; do not bypass browser or OS protections. The Go engine uses a random loopback port.
- **Offline remote repo failure:** use a local folder; public URL downloads need GitHub/Bitbucket connectivity and respect rate limits.
- **W.H.I.T.E. incomplete:** inspect the report `errors`/`checks`, Git history availability and offline dependency cache.
- **Protected file cannot be inspected:** a partial report is safer than forcing privileges or changing access controls.
- **Taskbar shows an old icon:** remove an obsolete pin from the previous standalone program; verify a current install's signed provenance before repinning.
- **False positives:** review the rule, original context and independent Defender result. No heuristic score alone authorizes deletion.

Report reproducible, sanitized bugs to the repository maintainers. Release readiness: `PROJECT_STATUS.md`, `QA_ACCEPTANCE.md`, `TEST_EVIDENCE.md` and `RELEASE-GATES.md`.
