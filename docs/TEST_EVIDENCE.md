# OTS Security Suite — Test Evidence (actual results only)

**Updated:** 2026-11-11 (Pacific/Honolulu)  
**Baseline main commit:** `d45de9592345e0b43acda4226004d72e2a181195`  
**Active branch:** `work/white-audit-lifecycle-and-blueprint-20261111`  
**Environment available in chat:** Linux x86_64 container, Python 3.13.5, Git 2.47.3, Go installed, Node 22; **no .NET SDK, Windows GUI or direct GitHub DNS**. GitHub connector has read/write access.

## Recorded evidence

| ID | Requirement | Tool / method | Observed outcome | Status and scope |
|---|---|---|---|---|
| E-001 | M0 | GitHub connector read `main` repository metadata/tree/files | `main@d45de9592345...` has WPF native host, Go scanner, submodule links to WHITE and Sanitizer, Inno installer, extension, workflow | PASS — **repository inspection only** |
| E-002 | REQ-011 baseline | GitHub REST `GET /actions/runs?per_page=5` | Run [#7](https://github.com/ohanatechsolutions/OTS_Security_Suite/actions/runs/43132451936), commit `d45de959...`, `conclusion=success`, 2026-11-12 01:13:21 UTC | PASS — **previous main-branch configured Windows CI incl. build/installer/engine session smoke only**; not tested against feature branch |
| E-003 | M1 code present | GitHub connector updates and content guard checks | `MainWindow.xaml.cs` gained `CancelWhiteAudit`, linked deadline/cancel token, child kill on close, stale-report clear, 16 Mi-character stdout and 128 Ki-character stderr limits, JSON object verification, and no display of raw stderr; XAML has wired `WhiteCancel` button | PASS — **static source change**, NOT Windows compile or runtime |
| E-010 | REQ-006 static wiring | GitHub connector fetched branch XAML/C#; checked 22 XAML event-handler names against C# and 7 cancellation/privacy code guards | 22/22 handlers have code references; 7/7 guards true | PASS — **static contract inspection only** |
| E-011 | REQ-005 JSON format contract | Read pinned W.H.I.T.E. submodule commit `5328f276` CLI/reporting | `--format json` returns `json.dumps(report.as_dict())`, object-valued report; exit 0/1/2 based on clean/findings/incomplete | PASS — **source contract inspection only** |
| E-004 | Tool limitation | `timeout 9 git ls-remote https://github.com/ohanatechsolutions/OTS_Security_Suite.git HEAD` in Linux | `Could not resolve host: github.com` | BLOCKED — local clone unavailable; GitHub connector used instead |
| E-005 | REQ-006/017 | Windows integration: start long-running W.H.I.T.E., click Cancel, inspect child process tree, retry, close window | **NOT RUN** — Windows test host unavailable | BLOCKED |
| E-006 | REQ-011/016 | Current branch Windows build/install/uninstall/upgrade, PE header SHA-256, signing verification | **NOT RUN** — no authorized run on this branch / Windows host | BLOCKED |
| E-007 | REQ-003/004/014 | Go fixture corpus / rule category coverage / archive fuzzing | **NOT RUN for current branch** | NOT RUN |
| E-008 | REQ-005/007/008/009/010 | W.H.I.T.E. + Sanitizer cross-module VM end-to-end, encrypted quarantine restore | **NOT RUN** | NOT RUN |
| E-009 | REQ-001/002/012/013 | GUI DPI, WebView2, custom protocol/Chrome, privacy/security verification | **NOT RUN** | NOT RUN |

**Important:** Source changes E-003 do not make REQ-006 VERIFIED. Passing baseline CI E-002 cannot be carried forward as verification of later unbuilt commits. The Go count/heuristic labels, malware classifications, GUI icon, and signature have not been independently validated in this session.

## Windows acceptance procedure for M1 / TEST-006 + TEST-017

1. Check out current review branch with recursive submodules; record exact commit SHA and `git status --short`.
2. On Windows 11 x64 (then Windows 10 x64), run `dotnet build src/OTSSecuritySuite.Desktop/OTSSecuritySuite.Desktop.csproj -c Release`; record errors and exit status. Run the existing workflow's build/test equivalents only under approved cost arrangements.
3. Run WPF suite; capture suite PID and Go process PID; start W.H.I.T.E. against a disposable synthetic local Git repository. Confirm "RUN" disabled and "CANCEL" enabled while running.
4. Click Cancel; verify UI says cancelled (not successful), W.H.I.T.E. PID and descendants exit within target (proposed ≤5 s), re-run works, previous report cannot be exported.
5. Force a long audit/timeout in a controlled test harness; verify process tree reaped after 12 minutes or a test-injected shorter deadline (never modify production timeout solely to make a CI test pass).
6. Close window mid-audit; verify neither W.H.I.T.E. nor its children remain; Go engine also exits. Test deny/failed startup and expected cleanup.
7. Include stdout/stderr under bounded synthetic flood and one stderr line that resembles sensitive data; ensure no unredacted data is displayed, exported, logged or uploaded.
8. Retain sanitized process/PID report and screenshots of Windows state; update this file with command, OS build, artifact hash and PASS/FAIL. A human verifies the complete user journey.

## Release blocking verification inventory

| Test ID | Target | Status |
|---|---|---|
| TEST-001 | WPF/taskbar titlebar logo and DPI sizing | NOT RUN |
| TEST-002 | Go ephemeral session, WebView2 navigation and exit | baseline CI only; full test NOT RUN |
| TEST-003 | Repo/file/folder/archive E2E and abusive inputs | NOT RUN |
| TEST-004 | 95-rule/12-category mapping + meaningful fixtures | NOT RUN |
| TEST-005 | W.H.I.T.E. real secrets/SAST/history/offline SCA | NOT RUN |
| TEST-006 | Cancel/timeout/close and stale export | NOT RUN |
| TEST-007 | Quick/Deep/Defender permissions | NOT RUN |
| TEST-008 | DPAPI quarantine + restore across old versions | NOT RUN |
| TEST-009 | Investigate/review/destroy confirmation and denial | NOT RUN |
| TEST-010 | Cleanup select/partial failures/denial | NOT RUN |
| TEST-011 | Real Windows installer + upgrade/repair/uninstall | baseline CI smoke only; full test NOT RUN |
| TEST-012 | Chrome extension + custom protocol clean install | NOT RUN |
| TEST-013 | Local data/secret leak/egress controls | NOT RUN |
| TEST-014 | Inventory, skipped and truncated verdict correctness | NOT RUN |
| TEST-015 | Report export/invalid/empty/cancel states | NOT RUN |
| TEST-016 | Signing, PE, hash and release decision | NOT RUN |
| TEST-017 | No surviving spawned scanner/auditor after close | NOT RUN |

**NO-GO:** There is no verified production release. No external security certification is claimed.
