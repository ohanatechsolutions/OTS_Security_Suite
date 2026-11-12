# OTS Security Suite — Test Evidence (actual results only)

**Updated:** 2026-11-11 (Pacific/Honolulu)  
**Baseline main commit:** `d45de9592345e0b43acda4226004d72e2a181195`  
**Active branch:** `work/white-audit-lifecycle-and-blueprint-20261111`  
**Environment:** Chat Linux session has no Windows/.NET GUI; code was tested on GitHub Actions `windows-latest` runner. See exact source SHA and workflow logs below. GitHub connector has repository write access.

## Recorded evidence

| ID | Requirement | Tool / method | Observed outcome | Status and scope |
|---|---|---|---|---|
| E-001 | M0 | GitHub connector read `main` repository metadata/tree/files | `main@d45de9592345...` has WPF native host, Go scanner, submodule links to WHITE and Sanitizer, Inno installer, extension, workflow | PASS — **repository inspection only** |
| E-002 | REQ-011 baseline | GitHub REST `GET /actions/runs?per_page=5` | Run [#7](https://github.com/ohanatechsolutions/OTS_Security_Suite/actions/runs/43132451936), commit `d45de959...`, `conclusion=success`, 2026-11-12 01:13:21 UTC | PASS — **previous main-branch configured Windows CI incl. build/installer/engine session smoke only**; not tested against feature branch |
| E-003 | M1 code present | GitHub connector updates and content guard checks | `MainWindow.xaml.cs` gained `CancelWhiteAudit`, linked deadline/cancel token, child kill on close, stale-report clear, 16 Mi-character stdout and 128 Ki-character stderr limits, JSON object verification, and no display of raw stderr; XAML has wired `WhiteCancel` button | PASS — **static source change**, NOT Windows compile or runtime |
| E-010 | REQ-006 static wiring | GitHub connector fetched branch XAML/C#; checked 22 XAML event-handler names against C# and 7 cancellation/privacy code guards | 22/22 handlers have code references; 7/7 guards true | PASS — **static contract inspection only** |
| E-011 | REQ-005 JSON format contract | Read pinned W.H.I.T.E. submodule commit `5328f276` CLI/reporting | `--format json` returns `json.dumps(report.as_dict())`, object-valued report; exit 0/1/2 based on clean/findings/incomplete | PASS — **source contract inspection only** |
| E-012 | REQ-006/005 current branch static review | Fetched exact current `MainWindow.xaml` and `MainWindow.xaml.cs` via GitHub connector; checked event names, cancellation, safe output guards and invalid exit behavior | 22/22 XAML event names resolved, 10/10 code contract assertions true; XAML blob `69c313f2`, C# blob `d987be3f` | PASS — **static source only**; compilation/integration NOT RUN |
| E-004 | Tool limitation | `timeout 9 git ls-remote https://github.com/ohanatechsolutions/OTS_Security_Suite.git HEAD` in Linux | `Could not resolve host: github.com` | BLOCKED — local clone unavailable; GitHub connector used instead |
| E-005 | REQ-006/017 | Windows integration: start long-running W.H.I.T.E., click Cancel, inspect child process tree, retry, close window | **NOT RUN** — Windows test host unavailable | BLOCKED |
| E-006 | REQ-011/016 | Current branch Windows build/install/uninstall/upgrade, PE header SHA-256, signing verification | **NOT RUN** — no authorized run on this branch / Windows host | BLOCKED |
| E-007 | REQ-003/004/014 | Go fixture corpus / rule category coverage / archive fuzzing | **NOT RUN for current branch** | NOT RUN |
| E-008 | REQ-005/007/008/009/010 | W.H.I.T.E. + Sanitizer cross-module VM end-to-end, encrypted quarantine restore | **NOT RUN** | NOT RUN |
| E-009 | REQ-001/002/012/013 | GUI DPI, WebView2, custom protocol/Chrome, privacy/security verification | **NOT RUN** | NOT RUN |

**Important:** Static source change E-003 alone is not verified; newer E-013..E-021 document Windows CI subprocess and installer checks. No interactive GUI acceptance for REQ-006 has been performed. Passing baseline CI E-002 cannot be carried forward as verification of later unbuilt commits. The Go count/heuristic labels, malware classifications, GUI icon, and signature have not been independently validated in this session.

## E-022 through E-030: unverified source additions (do not mark PASS)

The following additions are **code and test cases present in draft PR #2**, source commit `a2f39b812e61116ecaa3f4813909b662d4149224`. GitHub Actions [run 43188038745](https://github.com/ohanatechsolutions/OTS_Security_Suite/actions/runs/43188038745) was still **queued** when this section was recorded. None of these are falsely promoted to runtime PASS.

| ID | Requirements | What was added | Verification state |
|---|---|---|---|
| E-022 | REQ-003/014 | Go `ScanDirContext`, `ScanRemoteContext`, frontend AbortController/Cancel Scan and upload cancellation | Implemented; Go + GUI cancel regression PENDING |
| E-023 | REQ-002/013 | Auth/session-origin, cross-origin denial, cancellation-no-save and local HTTP timeout Go tests | Test source added; execution PENDING |
| E-024 | REQ-008 | Dual vault registry and synthetic current/legacy DPAPI/AES quarantine+restore test cases | Test source added; Windows execution PENDING |
| E-025 | REQ-009 | Review identity incorporates GUID, exact vault path and SHA-256; list refresh invalidates approvals | C# synthetic regression added; execution PENDING |
| E-026 | REQ-005/015 | WHITE JSON validator checks tool, schema, complete, checks, errors, findings and exit status; cannot mislabel incomplete as clean | C# regression added; execution PENDING |
| E-027 | REQ-001 | Matching AppUserModelID in WPF process and Inno shortcuts, PNG sampled-alpha CI check | Static source and test exist; build/transparency result PENDING; visual taskbar QA NOT RUN |
| E-028 | REQ-011/012 | Chrome extension/license/third-party notice installer staging and canary surviving silent uninstall | Windows install checks added; execution PENDING |
| E-029 | REQ-003/014 | Explicit decompression exhaustion error instead of false TAR end-of-file, including metadata ceiling | Go test added; execution PENDING |
| E-030 | REQ-005/011 | `tools/windows-ui-smoke.ps1` locates installed WPF, navigates source audit, runs harmless one-file WHITE audit, reads JSON | Automation source added; Windows execution PENDING, independent human GUI QA NOT RUN |

**Previous verified pass remains E-013–E-021** at older source `59243e6b15c6` and [run 43172812782](https://github.com/ohanatechsolutions/OTS_Security_Suite/actions/runs/43172812782); the later [run 43174959907](https://github.com/ohanatechsolutions/OTS_Security_Suite/actions/runs/43174959907) passed 10/10 subprocess/report tests for `2d752f765373`. Do not reuse old hashes: the latest candidate's installer SHA-256 is unknown until its CI output is inspected.

## Latest candidate: verified Windows CI results (supersedes old NOT RUN entries below where scoped)

**Evidence source:** [GitHub Actions run 43172812782](https://github.com/ohanatechsolutions/OTS_Security_Suite/actions/runs/43172812782), `windows-latest`, commit `59243e6b15c61203bca39ef9cd95701f09cfa2e9`. Completed **SUCCESS** 2026-11-12 07:11 UTC (2026-11-11 21:11 HST). Workflow step-level success independently checked using GitHub Actions job ID `131029875670` and decoded job logs. The upload-artifact step was **SKIPPED INTENTIONALLY** for draft PR.

| Evidence ID | Requirements | Command / observed output | Scope / result |
|---|---|---|---|
| E-013 | REQ-003/004/014 | Workflow `go test ./...`, `go vet ./...`; scanner 95-rule check and new synthetic TAR size/URL tests | **PASS** Windows CI Go unit and vet; accuracy corpus / external pentest NOT RUN |
| E-014 | REQ-012/013 | `python -m unittest discover -s tools -p 'test_*.py'`, `node --check extension/popup.js` | **PASS** manifest least-privilege and extension syntax; clean Chrome install NOT RUN |
| E-015 | REQ-005 | Pinned WHITE `python -m unittest discover -s tests -p 'test_*.py'`; log reports `Ran 36 tests ... OK` | **PASS** packaged source module tests; external OSV cache scenario NOT RUN |
| E-016 | REQ-005/015 | `OTSWhiteAudit.exe` with synthetic one-file local repository; JSON complete exit=0, and non-Git `--history` JSON incomplete exit=2 | **PASS** executable invocation and expected incomplete contract |
| E-017 | REQ-006/013/017 | `dotnet run --project tests/OTSSecuritySuite.AuditSmoke/OTSSecuritySuite.AuditSmoke.csproj -c Release`; log `Audit runner tests: 8/8 PASS` | **PASS** real process cancellation, timeout, size bounds, stderr privacy, concurrency, unsafe config; GUI click NOT RUN |
| E-018 | REQ-007/011 | Sanitizer smoke and `dotnet publish` WPF and Sanitizer; workflow build steps success | **PASS** build and component smoke; Defender/DPAPI manual paths NOT RUN |
| E-019 | REQ-002/004/011 | Started Go ephemeral local process; authenticated `/api/info` reports 95 rules, valid 200 session | **PASS** local engine session, not adversarial origin test |
| E-020 | REQ-001/002/011/017 | Inno build & install; installed WPF `OTSSecuritySuite.exe` remained running, log `Installed WPF suite stayed alive after launch (PID 4304)`, then `Suite window close and immediate child-process cleanup verified` | **PASS** installed app launch, normal window close and immediate Go child exit on CI; no human visual/icon/Alt+Tab or W.H.I.T.E. close-mid-audit GUI acceptance |
| E-021 | REQ-011/016 | Installer `MZ` PE header check, `Get-FileHash -Algorithm SHA256`, per-user install/URI registration/uninstall cleanup; logged `Installer, bundled modules, icon, URI registration and uninstaller smoke checks passed` | **PASS** CI installer smoke; clean independent Win10/Win11 upgrade/repair and Authenticode signature NOT RUN |

**CI-generated installer SHA-256 (not released):**
```text
389DBCFE20AE5CB29EAA4F17B5360DEF0DD14841FA4DE7F767301289AFABF092  OTS-Security-Suite-Setup-x64.exe
```
The PR deliberately does not publish an artifact. An executable existing transiently on CI does not mean a public or user-accessible installer has been released.

**Real CI failure and fix:** Run [43171854132](https://github.com/ohanatechsolutions/OTS_Security_Suite/actions/runs/43171854132) failed because PowerShell propagated an **expected** WHITE exit status 2 after validation. Code change reset `$global:LASTEXITCODE = 0` **only after** checking JSON incomplete and exit=2; subsequent final candidate CI run succeeded. Do not erase this regression record.

**Still NOT RUN / release blockers:** independent Windows 10/11 fresh install, upgrade/downgrade and repair, signed-publisher provenance, real Chrome extension install, DPI/taskbar visuals, keyboard/screen reader, Defender denied/UAC, legacy encrypted quarantine/restore, cleanup/deletion fail-safe, actual user file false positives, privacy egress and external security review. These remain NO-GO irrespective of successful CI.

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
| TEST-001 | WPF/taskbar titlebar logo and DPI sizing | WPF launch PASS CI; visual and DPI NOT RUN |
| TEST-002 | Go ephemeral session, WebView2 navigation and exit | CI ephemeral session/normal close PASS; adversarial UI security NOT RUN |
| TEST-003 | Repo/file/folder/archive E2E and abusive inputs | Go synthetic TAR/URL tests PASS; wider corpus NOT RUN |
| TEST-004 | 95-rule/12-category mapping + meaningful fixtures | 95-rule/12-category assertion PASS; real accuracy corpus NOT RUN |
| TEST-005 | W.H.I.T.E. real secrets/SAST/history/offline SCA | packaged benign+incomplete contract PASS; full scenarios NOT RUN |
| TEST-006 | Cancel/timeout/close and stale export | 8/8 subprocess smoke PASS; interactive GUI mid-audit NOT RUN |
| TEST-007 | Quick/Deep/Defender permissions | Sanitizer smoke PASS; manual permission paths NOT RUN |
| TEST-008 | DPAPI quarantine + restore across old versions | NOT RUN |
| TEST-009 | Investigate/review/destroy confirmation and denial | NOT RUN |
| TEST-010 | Cleanup select/partial failures/denial | NOT RUN |
| TEST-011 | Real Windows installer + upgrade/repair/uninstall | CI MZ/install/launch/close/URI/uninstall PASS; upgrade/repair/independent Win10/11 NOT RUN |
| TEST-012 | Chrome extension + custom protocol clean install | manifest/JS & Windows URI registration PASS; clean Chrome profile NOT RUN |
| TEST-013 | Local data/secret leak/egress controls | synthetic stderr privacy 8-test suite PASS; full egress NOT RUN |
| TEST-014 | Inventory, skipped and truncated verdict correctness | Go synthetic limit/TAR tests PASS; broad coverage acceptance NOT RUN |
| TEST-015 | Report export/invalid/empty/cancel states | packaged WHITE JSON output PASS; save/export UI NOT RUN |
| TEST-016 | Signing, PE, hash and release decision | PE + hash PASS; signature/release decision NOT RUN |
| TEST-017 | No surviving spawned scanner/auditor after close | CI WPF close-Go exit and WHITE subprocess tests PASS; UI close during WHITE audit NOT RUN |

**NO-GO:** There is no verified production release. No external security certification is claimed.
