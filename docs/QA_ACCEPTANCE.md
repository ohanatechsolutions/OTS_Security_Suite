# OTS Security Suite — Windows acceptance matrix

**Status: TEST PLAN, NOT SELF-CERTIFICATION.** Automated GitHub Windows CI is additional evidence; a CI smoke run does **not** certify a real user environment. Test in disposable Windows VMs or synthetic folders only. Preserve any existing encrypted vaults; no real deletion until specifically authorized.

| Case | Environment | Procedure / expected result | Actual evidence | Status |
|---|---|---|---|---|
| QA-01 / REQ-001 | Windows 11 x64, 100% scaling | Install without admin; startup window centered and 1300×800 if possible, logo white on transparent, title/taskbar/Alt+Tab .ico matches app | — | NOT RUN |
| QA-02 / REQ-001 | Windows 11, 150% and 200%; 1366×768 display | No clipped controls, scroll when needed, buttons keyboard accessible | — | NOT RUN |
| QA-03 / REQ-001/011 | Windows 10 x64 non-admin | Install/launch without developer SDK, WebView2 dependency handled and correct icon | — | NOT RUN |
| QA-04 / REQ-003/004/014 | Offline local synthetic 12-file folder | Inventory 12/12 with per-file SHA-256 and no execution; visibly distinguish partial/uninspected | Go unit fixtures, not installed GUI | IN PROGRESS |
| QA-05 / REQ-003 | Repository URL, network on/off | Approved public root URL works; offline failure clear; branch/path URL refused | Go unit tests only | IN PROGRESS |
| QA-06 / REQ-006/017 | W.H.I.T.E. slow synthetic folder | Click Cancel Audit and close while active, confirm all descendants terminate and old report cannot export | Headless process tests, GUI pending | IN PROGRESS |
| QA-07 / REQ-005/015 | W.H.I.T.E. local Git history and OSV cache | Complete/error JSON states, redaction, export fail-safe and manual save | Packaged and writer tests, GUI pending | IN PROGRESS |
| QA-08 / REQ-007 | Windows quick/deep scan, denied files | Cancel and skipped counters; Defender denied/unavailable handled; no elevation bypass | Sanitizer smoke only | IN PROGRESS |
| QA-09 / REQ-008/009 | Disposable VM with old and current vault items | Both visible, current and legacy restoration succeed, encrypted manifest preserved, no auto-deletion | Synthetic registry test planned | IN PROGRESS |
| QA-10 / REQ-010 | Synthetic old temp files, locked/protected files | Only reviewed selections removed; mismatch/TOCTOU safe, partial failures accurate | Sanitizer smoke, manual pending | IN PROGRESS |
| QA-11 / REQ-011 | Windows 10/11 clean and upgrade | Real signed installer hashes, shortcuts, protocol registration, upgrade, uninstall and user data preservation | CI silent install/uninstall only | IN PROGRESS |
| QA-12 / REQ-012 | Clean Chrome profile | Load reviewed extension, activeTab only, native protocol launches suite, restart/revoke without exposing data | Static manifest test only | IN PROGRESS |
| QA-13 / REQ-013 | Offline network-visibility test | No unexpected private source upload; reports only local; redacted stderr and protected paths | Synthetic stderr test only | IN PROGRESS |
| QA-14 / REQ-003/014 | Hostile-but-harmless archive corpus | Limits on compressed/unpacked bytes, symlinks and paths; incomplete verdict never reported clean | Go synthetic tests, corpus pending | IN PROGRESS |
| QA-15 / REQ-016 | Authenticode publisher-signed approval candidate | Verify signature, timestamp, SHA-256, Microsoft Defender/SmartScreen and updater instructions; rollback trial | No valid signing cert provided | BLOCKED |

**Expected outcome:** Each P0 scenario must be observed on supported real Windows versions. Capture source SHA, installer SHA-256, Windows build number, DPI settings, date/time, sanitized logs/screenshot, PASS/FAIL, verifier and reproducible defect if any. A result remains NOT RUN unless an actual execution is recorded.

## CI execution facts vs human signoff

- See `TEST_EVIDENCE.md` for timestamped automated test logs. The last verified earlier regression passed 10/10 Windows process/export tests on commit `2d752f765373` ([run 43174959907](https://github.com/ohanatechsolutions/OTS_Security_Suite/actions/runs/43174959907)).
- Subsequent RepoScan cancellation, dual-vault and WPF UI Automation source changes are **not** considered verified until their own CI run completes.
- The installer of a **draft pull request is intentionally not uploaded or published**, even if the workflow succeeds.
- Independent GUI testing of the actual Chrome extension and user-specific SmartScreen reputation requires an approved test environment and responsible owner signoff.

## Owner acceptance

| Role | Reviewer | Date | Decision | Evidence / exceptions |
|---|---|---|---|---|
| Product owner | — | — | PENDING | — |
| Security reviewer | — | — | PENDING | — |
| Windows QA reviewer | — | — | PENDING | — |
| Release / publisher owner | — | — | PENDING | — |

**Release decision:** NO-GO until all release-critical blockers are closed with evidence. N/A: payments, hosted SaaS, mobile, IoT, and AI/LLM components (not part of V1).

**Current actual Windows CI evidence:** [run 43189027296](https://github.com/ohanatechsolutions/OTS_Security_Suite/actions/runs/43189027296) **SUCCESS** for docs head `de277e5fa3bb2d7e1bd8b2aac362a3d9e74ff916` containing executable source `a2f39b812e61116ecaa3f4813909b662d4149224`, with `Audit runner tests: 15/15 PASS`, packaged WHITE success/incomplete contract, 95 scanner rules and Go tests/vet, WPF synthetic navigation and real CLI execution, logo PNG sampled transparency (1563×1563), Inno installer, bundled MIT/license notices, extension files, synthetic vault preservation, URI registration, normal close and uninstall. Installer SHA-256 `8872BB5E2039C7B5F6AA13EA7AC52276CB22C80AA88B00FCDEE6271B5BC1C929` (CI-created, deliberately not uploaded on draft PR). **Automated gates passed; human Win10/Win11, clean Chrome extension, legacy real-user vault, independent security and publisher signing remain NOT RUN / blocked.**

**Accepted automated scope:** 15/15 C# cases, Go security/coverage/cancel tests, installed WPF synthetic UI audit, bundled extension/legal notices, protected test vault canary and PNG alpha PASS. **Human cases QA-01–03, QA-06 mid-audit, QA-08–15 requiring real user interaction, historical data or publisher signature remain IN PROGRESS / NOT RUN.**
