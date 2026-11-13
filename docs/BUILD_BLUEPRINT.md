# OTS Security Suite — Build Blueprint (working specification)

**Project:** OTS Security Suite (Ohana Tech Solutions)  
**Repository:** `ohanatechsolutions/OTS_Security_Suite`  
**Baseline inspected:** `main@d45de9592345e0b43acda4226004d72e2a181195`  
**Date:** 2026-11-11 (Pacific/Honolulu)  
**Status:** DRAFT — implementation/release evidence tracked separately in `PROJECT_STATUS.md` and `TEST_EVIDENCE.md`.  
**Source standards:** `01_AI_WORKFLOW_AND_GOVERNANCE.md` first; relevant sections of sources 02–05, especially 05 §08.01, §08.03, §08.06 and §08.07.

## 1. Product definition and boundaries

**Problem:** Existing OTS tools split repository malware heuristics, code/secrets auditing and Windows threat/cleanup tasks into disconnected applications. The target product gives Windows users one controlled entry point without rewriting or destroying the working scanners.

**Audience / jobs-to-be-done:** (1) Windows owners/operators inspect local files, Windows threats and cleanup candidates; (2) source maintainers scan URLs, worktrees, archives and security configuration; (3) security operators review, export, quarantine, restore and explicitly remove selected items. Owner/publisher: Ohana Tech Solutions.

**Confirmed requirements from previous user decisions:** Integrate RepoScan / OTS GitHub Malware Scanner, OTS W.H.I.T.E., and OTS System Sanitizer; keep the separate applications while validating integration; native Windows .exe + installer; official white-on-transparent Ohana logo and supplied icon for title bar/taskbar; dark near-black/neon-green suite styling; scan with URL/path/folder/file inputs; retain 95 detection rules and 12 categories as independently testable claims; full inventory counting vs actual depth of analysis; protect quarantine and legacy data; child scanner must terminate when suite closes; Windows 10/11 x64; no subscription or paid service required; no silent or irreversible remediation.

**Reversible working assumptions:** Keep existing WPF/.NET 10 shell, Go engine, Python W.H.I.T.E. executable and .NET Sanitizer core, rather than porting everything to Python. Keep embedded WebView2 for the Go scanner until it is tested. Retain the existing four navigation modules. English UI is V1 locale; future localization should not be blocked by hard-coded logic. Default sizing should be centered and adapt to available screen; candidate preferred default 1300×800 DIPs, subject to owner approval and Windows DPI testing.

**V1 scope (must work before READY):**
- Repository Security: public GitHub/Bitbucket URL scans; local directory, folder-upload and single-file scans; safe bounded archive/binary/text inspection; 95-rule inventory; accurate scanned/skipped/truncated counts; review/export reports.
- Code & Secrets Audit (W.H.I.T.E.): local repository audit, optional history and offline SCA (requires explicitly supplied OSV cache); redacted output; failure states; user cancellation and automatic process cleanup.
- Windows Security (Sanitizer): Quick/Deep, Defender integration, inspect selected findings, reviewed quarantine, restore, and safe destruction only with explicit confirmation.
- Space Recovery: discover, select and confirm deletion of cleanup candidates; report per-item failures, never auto-delete.
- Packaging: native window/taskbar/icon, optional Chrome extension with minimal permissions, per-user installer/uninstaller and reliable shutdown, real SHA-256 and verified install/upgrade.

**Not V1 promises:** guaranteed perfect detection; kernel antivirus or firewall replacement; automated remediation without approval; commercial cloud scanning or cloud AI; multi-user cloud SaaS; privileged system service; automatic update network service; cross-platform installers. Keep enhancements in backlog, not fake controls.

**Success / release criteria:** All P0 flows pass on a clean Windows 10 and Windows 11 x64 test installation; no known blocker/critical/high exploitable security gaps; 95-rule/category inventory reconciles with implementation; no legacy quarantine data loss; all long-lived processes stop after cancellation/window close; actual installer/uninstaller/repair and icon behavior verified; accurate partial-scan reporting; accessibility, performance and antivirus/SmartScreen results recorded; distribution signed using an authorized publisher identity or treated as unsigned non-public preview pending explicit risk acceptance. None of these is assumed PASS.

## 2. User journeys and interface/state contract

| Screen / ID | Main journey | Empty, pending, error, cancel and recovery behavior |
|---|---|---|
| `SCR-01 Repository Security` | Choose repo URL / local path / folder upload / file upload → validate → begin scan → see inventory, rule hits and partial coverage → inspect/export | No input disables/safely rejects scan; network absence affects only URL; progress and cancellation; rejected upload/path and malformed archive reported; do not mark truncated scans CLEAN |
| `SCR-02 Code & Secrets Audit` | Browse local Git repo → select history/SCA → run → read redacted results → export JSON | Missing folder/engine/cache yields actionable failure; disable duplicate run; Cancel Audit terminates child; timeout and window close terminate child; failed run clears stale export; save dialog cancellation makes no file |
| `SCR-03 Windows Security` | Quick/Deep scan or Defender request → findings → investigate → confirm quarantine | Scan pending/progress/cancel; inaccessible paths counted, not treated as safe; permission denial reported; unauthorized locations not mutated |
| `SCR-04 Quarantine & Cleanup` | Review vault → investigate selected → restore or explicitly destroy; discover temp candidates → multi-select → confirm | Empty state explains no findings; restore conflict/locked file preserves vault entry; only reviewed items destroy; cancel/no selection never deletes; show partial cleanup failures |

Navigation is left-side modules with a persistent local-first/privacy indicator. Use real focus styles, keyboard traversal, readable text, screen-reader labels, high-DPI reflow and windows sized to work at 100–200% display scaling. No fake success controls, no silent permission grants, and no destructive action on a scan result alone.

**State transitions:**
- Audit: `IDLE → VALIDATING → RUNNING → COMPLETED | FINDINGS | INCOMPLETE | FAILED | CANCELLED | TIMED_OUT`; `RUNNING → CANCELLING → CANCELLED`. Only `COMPLETED/FINDINGS/INCOMPLETE` with valid JSON may enable report export; distinguish incomplete from clean.
- Quarantine: `DISCOVERED → INVESTIGATED → QUARANTINED → REVIEWED → RESTORED | DESTROYED`. Destroy requires separate affirmative confirmation. Restoration conflicts halt safely.
- Scan engine: `STOPPED → STARTING → READY → STOPPING → STOPPED` or `FAILED`; closing WPF must close its spawned engines. The full legacy Sanitizer GUI is intentionally an independently launched specialized window.

## 3. Requirements, inputs and acceptance (priority / planned test)

| ID | Priority | Input / validation / result and acceptance criterion | Planned evidence |
|---|---|---|---|
| REQ-001 | P0 | Launch native suite (not Chrome app); centered responsive window shows official embedded logo and .ico in window/taskbar; functionally navigable tabs | TEST-001 clean Windows UI/icon/DPI |
| REQ-002 | P0 | Spawn Go engine on random loopback-only port; reject non-loopback navigation, origins and popups; closing host terminates child | TEST-002 session, origin/host, shutdown |
| REQ-003 | P0 | Accept authorized URL/local folder/upload and validate; never execute repository code; produce findings and truthful partial inventory | TEST-003 benign/malicious fixtures, malformed/oversize, offline |
| REQ-004 | P0 | Verify implemented 95 heuristic rules / 12 categories; show scope and limits; no zero-risk guarantee | TEST-004 count/category/fixture mapping |
| REQ-005 | P0 | Local W.H.I.T.E. audit produces redacted JSON with explicit result codes, optional history and optional offline SCA; missing cache is INCOMPLETE, not clean | TEST-005 W.H.I.T.E. smoke/negative |
| REQ-006 | P0 | Cancel/12-minute timeout/window close stops W.H.I.T.E. process tree; one concurrent audit; stale report never exported | TEST-006 GUI process lifecycle, timeout, cancellation |
| REQ-007 | P0 | Quick/Deep system inspections report inaccessible files and progress; Defender invocation must report permission failures | TEST-007 Windows standard/non-admin |
| REQ-008 | P0 | Investigate then quarantine selected allowed file using existing encrypted per-user format; restore without overwriting newer user data | TEST-008 disposable VM and legacy vault |
| REQ-009 | P0 | Destroy only explicitly reviewed quarantined item after separate user approval; no accidental system-path deletion | TEST-009 negative and rollback |
| REQ-010 | P0 | Discover cleanup candidates, select explicitly, confirm delete, report per-file errors; browser caches are opt-in | TEST-010 synthetic temp files |
| REQ-011 | P0 | Build genuine Windows x64 binaries, bundle assets/dependencies; clean install/start/uninstall and preserve existing standalone installations/data; hash output | TEST-011 CI package/VM install |
| REQ-012 | P1 | Extension requests minimal permissions and launches `ots-security://scan?url=` securely; rejects unexpected/untrusted URLs | TEST-012 Chrome clean-profile |
| REQ-013 | P0 | No secret values/repo source contents in telemetry or unexpected network egress; no automatic paid integrations | TEST-013 privacy and outbound network |
| REQ-014 | P0 | No falsely CLEAN result on truncated/incomplete/error scans; numeric coverage reconciles inventory | TEST-014 partial/large inputs |
| REQ-015 | P1 | Redacted manual export/import of reports has explicit user-selected path, safe filename and cancellation behavior | TEST-015 report roundtrip and cancel |
| REQ-016 | P0 | Signed publisher release requires owner authorization; unsigned preview is clearly labelled and not declared public ship-ready | TEST-016 signature/release record |
| REQ-017 | P0 | Critical child processes must be stoppable, bounded and not survive normal suite shutdown | TEST-017 child-process inventory on Windows |

**Given / When / Then acceptance samples:** Given a normal Windows user starts the suite, when they run a local folder scan offline, then a report names files inventoried, actually examined, skipped and reasons and does not run untrusted code (REQ-003/014). Given an audit is running, when Cancel Audit is activated or the suite closes, then the audit process and descendants exit within the agreed threshold and no stale report is exportable (REQ-006/017). Given a quarantined item has not been reviewed, when Destroy is invoked, then nothing is removed; given it has been reviewed but confirmation is denied, then nothing is removed (REQ-009).

## 4. Nonfunctional requirements and measurements

- **Platform:** Windows 10/11 x64 user install; .NET 10 and WebView2 dependencies, Go/Python worker builds. Confirm runtime/OS compatibility on actual machines; do not infer from target framework.
- **Security:** least-privilege per-user installation; local-only HTTP with strong random session, strict same-origin and host checks; scanner inputs treated as data; no elevation for ordinary scans; separate confirmation for privileged/destructive operations.
- **Privacy/data:** local-first; public-remote repo fetch only after user action; any reports stored locally with user access, no upload/analytics by default; sanitization of finding strings and diagnostics; explicit export only. Quarantine remains encrypted user-scoped with unchanged legacy vault format. Owner-controlled retention/removal to be documented and tested.
- **Reliability:** duplicate runs refused; timeout and cancellation; incomplete scans and parser failures surfaced with reason; no child orphan after normal close. Candidate target for cancellation process exit ≤5 seconds on reference Windows hardware; measure, don't assert.
- **Performance target (proposed, not measured):** UI interactive ≤5 seconds after startup excluding engine warmup; benchmark scan CPU/RAM and large repositories before final SLO acceptance. No indefinite recursion or unbounded upload size.
- **Accessibility:** keyboard-only primary flows and visible focus; screen-reader names/status; high DPI at 100/150/200%, window resize/overflow tests. English first, localization backlog.
- **Cost:** no paid hosted services/APIs, no subscription, no automatically enabled paid CI. Signed release credential/certificate purchase requires explicit owner approval.

## 5. Architecture, trust boundaries and data contracts

```text
Windows user (untrusted files / URLs)
   → WPF shell: UI, explicit confirmations, bounded worker lifecycle
     → WebView2 (loopback-only) → Go scanner process : ephemeral 127.0.0.1 + random cookie
        → read-only local paths OR deliberate public GitHub/Bitbucket fetch
        → local JSON reports in user config directory
     → W.H.I.T.E. CLI subprocess : bounded stdout/stderr + cancel/kill
        → local repository; optional Git history; optional offline OSV
        → redacted JSON displayed / explicit file export
     → Sanitizer .NET Core services : inspection, Defender adapter, cleanup
        → DPAPI encrypted quarantine vault and legacy user data
   → Separate original Sanitizer GUI when explicitly invoked
Chrome MV3 extension → allowlisted custom URL → installed WPF shell
```

**Actual directories:** `src/OTSSecuritySuite.Desktop` (WPF), `scanner/internal/engine` and `scanner/internal/desktop` (Go), `modules/OTS_WHITE` and `modules/OTS_System_Sanitizer` (pinned submodules), `extension`, `installer`, `tools`, and `.github/workflows`. Do not rewrite the original apps or move vault paths without a reversible migration. Existing framework compatibility must be inspected before redesign.

**Current contract examples:** Go process invoked with `--no-browser --ephemeral --print-url`, emits a one-time `OTS_SCAN_URL=http://127.0.0.1:port/?t=...` to parent stdout, then authenticates local UI using HttpOnly SameSite cookie. Never log that token. W.H.I.T.E. receives folder path and `--format json`, optional `--history`, `--no-sca` when offline CVE scan not requested; observed contract exit codes 0=no threshold findings, 1=findings, 2=incomplete. Any other exit is failure; timeout/cancel are not success. Sanitizer uses existing interfaces and DPAPI vault. Persist scan reports as JSON with explicit schema version for future migration (versioning is future work, not currently verified).

**Failure/rollback:** keep the working standalone products; prefer feature branch/PR; installer is a separate AppId, never force-overwrite standalone apps. Reinstall last independently verified artifact if the suite fails. Preserve user reports and quarantine on uninstall until owner chooses explicit deletion. Rollback and upgrade must be tested.

## 6. Threat model / cost / ownership

| Threat | Boundary / impact | Control and release test |
|---|---|---|
| TH-001 | Malicious local web page tries to call privileged loopback scanner | random session + origin/host guard + browser navigation restrictions; TEST-002 |
| TH-002 | Crafted URL/archive/zip bomb/symlink attempts access or DoS | input allowlist/limits, no execution, traversal & reparse tests; TEST-003/014 |
| TH-003 | False-positive causes irrecoverable user-file removal | read-only findings, review, encrypted quarantine, independent confirmation; TEST-008/009 |
| TH-004 | Child survives UI or consumes CPU indefinitely | cancellation, deadline, kill process tree, test normal/error/close; TEST-006/017 |
| TH-005 | Secrets or personal paths leak through raw CLI stderr, report or export | redact/minimize output, local-only storage, opt-in export; TEST-005/013 |
| TH-006 | Compromised dependency, unsigned binary or stale pinned module | pin submodules and dependencies, SBOM/license scan, Windows signature verification; TEST-011/016 |
| TH-007 | Partial or failed scan presented as clean | explicit skipped/truncated/errors and incomplete verdict; TEST-014 |
| TH-008 | User loses encrypted legacy quarantine due to migration | no automatic migration/deletion, isolated backup/restore test; TEST-008/011 |

**Key third parties:** GitHub/Bitbucket only for explicitly requested remote snapshot fetch; Microsoft Windows Defender, WebView2/.NET; Go/Python tools; optional offline OSV cache. Check license and maintenance before redistribution. Hosting, subscriptions and cloud AI are N/A for current offline desktop V1. Always obtain owner approval for spending, public publication, broad system scanning on third-party machines, deletion of real data, signing identity acquisition and privilege elevation.

## 7. Delivery roadmap and evidence gates

| Milestone | Slice / dependencies | Gate |
|---|---|---|
| M0 | Reconcile actual repo, submodule commits, current CI; record this blueprint/status/evidence | files exist on review branch; state is truthful |
| M1 | REQ-006/017: W.H.I.T.E. cancellation/timeout/shutdown with real Cancel UI | targeted Windows manual/automated child-exit test; current code change alone remains IN PROGRESS |
| M2 | REQ-003/004/014: representative Go repository/file fixtures, coverage semantics and parser hardening | Go unit/integration and realistic bad/benign fixture results |
| M3 | REQ-005/007/008/009/010: cross-module Windows tests, vault/restore/cleanup safeguards, normal/denied user | disposable VM integration + legacy vault recovery |
| M4 | REQ-001/002/012/013/015: titlebar/taskbar branding, WebView2/extension/URI lifecycle, privacy | Windows and Chrome UI/security/keyboard tests |
| M5 | REQ-011/016: packaging, clean install/upgrade/repair/uninstall, signature, hash, rollback, owner UAT | authorized GO decision and evidence; no automatic publish |

**Requirement-to-test ownership:** each REQ listed in §3 maps to its TEST ID. Code paths only enter VERIFIED when practical E2E + negative-path checks pass on supported Windows environment with commit, date, tester and evidence. CI green is narrower than user acceptance.

## 8. Open decisions and applicability

**Needs explicit owner approval:** public release or new paid signing certificate; any change to quarantine format/installation data retention; changing the existing Windows platform or rewriting engines; destructive scanning/cleanup of real files during acceptance; whether the Chrome extension ships in same release. No approval inferred from “build everything.”

**N/A for this V1:** mobile app store, payment gateway/recurring billing, cloud SaaS/tenant separation, AI agent/LLM task execution, IoT/firmware, server fleet backup, cloud production deploy. Justification: local-first Windows security utility with optional browser companion. Windows desktop, browser extension, offline, and security-system addenda **do apply**.

**Known unresolved design risks:** W.H.I.T.E. audit stdout memory bound and stderr redaction; Windows hardware/OS runtime QA; scanner partial coverage; user-scope permissions; legacy vault restore; signing and SmartScreen; external tooling/source licenses. Do not present these as solved by this document.
