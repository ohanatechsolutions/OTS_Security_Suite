# OTS Security Suite — public release gates

Current status: **INTEGRATION PREVIEW, NOT SHIP-READY**.

**2026-11-11 (HST) governance:** Baseline main `d45de9592345` has successful GitHub Windows CI [run #7](https://github.com/ohanatechsolutions/OTS_Security_Suite/actions/runs/43132451936). This is **not** evidence that the M1 feature branch is buildable or user-installable. Current source/requirements, actual checks, and open decisions are recorded in [BUILD_BLUEPRINT](BUILD_BLUEPRINT.md), [PROJECT_STATUS](PROJECT_STATUS.md), and [TEST_EVIDENCE](TEST_EVIDENCE.md).

**Formal release decision: NO-GO.** No owner/publication approval, verified Windows end-to-end integration acceptance, or independently verified publisher signature. Preserve original apps and quarantine; never publish an unsigned beta as a signed public release.

- [x] Review W.H.I.T.E. and System Sanitizer source boundaries
- [x] Preserve the Go scanner engine and 95-rule table (avoid regression from rewrite)
- [x] Native WPF host project and user-supplied Windows .ico and header PNG
- [x] Ephemeral local port and host-managed child engine lifecycle
- [x] Local Go tests, Go vet, extension JS syntax, project manifest/XAML parse tests
- [x] Baseline main `d45de959` GitHub Windows build green with submodules initialized — CI #7 only; see evidence E-002
- [ ] Re-run and review **current release candidate** Windows build and integration checks (this branch NOT RUN)
- [ ] Confirm WebView2 and .NET 10 runtime on clean Windows 11 VM
- [ ] Run an installed app, then close window and verify child engine has exited
- [ ] Verify tray/taskbar/title-bar/Alt+Tab all use the new .ico; no Chrome app window
- [ ] Verify v2.5 repository test fixture and public keyboard-lock snapshot
- [ ] Validate W.H.I.T.E. secrets + SAST + Git history + OSV optional path
- [ ] Validate System Sanitizer Defender invocation, persistence review, quarantine and restore
- [ ] Upgrade from existing Sanitizer without touching encrypted quarantine data or legacy keys
- [ ] Windows installer fresh install/repair/uninstall, shortcuts, custom protocol handler
- [ ] Test custom Chrome extension and URI activation on clean Chrome profile
- [ ] Adversarial file/archive fuzzing, excessive-size handling, symlink/reparse tests
- [ ] Antivirus/SmartScreen review and malware/false-positive corpus validation
- [ ] Independent security review of local WebView2 and embedded secret handling
- [ ] Publisher-verifiable code signing, timestamp and release reproducibility
- [ ] Versioned docs, backup instructions, update policy and signed Release checksums

Never turn an incomplete scan into a clean malware verdict. Neither heuristics nor file coverage guarantee a safe repository. Keep quarantine/destruction explicit, reversible where possible, and audited.


## Mandatory owner approval and platform verification

- [ ] TEST-006 / TEST-017: Cancel W.H.I.T.E., force timeout, close suite during audit, verify no child/descendant remains; inspect any termination failures.
- [ ] Confirm invalid/empty W.H.I.T.E. JSON cannot be exported, audit stderr is not exposed, and output streams are bounded against hostile input.
- [ ] Confirm 95-rule/12-category inventory and accurate partial scan semantics (TEST-004/014); do not imply 100% malware detectability.
- [ ] Confirm local-only HTTP origin, WebView2 pop-up/permission denial, protocol URL allowlist and Chrome clean-profile behavior.
- [ ] Perform non-admin Windows 10/11 tests for vault/restore and explicit deletion denied states, including old Sanitizer vault.
- [ ] Record actual .exe PE headers, architecture, runtime files, hash and real install/repair/uninstall from a clean machine.
- [ ] Approve artifact signing identity (or explicitly accept **private unsigned preview only**) and record product/security/ops human GO before publication.
- [ ] Keep tested prior build and recovery runbook accessible; perform a rollback trial.

**N/A with rationale:** payments/subscriptions, mobile app stores, SaaS production deployment, AI agent/LLM behavior and firmware: no such product components in Windows V1. The Windows desktop, browser-extension, local-first and security utility addenda remain applicable.
