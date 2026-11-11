# OTS Security Suite — public release gates

Current status: **INTEGRATION PREVIEW, NOT SHIP-READY**.

- [x] Review W.H.I.T.E. and System Sanitizer source boundaries
- [x] Preserve the Go scanner engine and 95-rule table (avoid regression from rewrite)
- [x] Native WPF host project and user-supplied Windows .ico and header PNG
- [x] Ephemeral local port and host-managed child engine lifecycle
- [x] Local Go tests, Go vet, extension JS syntax, project manifest/XAML parse tests
- [ ] GitHub Windows build green with all Git submodules initialized
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
