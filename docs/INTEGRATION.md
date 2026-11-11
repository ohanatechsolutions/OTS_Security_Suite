# Cross-module integration decisions

- Keep the three source languages while the suite is new. A full Python rewrite is not required for Windows window icons, and rebuilding the quarantine implementation creates unnecessary migration risk.
- Native WPF owns the top-level window; its `Window Icon` and `ApplicationIcon` use `AppIcon.ico`, unlike Chrome app mode.
- Local Go scanner starts via Process.Start and prints a temporary session URL on stdout (`--no-browser --ephemeral --print-url`). WPF validates loopback origin, restricts WebView2 navigation to that port and kills the scanner on close. No fixed port `48728` is required in suite mode.
- The Python W.H.I.T.E. module remains process-isolated. The suite captures redacted JSON output and interprets exit code 0 success, 1 findings and 2 incomplete. The external OSV scanner is not silently skipped when the user explicitly requests dependency scanning.
- System Sanitizer's core DLL is referenced directly; the original installed GUI is retained for its full features. Existing DPAPI quarantine paths, manifest and vault data are not migrated or deleted by the suite. Core API confirmations remain in the suite.
- No module is permitted to automatically destroy or quarantine repository files based merely on a Go risk score. Windows remediation is always a separate explicit user command.
- The extension uses a registered `ots-security://scan?url=` protocol and does not need a browser-accessible localhost port or persistent background engine.
- The first native installer is a separate product with its own AppId so it cannot automatically overwrite existing standalone Sanitizer/White installations or delete user data.
