# OTS Security Suite — integration preview 0.9.0

Ohana Tech Solutions is unifying **OTS GitHub Malware Scanner**, **OTS W.H.I.T.E.**, and **OTS System Sanitizer** into a single native Windows application.

**Status: integration preview; NOT ship-ready.** The native WPF build, installer, integration tests, and signed distribution must pass the release gates before public release.

The integration design preserves the existing Go malware scanner, Python code-security audit, and .NET Windows security utilities. The suite uses a native WPF/WebView2 shell rather than a Chrome app window, with a user-provided icon and logo. Browser extension integration launches via the `ots-security://` protocol.

Development artifacts and complete integration work-in-progress are being prepared. Do not release an installer from this repository until Windows CI verifies the bundled engines.

Source projects:
- https://github.com/ohanatechsolutions/OTS_W.H.I.T.E.
- https://github.com/ohanatechsolutions/OTS_System_Santizer

The existing OTS Malware Scanner source is part of the local integration bundle and must also be published before this repository is build-complete.
