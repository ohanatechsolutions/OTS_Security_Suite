# OTS Security Suite — Security Policy (integration preview)

**Status:** pre-release, no independent security certification or guaranteed malware prevention.

## Supported scope
The draft integrated Windows 10/11 x64 application includes a Go static repository scanner, Python-based OTS W.H.I.T.E. source audit, and the .NET System Sanitizer. These tools report **heuristics and coverage**, not definitive infection status. Continue running Microsoft Defender or another approved endpoint protection product.

No public support or security-update SLA has been established for version 0.9.0. Do not distribute the unsigned preview as a verified publisher-signed release.

## Reporting vulnerabilities
If GitHub's **Report a vulnerability** / private security advisory option is available for this repository, use it. Otherwise contact the Ohana Tech Solutions repository maintainers privately through a verified channel. Do not publish exploit steps, user paths, private repository content, passwords, tokens or real malware payloads in a public issue.

Provide the affected commit or version, impacted component, safe minimal reproduction, expected vs. actual outcome and sanitized technical evidence. The team should acknowledge privately, evaluate impact, reproduce in an isolated environment, create a fix and regression test, and publish an advisory only after an authorized disclosure decision.

## Trust boundaries
- Repository URLs: public GitHub/Bitbucket snapshots only; HTTPS and host allowlist, redirect controls, archive budgets.
- RepoScan browser UI: authenticated ephemeral localhost session, strict origin checking for writes, CSP and no arbitrary external WebView2 navigation.
- Source audit: local subprocess with bounded output; stdout JSON validation; no raw stderr in the UI.
- Windows Security: local read-only heuristic inspection by default; review/explicit confirmation required for quarantine and deletion.
- Local reports: may contain sensitive filenames or locations. Treat them as private and export only to trusted destinations.
- Browser extension: `activeTab` access is temporary and user invoked; custom native protocol carries repository URL only.
- Distribution: installer integrity requires a verified SHA-256 and a legitimate Authenticode signature before public release.

## Security dependencies and recovery
Rebuild with supported patched runtimes and pinned reviewable submodule versions. Keep prior clean installers/verified checksums for rollback. Never erase encrypted vaults, old DPAPI keys or reports during an upgrade/uninstall without a separate reviewed retention decision.

Consult `docs/RELEASE-GATES.md`, `docs/QA_ACCEPTANCE.md`, and `docs/PROJECT_STATUS.md` for the actual security QA and release status. Automated tests are recorded separately from a human penetration/security review.

**Current verification warning (2026-11-11 HST):** newest draft commit `a2f39b812e61` has not yet received a complete Windows CI result; see [queued run 43188038745](https://github.com/ohanatechsolutions/OTS_Security_Suite/actions/runs/43188038745). The prior green CI applies only to earlier source. Do not distribute current binaries or claim final security verification from the staged source alone.
