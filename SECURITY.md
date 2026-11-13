# OTS Security Suite — Security Policy (integration preview)

**Status:** pre-release, no independent security certification or guaranteed malware prevention.

## Current evidence and limitations

The latest Windows CI [run #43414634076](https://github.com/ohanatechsolutions/OTS_Security_Suite/actions/runs/43414634076) passed its configured tests and completed the offline W.H.I.T.E. worktree/history source audit with no high/critical findings **under that scanner's rules**. It also verifies negative cases for RepoScan local report history, external origin rejection, cancellation and limited decompression. That does **not** amount to independent penetration testing, detection certification, vulnerability-free dependencies or authorization to distribute. Product/security owners still need to approve any release.

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

**Current actual Windows CI evidence:** [run 43189027296](https://github.com/ohanatechsolutions/OTS_Security_Suite/actions/runs/43189027296) **SUCCESS** for docs head `de277e5fa3bb2d7e1bd8b2aac362a3d9e74ff916` containing executable source `a2f39b812e61116ecaa3f4813909b662d4149224`, with `Audit runner tests: 15/15 PASS`, packaged WHITE success/incomplete contract, 95 scanner rules and Go tests/vet, WPF synthetic navigation and real CLI execution, logo PNG sampled transparency (1563×1563), Inno installer, bundled MIT/license notices, extension files, synthetic vault preservation, URI registration, normal close and uninstall. Installer SHA-256 `8872BB5E2039C7B5F6AA13EA7AC52276CB22C80AA88B00FCDEE6271B5BC1C929` (CI-created, deliberately not uploaded on draft PR). **Automated gates passed; human Win10/Win11, clean Chrome extension, legacy real-user vault, independent security and publisher signing remain NOT RUN / blocked.**

The successful CI is not an independent penetration test, endpoint detection certification or publisher-signed release. No public distribution approval is inferred.
