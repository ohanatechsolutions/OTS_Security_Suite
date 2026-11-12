# Release & Recovery Runbook — OTS Security Suite

**No release is approved yet.** This is a controlled, reproducible runbook. It does not authorize signing, publishing, paid certificates, migration, deleting a branch or changing a user machine without consent.

## 1. Freeze and review
1. Confirm a reviewed immutable source commit SHA and pinned W.H.I.T.E./Sanitizer submodule revisions.
2. Confirm `docs/BUILD_BLUEPRINT.md` and requirements have not changed without recorded review.
3. Check every automated CI step and inspect failures, not merely the GitHub green badge.
4. Verify all P0/critical cases in `docs/QA_ACCEPTANCE.md` against supported Windows 10/11 and clean Chrome profiles.
5. Inspect detection false positives, partial-scan semantics, local network origin, startup/shutdown and user scoped remediation permissions.
6. Collect human product, security and Windows QA signoffs. Missing approval is **NO-GO**.

## 2. Create candidate, with authorized dependencies only
- Build from a verified commit using the maintained Windows workflow with pinned toolchains.
- Output `OTS-Security-Suite-Setup-x64.exe`, `SHA256SUMS.txt`, source/release manifest and release notes.
- Verify genuine PE `MZ` header, Win-x64 architecture, self-contained .NET files, original icon and transparent logo, real scanner and Sanitizer executables.
- Rebuild in a fresh environment; compare evidence. Exact bit-identical builds are not yet promised.

PowerShell SHA-256 verification:

```powershell
Get-FileHash -LiteralPath '.\OTS-Security-Suite-Setup-x64.exe' -Algorithm SHA256
```

Compare the output to the checksum published through an independently trusted official channel. A checksum on the same untrusted download server alone does not authenticate a publisher.

## 3. Publisher signing — blocked pending owner decision
- **Never use a self-signed/test certificate to represent Ohana Tech Solutions as a trusted signed publisher.**
- Obtain authorization for a legitimate OTS Authenticode certificate or approved secure signing service; verify cost and identity before use.
- Do not commit a PFX, private key, signing password or temporary certificate file to GitHub, workflows, logs or installer assets.
- Sign all distributed EXEs and the installer where applicable, with the approved certificate and trusted timestamp service. Check actual signatures with Windows `Get-AuthenticodeSignature`.
- If a valid certificate is unavailable, keep the build **private/non-release preview**; do not claim SmartScreen or reputation clearance.

## 4. Non-admin acceptance on isolated machines
1. Use disposable, clean Windows 10/11 x64 VMs. Preserve a previous full installer and backups.
2. Install as standard user; verify no unexplained elevation and all dependencies including WebView2.
3. Confirm the shield icon in the file, window, taskbar and Alt+Tab; check DPI settings.
4. Run synthetic RepoScan, W.H.I.T.E. and Sanitizer scenarios including cancel, corrupted input and offline behavior. No real malware execution.
5. Test fresh install, upgrade, repair/roll-back and uninstall. Confirm legacy and current encrypted quarantines, DPAPI-protected keys and private reports survive.
6. Test Chrome companion on a clean profile; do not silently install extensions or widen permissions.

## 5. Release authorization / publication
- Require written owner GO with source SHA, installer SHA256, signature identity, artifact hashes, QA evidence, open-risk acceptance and recovery owner.
- Only after authorization, publish versioned release notes and signed binaries in the designated OTS repository. Never substitute placeholder binaries.
- Verify the actual published asset downloaded in a clean environment, not just CI's temporary artifact.
- Record date/time, installer SHA, license/dependency inventory, support channel and rollback location.

## 6. Recovery, incidents and retention
- If a security regression appears: halt publication, preserve logs in sanitized form, retain current and legacy DPAPI vault directories, isolate synthetic test material and notify the owner privately.
- Revert the release via a reviewed commit, not history rewrite. Restore the last known-good signed installer only after verifying its checksum and certificate.
- Do **not** delete user report history, quarantine, WebView2 profile or private source data during routine uninstall.
- Ensure support staff do not request raw secret matches, password files or unencrypted vault content. Report and fix with minimal synthetic fixtures.

**N/A:** hosted deployment/rollout health dashboards, payments, mobile stores, AI agent controls and hardware firmware. **Applicable:** Windows desktop installer, Chrome extension, offline/local-first data, Windows security utility safe remediation.
