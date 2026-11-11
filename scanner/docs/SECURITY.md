# OTS scanner — security architecture and limitations (v2.0)

## Invariants

- Repository content is treated strictly as **untrusted data**. The scanner never executes downloaded code, npm/pip dependencies, scripts, executables or macros; it does not call `git clone` on untrusted input.
- All browser UI API methods run on `127.0.0.1:48728`, with randomized session cookie, Host restrictions, and same-origin POST check. The Chrome extension is only a local UI launcher, not an API bypass.
- Remote URL scans only accept public GitHub / Bitbucket hosts. Downloads use allowlisted HTTPS endpoints, and outgoing redirects are constrained to known providers. No arbitrary URL fetch or scanning of private LAN targets is supported.
- Source snapshots lack historical commits, LFS object bytes and submodule contents. User receives warnings, not a false full-history assurance.
- Archive reading is in memory. ZIP member paths are checked, and symlinks and traversals are **not extracted or followed**. Expanded bytes, per-file sizes, depth, and aggregate scan resources have ceilings.
- A file larger than 16 MiB may receive **prefix-only inspection** and partial hash. Never call the partial hash SHA-256 of the entire file. A zero-indicator score is not proof of safety.
- Reports intentionally omit source-code snippets to minimize leaking potentially sensitive tokens. User file paths and detected indicators are still stored; restrict report access.

## Residual risks

- Static inspection may miss packed malware, RAR/7z embedded files, unsupported formats, encrypted archives, malicious runtime behaviors, deep dependency chains, supply-chain compromises, vulnerabilities without signatures, and novel malware. PE/ELF/Mach-O header inspection is preliminary; it does not emulate binaries.
- Rule patterns produce false positives. For example, keyboard hooks are common in legitimate accessibility and input-locking utilities.
- Third-party file parsers, decompression and malformed input handling require fuzzing and external review. This is **not a formally verified, containerized sandbox**.
- Google Chrome itself shares browser/system trust boundaries with other desktop software; this is not an isolation mechanism.
- The updater is not implemented. There is no built-in automatic rules feed, authentication service or digital signing.
- Untrusted public repos may contain objectionable text or files. Avoid sharing reports without review.

## Limits

- 25,000 file-analysis attempts, 16 MiB per file full content, 384 MiB aggregate, 4 nested archive levels, 192 MiB per archive expanded, 60 MiB compressed source archive, 240 MiB browser upload, 2,500 findings, 50,000 per-file coverage records.
- Symlinks and unsupported non-regular entries are inventoried as uninspected, not opened. Disallowed paths inside archives are flagged as uninspected.
- Resource-limit states and failures must remain visible in the report and reflected in risk verdicts.

## Release verification

Run `go test ./...`, `go vet ./...`, `node --check` on UI/extension JS, review complete source and SHA-256. Test installer and uninstall via Windows 11 VM and use Microsoft Defender plus independent file reputation checks. Obtain an organization-verified OTS signing certificate and Authenticode timestamp before production deployment.
