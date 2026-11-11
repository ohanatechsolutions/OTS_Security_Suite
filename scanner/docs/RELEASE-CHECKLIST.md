# OTS v2.0 release gate

- [x] Original local scanner, no dependency on ScanRepo.dev
- [x] All recognized and unknown extensions receive baseline inspection
- [x] File coverage manifest, SHA-256 and partial/uninspected reasons
- [x] ZIP/TAR/GZIP nested inspection with resource limits
- [x] Preliminary native PE/ELF/Mach-O parsing, string checks
- [x] EICAR marker as a harmless regression case
- [x] 95 text-pattern indicators and format-specific checks
- [x] Tests: 12-file synthetic repo, archives, limit handling, local API, malicious patterns
- [x] Windows x64 EXE / setup / uninstall cross-compilation
- [x] Chrome extension links local app
- [ ] Windows VM installer / uninstall smoke test
- [ ] Windows Defender and independent binary reputation scan
- [ ] Third-party source code audit
- [ ] Fuzzing of archive formats and stress/DoS tests
- [ ] Real-world labeled detection corpus: sensitivity and false-positive evaluation
- [ ] Full RAR/7z/OLE/encrypted document support
- [ ] Git LFS objects, submodules and optional Git history support
- [ ] Supported package vulnerability database and graph analysis
- [ ] Authenticode verified publisher signing and timestamp
- [ ] Validated software update channel

The checked boxes describe implemented or locally verified work, not production security certification.
