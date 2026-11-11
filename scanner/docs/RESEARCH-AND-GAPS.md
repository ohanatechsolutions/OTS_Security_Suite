# ScanRepo public-feature comparison & honest gaps

**Status: independent implementation, not recovered ScanRepo code.**

Source research (2026-11-11):

- https://www.scanrepo.dev/ — public repository scan workflow, static rules, risk score, verdict and categories
- https://www.scanrepo.dev/about — repository snapshots, entropy, architecture graph, metadata, LLM review, scan caps
- https://www.scanrepo.dev/cli — public npm CLI interface, exit codes, JSON report, option to disable publishing
- https://github.com/rubenmarcus/malicious-repositories — malware research corpus, **not full website source code**; contains malicious code and is *not included or executed*

No accessible public source for the complete ScanRepo website/backend was verified in this work. REA or browser inspection could characterize exposed client behavior but cannot recover private backend source or prove exact rule/scoring parity. We did not clone the target website, decompile private binaries or copy source from it.

| Published ScanRepo workflow | OTS implementation | Important gap |
|---|---|---|
| Paste a GitHub URL & scan | Implemented | No equivalent reputation metadata or automatic cache |
| Bitbucket public URL scan | Implemented initial tarball adapter | Live provider compatibility not tested |
| Source archive scanning without execution | Implemented | All extension types get baseline inspection, but specialized coverage differs |
| Static suspicious-code categories | 95 original static rules | Not ScanRepo's rules, detection corpus, or tuning |
| Risk score / verdict | 0–100 original heuristics | Scores not comparable |
| File-and-line findings | Implemented | Reporting UI/layout original |
| Shannon entropy | Implemented for long alphanumeric strings | No full statistical pass or flow analysis |
| Import/architecture graph | Not implemented | Requires language parsing, entry-point mapping |
| Repository reputation signals | Not implemented | Would require provider metadata and threat-intel validation |
| AI-assisted verdict | Not implemented | Would require safe local-model integration or a paid API |
| Scan feed, cache, community votes | Not implemented | Intentionally private local history instead |
| Fully offline folder scan | Implemented | All regular files get baseline checks, not execution behavior |
| Windows EXE installer | Implemented (original OTS) | Cross-compiled, not tested on Windows or signed |
| Chrome extension | Implemented | Local-app launcher, not independent engine |

Recommended future validation: run on real Windows 11 VM; confirm installer/uninstaller paths; test URL scans using known benign repos and synthetic malware test fixtures; extend tests for false positives; add import-graph reachability; validate Bitbucket endpoint; add optional trusted malware corpus via licensing; conduct dependency and supply-chain audit; sign releases and verify Windows security warnings legitimately.
