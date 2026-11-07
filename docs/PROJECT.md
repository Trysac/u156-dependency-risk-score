# Project Record\n\n## Objective\n\nScore dependency risk from offline facts: release staleness, maintainer count, deprecation, known vulnerabilities and license category, with reasons and CI exit codes.\n\n## Scope\n\n- The public Python API (`dependency_risk_score` package) including type-checked `load_facts`, `score_package`, and `score_all` functions.\n- CLI tool `dependency-risk-score` provided via `__main__.py`.\n- Default SPDX license classification table.\n\n## Out-of-Scope\n\n- Fetching facts (OSV, deps.dev, registries).\n- SPDX expression parsing.\n- Version range matching.\n- Transitive graph traversal.\n- Legal license compliance determinations.\n\n## Timeline\n\n| Date | Event |\n|---|---|\n| 2026 | Repository created from factory template. |\n\n## Effort Metrics\n\n| Metric | Value |\n|---|---|\n| Tokens (input / output) | pending measurement |\n| Hours (human) | pending measurement |\n| Cost (USD) | pending measurement |

## Factory run u156 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | gemini-3.8-flash | yes | 4700 | 14011 | 0 | 0 | 0.0280 |
| fix-1 | gemini-3.8-flash | no | 61395 | 1340 | 0 | 339712 | 0.0765 |
| fix-2 | gemini-3.8-flash | no | 24299 | 633 | 0 | 42531 | 0.0238 |
| audit | gemini-3.1-flash-lite | no | 45888 | 183 | 0 | 101894 | 0.0143 |
| docs | gemini-3.1-flash-lite | no | 179225 | 1400 | 0 | 0 | 0.0469 |

Total: $0.1896. Prices: Anthropic list prices.
