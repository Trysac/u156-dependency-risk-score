# Architecture

## Overview

`dependency-risk-score` provides offline, deterministic risk scoring for package dependencies based on factual input data. It intentionally decouples fact-gathering (from registries, advisory databases, or package managers) from risk scoring.

```
[ JSON Facts File / String ]
            │
            ▼
       load_facts()  ─── validates structure, sizes, and formats into immutable Package instances
            │
            ▼
   score_package() / score_all()
      - Computes release age relative to injected `as_of` date
      - Evaluates maintainer counts (<= 1 triggers single_maintainer)
      - Checks deprecation status
      - Looks up SPDX license categories in DEFAULT_LICENSES
      - Calculates capped vulnerability scores
      - Derives final 0-100 score and risk level ('low', 'medium', 'high', 'critical')
            │
            ▼
      [ RiskReport ]
```

## Rule Evaluation Order

Reasons are emitted in a strict, deterministic sequence:
1. `aging_release` (366 - 730 days) or `stale_release` (> 730 days)
2. `single_maintainer` (maintainers is 0 or 1)
3. `deprecated`
4. `weak_copyleft`, `strong_copyleft`, or `unknown_license`
5. `vulnerability:<id>:<severity>` in original input order

## Resource Limits

- `max_bytes`: 5,242,880 bytes (5 MiB) default max JSON payload.
- `max_packages`: 10,000 maximum packages per facts file.
- Maximum 1,000 vulnerabilities per package.
- Strict 10-character ISO 8601 date checking (`YYYY-MM-DD`).
