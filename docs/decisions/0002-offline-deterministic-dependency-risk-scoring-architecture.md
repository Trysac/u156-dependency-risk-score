# Offline deterministic dependency risk scoring architecture

Status: accepted (generated, pending human review)

## Context

Teams evaluating software dependencies need a unified, explainable way to quantify dependency risk across release age, maintainer scarcity, deprecation, vulnerabilities, and license posture. Combining these offline without external network dependencies ensures reproducible CI checks and audits.

## Decision

Implement dependency risk scoring with pure standard library Python, strict input limits, immutable dataclasses, explicit bundled SPDX license mapping, and deterministic rule order.

## Consequences

Scoring is completely offline, highly performant, and reproducible across environments. Complex SPDX expressions and legal compliance auditing are explicitly out of scope.
