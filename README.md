# dependency-risk-score

[![PyPI version](https://img.shields.io/pypi/v/trysac-dependency-risk-score)](https://pypi.org/project/trysac-dependency-risk-score/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-dependency-risk-score)](LICENSE)
[![CI](https://github.com/Trysac/u156-dependency-risk-score/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u156-dependency-risk-score/actions/workflows/ci.yml)

Score dependency risk from offline facts: release staleness, maintainer count, deprecation, known vulnerabilities and license category, with reasons and CI exit codes

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-dependency-risk-score
# or
uv add trysac-dependency-risk-score
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import dependency_risk_score

# normalize() trims surrounding whitespace and lower-cases the text.
print(dependency_risk_score.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    dependency_risk_score.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
