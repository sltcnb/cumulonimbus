# Contributing to Cumulonimbus

Thanks for helping improve Cumulonimbus. This guide covers how to set up a dev
environment, the project conventions, and how to submit changes.

## Development setup

```bash
git clone https://github.com/sltcnb/cumulonimbus
cd cumulonimbus
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

## Running checks

```bash
pytest -q                          # run the test suite
pytest -q --cov=cumulonimbus       # with coverage
ruff check cumulonimbus tests      # lint
ruff format --check cumulonimbus tests   # formatting
```

All of the above run in CI on Python 3.9–3.12. Please make sure they pass
locally before opening a pull request. `pre-commit` runs ruff (lint + format)
and basic hygiene hooks automatically on commit.

## Adding a dataset

Cumulonimbus is designed to be extended with new datasets. See the
[Extending Cumulonimbus](README.md#extending-cumulonimbus) section of the
README. In short:

1. **Parser** — subclass `Parser`, decorate with `@register("<provider>.<dataset>")`,
   and import the module from the provider's `parsers/__init__.py`.
2. **Collector** (optional) — subclass `Collector`, set `dataset`, implement
   `collect()`, and add it to the provider's `COLLECTORS` map.
3. **Tests** — add a golden fixture and a parser test. Parsers must fail soft:
   a malformed record returns `None`, never raises out of `parse()`.

## Conventions

- **Commits** follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `chore:`, `test:`, `refactor:`, …).
- **Style** is enforced by ruff (`line-length = 100`). Run `ruff format` before
  committing.
- **Type hints** are expected on new public functions.
- **Fail soft.** A single bad record or a broken enricher must never abort a
  run — mirror the existing `try/except` patterns in `parser.py` and
  `normalizer.py`.
- **Raw first.** Never mutate collected evidence; normalization is a separate,
  repeatable step.

## Pull requests

- Keep PRs focused and small where possible.
- Describe *what* changed and *why*.
- Add or update tests for behavior changes.
- Update the README and `CHANGELOG.md` when user-facing behavior changes.

## Reporting bugs and requesting features

Use the GitHub issue templates. For security issues, follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.
