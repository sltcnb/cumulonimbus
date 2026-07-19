# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `SECURITY.md` with a private vulnerability-reporting process.
- `CONTRIBUTING.md` with dev-setup, conventions, and PR guidance.
- Issue and pull-request templates under `.github/`.
- Dependabot configuration for GitHub Actions and pip dependencies.
- `.editorconfig` for consistent editor defaults.
- README badges (license, Python versions) and a contributing section.
- CI now enforces `ruff format --check` and pins ruff to match pre-commit.

## [0.1.0]

### Added
- Initial release: collect / parse / normalize / analyze / export / push
  pipeline for AWS, Azure, GCP, and Kubernetes logs to ECS v8.

[Unreleased]: https://github.com/sltcnb/cumulonimbus/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sltcnb/cumulonimbus/releases/tag/v0.1.0
