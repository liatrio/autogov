# Contributing to autogov

Contributions are welcome. Keep pull requests focused, include tests when they
reduce regression risk, and update user-facing docs when behavior changes.

## Local setup

Prerequisites:

- Go 1.27 or higher
- GitHub CLI (`gh`) for trusted root fetching
- Docker for container registry access
- `golangci-lint`
- [Task](https://taskfile.dev)

```bash
git clone https://github.com/liatrio/autogov
cd autogov
go mod download
task verify
```

Useful commands:

```bash
task --list
task build
task test
task lint
task verify
```

## Pull requests

- Open an issue first for substantial changes.
- Keep the branch scoped to one change.
- Run `task verify` before opening the PR.
- Call out breaking changes or migration notes in the PR body.

## Code expectations

- Follow normal Go idioms.
- Wrap errors with context.
- Add or update tests when they materially help.
- Keep docs and examples in sync with behavior.
- Document public APIs with GoDoc comments.

## AI assistance

AI-assisted drafting is fine. Review it as if you wrote it yourself.

Note meaningful AI assistance in the pull request description, not in commit
messages or code comments. AI-assisted review is tooling and does not count as
a second reviewing party; see [MAINTAINERS.md](MAINTAINERS.md).

## Code of conduct

This project follows the [Contributor Covenant Code of
Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
