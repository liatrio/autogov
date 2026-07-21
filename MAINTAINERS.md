# Maintainers

autogov is maintained by Liatrio's AutoGov team. Review and merge authority for
the repository is held by the `@liatrio/tag-autogov` team (see
[`CODEOWNERS`](CODEOWNERS)).

| Maintainer  | GitHub                                        | Role            |
| ----------- | --------------------------------------------- | --------------- |
| Ian Hundere | [@ianhundere](https://github.com/ianhundere)  | Lead maintainer |

Maintainers triage issues, review and merge pull requests, cut releases, and
respond to security reports (see [`SECURITY.md`](SECURITY.md)).

## Review model & SLSA source posture

This project is currently maintained by a **single maintainer**, so
`@liatrio/tag-autogov` effectively resolves to one person. Genuine two-party
review (SLSA Source **L4**) requires two trusted persons per change and is
therefore **not met today** — it is an aspiration we will adopt as the project
gains community co-maintainers. What *is* continuously enforced and recorded —
branch protection, signed commits, linear/retained history, required status
checks — earns an honest **SLSA Source L3**. Changes receive AI-assisted review
as *tooling*; that assists the maintainer but is **not** counted as a second
reviewing party. The repo's own release self-verifies `source_review` at
`min_approvals: 0` by disclosed design, so a release is never gated on a review
that did not independently happen; the published policy bundle keeps the strict
default for adopters with real review teams.

## Contributing

Contributions are welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md). Contributors
who demonstrate sustained, high-quality involvement may be invited by the current
maintainers to join as maintainers.
