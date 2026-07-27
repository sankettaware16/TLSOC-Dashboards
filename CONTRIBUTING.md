# Contributing to TLSOC

TLSOC is an open-source SOC platform built by [IITB Trust Lab](https://trustlab.iitb.ac.in/)
as a hard fork of OpenSearch Dashboards. Contributions are welcome — bug reports, detection
content, documentation, and code.

## First things first

**When in doubt, open an issue.** For almost any contribution the first step is
[opening an issue](https://github.com/sankettaware16/TLSOC-Dashboards/issues) — a bug report,
a feature idea, or a question. For substantial code changes, please discuss in an issue
*before* writing the code, so nobody's work is wasted.

**Security problems are the exception:** never open a public issue for a vulnerability —
follow [SECURITY.md](SECURITY.md) instead.

## Bug reports

Please include:

- The TLSOC version (Help menu in the UI, e.g. `v1.3.0`) and how you deployed it
  (`tlsocdistro/` Docker, or from source).
- What you did, what you expected, and what happened instead — screenshots help a lot for UI
  issues.
- Relevant log lines from the `tlsoc-dashboards` container
  (`docker logs tlsoc-dashboards`) when the problem is server-side.

## Contributing code

1. Fork this repository and create a branch from `main`.
2. Set up a dev environment: Node 22 (`nvm use`), `yarn osd bootstrap`, then `yarn start`
   against a local OpenSearch. The upstream
   [developer guide](DEVELOPER_GUIDE.md) largely applies to the build tooling.
3. Keep changes focused; match the style of the surrounding code.
4. Add or update tests for what you change. TLSOC's own code lives mainly under
   `src/plugins/tlsoc/` — run its suite with `node scripts/jest src/plugins/tlsoc`.
5. Open a pull request against `main` describing the problem and the fix. Small, reviewable
   PRs get merged much faster than big ones.

### Ground rules for this fork

- **Never patch the OpenSearch engine** — TLSOC changes only the Dashboards fork; the backend
  stays stock upstream.
- **Apache-2.0 only.** Only submit work you have the rights to submit. Do not copy code from
  incompatibly-licensed projects (e.g. Elastic-licensed Kibana 7.11+, current EUI, or
  x-pack) — such contributions will be rejected regardless of quality.
- **Subtract when possible.** This fork deliberately removes what a SOC doesn't need; PRs that
  re-add general-purpose analytics surface area need a strong justification.

## Developer Certificate of Origin

By contributing, you certify the [Developer Certificate of Origin](https://developercertificate.org/) —
that you have the right to submit the work under Apache-2.0. Sign your commits with
`git commit -s`.

## License

All contributions are licensed under [Apache-2.0](LICENSE.txt).
