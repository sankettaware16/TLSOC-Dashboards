# Reporting a Vulnerability

TLSOC is a security product, and we take vulnerabilities in it seriously.

If you discover a potential security issue in **TLSOC** (this repository or the
`tlsocdistro/` distribution), please report it **privately** via GitHub's security advisory
form: **[Report a vulnerability](https://github.com/sankettaware16/TLSOC-Dashboards/security/advisories/new)**.
Please do **not** open a public GitHub issue for security problems.

Include what you can: affected version (see the Help menu in the UI, e.g. `v1.3.0`),
reproduction steps, impact, and any suggested fix. You will get an acknowledgement, and a fix
release with credit to the reporter (unless you prefer to stay anonymous).

## Scope notes

- **TLSOC Dashboards** (this repo) and the **tlsocdistro** deployment are in scope here.
- Issues in the **OpenSearch engine** itself should go to upstream OpenSearch Security
  (security@opensearch.org) — TLSOC consumes stock OpenSearch and does not patch it.
- Issues in the **FOSS SOC Engine** (log parser) belong on
  [sankettaware16/foss-soc-engine](https://github.com/sankettaware16/foss-soc-engine).

## Fixing dependency vulnerabilities

- For direct dependencies (listed explicitly in `package.json`): after identifying a version
  that is compatible and includes the fix, update `package.json` and run `yarn osd bootstrap`
  to rebuild and update `yarn.lock`.
- For nested dependencies: add or update a `"resolutions"` entry in `package.json` pinning the
  fixed version, then run `yarn osd bootstrap` and verify `yarn.lock`.
