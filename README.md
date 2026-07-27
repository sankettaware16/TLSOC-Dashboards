<p align="center">
  <img src="src/core/server/core_app/assets/logos/tlsoc_mark.svg" alt="TLSOC" width="96" />
</p>

<h1 align="center">TLSOC — TrustLab Security Operations Center</h1>

<p align="center">
  <b>An open-source, self-hosted SOC platform for universities and mid-size organizations.</b><br/>
  Built by <a href="https://trustlab.iitb.ac.in/">IITB Trust Lab</a> as a hard fork of OpenSearch Dashboards.<br/>
  Apache-2.0. No agents on endpoints. No per-GB pricing. Your logs stay on your hardware.
</p>

<p align="center">
  <a href="https://github.com/sankettaware16/TLSOC-Dashboards/releases/latest"><img src="https://img.shields.io/github/v/release/sankettaware16/TLSOC-Dashboards?label=release&color=5577D1" alt="Latest release"/></a>
  <a href="LICENSE.txt"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache-2.0"/></a>
  <a href="https://github.com/opensearch-project/OpenSearch-Dashboards"><img src="https://img.shields.io/badge/hard%20fork%20of-OpenSearch%20Dashboards-005EB8" alt="Hard fork of OpenSearch Dashboards"/></a>
  <a href="https://github.com/sankettaware16/TLSOC-Dashboards/issues"><img src="https://img.shields.io/github/issues/sankettaware16/TLSOC-Dashboards" alt="Issues"/></a>
</p>

---

## What is TLSOC?

TLSOC is a **complete Security Operations Center in a box**: log collection, parsing and
normalization, threat detection, alerting, and case management — deployable on a single Linux
host with Docker Compose, and scalable from a lab to a campus.

It is a **hard fork of [OpenSearch Dashboards](https://github.com/opensearch-project/OpenSearch-Dashboards)**
(the way OpenSearch itself forked Elasticsearch, or Wazuh forked OSSEC): we took a snapshot,
severed the upstream tie, stripped out everything that is not security-relevant, reskinned it
into a modern SOC product, and added the SOC features OpenSearch lacks. OpenSearch (the search
engine) stays underneath as the storage/query backend, **unmodified**.

```
endpoints ──rsyslog/omkafka──▶ Kafka ──▶ FOSS SOC Engine ──▶ Logstash ──▶ OpenSearch ──▶ TLSOC Dashboards
 (agentless)                 (buffer)   (parse → ECS)       (ship)      (store/query)     (the SOC UI)
```

## Why TLSOC?

Universities and smaller organizations face the same attacks as enterprises, but commercial
SIEM/SOC pricing (per-GB ingest, per-seat analyst licensing) is built for enterprises. The
usual alternatives each fall short:

- **Raw ELK / OpenSearch** — a general-purpose analytics stack. Powerful, but you assemble the
  SOC yourself: detection content, alert triage, case workflow, onboarding — all DIY.
- **Wazuh & friends** — strong host security, but agent-based: you must install and maintain an
  agent on every endpoint, which is often impossible across a federated campus.
- **Commercial SIEM** — excellent, and priced accordingly.

TLSOC's answers:

- **Agentless onboarding.** Endpoints forward logs with stock `rsyslog` + its Kafka output
  module — software already present on virtually every Linux server. One script
  (`tlsoc-onboard.sh`), zero agents to maintain.
- **A real SOC workflow out of the box.** Detections → alerts → cases, in one UI, with the
  triage states a duty analyst actually needs — not a dashboard toolkit.
- **Security-first UI.** Everything not relevant to security operations was removed from the
  fork; what remains is a focused SOC console, not a general BI product.
- **Genuinely open.** Apache-2.0, self-hosted, standard formats (ECS fields, Sigma export).
  No telemetry, no license keys, no per-GB meter.

## Features

### Detection engine — six rule types, no code required
- **Custom query** rules (DQL or Lucene) for match-based detections.
- **Threshold** rules (stateless aggregations: count / distinct / min / max / avg / sum with
  `HAVING`-style conditions, grouped by any fields).
- **Stateful** rules (aggregations with memory across runs — e.g. "alert when a source appears
  that exceeded the threshold in the last N runs").
- **PPL** rules — write detections in Piped Processing Language with pre-save validation.
- **New terms** rules — alert the first time a value (user, host, process, country, …) is seen
  within a look-back window.
- **Indicator match** rules — match events against value lists / threat-intel indicators.
- **Exceptions & suppression** per rule, a **starter pack** of ready-made rules, **MITRE
  ATT&CK coverage** view, and **Sigma export** for rules that map cleanly.
- **Honest health reporting**: a rule's health reflects what the engine actually knows — TLSOC
  never invents a "Succeeded" status it cannot verify — and rules that would silently never
  fire are rejected at save time (queries and PPL are validated server-side against your data).

### Alerts & case management
- Alert queue with acknowledge/close triage synced to the alerting engine.
- **Cases**: group alerts into an investigation, close a case to acknowledge its alerts,
  reopen it to bring them back into the active queue — the full workflow survives alerts being
  shared across multiple cases.

### Onboarding & visibility cockpit
- The **Overview** app guides a fresh install: it detects when no logs have arrived and shows
  the exact onboarding steps; once events flow, it lights up with new sources, ingest lag,
  source types, and geo views — automatically.
- Per-endpoint daily indices (`fosstlsoc-logs-<server>-YYYY.MM.dd`) with a 90-day retention
  policy applied out of the box (configurable).

### The platform underneath
- Full **Discover / Visualize / Dashboards** stack for ad-hoc hunting and reporting, inherited
  from OpenSearch Dashboards and reskinned.
- **Role-based access control** and multi-tenant **workspaces** via the OpenSearch security
  plugin (pre-wired in the distribution).
- **Universal accent palette** — pick one color and the entire UI re-themes instantly; one
  click reverts to the default theme. Light and dark modes.

## Use cases

- **University / campus SOC** — federated departments forward syslog to a central stack;
  student analysts triage alerts and work cases; no agent rollout negotiations.
- **Small/medium org SIEM** — a single VM gives you collection, detection, and case management
  without a per-GB bill.
- **Teaching & research** — a real, inspectable SOC pipeline (Kafka topics, ECS documents,
  detection rules, alert lifecycle) for security courses and labs.
- **Home lab / blue-team practice** — point a few VMs at it and build detections against real
  telemetry.

## Getting started

The supported way to run TLSOC is the bundled one-click distribution in
[`tlsocdistro/`](tlsocdistro/) — Docker Compose for **OpenSearch + TLSOC Dashboards + Kafka +
Logstash**, plus the parsing engine and an endpoint onboarding script. The short version:

```bash
# 1. Get the deployment files (the image itself is prebuilt — no compilation needed)
git clone --depth 1 --branch v1.3.1 https://github.com/sankettaware16/TLSOC-Dashboards.git
cd TLSOC-Dashboards
#    (the TLSOC Dashboards image ghcr.io/sankettaware16/tlsoc-dashboards:1.3.0 is pulled
#     automatically; to build it yourself instead: bash tlsocdistro/dashboards/build-image.sh)

# 2. Install the FOSS SOC Engine (parses raw logs → ECS)
#    https://github.com/sankettaware16/foss-soc-engine

# 3. Start the stack
cd tlsocdistro && cp .env.example .env   # set passwords
sudo ./install.sh

# 4. Onboard an endpoint (run ON the endpoint — agentless)
sudo bash tlsoc-onboard.sh
```

Then open `http://<HOST_IP>:5601/`, log in, and the Overview app walks you through the rest.
**Full instructions, pipeline verification, retention tuning, and production hardening:**
[`tlsocdistro/README.md`](tlsocdistro/README.md).

### Building from source (development)

```bash
nvm use                # Node 22 (see .nvmrc)
yarn osd bootstrap     # install dependencies
yarn start             # dev server against a local OpenSearch
```

This is a fork of OpenSearch Dashboards, so its
[developer guide](https://github.com/opensearch-project/OpenSearch-Dashboards/blob/main/DEVELOPER_GUIDE.md)
largely applies to the build tooling.

## Architecture notes

- **The fork is UI + application server only.** OpenSearch (the engine) is consumed as a stock
  upstream image and never patched — upgrades to the backend stay easy.
- **Detections compile to native OpenSearch alerting monitors** (doc-level and bucket-level),
  so rule execution, scheduling, and alert state live in the battle-tested alerting plugin;
  TLSOC adds the no-code layer, validation gates, and SOC workflow on top.
- **Events are ECS-normalized** by the FOSS SOC Engine before indexing, so detections and
  dashboards work across heterogeneous log sources.

## The TLSOC ecosystem

This repository is the SOC console — one component of the TLSOC stack:

| Repository | Role |
|---|---|
| **[TLSOC-Dashboards](https://github.com/sankettaware16/TLSOC-Dashboards)** (this repo) | The SOC UI + application server, incl. the one-click distribution in [`tlsocdistro/`](tlsocdistro/) |
| [foss-soc-engine](https://github.com/sankettaware16/foss-soc-engine) | The parsing engine: consumes raw logs from Kafka, normalizes to ECS |
| [tlsoc-machinelearning-framework](https://github.com/sankettaware16/tlsoc-machinelearning-framework) | ML-based detection component |
| [TLSOCDockerDeploy](https://github.com/sankettaware16/TLSOCDockerDeploy) | The ELK-edition deployment (predecessor of `tlsocdistro/`) |
| [tlsoc](https://github.com/sankettaware16/tlsoc) | Project landing page & docs |

## Support, issues & security

- **Bugs and feature requests** → [GitHub issues](https://github.com/sankettaware16/TLSOC-Dashboards/issues)
  (see [CONTRIBUTING.md](CONTRIBUTING.md) for what to include).
- **Security vulnerabilities** → report **privately** per [SECURITY.md](SECURITY.md) — never
  in a public issue.
- **Versioning**: TLSOC product releases are tagged `v1.x` (this is `v1.3.1`; the version is
  shown in the UI's Help menu). The underlying platform code is based on the OpenSearch
  Dashboards 3.x line, which is why `package.json` carries a `3.x` platform version.

## License & attribution

TLSOC is **Apache-2.0** (see [LICENSE.txt](LICENSE.txt)).

It is a fork of [OpenSearch Dashboards](https://github.com/opensearch-project/OpenSearch-Dashboards)
(itself derived from Kibana 7.10.2), and retains the original attribution and
[NOTICE.txt](NOTICE.txt). We are grateful to the OpenSearch project — the platform underneath
this product is theirs. TLSOC is not affiliated with or endorsed by the OpenSearch project,
Amazon, or Elastic. All TLSOC-added code is clean-room, Apache-2.0 licensed work.

## Project status

TLSOC is under active development by IITB Trust Lab and is deployed against live campus
telemetry. Issues and contributions are welcome — please open an issue to discuss substantial
changes first.
