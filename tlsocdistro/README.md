# TLSOC — One-Click SOC Stack (OpenSearch edition)

A **plug-and-play SOC deployment** using Docker Compose:

```
endpoints ──rsyslog/omkafka──▶ Kafka ──▶ FOSS SOC Engine ──▶ Logstash ──▶ OpenSearch ──▶ TLSOC Dashboards
```

This is the OpenSearch edition of `TLSOCDockerDeploy` (the ELK edition). It follows the **same
layout and flow** — the only differences are:

| | ELK edition (`TLSOCDockerDeploy`) | This edition (`tlsocdistro`) |
|---|---|---|
| Store | Elasticsearch | **OpenSearch** |
| UI | Kibana | **TLSOC Dashboards** (the hard fork) |
| Log transport | Kafka | Kafka (unchanged) |
| Parsing | FOSS SOC Engine | FOSS SOC Engine (unchanged) |
| Ship to store | Logstash → `elasticsearch` output | Logstash → **`opensearch` output** (only the output plugin + index name changed) |

Agentless: endpoints only run the standard rsyslog Kafka forwarder — nothing else to install on them.

---

## Prerequisites

- A Linux host (Ubuntu 22.04 / 24.04 recommended), Docker + Docker Compose v2.
- To **build the TLSOC Dashboards image** (one-time): a machine with the OpenSearch-Dashboards fork
  checked out, Node 22, ~8 GB RAM.

---

## Install (4 steps)

### 1. Get the TLSOC Dashboards image

**Option A — pull the prebuilt image (default, ~2 min).** The `.env.example` already points at
the public image, so Docker pulls it automatically on `install.sh`:

```bash
docker pull ghcr.io/sankettaware16/tlsoc-dashboards:1.3.0    # optional pre-pull
```

**Option B — build it from source (one-time, ~20–40 min).** For air-gapped hosts or custom
builds:

```bash
# from the TLSOC-Dashboards repo root (Node 22, ~8 GB RAM):
bash tlsocdistro/dashboards/build-image.sh      # → tlsoc-dashboards:1.3.0
```

Then set `TLSOC_DASHBOARDS_IMAGE=tlsoc-dashboards:1.3.0` in `.env` (and copy the image to your
deployment host or your own registry if you build elsewhere).

### 2. Install the FOSS SOC Engine on this host

The engine consumes raw logs from Kafka, parses/normalizes them to ECS, and writes JSON into
`PARSER_OUTPUT_DIR` (default `/var/log/soc_output`), which Logstash tails.

```bash
git clone -b production-hardening https://github.com/sankettaware16/foss-soc-engine.git
cd foss-soc-engine && ./install.sh
# edit config.yaml:
#   kafka.bootstrap_servers: ["localhost:9094"]     # this host's Kafka external listener
#   kafka.input_topic: "cse_logs"                    # or a regex matching your topics
#   paths.output_dir: "/var/log/soc_output"          # must equal PARSER_OUTPUT_DIR in .env
#   program_mapping: map each source_program → a parsing rule
python3 preflight.py            # validates config + Kafka reachability
sudo ./setup_service.sh         # runs it under systemd (foss-soc)
```

### 3. Configure and start the stack

```bash
cd tlsocdistro
cp .env.example .env
nano .env                       # set OPENSEARCH_ADMIN_PASSWORD, TLSOC_DASHBOARDS_IMAGE, PARSER_OUTPUT_DIR
sudo ./install.sh               # auto-detects HOST_IP, starts everything, loads the index template
```

Open **`http://<HOST_IP>:5601/`** → log in as `admin` / your `OPENSEARCH_ADMIN_PASSWORD`.
With no logs yet, the **Overview** shows the onboarding guide (this is expected).

### 4. Onboard your first endpoint

On any server you want to monitor, forward its logs to this stack's Kafka:

```bash
sudo apt install -y rsyslog-kafka
# automated (asks org/dept/env/server-id, auto-discovers /var/log, verifies delivery):
sudo bash tlsoc-onboard.sh
#   → point it at  <HOST_IP>:9094  and choose a Kafka topic (e.g. cse_logs)
```

Within seconds the events flow through Kafka → engine → Logstash → OpenSearch, and the TLSOC
**Overview cockpit** lights up automatically (new sources, ingest lag, source types, geo, …).

---

## Verify the pipeline

```bash
# logs reaching Kafka:
docker exec -it tlsoc-kafka /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server kafka:9092 --topic <your-topic>

# events landing in OpenSearch:
source .env
curl -sk -u admin:"$OPENSEARCH_ADMIN_PASSWORD" "https://localhost:9200/_cat/indices/fosstlsoc-logs-*?v"

# Logstash health:
docker logs tlsoc-logstash -f
```

---

## Index naming, retention & event timestamps

- **Per-endpoint indices.** Logstash writes each endpoint's logs to its own daily index:
  `fosstlsoc-logs-<server_slug>-YYYY.MM.dd`, where `server_slug` is the endpoint's
  `observer.server` (falling back to `observer.source_host`, then the literal `unknown`),
  lowercased and sanitized to `[a-z0-9_.-]`. The `fosstlsoc-logs-*` index pattern/template still
  matches every one of these, so Discover/data-views/dashboards built against it keep working
  unchanged. Indices from before this change (plain `fosstlsoc-logs-YYYY.MM.dd`, no per-endpoint
  slug) remain valid and queryable — nothing is migrated or deleted.
- **Retention.** `install.sh` also loads an ISM (Index State Management) policy,
  `fosstlsoc-logs-retention`, that auto-attaches to every `fosstlsoc-logs-*` index and deletes it
  once it turns **90 days old** (default). To change the retention window, edit
  `min_index_age` in `opensearch/fosstlsoc-ism-policy.json` and re-run the PUT in `install.sh`
  (or `curl -X PUT .../_plugins/_ism/policies/fosstlsoc-logs-retention` with the updated body —
  existing indices already attached to the policy pick up the new age on their next check).
- **Event timestamps.** `tlsoc-onboard.sh` now forwards the endpoint's real syslog timestamp
  (`meta.source_timestamp`, RFC3339) in the envelope it sends to Kafka, so the engine can use the
  log line's actual time instead of falling back to ingest time. This is backward compatible:
  endpoints onboarded with an older version of the script simply omit the field and keep using
  ingest-time timestamps until they're re-onboarded with the current script.

---

## Production hardening (before real use)

This edition boots with OpenSearch's **demo security** (self-signed certs + a demo internal-users
config) so it runs out of the box. Before production:

1. **Replace the demo certificates** with real ones (node + admin certs), set
   `opensearch.ssl.verificationMode: full` in `dashboards/opensearch_dashboards.yml` and
   `ssl_certificate_verification => true` (+ a `cacert`) in `logstash/pipeline/all.conf`.
2. **Change every credential**: `OPENSEARCH_ADMIN_PASSWORD`, the `kibanaserver` service account, the
   `opensearch_security.cookie.password`, and provision real SOC users via the security UI.
3. **Firewall OpenSearch (`:9200`) away from end users** — TLSOC Dashboards must be the only client.
4. Provision the real SOC roles/users and workspaces (see the TLSOC Dashboards docs).

---

## Layout

```
tlsocdistro/
├── docker-compose.yml            # opensearch · tlsoc-dashboards · kafka · logstash
├── .env.example                  # versions, passwords, HOST_IP, ports, parser output dir
├── install.sh                    # one-click: detect IP → start → load index template + ISM retention policy
├── tlsoc-onboard.sh              # run ON an endpoint to forward its logs (agentless)
├── opensearch/
│   ├── fosstlsoc-index-template.json   # ECS field types for fosstlsoc-logs-* (from the engine template)
│   └── fosstlsoc-ism-policy.json       # 90d retention policy, auto-attached to fosstlsoc-logs-*
├── dashboards/
│   ├── Dockerfile                # packages the built TLSOC Dashboards distributable
│   ├── build-image.sh            # builds that distributable from the forked source
│   └── opensearch_dashboards.yml # TLSOC config (security, workspaces, Overview pattern)
└── logstash/
    ├── config/{logstash.yml,pipelines.yml}
    └── pipeline/all.conf         # /parser_output/*.json → opensearch (index fosstlsoc-logs-<server_slug>-*)
```
