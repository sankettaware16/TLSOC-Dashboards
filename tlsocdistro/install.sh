#!/usr/bin/env bash
# TLSOC (OpenSearch edition) — one-click installer. Mirrors TLSOCDockerDeploy.
set -e

echo "[+] TLSOC One-Click Installer (OpenSearch edition)"

command -v docker >/dev/null || { echo "Docker is required"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required"; exit 1; }

# ---- Env ----
if [ ! -f .env ]; then
  echo "[+] Creating .env from template — review the passwords in it before production use."
  cp .env.example .env
fi

# ---- HOST_IP (endpoints forward to <HOST_IP>:9094) ----
AUTO_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}')
ENV_IP=$(grep '^HOST_IP=' .env | cut -d= -f2)
if [[ -z "$ENV_IP" || "$ENV_IP" == "<IP_OF_THIS_MACHINE>" ]]; then
  echo "[+] Auto-detected HOST_IP: $AUTO_IP"
  sed -i "s|^HOST_IP=.*|HOST_IP=$AUTO_IP|" .env
fi

# ---- Load env ----
set -a; source .env; set +a

# ---- Parser output dir (the FOSS SOC Engine writes here; Logstash mounts it) ----
mkdir -p "$PARSER_OUTPUT_DIR" 2>/dev/null || sudo mkdir -p "$PARSER_OUTPUT_DIR"
echo "[+] Parser output dir: $PARSER_OUTPUT_DIR (install the FOSS SOC Engine to write here — see README)"

# ---- TLSOC Dashboards image present? Pull it if not (the default is the public GHCR image) ----
if ! docker image inspect "$TLSOC_DASHBOARDS_IMAGE" >/dev/null 2>&1; then
  echo "[+] TLSOC Dashboards image '$TLSOC_DASHBOARDS_IMAGE' not found locally — pulling…"
  if ! docker pull "$TLSOC_DASHBOARDS_IMAGE"; then
    echo "[!] Could not pull '$TLSOC_DASHBOARDS_IMAGE'."
    echo "    Either fix TLSOC_DASHBOARDS_IMAGE in .env (default: the public image"
    echo "    ghcr.io/sankettaware16/tlsoc-dashboards:1.3.0), or build it from source (one-time):"
    echo "        bash dashboards/build-image.sh"
    echo "    then re-run ./install.sh"
    exit 1
  fi
fi

# ---- Start (everything EXCEPT Logstash) ----
# Logstash is held back deliberately: if it starts alongside OpenSearch it can index the first
# events — creating per-endpoint indices with DYNAMIC (text) field mappings — BEFORE the ECS index
# template is loaded, which then breaks aggregations like source.ip on the Overview. Load the
# template + ISM first, THEN start Logstash so every fosstlsoc-logs-* index is born with correct
# ECS types.
echo "[+] Starting OpenSearch, Dashboards, and Kafka (Logstash starts after the template loads)…"
docker compose up -d opensearch tlsoc-dashboards kafka

# ---- Wait for OpenSearch, then load the log index template ----
echo "[+] Waiting for OpenSearch to be ready…"
until curl -sk -u "admin:${OPENSEARCH_ADMIN_PASSWORD}" https://localhost:9200 >/dev/null 2>&1; do sleep 5; done
echo "[+] Loading the TLSOC log index template (correct ECS field types)…"
# Retry + verify: the bare PUT used to swallow its response, so a transient failure (cluster still
# settling right after the readiness probe) left indices to be created with dynamic text mappings.
TPL_OK=""
for attempt in 1 2 3 4 5 6; do
  TPL_RESP=$(curl -sk -u "admin:${OPENSEARCH_ADMIN_PASSWORD}" -H 'Content-Type: application/json' \
    -X PUT "https://localhost:9200/_index_template/fosstlsoc-logs" \
    --data-binary @opensearch/fosstlsoc-index-template.json)
  if echo "$TPL_RESP" | grep -q '"acknowledged":true'; then TPL_OK=yes; echo "    template loaded"; break; fi
  echo "    template not accepted yet (attempt $attempt/6), retrying in 10s… (last: $TPL_RESP)"; sleep 10
done
[ -z "$TPL_OK" ] && { echo "    [!] index template FAILED to load — aborting before Logstash starts so indices don't get dynamic mappings. Last response: $TPL_RESP"; exit 1; }

echo "[+] Loading the TLSOC log retention policy (ISM, 90d default)…"
# The ISM plugin warms up AFTER the cluster reports ready — a PUT fired too early fails with an
# opaque error (seen in the first from-scratch install). Retry until it lands; only a
# version_conflict (policy already exists from a prior run) is acceptable as-is.
ISM_OK=""
for attempt in 1 2 3 4 5 6; do
  ISM_RESP=$(curl -sk -u "admin:${OPENSEARCH_ADMIN_PASSWORD}" -H 'Content-Type: application/json' \
    -X PUT "https://localhost:9200/_plugins/_ism/policies/fosstlsoc-logs-retention" \
    --data-binary @opensearch/fosstlsoc-ism-policy.json)
  if echo "$ISM_RESP" | grep -q '"policy_id"'; then ISM_OK=yes; echo "    ISM policy loaded"; break; fi
  if echo "$ISM_RESP" | grep -q 'version_conflict'; then ISM_OK=yes; echo "    ISM policy already exists (ok)"; break; fi
  echo "    ISM not ready yet (attempt $attempt/6), retrying in 10s…"; sleep 10
done
[ -z "$ISM_OK" ] && echo "    [!] ISM policy could not be loaded — run the PUT from install.sh manually. Last response: $ISM_RESP"
# ism_template only auto-attaches to indices created AFTER the policy exists; attach any that
# already exist (first boot after an upgrade, or logs that raced the install). Harmless if none.
curl -sk -u "admin:${OPENSEARCH_ADMIN_PASSWORD}" -H 'Content-Type: application/json' \
  -X POST "https://localhost:9200/_plugins/_ism/add/fosstlsoc-logs-*" \
  -d '{"policy_id":"fosstlsoc-logs-retention"}' >/dev/null 2>&1 || true

# ---- Now that the template + ISM are in place, start Logstash ----
echo "[+] Starting Logstash (indices will now be created with correct ECS mappings)…"
docker compose up -d logstash

echo "--------------------------------------------------------------"
echo " TLSOC Dashboards: http://${HOST_IP}:${DASHBOARDS_PORT}/"
echo " Login:            admin / (OPENSEARCH_ADMIN_PASSWORD in .env)"
echo ""
echo " No logs yet? That's expected — the Overview shows the onboarding"
echo " guide. Onboard your first server:  run ./tlsoc-onboard.sh on it"
echo " (it forwards logs to ${HOST_IP}:9094). Make sure the FOSS SOC"
echo " Engine is running on this host and writing to ${PARSER_OUTPUT_DIR}."
echo "--------------------------------------------------------------"
