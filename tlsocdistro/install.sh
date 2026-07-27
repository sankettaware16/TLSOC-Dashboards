#!/usr/bin/env bash
# TLSOC (OpenSearch edition) — one-click installer. Mirrors TLSOCDockerDeploy.
set -e

echo "[+] TLSOC One-Click Installer (OpenSearch edition)"

command -v docker >/dev/null || { echo "Docker is required"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required"; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required (used to generate the dashboards TLS certificate)"; exit 1; }

# ---- Env ----
if [ ! -f .env ]; then
  echo "[+] Creating .env from template — review the passwords in it before production use."
  cp .env.example .env
fi

# ---- HOST_IP (endpoints forward to <HOST_IP>:9094) ----
# Prefer a default-route interface that is NOT a VPN/virtual one (tun*, tailscale*, wg*, docker*…) —
# picking a VPN IP here would make Kafka advertise an address endpoints can't reach.
detect_host_ip() {
  local dev ip
  for dev in $(ip route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev") print $(i+1)}'); do
    case "$dev" in tun*|tap*|wg*|tailscale*|zt*|docker*|br-*|veth*|lo) continue ;; esac
    ip=$(ip -4 addr show dev "$dev" scope global 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}' | head -1)
    [ -n "$ip" ] && { echo "$ip"; return; }
  done
  # fallback: first global IPv4 on a physical-looking interface
  ip -4 -o addr show scope global 2>/dev/null \
    | awk '$2 !~ /^(tun|tap|wg|tailscale|zt|docker|br-|veth)/ {print $4}' | cut -d/ -f1 | head -1
}
AUTO_IP=$(detect_host_ip)
ENV_IP=$(grep '^HOST_IP=' .env | cut -d= -f2)
if [[ -z "$ENV_IP" || "$ENV_IP" == "<IP_OF_THIS_MACHINE>" ]]; then
  echo "[+] Auto-detected HOST_IP: $AUTO_IP   (wrong one? set HOST_IP in .env and re-run)"
  sed -i "s|^HOST_IP=.*|HOST_IP=$AUTO_IP|" .env
fi

# ---- Load env ----
set -a; source .env; set +a

# ---- Admin password preflight (OpenSearch 2.12+ rejects weak/similar passwords at first boot) ----
PW="$OPENSEARCH_ADMIN_PASSWORD"
PW_ERR=""
[ ${#PW} -lt 8 ] && PW_ERR="it is shorter than 8 characters"
echo "$PW" | grep -q '[A-Z]' || PW_ERR="it has no uppercase letter"
echo "$PW" | grep -q '[a-z]' || PW_ERR="it has no lowercase letter"
echo "$PW" | grep -q '[0-9]' || PW_ERR="it has no digit"
echo "$PW" | grep -q '[^A-Za-z0-9]' || PW_ERR="it has no special character"
echo "$PW" | grep -qi 'admin' && PW_ERR="it contains 'admin' (too similar to the username — OpenSearch rejects this)"
if [ -n "$PW_ERR" ]; then
  echo "[!] OPENSEARCH_ADMIN_PASSWORD in .env would be REJECTED by OpenSearch: $PW_ERR."
  echo "    Set a password with upper+lower+digit+special, 8+ chars, not containing 'admin',"
  echo "    then re-run ./install.sh   (example shape: Blue#Harbor2026!)"
  exit 1
fi

# ---- Parser output dir (the FOSS SOC Engine writes here; Logstash mounts it) ----
mkdir -p "$PARSER_OUTPUT_DIR" 2>/dev/null || sudo mkdir -p "$PARSER_OUTPUT_DIR"
echo "[+] Parser output dir: $PARSER_OUTPUT_DIR (install the FOSS SOC Engine to write here — see README)"

# ---- Dashboards TLS certificate (self-signed; HTTPS by default) ----
# Browsers warn once on a self-signed cert — accept it, or replace with a real cert for
# production (see README → Production hardening).
if [ ! -f certs/dashboards/tlsoc-dashboards.crt ]; then
  echo "[+] Generating a self-signed TLS certificate for the dashboards…"
  mkdir -p certs/dashboards
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout certs/dashboards/tlsoc-dashboards.key \
    -out   certs/dashboards/tlsoc-dashboards.crt \
    -subj "/CN=tlsoc-dashboards" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:${HOST_IP}" 2>/dev/null
  chmod 644 certs/dashboards/tlsoc-dashboards.key certs/dashboards/tlsoc-dashboards.crt
fi

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

# ---- Remove stale TLSOC containers from a previous install (data volumes are preserved) ----
# Containers survive `rm -rf` of a project folder; a leftover with the same name makes
# `docker compose up` fail with "Conflict: container name already in use".
for C in tlsoc-opensearch tlsoc-dashboards tlsoc-kafka tlsoc-logstash; do
  if docker ps -a --format '{{.Names}}' | grep -qx "$C"; then
    echo "[+] Removing stale container $C from a previous install (volumes/data are kept)…"
    docker rm -f "$C" >/dev/null
  fi
done

# ---- Start (everything EXCEPT Logstash) ----
# Logstash is held back deliberately: if it starts alongside OpenSearch it can index the first
# events — creating per-endpoint indices with DYNAMIC (text) field mappings — BEFORE the ECS index
# template is loaded, which then breaks aggregations like source.ip on the Overview. Load the
# template + ISM first, THEN start Logstash so every fosstlsoc-logs-* index is born with correct
# ECS types.
echo "[+] Starting OpenSearch, Dashboards, and Kafka (Logstash starts after the template loads)…"
docker compose up -d opensearch tlsoc-dashboards kafka

# ---- Wait for OpenSearch (bounded, with real diagnostics on failure) ----
echo "[+] Waiting for OpenSearch to be ready…"
OS_OK=""
for attempt in $(seq 1 60); do
  STATE=$(docker inspect -f '{{.State.Status}}' tlsoc-opensearch 2>/dev/null || echo missing)
  if [ "$STATE" = "exited" ] || [ "$STATE" = "dead" ] || [ "$STATE" = "missing" ]; then
    echo "[!] OpenSearch container is '$STATE'. Last log lines:"
    echo "--------------------------------------------------------------"
    docker logs --tail 25 tlsoc-opensearch 2>&1 || true
    echo "--------------------------------------------------------------"
    echo "    Common cause: the admin password failed OpenSearch's validation"
    echo "    (e.g. it contains 'admin' or is too weak). Fix OPENSEARCH_ADMIN_PASSWORD"
    echo "    in .env and re-run ./install.sh"
    exit 1
  fi
  if curl -sk -u "admin:${OPENSEARCH_ADMIN_PASSWORD}" https://localhost:9200 >/dev/null 2>&1; then OS_OK=yes; break; fi
  sleep 5
done
if [ -z "$OS_OK" ]; then
  echo "[!] OpenSearch did not become ready within 5 minutes. Last log lines:"
  docker logs --tail 25 tlsoc-opensearch 2>&1 || true
  exit 1
fi

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

# ---- Wait for the Dashboards login page (bounded; diagnostics on failure) ----
echo "[+] Waiting for TLSOC Dashboards…"
DASH_OK=""
for attempt in $(seq 1 24); do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://localhost:${DASHBOARDS_PORT}/app/login" 2>/dev/null || true)
  [ "$CODE" = "200" ] && { DASH_OK=yes; break; }
  sleep 5
done
if [ -z "$DASH_OK" ]; then
  echo "[!] Dashboards not answering yet on https://localhost:${DASHBOARDS_PORT}/ — recent logs:"
  docker logs --tail 20 tlsoc-dashboards 2>&1 || true
  echo "    (it may still come up — check again with:  docker logs -f tlsoc-dashboards)"
fi

echo "--------------------------------------------------------------"
echo " TLSOC Dashboards: https://${HOST_IP}:${DASHBOARDS_PORT}/"
echo " Login:            admin / (OPENSEARCH_ADMIN_PASSWORD in .env)"
echo ""
echo " The certificate is self-signed, so your browser warns once —"
echo " choose Advanced → Continue. Replace it with a real certificate"
echo " for production (README → Production hardening)."
echo ""
echo " No logs yet? That's expected — the Overview shows the onboarding"
echo " guide. Onboard your first server:  run ./tlsoc-onboard.sh on it"
echo " (it forwards logs to ${HOST_IP}:9094). Make sure the FOSS SOC"
echo " Engine is running on this host and writing to ${PARSER_OUTPUT_DIR}."
echo "--------------------------------------------------------------"
