#!/usr/bin/env bash
#
# Build the TLSOC Dashboards Docker image from the hard-forked OpenSearch-Dashboards source.
# This is the one heavy, one-time step of the distribution (the production build takes ~20–40 min).
# Run it on a build machine (Node 22, ~8 GB RAM, the OSD repo checked out), then copy the resulting
# image to your deployment host (or push it to a registry).
#
# Usage:   bash dashboards/build-image.sh [image:tag]     (default tlsoc-dashboards:1.3.1)
set -euo pipefail

IMAGE="${1:-${TLSOC_DASHBOARDS_IMAGE:-tlsoc-dashboards:1.3.1}}"
# tlsocdistro/dashboards/ -> repo root (two levels up)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

echo "[+] TLSOC Dashboards image build"
echo "    repo:  $REPO_ROOT"
echo "    image: $IMAGE"

command -v docker >/dev/null || { echo "Docker is required"; exit 1; }

echo "[+] (1/4) Bootstrapping dependencies (yarn osd bootstrap)…"
yarn osd bootstrap

echo "[+] (2/4) Building the vendored plugin zips…"
# scripts/build's CopySource step does not select plugins/**, and the vendored plugins ship as
# husks in the distributable without this step (PROB-6) — build their installable zips explicitly.
SECURITY_PLUGIN_DIR="$REPO_ROOT/plugins/security-dashboards-plugin"
if [ ! -d "$SECURITY_PLUGIN_DIR" ]; then
  echo "[!] $SECURITY_PLUGIN_DIR not found — the security-dashboards-plugin must be vendored first:"
  echo "    git clone https://github.com/opensearch-project/security-dashboards-plugin plugins/security-dashboards-plugin"
  echo "    (use a commit whose opensearch_dashboards.json targets opensearchDashboardsVersion 3.8.0, e.g. a3062d15cd5e)"
  exit 1
fi
(cd "$SECURITY_PLUGIN_DIR" && yarn build)
SECURITY_PLUGIN_ZIP="$(ls -t "$SECURITY_PLUGIN_DIR"/build/security-dashboards-*.zip 2>/dev/null | head -1 || true)"
if [ -z "$SECURITY_PLUGIN_ZIP" ]; then
  echo "[!] security-dashboards-plugin build did not produce a zip (expected plugins/security-dashboards-plugin/build/security-dashboards-*.zip)."
  exit 1
fi
echo "[+] built security plugin zip: $SECURITY_PLUGIN_ZIP"

ISM_PLUGIN_DIR="$REPO_ROOT/plugins/index-management-dashboards-plugin"
if [ ! -d "$ISM_PLUGIN_DIR" ]; then
  echo "[!] $ISM_PLUGIN_DIR not found — the index-management-dashboards-plugin must be vendored first:"
  echo "    git clone https://github.com/opensearch-project/index-management-dashboards-plugin plugins/index-management-dashboards-plugin"
  echo "    (use a commit whose opensearch_dashboards.json targets opensearchDashboardsVersion 3.8.0, e.g. e47561cf920d)"
  exit 1
fi
(cd "$ISM_PLUGIN_DIR" && yarn build)
ISM_PLUGIN_ZIP="$(ls -t "$ISM_PLUGIN_DIR"/build/index-management-dashboards-*.zip 2>/dev/null | head -1 || true)"
if [ -z "$ISM_PLUGIN_ZIP" ]; then
  echo "[!] index-management-dashboards-plugin build did not produce a zip (expected plugins/index-management-dashboards-plugin/build/index-management-dashboards-*.zip)."
  exit 1
fi
echo "[+] built index-management plugin zip: $ISM_PLUGIN_ZIP"

echo "[+] (3/4) Building the linux-x64 distributable — this takes a while…"
./scripts/use_node scripts/build --linux --skip-os-packages --release

PLATDIR="$(ls -d "$REPO_ROOT"/build/opensearch-dashboards-*-linux-x64 2>/dev/null | head -1 || true)"
if [ -z "$PLATDIR" ] || [ ! -x "$PLATDIR/bin/opensearch-dashboards" ]; then
  echo "[!] Build output not found (expected build/opensearch-dashboards-*-linux-x64/bin/opensearch-dashboards)."
  exit 1
fi
echo "[+] built: $PLATDIR"

echo "[+] Installing the vendored plugins into the distributable…"
"$PLATDIR/bin/opensearch-dashboards-plugin" install "file://$SECURITY_PLUGIN_ZIP"
echo "[+] installed plugin: $(basename "$SECURITY_PLUGIN_ZIP") -> $PLATDIR/plugins/securityDashboards"
"$PLATDIR/bin/opensearch-dashboards-plugin" install "file://$ISM_PLUGIN_ZIP"
echo "[+] installed plugin: $(basename "$ISM_PLUGIN_ZIP") -> $PLATDIR/plugins/indexManagementDashboards"

# scripts/build's optimizer emits manifest-less husks of the vendored plugins (browser bundles
# only) into the distributable's plugins/ — inert at runtime (no opensearch_dashboards.json →
# plugin discovery skips it) but dead weight next to the real installs above; drop them.
rm -rf "$PLATDIR/plugins/security-dashboards-plugin"
rm -rf "$PLATDIR/plugins/index-management-dashboards-plugin"

echo "[+] (4/4) Building Docker image $IMAGE…"
docker build -f "$REPO_ROOT/tlsocdistro/dashboards/Dockerfile" -t "$IMAGE" "$PLATDIR"

echo "[+] Done. Set  TLSOC_DASHBOARDS_IMAGE=$IMAGE  in tlsocdistro/.env, then run ./install.sh"
