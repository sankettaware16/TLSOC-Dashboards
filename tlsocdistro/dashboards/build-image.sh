#!/usr/bin/env bash
#
# Build the TLSOC Dashboards Docker image from the hard-forked OpenSearch-Dashboards source.
# This is the one heavy, one-time step of the distribution (the production build takes ~20–40 min).
# Run it on a build machine (Node 22, ~8 GB RAM, the OSD repo checked out), then copy the resulting
# image to your deployment host (or push it to a registry).
#
# Usage:   bash dashboards/build-image.sh [image:tag]     (default tlsoc-dashboards:1.3.0)
set -euo pipefail

IMAGE="${1:-${TLSOC_DASHBOARDS_IMAGE:-tlsoc-dashboards:1.3.0}}"
# tlsocdistro/dashboards/ -> repo root (two levels up)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

echo "[+] TLSOC Dashboards image build"
echo "    repo:  $REPO_ROOT"
echo "    image: $IMAGE"

command -v docker >/dev/null || { echo "Docker is required"; exit 1; }

echo "[+] (1/4) Bootstrapping dependencies (yarn osd bootstrap)…"
yarn osd bootstrap

echo "[+] (2/4) Building the security-dashboards-plugin zip…"
# scripts/build's CopySource step does not select plugins/**, and the vendored plugin ships as a
# husk in the distributable without this step (PROB-6) — build its installable zip explicitly.
SECURITY_PLUGIN_DIR="$REPO_ROOT/plugins/security-dashboards-plugin"
if [ ! -d "$SECURITY_PLUGIN_DIR" ]; then
  echo "[!] $SECURITY_PLUGIN_DIR not found — the security-dashboards-plugin must be vendored first."
  exit 1
fi
(cd "$SECURITY_PLUGIN_DIR" && yarn build)
SECURITY_PLUGIN_ZIP="$(ls -t "$SECURITY_PLUGIN_DIR"/build/security-dashboards-*.zip 2>/dev/null | head -1 || true)"
if [ -z "$SECURITY_PLUGIN_ZIP" ]; then
  echo "[!] security-dashboards-plugin build did not produce a zip (expected plugins/security-dashboards-plugin/build/security-dashboards-*.zip)."
  exit 1
fi
echo "[+] built security plugin zip: $SECURITY_PLUGIN_ZIP"

echo "[+] (3/4) Building the linux-x64 distributable — this takes a while…"
./scripts/use_node scripts/build --linux --skip-os-packages --release

PLATDIR="$(ls -d "$REPO_ROOT"/build/opensearch-dashboards-*-linux-x64 2>/dev/null | head -1 || true)"
if [ -z "$PLATDIR" ] || [ ! -x "$PLATDIR/bin/opensearch-dashboards" ]; then
  echo "[!] Build output not found (expected build/opensearch-dashboards-*-linux-x64/bin/opensearch-dashboards)."
  exit 1
fi
echo "[+] built: $PLATDIR"

echo "[+] Installing the security-dashboards-plugin into the distributable…"
"$PLATDIR/bin/opensearch-dashboards-plugin" install "file://$SECURITY_PLUGIN_ZIP"
echo "[+] installed plugin: $(basename "$SECURITY_PLUGIN_ZIP") -> $PLATDIR/plugins/securityDashboards"

# scripts/build's optimizer emits a manifest-less husk of the vendored plugin (browser bundles
# only) into the distributable's plugins/ — inert at runtime (no opensearch_dashboards.json →
# plugin discovery skips it) but dead weight next to the real install above; drop it.
rm -rf "$PLATDIR/plugins/security-dashboards-plugin"

echo "[+] (4/4) Building Docker image $IMAGE…"
docker build -f "$REPO_ROOT/tlsocdistro/dashboards/Dockerfile" -t "$IMAGE" "$PLATDIR"

echo "[+] Done. Set  TLSOC_DASHBOARDS_IMAGE=$IMAGE  in tlsocdistro/.env, then run ./install.sh"
