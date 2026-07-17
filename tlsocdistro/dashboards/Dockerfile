# TLSOC Dashboards runtime image.
#
# Build CONTEXT for this Dockerfile is the OSD linux-x64 platform directory produced by the OSD
# build (build/opensearch-dashboards-<version>-linux-x64/). Do not build it by hand — run
# ./dashboards/build-image.sh, which builds the distributable from the hard-forked source and then
# invokes this Dockerfile. The distributable bundles its own Node runtime, so no Node install here.

FROM ubuntu:24.04

RUN userdel -r ubuntu 2>/dev/null || true \
 && groupdel ubuntu 2>/dev/null || true \
 && groupadd -g 1000 tlsoc \
 && useradd -u 1000 -g 1000 -d /usr/share/opensearch-dashboards -s /bin/bash tlsoc \
 && apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl fontconfig \
 && rm -rf /var/lib/apt/lists/*

COPY --chown=1000:1000 . /usr/share/opensearch-dashboards/

WORKDIR /usr/share/opensearch-dashboards
USER 1000
ENV OSD_PATH_CONF=/usr/share/opensearch-dashboards/config
EXPOSE 5601

# config/opensearch_dashboards.yml is bind-mounted by docker-compose at runtime.
CMD ["./bin/opensearch-dashboards"]
