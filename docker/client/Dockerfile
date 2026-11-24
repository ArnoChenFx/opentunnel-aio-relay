# OpenTunnel official client + lightweight web management UI.
#
# Build:
#   docker build -f docker/client/Dockerfile \
#     --build-arg OPENTUNNEL_VERSION=latest \
#     -t opentunnel-client .
#
# Run:
#   docker run --rm -e OPENTUNNEL_API=https://tunnel.example.com \
#     -p 9080:9080 -v opentunnel-data:/data \
#     --add-host=host.docker.internal:host-gateway \
#     opentunnel-client

ARG OPENTUNNEL_VERSION=latest

FROM debian:bookworm-slim AS fetch
ARG OPENTUNNEL_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /tmp
# Resolve the tag once so the tarball and its SHA256SUMS come from the same release.
RUN set -eux; \
  ver="${OPENTUNNEL_VERSION}"; \
  if [ "$ver" = "latest" ]; then \
    tag="$(curl -fsSIL -o /dev/null -w '%{url_effective}' https://github.com/anomalyco/opentunnel/releases/latest)"; \
    tag="${tag##*/}"; \
  else \
    tag="v${ver#v}"; \
  fi; \
  base="https://github.com/anomalyco/opentunnel/releases/download/${tag}"; \
  curl -fsSL --retry 3 -O "${base}/opentunnel-linux-x64.tar.gz"; \
  curl -fsSL --retry 3 -O "${base}/SHA256SUMS"; \
  grep -E '  opentunnel-linux-x64\.tar\.gz$' SHA256SUMS > expected.sha256; \
  sha256sum -c expected.sha256; \
  tar -xzf opentunnel-linux-x64.tar.gz; \
  chmod +x opentunnel; \
  ./opentunnel --version

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates python3 \
  && rm -rf /var/lib/apt/lists/*
COPY --from=fetch /tmp/opentunnel /usr/local/bin/opentunnel
COPY docker/client/entrypoint.sh /entrypoint.sh
COPY docker/client/mgmt /app/mgmt
RUN chmod +x /entrypoint.sh

ENV OPENTUNNEL_BIN=/usr/local/bin/opentunnel \
    OT_CLIENT_ADMIN_PORT=9080 \
    XDG_CONFIG_HOME=/data/config \
    XDG_DATA_HOME=/data/data \
    XDG_STATE_HOME=/data/state \
    XDG_RUNTIME_DIR=/run/opentunnel

VOLUME ["/data"]
EXPOSE 9080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9080/health')" || exit 1

ENTRYPOINT ["/entrypoint.sh"]
