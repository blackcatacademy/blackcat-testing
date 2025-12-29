FROM ghcr.io/foundry-rs/foundry:stable AS foundry

FROM debian:bookworm-slim

RUN set -eux; \
  apt-get update; \
  apt-get install -y --no-install-recommends ca-certificates jq; \
  rm -rf /var/lib/apt/lists/*

COPY --from=foundry /usr/local/bin/cast /usr/local/bin/cast

COPY blackcat-testing/docker/minimal-prod/watcher/watcher.sh /watcher.sh
RUN chmod 0755 /watcher.sh

USER 33:33
ENTRYPOINT ["/watcher.sh"]

