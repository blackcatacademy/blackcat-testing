FROM alpine:3.20

RUN apk add --no-cache bash curl jq

COPY blackcat-testing/docker/minimal-prod/attacker/run.sh /run.sh
RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]

