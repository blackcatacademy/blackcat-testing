FROM composer:2.7 AS builder

WORKDIR /workspace

COPY blackcat-core/ /workspace/blackcat-core/
COPY blackcat-config/ /workspace/blackcat-config/

COPY blackcat-testing/composer.json blackcat-testing/composer.lock /workspace/blackcat-testing/
COPY blackcat-testing/phpunit.xml.dist blackcat-testing/phpstan.neon /workspace/blackcat-testing/
COPY blackcat-testing/src/ /workspace/blackcat-testing/src/
COPY blackcat-testing/tests/ /workspace/blackcat-testing/tests/
COPY blackcat-testing/docker/test-suite/entrypoint.sh /workspace/blackcat-testing/docker/test-suite/entrypoint.sh

WORKDIR /workspace/blackcat-testing
RUN COMPOSER_MIRROR_PATH_REPOS=1 composer install --no-interaction --no-progress

FROM php:8.3-cli

RUN set -eux; \
  apt-get update; \
  apt-get install -y --no-install-recommends libcurl4-openssl-dev; \
  docker-php-ext-install curl; \
  rm -rf /var/lib/apt/lists/*; \
  php -m | grep -E '^curl$'; \
  php -m | grep -E '^sodium$'

WORKDIR /app
COPY --from=builder /workspace/blackcat-testing/ /app/
COPY --from=builder /workspace/blackcat-testing/vendor/ /app/vendor/

RUN chmod +x /app/docker/test-suite/entrypoint.sh

ENTRYPOINT ["/app/docker/test-suite/entrypoint.sh"]
