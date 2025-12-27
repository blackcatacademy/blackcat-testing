FROM composer:2.7 AS builder

WORKDIR /workspace

# Path repositories referenced by blackcat-testing/composer.json
COPY blackcat-core/ /workspace/blackcat-core/
COPY blackcat-config/ /workspace/blackcat-config/
COPY blackcat-testing/ /workspace/blackcat-testing/

WORKDIR /workspace/blackcat-testing
RUN COMPOSER_MIRROR_PATH_REPOS=1 composer install --no-dev --no-interaction --no-progress --optimize-autoloader

FROM php:8.3-cli

RUN set -eux; \
  docker-php-ext-install pdo_mysql; \
  php -m | grep -E '^pdo_mysql$'; \
  php -m | grep -E '^sodium$'

WORKDIR /srv/blackcat

COPY --from=builder /workspace/blackcat-testing/vendor/ /srv/blackcat/vendor/
COPY --from=builder /workspace/blackcat-testing/environments/minimal-site/ /srv/blackcat/site/
COPY --from=builder /workspace/blackcat-core/ /srv/blackcat-core/
COPY --from=builder /workspace/blackcat-config/ /srv/blackcat-config/

COPY blackcat-testing/docker/minimal-prod/app/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
