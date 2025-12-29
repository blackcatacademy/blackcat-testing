FROM composer:2.7 AS builder

WORKDIR /workspace

# Path repositories referenced by blackcat-testing/composer.json
COPY blackcat-core/ /workspace/blackcat-core/
COPY blackcat-config/ /workspace/blackcat-config/

# Keep composer install cache stable: copy only what affects dependencies/autoload.
COPY blackcat-testing/composer.json blackcat-testing/composer.lock /workspace/blackcat-testing/
COPY blackcat-testing/src/ /workspace/blackcat-testing/src/

WORKDIR /workspace/blackcat-testing
RUN COMPOSER_MIRROR_PATH_REPOS=1 composer install --no-dev --no-interaction --no-progress --optimize-autoloader

FROM php:8.3-cli

RUN set -eux; \
  apt-get update; \
  apt-get install -y --no-install-recommends libcurl4-openssl-dev; \
  docker-php-ext-install pdo_mysql; \
  docker-php-ext-install curl; \
  rm -rf /var/lib/apt/lists/*; \
  php -m | grep -E '^pdo_mysql$'; \
  php -m | grep -E '^curl$'; \
  php -m | grep -E '^sodium$'

WORKDIR /srv/blackcat

COPY blackcat-testing/docker/minimal-prod/app/blackcat-hardening.ini /usr/local/etc/php/conf.d/99-blackcat-hardening.ini

COPY --from=builder /workspace/blackcat-testing/vendor/ /srv/blackcat/vendor/
COPY blackcat-testing/composer.json blackcat-testing/composer.lock /srv/blackcat/
COPY blackcat-testing/environments/minimal-site/ /srv/blackcat/site/
COPY --from=builder /workspace/blackcat-core/ /srv/blackcat-core/
COPY --from=builder /workspace/blackcat-config/ /srv/blackcat-config/

COPY blackcat-testing/docker/minimal-prod/app/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
