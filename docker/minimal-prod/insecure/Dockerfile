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

WORKDIR /srv/insecure

COPY blackcat-testing/environments/insecure-site/ /srv/insecure/site/
COPY blackcat-testing/docker/minimal-prod/insecure/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]

