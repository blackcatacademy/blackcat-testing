#!/bin/sh
set -eu

cd /app

echo "[blackcat-testing] phpunit: offline"
vendor/bin/phpunit --colors=always --testsuite offline

echo "[blackcat-testing] phpunit: workspace"
vendor/bin/phpunit --colors=always --testsuite workspace

echo "[blackcat-testing] phpunit: live (may skip if BLACKCAT_TESTING_LIVE_CONFIG is not set)"
vendor/bin/phpunit --colors=always --testsuite live

echo "[blackcat-testing] phpstan"
vendor/bin/phpstan analyse --memory-limit=512M

echo "[blackcat-testing] OK"
