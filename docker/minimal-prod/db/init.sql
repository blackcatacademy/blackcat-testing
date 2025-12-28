-- blackcat-testing minimal-prod DB init
-- Creates a dedicated read-only user to support stale-mode / least-privilege testing.

CREATE USER IF NOT EXISTS 'blackcat_ro'@'%' IDENTIFIED BY 'blackcat_ro';
GRANT SELECT, SHOW VIEW ON blackcat_test.* TO 'blackcat_ro'@'%';
FLUSH PRIVILEGES;

