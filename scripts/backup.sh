#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/lib/soc-monitor/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
DB_NAME="${DB_NAME:-socmonitor}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUT_FILE="${BACKUP_DIR}/socmonitor_${TIMESTAMP}.sql.gz"

mkdir -p "${BACKUP_DIR}"
su - postgres -c "pg_dump ${DB_NAME}" | gzip > "${OUT_FILE}"
chmod 600 "${OUT_FILE}"

# Prune backups older than retention
find "${BACKUP_DIR}" -type f -name "socmonitor_*.sql.gz" -mtime +"${RETENTION_DAYS}" -delete
echo "Backup created: ${OUT_FILE}"
