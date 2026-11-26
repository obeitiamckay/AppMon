#!/usr/bin/env bash
set -euo pipefail

# Idempotent installer for soc-monitor on Rocky Linux 10
APP_DIR="/opt/soc-monitor"
CONF_DIR="/etc/soc-monitor"
DATA_DIR="/var/lib/soc-monitor"
LOG_DIR="/var/log/soc-monitor"
SERVICE_USER="socmonitor"
PORT="${PORT:-8443}"

echo "[1/8] Installing system dependencies via dnf..."
dnf -y install \
  python3.12 python3.12-pip python3.12-devel \
  postgresql-server postgresql-contrib \
  pango cairo gdk-pixbuf2 libffi-devel gcc openssl \
  policycoreutils-python-utils firewalld logrotate git rsync

echo "[2/8] Creating service user and directories..."
id -u "${SERVICE_USER}" >/dev/null 2>&1 || useradd --system --home-dir "${APP_DIR}" --shell /sbin/nologin "${SERVICE_USER}"
mkdir -p "${APP_DIR}" "${CONF_DIR}/certs" "${DATA_DIR}/reports" "${DATA_DIR}/backups" "${LOG_DIR}"

echo "[3/8] Initializing PostgreSQL 16..."
if [ ! -f /var/lib/pgsql/data/PG_VERSION ]; then
  postgresql-setup --initdb
fi

systemctl enable --now postgresql

git config --global --add safe.directory "${APP_DIR}" || true

PG_HBA=$(su - postgres -c "psql -tAc 'SHOW hba_file'" | tr -d '[:space:]')
if [ -f "${PG_HBA}" ]; then
  sed -i -E '/^host[[:space:]]/ s/[[:space:]]+ident([[:space:]]*#.*)?$/ scram-sha-256\1/' "${PG_HBA}"
  sed -i -E '/^host[[:space:]]/ s/[[:space:]]+peer([[:space:]]*#.*)?$/ scram-sha-256\1/' "${PG_HBA}"
fi
su - postgres -c "psql -c \"ALTER SYSTEM SET password_encryption = 'scram-sha-256';\" -c \"SELECT pg_reload_conf();\""
systemctl restart postgresql

DB_PASS="${DB_PASS:-$(openssl rand -hex 16)}"
if [ -f "${CONF_DIR}/.env" ]; then
  EXISTING_PASS=$(grep -E '^DATABASE_URL=' "${CONF_DIR}/.env" | sed -E 's|.*://[^:]+:([^@]+)@.*|\1|' || true)
  if [ -n "${EXISTING_PASS}" ]; then
    DB_PASS="${EXISTING_PASS}"
  fi
fi
su - postgres -c "psql -tc \"SELECT 1 FROM pg_roles WHERE rolname='socmonitor'\" | grep -q 1 && psql -c \"ALTER USER socmonitor WITH PASSWORD '${DB_PASS}';\" || psql -c \"CREATE USER socmonitor WITH PASSWORD '${DB_PASS}';\""
su - postgres -c "psql -tc \"SELECT 1 FROM pg_database WHERE datname='socmonitor'\" | grep -q 1 || psql -c \"CREATE DATABASE socmonitor OWNER socmonitor;\""

echo "[4/8] Copying application and setting up Python 3.12 venv..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "${SCRIPT_DIR}" != "${APP_DIR}" ]; then
  rsync -a --exclude '.venv' --exclude '.git' "${SCRIPT_DIR}/" "${APP_DIR}/"
fi
python3.12 -m venv "${APP_DIR}/.venv"
"${APP_DIR}/.venv/bin/pip" install --upgrade pip
"${APP_DIR}/.venv/bin/pip" install -r "${APP_DIR}/requirements.txt"

echo "[5/8] Generating TLS certificate and .env if missing..."
if [ ! -f "${CONF_DIR}/certs/server.crt" ]; then
  openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
    -keyout "${CONF_DIR}/certs/server.key" \
    -out "${CONF_DIR}/certs/server.crt" \
    -subj "/CN=$(hostname -f)"
fi

if [ ! -f "${CONF_DIR}/.env" ]; then
  FERNET_KEY=$("${APP_DIR}/.venv/bin/python" -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
  JWT_SECRET=$(openssl rand -hex 32)
  cat > "${CONF_DIR}/.env" <<EOF
APP_ENV=production
HOST=0.0.0.0
PORT=${PORT}
SSL_CERTFILE=${CONF_DIR}/certs/server.crt
SSL_KEYFILE=${CONF_DIR}/certs/server.key
DATABASE_URL=postgresql+psycopg://socmonitor:${DB_PASS}@localhost:5432/socmonitor
FERNET_KEY=${FERNET_KEY}
JWT_SECRET=${JWT_SECRET}
REPORTS_DIR=${DATA_DIR}/reports
LOGS_DIR=${LOG_DIR}
INITIAL_ADMIN_USER=socadmin
INITIAL_ADMIN_PASSWORD=ChangeMe!SocAdmin2026
EOF
  chmod 600 "${CONF_DIR}/.env"
fi

chown -R "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}" "${CONF_DIR}" "${DATA_DIR}" "${LOG_DIR}"

echo "[6/8] Running Alembic database migrations..."
su -s /bin/bash "${SERVICE_USER}" -c "cd ${APP_DIR} && set -a && source ${CONF_DIR}/.env && set +a && ${APP_DIR}/.venv/bin/alembic upgrade head"

echo "[7/8] Configuring SELinux, firewalld, and logrotate..."
semanage port -a -t http_port_t -p tcp "${PORT}" 2>/dev/null || semanage port -m -t http_port_t -p tcp "${PORT}" || true
restorecon -Rv "${APP_DIR}" "${CONF_DIR}" "${DATA_DIR}" "${LOG_DIR}" || true

systemctl enable --now firewalld
firewall-cmd --permanent --add-port="${PORT}/tcp"
firewall-cmd --reload

cat > /etc/logrotate.d/soc-monitor <<EOF
${LOG_DIR}/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF

echo "[8/8] Installing and starting systemd service..."
cp "${APP_DIR}/systemd/soc-monitor.service" /etc/systemd/system/
cp "${APP_DIR}/systemd/soc-monitor.timer" /etc/systemd/system/
cp "${APP_DIR}/systemd/soc-monitor-scan.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now soc-monitor.service

echo "Installation complete! Access web console at https://$(hostname -I | awk '{print $1}'):${PORT}"
