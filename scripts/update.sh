#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/soc-monitor"
CONF_DIR="/etc/soc-monitor"
SERVICE_USER="socmonitor"

echo "Updating soc-monitor in ${APP_DIR}..."
cd "${APP_DIR}"

if [ -d .git ]; then
  git config --global --add safe.directory "${APP_DIR}" || true
  git pull --ff-only
fi

"${APP_DIR}/.venv/bin/pip" install --upgrade -r requirements.txt

su -s /bin/bash "${SERVICE_USER}" -c "cd ${APP_DIR} && set -a && source ${CONF_DIR}/.env && set +a && ${APP_DIR}/.venv/bin/alembic upgrade head"

systemctl restart soc-monitor.service
systemctl status soc-monitor.service --no-pager
echo "Update completed successfully."
