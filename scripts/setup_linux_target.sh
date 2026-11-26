#!/usr/bin/env bash
set -euo pipefail

# Run on target Linux servers to create a least-privilege read-only monitoring user.
MON_USER="socmon_ro"
PUB_KEY="${1:-}"

if [ -z "${PUB_KEY}" ]; then
  echo "Usage: $0 '<ssh-ed25519 AAAA... soc-monitor>'"
  exit 1
fi

id -u "${MON_USER}" >/dev/null 2>&1 || useradd --system --create-home --shell /bin/bash "${MON_USER}"
mkdir -p "/home/${MON_USER}/.ssh"
echo "${PUB_KEY}" > "/home/${MON_USER}/.ssh/authorized_keys"
chmod 700 "/home/${MON_USER}/.ssh"
chmod 600 "/home/${MON_USER}/.ssh/authorized_keys"
chown -R "${MON_USER}:${MON_USER}" "/home/${MON_USER}/.ssh"

cat > "/etc/sudoers.d/${MON_USER}" <<EOF
Defaults:${MON_USER} !requiretty
${MON_USER} ALL=(root) NOPASSWD: /usr/bin/ss -tulnpH, /usr/bin/firewall-cmd --list-all*, /usr/sbin/nft list ruleset, /usr/sbin/iptables -S, /usr/bin/journalctl *, /usr/bin/grep *, /usr/bin/cat /etc/sudoers*
EOF
chmod 440 "/etc/sudoers.d/${MON_USER}"
echo "Linux target user ${MON_USER} configured with read-only sudoers."
