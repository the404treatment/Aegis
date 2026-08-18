#!/usr/bin/env bash
# One-line Linux agent installer.
#   sudo ./install-agent.sh https://aegis.internal:8787 <enrollment-token>
set -euo pipefail
SERVER="${1:?usage: install-agent.sh <server-url> <enrollment-token>}"
TOKEN="${2:?usage: install-agent.sh <server-url> <enrollment-token>}"
SRC="$(dirname "$0")/../agents/aegis-agent.py"

install -m 0755 "$SRC" /usr/local/bin/aegis-agent.py
mkdir -p /etc/aegis && chmod 700 /etc/aegis

cat > /etc/systemd/system/aegis-agent.service <<EOF
[Unit]
Description=AEGIS Agent
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/aegis-agent.py --server ${SERVER} --token ${TOKEN} --once
User=root
NoNewPrivileges=true
ProtectHome=true
EOF

cat > /etc/systemd/system/aegis-agent.timer <<'EOF'
[Unit]
Description=Run AEGIS agent every 5 minutes
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s
[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now aegis-agent.timer
/usr/local/bin/aegis-agent.py --server "$SERVER" --token "$TOKEN" --once
echo "AEGIS agent installed on $(hostname)"
