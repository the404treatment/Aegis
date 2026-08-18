#!/usr/bin/env bash
# AEGIS launcher for Linux and macOS.
#
#   ./start.sh
#
# Runs setup on first launch (config + build), then starts the server and
# opens the console. Safe to run repeatedly: setup keeps existing tokens and
# data, so after the first time this is simply "start AEGIS".
set -euo pipefail
cd "$(dirname "$0")"

echo
echo "  AEGIS"
echo "  ====="
echo

# Find node. PATH first, then the usual install locations — a shell launched
# from a desktop icon often has a thinner PATH than an interactive one, and
# nvm/homebrew installs regularly aren't on it at all.
NODE=""
if command -v node >/dev/null 2>&1; then
  NODE="$(command -v node)"
else
  for candidate in \
    /usr/local/bin/node \
    /opt/homebrew/bin/node \
    /usr/bin/node \
    /snap/bin/node \
    "$HOME/.nvm/versions/node"/*/bin/node \
    "$HOME/.local/bin/node"
  do
    [ -x "$candidate" ] && NODE="$candidate" && break
  done
fi

if [ -z "$NODE" ]; then
  cat <<'EOF'
  Node.js is not installed, or not on PATH.

  Install Node 18 or newer, then run this again:

    Debian/Ubuntu   sudo apt install nodejs
    Fedora/RHEL     sudo dnf install nodejs
    macOS           brew install node
    any             https://nodejs.org

  Nothing else is needed — AEGIS has no dependencies to download.
EOF
  exit 1
fi

MAJOR="$("$NODE" -p 'process.versions.node.split(".")[0]')"
if [ "$MAJOR" -lt 18 ]; then
  echo "  Node $("$NODE" -v) is too old — AEGIS needs 18 or newer."
  exit 1
fi

if [ ! -f server/config.json ]; then
  echo "  First run — setting up..."
  echo
  "$NODE" setup.mjs
  echo
  printf '  Press Enter to start the server... '
  read -r _
else
  # Rebuild so the console always matches the current source.
  "$NODE" build.mjs >/dev/null
fi

# Open the console once the server has had a moment to bind. Best-effort:
# on a headless box there is simply no browser to open, which is fine.
( sleep 2
  if command -v xdg-open >/dev/null 2>&1; then xdg-open http://127.0.0.1:8787 >/dev/null 2>&1 || true
  elif command -v open >/dev/null 2>&1; then open http://127.0.0.1:8787 >/dev/null 2>&1 || true
  fi
) &

echo
echo "  Starting AEGIS. Press Ctrl-C to stop."
echo
exec "$NODE" server/aegis-server.mjs --config ./server/config.json
