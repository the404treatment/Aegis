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

# Find node. PATH first, then the usual install locations - a shell launched
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

# Which package manager does this machine actually have? Used both to offer an
# install and to name the right command if the user declines.
pkg_mgr=""
pkg_cmd=""
if   command -v apt-get >/dev/null 2>&1; then pkg_mgr="apt";    pkg_cmd="sudo apt-get update && sudo apt-get install -y nodejs npm"
elif command -v dnf     >/dev/null 2>&1; then pkg_mgr="dnf";    pkg_cmd="sudo dnf install -y nodejs"
elif command -v pacman  >/dev/null 2>&1; then pkg_mgr="pacman"; pkg_cmd="sudo pacman -S --noconfirm nodejs npm"
elif command -v zypper  >/dev/null 2>&1; then pkg_mgr="zypper"; pkg_cmd="sudo zypper install -y nodejs"
elif command -v apk     >/dev/null 2>&1; then pkg_mgr="apk";    pkg_cmd="sudo apk add nodejs npm"
elif command -v brew    >/dev/null 2>&1; then pkg_mgr="brew";   pkg_cmd="brew install node"
fi

# Offer to install through the system package manager, which is signed and
# trusted by this machine already. Deliberately NOT piping a vendor install
# script into a shell: that is the supply-chain pattern AEGIS exists to help
# you detect, and doing it here would be indefensible.
if [ -z "$NODE" ]; then
  echo "  Node.js is not installed, or not on PATH."
  echo
  if [ -n "$pkg_mgr" ]; then
    echo "  AEGIS needs Node 18 or newer. Nothing else - it has no dependencies."
    echo "  This machine has $pkg_mgr, so it can be installed with:"
    echo
    echo "    $pkg_cmd"
    echo
    # Only offer if there is a terminal to answer on; piped/CI runs just get
    # the instruction and a clean exit.
    if [ -t 0 ]; then
      printf '  Run that now? [y/N] '
      read -r reply || reply=""
      case "$reply" in
        [Yy]*)
          echo
          sh -c "$pkg_cmd" || { echo; echo "  That failed. Run it by hand, then start AEGIS again."; exit 1; }
          echo
          if command -v node >/dev/null 2>&1; then NODE="$(command -v node)"; else
            echo "  Installed, but node is still not on PATH. Open a new terminal and try again."
            exit 1
          fi
          ;;
        *) echo; echo "  Nothing installed. Run the command above, then start AEGIS again."; exit 1 ;;
      esac
    else
      exit 1
    fi
  else
    cat <<'EOF'
  Install Node 18 or newer, then run this again:

    Debian/Ubuntu   sudo apt-get install nodejs npm
    Fedora/RHEL     sudo dnf install nodejs
    Arch            sudo pacman -S nodejs npm
    Alpine          sudo apk add nodejs npm
    macOS           brew install node
    any             https://nodejs.org

  Nothing else is needed - AEGIS has no dependencies to download.
EOF
    exit 1
  fi
fi

MAJOR="$("$NODE" -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
if [ "$MAJOR" -lt 18 ]; then
  echo "  Node $("$NODE" -v) is too old - AEGIS needs 18 or newer."
  echo
  # Several LTS distributions still ship Node 12/16, so "install nodejs" can
  # succeed and still leave you below the floor. Say so plainly instead of
  # looping someone through the same package manager a second time.
  echo "  Your distribution's packaged Node is older than AEGIS supports."
  echo "  Get a current one with nvm (installs into your home directory, no root):"
  echo
  echo "    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash"
  echo "    exec \$SHELL -l && nvm install 22"
  echo
  echo "  or use your distribution's current-Node package if it has one."
  exit 1
fi

# A ZIP download does not preserve the executable bit, which makes
# `sudo ./aegis-agent.py` fail with a misleading "command not found". Restore
# it here so both invocations work.
chmod +x agents/aegis-agent.py 2>/dev/null || true

if [ ! -f server/config.json ]; then
  echo "  First run - setting up..."
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
