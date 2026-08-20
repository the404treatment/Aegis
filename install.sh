#!/usr/bin/env sh
# AEGIS one-line installer (Linux / macOS).
#
#   curl -fsSL https://raw.githubusercontent.com/the404treatment/Aegis/main/install.sh | sh
#
# Installs into ~/.aegis, generates tokens, builds the console, registers a
# service that survives a reboot, and waits until the server actually answers
# before telling you it worked.
#
# Deliberate:
#   - POSIX sh, not bash. Alpine and slim containers ship dash.
#   - No sudo, anywhere. It installs to your home directory and registers a
#     *user* service. An installer that asks for root to run a log collector
#     has already made your security posture worse.
#   - Node is installed through the system package manager, with consent, or
#     not at all. Piping another vendor's install script into a shell is how
#     supply-chain incidents start, so that is never done; the distro's own
#     signed repositories are used instead, and a non-interactive run just
#     prints the command and stops.
#   - Idempotent. Re-running upgrades in place and keeps your tokens, so
#     enrolled agents keep working.
set -eu

REPO="${AEGIS_REPO:-https://github.com/the404treatment/Aegis}"
BRANCH="${AEGIS_BRANCH:-main}"
DIR="${AEGIS_DIR:-$HOME/.aegis}"
PORT="${AEGIS_PORT:-8787}"

if [ -t 1 ]; then B=$(printf '\033[1m'); D=$(printf '\033[2m'); G=$(printf '\033[32m'); Y=$(printf '\033[33m'); R=$(printf '\033[31m'); Z=$(printf '\033[0m')
else B=''; D=''; G=''; Y=''; R=''; Z=''; fi
say()  { printf '%s\n' "$*"; }
step() { printf '  %s%s%s\n' "$B" "$*" "$Z"; }
warn() { printf '  %s%s%s\n' "$Y" "$*" "$Z"; }
die()  { printf '\n  %sERROR%s %s\n\n' "$R" "$Z" "$*" >&2; exit 1; }

say ""
say "  ${B}AEGIS${Z}  SOC detection console + incident platform"
say "  ${D}------------------------------------------------------------${Z}"

# --- Node -------------------------------------------------------------------
PKG_CMD=""
if   command -v apt-get >/dev/null 2>&1; then PKG_CMD="sudo apt-get update && sudo apt-get install -y nodejs npm"
elif command -v dnf     >/dev/null 2>&1; then PKG_CMD="sudo dnf install -y nodejs"
elif command -v pacman  >/dev/null 2>&1; then PKG_CMD="sudo pacman -S --noconfirm nodejs npm"
elif command -v zypper  >/dev/null 2>&1; then PKG_CMD="sudo zypper install -y nodejs"
elif command -v apk     >/dev/null 2>&1; then PKG_CMD="sudo apk add nodejs npm"
elif command -v brew    >/dev/null 2>&1; then PKG_CMD="brew install node"
fi

if ! command -v node >/dev/null 2>&1; then
  [ -n "$PKG_CMD" ] || die "Node.js 18+ is required but not installed, and no supported
  package manager was found. Install Node from https://nodejs.org and run this again.
  AEGIS itself has no dependencies - Node is the only thing it needs."

  warn "Node.js is not installed."
  say  "  ${D}It can be installed from your distribution's own repositories with:${Z}"
  say  ""
  say  "      $PKG_CMD"
  say  ""
  # `curl … | sh` leaves stdin as the pipe, so there is nothing to read an
  # answer from. Read from the terminal directly when there is one, and
  # otherwise print the command and stop rather than installing unasked.
  if [ -r /dev/tty ]; then
    printf '  Run that now? [y/N] '
    read -r reply </dev/tty || reply=""
    case "$reply" in
      [Yy]*) say ""; sh -c "$PKG_CMD" || die "that failed - run it by hand, then re-run this installer." ;;
      *) die "nothing installed. Run the command above, then re-run this installer." ;;
    esac
  else
    die "no terminal to confirm on. Run the command above, then re-run this installer."
  fi
  command -v node >/dev/null 2>&1 || die "Node still is not on PATH. Open a new shell and re-run this."
fi

NODE_MAJOR=$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)
[ "$NODE_MAJOR" -ge 18 ] 2>/dev/null || die "Node.js 18 or newer is required (found $(node -v)).
  Several long-term-support distributions still package Node 12 or 16, so installing
  'nodejs' can succeed and still land below what AEGIS needs. Install a current one
  into your home directory with nvm (no root required):
      curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
      exec \$SHELL -l && nvm install 22
  then re-run this installer."
step "node            $(node -v)"

# --- fetch ------------------------------------------------------------------
UPGRADE=no
if [ -d "$DIR/.git" ]; then
  UPGRADE=yes
  step "upgrading       $DIR"
  git -C "$DIR" fetch --quiet --depth 1 origin "$BRANCH" \
    && git -C "$DIR" reset --quiet --hard "origin/$BRANCH" \
    || die "could not update $DIR - move it aside and re-run."
elif command -v git >/dev/null 2>&1; then
  step "cloning         $REPO"
  git clone --quiet --depth 1 --branch "$BRANCH" "$REPO" "$DIR" \
    || die "could not clone $REPO"
else
  # No git: fall back to the tarball so a bare container still works.
  step "downloading     $REPO ($BRANCH)"
  command -v tar >/dev/null 2>&1 || die "need either git or tar to install"
  mkdir -p "$DIR"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$REPO/archive/refs/heads/$BRANCH.tar.gz" | tar xz -C "$DIR" --strip-components=1
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "$REPO/archive/refs/heads/$BRANCH.tar.gz" | tar xz -C "$DIR" --strip-components=1
  else
    die "need curl or wget to download AEGIS"
  fi
fi

# --- configure + build ------------------------------------------------------
# setup.mjs is idempotent: it keeps existing tokens unless --rotate is passed,
# so an upgrade never orphans the agents already reporting in.
step "configuring     tokens + build"
( cd "$DIR" && node setup.mjs --port "$PORT" >/dev/null ) || die "setup failed - run 'node setup.mjs' in $DIR to see why"
# The tarball fallback above does not carry file modes, so the Python agent can
# arrive without its executable bit and fail as "command not found".
chmod +x "$DIR/agents/aegis-agent.py" 2>/dev/null || true

# --- service ----------------------------------------------------------------
SERVICE=none
if [ "$(uname -s)" = "Darwin" ]; then
  PLIST="$HOME/Library/LaunchAgents/com.aegis.server.plist"
  mkdir -p "$HOME/Library/LaunchAgents"
  cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.aegis.server</string>
  <key>ProgramArguments</key><array>
    <string>$(command -v node)</string>
    <string>$DIR/server/aegis-server.mjs</string>
    <string>--config</string><string>$DIR/server/config.json</string>
  </array>
  <key>WorkingDirectory</key><string>$DIR</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$DIR/aegis.log</string>
  <key>StandardErrorPath</key><string>$DIR/aegis.log</string>
</dict></plist>
PLISTEOF
  launchctl unload "$PLIST" 2>/dev/null || true
  launchctl load "$PLIST" 2>/dev/null && SERVICE=launchd
elif command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
  mkdir -p "$HOME/.config/systemd/user"
  cat > "$HOME/.config/systemd/user/aegis.service" <<UNITEOF
[Unit]
Description=AEGIS SOC console
After=network.target

[Service]
Type=simple
WorkingDirectory=$DIR
ExecStart=$(command -v node) $DIR/server/aegis-server.mjs --config $DIR/server/config.json
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
UNITEOF
  systemctl --user daemon-reload
  systemctl --user enable --now aegis.service >/dev/null 2>&1 && SERVICE=systemd
  # Without lingering, a user service stops the moment you log out - which for
  # a machine collecting telemetry is exactly the wrong behaviour. Ask nicely;
  # this is the one thing that wants root, and it is optional.
  if [ "$SERVICE" = systemd ] && command -v loginctl >/dev/null 2>&1; then
    loginctl enable-linger "$(id -un)" >/dev/null 2>&1 \
      || warn "could not enable lingering - AEGIS will stop when you log out."
    warn "  fix with: sudo loginctl enable-linger $(id -un)"
  fi
fi

if [ "$SERVICE" = none ]; then
  warn "no user service manager found - starting in the background instead."
  warn "it will not survive a reboot; start it again with: cd $DIR && ./start.sh"
  ( cd "$DIR" && nohup node server/aegis-server.mjs --config server/config.json >aegis.log 2>&1 & )
else
  step "service         $SERVICE (starts on boot)"
fi

# --- wait for it to actually answer ----------------------------------------
step "waiting         for the server to come up"
i=0
while [ $i -lt 60 ]; do
  if command -v curl >/dev/null 2>&1; then
    curl -fsS "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1 && break
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1 && break
  else
    node -e "fetch('http://127.0.0.1:$PORT/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" 2>/dev/null && break
  fi
  i=$((i+1)); sleep 1
done
[ $i -lt 60 ] || die "the server did not come up within 60s. Check $DIR/aegis.log"

# --- done -------------------------------------------------------------------
ENROLL=$(node -p "JSON.parse(require('fs').readFileSync('$DIR/server/config.json','utf8')).enrollmentToken" 2>/dev/null || echo '(see server/config.json)')
LAN=$(node -e "const os=require('os');for(const[n,a]of Object.entries(os.networkInterfaces())){if(/vmware|virtualbox|hyper-v|docker|veth|tailscale|zerotier|wg/i.test(n))continue;for(const x of a||[])if(x.family==='IPv4'&&!x.internal){console.log(x.address);process.exit(0)}}console.log('127.0.0.1')" 2>/dev/null || echo 127.0.0.1)

say ""
say "  ${G}AEGIS is running.${Z}"
say ""
say "  Open the console    ${B}http://127.0.0.1:$PORT${Z}"
say "  Agents report to    ${B}http://$LAN:$PORT${Z}"
say ""
say "  ${D}The console will ask you to create the first account. It becomes the${Z}"
say "  ${D}lead, and can add everyone else from there.${Z}"
say ""
say "  Add an endpoint:"
say "    ${D}Linux/macOS${Z}   sudo python3 $DIR/agents/aegis-agent.py --server http://$LAN:$PORT --token $ENROLL --once"
say "    ${D}Windows${Z}       see INSTALL.md"
say ""
if [ "$SERVICE" = systemd ]; then
  say "  ${D}logs${Z}    journalctl --user -u aegis -f"
  say "  ${D}stop${Z}    systemctl --user stop aegis"
elif [ "$SERVICE" = launchd ]; then
  say "  ${D}logs${Z}    tail -f $DIR/aegis.log"
  say "  ${D}stop${Z}    launchctl unload ~/Library/LaunchAgents/com.aegis.server.plist"
fi
say ""
[ "$UPGRADE" = yes ] && say "  ${D}Upgraded in place - your tokens and data were kept.${Z}" && say ""
exit 0
