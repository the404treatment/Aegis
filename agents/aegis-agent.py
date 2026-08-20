#!/usr/bin/env python3
"""
AEGIS Linux/macOS agent.

Read-only by design: reads journald/auth logs and reports host facts. It does
not accept commands from the server and has no exec path.

  sudo python3 aegis-agent.py --server https://aegis.internal:8787 --token <enrollment>
  sudo python3 aegis-agent.py --server ... --token ... --once   # for cron/systemd timer

Invoke it through python3 rather than ./aegis-agent.py unless you know the
executable bit survived: a ZIP download of the repository does not preserve
it, and ./aegis-agent.py then fails with "command not found", which reads as
though the file is missing rather than merely not executable.

State (agent id + key) lives in /etc/aegis/agent.json, chmod 600.
"""
import argparse, json, os, platform, re, socket, subprocess, sys, time, uuid
import urllib.request, urllib.error

VERSION = "1.0.0"
STATE_DIR = "/etc/aegis" if os.geteuid() == 0 else os.path.expanduser("~/.aegis")
STATE_FILE = os.path.join(STATE_DIR, "agent.json")

# journald units / patterns worth shipping. Add here rather than shipping all.
PATTERNS = [
    (r"Failed password for .* from ([\d.]+)", "auth_failure", "suspicious"),
    (r"Accepted (password|publickey) for (\S+) from ([\d.]+)", "auth_success", "info"),
    (r"session opened for user root", "root_session", "suspicious"),
    (r"sudo:.*COMMAND=(.*)", "sudo_command", "info"),
    (r"useradd|usermod|groupadd", "account_change", "suspicious"),
    (r"(nc|ncat|socat)\s+-l", "listener_started", "suspicious"),
    (r"chmod\s+[+]s|chmod\s+4\d{3}", "setuid_change", "suspicious"),
    (r"(wget|curl)\s+http", "remote_download", "suspicious"),
    (r"base64\s+-d|echo\s+[A-Za-z0-9+/]{40,}=*\s*\|\s*base64", "encoded_payload", "malicious"),
    (r"history\s+-c|unset\s+HISTFILE", "history_cleared", "malicious"),
    (r"systemctl (stop|disable) (auditd|falco|osquer)", "security_tool_stopped", "malicious"),
]


def log(msg):
    print(f"[aegis] {msg}", file=sys.stderr)


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return None


def save_state(s):
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(s, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE_FILE)


def host_facts():
    roles = []
    if os.path.exists("/etc/samba/smb.conf"):
        roles.append("fileserver")
    for svc, role in (("nginx", "web"), ("apache2", "web"), ("httpd", "web"),
                      ("docker", "container_host"), ("kubelet", "kubernetes")):
        if os.path.exists(f"/usr/sbin/{svc}") or os.path.exists(f"/usr/bin/{svc}"):
            roles.append(role)
    ip = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass
    return {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "ip": ip,
        "roles": roles,
        "version": VERSION,
    }



def logging_posture():
    """What this host is actually logging. Drives the gap report."""
    def has(path):
        return os.path.exists(path)
    auditd = False
    try:
        r = subprocess.run(["systemctl", "is-active", "auditd"], capture_output=True, text=True, timeout=5)
        auditd = r.stdout.strip() == "active"
    except Exception:
        pass
    return {
        "auditd": auditd,
        "journald": has("/var/log/journal") or has("/run/log/journal"),
        "authlog": has("/var/log/auth.log") or has("/var/log/secure"),
        "sysmonLinux": has("/opt/sysmon/sysmon") or has("/usr/bin/sysmon"),
    }


def peers():
    """Established connections to other hosts = real adjacency for the map."""
    out = []
    try:
        r = subprocess.run(["ss", "-tn", "state", "established"],
                           capture_output=True, text=True, timeout=15)
        for line in r.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            peer = parts[-1]
            if ":" not in peer:
                continue
            ip, _, port = peer.rpartition(":")
            ip = ip.strip("[]")
            if ip.startswith(("127.", "::1")):
                continue
            out.append({"ip": ip, "port": int(port) if port.isdigit() else 0, "proto": "tcp"})
    except Exception:
        pass
    # de-duplicate
    seen, uniq = set(), []
    for p in out:
        k = (p["ip"], p["port"])
        if k not in seen:
            seen.add(k)
            uniq.append(p)
    return uniq[:200]


def listening():
    out = []
    try:
        r = subprocess.run(["ss", "-tln"], capture_output=True, text=True, timeout=10)
        for line in r.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            _, _, port = parts[3].rpartition(":")
            if port.isdigit():
                out.append(int(port))
    except Exception:
        pass
    return sorted(set(out))[:100]


def call(server, path, body=None, headers=None, method="POST", timeout=30):
    url = server.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read() or b"{}")


def machine_id():
    """A random id generated once and kept alongside the enrollment state,
    independent of hostname. The server uses this to tell "this machine
    reinstalled the agent" apart from "a different machine claims the same
    hostname" - default and cloned hostnames collide across unrelated fleets
    constantly, and hostname alone used to be the only signal it had.
    Survives a normal reinstall (STATE_DIR is untouched); does not survive a
    full OS reimage, which is the point - that really is a different machine
    as far as this identity is concerned."""
    st = load_state()
    if st and st.get("machineId"):
        return st["machineId"]
    return str(uuid.uuid4())


def enroll(server, token):
    f = host_facts()
    f["enrollmentToken"] = token
    mid = machine_id()
    f["machineId"] = mid
    r = call(server, "/api/enroll", f)
    st = {"agentId": r["agentId"], "agentKey": r["agentKey"], "server": server, "cursor": "", "machineId": mid}
    save_state(st)
    log(f"enrolled as {r['agentId']}")
    return st


def collect(since_secs):
    """Pull recent log lines and classify them. journalctl first, syslog fallback."""
    lines = []
    try:
        out = subprocess.run(
            ["journalctl", "--since", f"-{since_secs}s", "--no-pager", "-o", "short-iso"],
            capture_output=True, text=True, timeout=45)
        lines = out.stdout.splitlines()
    except Exception:
        for p in ("/var/log/auth.log", "/var/log/secure"):
            if os.path.exists(p):
                try:
                    with open(p, errors="ignore") as fh:
                        lines = fh.readlines()[-2000:]
                    break
                except Exception:
                    pass

    events, now_ms = [], int(time.time() * 1000)
    for ln in lines[-4000:]:
        for pat, name, sev in PATTERNS:
            if re.search(pat, ln):
                events.append({
                    "ts": now_ms,
                    "channel": "syslog",
                    "eventId": name,
                    "severity": sev,
                    "message": ln.strip()[:1000],
                    "fields": {},
                })
                break
    return events[:500]


def cycle(server, token, interval):
    st = load_state()
    if not st or not st.get("agentKey"):
        if not token:
            raise SystemExit("no saved credentials and no --token given")
        st = enroll(server, token)
    hdr = {"X-Agent-Id": st["agentId"], "X-Agent-Key": st["agentKey"]}
    f = host_facts()
    try:
        call(server, "/api/heartbeat", {"ip": f["ip"], "roles": f["roles"]}, hdr)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            log("credentials rejected, re-enrolling")
            st = enroll(server, token)
            hdr = {"X-Agent-Id": st["agentId"], "X-Agent-Key": st["agentKey"]}
        else:
            raise
    try:
        call(server, "/api/discovery",
             {"peers": peers(), "listening": listening(), "logging": logging_posture()}, hdr)
    except Exception as e:
        log(f"discovery failed: {e}")

    evs = collect(interval + 30)
    if evs:
        for i in range(0, len(evs), 200):
            call(server, "/api/events", {"events": evs[i:i + 200]}, hdr)
        log(f"shipped {len(evs)} events")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True)
    ap.add_argument("--token", help="enrollment token (first run only)")
    ap.add_argument("--interval", type=int, default=300)
    ap.add_argument("--once", action="store_true")
    a = ap.parse_args()

    if a.once:
        cycle(a.server, a.token, a.interval)
        return
    log(f"running, interval {a.interval}s")
    while True:
        try:
            cycle(a.server, a.token, a.interval)
        except Exception as e:
            log(f"error: {e}")
        time.sleep(a.interval)


if __name__ == "__main__":
    main()
