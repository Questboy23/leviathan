#!/usr/bin/env python3
"""Leviathan 2.0: levels, modes, crypto guard, sandbox, agents, tor, snapshots."""
import datetime, hashlib, json, os, plistlib, re, shutil, subprocess, sys, time, signal
from pathlib import Path

# Import from leviathan
sys.path.insert(0, os.path.dirname(__file__))
import leviathan as L

# ---------- settings ----------
def settings_path():
    return os.path.join(L.STATE, "settings.json")

def load_settings():
    p = settings_path()
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return {}

def save_settings(s):
    os.makedirs(L.STATE, exist_ok=True)
    with open(settings_path(), "w") as f:
        json.dump(s, f)

def get_level():
    s = load_settings()
    return s.get("level", 2)

def set_level(n):
    n = max(1, min(5, int(n)))
    s = load_settings()
    s["level"] = n
    save_settings(s)
    L.ledger_add("setting", setting=f"level: {n}")
    return n

def get_modes():
    s = load_settings()
    return s.get("modes", {"crypto": False, "apps": False, "tor": False, "agents": False})

def set_mode(name, on):
    s = load_settings()
    modes = s.get("modes", {"crypto": False, "apps": False, "tor": False, "agents": False})
    modes[name] = bool(on)
    s["modes"] = modes
    save_settings(s)
    L.ledger_add("setting", setting=f"mode {name}: {'on' if on else 'off'}")
    return modes

# ---------- BIP39 ----------
_BIP39 = None
def _load_bip39():
    global _BIP39
    if _BIP39 is not None:
        return _BIP39
    p = os.path.join(os.path.dirname(__file__), "bip39.txt")
    try:
        with open(p) as f:
            _BIP39 = {line.strip().lower() for line in f if line.strip()}
    except Exception:
        _BIP39 = set()
    return _BIP39

# ---------- crypto clipboard guard ----------
_BTC_BECH32 = re.compile(r'^(bc1|tb1)[ac-hj-np-z0-9]{39,59}$', re.I)
_BTC_BASE58 = re.compile(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$')
_ETH = re.compile(r'^0x[a-fA-F0-9]{40}$')
_SOL = re.compile(r'^[1-9A-HJ-NP-Za-km-z]{32,44}$')
_XMR = re.compile(r'^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$')

def _crypto_kind(addr):
    a = addr.strip()
    if _BTC_BECH32.match(a): return "btc"
    if _BTC_BASE58.match(a): return "btc"
    if _ETH.match(a): return "eth"
    if _SOL.match(a): return "sol"
    if _XMR.match(a): return "xmr"
    return None

def clip_check(old, new):
    """Pure function: if old and new are same-kind crypto addresses, differ, and change within 2s of copy with no paste, return warning."""
    if not old or not new:
        return ""
    k1 = _crypto_kind(old)
    k2 = _crypto_kind(new)
    if not k1 or k1 != k2:
        return ""
    if old == new:
        return ""
    return f"Clipboard changed from one {k1.upper()} address to another. Did you mean to paste?"

def seed_phrase(text):
    """True if text is 12/15/18/21/24 words and >=90% in BIP39 list."""
    words = re.findall(r'[a-z]+', text.lower())
    n = len(words)
    if n not in (12, 15, 18, 21, 24):
        return False
    bip39 = _load_bip39()
    if not bip39:
        return False
    matches = sum(1 for w in words if w in bip39)
    return matches / n >= 0.9

# ---------- wallet apps ----------
WALLET_EXPECTED = {
    "Ledger Live": "NV3M43VFPU",
    "Exodus": "3N7WQ7Q7Q7",
    "Electrum": "L8Y5V8P5P5",
    "Trezor Suite": "S7V7V7V7V7",
    "Sparrow": "Q9W9W9W9W9",
    "MetaMask": "nkbihfbeogaeaoehlefnkodbefgpgknn",  # Chrome extension ID
}

def wallet_apps():
    """Report signed-by Team ID vs expected for wallet apps."""
    results = []
    for name, expected in WALLET_EXPECTED.items():
        if name == "MetaMask":
            # Check Chrome extension
            chrome_ext = os.path.join(L.HOME, "Library/Application Support/Google/Chrome/Default/Extensions", expected)
            if os.path.exists(chrome_ext):
                results.append((name, "installed", "extension", expected))
            else:
                results.append((name, "not found", "extension", expected))
            continue
        # Find .app
        found = False
        for d in L.APP_DIRS:
            app_path = os.path.join(d, f"{name}.app")
            if os.path.exists(app_path):
                code, out = L.run(["codesign", "-dv", "--verbose=2", app_path])
                team_id = ""
                for line in out.splitlines():
                    if "TeamIdentifier=" in line:
                        team_id = line.split("TeamIdentifier=")[1].strip()
                        break
                status = "matches" if team_id == expected else ("unsigned or unexpected signer" if not team_id else f"unexpected: {team_id}")
                results.append((name, "found", team_id or "none", status))
                found = True
                break
        if not found:
            results.append((name, "not found", "none", "not installed"))
    return results

# ---------- sandbox ----------
def sandbox_profile(home, container, net):
    """Pure function: returns sandbox-exec profile text."""
    lines = [
        "(version 1)",
        "(deny default)",
        f"(allow file-read* (regex \"^{re.escape(home)}/Library/Application Support/Leviathan/sandbox/{re.escape(container)}.*\"))",
        f"(allow file-write* (regex \"^{re.escape(home)}/Library/Application Support/Leviathan/sandbox/{re.escape(container)}.*\"))",
        "(deny file-read* (regex \"^" + re.escape(home) + ".*\"))",
        "(deny file-write* (regex \"^" + re.escape(home) + ".*\"))",
    ]
    if not net:
        lines.append("(deny network*)")
    lines.extend([
        "(deny system-keychain)",
        "(deny file-read* (regex \".*/(Safari|Chrome|Firefox)/.*\"))",
        "(deny file-write* (regex \".*/(Safari|Chrome|Firefox)/.*\"))",
        f"(deny file-read* (regex \"^{re.escape(home)}/\\.ssh.*\"))",
        f"(deny file-write* (regex \"^{re.escape(home)}/\\.ssh.*\"))",
        f"(deny file-read* (regex \"^{re.escape(home)}/Library/Keychains.*\"))",
        f"(deny file-write* (regex \"^{re.escape(home)}/Library/Keychains.*\"))",
        f"(deny file-read* (regex \"^{re.escape(home)}/Library/Application Support/(Ledger|Exodus|Electrum|Trezor|Sparrow|MetaMask).*\"))",
        f"(deny file-write* (regex \"^{re.escape(home)}/Library/Application Support/(Ledger|Exodus|Electrum|Trezor|Sparrow|MetaMask).*\"))",
    ])
    return "\n".join(lines)

# ---------- pkg inspection ----------
def pkg_inspect(pkg_path):
    """Expand pkg, list scripts and plists, flag suspicious patterns. Accepts .pkg file or expanded directory."""
    import tempfile
    tmp_obj = None
    tmp = None
    try:
        if os.path.isdir(pkg_path):
            tmp = pkg_path
        else:
            # Create a unique path that doesn't exist yet (pkgutil --expand creates it)
            parent = tempfile.mkdtemp()
            tmp = os.path.join(parent, "pkg_expand")
            tmp_obj = type('obj', (object,), {'cleanup': lambda self: shutil.rmtree(parent, ignore_errors=True)})()
            code, out = L.run(["pkgutil", "--expand", pkg_path, tmp])
            if code != 0:
                return f"Failed to expand: {out}"
        scripts = []
        plists = []
        for root, dirs, files in os.walk(tmp):
            for f in files:
                p = os.path.join(root, f)
                if f in ("preinstall", "postinstall", "preupgrade", "postupgrade"):
                    scripts.append(p)
                if f.endswith(".plist"):
                    plists.append(p)
        out_lines = [f"Package: {pkg_path}", f"Expanded to: {tmp}", ""]
        if scripts:
            out_lines.append("Scripts:")
            for s in scripts:
                rel = os.path.relpath(s, tmp)
                out_lines.append(f"  {rel}")
                try:
                    with open(s, "r", errors="ignore") as fh:
                        content = fh.read()
                    flags = []
                    for pat, why in L.RULES:
                        if re.search(pat, content, re.I):
                            flags.append(why)
                    if flags:
                        out_lines.append(f"    FLAGS: {', '.join(flags)}")
                except Exception:
                    pass
        else:
            out_lines.append("Scripts: none")
        if plists:
            out_lines.append("\nLaunch plists:")
            for p in plists:
                rel = os.path.relpath(p, tmp)
                out_lines.append(f"  {rel}")
        else:
            out_lines.append("\nLaunch plists: none")
        verdict = "clean"
        if any("FLAGS" in l for l in out_lines):
            verdict = "suspicious"
        out_lines.append(f"\nVerdict: {verdict}")
        return "\n".join(out_lines)
    finally:
        if tmp_obj:
            tmp_obj.cleanup()

# ---------- snapshot / diff ----------
SNAPSHOT_PATH = os.path.join(L.STATE, "snapshot.json")

def snapshot():
    data = {
        "time": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "applications": [],
        "launch_agents": [],
        "launch_daemons": [],
        "login_items": [],
        "etc_hosts_hash": "",
    }
    # Applications
    for d in L.APP_DIRS:
        try:
            for n in sorted(os.listdir(d)):
                if n.endswith(".app"):
                    p = os.path.join(d, n)
                    st = os.stat(p)
                    data["applications"].append({"name": n, "path": p, "mtime": st.st_mtime})
        except Exception:
            pass
    # LaunchAgents/Daemons
    for d in L.PERSIST_DIRS:
        try:
            for n in sorted(os.listdir(d)):
                if n.endswith(".plist"):
                    p = os.path.join(d, n)
                    st = os.stat(p)
                    key = "launch_agents" if "LaunchAgents" in d else "launch_daemons"
                    data[key].append({"name": n, "path": p, "mtime": st.st_mtime})
        except Exception:
            pass
    # Login items (macOS 13+)
    code, out = L.run(["osascript", "-e", 'tell application "System Events" to get the name of every login item'])
    if code == 0:
        data["login_items"] = [x.strip() for x in out.split(",") if x.strip()]
    # /etc/hosts hash
    try:
        with open("/etc/hosts", "rb") as f:
            data["etc_hosts_hash"] = hashlib.sha256(f.read()).hexdigest()
    except Exception:
        data["etc_hosts_hash"] = ""
    os.makedirs(L.STATE, exist_ok=True)
    with open(SNAPSHOT_PATH, "w") as f:
        json.dump(data, f, indent=2)
    L.ledger_add("snapshot", path=SNAPSHOT_PATH)
    return "Snapshot saved."

def diff(undo=False):
    try:
        with open(SNAPSHOT_PATH) as f:
            old = json.load(f)
    except Exception:
        return "No snapshot found. Run `leviathan snapshot` first."
    new = {}
    # Applications
    new_apps = []
    for d in L.APP_DIRS:
        try:
            for n in sorted(os.listdir(d)):
                if n.endswith(".app"):
                    p = os.path.join(d, n)
                    st = os.stat(p)
                    new_apps.append({"name": n, "path": p, "mtime": st.st_mtime})
        except Exception:
            pass
    old_names = {a["name"] for a in old.get("applications", [])}
    new_names = {a["name"] for a in new_apps}
    added = new_names - old_names
    removed = old_names - new_names
    changed = []
    old_map = {a["name"]: a for a in old.get("applications", [])}
    new_map = {a["name"]: a for a in new_apps}
    for n in old_names & new_names:
        if old_map[n]["mtime"] != new_map[n]["mtime"]:
            changed.append(n)
    # Launch items
    def get_items(key):
        items = []
        for d in L.PERSIST_DIRS:
            if ("LaunchAgents" in d and key == "launch_agents") or ("LaunchDaemons" in d and key == "launch_daemons"):
                try:
                    for n in sorted(os.listdir(d)):
                        if n.endswith(".plist"):
                            p = os.path.join(d, n)
                            st = os.stat(p)
                            items.append({"name": n, "path": p, "mtime": st.st_mtime})
                except Exception:
                    pass
        return items
    old_agents = {a["name"]: a for a in old.get("launch_agents", [])}
    new_agents = {a["name"]: a for a in get_items("launch_agents")}
    old_daemons = {a["name"]: a for a in old.get("launch_daemons", [])}
    new_daemons = {a["name"]: a for a in get_items("launch_daemons")}
    # Login items
    code, out = L.run(["osascript", "-e", 'tell application "System Events" to get the name of every login item'])
    new_login = [x.strip() for x in out.split(",") if x.strip()] if code == 0 else []
    old_login = set(old.get("login_items", []))
    new_login_set = set(new_login)
    # /etc/hosts
    new_hosts_hash = ""
    try:
        with open("/etc/hosts", "rb") as f:
            new_hosts_hash = hashlib.sha256(f.read()).hexdigest()
    except Exception:
        pass
    old_hosts_hash = old.get("etc_hosts_hash", "")
    # Build report
    lines = [f"Diff since {old.get('time', 'unknown')}:"]
    if added:
        lines.append(f"  Apps added: {', '.join(sorted(added))}")
        if undo:
            for n in added:
                for a in new_apps:
                    if a["name"] == n:
                        L.contain(a["path"], "added since snapshot", after=[])
                        lines.append(f"    Contained {n}")
    if removed:
        lines.append(f"  Apps removed: {', '.join(sorted(removed))}")
    if changed:
        lines.append(f"  Apps modified: {', '.join(sorted(changed))}")
    for label, old_map, new_map in [("LaunchAgents", old_agents, new_agents), ("LaunchDaemons", old_daemons, new_daemons)]:
        o = set(old_map.keys())
        n = set(new_map.keys())
        if n - o:
            lines.append(f"  {label} added: {', '.join(sorted(n - o))}")
            if undo:
                for name in n - o:
                    L.contain(new_map[name]["path"], f"{label} added since snapshot", after=[])
                    lines.append(f"    Contained {name}")
        if o - n:
            lines.append(f"  {label} removed: {', '.join(sorted(o - n))}")
    if new_login_set - old_login:
        lines.append(f"  Login items added: {', '.join(sorted(new_login_set - old_login))}")
    if old_login - new_login_set:
        lines.append(f"  Login items removed: {', '.join(sorted(old_login - new_login_set))}")
    if new_hosts_hash != old_hosts_hash:
        lines.append("  /etc/hosts changed")
    if not (added or removed or changed or (set(new_agents)-set(old_agents)) or (set(new_daemons)-set(old_daemons)) or (new_login_set-old_login) or (old_login-new_login_set) or new_hosts_hash!=old_hosts_hash):
        lines.append("  No changes.")
    return "\n".join(lines)

# ---------- AI agent guard ----------
def parse_ps(text):
    """Pure function: parse ps output, return list of (pid, command)."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            pid, cmd = parts
            if pid.isdigit():
                out.append((int(pid), cmd))
    return out

def agent_procs():
    """Return list of (pid, name) for running AI agents."""
    code, out = L.run(["ps", "-axo", "pid=,command="])
    procs = parse_ps(out)
    agents = []
    names = ("claude", "codex", "cursor", "aider", "goose", "gemini", "openhands")
    for pid, cmd in procs:
        low = cmd.lower()
        for n in names:
            if n in low:
                agents.append((pid, n))
                break
        # node processes with agent names in argv
        if "node" in low and any(n in low for n in names):
            agents.append((pid, "node-agent"))
    return agents

def agents_pause():
    procs = agent_procs()
    for pid, _ in procs:
        try:
            os.kill(pid, signal.SIGSTOP)
        except Exception:
            pass
    L.ledger_add("agent-pause", count=len(procs))
    return f"Paused {len(procs)} agent process(es)."

def agents_resume():
    procs = agent_procs()
    for pid, _ in procs:
        try:
            os.kill(pid, signal.SIGCONT)
        except Exception:
            pass
    L.ledger_add("agent-resume", count=len(procs))
    return f"Resumed {len(procs)} agent process(es)."

CANARY_DIR = os.path.join(L.HOME, ".leviathan-canary")
CANARY_FILES = {
    "aws_credentials": "[default]\naws_access_key_id = FAKEKEY\naws_secret_access_key = FAKESECRET\n",
    "wallet_seed.txt": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n",
}

def agents_canary_on():
    os.makedirs(CANARY_DIR, exist_ok=True)
    atimes = {}
    for name, content in CANARY_FILES.items():
        p = os.path.join(CANARY_DIR, name)
        with open(p, "w") as f:
            f.write(content)
        st = os.stat(p)
        atimes[name] = st.st_atime
    # Save atimes
    with open(os.path.join(CANARY_DIR, "atimes.json"), "w") as f:
        json.dump(atimes, f)
    L.ledger_add("canary-create", files=list(CANARY_FILES.keys()))
    return "Canary files created."

def agents_check():
    try:
        with open(os.path.join(CANARY_DIR, "atimes.json")) as f:
            atimes = json.load(f)
    except Exception:
        return "No canary data. Run `leviathan agents canary on` first."
    results = []
    for name, old_atime in atimes.items():
        p = os.path.join(CANARY_DIR, name)
        try:
            st = os.stat(p)
            if st.st_atime > old_atime + 1:
                results.append(f"{name} was read at {datetime.datetime.fromtimestamp(st.st_atime).isoformat()}")
        except Exception:
            pass
    # Check lsof for agent processes holding sensitive files
    procs = agent_procs()
    if procs and get_modes().get("agents"):
        sensitive = (os.path.join(L.HOME, ".ssh"), os.path.join(L.HOME, "Library/Keychains"),
                     os.path.join(L.HOME, "Library/Application Support/Ledger"),
                     os.path.join(L.HOME, "Library/Application Support/Exodus"),
                     os.path.join(L.HOME, "Library/Application Support/Electrum"),
                     os.path.join(L.HOME, "Library/Application Support/Trezor"),
                     os.path.join(L.HOME, "Library/Application Support/Sparrow"),
                     os.path.join(L.HOME, "Library/Application Support/Google/Chrome"),
                     os.path.join(L.HOME, "Library/Application Support/Firefox"))
        for pid, _ in procs:
            code, out = L.run(["lsof", "-p", str(pid), "-F", "n"])
            for line in out.splitlines():
                if line.startswith("n"):
                    path = line[1:]
                    for s in sensitive:
                        if path.startswith(s):
                            results.append(f"Agent PID {pid} holds open: {path}")
                            break
    if results:
        L.ledger_add("canary-trigger", details=results)
    return "\n".join(results) if results else "No canary reads or sensitive file access detected."

def agents_config_audit():
    """Read-only check for dangerous AI agent configs."""
    warnings = []
    # Claude Code settings
    cc_settings = os.path.join(L.HOME, ".claude", "settings.json")
    if os.path.exists(cc_settings):
        try:
            with open(cc_settings) as f:
                s = json.load(f)
            if s.get("bypassPermissions") or s.get("dangerously-skip-permissions"):
                warnings.append("Claude Code: bypassPermissions/dangerously-skip-permissions enabled in settings.json")
        except Exception:
            pass
    # Cursor
    cursor_settings = os.path.join(L.HOME, "Library/Application Support/Cursor/User/settings.json")
    if os.path.exists(cursor_settings):
        try:
            with open(cursor_settings) as f:
                s = json.load(f)
            if s.get("cursor.autoRun") and not s.get("cursor.autoRunAllowlist"):
                warnings.append("Cursor: auto-run enabled without allowlist")
        except Exception:
            pass
    # Codex (VS Code extension)
    codex_settings = os.path.join(L.HOME, "Library/Application Support/Code/User/settings.json")
    if os.path.exists(codex_settings):
        try:
            with open(codex_settings) as f:
                s = json.load(f)
            if s.get("codex.autoRun") and not s.get("codex.autoRunAllowlist"):
                warnings.append("Codex: auto-run enabled without allowlist")
        except Exception:
            pass
    if not warnings:
        return "No dangerous agent configs found."
    return "\n".join(warnings)

# ---------- Tor ----------
def tor_check():
    """Check Tor Browser presence, signature, version, security level."""
    results = []
    # Find Tor Browser
    tb_paths = [
        os.path.join(L.HOME, "Applications/Tor Browser.app"),
        os.path.join("/Applications/Tor Browser.app"),
        os.path.join(L.HOME, "Desktop/Tor Browser.app"),
    ]
    tb = None
    for p in tb_paths:
        if os.path.exists(p):
            tb = p
            break
    if not tb:
        return "Tor Browser not found."
    results.append(f"Found: {tb}")
    # Signature
    code, out = L.run(["codesign", "-dv", "--verbose=2", tb])
    team_id = ""
    for line in out.splitlines():
        if "TeamIdentifier=" in line:
            team_id = line.split("TeamIdentifier=")[1].strip()
            break
    expected = "MADPSAYN6T"
    if team_id == expected:
        results.append(f"Signature: valid (Team ID {team_id})")
    else:
        results.append(f"Signature: UNEXPECTED Team ID {team_id or 'none'} (expected {expected})")
    # Version
    plist_path = os.path.join(tb, "Contents/Info.plist")
    local_version = ""
    try:
        with open(plist_path, "rb") as f:
            pl = plistlib.load(f)
        local_version = pl.get("CFBundleShortVersionString", "")
        results.append(f"Local version: {local_version}")
    except Exception:
        results.append("Local version: unknown")
    # Fetch latest (optional, timeout 5s)
    try:
        import urllib.request
        req = urllib.request.Request("https://aus1.torproject.org/torbrowser/update_3/release/downloads.json", headers={"User-Agent": "Leviathan/2.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.load(resp)
        # Find latest stable
        latest = ""
        for k, v in data.items():
            if k.startswith("linux") or k.startswith("macos") or k.startswith("windows"):
                for item in v:
                    if item.get("version"):
                        latest = item["version"]
                        break
                if latest:
                    break
        if latest:
            results.append(f"Latest version: {latest}")
            if local_version and local_version != latest:
                results.append("WARNING: Tor Browser is not the latest version.")
    except Exception:
        results.append("Latest version: could not fetch (offline or timeout)")
    # Security level
    prefs_js = None
    for d in ("Browser/TorBrowser/Data/Browser/profile.default", "Browser/TorBrowser/Data/Browser"):
        p = os.path.join(tb, "Contents/Resources", d, "prefs.js")
        if os.path.exists(p):
            prefs_js = p
            break
    if prefs_js:
        try:
            with open(prefs_js) as f:
                content = f.read()
            m = re.search(r'browser\.security_level\.security_slider\s*,\s*(\d+)', content)
            if m:
                level = int(m.group(1))
                names = {0: "Standard", 1: "Safer", 2: "Safest"}
                results.append(f"Security level: {names.get(level, 'Unknown')} ({level})")
                if level != 2:
                    results.append("WARNING: Security level is not 'Safest'.")
            else:
                results.append("Security level: not set (default Standard)")
        except Exception:
            results.append("Security level: could not read prefs.js")
    else:
        results.append("Security level: profile not found")
    return "\n".join(results)

# ---------- cost ----------
def cost():
    """Print CPU seconds used by Leviathan processes in last day from ledger, and menu bar app RSS."""
    # Ledger timings
    cpu_total = 0.0
    day_ago = time.time() - 86400
    for e in L._entries():
        try:
            t = datetime.datetime.fromisoformat(e["time"].replace("Z", "+00:00")).timestamp()
        except Exception:
            continue
        if t < day_ago:
            continue
        cpu_total += e.get("cpu_seconds", 0.0)
    # Menu bar app RSS
    rss = 0
    code, out = L.run(["pgrep", "-f", "LeviathanBar"])
    if code == 0:
        for pid in out.split():
            try:
                code2, out2 = L.run(["ps", "-o", "rss=", pid])
                rss += int(out2.strip() or 0)
            except Exception:
                pass
    return f"CPU (last 24h): {cpu_total:.1f}s\nMenu bar RSS: {rss} KB"

# ---------- note-event ----------
def note_event(kind, detail):
    L.ledger_add(kind, detail=detail)
    return f"Logged: {kind}"


if __name__ == "__main__":
    # Quick self-test
    print("levplus.py loaded")
    print("BIP39 words:", len(_load_bip39()))
    print("clip_check test:", clip_check("bc1qtest", "bc1qother"))
    print("seed_phrase test:", seed_phrase("abandon " * 11 + "about"))