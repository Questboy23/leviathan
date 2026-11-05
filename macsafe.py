#!/opt/homebrew/bin/python3
"""MacSafe: quiet, local Mac protection. Every action is logged and undoable.
Commands: scan-downloads | scan-apps | scan-persist | sweep [--fix] | check-cmd CMD |
          pwwatch SECONDS | undo ID | status | verify | fix-chrome-notify"""
import datetime, hashlib, json, os, plistlib, re, shutil, subprocess, sys, time

HOME = os.path.expanduser("~")
STATE = os.environ.get("MACSAFE_STATE", os.path.join(HOME, ".macsafe"))
QUAR = os.path.join(STATE, "quarantine")
LEDGER = os.path.join(STATE, "ledger.jsonl")
SEEN = os.path.join(STATE, "seen.json")
BLOCKLIST = "/var/db/macsafe/blocklist.txt" if os.path.exists("/var/db/macsafe/blocklist.txt") else os.path.join(STATE, "blocklist.txt")
EXTRA_YARA = os.path.join(STATE, "extra.yara")
DOWNLOADS = os.environ.get("MACSAFE_DOWNLOADS", os.path.join(HOME, "Downloads"))
XPROTECT_YARA = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara"
YARA = shutil.which("yara") or "/opt/homebrew/bin/yara"
PERSIST_DIRS = [os.path.join(HOME, "Library/LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"]
if os.environ.get("MACSAFE_PERSIST_DIRS"):
    PERSIST_DIRS = os.environ["MACSAFE_PERSIST_DIRS"].split(":")
QUIET = os.environ.get("MACSAFE_QUIET") == "1"
SKIP_SUFFIX = (".crdownload", ".download", ".part", ".tmp")


def run(argv, timeout=60):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return 99, str(e)


# ---------- tamper-proof ledger ----------
def _entries():
    if not os.path.exists(LEDGER):
        return []
    with open(LEDGER) as f:
        return [json.loads(l) for l in f if l.strip()]


def _hash(prev, entry):
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256((prev + json.dumps(body, sort_keys=True)).encode()).hexdigest()


def ledger_add(kind, **data):
    os.makedirs(STATE, exist_ok=True)
    es = _entries()
    prev = es[-1]["hash"] if es else "0" * 64
    e = {"id": (es[-1]["id"] + 1) if es else 1,
         "time": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
         "kind": kind, **data, "prev": prev}
    e["hash"] = _hash(prev, e)
    with open(LEDGER, "a") as f:
        f.write(json.dumps(e) + "\n")
    return e["id"]


def verify():
    prev = "0" * 64
    for e in _entries():
        if e["prev"] != prev or _hash(prev, e) != e["hash"]:
            print(f"Ledger was edited at entry {e['id']}.")
            return False
        prev = e["hash"]
    print("Ledger intact.")
    return True


def notify(msg):
    if QUIET:
        print("NOTIFY:", msg)
        return
    safe = msg.replace("\\", "").replace('"', "'")
    run(["osascript", "-e", f'display notification "{safe}" with title "MacSafe"'])


# ---------- detection ----------
def yara_hits(target):
    hits = []
    if not os.path.exists(YARA):
        return hits
    if target.endswith(".app") and os.path.isdir(os.path.join(target, "Contents/MacOS")):
        target = os.path.join(target, "Contents/MacOS")  # scan the app's programs, not its images and fonts
    for rules in (XPROTECT_YARA, EXTRA_YARA):
        if os.path.exists(rules):
            code, out = run([YARA, "-w", "-r", rules, target], timeout=120)
            hits += [l.split()[0] for l in out.splitlines() if l.strip() and not l.startswith("error")]
    return hits


def blocklist():
    s = set()
    if os.path.exists(BLOCKLIST):
        with open(BLOCKLIST, errors="ignore") as f:
            for l in f:
                l = l.strip().lstrip("*.")
                if l and not l.startswith("#"):
                    s.add(l.lower())
    return s


def domain_blocked(host, bl):
    parts = host.lower().split(".")
    return any(".".join(parts[i:]) in bl for i in range(len(parts) - 1))


def where_from(path):
    code, out = run(["mdls", "-raw", "-name", "kMDItemWhereFroms", path])
    return re.findall(r'https?://([^/"\s:]+)', out)


def sign_check(path):
    """Returns (revoked, apple_ok)."""
    revoked = False
    ext = path.lower()
    kind = "install" if ext.endswith((".pkg", ".mpkg")) else "execute"
    args = ["spctl", "--assess", "--type", kind, path]
    if ext.endswith(".dmg"):
        args = ["spctl", "--assess", "--type", "open", "--context", "context:primary-signature", path]
    code2, sp = run(args, timeout=180)
    if code2 == 99:
        return False, True  # couldn't decide in time: don't bother the user
    return "REVOKED" in sp.upper(), code2 == 0


def is_runnable(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in {".app", ".pkg", ".mpkg", ".dmg", ".command", ".tool", ".terminal", ".scpt", ".jar", ".sh"}:
        return True
    try:
        with open(path, "rb") as f:
            head = f.read(4)
        return head in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xce\xfa\xed\xfe") or head[:2] == b"#!"
    except Exception:
        return False


def verdict(path, bl=None):
    """('bad', reason) auto-contain | ('unverified', reason) label only | ('ok', '')"""
    hits = yara_hits(path)
    if hits:
        return "bad", f"matches Apple's malware rules ({hits[0]})"
    bl = bl if bl is not None else blocklist()
    for host in where_from(path):
        if domain_blocked(host, bl):
            return "bad", f"downloaded from a known malware or scam site ({host})"
    if is_runnable(path):
        revoked, ok = sign_check(path)
        if revoked:
            return "bad", "its developer certificate was revoked by Apple"
        if not ok:
            return "unverified", "not checked by Apple (unsigned or not notarized)"
    return "ok", ""


# ---------- actions (all undoable) ----------
def contain(path, reason, after=None):
    os.makedirs(QUAR, exist_ok=True)
    dst = os.path.join(QUAR, time.strftime("%Y%m%d-%H%M%S-") + os.path.basename(path.rstrip("/")))
    modes = {}
    shutil.move(path, dst)
    for root, dirs, files in os.walk(dst) if os.path.isdir(dst) else [(os.path.dirname(dst), [], [os.path.basename(dst)])]:
        for fn in files:
            p = os.path.join(root, fn)
            try:
                m = os.lstat(p).st_mode
                modes[os.path.relpath(p, dst) if os.path.isdir(dst) else "."] = m
                os.chmod(p, m & ~0o111)
            except Exception:
                pass
    i = ledger_add("contained", path=path, reason=reason,
                   undo={"type": "move", "src": dst, "dst": path, "modes": modes, "after": after or []})
    notify(f"Removed a threat: {os.path.basename(path)}. It can't run. Undo: macsafe undo {i}")
    start_pwwatch()
    return i


def label(path, reason):
    tag = plistlib.dumps(["MacSafe unverified\n5"], fmt=plistlib.FMT_BINARY).hex()
    run(["xattr", "-wx", "com.apple.metadata:_kMDItemUserTags", tag, path])
    ledger_add("labeled", path=path, reason=reason,
               undo={"type": "cmd", "argv": ["xattr", "-d", "com.apple.metadata:_kMDItemUserTags", path]})
    start_pwwatch()


def undo(i):
    es = _entries()
    if any(e["kind"] == "undone" and e.get("ref") == i for e in es):
        print(f"Entry {i} was already undone.")
        return
    e = next((e for e in es if e["id"] == i), None)
    if not e or "undo" not in e:
        print(f"Nothing to undo for entry {i}.")
        return
    u = e["undo"]
    if u["type"] == "move":
        shutil.move(u["src"], u["dst"])
        for rel, m in u.get("modes", {}).items():
            p = u["dst"] if rel == "." else os.path.join(u["dst"], rel)
            try:
                os.chmod(p, m)
            except Exception:
                pass
        for argv in u.get("after", []):
            run(argv)
    elif u["type"] == "cmd":
        run(u["argv"])
    elif u["type"] == "cmds":
        for argv in u["argv"]:
            run(argv)
    ledger_add("undone", ref=i)
    print(f"Undid entry {i}: {e.get('path') or e.get('setting') or e['kind']}.")


# ---------- scanners ----------
def _seen():
    try:
        with open(SEEN) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_seen(s):
    os.makedirs(STATE, exist_ok=True)
    with open(SEEN, "w") as f:
        json.dump(s, f)


def scan_dir(folder, key, only_apps=False):
    seen = _seen()
    known = seen.setdefault(key, {})
    first = not seen.get(key + ":baselined")
    seen[key + ":baselined"] = True
    bl = blocklist()
    try:
        names = os.listdir(folder)
    except Exception as e:
        print(f"Can't read {folder}: {e}")
        return
    for n in names:
        p = os.path.join(folder, n)
        if n.startswith(".") or n.endswith(SKIP_SUFFIX) or (only_apps and not n.endswith(".app")):
            continue
        try:
            mt = str(os.stat(p).st_mtime)
        except Exception:
            continue
        if known.get(n) == mt:
            continue
        known[n] = mt
        if first and only_apps:
            continue  # baseline existing apps quietly
        level, why = verdict(p, bl)
        if level == "bad":
            contain(p, why)
        elif level == "unverified" and not first:
            label(p, why)
    _save_seen(seen)


def _program(plist_path):
    try:
        with open(plist_path, "rb") as f:
            d = plistlib.load(f)
    except Exception:
        return None, None
    prog = d.get("Program") or (d.get("ProgramArguments") or [None])[0]
    return d.get("Label", ""), prog


def _apple_signed(path):
    code, out = run(["codesign", "-dv", "--verbose=2", path])
    return "Authority=Software Signing" in out


def _is_macho(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xce\xfa\xed\xfe")
    except Exception:
        return False


def persist_verdict(plist_path):
    lab, prog = _program(plist_path)
    if not prog or not os.path.exists(prog):
        return "ok", ""
    if yara_hits(prog):
        return "bad", "its program matches Apple's malware rules"
    if lab.startswith("com.apple.") and not prog.startswith(("/System/", "/usr/")) and not _apple_signed(prog):
        return "bad", "it pretends to be part of macOS but isn't from Apple"
    hidden = any(part.startswith(".") for part in prog.split("/")[1:-1]) or prog.startswith(("/tmp/", "/private/tmp/", "/Users/Shared/"))
    code, _ = run(["codesign", "--verify", prog])
    if hidden and _is_macho(prog) and code != 0:
        return "bad", "an unsigned program hidden in a secret folder set itself to auto-start"
    if code != 0:
        return "unverified", "auto-starts an unsigned program"
    return "ok", ""


def scan_persist():
    seen = _seen()
    known = seen.setdefault("persist", {})
    uid = str(os.getuid())
    for d in PERSIST_DIRS:
        try:
            names = [n for n in os.listdir(d) if n.endswith(".plist")]
        except Exception:
            continue
        for n in names:
            p = os.path.join(d, n)
            try:
                mt = str(os.stat(p).st_mtime)
            except Exception:
                continue
            if known.get(p) == mt:
                continue
            known[p] = mt
            level, why = persist_verdict(p)
            if level == "bad":
                if os.access(d, os.W_OK):
                    run(["launchctl", "bootout", f"gui/{uid}", p])
                    contain(p, why, after=[["launchctl", "bootstrap", f"gui/{uid}", p]])
                else:
                    ledger_add("flagged", path=p, reason=why)
                    notify(f"Found a threat that needs your password to remove: {n}. Run: sudo macsafe contain '{p}'")
            elif level == "unverified":
                ledger_add("noticed", path=p, reason=why)
    _save_seen(seen)


# ---------- fake password box watch ----------
PW_LOCK = os.path.join(STATE, "pwwatch.until")


def start_pwwatch(seconds=900):
    try:
        os.makedirs(STATE, exist_ok=True)
        until = time.time() + seconds
        running = os.path.exists(PW_LOCK) and float(open(PW_LOCK).read() or 0) > time.time()
        with open(PW_LOCK, "w") as f:
            f.write(str(until))
        if not running and not os.environ.get("MACSAFE_NO_SPAWN"):
            subprocess.Popen([sys.executable, os.path.abspath(__file__), "pwwatch"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except Exception:
        pass


FAKE_PW = re.compile(r"osascript.*(hidden answer|with hidden).*", re.I)


def pwwatch():
    while True:
        try:
            until = float(open(PW_LOCK).read() or 0)
        except Exception:
            until = 0
        if time.time() > until:
            break
        code, out = run(["ps", "-axo", "pid=,command="])
        for line in out.splitlines():
            line = line.strip()
            if FAKE_PW.search(line) and "macsafe" not in line:
                pid = line.split()[0]
                run(["kill", "-9", pid])
                ledger_add("blocked", what="fake password box", detail=line[:300])
                notify("Blocked a fake password box. Don't type your password into pop-ups you didn't expect.")
        time.sleep(2)


# ---------- paste guard explanations ----------
TRUSTED_INSTALLERS = ("raw.githubusercontent.com/homebrew/", "brew.sh", "sh.rustup.rs", "astral.sh",
                      "bun.sh", "deno.land", "claude.ai/install", "ollama.com/install", "get.pnpm.io",
                      "raw.githubusercontent.com/nvm-sh/", "install.python-poetry.org", "fly.io/install",
                      "supabase.com", "vercel.com", "cli.github.com", "sdk.cloud.google.com")
RULES = [
    (r"(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(/bin/|/usr/bin/)?(ba|z|da|k)?sh\b", "downloads a program from the internet and runs it immediately"),
    (r"(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(python\d*|perl|ruby|osascript|node)\b", "downloads code from the internet and runs it immediately"),
    (r"(eval|(ba|z)?sh\s+-c)\s*[\"']?\$\(\s*(curl|wget)", "runs code downloaded from the internet"),
    (r"base64\s+(-d|-D|--decode)", "unscrambles hidden text, usually to run something it doesn't want you to read"),
    (r"xattr\s+(-[a-z]*[dc][a-z]*\s+)*(-[a-z]*\s+)*com\.apple\.quarantine|xattr\s+-c", "removes Apple's safety check from a file"),
    (r"osascript.*(password|hidden answer)", "shows a fake password box to steal your Mac password"),
    (r"/dev/tcp/", "opens a hidden connection to another computer"),
    (r"spctl\s+--(master|global)-disable", "turns off Apple's app checks"),
    (r"(curl|wget)\b.*(-o|-O|>)\s*\S*(/tmp/|/private/tmp/|/Users/Shared/)\S*.*(chmod\s+\+?[0-7]*x|open\s|\./)", "downloads a program to a hidden spot and runs it"),
]


def check_cmd(line):
    low = line.lower()
    hosts = re.findall(r"https?://([^/\s\"'|)]+)", low)
    bl = blocklist()
    for h in hosts:
        if domain_blocked(h, bl):
            return f"It connects to a known malware or scam site ({h})."
    urls = re.findall(r"https?://([^\s\"'|)]+)", low)
    for pat, why in RULES:
        if re.search(pat, low):
            if urls and all(u.startswith(TRUSTED_INSTALLERS) for u in urls):
                return ""
            return f"It {why}. Fake 'fix' and 'verify you're human' pages ask people to paste commands like this."
    return ""


# ---------- settings sweep ----------
def _read(argv):
    return run(argv)[1].strip()


def sweep_user(fix):
    out = []
    mode = _read(["defaults", "read", "com.apple.sharingd", "DiscoverableMode"])
    if mode == "Everyone":
        if fix:
            run(["defaults", "write", "com.apple.sharingd", "DiscoverableMode", "-string", "Contacts Only"])
            run(["killall", "sharingd"])
            ledger_add("setting", setting="AirDrop: Everyone -> Contacts Only",
                       undo={"type": "cmds", "argv": [["defaults", "write", "com.apple.sharingd", "DiscoverableMode", "-string", "Everyone"], ["killall", "sharingd"]]})
        out.append(("fixed" if fix else "issue", "AirDrop was open to everyone; now contacts only"))
    else:
        out.append(("ok", "AirDrop limited"))
    out += chrome_report()
    return out


def sweep_system(fix):
    out = []
    fw = _read(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    if "disabled" in fw.lower():
        if fix:
            run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"])
            run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setallowsigned", "on"])
            run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setallowsignedapp", "on"])
            ledger_add("setting", root=True, setting="Firewall: off -> on",
                       undo={"type": "cmd", "argv": ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "off"]})
        out.append(("fixed" if fix else "issue", "Firewall was off"))
    else:
        out.append(("ok", "Firewall on"))
    if "disabled" in _read(["spctl", "--status"]):
        if fix:
            run(["spctl", "--global-enable"])
            ledger_add("setting", root=True, setting="Apple app checks: off -> on", undo={"type": "cmd", "argv": ["spctl", "--global-disable"]})
        out.append(("fixed" if fix else "issue", "Apple's app checks were off"))
    else:
        out.append(("ok", "Apple's app checks on"))
    pref = "/Library/Preferences/com.apple.SoftwareUpdate"
    for key, name in (("AutomaticCheckEnabled", "check for updates"), ("AutomaticDownload", "download updates"),
                      ("CriticalUpdateInstall", "install security fixes"), ("ConfigDataInstall", "update malware rules")):
        if _read(["defaults", "read", pref, key]) != "1":
            if fix:
                prev = _read(["defaults", "read", pref, key])
                run(["defaults", "write", pref, key, "-bool", "true"])
                undo_argv = ["defaults", "write", pref, key, "-bool", "false"] if prev == "0" else ["defaults", "delete", pref, key]
                ledger_add("setting", root=True, setting=f"Auto {name}: on", undo={"type": "cmd", "argv": undo_argv})
            out.append(("fixed" if fix else "issue", f"Automatic {name} was off"))
    out.append(("ok" if "On" in _read(["fdesetup", "status"]) else "issue", "Disk encryption (FileVault)"))
    rl = _read(["systemsetup", "-getremotelogin"])
    if "On" in rl:
        out.append(("issue", "Remote login (SSH) is on. Turn off in System Settings > General > Sharing if unused"))
    prof = _read(["profiles", "list"])
    if prof and "There are no" not in prof:
        out.append(("issue", "Settings profiles installed (check System Settings > Privacy & Security > Profiles): " + prof[:200]))
    return out


# ---------- Chrome: notification spam + hijacked search ----------
CHROME = os.path.join(HOME, "Library/Application Support/Google/Chrome")
GOOD_SEARCH = ("google.", "bing.com", "duckduckgo.com", "search.brave.com", "ecosia.org", "yahoo.com",
               "kagi.com", "startpage.com", "perplexity.ai", "chatgpt.com")
SPAMMY = re.compile(r"(push|notif|alert|allow|captcha|verify|robot|clicks?|win|prize|news\d|\d{4,})", re.I)


def _chrome_profiles():
    if not os.path.isdir(CHROME):
        return []
    return [os.path.join(CHROME, d, "Preferences") for d in os.listdir(CHROME)
            if (d == "Default" or d.startswith("Profile ")) and os.path.exists(os.path.join(CHROME, d, "Preferences"))]


def _spam_sites(prefs, bl):
    ex = prefs.get("profile", {}).get("content_settings", {}).get("exceptions", {}).get("notifications", {})
    bad = []
    for pat, v in ex.items():
        if v.get("setting") != 1:
            continue
        host = re.sub(r"^https?://|[:/].*$|^\[\*\.\]", "", pat.split(",")[0])
        if domain_blocked(host, bl) or SPAMMY.search(host):
            bad.append(pat)
    return bad


def chrome_report():
    out, bl = [], blocklist()
    for pf in _chrome_profiles():
        try:
            prefs = json.load(open(pf))
        except Exception:
            continue
        name = os.path.basename(os.path.dirname(pf))
        spam = _spam_sites(prefs, bl)
        if spam:
            out.append(("issue", f"Chrome ({name}): {len(spam)} likely spam sites can send you notifications. Fix: quit Chrome, run: macsafe fix-chrome-notify"))
        url = prefs.get("default_search_provider_data", {}).get("template_url_data", {}).get("url", "")
        if url and not any(g in url for g in GOOD_SEARCH):
            out.append(("issue", f"Chrome ({name}) search engine looks hijacked: {url[:80]}. Fix in Chrome Settings > Search engine"))
    if _chrome_profiles() and not out:
        out.append(("ok", "Chrome notifications and search engine look clean"))
    return out


def fix_chrome_notify():
    if run(["pgrep", "-x", "Google Chrome"])[0] == 0:
        print("Quit Chrome first, then run this again.")
        return
    bl = blocklist()
    for pf in _chrome_profiles():
        prefs = json.load(open(pf))
        spam = _spam_sites(prefs, bl)
        if not spam:
            continue
        backup = pf + ".macsafe-" + time.strftime("%Y%m%d%H%M%S")
        shutil.copy2(pf, backup)
        ex = prefs["profile"]["content_settings"]["exceptions"]["notifications"]
        for pat in spam:
            ex.pop(pat, None)
        json.dump(prefs, open(pf, "w"))
        ledger_add("setting", setting=f"Chrome: revoked notifications for {len(spam)} spam sites",
                   undo={"type": "move", "src": backup, "dst": pf})
        print(f"Revoked {len(spam)} spam notification sites. Undo with macsafe undo.")


# ---------- status + main ----------
def status():
    es = _entries()
    undone = {e.get("ref") for e in es if e["kind"] == "undone"}
    shown = [e for e in es if e["kind"] in ("contained", "labeled", "setting", "blocked", "flagged")]
    if not shown:
        print("Nothing has needed action yet.")
    for e in shown[-30:]:
        tag = " (undone)" if e["id"] in undone else (f"   undo: macsafe undo {e['id']}" if "undo" in e else "")
        print(f"#{e['id']} {e['time'][:16]} {e['kind']}: {e.get('path') or e.get('setting') or e.get('what')} {('- ' + e['reason']) if e.get('reason') else ''}{tag}")


def print_sweep(results):
    for lvl, msg in results:
        mark = {"ok": "OK   ", "fixed": "FIXED", "issue": "CHECK"}[lvl]
        print(f"  {mark} {msg}")


def main():
    a = sys.argv[1:] or ["status"]
    c = a[0]
    if c == "scan-downloads":
        scan_dir(DOWNLOADS, "downloads")
    elif c == "scan-apps":
        scan_dir("/Applications", "apps", only_apps=True)
    elif c == "scan-persist":
        scan_persist()
    elif c == "scan-all":
        scan_dir(DOWNLOADS, "downloads"); scan_dir("/Applications", "apps", only_apps=True); scan_persist()
    elif c == "sweep":
        fix = "--fix" in a
        res = sweep_system(fix) if os.geteuid() == 0 else sweep_user(fix)
        if "--quiet" not in a:
            print_sweep(res)
    elif c == "check-cmd":
        msg = check_cmd(" ".join(a[1:]))
        if msg:
            print(msg)
            ledger_add("paste-stopped", detail=" ".join(a[1:])[:300], reason=msg)
            start_pwwatch()
    elif c == "contain" and len(a) > 1:
        contain(a[1], "removed by you")
    elif c == "pwwatch":
        pwwatch()
    elif c == "undo" and len(a) > 1:
        undo(int(a[1]))
    elif c == "verify":
        sys.exit(0 if verify() else 1)
    elif c == "fix-chrome-notify":
        fix_chrome_notify()
    else:
        status()


if __name__ == "__main__":
    main()
