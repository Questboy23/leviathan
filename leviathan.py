#!/usr/bin/env python3
"""Leviathan: stops viruses before they run on a Mac. Every action is logged and undoable.
Commands: scan | scan-downloads | scan-apps | scan-persist | sweep [--fix] | check-cmd CMD |
          pwwatch | undo ID | undo-settings | status | verify | contain PATH | fix-chrome-notify"""
import datetime, hashlib, json, os, plistlib, re, shutil, subprocess, sys, time, signal

os.umask(0o077)  # the log and quarantine are readable by you only
HOME = os.path.expanduser("~")
IS_ROOT = os.geteuid() == 0
ROOT_DIR = "/var/db/leviathan"
ROOT_TOOL = "/Library/Application Support/Leviathan/leviathan-root"
# root keeps its own log in a root-owned folder, so nothing you can edit is ever run as root
STATE = ROOT_DIR if IS_ROOT else os.environ.get("LEVIATHAN_STATE", os.path.join(HOME, ".leviathan"))
QUAR = os.path.join(STATE, "quarantine")
LEDGER = os.path.join(STATE, "ledger.jsonl")
SEEN = os.path.join(STATE, "seen.json")
BLOCKLIST = os.path.join(ROOT_DIR, "blocklist.txt") if os.path.exists(os.path.join(ROOT_DIR, "blocklist.txt")) else os.path.join(STATE, "blocklist.txt")
EXTRA_YARA = os.path.join(STATE, "extra.yara")
DOWNLOADS = os.environ.get("LEVIATHAN_DOWNLOADS", os.path.join(HOME, "Downloads"))
_XP = ["/private/var/protected/xprotect/XProtect.bundle/Contents/Resources/XProtect.yara",
       "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara"]
_XP = [p for p in _XP if os.path.exists(p)]
XPROTECT_YARA = max(_XP, key=os.path.getmtime) if _XP else "/nonexistent"  # newest copy of Apple's rules
YARA = next((p for p in ("/opt/homebrew/bin/yara", "/usr/local/bin/yara") if os.path.exists(p)), shutil.which("yara") or "/opt/homebrew/bin/yara")
if IS_ROOT and not (os.path.exists(YARA) and os.stat(YARA).st_uid == 0):
    YARA = "/nonexistent"  # root never runs a yara binary that a normal user could have replaced
APP_DIRS = os.environ.get("LEVIATHAN_APP_DIRS", "/Applications:" + os.path.join(HOME, "Applications")).split(":")
PERSIST_DIRS = [os.path.join(HOME, "Library/LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"]
if os.environ.get("LEVIATHAN_PERSIST_DIRS"):
    PERSIST_DIRS = os.environ["LEVIATHAN_PERSIST_DIRS"].split(":")
QUIET = os.environ.get("LEVIATHAN_QUIET") == "1"
SKIP_SUFFIX = (".crdownload", ".download", ".part", ".tmp")


def run(argv, timeout=60):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return 99, str(e)


# ---------- tamper-proof ledger ----------
def _entries(path=None):
    path = path or LEDGER
    try:
        with open(path) as f:
            return [json.loads(l) for l in f if l.strip()]
    except (OSError, ValueError):
        return []


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
    if IS_ROOT:
        os.chmod(LEDGER, 0o644)
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
    run(["osascript", "-e", f'display notification "{safe}" with title "Leviathan"'])


# ---------- detection ----------
def _compiled(rules):
    """Compiles a rule file once (about 4 s for Apple's rules) and reuses it until the rules change."""
    yarac = os.path.join(os.path.dirname(YARA), "yarac")
    if not os.path.exists(yarac):
        return None
    dst = os.path.join(STATE, "rules-%s.yarc" % hashlib.sha256(rules.encode()).hexdigest()[:12])
    try:
        if os.path.exists(dst) and os.path.getmtime(dst) >= os.path.getmtime(rules):
            return dst
        os.makedirs(STATE, exist_ok=True)
        tmp = dst + ".tmp"
        if run([yarac, "-w", rules, tmp], timeout=180)[0] == 0:
            os.replace(tmp, dst)
            return dst
    except OSError:
        pass
    return None


def yara_hits(target):
    hits = []
    if not os.path.exists(YARA):
        return hits
    if target.endswith(".app") and os.path.isdir(os.path.join(target, "Contents/MacOS")):
        target = os.path.join(target, "Contents/MacOS")  # scan the app's programs, not its images and fonts
    for rules in (XPROTECT_YARA, EXTRA_YARA):
        if os.path.exists(rules):
            compiled = _compiled(rules)
            argv = [YARA, "-w", "-r", "-C", compiled, target] if compiled else [YARA, "-w", "-r", rules, target]
            code, out = run(argv, timeout=120)
            hits += [l.split()[0] for l in out.splitlines() if l.strip() and not l.startswith("error")]
    return hits


def batch_yara(targets):
    """Checks many apps in one yara run, so the rules load once. Returns {target: first rule hit}."""
    if not os.path.exists(YARA) or not targets:
        return {}
    dirs = {}
    for t in targets:
        d = os.path.join(t, "Contents/MacOS") if os.path.isdir(os.path.join(t, "Contents/MacOS")) else t
        dirs[d] = t
    lst = os.path.join(STATE, "scan-list.txt")
    os.makedirs(STATE, exist_ok=True)
    with open(lst, "w") as f:
        f.write("\n".join(dirs) + "\n")
    found = {}
    for rules in (XPROTECT_YARA, EXTRA_YARA):
        if not os.path.exists(rules):
            continue
        compiled = _compiled(rules)
        argv = [YARA, "-w", "-r", "--scan-list"] + (["-C", compiled] if compiled else [rules]) + [lst]
        code, out = run(argv, timeout=1800)
        for line in out.splitlines():
            rule, _, path = line.partition(" ")
            for d, t in dirs.items():
                if path == d or path.startswith(d + "/"):
                    found.setdefault(t, rule)
    os.remove(lst)
    return found


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
    notify(f"Removed a threat: {os.path.basename(path)}. It can't run. Undo: leviathan undo {i}")
    start_pwwatch()
    return i


def note(path, reason):
    """Unsigned is not malware. It is never moved or labeled, only noted in the private log."""
    ledger_add("noticed", path=path, reason=reason)
    start_pwwatch()  # fake password boxes often follow an unsigned download


def undo(i):
    try:
        i = int(i)
    except ValueError:
        print("Use the number shown by `leviathan`, like: leviathan undo 12")
        return
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
            note(p, why)
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
                    notify(f"Found a threat that needs your password to remove: {n}. Run: sudo \"{ROOT_TOOL}\" contain '{p}'")
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
        if not running and not os.environ.get("LEVIATHAN_NO_SPAWN"):
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
            if FAKE_PW.search(line) and "leviathan" not in line:
                pid = line.split()[0]
                run(["kill", "-9", pid])
                ledger_add("blocked", what="fake password box", detail=line[:300])
                notify("Blocked a fake password box. Don't type your password into pop-ups you didn't expect.")
        time.sleep(2)


# ---------- paste guard explanations ----------
TRUSTED_INSTALLERS = ("raw.githubusercontent.com/homebrew/", "brew.sh/", "sh.rustup.rs/", "astral.sh/",
                      "bun.sh/", "deno.land/", "claude.ai/install", "ollama.com/install", "get.pnpm.io/",
                      "raw.githubusercontent.com/nvm-sh/", "install.python-poetry.org/", "fly.io/install",
                      "cli.github.com/", "sdk.cloud.google.com/")


def _trusted(u):
    """u is a lowercased URL without its scheme. Host must match exactly; a trailing dot or port is not allowed."""
    u = u if "/" in u else u + "/"
    return any(u.startswith(t) for t in TRUSTED_INSTALLERS)
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
            if urls and all(_trusted(u) for u in urls):
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
    ids = sorted(set(re.findall(r"profileIdentifier:\s*(\S+)", prof)))
    if ids:
        out.append(("issue", "Settings profiles installed, check they are ones you added (System Settings > General > Device Management): " + ", ".join(ids)))
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
            out.append(("issue", f"Chrome ({name}): {len(spam)} likely spam sites can send you notifications. Fix: quit Chrome, run: leviathan fix-chrome-notify"))
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
        backup = pf + ".leviathan-" + time.strftime("%Y%m%d%H%M%S")
        shutil.copy2(pf, backup)
        ex = prefs["profile"]["content_settings"]["exceptions"]["notifications"]
        for pat in spam:
            ex.pop(pat, None)
        json.dump(prefs, open(pf, "w"))
        ledger_add("setting", setting=f"Chrome: revoked notifications for {len(spam)} spam sites",
                   undo={"type": "move", "src": backup, "dst": pf})
        print(f"Revoked {len(spam)} spam notification sites. Undo with leviathan undo.")


# ---------- full scan (read-only) ----------
def _listeners():
    """Programs accepting connections from other computers, not just this Mac."""
    code, out = run(["lsof", "+c", "0", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcn"], timeout=30)
    found, pid, prog = {}, "", ""
    for line in out.splitlines():
        tag, val = line[:1], line[1:]
        if tag == "p":
            pid = val
        elif tag == "c":
            prog = val.replace("\\x20", " ")
        if tag != "n" or not pid:
            continue
        exe = run(["ps", "-p", pid, "-o", "comm="])[1].strip()
        if exe.startswith(("/System/", "/usr/libexec/", "/usr/sbin/")):
            continue  # macOS's own sharing services (AirPlay, Handoff) are expected
        addr = val
        host, _, port = addr.rpartition(":")
        if host in ("127.0.0.1", "[::1]", "localhost") or host.startswith("127."):
            continue
        found.setdefault((prog, port), host)
    return [f"{prog} accepts connections from your network on port {port}" for (prog, port) in sorted(found)]


def full_scan():
    """Checks everything once and changes nothing. Returns the number of threats."""
    threats, issues = [], []
    bl = blocklist()
    apps = []
    for d in APP_DIRS:
        try:
            apps += [os.path.join(d, n) for n in sorted(os.listdir(d)) if n.endswith(".app")]
        except OSError:
            pass
    print(f"Leviathan scan: {len(apps)} apps, Downloads, auto-start items, network, settings. Changes nothing.\n")
    print("  checking apps against Apple's malware rules...")
    for p, rule in batch_yara(apps).items():
        threats.append(f"{p}: matches Apple's malware rules ({rule})")
    try:
        dl = [os.path.join(DOWNLOADS, n) for n in os.listdir(DOWNLOADS) if not n.startswith(".")]
    except OSError:
        dl = []
    archives = (".zip", ".dmg", ".pkg", ".mpkg", ".app", ".command", ".sh", ".jar", ".scpt")
    dl = [p for p in dl if is_runnable(p) or p.lower().endswith(archives)]  # documents and photos can't run on their own
    print(f"  checking {len(dl)} runnable downloads...")
    small = [p for p in dl if os.path.isdir(p) or os.path.getsize(p) < 300_000_000]  # real malware installers are far smaller
    for p, rule in batch_yara(small).items():
        threats.append(f"{p}: matches Apple's malware rules ({rule})")
    for p in dl:
        hosts = [h for h in where_from(p) if domain_blocked(h, bl)]
        if hosts:
            threats.append(f"{p}: downloaded from a known malware or scam site ({hosts[0]})")
    for d in PERSIST_DIRS:
        try:
            names = [n for n in os.listdir(d) if n.endswith(".plist")]
        except OSError:
            continue
        for n in names:
            level, why = persist_verdict(os.path.join(d, n))
            if level == "bad":
                threats.append(f"{os.path.join(d, n)}: {why}")
    issues += _listeners()
    for lvl, msg in sweep_system(False) + sweep_user(False):
        if lvl == "issue":
            issues.append(msg)
    print("\nThreats (things no one wants on their computer):")
    for t in threats or ["none found"]:
        print("  " + t)
    print("\nOpenings to close:")
    for t in issues or ["none found"]:
        print("  " + t)
    if threats:
        print("\nRemove a threat so it can't run (undoable): leviathan contain PATH")
    if issues:
        print("Fix the settings above automatically (undoable): leviathan sweep --fix, then sudo \"%s\" sweep --fix" % ROOT_TOOL)
    return len(threats)


def undo_settings():
    """Reverses every setting change in this log that is not already undone."""
    es = _entries()
    done = {e.get("ref") for e in es if e["kind"] == "undone"}
    for e in reversed(es):
        if e["kind"] == "setting" and e["id"] not in done:
            undo(e["id"])


# ---------- status + main ----------
def status():
    es = _entries()
    undone = {e.get("ref") for e in es if e["kind"] == "undone"}
    shown = [e for e in es if e["kind"] in ("contained", "setting", "blocked", "flagged")]
    if not shown and not os.path.exists(os.path.join(ROOT_DIR, "ledger.jsonl")):
        print("Nothing has needed action yet.")
    for e in shown[-30:]:
        tag = " (undone)" if e["id"] in undone else (f"   undo: leviathan undo {e['id']}" if "undo" in e else "")
        print(f"#{e['id']} {e['time'][:16]} {e['kind']}: {e.get('path') or e.get('setting') or e.get('what')} {('- ' + e['reason']) if e.get('reason') else ''}{tag}")
    if not IS_ROOT:
        rs = _entries(os.path.join(ROOT_DIR, "ledger.jsonl"))
        rdone = {e.get("ref") for e in rs if e["kind"] == "undone"}
        for e in [e for e in rs if e["kind"] in ("contained", "setting", "flagged")][-30:]:
            tag = " (undone)" if e["id"] in rdone else (f"   undo: leviathan undo S{e['id']}" if "undo" in e else "")
            print(f"#S{e['id']} {e['time'][:16]} system {e['kind']}: {e.get('path') or e.get('setting')}{tag}")


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
        if a[1].upper().startswith("S") and not IS_ROOT:
            print(f"System change. Run: sudo \"{ROOT_TOOL}\" undo {a[1][1:]}")
        else:
            undo(a[1].lstrip("Ss"))
    elif c == "undo-settings":
        undo_settings()
    elif c == "scan":
        sys.exit(1 if full_scan() else 0)
    elif c == "verify":
        sys.exit(0 if verify() else 1)
    elif c == "fix-chrome-notify":
        fix_chrome_notify()
    else:
        status()


# Import levplus for new commands
try:
    import levplus as LP
except Exception:
    LP = None

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
        if a[1].upper().startswith("S") and not IS_ROOT:
            print(f"System change. Run: sudo \"{ROOT_TOOL}\" undo {a[1][1:]}")
        else:
            undo(a[1].lstrip("Ss"))
    elif c == "undo-settings":
        undo_settings()
    elif c == "scan":
        sys.exit(1 if full_scan() else 0)
    elif c == "verify":
        sys.exit(0 if verify() else 1)
    elif c == "fix-chrome-notify":
        fix_chrome_notify()
    # ---- Leviathan 2.0 commands ----
    elif c == "level":
        if len(a) == 1:
            lvl = LP.get_level() if LP else 2
            print(f"Current level: {lvl}")
            print("Levels:")
            print("  1 Basic: 1.0 behaviour")
            print("  2 Standard (default): + crypto clipboard guard, recovery-phrase guard, fake password box guard")
            print("  3 Careful: + instant startup-item alert, wallet app signature check daily")
            print("  4 Strict: + new unsigned/ad-hoc apps from internet open in sandbox; Tor checks")
            print("  5 Lockdown: + new unsigned apps contained until approval; outbound internet alert for new apps (lsof sample every 60s)")
            print("Costs: more prompts, some apps break, sandboxed apps cannot see your files")
        elif a[1] == "--json":
            lvl = LP.get_level() if LP else 2
            print(json.dumps({"level": lvl}))
        else:
            try:
                n = int(a[1])
                LP.set_level(n) if LP else None
                print(f"Level set to {n}")
            except Exception:
                print("Usage: leviathan level [1-5]")
    elif c == "mode":
        if len(a) == 1:
            modes = LP.get_modes() if LP else {"crypto": False, "apps": False, "tor": False, "agents": False}
            for k, v in modes.items():
                print(f"  {k}: {'on' if v else 'off'}")
        elif a[1] == "--json":
            modes = LP.get_modes() if LP else {"crypto": False, "apps": False, "tor": False, "agents": False}
            print(json.dumps(modes))
        elif len(a) >= 3:
            name, val = a[1], a[2]
            if name in ("crypto", "apps", "tor", "agents") and val in ("on", "off"):
                LP.set_mode(name, val == "on") if LP else None
                print(f"Mode {name} = {val}")
            else:
                print("Usage: leviathan mode <crypto|apps|tor|agents> <on|off>")
        else:
            print("Usage: leviathan mode [crypto|apps|tor|agents] [on|off]")
    elif c == "clip":
        if not LP:
            print("levplus not available")
        else:
            data = sys.stdin.read()
            old = os.environ.get("LEVIATHAN_CLIP_OLD", "")
            warn = LP.clip_check(old, data.strip())
            if warn:
                print(warn)
                LP.ledger_add("clip-warning", detail=warn)
            if LP.seed_phrase(data):
                warn2 = "Clipboard contains a possible recovery phrase (seed phrase)."
                print(warn2)
                LP.ledger_add("clip-warning", detail=warn2)
    elif c == "cost":
        if LP:
            print(LP.cost())
        else:
            print("levplus not available")
    elif c == "note-event" and len(a) >= 3:
        if LP:
            print(LP.note_event(a[1], " ".join(a[2:])))
        else:
            print("levplus not available")
    elif c == "sandbox" and len(a) > 1:
        if not LP:
            print("levplus not available")
        else:
            app = a[1]
            net = "--net" in a
            # Find the main executable
            if app.endswith(".app") and os.path.isdir(app):
                exe = os.path.join(app, "Contents/MacOS")
                # find the actual binary
                try:
                    for f in os.listdir(exe):
                        p = os.path.join(exe, f)
                        if os.path.isfile(p) and os.access(p, os.X_OK):
                            exe = p
                            break
                except Exception:
                    pass
            else:
                exe = app
            container = os.path.basename(app).replace(".app", "").replace(" ", "_")
            home = os.path.expanduser("~")
            profile = LP.sandbox_profile(home, container, net)
            profile_path = os.path.join(home, "Library/Application Support/Leviathan/sandbox", container, "profile.sb")
            os.makedirs(os.path.dirname(profile_path), exist_ok=True)
            with open(profile_path, "w") as f:
                f.write(profile)
            os.makedirs(os.path.join(home, "Library/Application Support/Leviathan/sandbox", container), exist_ok=True)
            subprocess.Popen(["sandbox-exec", "-f", profile_path, exe])
    elif c == "pkg" and len(a) > 1:
        if LP:
            print(LP.pkg_inspect(a[1]))
        else:
            print("levplus not available")
    elif c == "snapshot":
        if LP:
            print(LP.snapshot())
        else:
            print("levplus not available")
    elif c == "diff":
        if LP:
            do_undo = "--undo" in a
            print(LP.diff(undo=do_undo))
        else:
            print("levplus not available")
    elif c == "agents":
        if not LP:
            print("levplus not available")
        elif len(a) > 1 and a[1] in ("pause", "resume"):
            print(LP.agents_pause() if a[1] == "pause" else LP.agents_resume())
        elif len(a) > 1 and a[1] == "canary":
            if len(a) > 2 and a[2] == "on":
                print(LP.agents_canary_on())
            else:
                print(LP.agents_check())
        elif len(a) > 1 and a[1] == "config":
            print(LP.agents_config_audit())
        elif len(a) > 1 and a[1] == "tripped":
            print(LP.agents_tripped())
        elif len(a) > 1 and a[1] == "level":
            if len(a) == 2:
                lvl = LP.get_agent_level()
                print(f"Current agent level: {lvl}")
                print("Levels:")
                for k, v in LP.agent_level_costs().items():
                    print(f"  {k}: {v}")
            elif a[2] in ("1", "2", "3"):
                LP.set_agent_level(int(a[2]))
                print(f"Agent level set to {a[2]}")
            else:
                print("Usage: leviathan agents level [1|2|3]")
        elif len(a) > 1 and a[1] == "run":
            if len(a) > 2:
                print(LP.agents_run(a[2:]))
            else:
                print("Usage: leviathan agents run <command> [args...]")
        elif len(a) > 1 and a[1] == "export":
            if "--jsonl" in a:
                print(LP.agents_export_jsonl())
            else:
                print("Usage: leviathan agents export --jsonl")
        elif len(a) > 1 and a[1] == "monitor":
            # Run level 2 monitoring checks
            LP._agent_monitor_sensitive_access()
            LP._agent_monitor_new_connections()
            LP._agent_monitor_startup_edits()
            print("Monitoring checks done.")
        else:
            procs = LP.agent_procs() if LP else []
            for pid, name in procs:
                print(f"  {pid}  {name}")
            if not procs:
                print("No AI agent processes found.")
    elif c == "ai":
        if not LP:
            print("levplus not available")
        elif len(a) > 1 and a[1] == "safety":
            print(LP.ai_safety_check())
        elif len(a) > 1 and a[1] == "tuneup":
            fix = "--fix" in a
            print(LP.ai_tuneup(fix=fix))
        else:
            print("Usage: leviathan ai <safety|tuneup [--fix]>")
    elif c == "tor":
        print(LP.tor_check() if LP else "levplus not available")
    elif c == "wallets":
        r = LP.wallet_apps() if LP else "levplus not available"
        print("\n".join(map(str, r)) if isinstance(r, list) else r)
    elif c == "vpn":
        if not LP:
            print("levplus not available")
        elif len(a) > 1 and a[1] in ("status", "on", "off"):
            if a[1] == "status":
                print(LP.vpn_status())
            elif a[1] == "on":
                print(LP.vpn_on())
            elif a[1] == "off":
                print(LP.vpn_off())
        else:
            print("Usage: leviathan vpn <status|on|off>")
    else:
        status()

if __name__ == "__main__":
    main()
