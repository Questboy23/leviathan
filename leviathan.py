#!/usr/bin/env python3
"""Leviathan: stops viruses before they run on a Mac, keeps AI agents in check, and turns on a VPN on
networks you don't trust. Every action is logged and undoable.
Commands: scan | scan-downloads | scan-apps | scan-persist | check-cmd CMD | pwwatch | undo ID | status | verify |
          contain PATH | check PATH [--contain] | purge | safebox open|wrap APP | safebox list |
          vpn [on|off|auto|check|trust|untrust]"""
import datetime, hashlib, json, os, plistlib, re, shlex, shutil, subprocess, sys, time

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
        os.chmod(LEDGER, 0o644)  # root ledger in /var/db/leviathan
    else:
        os.chmod(LEDGER, 0o600)  # user ledger in ~/.leviathan - private
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


def notify(msg, urgent=False):
    """Notification banner. urgent also opens an alert window, which Focus and Do Not Disturb
    do not hide; it closes itself after 10 minutes and does not block the caller."""
    if QUIET:
        print("URGENT:" if urgent else "NOTIFY:", msg)
        return
    safe = msg.replace("\\", "").replace('"', "'")
    run(["osascript", "-e", f'display notification "{safe}" with title "Leviathan"'])
    if urgent:
        subprocess.Popen(["osascript", "-e", f'display alert "Leviathan" message "{safe}" as critical giving up after 600'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


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
    code2, sp = run(args, timeout=30)
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
    notify(f"Removed a threat: {os.path.basename(path)}. It can't run. Deleted for good in {KEEP_DAYS} days. Undo: leviathan undo {i}")
    start_pwwatch()
    return i


KEEP_DAYS = 7


def purge(days=KEEP_DAYS, now=None):
    """Deletes quarantined items for good once they are older than `days` (the date is in the name contain() gives)."""
    if not os.path.isdir(QUAR):
        return 0
    cut, n = (now or time.time()) - days * 86400, 0
    for name in os.listdir(QUAR):
        try:
            t = time.mktime(time.strptime(name[:15], "%Y%m%d-%H%M%S"))
        except ValueError:
            continue  # not made by contain(): leave it
        if t > cut:
            continue
        p = os.path.join(QUAR, name)
        try:
            shutil.rmtree(p) if os.path.isdir(p) and not os.path.islink(p) else os.remove(p)
        except OSError:
            continue
        ledger_add("deleted", path=p, reason=f"kept in quarantine {days} days, not undone")
        n += 1
    return n


def check_file(path):
    """Plain-words answer to 'is this likely a virus?'. Returns the verdict level."""
    if not os.path.exists(path):
        print(f"No such file: {path}")
        return "missing"
    level, why = verdict(path)
    if level == "bad":
        print(f"Likely malware: {why}.\nRemove it: leviathan contain {shlex.quote(path)} (undoable for {KEEP_DAYS} days, then deleted).")
    elif level == "unverified":
        print(f"Unknown: {why}. Many free apps are unsigned, so this alone does not mean a virus.\n"
              "Safer: open it with Leviathan's sandbox (no access to your files or the internet).")
    else:
        print("No known threat found. Checked: Apple's malware rules, the site it came from, and Apple's signature.\n"
              "New malware that none of these know yet can still pass.")
    return level


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
        if not os.path.lexists(u["src"]):
            print(f"Entry {i} can't be undone: it was deleted after {KEEP_DAYS} days in quarantine.")
            return
        if u.get("remove") and os.path.isdir(u["remove"]) and os.path.exists(os.path.join(u["remove"], "Contents/MacOS/leviathan-safebox")):
            shutil.rmtree(u["remove"])  # only our own launcher, recognised by its executable name
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
            if p.endswith(".app") and quarantined(p) and safebox_wrap(p, why):
                known[n] = str(os.stat(p).st_mtime)  # the launcher now at p is ours
            else:
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
                    notify(f"Found a threat that needs your password to remove: {n}. Drag it to the Trash and type your password when asked.")
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
    (r"(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(python\d*|perl|ruby|osascript|node)\s*(-\s*)?($|[;&|])", "downloads code from the internet and runs it immediately"),
    (r"(eval|(ba|z)?sh\s+-c)\s*[\"']?\$\(\s*(curl|wget)", "runs code downloaded from the internet"),
    (r"base64\s+(-d|-D|--decode)[^;&]*\|\s*(sudo\s+)?(\S*/)?((ba|z|da|k)?sh|python\d*|perl|ruby|osascript|node)\b|(eval|(ba|z)?sh\s+-c)\s*[\"']?\$\(.*base64\s+(-d|-D|--decode)", "unscrambles hidden code and runs it, so you can't read what it does"),
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
    for i, (pat, why) in enumerate(RULES):
        if re.search(pat, low):
            if i < 3 and urls and all(_trusted(u) for u in urls):  # a known installer's own download-and-run line; never excuses the other rules
                continue
            return f"It {why}. Fake 'fix' and 'verify you're human' pages ask people to paste commands like this."
    return ""


# ---------- settings sweep ----------




def refresh_blocklist():
    """Weekly copy of the scam and malware site list that downloads and pasted commands are checked against."""
    p = os.path.join(STATE, "blocklist.txt")
    if os.path.exists(p) and time.time() - os.path.getmtime(p) < 6 * 86400:
        return
    tmp = p + ".new"
    code, _ = run(["curl", "-fsSL", "--max-time", "90", "-o", tmp,
                   "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt"], timeout=100)
    if code == 0 and os.path.getsize(tmp) > 100000:
        os.replace(tmp, p)
    elif os.path.exists(tmp):
        os.remove(tmp)



def website_filter_on():
    """True when this Mac's DNS is Quad9 (the filter profile), None when offline.
    Quad9 answers on.quad9.net with 216.21.3.77; every other resolver gets a different address."""
    import socket
    try:
        return socket.gethostbyname("on.quad9.net") == QUAD9_ON_IP
    except OSError:
        try:
            socket.gethostbyname("apple.com")
            return False
        except OSError:
            return None


QUAD9_ON_IP = "216.21.3.77"

def website_filter_report():
    on = website_filter_on()
    if on:
        return ("ok", "Website filter on (known malware and scam sites are blocked)")
    if on is None:
        return ("ok", "Website filter not checked (no internet)")
    return ("issue", "Website filter is OFF. Turn it on: click the shield, then 'Turn on website filter', then Install in System Settings")




# ---------- Chrome: notification spam + hijacked search ----------










# ---------- full scan (read-only) ----------


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
    print(f"Leviathan scan: {len(apps)} apps, Downloads, auto-start items, website filter. Changes nothing.\n")
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
    lvl, msg = website_filter_report()
    if lvl == "issue":
        issues.append(msg)
    print("\nThreats (things no one wants on their computer):")
    for t in threats or ["none found"]:
        print("  " + t)
    print("\nTo fix:")
    for t in issues or ["none found"]:
        print("  " + t)
    if threats:
        print("\nRemove a threat so it can't run (undoable): leviathan contain PATH")
    return len(threats)




# ---------- status + main ----------
AI_ALERT_KINDS = ("canary-trigger", "agent-tripped", "agent-secret-access")

def status():
    es = _entries()
    undone = {e.get("ref") for e in es if e["kind"] == "undone"}
    shown = [e for e in es if e["kind"] in ("contained", "safeboxed", "setting", "blocked", "flagged") + AI_ALERT_KINDS]
    if not shown and not os.path.exists(os.path.join(ROOT_DIR, "ledger.jsonl")):
        print("Nothing has needed action yet.")
    for e in shown[-30:]:
        tag = " (undone)" if e["id"] in undone else (f"   undo: leviathan undo {e['id']}" if "undo" in e else "")
        if e["kind"] in AI_ALERT_KINDS:
            what = "; ".join(e["details"]) if isinstance(e.get("details"), list) else " ".join(
                str(e[k]) for k in ("agent", "pid", "host", "path", "reason") if e.get(k))
            print(f"#{e['id']} {e['time'][:16]} AI alert, {e['kind']}: {what[:300]}")
            continue
        print(f"#{e['id']} {e['time'][:16]} {e['kind']}: {e.get('path') or e.get('setting') or e.get('what')} {('- ' + e['reason']) if e.get('reason') else ''}{tag}")
    if not IS_ROOT:
        rs = _entries(os.path.join(ROOT_DIR, "ledger.jsonl"))
        rdone = {e.get("ref") for e in rs if e["kind"] == "undone"}
        for e in [e for e in rs if e["kind"] in ("contained", "setting", "flagged")][-30:]:
            tag = " (undone)" if e["id"] in rdone else (f"   undo: leviathan undo S{e['id']}" if "undo" in e else "")
            print(f"#S{e['id']} {e['time'][:16]} system {e['kind']}: {e.get('path') or e.get('setting')}{tag}")




# ---------- Safe Box: apps Apple never checked run with no access to your files ----------
SAFEBOX = os.path.join(STATE, "safebox")
# Folders a Safe Box app can never open, even inside its own box rules (last matching rule wins).
SECRET_DIRS = (".ssh", ".aws", ".gnupg", ".config/gh", "Library/Keychains", "Library/Cookies", "Library/Safari",
               "Library/Mail", "Library/Messages",
               "Library/Application Support/Google/Chrome", "Library/Application Support/Firefox",
               "Library/Application Support/BraveSoftware", "Library/Application Support/Arc",
               "Library/Application Support/Ledger Live", "Library/Application Support/Exodus",
               "Library/Application Support/Electrum", "Library/Application Support/@trezor",
               "Library/Application Support/Sparrow", "Library/Application Support/Bitcoin")


LAUNCHER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "safebox", "leviathan-safebox")


def quarantined(path):
    """True when macOS marked the file as downloaded from the internet (apps you built yourself have no mark)."""
    return run(["xattr", "-p", "com.apple.quarantine", path])[0] == 0


def _sb(path):
    return json.dumps(path)  # a sandbox-profile string literal uses the same quoting as JSON


def safebox_profile(home, box, app):
    """Pure function: sandbox-exec profile text. macOS stays readable so the app starts; your home folder is
    closed except the app's own box; secret folders, password prompts and the keychain tool are blocked.
    In sandbox profiles the LAST matching rule wins, so the denies come first and the allows after."""
    home = os.path.realpath(home)  # sandbox rules match real paths, not symlinks
    lines = ["(version 1)", "(allow default)",
             f"(deny file-read* file-write* (subpath {_sb(home)}))",
             "(deny file-write* (subpath \"/Library\") (subpath \"/Applications\") (subpath \"/usr/local\") (subpath \"/opt\"))",
             f"(allow file-read* file-write* (subpath {_sb(os.path.realpath(box))}))",
             f"(allow file-read* (subpath {_sb(os.path.realpath(app))}))"]
    lines += [f"(deny file-read* file-write* (subpath {_sb(os.path.join(home, d))}))" for d in SECRET_DIRS]
    lines += ['(deny process-exec (literal "/usr/bin/osascript") (literal "/usr/bin/security") (literal "/usr/bin/sudo")'
              ' (literal "/bin/launchctl") (literal "/usr/bin/xattr") (literal "/usr/sbin/spctl"))']
    return "\n".join(lines) + "\n"


def _box_for(app):
    name = os.path.basename(app.rstrip("/"))
    name = name[:-4] if name.endswith(".app") else name
    return os.path.join(SAFEBOX, re.sub(r"[^A-Za-z0-9_-]", "_", name).strip("_") or "app")  # no dots: ".." never reaches the path


def safebox_wrap(path, why):
    """Moves a downloaded app Apple never checked into its Safe Box and puts a launcher with the same name where it
    was, so it opens from the Dock, Finder and Launchpad as before but can't see your files. Undo restores it."""
    if not path.endswith(".app") or not os.path.isdir(path):
        return False
    box = _box_for(path)
    real = os.path.join(box, "app", os.path.basename(path))
    if os.path.lexists(real):
        return False
    try:
        info = plistlib.load(open(os.path.join(path, "Contents/Info.plist"), "rb"))
        os.makedirs(os.path.dirname(real), exist_ok=True)
        shutil.move(path, real)
    except Exception:
        return False
    try:
        os.makedirs(os.path.join(path, "Contents/MacOS"))
        os.makedirs(os.path.join(path, "Contents/Resources"))
        icon = info.get("CFBundleIconFile", "")
        icon = icon if icon.endswith(".icns") or not icon else icon + ".icns"
        if icon and os.path.exists(os.path.join(real, "Contents/Resources", icon)):
            shutil.copy2(os.path.join(real, "Contents/Resources", icon), os.path.join(path, "Contents/Resources", icon))
        name = info.get("CFBundleName") or os.path.basename(path)[:-4]
        with open(os.path.join(path, "Contents/Info.plist"), "wb") as f:
            plistlib.dump({"CFBundleExecutable": "leviathan-safebox", "CFBundleIdentifier": "com.leviathan.safebox." + os.path.basename(box),
                           "CFBundleName": name, "CFBundlePackageType": "APPL", "CFBundleIconFile": icon,
                           "CFBundleShortVersionString": info.get("CFBundleShortVersionString", "1")}, f)
        # A small compiled launcher (safebox/launcher.c): Finder and the Dock refuse to open a bundle whose program is a script.
        shutil.copy2(LAUNCHER, os.path.join(path, "Contents/MacOS/leviathan-safebox"))
        with open(os.path.join(path, "Contents/Resources/run.sh"), "w") as f:
            f.write("exec %s %s safebox open --exec %s\n" % (shlex.quote(sys.executable), shlex.quote(os.path.abspath(__file__)), shlex.quote(real)))
        run(["codesign", "--force", "--sign", "-", path], timeout=30)
    except Exception:
        shutil.rmtree(path, ignore_errors=True)
        shutil.move(real, path)
        return False
    i = ledger_add("safeboxed", path=path, reason=why, undo={"type": "move", "src": real, "dst": path, "remove": path})
    notify(f"{os.path.basename(path)[:-4]} will open in a Safe Box: it can't see your files or passwords. Undo: leviathan undo {i}")
    return True


def safebox_open(app, exec_=False):
    try:  # the bundle names its own executable; the first file in MacOS/ may be a helper
        with open(os.path.join(app, "Contents/Info.plist"), "rb") as f:
            exe = os.path.join(app, "Contents/MacOS", plistlib.load(f)["CFBundleExecutable"])
    except Exception:
        sys.exit("Not a normal app: no executable named in Info.plist")
    if not (os.path.isfile(exe) and os.access(exe, os.X_OK)):
        sys.exit("Cannot run: " + exe)
    if "com.apple.security.app-sandbox" in run(["codesign", "-d", "--entitlements", "-", app])[1]:
        os.execv("/usr/bin/open", ["open", "-a", app])  # Apple's own sandbox already applies; macOS kills an app sandboxed twice
    box = _box_for(app)
    fake_home = os.path.join(box, "home")
    os.makedirs(fake_home, exist_ok=True)
    profile = os.path.join(box, "profile.sb")
    with open(profile, "w") as f:
        f.write(safebox_profile(HOME, box, app))
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "LANG", "TERM", "TMPDIR", "USER", "LOGNAME", "SHELL")}
    env.update(HOME=fake_home, CFFIXED_USER_HOME=fake_home)  # the app's settings and saves go to its box
    argv = ["/usr/bin/sandbox-exec", "-f", profile, exe]
    if exec_:
        os.execve(argv[0], argv, env)
    log = os.path.join(box, "safebox.log")  # a file, not a pipe: a long-running app must never block on output
    with open(log, "w") as lf:
        p = subprocess.Popen(argv, env=env, stdout=lf, stderr=lf, start_new_session=True)
    try:
        p.wait(timeout=2)
        sys.exit("Safe Box could not start it: " + (open(log, errors="replace").read().strip()[-400:] or "exit code %d" % p.returncode))
    except subprocess.TimeoutExpired:
        print(f"Started {os.path.basename(app)} in a Safe Box. It can't see your files. Its own folder: {fake_home}")


# ---------- VPN: Cloudflare WARP (free), on automatically on networks you haven't trusted ----------
VPN_FILE = os.path.join(STATE, "vpn.json")
WARP = next((p for p in ("/usr/local/bin/warp-cli", "/opt/homebrew/bin/warp-cli") if os.path.exists(p)), shutil.which("warp-cli"))


def vpn_state():
    try:
        st = json.load(open(VPN_FILE))
    except Exception:
        st = {}
    st.setdefault("mode", "auto")
    st.setdefault("trusted", [])
    return st


def _vpn_save(st):
    os.makedirs(STATE, exist_ok=True)
    with open(VPN_FILE, "w") as f:
        json.dump(st, f)


def network_id():
    """The router's hardware address, which stays the same while the VPN is up (the network name needs Location access)."""
    for dev in ("en0", "en1", "en2", "en3"):
        router = run(["ipconfig", "getoption", dev, "router"], timeout=5)[1].strip()
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", router):
            m = re.search(r" at ([0-9a-f:]{11,17}) ", run(["arp", "-n", router], timeout=5)[1])
            if m:
                return m.group(1)
    return None


def _warp(*args):
    return run([WARP, "--accept-tos"] + list(args), timeout=30)


def vpn_connected():
    return bool(WARP) and "Connected" in _warp("status")[1]


def _vpn_up():
    if _warp("registration", "show")[0] != 0:
        _warp("registration", "new")
    _warp("dns", "families", "off")  # Cloudflare's malware filter blocks legal adult sites; the Quad9 website filter covers malware
    _warp("connect")


def vpn_check():
    """Run by com.leviathan.vpnwatch whenever the network changes."""
    st = vpn_state()
    if not WARP:
        return "VPN needs Cloudflare WARP (free). Install: brew install --cask cloudflare-warp"
    if st["mode"] == "off":
        return "VPN is off."
    net = network_id()
    want = st["mode"] == "on" or net not in st["trusted"]
    if want and not vpn_connected():
        _vpn_up()
        ledger_add("vpn", what="VPN on", reason="untrusted network" if st["mode"] == "auto" else "always on")
    elif not want and vpn_connected():
        _warp("disconnect")
        ledger_add("vpn", what="VPN off", reason="trusted network")
    return vpn_status()


def vpn_set(mode):
    st = vpn_state()
    st["mode"] = mode
    _vpn_save(st)
    if mode == "off" and WARP:
        _warp("disconnect")
    return vpn_check()


def vpn_trust(on):
    st, net = vpn_state(), network_id()
    if not net:
        return "Not connected to a network."
    st["trusted"] = [t for t in st["trusted"] if t != net] + ([net] if on else [])
    _vpn_save(st)
    return vpn_check()


def vpn_status():
    st = vpn_state()
    if not WARP:
        return "VPN: not installed. Install Cloudflare WARP (free): brew install --cask cloudflare-warp"
    trace = run(["curl", "-s", "--max-time", "5", "https://www.cloudflare.com/cdn-cgi/trace"], timeout=8)[1]
    m = re.search(r"^warp=(\w+)", trace, re.M)
    real = {"on": "on", "plus": "on", "off": "off"}.get(m.group(1) if m else "", "unknown (offline)")
    here = "trusted" if network_id() in st["trusted"] else "not trusted"
    return f"VPN: {real}. Mode: {st['mode']}. This network: {here}."


# levplus holds the AI agent watch and the installer check
try:
    import levplus as LP
except Exception:
    LP = None

def main():
    a = sys.argv[1:] or ["status"]
    c = a[0]
    if c == "scan-downloads":
        scan_dir(DOWNLOADS, "downloads"); purge()
    elif c == "scan-apps":
        scan_dir("/Applications", "apps", only_apps=True)
    elif c == "scan-persist":
        scan_persist()
    elif c == "scan-all":
        scan_dir(DOWNLOADS, "downloads"); scan_dir("/Applications", "apps", only_apps=True); scan_persist(); purge()
    elif c == "check-cmd":
        msg = check_cmd(" ".join(a[1:]))
        if msg:
            print(msg)
            ledger_add("paste-stopped", detail=" ".join(a[1:])[:300], reason=msg)
            start_pwwatch()
    elif c == "contain" and len(a) > 1:
        if not os.path.lexists(a[1]):
            sys.exit("No such file: " + a[1])
        contain(os.path.abspath(a[1]), "removed by you")
    elif c == "check" and [x for x in a[1:] if x != "--contain"]:
        target = os.path.abspath([x for x in a[1:] if x != "--contain"][0])
        lvl = check_file(target)
        if lvl == "bad" and "--contain" in a:
            contain(target, "removed by you after check")
        sys.exit(1 if lvl in ("bad", "missing") else 0)
    elif c == "undo-all":  # uninstall: every setting change, and every app back out of the Safe Box
        es = _entries()
        done = {e.get("ref") for e in es if e["kind"] == "undone"}
        for e in reversed(es):
            if e["kind"] in ("setting", "safeboxed") and e["id"] not in done:
                undo(e["id"])
    elif c == "refresh":  # weekly: new scam-site list, old quarantine emptied
        refresh_blocklist(); purge()
    elif c == "purge":
        print(f"Deleted {purge()} quarantined item(s) older than {KEEP_DAYS} days.")
    elif c == "pwwatch":
        pwwatch()
    elif c == "undo" and len(a) > 1:
        if a[1].upper().startswith("S") and not IS_ROOT:
            print(f"System change. Run: sudo \"{ROOT_TOOL}\" undo {a[1][1:]}")
        else:
            undo(a[1].lstrip("Ss"))
    elif c == "scan":
        sys.exit(1 if full_scan() else 0)
    elif c == "verify":
        sys.exit(0 if verify() else 1)
    elif c == "safebox" and a[1:2] == ["list"]:
        boxed = sorted(os.listdir(SAFEBOX)) if os.path.isdir(SAFEBOX) else []
        print("\n".join(boxed) or "No apps in the Safe Box.")
    elif c == "safebox" and len(a) > 2 and a[1] in ("open", "wrap"):
        app = os.path.abspath(a[-1])
        if a[1] == "wrap":
            sys.exit(0 if safebox_wrap(app, "put in the Safe Box by you") else 1)
        safebox_open(app, exec_=("--exec" in a))
    elif c == "vpn":
        sub = a[1] if len(a) > 1 else "status"
        fn = {"on": lambda: vpn_set("on"), "off": lambda: vpn_set("off"), "auto": lambda: vpn_set("auto"),
              "check": vpn_check, "trust": lambda: vpn_trust(True), "untrust": lambda: vpn_trust(False),
              "status": vpn_status, "--json": lambda: json.dumps(vpn_state())}.get(sub)
        if not fn:
            sys.exit("Usage: leviathan vpn [on|off|auto|check|trust|untrust|status]")
        print(fn())
    elif c == "status":
        status()
    elif not LP:
        sys.exit("leviathan: levplus.py is missing; reinstall Leviathan")
    elif c == "mode":
        if len(a) >= 3 and a[1] == "agents" and a[2] in ("on", "off"):
            LP.set_mode("agents", a[2] == "on")
            print(f"AI agents watch: {a[2]}")
        elif len(a) == 2 and a[1] == "--json":
            print(json.dumps(LP.get_modes()))
        elif len(a) == 1:
            print(f"  agents: {'on' if LP.get_modes()['agents'] else 'off'}")
        else:
            sys.exit("Usage: leviathan mode agents on|off")
    elif c == "note-event" and len(a) >= 3:
        print(LP.note_event(a[1], " ".join(a[2:])))
    elif c == "pkg" and len(a) > 1:
        print(LP.pkg_inspect(a[1]))
    elif c == "agents":
        sub = a[1] if len(a) > 1 else ""
        if sub in ("pause", "resume"):
            print(LP.agents_pause() if sub == "pause" else LP.agents_resume())
        elif sub == "canary":
            print(LP.agents_canary_on() if a[2:3] == ["on"] else LP.agents_check())
        elif sub == "config":
            print(LP.agents_config_audit())
        elif sub == "monitor":
            print(LP.agents_monitor())
        elif sub == "tripped":
            print(LP.agents_tripped())
        elif sub == "report":
            print(LP.agents_report("--jsonl" in a))
        elif sub == "run":
            sys.exit(LP.agents_run(a[a.index("--") + 1:] if "--" in a else a[2:]))
        elif sub == "":
            procs = LP.agent_procs()
            for pid, name in procs:
                print(f"  {pid}  {name}")
            if not procs:
                print("No AI agent processes found.")
        else:
            sys.exit("Usage: leviathan agents [pause|resume|canary [on]|config|monitor|tripped|report [--jsonl]|run -- CMD]")
    elif c == "ai" and a[1:2] == ["safety"]:
        print(LP.ai_safety_check())
    else:
        sys.exit("leviathan: unknown command or missing argument: %s\nCommands: see the README" % " ".join(a))

if __name__ == "__main__":
    main()
