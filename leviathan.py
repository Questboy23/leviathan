#!/usr/bin/env python3
"""Leviathan 4.0: stops viruses before they run on a Mac. Every action is logged and undoable.
Commands: scan | scan-downloads | scan-apps | scan-persist | check-cmd CMD | check PATH [--contain] | pkg FILE.pkg |
          contain PATH | undo ID | status | verify | purge"""
import datetime, hashlib, json, os, plistlib, re, shlex, shutil, subprocess, sys, time

os.umask(0o077)  # the log and quarantine are readable by you only
HOME = os.path.expanduser("~")
IS_ROOT = os.geteuid() == 0
ROOT_DIR = "/var/db/leviathan"
ROOT_TOOL = "/Library/Application Support/Leviathan/leviathan-root"
# root keeps its own log in a root-owned folder, so nothing you can edit is ever run as root
STATE = ROOT_DIR if IS_ROOT else os.environ.get("LEVIATHAN_STATE", os.path.join(HOME, ".leviathan"))
QUAR = os.path.join(STATE, "quarantine")  # versions before 3.0.1 kept caught files here; purge() still empties it
TRASH = os.environ.get("LEVIATHAN_TRASH", os.path.join(HOME, ".Trash"))
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
    """Moves a certain threat to the Trash with its run permission removed, so double-clicking it there does nothing."""
    os.makedirs(TRASH, exist_ok=True)
    base = os.path.basename(path.rstrip("/"))
    dst = os.path.join(TRASH, base)
    if os.path.lexists(dst):  # the Trash keeps both, like Finder does
        stem, ext = os.path.splitext(base)
        dst = os.path.join(TRASH, f"{stem} (virus {time.strftime('%H.%M.%S')}){ext}")
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
    notify(f"Moved a virus to the Trash: {os.path.basename(path)}. It can't run there. Undo: leviathan undo {i}")
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
            print(f"Entry {i} can't be undone: it is no longer in the Trash (or was deleted after {KEEP_DAYS} days in the old quarantine).")
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


# ---------- paste guard ----------
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
    elif c == "undo-all":  # uninstall: every setting change
        es = _entries()
        done = {e.get("ref") for e in es if e["kind"] == "undone"}
        for e in reversed(es):
            if e["kind"] in ("setting", "safeboxed") and e["id"] not in done:
                undo(e["id"])
    elif c == "refresh":  # weekly: new scam-site list, old quarantine emptied
        refresh_blocklist(); purge()
    elif c == "purge":
        print(f"Deleted {purge()} quarantined item(s) older than {KEEP_DAYS} days.")
    elif c == "undo" and len(a) > 1:
        if a[1].upper().startswith("S") and not IS_ROOT:
            print(f"System change. Run: sudo \"{ROOT_TOOL}\" undo {a[1][1:]}")
        else:
            undo(a[1].lstrip("Ss"))
    elif c == "scan":
        sys.exit(1 if full_scan() else 0)
    elif c == "verify":
        sys.exit(0 if verify() else 1)
    elif c == "status":
        status()
    elif c == "pkg" and len(a) > 1:
        import levplus
        print(levplus.pkg_inspect(a[1]))
    else:
        sys.exit("leviathan: unknown command or missing argument: %s\nCommands: see the README" % " ".join(a))

if __name__ == "__main__":
    main()
