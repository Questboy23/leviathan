#!/usr/bin/env python3
"""Leviathan extras: AI agent watch (list, pause, decoy files, config and MCP audit) and the installer check."""
import datetime, hashlib, json, os, re, shutil, signal, sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
import leviathan as L

# ---------- settings: the only switch left is the AI agents watch ----------
def settings_path():
    return os.path.join(L.STATE, "settings.json")

def load_settings():
    try:
        with open(settings_path()) as f:
            return json.load(f)
    except Exception:
        return {}

def save_settings(s):
    os.makedirs(L.STATE, exist_ok=True)
    with open(settings_path(), "w") as f:
        json.dump(s, f)

def get_modes():
    return {"agents": bool(load_settings().get("modes", {}).get("agents"))}

def set_mode(name, on):
    if name != "agents":
        raise ValueError("only the agents mode exists")
    s = load_settings()
    s["modes"] = {"agents": bool(on)}
    save_settings(s)
    L.ledger_add("setting", setting=f"mode agents: {'on' if on else 'off'}")
    return s["modes"]

# ---------- AI agents ----------
CANARY_DIR = os.environ.get("LEVIATHAN_CANARY_DIR") or os.path.join(L.HOME, ".leviathan-canary")

def _read(path):
    try:
        with open(path, errors="ignore") as f:
            return f.read()
    except Exception:
        return ""

def claude_bypass(settings):
    """Why this Claude Code settings dict skips permission prompts, or "" if it does not.
    Current key is permissions.defaultMode; the top-level keys are from older versions."""
    if not isinstance(settings, dict):
        return ""
    perms = settings.get("permissions")
    if isinstance(perms, dict) and perms.get("defaultMode") == "bypassPermissions":
        return "permissions.defaultMode is bypassPermissions"
    for k in ("bypassPermissions", "dangerously-skip-permissions", "dangerouslySkipPermissions"):
        if settings.get(k) is True:
            return f"{k} is on"
    return ""

def _claude_bypass_files():
    """(path, reason) for each Claude Code settings file on this Mac that skips permission prompts."""
    out = []
    for rel in (".claude/settings.json", ".claude/settings.local.json"):
        p = os.path.join(L.HOME, rel)
        try:
            why = claude_bypass(json.loads(_read(p) or "{}"))
        except Exception:
            why = ""
        if why:
            out.append((p, why))
    return out

def codex_full_access(toml_text):
    """Why this Codex config.toml lets Codex run commands unasked, or ""."""
    m = re.search(r'^\s*approval_policy\s*=\s*"never"', toml_text, re.M)
    n = re.search(r'^\s*sandbox_mode\s*=\s*"danger-full-access"', toml_text, re.M)
    return " and ".join(x for x in (m and 'approval_policy = "never"', n and 'sandbox_mode = "danger-full-access"') if x)

def claude_mcp_servers(home=None):
    """{label: config} for every Claude Code MCP server: ~/.claude/settings.json, ~/.claude.json
    (user scope and each project), and ~/.mcp.json."""
    home = home or L.HOME
    out = {}
    def add(label, d):
        if isinstance(d, dict):
            for name, cfg in (d.get("mcpServers") or {}).items():
                if isinstance(cfg, dict):
                    out[f"{label}{name}"] = cfg
    for rel in (".claude/settings.json", ".mcp.json"):
        try:
            add("claude:", json.loads(_read(os.path.join(home, rel)) or "{}"))
        except Exception:
            pass
    try:
        d = json.loads(_read(os.path.join(home, ".claude.json")) or "{}")
        add("claude:", d)
        for proj, pd in (d.get("projects") or {}).items():
            add(f"claude:{os.path.basename(proj.rstrip('/')) or proj}/", pd)
    except Exception:
        pass
    return out

def agents_config_audit():
    """Read-only check for dangerous AI agent configs."""
    warnings = []
    # Claude Code settings
    for path, why in _claude_bypass_files():
        warnings.append(f"Claude Code: {why} in {path}. It runs commands and edits files without asking you.")
    why = codex_full_access(_read(os.path.join(L.HOME, ".codex", "config.toml")))
    if why:
        warnings.append(f"Codex: {why} in ~/.codex/config.toml. It runs commands without asking you.")
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

def mcp_skill_audit():
    """Check for new MCP servers or skills added since last check, flag if they run shell or fetch remote code."""
    warnings = []
    last_check_path = os.path.join(L.STATE, "mcp_last_check.json")
    last_check = {}
    try:
        with open(last_check_path) as f:
            last_check = json.load(f)
    except Exception:
        pass

    # Check Claude Code MCP servers
    current_mcp = claude_mcp_servers()

    first_run = not last_check
    # Check for new or changed MCP servers
    for key, config in ({} if first_run else current_mcp).items():
        if key not in last_check or last_check[key] != config:
            # Flag if it runs shell commands or fetches remote code
            cmd = config.get("command", "")
            args = " ".join(config.get("args", []))
            full = f"{cmd} {args}"
            if any(w in full for w in ["shell", "bash", "sh -c", "curl", "wget", "http", "python -c", "node -e"]):
                warnings.append(f"New/changed MCP server runs shell/remote code: {key} -> {full[:100]}")
            else:
                warnings.append(f"New/changed MCP server: {key}")

    # Check for new skills in ~/.claude/skills
    skills_dir = os.path.join(L.HOME, ".claude", "skills")
    if os.path.exists(skills_dir):
        current_skills = set(os.listdir(skills_dir))
        last_skills = set(last_check.get("skills", []))
        new_skills = current_skills - last_skills
        for skill in (new_skills if last_check else []):
            skill_path = os.path.join(skills_dir, skill)
            flagged = False
            # Check if skill runs shell or fetches remote
            try:
                for root, dirs, files in os.walk(skill_path):
                    if flagged:
                        break
                    for f in files:
                        if f.endswith((".py", ".sh", ".js", ".ts")):
                            fp = os.path.join(root, f)
                            with open(fp, "r", errors="ignore") as fh:
                                content = fh.read()
                            if any(w in content for w in ["subprocess", "os.system", "curl", "wget", "fetch(", "http.client", "urllib"]):
                                warnings.append(f"New skill runs shell/remote code: {skill} ({f})")
                                flagged = True
                                break
            except Exception:
                pass
            if not flagged:
                warnings.append(f"New skill: {skill}")

    # Save current state
    last_check.update(current_mcp)
    last_check["skills"] = list(current_skills) if os.path.exists(skills_dir) else []
    try:
        with open(last_check_path, "w") as f:
            json.dump(last_check, f)
    except Exception:
        pass

    if first_run:
        n_skills = len(last_check.get("skills", []))
        L.ledger_add("mcp-skill-audit", details=[f"starting point: {len(current_mcp)} MCP servers, {n_skills} skills"])
        return "No new/changed MCP servers or skills detected."
    if warnings:
        L.ledger_add("mcp-skill-audit", details=warnings)
    return "\n".join(warnings) if warnings else "No new/changed MCP servers or skills detected."

def parse_ps(text):
    """Pure function: parse ps output, return list of (pid, argv list)."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            pid, cmd = parts
            if pid.isdigit():
                argv = cmd.split()
                # ps does not quote, so a program path with spaces ("Application Support") arrives split
                if argv and argv[0].startswith("/") and not os.access(argv[0], os.X_OK):
                    for i in range(len(argv), 1, -1):
                        cand = " ".join(argv[:i])
                        if os.path.isfile(cand) and os.access(cand, os.X_OK):
                            argv = [cand] + argv[i:]
                            break
                out.append((int(pid), argv))
    return out

def _is_agent_process(argv):
    """Check if argv matches an AI agent.

    Agent criteria:
    - executable basename (argv[0], basename, lowercase) is exactly one of:
      claude, codex, aider, goose, gemini, openhands, cursor-agent
    - OR executable basename is node/python/python3/bun/deno AND
      second argv token basename starts with one of those names
    - Exclude anything with ".app/Contents/" in argv[0]
    """
    if not argv:
        return None

    exe = os.path.basename(argv[0]).lower()

    # Exclude .app/Contents/ paths (e.g., Claude desktop app)
    interpreters = {"node", "python", "python3", "bun", "deno"}
    # Homebrew's Python runs as .../Python.app/Contents/MacOS/Python, so interpreters stay in
    if ".app/contents/" in argv[0].lower() and "/claude-code/" not in argv[0].lower() and exe not in interpreters:
        return None

    # Exact matches for agent executables
    exact_agents = {"claude", "codex", "aider", "goose", "gemini", "openhands", "cursor-agent"}
    if exe in exact_agents:
        return exe

    # Interpreter + agent script
    if exe in interpreters and len(argv) > 1:
        arg1 = os.path.basename(argv[1]).lower()
        for agent in exact_agents:
            if arg1.startswith(agent):
                return f"{exe}-{agent}"

    return None

def _get_ancestor_pids(pid):
    """Walk ppid chain via ps to get all ancestor PIDs."""
    ancestors = set()
    current = pid
    while True:
        code, out = L.run(["ps", "-o", "ppid=", "-p", str(current)], timeout=5)
        if code != 0:
            break
        ppid = out.strip()
        if not ppid or ppid == "0" or ppid == "1":
            break
        ppid = int(ppid)
        if ppid in ancestors:
            break
        ancestors.add(ppid)
        current = ppid
    return ancestors

def agent_procs():
    """Return list of (pid, name) for running AI agents."""
    # Get current process and all ancestors to exclude
    my_pid = os.getpid()
    exclude_pids = {my_pid} | _get_ancestor_pids(my_pid)

    code, out = L.run(["ps", "-axo", "pid=,command="], timeout=15)
    procs = parse_ps(out)
    agents = []
    for pid, argv in procs:
        if pid in exclude_pids:
            continue
        name = _is_agent_process(argv)
        if name:
            agents.append((pid, name))
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

def _notify_once(lines, urgent=False):
    """Send each alert line as a notification the first time it is seen, so a job that
    repeats every few minutes does not repeat the same alert."""
    path = os.path.join(L.STATE, "notified.json")
    try:
        with open(path) as f:
            seen = json.load(f)
    except Exception:
        seen = []
    for line in lines:
        h = hashlib.sha256(line.encode()).hexdigest()[:16]
        if h not in seen:
            seen.append(h)
            L.notify(line, urgent=urgent)
    try:
        with open(path, "w") as f:
            json.dump(seen[-2000:], f)
    except Exception:
        pass

def note_event(kind, detail):
    L.ledger_add(kind, detail=detail)
    return f"Logged: {kind}"

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
            code, out = L.run(["pkgutil", "--expand", pkg_path, tmp], timeout=15)
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


# ---------- decoy files: fake secrets that nothing normal reads ----------
DECOYS = {
    "aws_credentials": "[default]\naws_access_key_id = AKIA{c}\naws_secret_access_key = {c}{c}{c8}\n",
    "wallet_seed.txt": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n",
}

def agents_canary_on():
    """Write the decoy files and remember their last-read times. Spotlight is told not to index the folder,
    so only a program that opens the files on purpose changes the read time."""
    os.makedirs(CANARY_DIR, exist_ok=True)
    Path(CANARY_DIR, ".metadata_never_index").touch()
    code = os.urandom(8).hex().upper()
    atimes = {}
    for name, body in DECOYS.items():
        p = os.path.join(CANARY_DIR, name)
        with open(p, "w") as f:
            f.write(body.format(c=code, c8=code[:8]))
        atimes[name] = os.stat(p).st_atime
    with open(os.path.join(CANARY_DIR, "atimes.json"), "w") as f:
        json.dump(atimes, f)
    L.ledger_add("canary-create", code=code)
    return f"Decoy files written to {CANARY_DIR}."

def agents_check():
    """Report each decoy read once, with the AI agents running at that moment."""
    try:
        with open(os.path.join(CANARY_DIR, "atimes.json")) as f:
            atimes = json.load(f)
    except Exception:
        return "No decoy files yet. Run: leviathan agents canary on"
    results = []
    for name, old in atimes.items():
        try:
            at = os.stat(os.path.join(CANARY_DIR, name)).st_atime
        except OSError:
            continue
        if at > old + 1:
            running = ", ".join(f"{n} (PID {p})" for p, n in agent_procs()) or "none"
            results.append(f"Decoy {name} was read at {datetime.datetime.fromtimestamp(at).isoformat(timespec='seconds')}. AI agents running: {running}")
            atimes[name] = at
    if results:
        with open(os.path.join(CANARY_DIR, "atimes.json"), "w") as f:
            json.dump(atimes, f)
        L.ledger_add("canary-trigger", details=results)
    return "\n".join(results) if results else "No decoy reads."

def ai_safety_check():
    """What the menu's AI Safety item shows: risky agent settings and new MCP servers or skills."""
    parts = [agents_config_audit()]
    mcp = mcp_skill_audit()
    if mcp != "No new/changed MCP servers or skills detected.":
        parts.append(mcp)
    return "\n\n".join(parts)

def agents_monitor():
    """Run every 5 minutes by com.leviathan.agentwatch. A decoy read is the one thing that sends a notification."""
    if not get_modes().get("agents"):
        return "AI agents mode is off, so nothing was checked. Turn it on: leviathan mode agents on"
    if not os.path.exists(os.path.join(CANARY_DIR, "atimes.json")):
        agents_canary_on()
    out = agents_check()
    if out.startswith("Decoy "):
        _notify_once(out.splitlines())
    return out
