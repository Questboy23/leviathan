# Leviathan 2.0 spec (levels, modes, menu bar, AI agent guard)

Goal: people will do risky things (crypto, cracked apps, Tor). Leviathan keeps their Mac, passwords and card numbers safe while they do. It never helps the activity itself. Keep it light: no polling loops in Python, no new always-on Python process. Python 3.9 stdlib only.

## Rules for implementers
- New logic goes in `levplus.py` (imported by leviathan.py). Only add CLI branches to leviathan.py `main()`; do not refactor existing code.
- Every action is logged with `ledger_add(...)` and reversible where it changes anything. Never delete user files; contain (move to locked folder) like `contain()`.
- Settings live in `$LEVIATHAN_STATE/settings.json` (state dir from leviathan.py). Missing file = level 2, all modes off.
- Respect LEVIATHAN_QUIET / LEVIATHAN_NO_SPAWN env used by tests.sh. Add tests to tests.sh for every pure function (no network, no system changes). `bash tests.sh` must pass.

## Levels (each includes the ones below). CLI: `leviathan level [1-5]`
1 Basic: 1.0 behaviour.
2 Standard (default): + crypto clipboard guard, recovery-phrase guard, fake password box guard (in menu bar app).
3 Careful: + instant startup-item alert (launchd WatchPaths on ~/Library/LaunchAgents, /Library/LaunchAgents, /Library/LaunchDaemons -> runs `leviathan scan-persist`), wallet app signature check daily.
4 Strict: + new unsigned/ad-hoc apps from the internet get "Open in sandbox" (sandbox-exec, see Piracy mode) as the default way to open; Tor checks.
5 Lockdown: + new unsigned apps are contained until the user approves; outbound internet alert for any app first seen in the last 7 days (via `lsof -i` sample every 60 s, only at level 5). Costs: more prompts, some apps break, sandboxed apps cannot see your files.
`leviathan level` with no number prints current level and what each level adds and costs.

## Modes (independent toggles). CLI: `leviathan mode <crypto|apps|tor|agents> <on|off>`, `leviathan mode` lists.
### crypto
- `clip_check(old, new)`: if old and new are both crypto addresses (BTC bech32/base58, ETH 0x40hex, SOL base58 32-44, XMR 95) of the same kind and differ, and the change happened within 2 s of a copy with no user paste, return a warning string. Pure function, tested.
- `seed_phrase(text)`: True if text is 12, 15, 18, 21 or 24 words and >= 90% are in the BIP39 English list (`bip39.txt`, ship it in repo). Tested.
- `wallet_apps()`: for Ledger Live, Exodus, Electrum, Trezor Suite, Sparrow, MetaMask (Chrome extension id nkbihfbeogaeaoehlefnkodbefgpgknn) report signed-by Team ID vs expected (put expected IDs in a dict; if unknown, report "unsigned or unexpected signer" only when unsigned/ad-hoc). Uses existing sign_check style (codesign -dv).
- Drainer/phishing sites: add MetaMask eth-phishing-detect `config.json` blacklist to the hourly list in dnswatch.sh when crypto mode is on (skip any host on the shared-hosts allowlist).
### apps (pirated / untrusted apps)
- `leviathan sandbox APP [--net]`: runs the app's main executable under `sandbox-exec` with a generated profile: deny read/write of ~ except a per-app container `~/Library/Application Support/Leviathan/sandbox/<name>`, deny network unless --net, deny Keychain, Safari/Chrome/Firefox profiles, ~/.ssh, wallet folders. Profile text built by a pure function `sandbox_profile(home, container, net)`; test it contains the denies.
- `leviathan pkg FILE.pkg`: expands with `pkgutil --expand` to a temp dir, lists preinstall/postinstall scripts and any LaunchAgent/LaunchDaemon plists, flags scripts matching check_cmd() patterns, prints a plain-English verdict. Read-only.
- `leviathan snapshot` / `leviathan diff`: records Applications, LaunchAgents/Daemons, login items, /etc/hosts hash, and shows what changed since; `leviathan diff --undo` contains new startup items (reversible).
### tor
- `tor_check()`: Tor Browser present? signature Team ID MADPSAYN6T, version vs latest (read local version only, plus optional fetch of https://aus1.torproject.org/torbrowser/update_3/release/downloads.json when online, timeout 5 s), security level Safest (prefs.js `browser.security_level.security_slider` == 1). Report plain English.
- Files downloaded from .onion (where_from contains .onion) are never opened directly: notify and offer `leviathan sandbox`.
### agents (AI agent guard)
- `agent_procs()`: list running AI agents (claude, codex, cursor, aider, goose, gemini, openhands, node processes with those names in argv). Pure parser `parse_ps(text)` tested.
- `leviathan agents pause|resume`: SIGSTOP/SIGCONT every agent process (kill switch; menu bar button "Pause all AI agents").
- Canary files: `leviathan agents canary on` writes decoy files (`~/.leviathan-canary/aws_credentials`, `wallet_seed.txt`, with obviously fake values) and records their atime; `leviathan agents check` reports any canary read since. Also: if an agent process holds open files under ~/.ssh, ~/Library/Keychains, wallet or browser cookie folders (`lsof -p` sample, only when agents mode on and agents are running, every 60 s), log + notify.
- Config audit: warn if Claude Code settings use bypassPermissions/dangerously-skip-permissions by default, or Cursor/Codex auto-run with no allowlist. Read-only report.

## Menu bar app (menubar/LeviathanBar.swift, AppKit, single file, `swiftc -O` builds it)
- NSStatusItem with a small shield icon (SF Symbol `shield.lefthalf.filled`), turns orange on a new alert.
- Menu: status line; Level 1..5 (checkmarks, calls `leviathan level N`); Modes: Crypto, Untrusted apps, Tor, AI agents (checkmarks); "Pause all AI agents" / "Resume"; "Open app in sandbox..." (file picker); "Check installer..." (file picker for .pkg); "Recent activity" (last 10 ledger lines); "Run full scan"; Quit.
- Clipboard guard native: NSPasteboard.general.changeCount polled every 0.5 s (no process spawn unless changed). On change, call `leviathan clip <stdin>`, which runs clip_check and seed_phrase and prints a warning or nothing; show warning as a notification and an alert.
- Fake password box guard: every 3 s, only at level >= 2, NSWorkspace/`ps` check for `osascript` with "hidden answer" whose parent is not Terminal typed by user; terminate it and alert.
- Built and installed by install.sh into ~/Applications/Leviathan Bar.app with a LaunchAgent; uninstall.sh removes it.

## Light on the computer
- No Python daemons. Python runs only on events (WatchPaths, clipboard change, hourly list refresh) and the existing schedules. Swift app idle CPU < 0.5%.
- Measure: `leviathan cost` prints CPU seconds used by Leviathan processes in the last day from the ledger timings and current RSS of the menu bar app.
