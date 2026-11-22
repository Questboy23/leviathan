<picture>
  <source media="(prefers-color-scheme: dark)" srcset="art/banner-dark.svg">
  <img alt="Leviathan: stops viruses before they run on your Mac" src="art/banner-light.svg" width="100%">
</picture>

# Leviathan

**Leviathan stops viruses on your Mac before they run.** It checks every new download, new app and new auto-start item, it stops scam commands pasted into Terminal, and it blocks known malware sites. It stays silent the rest of the time, and every action can be undone.

Version 4.0.0. 74 of 74 tests pass on macOS 26 (Apple silicon). Version 4.0 removed the Safe Box, the VPN, the AI agent watch and the fake password box closer to keep it small and quiet.

## Install

You need a Mac and [Homebrew](https://brew.sh). Leviathan installs its 2 helpers (yara, python) through Homebrew by itself. No password is needed to install.

1. Open Terminal: press Cmd+Space, type `Terminal`, press Return.
2. Paste this line and press Return:

```
cd ~ && curl -fsSL https://github.com/Questboy23/leviathan/archive/refs/tags/v4.0.0.tar.gz | tar xz && bash leviathan-4.0.0/install.sh
```

3. If macOS asks whether `python3` may access Downloads, click Allow.
4. At the end System Settings opens on Profiles. Double-click **Leviathan website filter**, click **Install**, and type your Mac password. This turns on the website filter.

Or download [Leviathan.zip](https://github.com/Questboy23/leviathan/releases/latest/download/Leviathan.zip), unzip it, and double-click `Install Leviathan.command`.

## What it does

| Part | What it catches | What it does |
|---|---|---|
| Downloads and apps | Files matching Apple's own malware rules (XProtect), apps whose developer Apple revoked, files downloaded from known malware sites | Moves them to the Trash with their permission to run removed, so they can't run even from there. `leviathan undo N` puts them back. Unsigned apps are only noted in the log. |
| Auto-start items | Programs that set themselves to start at login while pretending to be Apple, or hiding unsigned in a secret folder | Switches them off and moves them out. Undoable. |
| Paste guard | Pasted Terminal commands that download and run code, unscramble hidden code and run it, strip Apple's safety check, or draw a fake password box | Stops the command once and says why. Press Enter again to run it anyway. |
| Website filter | Known malware and phishing sites, through Quad9 DNS (9.9.9.9), encrypted. Legal sites stay open | The site never loads, in any app. It is a standard macOS profile: remove it any time in System Settings. |
| Is this a virus? | `leviathan check File`, `leviathan pkg File.pkg` | Answers in plain words, and shows what an installer's scripts will do before you run it. |

The menu bar shield is white while idle, green while a scan runs, orange on an alert you have not seen.

**When it runs:** a scan of Downloads, apps and auto-start items every hour and whenever a watched folder changes, plus a weekly download of the malware site list. The menu bar app checks once every 15 seconds whether a scan is running, and uses no measurable CPU.

**Nothing leaves your Mac** except website lookups (sent encrypted to Quad9) and the weekly list download.

## Use

```
leviathan scan                    check apps, Downloads, auto-start items and the website filter now
leviathan                         show everything it did, with an undo number for each
leviathan undo 12                 undo entry 12
leviathan check File              is this file a virus?
leviathan pkg File.pkg            what will this installer's scripts do?
leviathan verify                  check that the log has not been edited
```

## What it can't do

- **A brand-new flaw in macOS itself** can be attacked without you doing anything. Only Apple's updates fix those.
- **Malware no list knows yet** gets through the download check. The paste guard still catches the most common way Mac password stealers get in.
- **The website filter** blocks what Quad9 knows. A hotel Wi-Fi login page may not open while it is on; remove the profile for a moment.
- **Intel Macs** should work through Homebrew's `/usr/local` paths but were not tested.

## How it stays safe itself

- Nothing runs as administrator. The only admin step is the macOS profile, which macOS itself installs.
- Your log is readable by you only, and the log is hash-chained so `leviathan verify` catches edits.
- The background watcher wakes only when a watched folder changes, plus one check an hour.

## Uninstall

```
bash ~/.leviathan/bin/uninstall.sh
```

This removes every part and reverses every setting Leviathan changed. Add `--keep-settings` to leave the settings as they are. Viruses it caught stay in the Trash, where they can't run. Remove the website filter in System Settings > General > Device Management.

## Tests

```
bash tests.sh
```

The tests use a throwaway folder and change no system settings. They plant a harmless fake virus and a fake Apple auto-start job, then check that each one is stopped and undone correctly.

## AI disclosure

Reed Ostrov supplied the ideas and decisions. Claude Code (Anthropic) wrote code and tests at his direction. The code has no independent audit.

## License

MIT. See `LICENSE`. The banner is drawn by `art/make_art.py`.
