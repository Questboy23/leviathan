<picture>
  <source media="(prefers-color-scheme: dark)" srcset="art/banner-dark.svg">
  <img alt="Leviathan: stops viruses before they run on your Mac" src="art/banner-light.svg" width="100%">
</picture>

# Leviathan

**Leviathan stops viruses before they run on your Mac.** It moves real malware where it can't run, blocks scam and malware sites in every app, and stops the "paste this command" trick. It stays silent the rest of the time, and every action can be undone.

Version 2.1.1. 99 of 99 tests pass on macOS 26 (Apple silicon). Version 2.1 cut 9 features that rarely helped or did not work, and is about 40% smaller.

## Install

<a href="#one-line-install"><picture><source media="(prefers-color-scheme: dark)" srcset="art/install-dark.svg"><img alt="Install in one line" src="art/install-light.svg" width="300"></picture></a>
&nbsp;
<a href="https://github.com/Questboy23/leviathan/releases/latest/download/Leviathan.zip"><picture><source media="(prefers-color-scheme: dark)" srcset="art/download-dark.svg"><img alt="Download the zip" src="art/download-light.svg" width="300"></picture></a>

You need a Mac and [Homebrew](https://brew.sh). Leviathan installs its 2 helpers (yara, python) through Homebrew by itself. No password is needed to install.

### One-line install

1. Open Terminal: press Cmd+Space, type `Terminal`, press Return.
2. Paste this line and press Return:

```
cd ~ && curl -fsSL https://github.com/Questboy23/leviathan/archive/refs/tags/v2.1.1.tar.gz | tar xz && bash leviathan-2.1.1/install.sh
```

3. If macOS asks whether `python3` may access Downloads, click Allow.
4. At the end System Settings opens on Profiles. Double-click **Leviathan website filter**, click **Install**, and type your Mac password. This turns on the website filter.

Done. It takes about 1 to 3 minutes.

### Zip install

1. Click **Download the zip** above, then double-click the zip in Downloads to unzip it.
2. In the unzipped `Leviathan` folder, double-click `Install Leviathan.command`. The first time, macOS blocks it because it is not from the App Store: open System Settings, Privacy & Security, scroll down, click **Open Anyway**, then double-click it again.
3. Do step 4 above for the website filter. The zip includes a ready-built menu bar app, so Xcode tools are optional.

## What it does

| Watch | What it catches | What it does |
|---|---|---|
| Downloads and apps | Files matching Apple's own malware rules (XProtect), apps whose developer Apple revoked, files downloaded from known malware sites | Moves them to a folder where they can't run. `leviathan undo` puts them back for 7 days. |
| Auto-start items | Programs that set themselves to start at login while pretending to be Apple, or hiding unsigned in a secret folder | Switches them off and moves them out. Undoable. |
| Paste guard | Pasted Terminal commands that download and run code, unscramble hidden code and run it, strip Apple's safety check, or draw a fake password box | Stops the command once and says why. Press Enter again to run it anyway. |
| Fake password boxes | Pop-ups that ask for your password with hidden typing (AppleScript, compiled scripts, JavaScript) | Closes them. One you type yourself at a Terminal prompt is allowed. |
| Website filter | Known malware and phishing sites, through Cloudflare's security DNS (1.1.1.2), encrypted | The site never loads, in any app. It is a standard macOS profile: remove it any time in System Settings. |
| Settings | AirDrop open to everyone, Chrome notification spam and hijacked search | Fixes them. Undoable. Also reports firewall, Apple's app checks, updates, disk encryption and settings profiles. |
| AI agents (opt in) | Claude Code, Codex and other AI agents | Lists them and pauses or resumes all at once. With "Watch AI agents" on, decoy secret files are checked every 5 minutes and a read notifies you with the agents running. Warns when an agent is set to run commands without asking. |
| Is this a virus? | `leviathan check File`, `leviathan pkg File.pkg` | Answers in plain words, and shows what an installer's scripts will do before you run it. |

The menu bar shield is white while idle, green while a scan runs, orange on an alert you have not seen. It opens instantly. Copying text never triggers anything.

**It only acts on things no one wants on their computer.** Unsigned apps, cracked apps and homemade scripts are never blocked or labeled. They still get checked for actual malware.

**Nothing leaves your Mac** except website lookups (sent encrypted to Cloudflare once the filter is on) and a weekly list download.

### Removed in 2.1

Levels 1 to 5 and the crypto, untrusted-apps and Tor modes (they switched nothing on), the clipboard guard, wallet check, Tor check, app sandbox, snapshots, AI Tune-up, the decoy tripwire and code lookup, the AI attack, tamper and new-connection alerts (they fired on normal use), and the old website filter (it needed a background job running as administrator, and on the test Mac it never got installed).

## Use

```
leviathan scan        check everything now: apps, Downloads, auto-start, network openings, settings
leviathan             show everything it did, with an undo number for each
leviathan undo 12     undo entry 12
leviathan verify      check that the log has not been edited
```

`leviathan scan` changes nothing. On the test Mac it checked 50 apps and 29 downloads in 76 seconds.

## What it can't do

- **A brand-new flaw in macOS itself** can be attacked without you doing anything. Only Apple's updates fix those.
- **Malware no list knows yet** gets through the download check. The paste guard and fake password box watch still catch the most common way Mac password stealers get in.
- **The website filter** blocks what Cloudflare knows. A hotel Wi-Fi login page may not open while it is on; remove the profile for a moment, or use the login page's IP address.
- **Intel Macs** should work through Homebrew's `/usr/local` paths but were not tested.

## How it stays safe itself

- Nothing runs as administrator. The only admin step is the macOS profile, which macOS itself installs.
- Your log and quarantine folder are readable by you only, and the log is hash-chained so `leviathan verify` catches edits.
- The background watcher wakes only when a watched folder changes, plus one check an hour.

## Uninstall

```
bash ~/.leviathan/bin/uninstall.sh
```

This removes every part and reverses every setting Leviathan changed. Add `--keep-settings` to leave the settings as they are. Anything it caught stays in `~/.leviathan/quarantine`, where it can't run. Remove the website filter in System Settings > General > Device Management.

## Tests

```
bash tests.sh
```

The tests use a throwaway folder and change no system settings. They plant a harmless fake virus, a fake Apple auto-start job and a fake password box, then check that each one is stopped and undone correctly.

## AI disclosure

Reed Ostrov supplied the ideas and decisions. Claude Code (Anthropic) wrote code and tests at his direction. The code has no independent audit.

## License

MIT. See `LICENSE`. The banner is drawn by `art/make_art.py`.
