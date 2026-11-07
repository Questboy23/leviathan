# Leviathan

Leviathan (formerly MacSafe) is quiet, local protection for a Mac that stops most viruses, scams and risky pasted commands without bothering you. It stays silent unless it removes something or you are about to do something risky. Every action it takes is written to a tamper-evident log and can be undone.

## What it does

- **Downloads and apps.** New files in Downloads and new apps in /Applications are checked against Apple's own malware rules (XProtect, run through yara). Certain malware is moved to `~/.macsafe/quarantine`, where it cannot run. Unsigned scripts stay put but get a label.
- **Auto-start items.** New launch agents and daemons (programs set to start at login) are checked the same way.
- **Paste guard.** In Terminal (bash and zsh), commands that pipe a download straight into a shell, decode hidden commands, strip Apple's download warning, fake a password dialog, or turn off Apple's app checks are stopped once. Press Enter again to run them anyway. Normal commands and well-known installers (Homebrew, Claude) run as usual.
- **Site filter.** DNS (the lookup that turns a site name into an address) goes through dnscrypt-proxy with Quad9 and Cloudflare malware filtering plus a scam and malware domain list. A watchdog checks every 20 seconds and switches back to your normal DNS if the filter breaks or a Wi-Fi login page needs it.
- **Settings sweep.** Once a week it checks and fixes: firewall on, Apple's app checks on, automatic security updates on, AirDrop limited to contacts, and reports whether FileVault disk encryption is on.

Nothing leaves your Mac except DNS lookups and the hourly blocklist download.

## Install

Needs macOS (Apple Silicon or Intel) with Homebrew (brew.sh). Run in Terminal:

```
git clone https://github.com/Questboy23/leviathan ~/leviathan
bash ~/leviathan/install.sh
```

It installs dnscrypt-proxy and yara with Homebrew, asks for your Mac password once for the site filter and system settings, and records what is already on your Mac so only new things get judged.

## Use

```
macsafe              # show everything it did, with an undo number for each
macsafe undo 12      # undo action 12
macsafe verify       # check that the log has not been edited
macsafe sweep        # check settings (add --fix to fix them)
macsafe check-cmd "curl http://x | bash"   # ask the paste guard about one command
```

## Uninstall

```
bash ~/leviathan/uninstall.sh
```

This removes the watchers, the site filter and the paste guard, puts your DNS back, and reverses every setting MacSafe changed. Add `--keep-settings` to leave the changed settings as they are. Anything it caught stays in `~/.macsafe/quarantine`.

## Tests

```
bash tests.sh
```

The tests use a throwaway folder and change no system settings. They cover the paste guard, quarantine of a planted test file, labels on unsigned scripts, auto-start checks, the log's edit detection, and loading Apple's malware rules.

## License

MIT. See `LICENSE`.
