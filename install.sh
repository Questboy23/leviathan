#!/bin/bash
# MacSafe installer. Run from Terminal: bash ~/macsafe/install.sh   (asks for your Mac password once)
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"; S="$HOME/.macsafe"; PY=/opt/homebrew/bin/python3; U=$(id -u)
echo "Installing MacSafe..."
command -v brew >/dev/null || { echo "Needs Homebrew (brew.sh)."; exit 1; }
brew list dnscrypt-proxy >/dev/null 2>&1 || brew install -q dnscrypt-proxy
brew list yara >/dev/null 2>&1 || brew install -q yara
mkdir -p "$S/bin" "$S/quarantine"; cp "$SRC"/macsafe.py "$SRC"/guard.bash "$SRC"/guard.zsh "$SRC"/dnswatch.sh "$S/bin/"
chmod +x "$S/bin/"*.py "$S/bin/dnswatch.sh"; touch "$S/ledger.jsonl"
mkdir -p "$HOME/.local/bin"; ln -sf "$S/bin/macsafe.py" "$HOME/.local/bin/macsafe"

# paste guard in both shells
for rc in "$HOME/.bash_profile" "$HOME/.zshrc"; do
  ext=bash; [ "$rc" = "$HOME/.zshrc" ] && ext=zsh
  grep -q "macsafe/bin/guard" "$rc" 2>/dev/null || printf '\n[ -f "$HOME/.macsafe/bin/guard.%s" ] && . "$HOME/.macsafe/bin/guard.%s"  # macsafe\nexport PATH="$HOME/.local/bin:$PATH"  # macsafe\n' "$ext" "$ext" >> "$rc"
done

# background watchers: wake only when Downloads, Applications or auto-start folders change
LA="$HOME/Library/LaunchAgents"; mkdir -p "$LA"
cat > "$LA/com.macsafe.watch.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.macsafe.watch</string>
<key>ProgramArguments</key><array><string>$PY</string><string>$S/bin/macsafe.py</string><string>scan-all</string></array>
<key>WatchPaths</key><array><string>$HOME/Downloads</string><string>/Applications</string><string>$LA</string><string>/Library/LaunchAgents</string><string>/Library/LaunchDaemons</string></array>
<key>ThrottleInterval</key><integer>5</integer><key>LowPriorityIO</key><true/><key>Nice</key><integer>10</integer></dict></plist>
EOF
cat > "$LA/com.macsafe.weekly.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.macsafe.weekly</string>
<key>ProgramArguments</key><array><string>$PY</string><string>$S/bin/macsafe.py</string><string>sweep</string><string>--fix</string><string>--quiet</string></array>
<key>StartCalendarInterval</key><dict><key>Weekday</key><integer>0</integer><key>Hour</key><integer>11</integer><key>Minute</key><integer>17</integer></dict></dict></plist>
EOF

echo "Downloading scam and malware site lists..."
curl -fsSL --max-time 90 https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt -o "$S/blocklist.txt" || echo "  (list download failed; it will retry hourly)"

# baseline: record what's already here so only new things get judged
"$PY" "$S/bin/macsafe.py" scan-all
launchctl bootout gui/$U "$LA/com.macsafe.watch.plist" 2>/dev/null || true
launchctl bootout gui/$U "$LA/com.macsafe.weekly.plist" 2>/dev/null || true
launchctl bootstrap gui/$U "$LA/com.macsafe.watch.plist"; launchctl bootstrap gui/$U "$LA/com.macsafe.weekly.plist"

echo; echo "Your Mac password is needed once to turn on the site filter and safe settings."
sudo bash "$SRC/install-root.sh" "$HOME" "$U"
echo; echo "Settings check:"
"$PY" "$S/bin/macsafe.py" sweep --fix
sudo MACSAFE_STATE="$S" "$PY" "$S/bin/macsafe.py" sweep --fix
echo; echo "MacSafe is on. It stays quiet unless it removes something or you do something risky."
echo "See everything it did: macsafe   Undo anything: macsafe undo <number>   Remove it all: bash ~/macsafe/uninstall.sh"
