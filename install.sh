#!/bin/bash
# Leviathan installer. Run from Terminal: bash install.sh   (no password needed)
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"; S="$HOME/.leviathan"; U=$(id -u)
[ "$U" = 0 ] && { echo "Run this as yourself, without sudo."; exit 1; }
[ "$(uname)" = Darwin ] || { echo "Leviathan is for macOS."; exit 1; }
echo "Installing Leviathan..."
BREW=$(command -v brew || ls /opt/homebrew/bin/brew /usr/local/bin/brew 2>/dev/null | head -1)
[ -n "$BREW" ] || { echo "Leviathan needs Homebrew first. Install it from https://brew.sh, then run this again."; exit 1; }
P=$("$BREW" --prefix)
for f in yara python3; do
  [ -x "$P/bin/$f" ] || [ -x "$P/sbin/$f" ] || "$BREW" install -q "$( [ $f = python3 ] && echo python || echo $f )"
done
PY="$P/bin/python3"
mkdir -p "$S/bin" "$S/quarantine"; chmod 700 "$S"
rm -f "$S/bin/bip39.txt" "$S/bin/dnswatch.sh" "$S/bin/install-root.sh" "$S/bin/fix-filter.command" "$S/bin/fix-filter.sh"  # parts of older versions
cp "$SRC/leviathan.py" "$SRC/levplus.py" "$SRC/uninstall.sh" "$SRC/website-filter.mobileconfig" "$S/bin/"
for g in bash zsh; do sed "s#__PY__#$PY#g" "$SRC/guard.$g" > "$S/bin/guard.$g"; done
chmod +x "$S/bin/leviathan.py"; touch "$S/ledger.jsonl"; chmod 600 "$S/ledger.jsonl"
mkdir -p "$HOME/.local/bin"; rm -f "$HOME/.local/bin/leviathan"
printf '#!/bin/sh\nexec "%s" "%s" "$@"\n' "$PY" "$S/bin/leviathan.py" > "$HOME/.local/bin/leviathan"; chmod 755 "$HOME/.local/bin/leviathan"

# paste guard in both shells
for rc in "$HOME/.bash_profile" "$HOME/.zshrc"; do
  ext=bash; [ "$rc" = "$HOME/.zshrc" ] && ext=zsh
  grep -q "leviathan/bin/guard" "$rc" 2>/dev/null || printf '\n[ -f "$HOME/.leviathan/bin/guard.%s" ] && . "$HOME/.leviathan/bin/guard.%s"  # leviathan\nexport PATH="$HOME/.local/bin:$PATH"  # leviathan\n' "$ext" "$ext" >> "$rc"
done

# background watchers: wake only when Downloads, Applications or auto-start folders change
LA="$HOME/Library/LaunchAgents"; mkdir -p "$LA"
cat > "$LA/com.leviathan.watch.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.leviathan.watch</string>
<key>ProgramArguments</key><array><string>$PY</string><string>$S/bin/leviathan.py</string><string>scan-all</string></array>
<key>StartInterval</key><integer>3600</integer>
<key>WatchPaths</key><array><string>$HOME/Downloads</string><string>/Applications</string><string>$LA</string><string>/Library/LaunchAgents</string><string>/Library/LaunchDaemons</string></array>
<key>ThrottleInterval</key><integer>5</integer><key>LowPriorityIO</key><true/><key>Nice</key><integer>10</integer></dict></plist>
EOF
cat > "$LA/com.leviathan.weekly.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.leviathan.weekly</string>
<key>ProgramArguments</key><array><string>$PY</string><string>$S/bin/leviathan.py</string><string>sweep</string><string>--fix</string><string>--quiet</string></array>
<key>StartCalendarInterval</key><dict><key>Weekday</key><integer>0</integer><key>Hour</key><integer>11</integer><key>Minute</key><integer>17</integer></dict></dict></plist>
EOF

# persistwatch: checks new startup items the moment one appears
cat > "$LA/com.leviathan.persistwatch.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.leviathan.persistwatch</string>
<key>ProgramArguments</key><array><string>$PY</string><string>$S/bin/leviathan.py</string><string>scan-persist</string></array>
<key>WatchPaths</key><array><string>$HOME/Library/LaunchAgents</string><string>/Library/LaunchAgents</string><string>/Library/LaunchDaemons</string></array>
<key>ThrottleInterval</key><integer>5</integer><key>LowPriorityIO</key><true/><key>Nice</key><integer>10</integer></dict></plist>
EOF

echo "Downloading the scam and malware site list..."
curl -fsSL --max-time 90 https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt -o "$S/blocklist.txt" || echo "  (list download failed; the weekly check retries)"

# baseline: record what's already here so only new things get judged
"$PY" "$S/bin/leviathan.py" scan-all
[ -d "$HOME/.leviathan-canary" ] && "$PY" "$S/bin/leviathan.py" agents canary on >/dev/null  # rewrite decoys made by older versions
cat > "$LA/com.leviathan.agentwatch.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.leviathan.agentwatch</string>
<key>ProgramArguments</key><array><string>$PY</string><string>$S/bin/leviathan.py</string><string>agents</string><string>monitor</string></array>
<key>StartInterval</key><integer>300</integer><key>ThrottleInterval</key><integer>60</integer><key>LowPriorityIO</key><true/><key>Nice</key><integer>10</integer></dict></plist>
EOF
for j in watch weekly persistwatch agentwatch; do launchctl bootout gui/$U "$LA/com.leviathan.$j.plist" 2>/dev/null || true; launchctl bootstrap gui/$U "$LA/com.leviathan.$j.plist"; done

# Menu bar app: build it when swiftc exists, else use the prebuilt copy the release zip ships
APP_SRC=""
if command -v swiftc >/dev/null 2>&1 && (cd "$SRC/menubar" && bash build.sh >/dev/null 2>&1); then
    APP_SRC="$SRC/menubar/build/Leviathan Bar.app"
elif [ -d "$SRC/menubar/prebuilt/Leviathan Bar.app" ]; then
    APP_SRC="$SRC/menubar/prebuilt/Leviathan Bar.app"
    xattr -dr com.apple.quarantine "$APP_SRC" 2>/dev/null || true
fi
if [ -n "$APP_SRC" ]; then
        APP_DST="$HOME/Applications/Leviathan Bar.app"
        mkdir -p "$HOME/Applications"
        rm -rf "$APP_DST"
        cp -R "$APP_SRC" "$APP_DST"
        echo "Installed menu bar app to $APP_DST"
        # LaunchAgent for menu bar app (RunAtLoad)
        cat > "$LA/com.leviathan.bar.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.leviathan.bar</string>
<key>ProgramArguments</key><array><string>$APP_DST/Contents/MacOS/Leviathan Bar</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>EnvironmentVariables</key><dict><key>LEVIATHAN_BIN</key><string>$S/bin/leviathan.py</string></dict>
</dict></plist>
EOF
        launchctl bootout gui/$U "$LA/com.leviathan.bar.plist" 2>/dev/null || true
        launchctl bootstrap gui/$U "$LA/com.leviathan.bar.plist"
        echo "Menu bar app LaunchAgent installed."
    else
        echo "  (menu bar app unavailable: no swiftc and no prebuilt copy; the protection still runs)"
fi

echo; echo "Settings check:"
"$PY" "$S/bin/leviathan.py" sweep --fix
if ! "$PY" -c "import sys; sys.path.insert(0, '$S/bin'); import leviathan as L; sys.exit(L.website_filter_on() is False)"; then
  echo; echo "Last step: the website filter. System Settings opens; click Install there (it asks for your Mac password)."
  [ -z "$LEVIATHAN_NO_PROFILE" ] && open "$S/bin/website-filter.mobileconfig" && open "x-apple.systempreferences:com.apple.Profiles-Settings.extension"
fi
echo; echo "Leviathan is on. It stays quiet unless it removes something or you do something risky."
echo "Open a new Terminal window, then:"
echo "  leviathan scan       check everything now"
echo "  leviathan            see everything it did"
echo "  leviathan undo 12    undo entry 12"
echo "  bash ~/.leviathan/bin/uninstall.sh    remove it all"