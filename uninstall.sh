#!/bin/bash
# Removes Leviathan completely and reverses every setting it changed.
# Keeps the log; viruses it caught stay in the Trash where they can't run. Add --keep-settings to leave settings as they are.
S="$HOME/.leviathan"; U=$(id -u); LA="$HOME/Library/LaunchAgents"; R="/Library/Application Support/Leviathan"
for j in watch weekly persistwatch agentwatch vpnwatch bar; do launchctl bootout gui/$U "$LA/com.leviathan.$j.plist" 2>/dev/null; rm -f "$LA/com.leviathan.$j.plist"; done
PY=$(sed -n 's/^exec "\([^"]*\)".*/\1/p' "$HOME/.local/bin/leviathan" 2>/dev/null)
[ "$1" != "--keep-settings" ] && [ -x "$PY" ] && "$PY" "$S/bin/leviathan.py" undo-all
# versions before 2.1 ran a site filter as administrator; remove it if it is still there
if [ -e /Library/LaunchDaemons/com.leviathan.dnscrypt.plist ] || [ -d "$R" ]; then
  echo "Removing the old website filter (asks for your Mac password)."
  sudo bash -c '
    D=/var/db/leviathan; R="/Library/Application Support/Leviathan"; touch $D/disabled 2>/dev/null
    for j in dnswatch dnscrypt; do
      launchctl bootout system /Library/LaunchDaemons/com.leviathan.$j.plist 2>/dev/null
      rm -f /Library/LaunchDaemons/com.leviathan.$j.plist
    done
    networksetup -listallnetworkservices | tail -n +2 | sed "s/^\*//" | while read -r s; do
      f="$D/prev-dns/$(echo "$s" | tr "/ " "__")"; prev=$(cat "$f" 2>/dev/null); [ -z "$prev" ] && prev=Empty
      networksetup -setdnsservers "$s" $prev
    done
    rm -rf "$R"
  '
fi
# Remove menu bar app
rm -rf "$HOME/Applications/Leviathan Bar.app"
for rc in "$HOME/.bash_profile" "$HOME/.zshrc"; do [ -f "$rc" ] && sed -i '' '/# leviathan$/d' "$rc"; done
rm -f "$HOME/.local/bin/leviathan"
echo "Leviathan removed. Every setting it changed is back to how it was."
echo "If you installed the website filter: System Settings > General > Device Management (or Privacy & Security > Profiles), select Leviathan website filter, click Remove."
echo "Viruses it caught are in the Trash, where they can't run. Empty the Trash to delete them."