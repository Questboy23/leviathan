#!/bin/bash
# Removes Leviathan completely and reverses every setting it changed.
# Keeps ~/.leviathan/quarantine and the log so nothing it caught is lost. Add --keep-settings to leave settings as they are.
S="$HOME/.leviathan"; U=$(id -u); LA="$HOME/Library/LaunchAgents"; R="/Library/Application Support/Leviathan"
for j in watch weekly persistwatch bar; do launchctl bootout gui/$U "$LA/com.leviathan.$j.plist" 2>/dev/null; rm -f "$LA/com.leviathan.$j.plist"; done
PY=$(sed -n 's/^exec "\([^"]*\)".*/\1/p' "$HOME/.local/bin/leviathan" 2>/dev/null)
if [ "$1" != "--keep-settings" ]; then
  [ -x "$PY" ] && "$PY" "$S/bin/leviathan.py" undo-settings
  [ -x "$R/leviathan-root" ] && sudo "$R/leviathan-root" undo-settings
fi
sudo bash -c '
  D=/var/db/leviathan; R="/Library/Application Support/Leviathan"; touch $D/disabled
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
# Remove menu bar app
rm -rf "$HOME/Applications/Leviathan Bar.app"
for rc in "$HOME/.bash_profile" "$HOME/.zshrc"; do [ -f "$rc" ] && sed -i '' '/# leviathan$/d' "$rc"; done
rm -f "$HOME/.local/bin/leviathan"
echo "Leviathan removed. Your internet settings and every changed setting are back to how they were."
echo "Anything it caught is still in $S/quarantine (it can't run there)."