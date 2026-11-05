#!/bin/bash
# Removes MacSafe completely and reverses every setting it changed.
# Keeps ~/.macsafe/quarantine and the log so nothing it caught is lost. Add --keep-settings to leave settings as they are.
S="$HOME/.macsafe"; PY=/opt/homebrew/bin/python3; U=$(id -u); LA="$HOME/Library/LaunchAgents"
for j in watch weekly; do launchctl bootout gui/$U "$LA/com.macsafe.$j.plist" 2>/dev/null; rm -f "$LA/com.macsafe.$j.plist"; done
if [ "$1" != "--keep-settings" ]; then
  for id in $("$PY" - "$S/ledger.jsonl" <<'EOF'
import json, sys
es = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
done = {e.get("ref") for e in es if e["kind"] == "undone"}
print(" ".join(f'{e["id"]}:{"root" if e.get("root") else "user"}' for e in reversed(es) if e["kind"] == "setting" and e["id"] not in done))
EOF
); do
    n=${id%%:*}; who=${id##*:}
    if [ "$who" = root ]; then sudo MACSAFE_STATE="$S" "$PY" "$S/bin/macsafe.py" undo "$n"; else "$PY" "$S/bin/macsafe.py" undo "$n"; fi
  done
fi
sudo bash -c '
  D=/var/db/macsafe; touch $D/disabled
  launchctl bootout system /Library/LaunchDaemons/com.macsafe.dnswatch.plist 2>/dev/null
  rm -f /Library/LaunchDaemons/com.macsafe.dnswatch.plist; rm -rf "/Library/Application Support/MacSafe"
  networksetup -listallnetworkservices | tail -n +2 | sed "s/^\*//" | while read -r s; do
    f="$D/prev-dns/$(echo "$s" | tr "/ " "__")"; prev=$(cat "$f" 2>/dev/null); [ -z "$prev" ] && prev=Empty
    networksetup -setdnsservers "$s" $prev
  done
  /opt/homebrew/bin/brew services stop dnscrypt-proxy >/dev/null 2>&1
  [ -f $D/dnscrypt-proxy.toml.orig ] && cp $D/dnscrypt-proxy.toml.orig /opt/homebrew/etc/dnscrypt-proxy.toml
'
for rc in "$HOME/.bash_profile" "$HOME/.zshrc"; do [ -f "$rc" ] && sed -i '' '/# macsafe$/d' "$rc"; done
rm -f "$HOME/.local/bin/macsafe"
echo "MacSafe removed. Your internet settings and every changed setting are back to how they were."
echo "Anything it caught is still in $S/quarantine (it can't run there)."
