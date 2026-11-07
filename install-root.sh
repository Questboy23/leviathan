#!/bin/bash
# Root half of the installer: site filter + watchdog. Called by install.sh with sudo.
set -e
UHOME="$1"; D=/var/db/macsafe; mkdir -p "$D/prev-dns"; rm -f "$D/disabled"
BREW=$(for p in /opt/homebrew/bin/brew /usr/local/bin/brew; do [ -x "$p" ] && { echo $p; break; }; done); BREW=${BREW:-/opt/homebrew/bin/brew}
PYB=$(for p in /opt/homebrew/bin/python3 /usr/local/bin/python3; do [ -x "$p" ] && { echo $p; break; }; done); PYB=${PYB:-$(command -v python3)}
TOML="$(dirname "$(dirname "$BREW")")/etc/dnscrypt-proxy.toml"
[ -f "$D/dnscrypt-proxy.toml.orig" ] || cp "$TOML" "$D/dnscrypt-proxy.toml.orig"
cp "$UHOME/.macsafe/blocklist.txt" "$D/blocklist.txt" 2>/dev/null || touch "$D/blocklist.txt"
"$PYB" - "$D/dnscrypt-proxy.toml.orig" "$TOML" <<'EOF'
import re, sys
s = open(sys.argv[1]).read()
s = re.sub(r"(?m)^#?\s*server_names\s*=.*$", "server_names = ['quad9-doh-ip4-port443-filter-pri', 'cloudflare-security']", s, count=1)
s = re.sub(r"(?m)^#?\s*require_nofilter\s*=.*$", "require_nofilter = false", s, count=1)
s = re.sub(r"(?m)^#?\s*listen_addresses\s*=.*$", "listen_addresses = ['127.0.0.1:53']", s, count=1)
s = re.sub(r"(?m)^#?\s*blocked_names_file\s*=.*$", "blocked_names_file = '/var/db/macsafe/blocklist.txt'", s, count=1)
if "blocked_names_file = '/var" not in s:
    s += "\n[blocked_names]\nblocked_names_file = '/var/db/macsafe/blocklist.txt'\n"
open(sys.argv[2], "w").write(s)
EOF
# remember current DNS so the watchdog and uninstall can restore it exactly
networksetup -listallnetworkservices | tail -n +2 | sed 's/^\*//' | while read -r s; do
  f="$D/prev-dns/$(echo "$s" | tr '/ ' '__')"
  [ -f "$f" ] && continue
  cur=$(networksetup -getdnsservers "$s" 2>/dev/null)
  case "$cur" in *"aren't any"*|*127.0.0.1*) echo "" > "$f" ;; *) echo $cur > "$f" ;; esac
done
"$BREW" services restart dnscrypt-proxy >/dev/null 2>&1 || "$BREW" services start dnscrypt-proxy
R="/Library/Application Support/MacSafe"; mkdir -p "$R"; install -m 755 -o root -g wheel "$UHOME/.macsafe/bin/dnswatch.sh" "$R/dnswatch.sh"
cat > /Library/LaunchDaemons/com.macsafe.dnswatch.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.macsafe.dnswatch</string>
<key>ProgramArguments</key><array><string>/bin/bash</string><string>$R/dnswatch.sh</string><string>$UHOME</string></array>
<key>StartInterval</key><integer>20</integer><key>LowPriorityIO</key><true/><key>Nice</key><integer>10</integer></dict></plist>
EOF
launchctl bootout system /Library/LaunchDaemons/com.macsafe.dnswatch.plist 2>/dev/null || true
echo fallback > "$D/mode"
echo "Starting site filter..."
for i in $(seq 1 15); do dig +time=1 +tries=1 @127.0.0.1 apple.com A | grep -q "ANSWER SECTION" && break; sleep 1; done
launchctl bootstrap system /Library/LaunchDaemons/com.macsafe.dnswatch.plist
bash "$R/dnswatch.sh" "$UHOME"
echo "Site filter mode: $(cat $D/mode)"
