#!/bin/bash
# Root half of the installer: site filter + watchdog. Called by install.sh with sudo.
# Everything root runs is copied into root-owned folders first, so no program you (or malware
# running as you) can edit is ever run as root.
set -e
UHOME="$1"; P="$2"; D=/var/db/leviathan; R="/Library/Application Support/Leviathan"
[ "$(id -u)" = 0 ] || { echo "install-root.sh must run with sudo"; exit 1; }
[ -f "$UHOME/.leviathan/bin/leviathan.py" ] || { echo "Run install.sh, not this file."; exit 1; }
install -d -m 755 -o root -g wheel "$D" "$D/prev-dns" "$R"; rm -f "$D/disabled"
install -m 644 -o root -g wheel "$UHOME/.leviathan/bin/leviathan.py" "$R/leviathan.py"
install -m 755 -o root -g wheel "$UHOME/.leviathan/bin/dnswatch.sh" "$R/dnswatch.sh"
DP="$P/sbin/dnscrypt-proxy"; [ -x "$DP" ] || DP="$P/bin/dnscrypt-proxy"
install -m 755 -o root -g wheel "$DP" "$R/dnscrypt-proxy"
printf '#!/bin/sh\n# Runs Leviathan as root from its root-owned copy with Apple'"'"'s own Python.\nexec /usr/bin/python3 -I "%s/leviathan.py" "$@"\n' "$R" > "$R/leviathan-root"
chown root:wheel "$R/leviathan-root"; chmod 755 "$R/leviathan-root"
[ -s "$D/blocklist.txt" ] || install -m 644 -o root -g wheel "$UHOME/.leviathan/blocklist.txt" "$D/blocklist.txt" 2>/dev/null || install -m 644 /dev/null "$D/blocklist.txt"

# filter config: Quad9 + Cloudflare malware filtering, plus the scam and malware site list
/usr/bin/python3 -I - "$P/etc/dnscrypt-proxy.toml" "$R/dnscrypt-proxy.toml" "$R" <<'EOF'
import re, sys
s = open(sys.argv[1]).read()
def put(key, val):
    global s
    s, n = re.subn(r"(?m)^#?\s*%s\s*=.*$" % key, "%s = %s" % (key, val), s, count=1)
    assert n == 1, key
put("server_names", "['quad9-doh-ip4-port443-filter-pri', 'cloudflare-security']")
put("require_nofilter", "false")
put("listen_addresses", "['127.0.0.1:53']")
s, n = re.subn(r"(?m)^#?\s*blocked_names_file\s*=.*$", "blocked_names_file = '/var/db/leviathan/blocklist.txt'", s, count=1)
if not n:
    s += "\n[blocked_names]\nblocked_names_file = '/var/db/leviathan/blocklist.txt'\n"
s = re.sub(r"(?m)^(\s*cache_file\s*=\s*)'([^/'][^']*)'", lambda m: "%s'%s/%s'" % (m.group(1), sys.argv[3], m.group(2)), s)
open(sys.argv[2], "w").write(s)
EOF
chown root:wheel "$R/dnscrypt-proxy.toml"; chmod 644 "$R/dnscrypt-proxy.toml"

# remember current DNS so the watchdog and uninstall can restore it exactly
networksetup -listallnetworkservices | tail -n +2 | sed 's/^\*//' | while read -r s; do
  f="$D/prev-dns/$(echo "$s" | tr '/ ' '__')"
  [ -f "$f" ] && continue
  cur=$(networksetup -getdnsservers "$s" 2>/dev/null)
  case "$cur" in *"aren't any"*|*127.0.0.1*) echo "" > "$f" ;; *) echo $cur > "$f" ;; esac
done

cat > /Library/LaunchDaemons/com.leviathan.dnscrypt.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.leviathan.dnscrypt</string>
<key>ProgramArguments</key><array><string>$R/dnscrypt-proxy</string><string>-config</string><string>$R/dnscrypt-proxy.toml</string></array>
<key>WorkingDirectory</key><string>$R</string><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>
EOF
cat > /Library/LaunchDaemons/com.leviathan.dnswatch.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.leviathan.dnswatch</string>
<key>ProgramArguments</key><array><string>/bin/bash</string><string>$R/dnswatch.sh</string></array>
<key>StartInterval</key><integer>20</integer><key>LowPriorityIO</key><true/><key>Nice</key><integer>10</integer></dict></plist>
EOF
for j in dnscrypt dnswatch; do
  chmod 644 /Library/LaunchDaemons/com.leviathan.$j.plist
  launchctl bootout system /Library/LaunchDaemons/com.leviathan.$j.plist 2>/dev/null || true
done
echo fallback > "$D/mode"
launchctl bootstrap system /Library/LaunchDaemons/com.leviathan.dnscrypt.plist
echo "Starting site filter..."
for i in $(seq 1 20); do dig +time=1 +tries=1 @127.0.0.1 apple.com A | grep -q "ANSWER SECTION" && break; sleep 1; done
launchctl bootstrap system /Library/LaunchDaemons/com.leviathan.dnswatch.plist
bash "$R/dnswatch.sh"
echo "Site filter mode: $(cat $D/mode)  (fallback means your normal DNS is in use until the filter answers)"
