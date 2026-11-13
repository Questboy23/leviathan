#!/bin/bash
# Leviathan site-filter watchdog (runs as root every 20s). Never lets the filter break your internet.
D=/var/db/leviathan; mkdir -p "$D/prev-dns"
MODE=$(cat "$D/mode" 2>/dev/null || echo filter)
ROOTBL="$D/blocklist.txt"
services() { networksetup -listallnetworkservices | tail -n +2 | sed 's/^\*//'; }
healthy() { dig +time=2 +tries=1 @127.0.0.1 apple.com A 2>/dev/null | grep -q "ANSWER SECTION"; }
online() { curl -s --max-time 4 http://captive.apple.com/hotspot-detect.html 2>/dev/null | grep -q Success; }
use_filter() { services | while read -r s; do networksetup -setdnsservers "$s" 127.0.0.1 2>/dev/null; done; echo filter > "$D/mode"; }
use_normal() {
  services | while read -r s; do
    f="$D/prev-dns/$(echo "$s" | tr '/ ' '__')"
    prev=$(cat "$f" 2>/dev/null); [ -z "$prev" ] && prev=Empty
    networksetup -setdnsservers "$s" $prev 2>/dev/null
  done; echo fallback > "$D/mode"
}
[ -f "$D/disabled" ] && exit 0
if [ "$MODE" = filter ]; then
  if ! healthy || ! online; then use_normal; fi      # filter down or wifi login page: step aside
else
  if healthy && online; then use_filter; fi           # internet open again: filter back on
fi
# hourly feed refresh; only plain domain names get through
if [ ! -s "$ROOTBL" ] || [ $(( $(date +%s) - $(stat -f %m "$ROOTBL") )) -gt 3600 ]; then
  T=$(mktemp)
  if curl -fsSL --max-time 60 https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt -o "$T.h"; then
    curl -fsSL --max-time 30 https://openphish.com/feed.txt 2>/dev/null | sed -E 's#^https?://([^/:]+).*#\1#' > "$T.o"
    # never block a shared host that millions of normal people use; a phishing page on it is one URL, the host is everyone's
    printf '%s\n' docs.google.com drive.google.com sites.google.com forms.gle storage.googleapis.com firebasestorage.googleapis.com \
      google.com www.google.com accounts.google.com github.com raw.githubusercontent.com gist.github.com objects.githubusercontent.com \
      gitlab.com bitbucket.org dropbox.com www.dropbox.com dl.dropboxusercontent.com onedrive.live.com 1drv.ms forms.office.com \
      login.microsoftonline.com office.com www.office.com s3.amazonaws.com icloud.com www.icloud.com apple.com www.apple.com \
      ipfs.io cloudflare-ipfs.com bit.ly t.co linktr.ee canva.com www.canva.com notion.so www.notion.so discord.com cdn.discordapp.com \
      telegra.ph t.me wetransfer.com we.tl mega.nz youtube.com www.youtube.com > "$T.k"
    cat "$T.h" "$T.o" | grep -v '^#' | grep -E '^[A-Za-z0-9*._-]+$' | sed 's/^\*\.//' | grep -vxiF -f "$T.k" | sort -u > "$T"
    if [ $(wc -l < "$T") -gt 1000 ]; then
      mv "$T" "$ROOTBL"; chmod 644 "$ROOTBL"
      launchctl kickstart -k system/com.leviathan.dnscrypt 2>/dev/null
    fi
  fi
  rm -f "$T" "$T.h" "$T.o" "$T.k"
fi
exit 0
