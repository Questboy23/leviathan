# MacSafe paste guard for bash. Stops dangerous pasted/typed commands once; run again to proceed.
case $- in *i*) ;; *) return 0 2>/dev/null ;; esac
__ms_py=/opt/homebrew/bin/python3
__ms_bin="$HOME/.macsafe/bin/macsafe.py"
__ms_pat='(curl|wget|base64|xattr|osascript|/dev/tcp|spctl)'
__ms_armed=0; __ms_rc=0; __ms_allow=""; __ms_lastnum=""
__ms_prompt() { __ms_armed=0; __ms_rc=0; }
__ms_arm() { __ms_armed=1; }
__ms_guard() {
  case "$BASH_COMMAND" in __ms_*) return 0 ;; esac
  [ "$__ms_armed" = 1 ] || return $__ms_rc
  __ms_armed=0; __ms_rc=0
  local h num line why
  h=$(HISTTIMEFORMAT= builtin history 1)
  num=$(printf '%s' "$h" | awk '{print $1}')
  line=$(printf '%s' "$h" | sed 's/^ *[0-9]*[* ] *//')
  [ "$num" = "$__ms_lastnum" ] && return 0
  __ms_lastnum=$num
  [[ $line =~ $__ms_pat ]] || return 0
  if [ "$line" = "$__ms_allow" ]; then __ms_allow=""; return 0; fi
  why=$("$__ms_py" "$__ms_bin" check-cmd "$line" 2>/dev/null)
  if [ -n "$why" ]; then
    printf '\n\033[1;31mMacSafe stopped this command.\033[0m %s\nIf you trust it, press Up then Enter to run it anyway.\n\n' "$why" >&2
    __ms_allow="$line"; __ms_rc=1; return 1
  fi
  return 0
}
PROMPT_COMMAND="__ms_prompt${PROMPT_COMMAND:+; $PROMPT_COMMAND}; __ms_arm"
shopt -s extdebug
trap '__ms_guard' DEBUG
