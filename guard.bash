# Leviathan paste guard for bash. Stops dangerous pasted/typed commands once; run again to proceed.
case $- in *i*) ;; *) return 0 2>/dev/null ;; esac
__lv_py=__PY__
__lv_bin="$HOME/.leviathan/bin/leviathan.py"
__lv_pat='(curl|wget|base64|xattr|osascript|/dev/tcp|spctl)'
__lv_armed=0; __lv_rc=0; __lv_allow=""; __lv_lastnum=""
__lv_prompt() { __lv_armed=0; __lv_rc=0; }
__lv_arm() { __lv_armed=1; }
__lv_guard() {
  case "$BASH_COMMAND" in __lv_*) return 0 ;; esac
  [ "$__lv_armed" = 1 ] || return $__lv_rc
  __lv_armed=0; __lv_rc=0
  local h num line why
  h=$(HISTTIMEFORMAT= builtin history 1)
  num=$(printf '%s' "$h" | awk '{print $1}')
  line=$(printf '%s' "$h" | sed 's/^ *[0-9]*[* ] *//')
  [ "$num" = "$__lv_lastnum" ] && return 0
  __lv_lastnum=$num
  [[ $line =~ $__lv_pat ]] || return 0
  if [ "$line" = "$__lv_allow" ]; then __lv_allow=""; return 0; fi
  why=$("$__lv_py" "$__lv_bin" check-cmd "$line" 2>/dev/null)
  if [ -n "$why" ]; then
    printf '\n\033[1;31mLeviathan stopped this command.\033[0m %s\nIf you trust it, press Up then Enter to run it anyway.\n\n' "$why" >&2
    __lv_allow="$line"; __lv_rc=1; return 1
  fi
  return 0
}
PROMPT_COMMAND="__lv_prompt${PROMPT_COMMAND:+; $PROMPT_COMMAND}; __lv_arm"
shopt -s extdebug
trap '__lv_guard' DEBUG
