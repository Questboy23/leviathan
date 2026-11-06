# Leviathan paste guard for zsh. Stops dangerous commands once; press Enter again to run.
[[ -o interactive ]] || return 0
__lv_allow=""
__lv_accept() {
  local line="$BUFFER"
  if [[ "$line" =~ '(curl|wget|base64|xattr|osascript|/dev/tcp|spctl)' && "$line" != "$__lv_allow" ]]; then
    local why
    why=$(__PY__ "$HOME/.leviathan/bin/leviathan.py" check-cmd "$line" 2>/dev/null)
    if [[ -n "$why" ]]; then
      __lv_allow="$line"
      zle -M $'\e[1;31mLeviathan stopped this command.\e[0m '"$why"$'\nPress Enter again to run it anyway.'
      return 0
    fi
  fi
  __lv_allow=""
  zle .accept-line
}
zle -N accept-line __lv_accept
