# MacSafe paste guard for zsh. Stops dangerous commands once; press Enter again to run.
[[ -o interactive ]] || return 0
__ms_allow=""
__ms_accept() {
  local line="$BUFFER"
  if [[ "$line" =~ '(curl|wget|base64|xattr|osascript|/dev/tcp|spctl)' && "$line" != "$__ms_allow" ]]; then
    local why
    why=$(/opt/homebrew/bin/python3 "$HOME/.macsafe/bin/macsafe.py" check-cmd "$line" 2>/dev/null)
    if [[ -n "$why" ]]; then
      __ms_allow="$line"
      zle -M $'\e[1;31mMacSafe stopped this command.\e[0m '"$why"$'\nPress Enter again to run it anyway.'
      return 0
    fi
  fi
  __ms_allow=""
  zle .accept-line
}
zle -N accept-line __ms_accept
