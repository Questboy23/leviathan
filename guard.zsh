# MacSafe paste guard for zsh. Stops dangerous commands once; press Enter again to run.
[[ -o interactive ]] || return 0
__ms_allow=""
read -r __ms_py < "$HOME/.macsafe/python" 2>/dev/null || __ms_py=/opt/homebrew/bin/python3
__ms_accept() {
  local line="$BUFFER"
  if [[ "$line" =~ '(curl|wget|base64|xattr|osascript|/dev/tcp|spctl)' && "$line" != "$__ms_allow" ]]; then
    local why
    why=$("$__ms_py" "$HOME/.macsafe/bin/macsafe.py" check-cmd "$line" 2>/dev/null)
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
