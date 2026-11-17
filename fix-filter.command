#!/bin/bash
# Turns the website filter (the system half of Leviathan) back on. Asks for your Mac password once.
BREW=$(command -v brew || ls /opt/homebrew/bin/brew /usr/local/bin/brew 2>/dev/null | head -1)
[ -n "$BREW" ] || { echo "Homebrew is missing. Install it from https://brew.sh first."; exit 1; }
sudo bash "$HOME/.leviathan/bin/install-root.sh" "$HOME" "$("$BREW" --prefix)" && echo "Website filter is on."

echo; read -n 1 -s -r -p "Press any key to close this window."
