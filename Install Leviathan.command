#!/bin/bash
# Double-click installer. The first time, macOS blocks it: open System Settings > Privacy & Security and click Open Anyway.
cd "$(dirname "$0")" || exit 1
bash ./install.sh
echo
read -n 1 -s -r -p "Done. Press any key to close this window."
