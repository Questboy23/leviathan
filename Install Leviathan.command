#!/bin/bash
# Double-click installer. First time: right-click, Open (macOS asks once because it is downloaded).
cd "$(dirname "$0")" || exit 1
bash ./install.sh
echo
read -n 1 -s -r -p "Done. Press any key to close this window."
