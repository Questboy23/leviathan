#!/bin/bash
# Build script for Leviathan Bar menu bar app
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
APP_NAME="Leviathan Bar"
APP_DIR="$BUILD_DIR/$APP_NAME.app"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"

echo "Building $APP_NAME..."

rm -rf "$BUILD_DIR"
mkdir -p "$MACOS_DIR"
mkdir -p "$RESOURCES_DIR"

echo "Compiling Swift..."
swiftc -O -framework AppKit "$SCRIPT_DIR/LeviathanBar.swift" -o "$MACOS_DIR/$APP_NAME"

if [ ! -f "$MACOS_DIR/$APP_NAME" ]; then
    echo "Compilation failed"
    exit 1
fi

echo "Creating Info.plist..."
cat > "$CONTENTS_DIR/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Leviathan Bar</string>
    <key>CFBundleIdentifier</key>
    <string>com.leviathan.bar</string>
    <key>CFBundleName</key>
    <string>Leviathan Bar</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHumanReadableCopyright</key>
    <string>Leviathan Security</string>
</dict>
</plist>
PLIST

echo "Build complete: $APP_DIR"
ls -la "$MACOS_DIR/"