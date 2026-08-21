#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 APK_PATH SCREENSHOT_PATH" >&2
  exit 64
fi

APK_PATH="$1"
SCREENSHOT_PATH="$2"
test -f "$APK_PATH"

aapt_bin="${AAPT:-}"
if [ -z "$aapt_bin" ]; then
  sdk_root="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
  if [ -n "$sdk_root" ]; then
    aapt_bin="$(find "$sdk_root/build-tools" -type f -name aapt -perm -111 | sort | tail -n 1)"
  fi
fi
if [ -z "$aapt_bin" ]; then
  aapt_bin="$(command -v aapt || true)"
fi
test -x "$aapt_bin"

package_name="$("$aapt_bin" dump badging "$APK_PATH" | sed -n "s/^package: name='\([^']*\)'.*/\1/p")"
test -n "$package_name"

mkdir -p "$(dirname "$SCREENSHOT_PATH")"
adb install -r "$APK_PATH"
adb shell am force-stop "$package_name"
adb shell monkey -p "$package_name" 1 >/dev/null

for _ in $(seq 1 30); do
  if adb shell pidof "$package_name" | tr -d '\r' | grep -q .; then
    break
  fi
  sleep 1
done

adb shell pidof "$package_name" | tr -d '\r' | grep -q .
adb exec-out screencap -p > "$SCREENSHOT_PATH"
test -s "$SCREENSHOT_PATH"
