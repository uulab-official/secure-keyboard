#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 APK_PATH SCREENSHOT_PATH UI_DUMP_PATH" >&2
  exit 64
fi

APK_PATH="$1"
SCREENSHOT_PATH="$2"
UI_DUMP_PATH="$3"
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
mkdir -p "$(dirname "$UI_DUMP_PATH")"
adb install -r "$APK_PATH"
adb shell am force-stop "$package_name"
launcher_activity="$(adb shell cmd package resolve-activity --brief "$package_name" | tr -d '\r' | awk 'NF { value = $0 } END { print value }')"
case "$launcher_activity" in
  "$package_name/"*) ;;
  *)
    echo "could not resolve a launcher activity for $package_name: $launcher_activity" >&2
    exit 1
    ;;
esac
adb shell am start -W -n "$launcher_activity" >/dev/null

for _ in $(seq 1 30); do
  if adb shell pidof "$package_name" | tr -d '\r' | grep -q .; then
    break
  fi
  sleep 1
done

adb shell pidof "$package_name" | tr -d '\r' | grep -q .

if ! adb shell dumpsys window windows | tr -d '\r' | PACKAGE_NAME="$package_name" python3 -c '
import os
import re
import sys

package = os.environ["PACKAGE_NAME"]
dump = sys.stdin.read()
focused = re.search(r"mCurrentFocus=Window\s*\{[^}]*\bu\d+\s+([^\s}]+)\}", dump)
if not focused or not focused.group(1).startswith(package + "/"):
    print("foreground app window does not belong to the launched package", file=sys.stderr)
    raise SystemExit(1)
for block in re.split(r"(?=Window\s*\{)", dump):
    if package not in block:
        continue
    for raw_flags in re.findall(r"\b(?:fl|flags)=0x([0-9a-fA-F]+)", block):
        if int(raw_flags, 16) & 0x2000:
            raise SystemExit(0)
print("FLAG_SECURE is not set on the foreground app window", file=sys.stderr)
raise SystemExit(1)
'; then
  echo "foreground app window does not enforce FLAG_SECURE" >&2
  exit 1
fi

adb exec-out screencap -p > "$SCREENSHOT_PATH"
test -s "$SCREENSHOT_PATH"

# FLAG_SECURE intentionally makes the content area unreadable to screencap. Verify the
# rendered native hierarchy through public accessibility metadata instead; no input value is
# queried or serialized here.
ui_dump_path="/sdcard/secure_keypad_ui.xml"
adb shell uiautomator dump "$ui_dump_path" >/dev/null
adb shell cat "$ui_dump_path" | tr -d '\r' > "$UI_DUMP_PATH"
test -s "$UI_DUMP_PATH"
grep -Fq 'content-desc="No input"' "$UI_DUMP_PATH"
grep -Fq 'content-desc="1"' "$UI_DUMP_PATH"
if grep -Fq 'class="android.widget.EditText"' "$UI_DUMP_PATH"; then
  echo "editable text controls must not exist in the secure keypad hierarchy" >&2
  exit 1
fi
if grep -Fq 'password="true"' "$UI_DUMP_PATH"; then
  echo "password accessibility nodes must not exist in the secure keypad hierarchy" >&2
  exit 1
fi
