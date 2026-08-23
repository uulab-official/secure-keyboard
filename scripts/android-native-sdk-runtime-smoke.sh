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

package_name="$($aapt_bin dump badging "$APK_PATH" | sed -n "s/^package: name='\([^']*\)'.*/\1/p")"
test -n "$package_name"

mkdir -p "$(dirname "$SCREENSHOT_PATH")"
mkdir -p "$(dirname "$UI_DUMP_PATH")"
initial_ui_dump="$(mktemp /tmp/secure-keypad-native-android-ui.XXXXXX)"
input_ui_dump="$(mktemp /tmp/secure-keypad-native-android-input-ui.XXXXXX)"
cleanup() {
  rm -f "$initial_ui_dump" "$input_ui_dump"
}
trap cleanup EXIT

dump_ui() {
  local output_path="$1"
  local device_path="/sdcard/secure_keypad_native_sdk_ui.xml"
  adb shell uiautomator dump "$device_path" >/dev/null
  adb shell cat "$device_path" | tr -d '\r' > "$output_path"
  test -s "$output_path"
}

assert_secure_window() {
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
    owner = re.search(r"Window\s*\{[^}]*\bu\d+\s+([^\s}]+)", block)
    if not owner or not owner.group(1).startswith(package + "/"):
        continue
    for raw_flags in re.findall(r"\b(?:fl|flags)=0x([0-9a-fA-F]+)", block):
        if int(raw_flags, 16) & 0x2000:
            raise SystemExit(0)
print("FLAG_SECURE is not set on the foreground app window", file=sys.stderr)
raise SystemExit(1)
'
  then
    echo "foreground app window does not enforce FLAG_SECURE" >&2
    exit 1
  fi
}

assert_safe_hierarchy() {
  local hierarchy="$1"
  grep -Fq 'content-desc="No input"' "$hierarchy"
  grep -Fq 'content-desc="1"' "$hierarchy"
  if grep -Fq 'class="android.widget.EditText"' "$hierarchy"; then
    echo "editable text controls must not exist in the standalone native hierarchy" >&2
    exit 1
  fi
  if grep -Fq 'password="true"' "$hierarchy"; then
    echo "password accessibility nodes must not exist in the standalone native hierarchy" >&2
    exit 1
  fi
}

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
assert_secure_window

dump_ui "$initial_ui_dump"
assert_safe_hierarchy "$initial_ui_dump"

tap_coordinates="$(python3 - "$initial_ui_dump" <<'PY'
import re
import sys
import xml.etree.ElementTree as ElementTree

root = ElementTree.parse(sys.argv[1]).getroot()
for node in root.iter("node"):
    if node.attrib.get("content-desc") != "1":
        continue
    match = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node.attrib.get("bounds", ""))
    if not match:
        continue
    left, top, right, bottom = (int(value) for value in match.groups())
    print((left + right) // 2, (top + bottom) // 2)
    raise SystemExit(0)
raise SystemExit("digit-1 accessibility bounds were not found")
PY
)"
tap_x="${tap_coordinates%% *}"
tap_y="${tap_coordinates##* }"
test -n "$tap_x"
test -n "$tap_y"
adb shell input tap "$tap_x" "$tap_y"
sleep 1
dump_ui "$input_ui_dump"
grep -Fq 'content-desc="1 characters entered"' "$input_ui_dump"

# Backgrounding and foregrounding forces the native view through its lifecycle
# zeroization path. The post-return hierarchy must expose an empty masked state,
# proving that the old native input session was not resumed.
adb shell input keyevent KEYCODE_HOME
sleep 1
adb shell am start -W -n "$launcher_activity" >/dev/null
sleep 1
assert_secure_window
dump_ui "$UI_DUMP_PATH"
assert_safe_hierarchy "$UI_DUMP_PATH"
grep -Fq 'content-desc="No input"' "$UI_DUMP_PATH"
if grep -Fq 'content-desc="1 characters entered"' "$UI_DUMP_PATH"; then
  echo "lifecycle recovery resumed the old masked input state" >&2
  exit 1
fi

adb exec-out screencap -p > "$SCREENSHOT_PATH"
test -s "$SCREENSHOT_PATH"
