#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 APP_PATH BUNDLE_ID SCREENSHOT_PATH" >&2
  exit 64
fi

APP_PATH="$1"
BUNDLE_ID="$2"
SCREENSHOT_PATH="$3"

test -d "$APP_PATH"
test -n "$BUNDLE_ID"

booted_device_id="$(xcrun simctl list devices | awk -F '[()]' '/\(Booted\)/ { print $2; exit }')"
created_device_id=""

cleanup() {
  if [ -n "$created_device_id" ]; then
    xcrun simctl shutdown "$created_device_id" >/dev/null 2>&1 || true
    xcrun simctl delete "$created_device_id" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [ -z "$booted_device_id" ]; then
  device_type_id="$(xcrun simctl list devicetypes available -j | python3 -c '
import json
import sys

data = json.load(sys.stdin)
for item in data["devicetypes"]:
    if item.get("name", "").startswith("iPhone "):
        print(item["identifier"])
        break
')"
  runtime_id="$(xcrun simctl list runtimes available -j | python3 -c '
import json
import sys

data = json.load(sys.stdin)
runtimes = [
    item for item in data["runtimes"]
    if item.get("platform") == "iOS" and item.get("isAvailable")
]
if runtimes:
    print(sorted(runtimes, key=lambda item: item.get("version", ""))[-1]["identifier"])
')"
  test -n "$device_type_id"
  test -n "$runtime_id"
  created_device_id="$(xcrun simctl create secure-keypad-runtime-smoke "$device_type_id" "$runtime_id")"
  xcrun simctl boot "$created_device_id"
  xcrun simctl bootstatus "$created_device_id" -b
  booted_device_id="$created_device_id"
fi

mkdir -p "$(dirname "$SCREENSHOT_PATH")"
xcrun simctl install "$booted_device_id" "$APP_PATH"
xcrun simctl launch "$booted_device_id" "$BUNDLE_ID"
# Allow the embedded/bundled framework UI to complete its first layout pass
# before capturing evidence on slower CI simulators.
sleep 5
xcrun simctl io "$booted_device_id" screenshot "$SCREENSHOT_PATH"
test -s "$SCREENSHOT_PATH"
