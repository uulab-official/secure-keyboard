#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || -z "$1" ]]; then
  echo "usage: $0 <destination>" >&2
  exit 64
fi

readonly destination="$1"
readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly corpus_root="$repository_root/fuzz/corpus"
readonly targets=(auth_envelope core_sequence ffi_sequence webauthn_state)

mkdir -p "$destination"
for target in "${targets[@]}"; do
  corpus_path="$corpus_root/$target"
  target_path="$destination/$target"
  test -d "$corpus_path"
  mkdir -p "$target_path"
  cp -R "$corpus_path/." "$target_path/"
done
