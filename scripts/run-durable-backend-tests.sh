#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${SECURE_KEYPAD_COMPOSE_FILE:-$ROOT_DIR/compose.durable-backends.yml}"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required for durable backend interoperability tests" >&2
  exit 127
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required for durable backend interoperability tests" >&2
  exit 127
fi

cleanup() {
  docker compose -f "$COMPOSE_FILE" down --remove-orphans
}
trap cleanup EXIT

docker compose -f "$COMPOSE_FILE" up -d --wait

SECURE_KEYPAD_REDIS_URL=redis://127.0.0.1:6379 \
SECURE_KEYPAD_POSTGRES_URL='host=127.0.0.1 port=5432 user=secure_keypad password=secure_keypad_local_only dbname=secure_keypad' \
  cargo test --locked -p secure-webauthn-example --all-features --test durable_storage -- --ignored --nocapture

SECURE_KEYPAD_REDIS_URL=redis://127.0.0.1:6379 \
SECURE_KEYPAD_POSTGRES_URL='host=127.0.0.1 port=5432 user=secure_keypad password=secure_keypad_local_only dbname=secure_keypad' \
  cargo test --locked -p secure-auth-server --all-features --test durable_rate_limit -- --ignored --nocapture

SECURE_KEYPAD_REDIS_URL=redis://127.0.0.1:6379 \
SECURE_KEYPAD_POSTGRES_URL='host=127.0.0.1 port=5432 user=secure_keypad password=secure_keypad_local_only dbname=secure_keypad' \
  cargo test --locked -p secure-auth-server --all-features --test durable_one_time_state -- --ignored --nocapture
