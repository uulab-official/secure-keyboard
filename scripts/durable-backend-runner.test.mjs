import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const COMPOSE = readFileSync(`${ROOT}/compose.durable-backends.yml`, "utf8");
const RUNNER = readFileSync(`${ROOT}/scripts/run-durable-backend-tests.sh`, "utf8");

test("local durable services use the pinned CI images and loopback-only ports", () => {
  assert.match(COMPOSE, /image:\s*redis:7\.2-alpine/);
  assert.match(COMPOSE, /image:\s*postgres:16-alpine/);
  assert.match(COMPOSE, /127\.0\.0\.1:6379:6379/);
  assert.match(COMPOSE, /127\.0\.0\.1:5432:5432/);
  assert.match(COMPOSE, /redis-cli.*ping/);
  assert.match(COMPOSE, /pg_isready/);
});

test("durable runner executes every ignored interoperability suite and cleans up", () => {
  assert.match(RUNNER, /set -euo pipefail/);
  assert.match(RUNNER, /docker compose/);
  assert.match(RUNNER, /trap cleanup EXIT/);
  assert.match(RUNNER, /durable_storage -- --ignored --nocapture/);
  assert.match(RUNNER, /durable_rate_limit -- --ignored --nocapture/);
  assert.match(RUNNER, /durable_one_time_state -- --ignored --nocapture/);
  assert.match(RUNNER, /SECURE_KEYPAD_REDIS_URL=redis:\/\/127\.0\.0\.1:6379/);
  assert.match(RUNNER, /SECURE_KEYPAD_POSTGRES_URL=/);
  assert.doesNotMatch(RUNNER, /docker compose[^\n]*down[^\n]*--volumes/);
});
