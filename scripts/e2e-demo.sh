#!/usr/bin/env bash
#
# End-to-end demo: relay + host agent + support client on one machine.
#
# Proves the full secure pipeline — user auth, device registration, device
# challenge-response, host consent, signed ephemeral key exchange, and an
# E2E-encrypted screenshot — without needing a display (RIVET_FAKE_CAPTURE).
#
# Requires: postgres + redis reachable (docker compose up -d postgres redis),
# and the three binaries built (cargo build).
#
# Usage:  ./scripts/e2e-demo.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/target/debug"
WORK="$(mktemp -d /tmp/rivet-e2e.XXXXXX)"
RELAY_LOG="$WORK/relay.log"
AGENT_LOG="$WORK/agent.log"

export DATABASE_URL="${DATABASE_URL:-postgres://rivet:rivet_dev@localhost/rivet}"
export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379}"
export JWT_SECRET="${JWT_SECRET:-e2e-demo-secret-key-at-least-32-chars-long}"
export BIND_ADDR="${BIND_ADDR:-127.0.0.1:8080}"
export RUST_LOG="${RUST_LOG:-info}"

EMAIL="e2e-$(date +%s)@demo.test"
PASSWORD="demo-password-123"

RELAY_PID=""
AGENT_PID=""
cleanup() {
  [ -n "$AGENT_PID" ] && kill "$AGENT_PID" 2>/dev/null || true
  [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null || true
  echo
  echo "logs + artifacts in: $WORK"
}
trap cleanup EXIT

echo "==> 1. Starting relay (logs: $RELAY_LOG)"
"$BIN/rivet-relay" serve >"$RELAY_LOG" 2>&1 &
RELAY_PID=$!

# Wait for the relay to accept connections.
for i in $(seq 1 30); do
  if curl -fsS "http://$BIND_ADDR/health" >/dev/null 2>&1; then break; fi
  sleep 0.3
  if [ "$i" = "30" ]; then echo "relay did not come up"; cat "$RELAY_LOG"; exit 1; fi
done
echo "    relay healthy at http://$BIND_ADDR"

echo "==> 2. Registering a user (owner)"
REG=$(curl -fsS -X POST "http://$BIND_ADDR/auth/register" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"display_name\":\"E2E\",\"organization_name\":\"E2E Org\"}")
TOKEN=$(printf '%s' "$REG" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
[ -n "$TOKEN" ] || { echo "register failed: $REG"; exit 1; }
echo "    user $EMAIL registered"

echo "==> 3. Host: init + register device"
"$BIN/rivet-agent" --config "$WORK/agent.json" init \
  --device-name "demo-macbook" \
  --relay-url "ws://$BIND_ADDR/ws" \
  --relay-http-url "http://$BIND_ADDR" \
  --keystore-path "$WORK/agent-keys" >/dev/null
"$BIN/rivet-agent" --config "$WORK/agent.json" register --token "$TOKEN" --platform linux
# device_id is persisted in the agent config; read it from there.
DEVICE_ID=$(sed -n 's/.*"device_id": "\([^"]*\)".*/\1/p' "$WORK/agent.json")
echo "    device registered: $DEVICE_ID"

echo "==> 4. Client: init + pre-trust on host"
"$BIN/rivet-client" --config "$WORK/client.json" init \
  --relay-ws-url "ws://$BIND_ADDR/ws" \
  --relay-http-url "http://$BIND_ADDR" \
  --identity-path "$WORK/client-id.json" >/dev/null
CLIENT_KEY=$("$BIN/rivet-client" --config "$WORK/client.json" whoami)
"$BIN/rivet-agent" --config "$WORK/agent.json" trust-client \
  --public-key "$CLIENT_KEY" --name "E2E client" >/dev/null
echo "    client identity pre-trusted"

echo "==> 5. Host: run agent (trusted client, fake capture)"
RIVET_FAKE_CAPTURE=400000 "$BIN/rivet-agent" --config "$WORK/agent.json" run \
  >"$AGENT_LOG" 2>&1 &
AGENT_PID=$!
# Wait until the agent reports it is connected and waiting.
for i in $(seq 1 30); do
  if grep -q "waiting for session requests" "$AGENT_LOG" 2>/dev/null; then break; fi
  sleep 0.3
  if [ "$i" = "30" ]; then echo "agent did not connect"; cat "$AGENT_LOG"; exit 1; fi
done
echo "    agent connected to relay"

echo "==> 6. Client: list devices"
"$BIN/rivet-client" --config "$WORK/client.json" devices --email "$EMAIL" --password "$PASSWORD"

echo "==> 7. Client: capture screenshot over the secure channel"
"$BIN/rivet-client" --config "$WORK/client.json" view \
  --email "$EMAIL" --password "$PASSWORD" \
  --device "$DEVICE_ID" --out "$WORK/screenshot.bin" --no-open

echo "==> 8. Verify the decrypted payload"
SIZE=$(wc -c < "$WORK/screenshot.bin")
HEAD=$(head -c 26 "$WORK/screenshot.bin")
echo "    received $SIZE bytes, header: '$HEAD'"
if [ "$SIZE" -eq 400000 ] && [ "$HEAD" = "RIVETLINK-FAKE-SCREENSHOT" ]; then
  echo
  echo "✅ SUCCESS — end-to-end encrypted screenshot delivered intact."
else
  echo
  echo "❌ FAIL — payload mismatch (size=$SIZE)"
  exit 1
fi
