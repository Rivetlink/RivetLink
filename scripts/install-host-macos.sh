#!/usr/bin/env bash
#
# Install a RivetLink host agent on macOS.
#
# Builds the agent (or uses a prebuilt binary), provisions its keystore,
# registers the device with your relay, and installs a launchd service so the
# host comes online automatically.
#
# Usage:
#   ./install-host-macos.sh \
#       --relay-host 192.168.1.50:8080 \
#       --token <user-access-token> \
#       [--device-name "Gus MacBook"] \
#       [--insecure-http]   # use ws:// + http:// (LAN testing; default)
#
# Get <user-access-token> by logging in to the relay (e.g. with rivet-client
# or curl POST /auth/login) — it authorizes the one-time device registration.
set -euo pipefail

RELAY_HOST=""
TOKEN=""
DEVICE_NAME="$(scutil --get ComputerName 2>/dev/null || hostname)"
SCHEME_WS="ws"
SCHEME_HTTP="http"

while [ $# -gt 0 ]; do
  case "$1" in
    --relay-host) RELAY_HOST="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --device-name) DEVICE_NAME="$2"; shift 2 ;;
    --secure) SCHEME_WS="wss"; SCHEME_HTTP="https"; shift ;;
    --insecure-http) SCHEME_WS="ws"; SCHEME_HTTP="http"; shift ;;
    *) echo "unknown arg: $1"; exit 1 ;;
  esac
done

[ -n "$RELAY_HOST" ] || { echo "error: --relay-host required (e.g. 192.168.1.50:8080)"; exit 1; }
[ -n "$TOKEN" ]      || { echo "error: --token required (a user access token)"; exit 1; }

PREFIX="$HOME/.rivetlink"
BIN_DIR="$PREFIX/bin"
CONFIG="$PREFIX/agent.json"
KEYS="$PREFIX/keys"
AGENT_BIN="$BIN_DIR/rivet-agent"
mkdir -p "$BIN_DIR" "$KEYS"

echo "==> Locating rivet-agent binary"
if [ -x "./target/release/rivet-agent" ]; then
  cp ./target/release/rivet-agent "$AGENT_BIN"
elif command -v cargo >/dev/null 2>&1; then
  echo "    building from source (cargo build --release --bin rivet-agent)…"
  cargo build --release --bin rivet-agent
  cp ./target/release/rivet-agent "$AGENT_BIN"
else
  echo "error: no prebuilt binary and cargo not installed."
  echo "       install Rust (https://rustup.rs) or drop rivet-agent into $BIN_DIR"
  exit 1
fi
echo "    installed: $AGENT_BIN"

RELAY_WS="$SCHEME_WS://$RELAY_HOST/ws"
RELAY_HTTP="$SCHEME_HTTP://$RELAY_HOST"

echo "==> Initializing agent (keystore + config)"
"$AGENT_BIN" --config "$CONFIG" init \
  --device-name "$DEVICE_NAME" \
  --relay-url "$RELAY_WS" \
  --relay-http-url "$RELAY_HTTP" \
  --keystore-path "$KEYS"

echo "==> Registering device with relay"
"$AGENT_BIN" --config "$CONFIG" register --token "$TOKEN" --platform macos

PLIST="$HOME/Library/LaunchAgents/com.rivetlink.agent.plist"
echo "==> Installing launchd service: $PLIST"
mkdir -p "$HOME/Library/LaunchAgents"
cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.rivetlink.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>$AGENT_BIN</string>
        <string>--config</string>
        <string>$CONFIG</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$PREFIX/agent.log</string>
    <key>StandardErrorPath</key>
    <string>$PREFIX/agent.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
</dict>
</plist>
PLIST_EOF

launchctl unload "$PLIST" 2>/dev/null || true
launchctl load "$PLIST"

cat <<DONE

==> Done.

  Host agent installed and running as a launchd service.
  Config:   $CONFIG
  Keys:     $KEYS
  Logs:     $PREFIX/agent.log

  NOTE: the service runs with the operator-consent prompt DISABLED is NOT the
  default — by default the agent will prompt on first connect. A launchd
  background service cannot show a terminal prompt, so for unattended hosts you
  must pre-trust clients. To approve a client, run the agent in a terminal once:

      $AGENT_BIN --config $CONFIG run

  and answer the prompt, or add the client key to:

      $KEYS/trusted_clients.json

  Manage the service:
      launchctl unload $PLIST   # stop
      launchctl load   $PLIST   # start
DONE
