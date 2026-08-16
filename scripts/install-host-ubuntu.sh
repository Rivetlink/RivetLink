#!/usr/bin/env bash
#
# Install RivetLink's screenshot-only, headless GNOME host on Ubuntu Desktop
# 24.04 LTS or newer. Run this as the desktop user, never as root.
#
# This installs two systemd *user* services:
#   1. a dedicated Mutter/GNOME Shell Wayland compositor with one virtual monitor
#   2. rivet-agent, restricted to E2E on-demand screenshot sessions
#
# Usage:
#   ./scripts/install-host-ubuntu.sh \
#       --relay-host relay.example.com \
#       --token <user-access-token> \
#       --trusted-client-key "$(rivet-client --config client.json whoami)" \
#       --trusted-client-name "Owner laptop"
#
# `--insecure-http` is only for a trusted LAN development relay. Production
# deployments must keep the default HTTPS/WSS transport.
set -euo pipefail
umask 077

RELAY_HOST=""
TOKEN=""
TRUSTED_CLIENT_KEY=""
TRUSTED_CLIENT_NAME=""
DEVICE_NAME="$(hostnamectl --static 2>/dev/null || hostname)"
RESOLUTION="1920x1080"
SCHEME_WS="wss"
SCHEME_HTTP="https"

while [ $# -gt 0 ]; do
  case "$1" in
    --relay-host) RELAY_HOST="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --trusted-client-key) TRUSTED_CLIENT_KEY="$2"; shift 2 ;;
    --trusted-client-name) TRUSTED_CLIENT_NAME="$2"; shift 2 ;;
    --device-name) DEVICE_NAME="$2"; shift 2 ;;
    --resolution) RESOLUTION="$2"; shift 2 ;;
    --insecure-http) SCHEME_WS="ws"; SCHEME_HTTP="http"; shift ;;
    *) echo "error: unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -ne 0 ] || { echo "error: run this installer as the intended non-root desktop user" >&2; exit 2; }
[ -n "$RELAY_HOST" ] || { echo "error: --relay-host is required" >&2; exit 2; }
[ -n "$TOKEN" ] || { echo "error: --token is required" >&2; exit 2; }
[ -n "$TRUSTED_CLIENT_KEY" ] || { echo "error: --trusted-client-key is required; unknown clients are never auto-trusted" >&2; exit 2; }
[ -n "$TRUSTED_CLIENT_NAME" ] || { echo "error: --trusted-client-name is required" >&2; exit 2; }
[[ "$RESOLUTION" =~ ^[1-9][0-9]{2,4}x[1-9][0-9]{2,4}$ ]] || {
  echo "error: --resolution must look like 1920x1080" >&2
  exit 2
}

PREFIX="$HOME/.rivetlink"
BIN_DIR="$PREFIX/bin"
CONFIG="$PREFIX/agent.json"
KEYS="$PREFIX/keys"
AGENT_BIN="$BIN_DIR/rivet-agent"
UNIT_DIR="$HOME/.config/systemd/user"

echo "==> Installing Ubuntu Wayland/PipeWire capture prerequisites"
sudo apt-get update
sudo apt-get install -y gnome-shell pipewire gstreamer1.0-tools gstreamer1.0-pipewire

echo "==> Building or installing rivet-agent"
install -d -m 700 "$BIN_DIR" "$KEYS" "$UNIT_DIR"
if [ -x "./target/release/rivet-agent" ]; then
  install -m 700 "./target/release/rivet-agent" "$AGENT_BIN"
elif command -v cargo >/dev/null 2>&1; then
  cargo build --release --bin rivet-agent
  install -m 700 "./target/release/rivet-agent" "$AGENT_BIN"
else
  echo "error: no release binary and Cargo is unavailable" >&2
  exit 1
fi

RELAY_WS="$SCHEME_WS://$RELAY_HOST/ws"
RELAY_HTTP="$SCHEME_HTTP://$RELAY_HOST"

echo "==> Creating owner-only config and device identity"
"$AGENT_BIN" --config "$CONFIG" init \
  --device-name "$DEVICE_NAME" \
  --relay-url "$RELAY_WS" \
  --relay-http-url "$RELAY_HTTP" \
  --keystore-path "$KEYS" \
  --headless --allow-trusted-headless
chmod 600 "$CONFIG"
chmod 700 "$PREFIX" "$KEYS"

echo "==> Registering host device"
"$AGENT_BIN" --config "$CONFIG" register --token "$TOKEN" --platform linux

echo "==> Pre-trusting the explicit screenshot-only owner client"
"$AGENT_BIN" --config "$CONFIG" trust-client \
  --public-key "$TRUSTED_CLIENT_KEY" \
  --name "$TRUSTED_CLIENT_NAME"
chmod 600 "$KEYS/trusted_clients.json"

echo "==> Installing systemd user services"
cat > "$UNIT_DIR/rivetlink-headless-gnome.service" <<EOF
[Unit]
Description=RivetLink dedicated headless GNOME virtual monitor
After=default.target

[Service]
Type=simple
ExecStart=/usr/bin/gnome-shell --headless --virtual-monitor $RESOLUTION
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=default.target
EOF

cat > "$UNIT_DIR/rivetlink-agent.service" <<EOF
[Unit]
Description=RivetLink screenshot-only headless host agent
Requires=rivetlink-headless-gnome.service
After=rivetlink-headless-gnome.service

[Service]
Type=simple
ExecStart=$AGENT_BIN --config $CONFIG run --headless
Restart=always
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
LockPersonality=yes
RestrictSUIDSGID=yes
Environment=RUST_LOG=info

[Install]
WantedBy=default.target
EOF
chmod 600 "$UNIT_DIR/rivetlink-headless-gnome.service" "$UNIT_DIR/rivetlink-agent.service"

echo "==> Enabling boot persistence for user $(id -un)"
sudo loginctl enable-linger "$(id -un)"
systemctl --user daemon-reload
systemctl --user enable --now rivetlink-headless-gnome.service rivetlink-agent.service

cat <<DONE

==> Done.

The agent runs as $(id -un), never as root. It captures only the dedicated
$RESOLUTION virtual GNOME monitor; it does not expose RDP, shell, files, or
input control. The trusted client is the only key eligible for unattended
headless screenshots.

Status: systemctl --user status rivetlink-headless-gnome rivetlink-agent
Logs:   journalctl --user -u rivetlink-agent -f
Remove: ./scripts/uninstall-host-ubuntu.sh

Read docs/ubuntu-headless-host.md before changing trust or headless settings.
DONE
