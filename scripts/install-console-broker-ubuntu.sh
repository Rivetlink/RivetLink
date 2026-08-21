#!/usr/bin/env bash
#
# Install RivetLink's physical-console broker for Ubuntu GNOME + a permanent
# HDMI dummy/EDID emulator. This intentionally uses GDM's real seat0 session;
# it never starts `gnome-shell --headless` or enables automatic login.
#
# Run as the Ubuntu desktop owner (not root). The script asks sudo only to
# create RivetLink's system account, install units, and grant the GDM/owner
# sessions access to the broker socket group.
set -euo pipefail
umask 077

RELAY_HOST=""
TOKEN=""
TRUSTED_CLIENT_KEY=""
TRUSTED_CLIENT_NAME=""
OWNER_USER="$(id -un)"
DEVICE_NAME="$(hostnamectl --static 2>/dev/null || hostname)"
AGENT_SOURCE="./target/release/rivet-agent"
SCHEME_WS="wss"
SCHEME_HTTP="https"

while [ $# -gt 0 ]; do
  case "$1" in
    --relay-host) RELAY_HOST="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --trusted-client-key) TRUSTED_CLIENT_KEY="$2"; shift 2 ;;
    --trusted-client-name) TRUSTED_CLIENT_NAME="$2"; shift 2 ;;
    --device-name) DEVICE_NAME="$2"; shift 2 ;;
    --agent) AGENT_SOURCE="$2"; shift 2 ;;
    --insecure-http) SCHEME_WS="ws"; SCHEME_HTTP="http"; shift ;;
    *) echo "error: unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -ne 0 ] || { echo "error: run as the intended desktop owner, not root" >&2; exit 2; }
[ -n "$RELAY_HOST" ] || { echo "error: --relay-host is required" >&2; exit 2; }
[ -n "$TOKEN" ] || { echo "error: --token is required" >&2; exit 2; }
[ -n "$TRUSTED_CLIENT_KEY" ] || { echo "error: --trusted-client-key is required" >&2; exit 2; }
[ -n "$TRUSTED_CLIENT_NAME" ] || { echo "error: --trusted-client-name is required" >&2; exit 2; }
[ -x "$AGENT_SOURCE" ] || { echo "error: --agent must be an executable rivet-agent binary" >&2; exit 2; }
id gdm >/dev/null 2>&1 || { echo "error: GDM is required; no gdm system user found" >&2; exit 2; }
getent passwd "$OWNER_USER" >/dev/null || { echo "error: owner user does not exist" >&2; exit 2; }

OWNER_UID="$(id -u "$OWNER_USER")"
GDM_UID="$(id -u gdm)"
RELAY_WS="$SCHEME_WS://$RELAY_HOST/ws"
RELAY_HTTP="$SCHEME_HTTP://$RELAY_HOST"

echo "==> Installing broker binary, isolated account, and systemd units"
sudo groupadd --system rivetlink-console 2>/dev/null || true
sudo useradd --system --home-dir /var/lib/rivetlink --create-home \
  --shell /usr/sbin/nologin --gid rivetlink-console rivetlink 2>/dev/null || true
sudo usermod -a -G rivetlink-console gdm
sudo usermod -a -G rivetlink-console "$OWNER_USER"
sudo install -d -o rivetlink -g rivetlink-console -m 0710 /var/lib/rivetlink /var/lib/rivetlink/keys
sudo install -d -o root -g rivetlink-console -m 0710 /etc/rivetlink
sudo install -d -o root -g root -m 0755 /usr/local/lib/rivetlink /etc/systemd/user
# Keep an already-running broker on its old executable until a complete new
# agent is present. `mv` within this directory is atomic, so broker and worker
# never observe a partly copied binary during a recovery/update installation.
sudo install -o root -g root -m 0755 "$AGENT_SOURCE" /usr/local/lib/rivetlink/rivet-agent.next
sudo mv -f /usr/local/lib/rivetlink/rivet-agent.next /usr/local/lib/rivetlink/rivet-agent
sudo apt-get update
sudo apt-get install -y pipewire gstreamer1.0-tools gstreamer1.0-pipewire

echo "==> Creating non-root broker identity and registering it once"
if [ ! -f /var/lib/rivetlink/agent.json ]; then
  sudo -u rivetlink /usr/local/lib/rivetlink/rivet-agent --config /var/lib/rivetlink/agent.json init \
    --device-name "$DEVICE_NAME" --relay-url "$RELAY_WS" --relay-http-url "$RELAY_HTTP" \
    --keystore-path /var/lib/rivetlink/keys --headless --allow-trusted-headless
  sudo chmod 0600 /var/lib/rivetlink/agent.json
  sudo -u rivetlink /usr/local/lib/rivetlink/rivet-agent --config /var/lib/rivetlink/agent.json register \
    --token "$TOKEN" --platform linux
else
  echo "==> Existing RivetLink broker identity retained"
fi
sudo -u rivetlink /usr/local/lib/rivetlink/rivet-agent --config /var/lib/rivetlink/agent.json trust-client \
  --public-key "$TRUSTED_CLIENT_KEY" --name "$TRUSTED_CLIENT_NAME" \
  --allow-unattended-console --allow-console-control
sudo chmod 0600 /var/lib/rivetlink/keys/trusted_clients.json

sudo tee /etc/systemd/system/rivetlink-console-broker.service >/dev/null <<UNIT
[Unit]
Description=RivetLink physical console broker
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=rivetlink
Group=rivetlink-console
RuntimeDirectory=rivetlink
RuntimeDirectoryMode=0710
ExecStart=/usr/local/lib/rivetlink/rivet-agent --config /var/lib/rivetlink/agent.json console-broker --socket /run/rivetlink/console.sock --allowed-worker-uid $GDM_UID --allowed-worker-uid $OWNER_UID
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/rivetlink /run/rivetlink
LockPersonality=yes
RestrictSUIDSGID=yes
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
UNIT

# A global user unit starts within the *existing* graphical systemd user
# session. GDM and the normal desktop therefore each use their own session bus;
# neither unit runs the worker as root or starts a second GNOME session.
sudo tee /etc/systemd/user/rivetlink-console-worker.service >/dev/null <<'UNIT'
[Unit]
Description=RivetLink worker for the active GNOME/GDM console
After=graphical-session.target
PartOf=graphical-session.target

[Service]
Type=simple
ExecStart=/usr/local/lib/rivetlink/rivet-agent console-worker --socket /run/rivetlink/console.sock
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
LockPersonality=yes
RestrictSUIDSGID=yes
Environment=RUST_LOG=info

[Install]
WantedBy=graphical-session.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now rivetlink-console-broker.service
sudo systemctl --global enable rivetlink-console-worker.service

cat <<DONE

Installed the RivetLink physical-console broker.

After a reboot, GDM's own graphical session starts the worker and attaches it
to the broker. The HDMI dummy must remain connected. No Ubuntu auto-login,
password storage, virtual GNOME monitor, RDP/VNC, root shell, or filesystem API
is enabled by this installer.

Status: systemctl status rivetlink-console-broker
Logs:   journalctl -u rivetlink-console-broker -b
Worker: journalctl _SYSTEMD_USER_UNIT=rivetlink-console-worker.service -b

Important: this first broker wiring provides authenticated GDM/GNOME capture
and an authorization-gated input IPC path. Use a RivetLink build whose desktop
client supports the ConsoleControl session capability before expecting the UI
to send input through the relay.
DONE
