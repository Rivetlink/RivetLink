#!/usr/bin/env bash
# Remove RivetLink's Ubuntu user services. Run as the same non-root user that
# installed the host. `--purge` additionally deletes the device identity and
# trusted-client store; without it those owner-only files are retained.
set -euo pipefail

PURGE=false
if [ "${1:-}" = "--purge" ]; then
  PURGE=true
elif [ $# -ne 0 ]; then
  echo "usage: $0 [--purge]" >&2
  exit 2
fi

[ "$(id -u)" -ne 0 ] || { echo "error: run as the RivetLink desktop user, not root" >&2; exit 2; }

UNIT_DIR="$HOME/.config/systemd/user"
PREFIX="$HOME/.rivetlink"
systemctl --user disable --now rivetlink-agent.service rivetlink-headless-gnome.service 2>/dev/null || true
rm -f -- "$UNIT_DIR/rivetlink-agent.service" "$UNIT_DIR/rivetlink-headless-gnome.service"
systemctl --user daemon-reload

if [ "$PURGE" = true ]; then
  [ "$PREFIX" = "$HOME/.rivetlink" ] || { echo "refusing unexpected data path" >&2; exit 1; }
  rm -rf -- "$PREFIX"
  echo "RivetLink services and local identity/trust data removed. The relay device record remains."
else
  echo "RivetLink services removed. Local identity and trust data retained at $PREFIX."
  echo "Run '$0 --purge' to delete those local files deliberately."
fi
