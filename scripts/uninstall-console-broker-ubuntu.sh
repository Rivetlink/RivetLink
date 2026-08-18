#!/usr/bin/env bash
# Remove only RivetLink's physical-console units. Run as an administrator or
# prefix with sudo. --purge also removes RivetLink's broker identity/trust data.
set -euo pipefail

PURGE=false
if [ "${1:-}" = "--purge" ]; then
  PURGE=true
elif [ $# -ne 0 ]; then
  echo "usage: $0 [--purge]" >&2
  exit 2
fi

systemctl disable --now rivetlink-console-broker.service 2>/dev/null || true
systemctl --global disable rivetlink-console-worker.service 2>/dev/null || true
rm -f /etc/systemd/system/rivetlink-console-broker.service
rm -f /etc/systemd/user/rivetlink-console-worker.service
rm -f /usr/local/lib/rivetlink/rivet-agent
rmdir /usr/local/lib/rivetlink 2>/dev/null || true
systemctl daemon-reload

if [ "$PURGE" = true ]; then
  rm -rf --one-file-system /var/lib/rivetlink
  userdel rivetlink 2>/dev/null || true
  groupdel rivetlink-console 2>/dev/null || true
  echo "RivetLink broker units and local broker identity/trust data removed."
else
  echo "RivetLink broker units removed; /var/lib/rivetlink identity/trust data retained."
fi
