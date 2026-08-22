# Ubuntu physical-console broker (GDM + HDMI dummy)

RivetLink's Ubuntu console captures and controls the actual HDMI-backed GNOME
desktop after normal login. It does not create a virtual desktop or enable
Ubuntu auto-login.

## GNOME login boundary

Stock GNOME/Mutter intentionally rejects third-party `ScreenCast` and
`RemoteDesktop` sessions for the existing physical GDM or locked `seat0`
display. RivetLink therefore reports `GdmLogin` as unavailable rather than
changing AppArmor, socket permissions, GDM policy, or taking screenshots on
disk. This is an operating-system security boundary, not a setup error.

GNOME Remote Login is a different product architecture: it creates a separate
headless GDM `RemoteDisplay` and GNOME Remote Desktop owns an RDP socket and
its private handover protocol. It is not a public raw-frame/input API that a
third-party encrypted transport can attach to. See
[the upstream boundary note](ubuntu-gnome-remote-login.md).

## Security and service layout

```text
trusted RivetLink client ── LAN or E2E relay ── non-root broker ── session worker ── GNOME desktop
```

- The broker runs as the dedicated non-login `rivetlink` account.
- The worker runs only in the existing GDM or GNOME graphical systemd user
  session. It has no relay credential or privileged filesystem API.
- The local Unix socket remains restrictive; broker peer credentials must match
  the GDM greeter or configured desktop-owner UID.
- The interactive AppImage is never a service executable. Setup installs the
  matching native `rivet-agent` at `/usr/local/lib/rivetlink/rivet-agent`
  atomically; both services execute it directly. This avoids the AppImage
  user-namespace/AppArmor conflict.
- Unknown or revoked devices, and trusted devices without `can_view`,
  `can_control`, and `can_unattended_console`, cannot open a console session.
- Frames and input stay in memory in the authenticated RivetLink connection.
  RivetLink neither stores nor logs Ubuntu credentials.

## Owner checks

```bash
sudo systemctl status rivetlink-console-broker.service --no-pager -l
systemctl --user status rivetlink-console-worker.service --no-pager -l
sudo journalctl -u rivetlink-console-broker.service -b -f -o cat
sudo journalctl -b _SYSTEMD_USER_UNIT=rivetlink-console-worker.service -f -o cat
sudo journalctl -k -b --since '10 minutes ago' \
  | grep -Ei 'apparmor.*DENIED.*(rivetlink|console.sock)|unprivileged_userns'
```

After a normal GNOME desktop login, connect through either Local network or
Relay and verify capture plus normalized pointer/keyboard input. At the GDM or
locked physical login screen, expect a clear unavailable error, never an
infinite spinner or a security-policy workaround.

Use `scripts/uninstall-console-broker-ubuntu.sh` to remove the broker and
worker; add `--purge` only to remove the local RivetLink identity and trust
data as well.
