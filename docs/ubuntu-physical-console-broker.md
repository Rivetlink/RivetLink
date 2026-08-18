# Ubuntu physical-console broker (GDM + HDMI dummy)

This is RivetLink's unattended Ubuntu design for a permanently connected HDMI
dummy/EDID emulator. It captures the actual seat0 monitor owned first by GDM
and then by the normal GNOME desktop; it does **not** start a separate virtual
GNOME monitor and does not enable automatic Ubuntu login.

## Security boundary

`rivetlink-console-broker.service` runs as the dedicated, non-login
`rivetlink` system account. It owns device identity, trusted-controller policy
and the relay websocket, but has no session D-Bus address and cannot capture
or inject input itself.

`rivetlink-console-worker.service` runs only inside the existing graphical GDM
or GNOME systemd user session. It gets the session's Mutter ScreenCast and
RemoteDesktop D-Bus access, but has no relay credential and exposes only a
length-bounded Unix socket protocol for a PNG capture and normalized pointer,
scroll or key event. The socket is `0660`, belongs to the private
`rivetlink-console` group, and broker-side peer credentials must match the GDM
or configured owner UID.

The broker accepts a physical-console session only if the exact local trusted
entry has all required owner permissions:

```json
{
  "can_view": true,
  "can_control": true,
  "can_unattended_console": true
}
```

Unknown/revoked clients and normal screenshot-only trusted clients are denied.
Input is encrypted in the existing E2E session before relay forwarding. The
relay does not receive plaintext keystrokes or screen pixels. RivetLink does
not store, inspect or log the Ubuntu password.

## Install

Target: Ubuntu Desktop 24.04 LTS or newer, GNOME on Wayland, GDM, a permanent
HDMI dummy capable of the desired mode (1920×1080@60 is the supported
baseline), and Ethernet.

The supported installation path is in **RivetLink Application → Settings →
Ubuntu physical console**. Sign in to the selected relay in the app, confirm
the owner controller key, and select **Install and enable**. PolicyKit asks
once for the local Ubuntu administrator password to install the tightly scoped
system files. Device registration itself is performed by the app's existing
authenticated relay client: no relay token is copied, stored in a unit, passed
to `sudo`/`pkexec`, or supplied to a script.

The installer preserves an existing `/var/lib/rivetlink` identity and trust
store on update. It intentionally does not change GDM/PAM configuration or
enable auto-login. The repository script is a developer/incident-recovery
fallback only; it is not the end-user setup path.

The root-owned installer creates only:

```text
rivetlink-console-broker.service       non-root system broker
rivetlink-console-worker.service       global session unit for GDM/GNOME
/var/lib/rivetlink                     broker identity/configuration
/usr/local/lib/rivetlink/rivet-agent   installed agent binary
```

Check operation:

```bash
systemctl status rivetlink-console-broker
journalctl -u rivetlink-console-broker -b
journalctl _SYSTEMD_USER_UNIT=rivetlink-console-worker.service -b
```

After first installation, reboot once so GDM and the desktop receive the
`rivetlink-console` group. A normal subsequent reboot requires no local
command.

## Recovery and removal

The broker has `Restart=on-failure` with a 5-second backoff. Relay failures are
also retried in-process (1, 2, 4, 8, 16, then 30 seconds). A reboot closes the
remote control session; after GDM has started again the owner manually connects
again.

```bash
sudo ./scripts/uninstall-console-broker-ubuntu.sh
sudo ./scripts/uninstall-console-broker-ubuntu.sh --purge
```

`--purge` removes RivetLink's broker identity/trust data only; it does not
alter GDM, GNOME, PAM, display configuration or unrelated accounts.

## Hardware acceptance test

1. Shut the node down with only power, Ethernet and the HDMI dummy attached.
2. Boot it; do not attach a monitor, keyboard or mouse.
3. Wait for GDM and verify the broker appears online in RivetLink.
4. Request a screenshot and verify it is the real GDM screen shown by the
   HDMI dummy.
5. Focus the image in the RivetLink Application, click the user/password field
   and type normally. RivetLink sends physical key events, not a password
   credential.
6. Verify GDM signs in, then capture/input move to the normal GNOME desktop.
7. Lock, unlock and log out; verify the worker reconnects to the appropriate
   graphical session each time.
8. Reboot from GNOME. Verify the client shows Offline while rebooting, then
   Online/GDM after the broker and GDM worker return. Manually reconnect.

Do not use the old `rivetlink-headless-gnome.service` virtual-monitor setup for
this deployment; it captures a separate desktop and cannot show the real GDM
console.
