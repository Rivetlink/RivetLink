# Ubuntu physical-console broker (GDM + HDMI dummy)

This is RivetLink's unattended Ubuntu design for a permanently connected HDMI
dummy/EDID emulator. It captures the actual seat0 monitor owned first by GDM
and then by the normal GNOME desktop; it does **not** start a separate virtual
GNOME monitor and does not enable automatic Ubuntu login.

## Security boundary

`rivetlink-console-broker.service` runs as the dedicated, non-login
`rivetlink` system account. It owns device identity, trusted-controller policy
and the selected network transports, but has no session D-Bus address and
cannot capture or inject input itself.

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
Input is encrypted in the existing E2E session before relay forwarding or in
the authenticated direct-LAN channel. The relay does not receive plaintext
keystrokes or screen pixels; direct LAN does not contact the relay at all.
RivetLink does not store, inspect or log the Ubuntu password.

## Transports

The physical-console broker has one GDM/GNOME capture and input source with
two independent routes to it:

```text
trusted client ── encrypted direct LAN ──┐
                                         ├─ physical-console broker ─ seat0 worker ─ GDM/GNOME
trusted client ── E2E relay ciphertext ──┘
```

Both routes may be enabled together. LAN mode listens on `0.0.0.0:47823` by
default and advertises `_rivetlink._tcp.local` with the host public key and the
`physical-console` mode. Discovery is not authorization: a LAN client must pin
that advertised host key, complete the signed direct handshake, and match a
local trusted entry with the permissions above. There is no PIN, TOFU, account
or relay fallback for the pre-login LAN listener. Restrict TCP/47823 to trusted
LAN interfaces with your normal firewall if the node has untrusted interfaces.

Relay mode needs the existing registered device id and relay endpoints. A
LAN-only install has neither requirement and starts even when DNS, internet or
the relay is unavailable. Existing installations default to relay-only on
upgrade; LAN exposure is enabled only by an explicit owner action.

## Install

Target: Ubuntu Desktop 24.04 LTS or newer, GNOME on Wayland, GDM, a permanent
HDMI dummy capable of the desired mode (1920×1080@60 is the supported
baseline), and Ethernet.

The supported installation path is **RivetLink Application → Settings → Ubuntu
physical console**. Confirm the owner controller key and select one or both:

- **Local network**: no relay selection, account, token or internet is needed.
- **Via relay**: select a relay and sign in; registration uses the app's
  authenticated relay session.

PolicyKit asks once for the local Ubuntu administrator password to install the
tightly scoped system files. No relay token is copied, stored in a unit, passed
to `sudo`/`pkexec`, or supplied to a script. When both routes are selected the
same host identity and trusted-client file serve both; this does not create a
second virtual desktop or second capture service.

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
sudo ufw allow in on enp1s0 to any port 47823 proto tcp  # only if UFW is enabled; use your LAN NIC
```

After first installation, reboot once so GDM and the desktop receive the
`rivetlink-console` group. A normal subsequent reboot requires no local
command.

## Recovery and removal

The broker has `Restart=on-failure` with a 5-second backoff. Relay failures are
also retried in-process (1, 2, 4, 8, 16, then 30 seconds); they never stop the
LAN listener. A failed LAN listener retries independently every five seconds
and never stops relay access. A reboot closes the remote control session; after
GDM has started again the owner manually connects again.

```bash
sudo ./scripts/uninstall-console-broker-ubuntu.sh
sudo ./scripts/uninstall-console-broker-ubuntu.sh --purge
```

`--purge` removes RivetLink's broker identity/trust data only; it does not
alter GDM, GNOME, PAM, display configuration or unrelated accounts.

## Owner hardware acceptance checklist

1. Shut the node down with only power, Ethernet and the HDMI dummy attached.
2. Boot it; do not attach a monitor, keyboard or mouse.
3. Configure **Local network** only, disable internet while retaining Ethernet
   LAN, then wait for GDM and discover the host in RivetLink's Local network
   tab. It must appear without a relay account or server.
4. Open its **Physical console · Local network** view and verify it is the real GDM screen shown by the
   HDMI dummy.
5. Focus the image in the RivetLink Application, click the user/password field
   and type normally. RivetLink sends physical key events, not a password
   credential.
6. Verify GDM signs in, then capture/input move to the normal GNOME desktop.
7. Lock, unlock and log out; verify the worker reconnects to the appropriate
   graphical session each time.
8. Reboot from GNOME. Verify the LAN client cannot remain falsely connected,
   then discovers/reaches GDM again after the broker and GDM worker return.
9. Enable both Local network and Via relay. On the LAN verify the Local network
   route; from outside the LAN verify the relay route to the same GDM, then
   repeat login, lock/unlock and logout on each route.

The owner, not CI, must run this real HDMI-dummy/GDM checklist. Automated tests
cover the configuration, authenticated direct handshake and state machine but
cannot emulate Mutter owning a physical seat in CI.

Do not use the old `rivetlink-headless-gnome.service` virtual-monitor setup for
this deployment; it captures a separate desktop and cannot show the real GDM
console.
