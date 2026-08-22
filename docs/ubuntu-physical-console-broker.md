# Ubuntu physical-console broker (GDM + HDMI dummy)

This is RivetLink's Ubuntu design for a permanently connected HDMI dummy/EDID
emulator. It captures and controls the actual seat0 monitor after the normal
GNOME desktop is logged in; it does **not** start a separate virtual GNOME
monitor or enable automatic Ubuntu login.

> **Important platform boundary:** stock GNOME/Mutter deliberately does not
> permit a third-party process to capture or inject input into the existing
> physical GDM/locked display. RivetLink detects that state before it requests
> a Mutter session and returns a stable non-sensitive error. This is intentional
> and is not fixed by changing Unix-socket ACLs, AppArmor, or service users.

GNOME's supported pre-login feature is **Remote Login**, but it is materially
different from a physical-console viewer: its privileged system dispatcher asks
GDM to create a separate **headless RemoteDisplay**, then hands an **RDP**
connection from that display to a headless user session after login. It neither
captures nor controls the real HDMI-backed `seat0` greeter. RivetLink does not
enable, expose, or impersonate that RDP service because doing so would violate
the physical-seat and no-RDP requirements of this deployment. See GNOME's
[Remote Desktop source README](https://github.com/GNOME/gnome-remote-desktop/blob/main/README.md),
its [remote-login design discussion](https://discourse.gnome.org/t/persistent-remote-desktop-access-api/19415/2),
and Mutter's [RemoteAccessController API](https://gnome.pages.gitlab.gnome.org/mutter/meta/class.RemoteAccessController.html).

## Security boundary

`rivetlink-console-broker.service` runs as the dedicated, non-login
`rivetlink` system account. It owns device identity, trusted-controller policy
and the selected network transports, but has no session D-Bus address and
cannot capture or inject input itself.

`rivetlink-console-worker.service` runs only inside the existing graphical GDM
or GNOME systemd user session. Ubuntu may name its greeter account
`gdm-greeter` rather than `gdm`; the installer detects and allow-lists each
installed GDM account. The GDM worker is limited to reporting the authenticated
`GdmLogin` state and performs **no** capture or input attempt. The normal GNOME
worker gets the session's Mutter ScreenCast access, but has no relay credential
and exposes only a length-bounded Unix socket protocol for in-memory PNG
capture and normalized pointer, scroll or key events. It never asks GNOME Shell
to save a screenshot, creates no image file, does not relax Mutter/AppArmor
policy, and does not open a portal chooser. The socket is `0660`, belongs to
the private `rivetlink-console` group, and broker-side peer credentials must
match the GDM or configured owner UID.

The interactive desktop AppImage is never used as either service executable.
During setup its separately bundled native `rivet-agent` is installed as a
root-owned executable at `/usr/local/lib/rivetlink/rivet-agent` using an
atomic replacement; both the broker and worker execute that same file directly.
This keeps the broker/worker pair on one version while leaving the GUI AppImage
for normal desktop use. In particular, the worker does not enter AppImage's
unprivileged user-namespace runtime, so normal operation needs no AppArmor
exception, relaxed user-namespace policy, or weaker Unix-socket permissions.

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

The physical-console broker has one GDM/GNOME state source and a GNOME capture
and input source with
two independent routes to it:

```text
trusted client ── encrypted direct LAN ──┐
                                         ├─ physical-console broker ─ seat0 worker ─ GNOME desktop
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

Every RivetLink Application update also carries its matching native service
agent. On the next launch, the desktop app compares that bundled agent with
`/usr/local/lib/rivetlink/rivet-agent`. If they differ, it asks only for the
normal PolicyKit authorization and invokes a narrow agent-update helper. That
helper atomically replaces the agent, restarts the broker only when it was
already active, and the app restarts the current session worker. It does not
ask for a controller key again and does not alter the identity, trusted clients,
LAN/relay settings, or service-unit contents. A disabled physical console stays
disabled while its agent is updated, ready for the next explicit enable.

The comparison is exact file content, rather than the agent's display version,
so a stale service executable cannot silently remain behind a successful
desktop update. The former extracted-AppImage service runtime is not a service
path any more and is removed by the explicit uninstall operation.

Check operation:

```bash
systemctl status rivetlink-console-broker
journalctl -u rivetlink-console-broker -b
journalctl _SYSTEMD_USER_UNIT=rivetlink-console-worker.service -b
systemctl cat rivetlink-console-broker.service
systemctl --user cat rivetlink-console-worker.service
sudo journalctl -k -b | grep -Ei 'apparmor.*DENIED.*rivetlink|unprivileged_userns'
sudo ufw allow in on enp1s0 to any port 47823 proto tcp  # only if UFW is enabled; use your LAN NIC
```

Both `ExecStart` values must name `/usr/local/lib/rivetlink/rivet-agent`, not
`AppRun`. With Ubuntu's restricted unprivileged-user-namespace profile, the
kernel log must contain no AppArmor `DENIED` connection to
`/run/rivetlink/console.sock` after the worker starts.

To check that the installed native agent is the one from the current RivetLink
Application build, open **Settings → Ubuntu physical console**: its service
agent badge must read **Native** and the broker badge **Running**. From a
terminal, the broker and worker command lines must both contain
`/usr/local/lib/rivetlink/rivet-agent`; do not use the agent's `--version`
output as the compatibility check because the installer compares the exact
bundled binary instead.

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
4. Open its **Physical console · Local network** view. At `state=GdmLogin`,
   verify RivetLink shows the supported-GNOME-API error rather than spinning,
   saving an image, or attempting to create a RemoteDesktop session.
5. Log in normally at the physical console, then connect in RivetLink and
   verify capture and normalized mouse/keyboard input on the real GNOME
   desktop.
6. Lock and log out. Verify the active worker changes state and that RivetLink
   safely reports GDM/locked capture as unavailable instead of bypassing it.
7. Reboot from GNOME. Verify the LAN client cannot remain falsely connected,
   then discovers the node again after the broker and GDM worker return.
8. Enable both Local network and Via relay. On the LAN verify the Local network
   route; from outside the LAN verify relay capture/input for the logged-in
   GNOME desktop.
9. On an Ubuntu installation with restricted unprivileged user namespaces,
    restart both units. Verify the worker stays active, the broker reports an
    active graphical worker, and the kernel journal contains no AppArmor denial
    for `/run/rivetlink/console.sock`.
10. Before and after this test, verify that no RivetLink screenshot images were
    created under `/run/user/*`, `/tmp`, or `/var/tmp`; GDM frame data must stay
    out of RivetLink entirely, and GNOME frame data must remain in the active
    worker and encrypted RivetLink session only.

The owner, not CI, must run this real HDMI-dummy/GDM checklist. Automated tests
cover the configuration, authenticated direct handshake and state machine but
cannot emulate Mutter owning a physical seat in CI.

If physical pre-login access is required, use a dedicated hardware IP-KVM with
HDMI capture and USB HID emulation. It is outside the host OS boundary and can
show/control the physical display without weakening GDM or pretending that a
headless GNOME Remote Login display is seat0. Do not use the old
`rivetlink-headless-gnome.service` virtual-monitor setup for this deployment;
it captures a separate desktop and cannot show the real GDM console.
