# Ubuntu Desktop headless screenshot host

This guide installs the first RivetLink Linux Host phase: a non-root,
reboot-persistent Ubuntu Desktop host that serves **only on-demand encrypted
screenshots**. It deliberately does not enable video, keyboard/mouse input,
shell access, file transfer, RDP, or any other control interface.

## Supported architecture

Target Ubuntu Desktop **24.04 LTS or newer** with GNOME on Wayland. The
installer starts a dedicated GNOME Shell/Mutter user service with:

```text
gnome-shell --headless --virtual-monitor 1920x1080
```

This is Mutter's Wayland headless virtual-monitor mode, not Xvfb, a dummy-Xorg
driver, or a physical HDMI emulation. RivetLink starts the compositor and its
own agent under the same non-root user and systemd user manager. The agent uses
Mutter's ScreenCast D-Bus service and PipeWire only to obtain one frame from
that virtual monitor, then encodes the PNG in memory. No plaintext screenshot
is written to disk or sent to the relay.

The captured desktop is this **dedicated virtual GNOME Shell session**, not an
existing physical-console or GDM session. It is persistent while its user
service runs, including after reboot because `loginctl enable-linger` keeps the
user manager alive without an interactive login. A physical HDMI dummy plug is
therefore unnecessary; it can still be used for a separate physical-console
workflow.

GNOME's own RDP sharing/Remote Login is not enabled or required. This avoids
introducing a second remote-control endpoint with credentials outside
RivetLink's trust model.

## Install

### RivetLink AppImage (recommended)

Install and open the RivetLink AppImage on the intended Ubuntu Desktop user
account. Add and select the relay under **Servers**, then open
**Settings → General → Headless Ubuntu-host** and choose **Headless host
instellen**. The visible confirmation dialog asks for:

- a Home Node name and virtual-monitor resolution;
- a one-time device-registration token for the selected relay; and
- Ubuntu's normal PolicyKit/system password prompt to install the required
  packages and enable user lingering.

The token is used once for registration and is never saved or put in a log.
The app pre-trusts only this AppImage user's existing RivetLink client identity
for screenshot viewing. It writes a user service whose executable is the
AppImage itself with an internal screenshot-agent argument. Consequently a
normal signed AppImage update continues to use the updated AppImage at its
stable path. An app update **never** starts this setup or changes trust on its
own; it only exposes the setup option for an owner to confirm.

The setup is shown only on Ubuntu Desktop 24.04 LTS or newer. It may ask for
the system password multiple times, depending on the local PolicyKit policy.
Neither long-lived service runs as root.

### CLI fallback

For automated provisioning, run the following **as the intended Ubuntu desktop
user, not root**, from the root of the `RivetLink` repository. First obtain the
support client's public identity on the client machine:

```bash
rivet-client --config client.json whoami
```

Then install on the Ubuntu Home Node. The default requires HTTPS/WSS; use
`--insecure-http` only for an isolated trusted-LAN development relay.

```bash
./scripts/install-host-ubuntu.sh \
  --relay-host relay.example.com \
  --token '<one-time registration access token>' \
  --trusted-client-key '<base64 value from whoami>' \
  --trusted-client-name 'Owner laptop'
```

The installer installs only the needed Ubuntu packages (`gnome-shell`, PipeWire
and GStreamer PipeWire tools), writes config/keys/trust data with owner-only
permissions, registers the device, and enables these user services:

```text
rivetlink-headless-gnome.service  dedicated virtual Wayland monitor
rivetlink-agent.service            RivetLink screenshot-only host
```

It invokes `sudo` only for package installation and `loginctl enable-linger`.
Neither service runs as root. The registration token is used once and is not
stored.

For a different virtual resolution, pass for example `--resolution 2560x1440`.
The agent caps the current screenshot capture path to a 1920×1080 bounding box
to keep an on-demand screenshot bounded; higher-resolution streaming is out of
scope for this phase.

## Trust and headless consent

The host's local `keys/trusted_clients.json` is authoritative. A client is
eligible only if its exact Ed25519 key is present with `can_view: true`.
Headless acceptance also requires this explicit owner-controlled config:

```json
"headless": {
  "enabled": true,
  "allow_trusted_clients": true
}
```

The installer creates it only after receiving `--trusted-client-key`. To add a
client later, run locally on the host:

```bash
~/.rivetlink/bin/rivet-agent --config ~/.rivetlink/agent.json trust-client \
  --public-key '<base64 key from rivet-client whoami>' \
  --name 'Second owner laptop'
```

That command grants screenshot viewing only; it never grants control. Unknown
keys, known keys without `can_view`, malformed identities, or a missing owner
opt-in are rejected without a prompt and without creating trust. There is no
headless `--auto-accept` option.

## Operation and recovery

```bash
systemctl --user status rivetlink-headless-gnome rivetlink-agent
journalctl --user -u rivetlink-headless-gnome -u rivetlink-agent -f
systemctl --user restart rivetlink-headless-gnome rivetlink-agent
```

After a reboot, wait for network connectivity then check the same status
commands. The agent reconnects to the relay and presents its existing device
identity. The normal client flow remains:

```bash
rivet-client --config client.json view \
  --email you@example.com --password '<password>' \
  --device '<device id>' --out screenshot.png --no-open
```

RivetLink keeps its existing device challenge-response, signed ephemeral key
exchange and ChaCha20-Poly1305 sealed channel. The PNG is sealed before
chunking/relay routing. Logs record requests, accept/reject decisions and
capture failures, but never screenshot contents, access tokens, private keys or
session keys.

## Limits and troubleshooting

Headless screenshots have a 10-second capture timeout, a 2-second minimum
interval per encrypted session and an 8 MiB post-encoding size limit. A failed
or missing virtual display returns an error to the authorized client; it does
not crash the agent or fall back to an unrelated X11 display.

If the virtual monitor is unavailable, inspect:

```bash
journalctl --user -u rivetlink-headless-gnome -b
journalctl --user -u rivetlink-agent -b
```

Confirm that this is a supported Wayland GNOME desktop and that the required
packages are installed:

```bash
command -v gnome-shell gst-launch-1.0 timeout
systemctl --user is-active rivetlink-headless-gnome
```

If PipeWire/GStreamer reports an error, reinstall
`gstreamer1.0-tools gstreamer1.0-pipewire` and restart both services. Do not
replace this with Xvfb or a globally enabled RDP service: those are outside the
supported security boundary for this phase.

## Uninstall

```bash
./scripts/uninstall-host-ubuntu.sh          # removes services, keeps identity
./scripts/uninstall-host-ubuntu.sh --purge  # also deletes local keys/trust data
```

`--purge` is deliberate and irreversible for the local identity. The relay's
device record is not deleted; remove it through the relay/API when appropriate.

## Follow-up phases

Live video, WebRTC transport, input injection, clipboard, files, shell access,
and broader host privileges are expressly excluded. Each requires a separate
security and consent review before implementation.
