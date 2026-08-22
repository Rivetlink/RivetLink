# Ubuntu physical-console broker (GNOME + optional LightDM login)

RivetLink's Ubuntu console captures and controls the real HDMI-backed GNOME
desktop after normal login. It never creates a virtual desktop or enables
Ubuntu auto-login.

## GDM boundary

Stock GNOME/Mutter intentionally rejects third-party `ScreenCast` and
`RemoteDesktop` sessions for the existing physical GDM or locked `seat0`
display when that greeter is Wayland. RivetLink never weakens that boundary:
no AppArmor changes, permissive socket permissions, screenshot files, or
Mutter/GDM policy bypasses.

Ubuntu's GDM 50 packaging deliberately disables its X11 greeter and removes
the Xorg dependency. `WaylandEnable=false` is therefore not a supported fix.
GDM also passes display-server capabilities into `GDM_SUPPORTED_SESSION_TYPES`,
so changing its display backend can remove normal Wayland session choices. See
[GDM's local display source](https://github.com/GNOME/gdm/blob/main/daemon/gdm-local-display-factory.c),
[the session-type export](https://github.com/GNOME/gdm/blob/main/daemon/gdm-launch-environment.c),
and [Ubuntu's GDM 49+ packaging change](https://bugs.launchpad.net/ubuntu-desktop-provision/%2Bbug/2125133/comments/11).

## Optional LightDM X11 login mode

RivetLink offers a **separate, explicit owner opt-in** for a local LightDM X11
greeter. It is never enabled by normal physical-console setup or by an update.
The design is:

```text
LightDM X11 greeter → RivetLink X11 capture/input → normal PAM login
                                                     ↓
                                      Ubuntu GNOME Wayland session
                                                     ↓
                                     existing Mutter/PipeWire backend
```

LightDM has native Wayland-session routing: it loads session entries from
`/usr/share/wayland-sessions` and starts them with `XDG_SESSION_TYPE=wayland`.
See [LightDM's documented feature set](https://github.com/ubuntu/lightdm),
[its Wayland-session release note](https://github.com/ubuntu/lightdm/blob/main/NEWS),
and [the session routing source](https://github.com/ubuntu/lightdm/blob/main/src/seat.c).
Thus the greeter can be X11 while the authenticated existing Ubuntu GNOME
session remains Wayland. This is statically preflighted but must be verified on
the actual GPU/Ubuntu installation; CI does not claim to test a real greeter.

Before altering the next-boot display-manager selection, RivetLink requires:

- Ubuntu Desktop 24.04+;
- a connected DRM/HDMI display (the HDMI dummy counts);
- the current native `rivet-agent` with the LightDM launcher;
- available `lightdm`, `lightdm-gtk-greeter`, and `xserver-xorg-core` packages;
- an existing `ubuntu.desktop` or `gnome.desktop` Wayland session that starts
  `gnome-session`;
- a current display-manager selection that can be backed up.

Setup records root-only rollback metadata, installs the minimum packages,
writes a single RivetLink LightDM override, and selects LightDM
non-interactively for the **next reboot**. It deliberately does not stop or
replace the currently running graphical session.

The override selects `lightdm-gtk-greeter`, sets `xserver-allow-tcp=false`,
and chooses the existing Ubuntu GNOME Wayland session. It does not enable
XDMCP, VNC, RDP, `xhost`, auto-login, or another desktop environment.

The LightDM root hook only discovers its own exact `lightdm` greeter process
and then drops to that account before spawning the normal X11 worker. It does
not capture or inject input as root, proxy arbitrary D-Bus, or accept remote
requests. That worker accepts only a local `DISPLAY` (`:N`) and its own regular
`XAUTHORITY` cookie. Capture uses X11 `GetImage` and in-memory PNG encoding;
input uses local XTEST. No frame, key, or password is persisted or logged.

## Security and service layout

```text
trusted RivetLink client ─ LAN or E2E relay ─ non-root broker ─ local worker ─ display
```

- The broker runs as the dedicated non-login `rivetlink` account.
- The broker socket remains restrictive and validates `SO_PEERCRED`; the
  LightDM worker UID is added only by the explicit LightDM setup.
- Unknown/revoked devices and trusted devices without `can_view`, `can_control`
  and `can_unattended_console` never reach a worker.
- The interactive AppImage is never a service executable. Setup atomically
  installs the matching native agent at `/usr/local/lib/rivetlink/rivet-agent`.
- LAN and relay use the same broker authorization and capture/input protocol.

## Owner verification

Before enabling the checkbox **Enable LightDM X11 login screen for remote
pre-login access**, confirm SSH or physical recovery is available.

1. Reboot after the explicit setup; do not log in locally.
2. Check the intended greeter:

   ```bash
   cat /etc/X11/default-display-manager
   sudo systemctl status lightdm --no-pager -l
   ps -eo user,args | grep -E '[X]org|[l]ightdm-gtk-greeter'
   sudo journalctl -u rivetlink-console-broker.service -b -o cat --no-pager
   ```

3. From an already trusted RivetLink device, connect over LAN and then relay.
   Verify the real LightDM greeter, pointer movement, clicks, password typing,
   and Enter. RivetLink does not store or inspect the password.
4. After authentication, run `echo $XDG_SESSION_TYPE`; it must report
   `wayland`. Verify RivetLink changes worker generation and continues capture
   and input. Log out and verify it returns to LightDM.
5. Confirm no unexpected AppArmor denial appears:

   ```bash
   sudo journalctl -k -b --since '10 minutes ago' \
     | grep -Ei 'apparmor.*DENIED.*(rivetlink|console.sock)|unprivileged_userns'
   ```

## Rollback and SSH recovery

Use **Restore GDM for next reboot** in Settings, then reboot. It restores the
saved display-manager selection and broker allow-list, removes only RivetLink's
LightDM override, and intentionally leaves packages installed.

If the graphical login fails but SSH works, run the installed RivetLink
executable with its fixed privileged restore entry point, then reboot:

```bash
sudo /path/to/RivetLink.AppImage --rivetlink-console-lightdm-restore
sudo reboot
```

If the application executable itself is unavailable, remove only RivetLink's
override and restore GDM with Ubuntu's package configuration:

```bash
sudo rm -f /etc/lightdm/lightdm.conf.d/90-rivetlink-unattended-console.conf
sudo dpkg-reconfigure gdm3
sudo systemctl daemon-reload
sudo reboot
```

Wayland GDM and locked physical sessions remain clearly unavailable rather
than spinning or attempting a security-policy workaround.
