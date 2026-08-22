# GNOME Remote Login: RivetLink integration boundary

## Finding

GNOME supports pre-login remote access, but its current implementation is not
a reusable compositor API for arbitrary remote-control protocols. It is a
complete GNOME Remote Desktop (GRD) **RDP** implementation:

1. GRD's system daemon accepts an incoming RDP connection.
2. Only then it calls GDM's `RemoteDisplayFactory.CreateRemoteDisplay` for a
   separate, headless remote greeter—not the HDMI-backed physical `seat0`.
3. GRD creates a per-logind-session `org.gnome.RemoteDesktop.Rdp.Handover`
   object, redirects the RDP client, and passes that exact RDP socket by Unix
   file descriptor to GRD's handover daemon.
4. GRD's own RDP renderer and input implementation own the PipeWire frames,
   pointer/keyboard handling, and post-authentication handoff.

The relevant upstream source makes the boundary explicit:

- [GRD creates a remote display only from `incoming-new-connection`](https://github.com/GNOME/gnome-remote-desktop/blob/main/src/grd-daemon-system.c#L689-L712).
- [The system daemon's remote client stores an RDP session and socket](https://github.com/GNOME/gnome-remote-desktop/blob/main/src/grd-daemon-system.c#L47-L66).
- [The handover API transfers the connected socket by file descriptor](https://github.com/GNOME/gnome-remote-desktop/blob/main/src/grd-daemon-system.c#L151-L182).
- [GRD sends an RDP server redirection during the handoff](https://github.com/GNOME/gnome-remote-desktop/blob/main/src/grd-daemon-system.c#L324-L405).
- [GDM's RemoteDisplayFactory definition](https://github.com/GNOME/gdm/blob/main/daemon/gdm-remote-display-factory.xml) and [RemoteDisplay model](https://github.com/GNOME/gdm/blob/main/daemon/gdm-remote-display.xml) expose lifecycle, not raw capture/input streams.

The observed physical-GDM errors—`Session creation inhibited` for ordinary
Mutter sessions and `Saving to disk is disabled` for screenshots—are therefore
expected. They must not be bypassed.

## Decision

RivetLink does **not** create a GDM RemoteDisplay or run a root helper in a
normal installation. Although a helper could request the lifecycle object, it
would not obtain an upstream-supported raw PipeWire/input channel. Doing so
would leave RivetLink guessing at private GRD/Mutter internals and could expose
the protected GDM surface incorrectly.

The supported, safe current behavior is:

- preserve RivetLink LAN/relay encryption and trusted-device policy;
- use native non-AppImage broker/worker services for DesktopReady;
- show a stable, non-sensitive pre-login-unavailable error at physical GDM;
- never persist screenshots, relax GDM/AppArmor, or expose RDP/VNC.

## Viable future product choices

There is no small public API integration to implement today. A future feature
requires one of these deliberate product decisions:

1. **Upstream GNOME API:** collaborate with GNOME to expose a documented,
   authorization-scoped local frame/input interface for a remote display that
   is independent of RDP. This is the preferred route.
2. **Explicit GRD/RDP integration:** use GNOME Remote Desktop as the remote
   login backend and implement a carefully maintained protocol bridge inside
   RivetLink. This would depend on GRD's RDP authentication, socket handover,
   redirection, rendering and lifecycle semantics; it is not merely a system
   D-Bus helper and needs a separate security/product review before work starts.

Neither option permits capturing the existing physical GDM `seat0` surface.

## Real-machine verification of the current safe boundary

1. Reboot Ubuntu with only power, Ethernet and the HDMI dummy attached.
2. Do not log in locally. Confirm the broker reports `state=GdmLogin`.
3. Connect from a trusted RivetLink device. Confirm it reports pre-login
   capture unavailable without creating files or an endless loading state.
4. Confirm no relevant AppArmor denial appears:

   ```bash
   sudo journalctl -k -b --since '10 minutes ago' \
     | grep -Ei 'apparmor.*DENIED.*(rivetlink|console.sock)|unprivileged_userns'
   ```

5. Log in normally, then confirm `DesktopReady` capture and input work through
   both Local network and Relay as configured.

This is documentation of an upstream limitation, not a claim that CI has
tested a real GDM compositor.
