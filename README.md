# RivetLink

Zero-trust remote-control platform in Rust. Self-hosted, end-to-end encrypted,
post-quantum-ready. The relay server only routes ciphertext — **the host device
decides who connects**, never the server.

> Status: early. The secure session pipeline works end to end (auth, device
> identity, host consent, signed key exchange, E2E-encrypted transfer). The
> current capture path delivers **on-demand screenshots**; live video and input
> injection are the next milestones.

## Components

| Binary         | Crate                | Role                                                        |
| -------------- | -------------------- | ----------------------------------------------------------- |
| `rivet-relay` | `rivetlink-server`  | Signaling/relay server (Axum + Postgres + Redis). Untrusted. |
| `rivet-agent` | `rivetlink-agent`   | Runs on the **host** (the machine being viewed).            |
| `rivet-client`| `rivetlink-client`  | The **support client** (the machine doing the viewing).     |

Shared crates: `rivetlink-core` (types), `rivetlink-protocol` (wire format),
`rivetlink-crypto` (Ed25519/x25519, ChaCha20-Poly1305, ML-KEM/ML-DSA).

## How a session works

```
client                         relay (untrusted)                 host agent
  │  POST /auth/login ───────────▶│                                   │
  │  GET  /devices  ◀─────────────│                                   │
  │  WS AUTH(jwt) ───────────────▶│◀──── WS DEVICE_HELLO + sig ───────│  (device challenge-response)
  │  SessionRequest(client_pk) ──▶│──── enriched w/ session_id ──────▶│
  │                               │            host checks trusted    │
  │                               │            store → prompt/accept  │
  │  ◀── SessionAccepted ─────────│◀──────────────────────────────────│
  │  ◀── SessionKeyExchange ──────│◀── signed ephemeral x25519 ───────│
  │  ─── SessionKeyExchange ─────▶│─── signed ephemeral x25519 ──────▶│
  │            (both derive a ChaCha20-Poly1305 sealed channel)        │
  │  ScreenshotRequest ──────────▶│──────────────────────────────────▶│  capture
  │  ◀── ScreenshotData (chunks) ─│◀──── sealed PNG, chunked ─────────│
  │       decrypt + open                                              │
```

Ephemeral keys are **signed by each side's long-term identity**, so a malicious
relay cannot man-in-the-middle the session. The relay never sees plaintext.

## Quickstart (LAN)

Run the relay on one machine (e.g. your Linux box), the host agent on the
machine you want to view (e.g. a MacBook), and the client wherever you are.
Both ends just need to reach the relay's IP on the LAN.

### 1. Start the relay

```bash
cd RivetLink
# generates .env with a random JWT_SECRET
cargo run --bin rivet-relay -- init

# bring up postgres + redis + relay
docker compose -f docker/docker-compose.yml --profile relay up -d --build
# (or run the relay natively: cargo run --bin rivet-relay -- serve)
```

The relay listens on `:8080`. Note your LAN IP (e.g. `192.168.1.50`).

### 2. Create a user

```bash
curl -X POST http://192.168.1.50:8080/auth/register \
  -H 'content-type: application/json' \
  -d '{"email":"me@example.com","password":"a-good-password","display_name":"Me","organization_name":"Home"}'
```

Log in later to get an access token (the host install needs one once):

```bash
curl -X POST http://192.168.1.50:8080/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"me@example.com","password":"a-good-password"}'
```

### 3. Install the host (on the MacBook)

```bash
./scripts/install-host-macos.sh \
  --relay-host 192.168.1.50:8080 \
  --token <access-token-from-login>
```

This builds `rivet-agent`, generates its keys, registers the device, and
installs a launchd service. **macOS will ask for Screen Recording permission**
the first time `screencapture` runs — grant it in
System Settings → Privacy & Security → Screen Recording.

### 4. Connect from the client

```bash
cargo run --bin rivet-client -- init \
  --relay-ws-url   ws://192.168.1.50:8080/ws \
  --relay-http-url http://192.168.1.50:8080

cargo run --bin rivet-client -- devices --email me@example.com --password a-good-password
cargo run --bin rivet-client -- view \
  --email me@example.com --password a-good-password \
  --device <device-id-from-the-list>
```

On the **first** connection the host prompts its operator to approve your
client (trust on first use). Approve it once and the host remembers your key.

## Trust model

- The **host** keeps its own `trusted_clients.json` and makes every admit/deny
  decision. The relay is never consulted for trust.
- Unknown client → operator prompt. Known client → silent admit.
- Pre-trust without a prompt by adding the client's public key (from
  `rivet-client whoami`) to the host's `keys/trusted_clients.json`.

## Deploying the relay to a VPS

1. Point DNS at the VPS, terminate TLS at nginx (see `docker/nginx/`), proxy to
   the relay on `:8080` (WebSocket upgrade enabled).
2. `rivet-relay init` to generate a strong `JWT_SECRET`, or set it via the
   compose `environment:`.
3. `docker compose --profile relay up -d --build`.
4. Clients/hosts use `wss://relay.example.com/ws` and
   `https://relay.example.com`. (The agent/client REST currently speaks plain
   HTTP — put them behind the same nginx, or keep them on the LAN until TLS
   client support lands.)

## Ubuntu unattended physical console

For an Ubuntu Desktop Home Node, use a permanent HDMI dummy/EDID emulator and
the App's **Settings → Ubuntu physical console** installation flow. It installs
a non-root system broker before login plus a narrow worker in GDM/GNOME's real
seat0 session. Choose direct authenticated **Local network**, **Via relay**, or
both: LAN needs no server/account/internet; relay registration uses the current
signed-in app session and never copies a token to a script or service. It does
not enable auto-login, RDP/VNC, shell or file access. See [the physical-console
guide](docs/ubuntu-physical-console-broker.md).

## Development

```bash
cargo test --workspace -- --test-threads=1   # all tests (needs docker pg+redis for integration)
cargo clippy --workspace --all-targets        # lints (must be clean)
./scripts/e2e-demo.sh                          # full pipeline on one machine (headless)
```
