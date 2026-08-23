# RivetLink network security model

RivetLink is designed to carry display frames and generic keyboard/pointer events over an untrusted network. It does not treat a LAN, mDNS, DNS, a relay, or relay TLS as a substitute for endpoint identity verification.

## Scope and threat model

An attacker may observe, delay, drop, replay, reorder, modify and inject all network traffic, advertise fake mDNS records, operate a relay and know all public keys and protocol source. The attacker does not initially possess an approved client or host Ed25519 private key.

The relay can still observe metadata: the fact that a device is online, relay account/device/session identifiers, timing, IP addresses (unless separately protected), packet sizes and session duration. It must not learn display frames, pointer events or keyboard events, including LightDM passwords typed as generic input events.

## Trust roots and pairing

- An endpoint has a long-term **Ed25519** signing identity. The public part is not secret and cannot authenticate its holder.
- A host authorises an approved client key locally. It verifies a signature from that client during every trusted-key connection. Copying the approved public key without the private key is rejected.
- Direct LAN hosts are pinned by a saved identity key. Discovery only yields a route. The direct API rejects an absent host pin, and a saved LAN key can never be silently replaced.
- Relay hosts use HTTPS/WSS only. On the owner's first protected connection, the application records the host public key scoped to the relay and device. A changed key is a hard error until the owner explicitly removes/re-pairs the host. Initial TOFU remains a user decision: verify a new host fingerprint out-of-band when the network/relay is not already trusted.
- PIN pairing uses the existing balanced SPAKE2 implementation. The PIN is never sent as a raw network field. PINs are short-lived/host-controlled; it is not a replacement for long-term host pinning.

Private identities are stored in owner-only files through `secure_file` (directory mode `0700`, file mode `0600` on Unix). The Linux service identity owns the host files. They are not sent to the relay or logged. Native Keychain/DPAPI/Secure-Enclave storage is future defence-in-depth work and is not currently claimed by this model.

## Protocol version 2

All signed session and channel contexts include a domain string and version. Older relay/session versions are rejected rather than silently downgraded.

### Direct LAN trusted-key handshake

1. Client creates ephemeral **X25519** key `eC`; it signs `"rivetlink-authenticated-kex-v2" || client-binding || eC` with its Ed25519 key. `client-binding` contains `rivetlink-direct-v2`, version, role and client identity.
2. Host verifies the client signature against its local trusted-key store. It creates `eH` and signs the same domain plus `host-binding || eH`. `host-binding` includes host identity and a SHA-256 hash of the complete client KEX wire fields.
3. Client verifies that the host identity equals its pinned key and verifies the host signature.
4. Both derive `X25519(eC,eH)`, with a canonical transcript containing both identities and both complete KEX messages. The client and host exchange encrypted channel confirmations before application messages are accepted.

The signature binding prevents role, version and cross-session key substitution. The ephemeral X25519 secret provides forward secrecy for a recorded session if a long-term Ed25519 key is later compromised.

### Relay session handshake

1. Client authenticates to the relay over WSS, requests a session with `protocol_version = 2`, an approved device id, requested capability and its Ed25519 public identity.
2. The relay routes only between authenticated same-organisation session members. It is not trusted for payload confidentiality or endpoint identity.
3. Host verifies local client authorisation and signs an ephemeral X25519 key bound to `rivetlink-relay-v2`, relay-issued session id, `host` role and host identity. Client sends the equivalent `client`-role KEX binding.
4. The client verifies the host KEX against its persisted host pin. Both derive the channel from a canonical transcript consisting of protocol domain/version, session id, both identities and both complete signed KEX packets.

The relay can route or deny a session, but cannot create a valid endpoint KEX, derive its channel keys or decrypt sealed content.

### Device-to-relay authentication

Before a host agent connects, the relay sends a fresh 32-byte nonce. The agent signs `rivetlink-relay-device-auth-v2 || version || device-id || nonce`. The nonce is consumed by the single WebSocket handshake. This prevents a signature collected for one device or protocol from being reused as a device authentication proof.

## Sealed channel

`rivetlink_crypto::sealed::SealedChannel` uses:

- **HKDF-SHA-256** over the ephemeral shared secret and SHA-256 transcript hash;
- distinct client-to-host and host-to-client keys;
- **ChaCha20-Poly1305** AEAD;
- a versioned, strictly monotonic 64-bit sequence as nonce material;
- the wire header and transcript hash as AEAD associated data.

The encrypted wire form is `version || sequence_be || ciphertext`. A receiver accepts exactly the expected sequence; duplicates, gaps and reordering fail before message parsing. Sequence exhaustion is a hard error and requires a fresh handshake. Tampering and truncated ciphertext fail AEAD verification.

## Operational limits

Unauthenticated LAN sockets have bounded concurrent-session slots and a bounded handshake timeout. Framing has explicit size limits before capture or input handling. Authentication occurs before expensive capture work. Input is only accepted from a capability-authorised session and only after sealed channel decryption; it is neither logged nor persisted by RivetLink.

Revoking a client removes its trusted key; later connections fail. Hosts should additionally close active sessions when revoking a device as an operational response to loss/theft.

## Verification status and limits

The Rust test suite includes regressions for copied-public-key impersonation, forged/changed host identity, transcript mismatch, replay, packet reordering, reflection, tampering, truncation, secure relay URL enforcement, relay-version downgrade rejection, local trust policy and protocol JSON property tests.

This document describes the current implementation, not a substitute for an independent cryptographic review or penetration test. In particular, users must protect local private-key storage, verify a first-use host fingerprint by an independent channel where the relay is not trusted, and use a valid certificate-backed HTTPS/WSS relay. Subject to those conditions, RivetLink v2's content channel is designed for hostile public Wi-Fi without requiring a VPN; a VPN remains useful for metadata and network-layer privacy.
