//! Direct LAN sessions — connect host↔client without a relay.
//!
//! Two peers on the same network establish an end-to-end encrypted channel
//! over a plain byte stream (a TCP socket, in practice). Authentication is one
//! of:
//!
//! - **Key (TOFU)** — the client presents its Ed25519 identity; the host
//!   decides whether to trust it (a trusted-keys store or an operator prompt).
//!   The signed ephemeral key exchange is MITM-proof.
//! - **Password (PAKE)** — a shared PIN authenticates the channel via SPAKE2,
//!   with an explicit confirmation step so a wrong PIN fails the handshake.
//!
//! The functions here are transport-agnostic: they work over any
//! `AsyncRead + AsyncWrite`, so the same logic drives a real socket in
//! production and an in-memory pipe in tests. Wiring to TCP + mDNS discovery is
//! the next layer.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use rivetlink_crypto::handshake;
use rivetlink_crypto::pake;
use rivetlink_crypto::sealed::{ChannelRole, SealedChannel};

use crate::error::{SdkError, SdkResult};
use crate::identity::Identity;

/// Upper bound on a single handshake frame — handshakes are tiny.
const MAX_FRAME: usize = 16 * 1024;
/// Wire protocol version. Older handshakes are rejected rather than silently
/// downgrading the authenticated transcript.
const DIRECT_PROTOCOL_VERSION: u16 = 2;
const DIRECT_DOMAIN: &[u8] = b"rivetlink-direct-v2";
/// Plaintext both sides seal to prove they derived the same channel.
const CONFIRM_TOKEN: &[u8] = b"rivetlink-direct-confirm-v1";

/// Handshake wire messages (length-prefixed JSON).
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t")]
enum Wire {
    /// SPAKE2 message (password mode).
    Pake { v: u16, msg: String },
    /// Signed ephemeral key exchange (key mode).
    Kex {
        v: u16,
        eph: String,
        id: String,
        sig: String,
    },
    /// Sealed confirmation token.
    Confirm { sealed: String },
    /// A deliberately generic pre-channel rejection. It must not disclose
    /// whether a supplied identity is present in the host trust store.
    Reject { reason: String },
}

async fn write_msg<W: AsyncWrite + Unpin>(w: &mut W, msg: &Wire) -> SdkResult<()> {
    let bytes = serde_json::to_vec(msg)?;
    let len = u32::try_from(bytes.len())
        .map_err(|_| SdkError::Crypto("handshake frame too large".to_string()))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

async fn read_msg<R: AsyncRead + Unpin>(r: &mut R) -> SdkResult<Wire> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(SdkError::Crypto("handshake frame too large".to_string()));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

fn decode(b64: &str) -> SdkResult<Vec<u8>> {
    B64.decode(b64.trim())
        .map_err(|e| SdkError::Base64(e.to_string()))
}

/// Short, log-safe prefix of a base64 key (identity keys aren't secret, but the
/// first 10 chars are enough to correlate the two ends of a handshake).
fn short(b64: &str) -> &str {
    let t = b64.trim();
    &t[..t.len().min(10)]
}

fn decode_n<const N: usize>(b64: &str) -> SdkResult<[u8; N]> {
    let raw = decode(b64)?;
    raw.as_slice()
        .try_into()
        .map_err(|_| SdkError::Crypto(format!("expected {N} bytes")))
}

fn require_version(version: u16) -> SdkResult<()> {
    if version == DIRECT_PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(SdkError::Crypto(
            "unsupported direct-LAN protocol version".to_string(),
        ))
    }
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn hash_fields(fields: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(DIRECT_DOMAIN);
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

fn pake_transcript(client_message: &[u8], host_message: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(DIRECT_DOMAIN);
    out.extend_from_slice(&DIRECT_PROTOCOL_VERSION.to_be_bytes());
    out.extend_from_slice(b"pake");
    append_field(&mut out, client_message);
    append_field(&mut out, host_message);
    out
}

fn client_kex_binding(client_identity_b64: &str) -> SdkResult<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(DIRECT_DOMAIN);
    out.extend_from_slice(&DIRECT_PROTOCOL_VERSION.to_be_bytes());
    out.extend_from_slice(b"client-kex");
    append_field(&mut out, &decode_n::<32>(client_identity_b64)?);
    Ok(out)
}

fn host_kex_binding(host_identity_b64: &str, client_fields_hash: &[u8; 32]) -> SdkResult<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(DIRECT_DOMAIN);
    out.extend_from_slice(&DIRECT_PROTOCOL_VERSION.to_be_bytes());
    out.extend_from_slice(b"host-kex");
    append_field(&mut out, &decode_n::<32>(host_identity_b64)?);
    append_field(&mut out, client_fields_hash);
    Ok(out)
}

fn kex_transcript(
    client_eph: &str,
    client_id: &str,
    client_sig: &str,
    host_eph: &str,
    host_id: &str,
    host_sig: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(DIRECT_DOMAIN);
    out.extend_from_slice(&DIRECT_PROTOCOL_VERSION.to_be_bytes());
    out.extend_from_slice(b"key");
    for value in [
        client_eph, client_id, client_sig, host_eph, host_id, host_sig,
    ] {
        append_field(&mut out, value.as_bytes());
    }
    out
}

fn parse_identity(b64: &str) -> SdkResult<VerifyingKey> {
    VerifyingKey::from_bytes(&decode_n::<32>(b64)?)
        .map_err(|e| SdkError::Crypto(format!("bad identity key: {e}")))
}

fn seal_token(ch: &SealedChannel) -> SdkResult<Wire> {
    let sealed = ch
        .seal(CONFIRM_TOKEN)
        .map_err(|e| SdkError::Crypto(e.to_string()))?;
    Ok(Wire::Confirm {
        sealed: B64.encode(sealed),
    })
}

fn open_token(ch: &SealedChannel, msg: Wire) -> SdkResult<()> {
    let Wire::Confirm { sealed } = msg else {
        return Err(SdkError::Crypto("expected confirmation".to_string()));
    };
    let opened = ch
        .open(&decode(&sealed)?)
        .map_err(|_| SdkError::Crypto("authentication failed".to_string()))?;
    if opened != CONFIRM_TOKEN {
        return Err(SdkError::Crypto("authentication failed".to_string()));
    }
    Ok(())
}

// ---- Password mode (PAKE) --------------------------------------------------

/// Client side of a password-authenticated direct session.
#[allow(clippy::cognitive_complexity)] // Ordered protocol state is safer to audit inline.
pub async fn client_connect_password<S>(stream: &mut S, password: &str) -> SdkResult<SealedChannel>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tracing::debug!("handshake[pake/client]: start, sending pake");
    let started = pake::start(password.as_bytes());
    write_msg(
        stream,
        &Wire::Pake {
            v: DIRECT_PROTOCOL_VERSION,
            msg: B64.encode(&started.message),
        },
    )
    .await?;

    let Wire::Pake { v, msg } = read_msg(stream).await? else {
        tracing::warn!("handshake[pake/client]: expected pake, got other message");
        return Err(SdkError::Crypto("expected pake message".to_string()));
    };
    require_version(v)?;
    let peer_message = decode(&msg)?;
    let transcript = pake_transcript(&started.message, &peer_message);
    let channel = started
        .handshake
        .finish(&peer_message, &transcript, ChannelRole::Initiator)
        .map_err(|e| SdkError::Crypto(e.to_string()))?;
    tracing::debug!("handshake[pake/client]: channel derived, confirming");

    // Initiator confirms first, then verifies the peer's confirmation.
    write_msg(stream, &seal_token(&channel)?).await?;
    open_token(&channel, read_msg(stream).await?).inspect_err(|_| {
        tracing::warn!("handshake[pake/client]: confirm failed (wrong PIN?)");
    })?;
    tracing::debug!("handshake[pake/client]: established");
    Ok(channel)
}

/// Host side of a password-authenticated direct session.
pub async fn host_accept_password<S>(stream: &mut S, password: &str) -> SdkResult<SealedChannel>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Wire::Pake { v, msg } = read_msg(stream).await? else {
        return Err(SdkError::Crypto("expected pake message".to_string()));
    };
    require_version(v)?;
    host_password_continue(stream, password, &msg).await
}

/// Finish the PAKE handshake after the client's first message has been read.
async fn host_password_continue<S>(
    stream: &mut S,
    password: &str,
    peer_msg_b64: &str,
) -> SdkResult<SealedChannel>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tracing::debug!("handshake[pake/host]: got client pake, replying");
    let peer_msg = decode(peer_msg_b64)?;

    let started = pake::start(password.as_bytes());
    write_msg(
        stream,
        &Wire::Pake {
            v: DIRECT_PROTOCOL_VERSION,
            msg: B64.encode(&started.message),
        },
    )
    .await?;
    let channel = started
        .handshake
        .finish(
            &peer_msg,
            &pake_transcript(&peer_msg, &started.message),
            ChannelRole::Responder,
        )
        .map_err(|e| SdkError::Crypto(e.to_string()))?;
    tracing::debug!("handshake[pake/host]: channel derived, verifying confirm");

    // Responder verifies the peer's confirmation first, then confirms.
    open_token(&channel, read_msg(stream).await?).inspect_err(|_| {
        tracing::warn!("handshake[pake/host]: confirm failed (wrong PIN?)");
    })?;
    write_msg(stream, &seal_token(&channel)?).await?;
    tracing::debug!("handshake[pake/host]: established");
    Ok(channel)
}

// ---- Key mode (TOFU) -------------------------------------------------------

/// Client side of a key-authenticated direct session.
///
/// A key-mode connection is never allowed to silently trust a host from an
/// unauthenticated network advertisement. The caller must supply the host key
/// recorded during explicit pairing/TOFU; any replacement is a hard failure.
#[allow(clippy::cognitive_complexity)] // Ordered protocol state is safer to audit inline.
pub async fn client_connect_key<S>(
    stream: &mut S,
    identity: &Identity,
    pinned_host: Option<VerifyingKey>,
) -> SdkResult<SealedChannel>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tracing::debug!(
        me = %short(&identity.public_key_b64()),
        pinned = pinned_host.is_some(),
        "handshake[key/client]: start, sending kex"
    );
    let client_id = identity.public_key_b64();
    let pinned_host = pinned_host.ok_or_else(|| {
        SdkError::Crypto(
            "host identity is not pinned; complete explicit pairing before connecting".to_string(),
        )
    })?;
    let kex = handshake::start(identity.signing_key(), &client_kex_binding(&client_id)?);
    let client_eph = B64.encode(kex.ephemeral_public());
    let client_sig = B64.encode(kex.signature());
    write_msg(
        stream,
        &Wire::Kex {
            v: DIRECT_PROTOCOL_VERSION,
            eph: client_eph.clone(),
            id: client_id.clone(),
            sig: client_sig.clone(),
        },
    )
    .await?;

    let (version, eph, id, sig) = match read_msg(stream).await? {
        Wire::Kex { v, eph, id, sig } => (v, eph, id, sig),
        Wire::Reject { reason } => {
            tracing::warn!("handshake[key/client]: host rejected client");
            return Err(SdkError::Crypto(format!(
                "host rejected connection: {reason}"
            )));
        },
        _ => {
            tracing::warn!("handshake[key/client]: expected kex, got other message");
            return Err(SdkError::Crypto("expected key exchange".to_string()));
        },
    };
    require_version(version)?;
    let host_id = parse_identity(&id)?;
    tracing::debug!(host = %short(&id), "handshake[key/client]: got host kex");
    if pinned_host.to_bytes() != host_id.to_bytes() {
        tracing::warn!(
            expected = %short(&B64.encode(pinned_host.to_bytes())),
            got = %short(&id),
            "handshake[key/client]: host identity mismatch (pinned)"
        );
        return Err(SdkError::Crypto("host identity mismatch".to_string()));
    }
    let host_eph = decode_n::<32>(&eph)?;
    let client_fields_hash = hash_fields(&[
        client_eph.as_bytes(),
        client_id.as_bytes(),
        client_sig.as_bytes(),
    ]);
    handshake::verify_peer(
        &host_id,
        &host_eph,
        &decode_n::<64>(&sig)?,
        &host_kex_binding(&id, &client_fields_hash)?,
    )
    .map_err(|e| SdkError::Crypto(format!("host key exchange invalid: {e}")))?;
    let channel = kex
        .into_channel(
            &host_eph,
            &kex_transcript(&client_eph, &client_id, &client_sig, &eph, &id, &sig),
            ChannelRole::Initiator,
        )
        .map_err(|e| SdkError::Crypto(e.to_string()))?;
    // Explicit key confirmation proves the host received the same transcript
    // and prevents a replayed client hello from becoming an authenticated session.
    write_msg(stream, &seal_token(&channel)?).await?;
    open_token(&channel, read_msg(stream).await?)?;
    tracing::debug!("handshake[key/client]: host verified and confirmed");

    Ok(channel)
}

/// Host side of a key-authenticated direct session. `trust` is called with the
/// client's base64 identity key and decides whether to accept the connection
/// (trusted-keys store or operator consent). Returns the sealed channel plus
/// the client's identity key.
pub async fn host_accept_key<S, F>(
    stream: &mut S,
    identity: &Identity,
    trust: F,
) -> SdkResult<(SealedChannel, String)>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&str) -> bool,
{
    let Wire::Kex { v, eph, id, sig } = read_msg(stream).await? else {
        return Err(SdkError::Crypto("expected key exchange".to_string()));
    };
    require_version(v)?;
    host_key_continue(stream, identity, trust, &eph, &id, &sig).await
}

/// Finish the signed key exchange after the client's first message has been
/// read. `trust` decides whether the client's identity is allowed.
#[allow(clippy::cognitive_complexity)] // Ordered protocol state is safer to audit inline.
async fn host_key_continue<S, F>(
    stream: &mut S,
    identity: &Identity,
    trust: F,
    eph: &str,
    id: &str,
    sig: &str,
) -> SdkResult<(SealedChannel, String)>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&str) -> bool,
{
    let client_id = parse_identity(id)?;
    let client_eph = decode_n::<32>(eph)?;
    tracing::debug!(client = %short(id), "handshake[key/host]: got client kex, verifying");
    handshake::verify_peer(
        &client_id,
        &client_eph,
        &decode_n::<64>(sig)?,
        &client_kex_binding(id)?,
    )
    .map_err(|e| SdkError::Crypto(format!("client key exchange invalid: {e}")))?;

    if !trust(id) {
        tracing::warn!(
            client = %short(id),
            "handshake[key/host]: client not trusted (not in allow-list, no PIN) — rejecting"
        );
        // Return a deliberately generic rejection. Network peers must not be
        // able to enumerate which identities appear in the host trust store.
        let _ = write_msg(
            stream,
            &Wire::Reject {
                reason: "connection rejected".to_string(),
            },
        )
        .await;
        return Err(SdkError::Crypto("client not trusted".to_string()));
    }
    tracing::debug!(client = %short(id), "handshake[key/host]: client trusted, replying kex");

    let client_fields_hash = hash_fields(&[eph.as_bytes(), id.as_bytes(), sig.as_bytes()]);
    let host_id = identity.public_key_b64();
    let kex = handshake::start(
        identity.signing_key(),
        &host_kex_binding(&host_id, &client_fields_hash)?,
    );
    let host_eph = B64.encode(kex.ephemeral_public());
    let host_sig = B64.encode(kex.signature());
    write_msg(
        stream,
        &Wire::Kex {
            v: DIRECT_PROTOCOL_VERSION,
            eph: host_eph.clone(),
            id: host_id.clone(),
            sig: host_sig.clone(),
        },
    )
    .await?;
    let channel = kex
        .into_channel(
            &client_eph,
            &kex_transcript(eph, id, sig, &host_eph, &host_id, &host_sig),
            ChannelRole::Responder,
        )
        .map_err(|e| SdkError::Crypto(e.to_string()))?;
    open_token(&channel, read_msg(stream).await?)?;
    write_msg(stream, &seal_token(&channel)?).await?;

    Ok((channel, id.to_string()))
}

/// Host side that accepts EITHER mode in one session: it reads the client's
/// first message and runs the PAKE handshake (the client used a password) or the
/// signed key exchange (the client used its identity key). For key mode `trust`
/// gates the client and the returned `Option<String>` is its identity; for
/// password mode it is `None`.
#[allow(clippy::cognitive_complexity)] // Ordered protocol state is safer to audit inline.
pub async fn host_accept_auto<S, F>(
    stream: &mut S,
    identity: &Identity,
    password: &str,
    trust: F,
) -> SdkResult<(SealedChannel, Option<String>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&str) -> bool,
{
    match read_msg(stream).await? {
        Wire::Pake { v, msg } => {
            require_version(v)?;
            tracing::debug!("handshake[auto/host]: client chose PIN (pake) mode");
            let channel = host_password_continue(stream, password, &msg).await?;
            Ok((channel, None))
        },
        Wire::Kex { v, eph, id, sig } => {
            require_version(v)?;
            tracing::debug!(client = %short(&id), "handshake[auto/host]: client chose key mode");
            let (channel, client_id) =
                host_key_continue(stream, identity, trust, &eph, &id, &sig).await?;
            Ok((channel, Some(client_id)))
        },
        Wire::Confirm { .. } => {
            tracing::warn!("handshake[auto/host]: unexpected confirmation as first message");
            Err(SdkError::Crypto(
                "unexpected confirmation as first message".to_string(),
            ))
        },
        Wire::Reject { .. } => {
            tracing::warn!("handshake[auto/host]: unexpected rejection as first message");
            Err(SdkError::Crypto(
                "unexpected rejection as first message".to_string(),
            ))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_identity(tag: &str) -> Identity {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "rivet-direct-{}-{tag}.json",
            uuid::Uuid::now_v7().simple()
        ));
        let id = Identity::load_or_create(&p).unwrap();
        let _ = std::fs::remove_file(&p);
        id
    }

    fn pipe() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        tokio::io::duplex(16 * 1024)
    }

    #[tokio::test]
    async fn password_match_establishes_channel() {
        let (mut c, mut h) = pipe();
        let host = tokio::spawn(async move { host_accept_password(&mut h, "4821").await });
        let client_ch = client_connect_password(&mut c, "4821").await.unwrap();
        let host_ch = host.await.unwrap().unwrap();

        let sealed = client_ch.seal(b"hi host").unwrap();
        assert_eq!(host_ch.open(&sealed).unwrap(), b"hi host");
    }

    #[tokio::test]
    async fn password_mismatch_is_rejected() {
        let (mut c, mut h) = pipe();
        let host = tokio::spawn(async move { host_accept_password(&mut h, "4821").await });
        let client = client_connect_password(&mut c, "0000").await;
        assert!(client.is_err());
        assert!(host.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn key_mode_trusted_establishes_channel() {
        let client_id = temp_identity("c");
        let host_id = temp_identity("h");
        let client_pub = client_id.public_key_b64();
        let host_pin = host_id.signing_key().verifying_key();

        let (mut c, mut h) = pipe();
        let host = tokio::spawn(async move { host_accept_key(&mut h, &host_id, |_| true).await });
        let client_ch = client_connect_key(&mut c, &client_id, Some(host_pin))
            .await
            .unwrap();
        let (host_ch, seen) = host.await.unwrap().unwrap();

        assert_eq!(seen, client_pub);
        let sealed = host_ch.seal(b"hi client").unwrap();
        assert_eq!(client_ch.open(&sealed).unwrap(), b"hi client");
    }

    #[tokio::test]
    async fn key_mode_untrusted_is_rejected() {
        let client_id = temp_identity("c2");
        let host_id = temp_identity("h2");
        let host_pin = host_id.signing_key().verifying_key();

        let (mut c, mut h) = pipe();
        let host = tokio::spawn(async move { host_accept_key(&mut h, &host_id, |_| false).await });
        let client = client_connect_key(&mut c, &client_id, Some(host_pin)).await;
        assert!(host.await.unwrap().is_err());
        assert!(client
            .unwrap_err()
            .to_string()
            .contains("connection rejected"));
    }

    #[tokio::test]
    async fn trusted_key_connection_requires_an_existing_host_pin() {
        let client_id = temp_identity("unpinned-client");
        let host_id = temp_identity("unpinned-host");
        let (mut client, mut host) = pipe();
        let host_task =
            tokio::spawn(async move { host_accept_key(&mut host, &host_id, |_| true).await });
        let error = client_connect_key(&mut client, &client_id, None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not pinned"));
        // The client rejects before sending an unauthenticated KEX. Abort the
        // peer task rather than treating the expected open stream as failure.
        host_task.abort();
    }

    #[tokio::test]
    async fn auto_accepts_password_client() {
        let host_id = temp_identity("ha");
        let (mut c, mut h) = pipe();
        let host =
            tokio::spawn(
                async move { host_accept_auto(&mut h, &host_id, "4821", |_| false).await },
            );
        let client_ch = client_connect_password(&mut c, "4821").await.unwrap();
        let (host_ch, who) = host.await.unwrap().unwrap();

        assert!(who.is_none()); // password mode reports no identity
        let sealed = client_ch.seal(b"hi").unwrap();
        assert_eq!(host_ch.open(&sealed).unwrap(), b"hi");
    }

    #[tokio::test]
    async fn auto_accepts_trusted_key_client() {
        let client_id = temp_identity("ca");
        let host_id = temp_identity("hb");
        let client_pub = client_id.public_key_b64();
        let host_pin = host_id.signing_key().verifying_key();

        let (mut c, mut h) = pipe();
        let host = tokio::spawn(async move {
            // Wrong password on purpose: the trusted key must be what lets it in.
            host_accept_auto(&mut h, &host_id, "0000", |_| true).await
        });
        let client_ch = client_connect_key(&mut c, &client_id, Some(host_pin))
            .await
            .unwrap();
        let (host_ch, who) = host.await.unwrap().unwrap();

        assert_eq!(who.as_deref(), Some(client_pub.as_str()));
        let sealed = host_ch.seal(b"yo").unwrap();
        assert_eq!(client_ch.open(&sealed).unwrap(), b"yo");
    }

    #[tokio::test]
    async fn auto_rejects_untrusted_key_client() {
        let client_id = temp_identity("cc");
        let host_id = temp_identity("hc");
        let host_pin = host_id.signing_key().verifying_key();
        let (mut c, mut h) = pipe();
        let host =
            tokio::spawn(
                async move { host_accept_auto(&mut h, &host_id, "4821", |_| false).await },
            );
        let client = client_connect_key(&mut c, &client_id, Some(host_pin)).await;
        assert!(host.await.unwrap().is_err());
        assert!(client.is_err());
    }

    #[tokio::test]
    async fn copied_trusted_public_key_cannot_impersonate_its_private_key() {
        let trusted = temp_identity("trusted");
        let attacker = temp_identity("attacker");
        let host_id = temp_identity("host");
        let trusted_public = trusted.public_key_b64();
        let forged = handshake::start(
            attacker.signing_key(),
            &client_kex_binding(&trusted_public).unwrap(),
        );
        let (mut attacker_side, mut host_side) = pipe();
        let trusted_for_host = trusted_public.clone();
        let host = tokio::spawn(async move {
            host_accept_key(&mut host_side, &host_id, |key| key == trusted_for_host).await
        });
        write_msg(
            &mut attacker_side,
            &Wire::Kex {
                v: DIRECT_PROTOCOL_VERSION,
                eph: B64.encode(forged.ephemeral_public()),
                // The attacker copies only the public key; its signature is
                // still made by a different private key and must fail.
                id: trusted_public,
                sig: B64.encode(forged.signature()),
            },
        )
        .await
        .unwrap();
        assert!(host.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn pinned_host_key_replacement_is_a_hard_failure() {
        let client = temp_identity("pinned-client");
        let expected_host = temp_identity("expected-host");
        let attacker_host = temp_identity("attacker-host");
        let pin = expected_host.signing_key().verifying_key();
        let (mut client_side, mut attacker_side) = pipe();
        let attacker = tokio::spawn(async move {
            host_accept_key(&mut attacker_side, &attacker_host, |_| true).await
        });
        let result = client_connect_key(&mut client_side, &client, Some(pin)).await;
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("host identity mismatch"));
        // The fake host never receives a valid confirmation, so it cannot turn
        // a stale/probed hello into an authenticated session either.
        attacker.abort();
        assert!(attacker.await.unwrap_err().is_cancelled());
    }
}
