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
use rivetlink_crypto::pq_kem::{self, PqKeyPair, PqSharedSecret};
use rivetlink_crypto::sealed::{ChannelRole, SealedChannel};

use crate::error::{SdkError, SdkResult};
use crate::identity::Identity;

/// Upper bound on a single handshake frame — handshakes are tiny.
const MAX_FRAME: usize = 16 * 1024;
/// Classical handshake (x25519 / SPAKE2 only), still accepted from older peers.
const CLASSIC_VERSION: u16 = 2;
/// Hybrid handshake: the classical exchange plus ML-KEM-768. The client sends
/// an encapsulation key, the host answers with a ciphertext, and both values
/// are signed and part of the transcript, so a MITM cannot strip them.
const HYBRID_VERSION: u16 = 3;
const DIRECT_DOMAIN: &[u8] = b"rivetlink-direct-v2";
/// Plaintext both sides seal to prove they derived the same channel.
const CONFIRM_TOKEN: &[u8] = b"rivetlink-direct-confirm-v1";

/// Handshake wire messages (length-prefixed JSON).
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t")]
enum Wire {
    /// SPAKE2 message (password mode).
    Pake {
        v: u16,
        msg: String,
        /// v3: the client's ML-KEM encapsulation key, or the host's
        /// ciphertext. Absent in v2, keeping those frames byte-identical.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pq: Option<String>,
    },
    /// Signed ephemeral key exchange (key mode).
    Kex {
        v: u16,
        eph: String,
        id: String,
        sig: String,
        /// v3: as for [`Wire::Pake`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pq: Option<String>,
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

/// Once the host has answered, a closed connection is no longer a sign of a
/// pre-v3 host, so it must not be mistaken for one (which would allow a
/// classical retry). Report it as a handshake failure instead.
fn closed_after_reply(error: SdkError) -> SdkError {
    match error {
        SdkError::Io(e) => SdkError::Crypto(format!("host closed the handshake: {e}")),
        other => other,
    }
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

/// A peer's message must be v2 without ML-KEM data or v3 with it.
fn require_version(version: u16, pq: Option<&String>) -> SdkResult<()> {
    match (version, pq) {
        (CLASSIC_VERSION, None) | (HYBRID_VERSION, Some(_)) => Ok(()),
        _ => Err(SdkError::Crypto(
            "unsupported direct-LAN protocol version".to_string(),
        )),
    }
}

/// The client's v3 ML-KEM state: its key pair and the encoded key it sent.
struct ClientPq {
    keys: PqKeyPair,
    encapsulation_key: String,
}

impl ClientPq {
    fn start(hybrid: bool) -> Option<Self> {
        hybrid.then(|| {
            let keys = PqKeyPair::generate();
            let encapsulation_key = B64.encode(keys.encapsulation_key_bytes());
            Self {
                keys,
                encapsulation_key,
            }
        })
    }

    fn version(pq: Option<&Self>) -> u16 {
        if pq.is_some() {
            HYBRID_VERSION
        } else {
            CLASSIC_VERSION
        }
    }

    /// Check the host answered in the version we asked for, then decapsulate
    /// its ciphertext. A host that drops to v2 for a v3 client is refused.
    fn finish(
        pq: Option<&Self>,
        version: u16,
        ciphertext: Option<&String>,
    ) -> SdkResult<Option<PqSharedSecret>> {
        require_version(version, ciphertext)?;
        match (pq, ciphertext) {
            (None, None) => Ok(None),
            (Some(pq), Some(ciphertext)) => pq
                .keys
                .decapsulate_bytes(&decode(ciphertext)?)
                .map(Some)
                .map_err(|e| SdkError::Crypto(e.to_string())),
            _ => Err(SdkError::Crypto(
                "host answered in another protocol version".to_string(),
            )),
        }
    }
}

/// Host side of v3: encapsulate to the client's key. Returns the encoded
/// ciphertext to send back and the shared secret.
fn host_pq(encapsulation_key: Option<&String>) -> SdkResult<Option<(String, PqSharedSecret)>> {
    encapsulation_key
        .map(|key| {
            let (ciphertext, secret) = pq_kem::encapsulate_to(&decode(key)?)
                .map_err(|e| SdkError::Crypto(e.to_string()))?;
            Ok((B64.encode(ciphertext), secret))
        })
        .transpose()
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

/// The client's signed fields, which the host's signature covers. In v3 the
/// encapsulation key is one of them; v2 hashes exactly as before.
fn client_fields_hash(eph: &str, id: &str, sig: &str, pq: Option<&str>) -> [u8; 32] {
    match pq {
        Some(pq) => hash_fields(&[eph.as_bytes(), id.as_bytes(), sig.as_bytes(), pq.as_bytes()]),
        None => hash_fields(&[eph.as_bytes(), id.as_bytes(), sig.as_bytes()]),
    }
}

fn pake_transcript(
    version: u16,
    client_message: &[u8],
    host_message: &[u8],
    client_pq: Option<&str>,
    host_pq: Option<&str>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(DIRECT_DOMAIN);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(b"pake");
    append_field(&mut out, client_message);
    append_field(&mut out, host_message);
    for value in [client_pq, host_pq].into_iter().flatten() {
        append_field(&mut out, value.as_bytes());
    }
    out
}

fn client_kex_binding(
    version: u16,
    client_identity_b64: &str,
    client_pq: Option<&str>,
) -> SdkResult<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(DIRECT_DOMAIN);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(b"client-kex");
    append_field(&mut out, &decode_n::<32>(client_identity_b64)?);
    if let Some(pq) = client_pq {
        append_field(&mut out, pq.as_bytes());
    }
    Ok(out)
}

fn host_kex_binding(
    version: u16,
    host_identity_b64: &str,
    client_fields_hash: &[u8; 32],
    host_pq: Option<&str>,
) -> SdkResult<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(DIRECT_DOMAIN);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(b"host-kex");
    append_field(&mut out, &decode_n::<32>(host_identity_b64)?);
    append_field(&mut out, client_fields_hash);
    if let Some(pq) = host_pq {
        append_field(&mut out, pq.as_bytes());
    }
    Ok(out)
}

/// One side's key-exchange fields, as sent on the wire.
struct KexFields<'a> {
    eph: &'a str,
    id: &'a str,
    sig: &'a str,
    pq: Option<&'a str>,
}

fn kex_transcript(version: u16, client: &KexFields<'_>, host: &KexFields<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(DIRECT_DOMAIN);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(b"key");
    for value in [
        client.eph, client.id, client.sig, host.eph, host.id, host.sig,
    ] {
        append_field(&mut out, value.as_bytes());
    }
    for value in [client.pq, host.pq].into_iter().flatten() {
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

/// Client side of a password-authenticated direct session. `hybrid` runs the
/// v3 handshake with ML-KEM; a host older than v3 closes the connection.
#[allow(clippy::cognitive_complexity)] // Ordered protocol state is safer to audit inline.
pub async fn client_connect_password<S>(
    stream: &mut S,
    password: &str,
    hybrid: bool,
) -> SdkResult<SealedChannel>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tracing::debug!(hybrid, "handshake[pake/client]: start, sending pake");
    let pq = ClientPq::start(hybrid);
    let version = ClientPq::version(pq.as_ref());
    let started = pake::start(password.as_bytes());
    write_msg(
        stream,
        &Wire::Pake {
            v: version,
            msg: B64.encode(&started.message),
            pq: pq.as_ref().map(|pq| pq.encapsulation_key.clone()),
        },
    )
    .await?;

    let Wire::Pake {
        v,
        msg,
        pq: host_ciphertext,
    } = read_msg(stream).await?
    else {
        tracing::warn!("handshake[pake/client]: expected pake, got other message");
        return Err(SdkError::Crypto("expected pake message".to_string()));
    };
    let pq_secret = ClientPq::finish(pq.as_ref(), v, host_ciphertext.as_ref())?;
    let peer_message = decode(&msg)?;
    let transcript = pake_transcript(
        version,
        &started.message,
        &peer_message,
        pq.as_ref().map(|pq| pq.encapsulation_key.as_str()),
        host_ciphertext.as_deref(),
    );
    let channel = started
        .handshake
        .finish(
            &peer_message,
            pq_secret.as_ref(),
            &transcript,
            ChannelRole::Initiator,
        )
        .map_err(|e| SdkError::Crypto(e.to_string()))?;
    tracing::debug!("handshake[pake/client]: channel derived, confirming");

    // Initiator confirms first, then verifies the peer's confirmation.
    write_msg(stream, &seal_token(&channel)?)
        .await
        .map_err(closed_after_reply)?;
    let confirm = read_msg(stream).await.map_err(closed_after_reply)?;
    open_token(&channel, confirm).inspect_err(|_| {
        tracing::warn!("handshake[pake/client]: confirm failed (wrong PIN?)");
    })?;
    tracing::debug!(hybrid, "handshake[pake/client]: established");
    Ok(channel)
}

/// Host side of a password-authenticated direct session (v2 or v3).
pub async fn host_accept_password<S>(stream: &mut S, password: &str) -> SdkResult<SealedChannel>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Wire::Pake { v, msg, pq } = read_msg(stream).await? else {
        return Err(SdkError::Crypto("expected pake message".to_string()));
    };
    require_version(v, pq.as_ref())?;
    host_password_continue(stream, password, v, &msg, pq.as_ref()).await
}

/// Finish the PAKE handshake after the client's first message has been read,
/// answering in the client's version.
async fn host_password_continue<S>(
    stream: &mut S,
    password: &str,
    version: u16,
    peer_msg_b64: &str,
    client_pq: Option<&String>,
) -> SdkResult<SealedChannel>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tracing::debug!(version, "handshake[pake/host]: got client pake, replying");
    let peer_msg = decode(peer_msg_b64)?;
    let pq = host_pq(client_pq)?;

    let started = pake::start(password.as_bytes());
    write_msg(
        stream,
        &Wire::Pake {
            v: version,
            msg: B64.encode(&started.message),
            pq: pq.as_ref().map(|(ciphertext, _)| ciphertext.clone()),
        },
    )
    .await?;
    let channel = started
        .handshake
        .finish(
            &peer_msg,
            pq.as_ref().map(|(_, secret)| secret),
            &pake_transcript(
                version,
                &peer_msg,
                &started.message,
                client_pq.map(String::as_str),
                pq.as_ref().map(|(ciphertext, _)| ciphertext.as_str()),
            ),
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

/// Client side of a key-authenticated direct session. `hybrid` runs the v3
/// handshake with ML-KEM; a host older than v3 closes the connection.
///
/// A key-mode connection is never allowed to silently trust a host from an
/// unauthenticated network advertisement. The caller must supply the host key
/// recorded during explicit pairing/TOFU; any replacement is a hard failure.
#[allow(clippy::cognitive_complexity)] // Ordered protocol state is safer to audit inline.
pub async fn client_connect_key<S>(
    stream: &mut S,
    identity: &Identity,
    pinned_host: Option<VerifyingKey>,
    hybrid: bool,
) -> SdkResult<SealedChannel>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tracing::debug!(
        me = %short(&identity.public_key_b64()),
        pinned = pinned_host.is_some(),
        hybrid,
        "handshake[key/client]: start, sending kex"
    );
    let client_id = identity.public_key_b64();
    let pinned_host = pinned_host.ok_or_else(|| {
        SdkError::Crypto(
            "host identity is not pinned; complete explicit pairing before connecting".to_string(),
        )
    })?;
    let pq = ClientPq::start(hybrid);
    let version = ClientPq::version(pq.as_ref());
    let client_pq = pq.as_ref().map(|pq| pq.encapsulation_key.as_str());
    let kex = handshake::start(
        identity.signing_key(),
        &client_kex_binding(version, &client_id, client_pq)?,
    );
    let client_eph = B64.encode(kex.ephemeral_public());
    let client_sig = B64.encode(kex.signature());
    write_msg(
        stream,
        &Wire::Kex {
            v: version,
            eph: client_eph.clone(),
            id: client_id.clone(),
            sig: client_sig.clone(),
            pq: client_pq.map(str::to_string),
        },
    )
    .await?;

    let (v, eph, id, sig, host_ciphertext) = read_host_kex(stream).await?;
    require_version(v, host_ciphertext.as_ref())?;
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
    // Verify the host's signature before touching its ciphertext.
    let host_eph = decode_n::<32>(&eph)?;
    handshake::verify_peer(
        &host_id,
        &host_eph,
        &decode_n::<64>(&sig)?,
        &host_kex_binding(
            v,
            &id,
            &client_fields_hash(&client_eph, &client_id, &client_sig, client_pq),
            host_ciphertext.as_deref(),
        )?,
    )
    .map_err(|e| SdkError::Crypto(format!("host key exchange invalid: {e}")))?;
    let pq_secret = ClientPq::finish(pq.as_ref(), v, host_ciphertext.as_ref())?;
    let channel = kex
        .into_channel(
            &host_eph,
            pq_secret.as_ref(),
            &kex_transcript(
                version,
                &KexFields {
                    eph: &client_eph,
                    id: &client_id,
                    sig: &client_sig,
                    pq: client_pq,
                },
                &KexFields {
                    eph: &eph,
                    id: &id,
                    sig: &sig,
                    pq: host_ciphertext.as_deref(),
                },
            ),
            ChannelRole::Initiator,
        )
        .map_err(|e| SdkError::Crypto(e.to_string()))?;
    // Explicit key confirmation proves the host received the same transcript
    // and prevents a replayed client hello from becoming an authenticated session.
    write_msg(stream, &seal_token(&channel)?)
        .await
        .map_err(closed_after_reply)?;
    open_token(
        &channel,
        read_msg(stream).await.map_err(closed_after_reply)?,
    )?;
    tracing::debug!(hybrid, "handshake[key/client]: host verified and confirmed");

    Ok(channel)
}

/// The host's answer to a key-mode hello: its key exchange fields, or the
/// generic rejection.
async fn read_host_kex<S>(
    stream: &mut S,
) -> SdkResult<(u16, String, String, String, Option<String>)>
where
    S: AsyncRead + Unpin,
{
    match read_msg(stream).await? {
        Wire::Kex {
            v,
            eph,
            id,
            sig,
            pq,
        } => Ok((v, eph, id, sig, pq)),
        Wire::Reject { reason } => {
            tracing::warn!("handshake[key/client]: host rejected client");
            Err(SdkError::Crypto(format!(
                "host rejected connection: {reason}"
            )))
        },
        _ => {
            tracing::warn!("handshake[key/client]: expected kex, got other message");
            Err(SdkError::Crypto("expected key exchange".to_string()))
        },
    }
}

/// Host side of a key-authenticated direct session (v2 or v3). `trust` is
/// called with the client's base64 identity key and decides whether to accept
/// the connection (trusted-keys store or operator consent). Returns the sealed
/// channel plus the client's identity key.
pub async fn host_accept_key<S, F>(
    stream: &mut S,
    identity: &Identity,
    trust: F,
) -> SdkResult<(SealedChannel, String)>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&str) -> bool,
{
    let Wire::Kex {
        v,
        eph,
        id,
        sig,
        pq,
    } = read_msg(stream).await?
    else {
        return Err(SdkError::Crypto("expected key exchange".to_string()));
    };
    require_version(v, pq.as_ref())?;
    let client = KexFields {
        eph: &eph,
        id: &id,
        sig: &sig,
        pq: pq.as_deref(),
    };
    host_key_continue(stream, identity, trust, v, &client).await
}

/// Finish the signed key exchange after the client's first message has been
/// read, answering in the client's version. `trust` decides whether the
/// client's identity is allowed.
#[allow(clippy::cognitive_complexity)] // Ordered protocol state is safer to audit inline.
async fn host_key_continue<S, F>(
    stream: &mut S,
    identity: &Identity,
    trust: F,
    version: u16,
    client: &KexFields<'_>,
) -> SdkResult<(SealedChannel, String)>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&str) -> bool,
{
    let client_id = parse_identity(client.id)?;
    let client_eph = decode_n::<32>(client.eph)?;
    tracing::debug!(client = %short(client.id), version, "handshake[key/host]: got client kex, verifying");
    handshake::verify_peer(
        &client_id,
        &client_eph,
        &decode_n::<64>(client.sig)?,
        &client_kex_binding(version, client.id, client.pq)?,
    )
    .map_err(|e| SdkError::Crypto(format!("client key exchange invalid: {e}")))?;

    if !trust(client.id) {
        tracing::warn!(
            client = %short(client.id),
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
    tracing::debug!(client = %short(client.id), "handshake[key/host]: client trusted, replying kex");

    let pq = host_pq(client.pq.map(str::to_string).as_ref())?;
    let host_ciphertext = pq.as_ref().map(|(ciphertext, _)| ciphertext.as_str());
    let host_id = identity.public_key_b64();
    let kex = handshake::start(
        identity.signing_key(),
        &host_kex_binding(
            version,
            &host_id,
            &client_fields_hash(client.eph, client.id, client.sig, client.pq),
            host_ciphertext,
        )?,
    );
    let host_eph = B64.encode(kex.ephemeral_public());
    let host_sig = B64.encode(kex.signature());
    write_msg(
        stream,
        &Wire::Kex {
            v: version,
            eph: host_eph.clone(),
            id: host_id.clone(),
            sig: host_sig.clone(),
            pq: host_ciphertext.map(str::to_string),
        },
    )
    .await?;
    let channel = kex
        .into_channel(
            &client_eph,
            pq.as_ref().map(|(_, secret)| secret),
            &kex_transcript(
                version,
                client,
                &KexFields {
                    eph: &host_eph,
                    id: &host_id,
                    sig: &host_sig,
                    pq: host_ciphertext,
                },
            ),
            ChannelRole::Responder,
        )
        .map_err(|e| SdkError::Crypto(e.to_string()))?;
    open_token(&channel, read_msg(stream).await?)?;
    write_msg(stream, &seal_token(&channel)?).await?;

    Ok((channel, client.id.to_string()))
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
        Wire::Pake { v, msg, pq } => {
            require_version(v, pq.as_ref())?;
            tracing::debug!("handshake[auto/host]: client chose PIN (pake) mode");
            let channel = host_password_continue(stream, password, v, &msg, pq.as_ref()).await?;
            Ok((channel, None))
        },
        Wire::Kex {
            v,
            eph,
            id,
            sig,
            pq,
        } => {
            require_version(v, pq.as_ref())?;
            tracing::debug!(client = %short(&id), "handshake[auto/host]: client chose key mode");
            let client = KexFields {
                eph: &eph,
                id: &id,
                sig: &sig,
                pq: pq.as_deref(),
            };
            let (channel, client_id) =
                host_key_continue(stream, identity, trust, v, &client).await?;
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
        let client_ch = client_connect_password(&mut c, "4821", true).await.unwrap();
        let host_ch = host.await.unwrap().unwrap();

        let sealed = client_ch.seal(b"hi host").unwrap();
        assert_eq!(host_ch.open(&sealed).unwrap(), b"hi host");
    }

    #[tokio::test]
    async fn password_mismatch_is_rejected() {
        let (mut c, mut h) = pipe();
        let host = tokio::spawn(async move { host_accept_password(&mut h, "4821").await });
        let client = client_connect_password(&mut c, "0000", true).await;
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
        let client_ch = client_connect_key(&mut c, &client_id, Some(host_pin), true)
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
        let client = client_connect_key(&mut c, &client_id, Some(host_pin), true).await;
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
        let error = client_connect_key(&mut client, &client_id, None, true)
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
        let client_ch = client_connect_password(&mut c, "4821", true).await.unwrap();
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
        let client_ch = client_connect_key(&mut c, &client_id, Some(host_pin), true)
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
        let client = client_connect_key(&mut c, &client_id, Some(host_pin), true).await;
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
            &client_kex_binding(CLASSIC_VERSION, &trusted_public, None).unwrap(),
        );
        let (mut attacker_side, mut host_side) = pipe();
        let trusted_for_host = trusted_public.clone();
        let host = tokio::spawn(async move {
            host_accept_key(&mut host_side, &host_id, |key| key == trusted_for_host).await
        });
        write_msg(
            &mut attacker_side,
            &Wire::Kex {
                v: CLASSIC_VERSION,
                eph: B64.encode(forged.ephemeral_public()),
                // The attacker copies only the public key; its signature is
                // still made by a different private key and must fail.
                id: trusted_public,
                sig: B64.encode(forged.signature()),
                pq: None,
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
        let result = client_connect_key(&mut client_side, &client, Some(pin), true).await;
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("host identity mismatch"));
        // The fake host never receives a valid confirmation, so it cannot turn
        // a stale/probed hello into an authenticated session either.
        attacker.abort();
        assert!(attacker.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn classical_clients_still_connect_to_a_hybrid_host() {
        let client_id = temp_identity("v2c");
        let host_id = temp_identity("v2h");
        let host_pin = host_id.signing_key().verifying_key();
        let (mut c, mut h) = pipe();
        let host =
            tokio::spawn(async move { host_accept_auto(&mut h, &host_id, "4821", |_| true).await });
        let client_ch = client_connect_key(&mut c, &client_id, Some(host_pin), false)
            .await
            .unwrap();
        let (host_ch, _) = host.await.unwrap().unwrap();
        assert_eq!(
            host_ch.open(&client_ch.seal(b"v2").unwrap()).unwrap(),
            b"v2"
        );

        let (mut c, mut h) = pipe();
        let host = tokio::spawn(async move { host_accept_password(&mut h, "4821").await });
        let client_ch = client_connect_password(&mut c, "4821", false)
            .await
            .unwrap();
        let host_ch = host.await.unwrap().unwrap();
        assert_eq!(
            host_ch.open(&client_ch.seal(b"v2").unwrap()).unwrap(),
            b"v2"
        );
    }

    #[tokio::test]
    async fn version_and_pq_field_must_agree() {
        assert!(require_version(CLASSIC_VERSION, None).is_ok());
        assert!(require_version(HYBRID_VERSION, Some(&"k".to_string())).is_ok());
        assert!(require_version(HYBRID_VERSION, None).is_err());
        assert!(require_version(CLASSIC_VERSION, Some(&"k".to_string())).is_err());
        assert!(require_version(4, None).is_err());
    }

    /// Relay every frame between `client` and `host`, letting `edit` rewrite
    /// each one; `from_host` tells which way the frame goes.
    async fn mitm<F>(
        mut client: tokio::io::DuplexStream,
        mut host: tokio::io::DuplexStream,
        mut edit: F,
    ) where
        F: FnMut(Wire, bool) -> Wire,
    {
        loop {
            tokio::select! {
                msg = read_msg(&mut client) => {
                    let Ok(msg) = msg else { return };
                    if write_msg(&mut host, &edit(msg, false)).await.is_err() { return }
                }
                msg = read_msg(&mut host) => {
                    let Ok(msg) = msg else { return };
                    if write_msg(&mut client, &edit(msg, true)).await.is_err() { return }
                }
            }
        }
    }

    #[tokio::test]
    async fn stripping_ml_kem_from_a_hybrid_hello_fails() {
        let client_id = temp_identity("strip-c");
        let host_id = temp_identity("strip-h");
        let host_pin = host_id.signing_key().verifying_key();
        let (mut c, c_mitm) = pipe();
        let (h_mitm, mut h) = pipe();
        let host = tokio::spawn(async move { host_accept_key(&mut h, &host_id, |_| true).await });
        // Rewrite the client's v3 hello into a v2 one, keeping its signature.
        tokio::spawn(mitm(c_mitm, h_mitm, |msg, from_host| match msg {
            Wire::Kex { eph, id, sig, .. } if !from_host => Wire::Kex {
                v: CLASSIC_VERSION,
                eph,
                id,
                sig,
                pq: None,
            },
            other => other,
        }));
        let client = client_connect_key(&mut c, &client_id, Some(host_pin), true).await;
        assert!(client.is_err());
        assert!(host
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("client key exchange invalid"));
    }

    #[tokio::test]
    async fn a_replaced_ml_kem_ciphertext_fails() {
        let client_id = temp_identity("ct-c");
        let host_id = temp_identity("ct-h");
        let host_pin = host_id.signing_key().verifying_key();
        let (mut c, c_mitm) = pipe();
        let (h_mitm, mut h) = pipe();
        let host = tokio::spawn(async move { host_accept_key(&mut h, &host_id, |_| true).await });
        // Swap the host's ciphertext for one the attacker made itself.
        tokio::spawn(mitm(c_mitm, h_mitm, |msg, from_host| match msg {
            Wire::Kex {
                v,
                eph,
                id,
                sig,
                pq: Some(_),
            } if from_host => {
                let ek = PqKeyPair::generate().encapsulation_key_bytes();
                let (ct, _) = pq_kem::encapsulate_to(&ek).unwrap();
                Wire::Kex {
                    v,
                    eph,
                    id,
                    sig,
                    pq: Some(B64.encode(ct)),
                }
            },
            other => other,
        }));
        let error = client_connect_key(&mut c, &client_id, Some(host_pin), true)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("host key exchange invalid"));
        host.abort();
    }

    #[tokio::test]
    async fn a_hybrid_client_refuses_a_classical_answer() {
        let client_id = temp_identity("down-c");
        let host_id = temp_identity("down-h");
        let host_pin = host_id.signing_key().verifying_key();
        let (mut c, mut h) = pipe();
        // A host that ignores the client's version and answers in v2.
        let host = tokio::spawn(async move {
            let Wire::Kex { eph, id, sig, .. } = read_msg(&mut h).await.unwrap() else {
                panic!("expected kex");
            };
            let client = KexFields {
                eph: &eph,
                id: &id,
                sig: &sig,
                pq: None,
            };
            host_key_continue(&mut h, &host_id, |_| true, CLASSIC_VERSION, &client).await
        });
        assert!(client_connect_key(&mut c, &client_id, Some(host_pin), true)
            .await
            .is_err());
        host.abort();
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Known answers for the v2 wire format, computed independently from
    /// `main` before v3 existed. A change here breaks every older peer.
    #[test]
    fn classical_frames_and_transcripts_are_unchanged() {
        let kex = Wire::Kex {
            v: CLASSIC_VERSION,
            eph: "e".into(),
            id: "i".into(),
            sig: "s".into(),
            pq: None,
        };
        assert_eq!(
            serde_json::to_string(&kex).unwrap(),
            r#"{"t":"Kex","v":2,"eph":"e","id":"i","sig":"s"}"#
        );
        let pake = Wire::Pake {
            v: CLASSIC_VERSION,
            msg: "m".into(),
            pq: None,
        };
        assert_eq!(
            serde_json::to_string(&pake).unwrap(),
            r#"{"t":"Pake","v":2,"msg":"m"}"#
        );

        let client = KexFields {
            eph: "ce",
            id: "ci",
            sig: "cs",
            pq: None,
        };
        let host = KexFields {
            eph: "he",
            id: "hi",
            sig: "hs",
            pq: None,
        };
        assert_eq!(
            sha256_hex(&kex_transcript(CLASSIC_VERSION, &client, &host)),
            "9beda968f789600471d4175fe7cafca2ad9726f1a452467dc8bd7a99d705ab56"
        );
        assert_eq!(
            sha256_hex(&pake_transcript(CLASSIC_VERSION, b"cm", b"hm", None, None)),
            "3c96f1e951262c6c75c002a6e8f1c5b951074802c321fee561859d1964843d3a"
        );
        let client_id = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        let host_id = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
        assert_eq!(
            sha256_hex(&client_kex_binding(CLASSIC_VERSION, client_id, None).unwrap()),
            "7deae37df536e42932e8f76a460ed312d4af7e7fa25edbeb7f6085cc176ed871"
        );
        assert_eq!(
            sha256_hex(
                &host_kex_binding(
                    CLASSIC_VERSION,
                    host_id,
                    &client_fields_hash("ce", "ci", "cs", None),
                    None
                )
                .unwrap()
            ),
            "bec7612338444a33742a94e15dce6f99e58451d97b0f98f83c2667b2b18f2ca3"
        );
    }

    fn fresh_encapsulation_key() -> String {
        B64.encode(PqKeyPair::generate().encapsulation_key_bytes())
    }

    fn fresh_ciphertext() -> String {
        let (ct, _) =
            pq_kem::encapsulate_to(&PqKeyPair::generate().encapsulation_key_bytes()).unwrap();
        B64.encode(ct)
    }

    #[tokio::test]
    async fn a_replaced_ml_kem_key_in_a_hybrid_hello_fails() {
        let client_id = temp_identity("ek-c");
        let host_id = temp_identity("ek-h");
        let host_pin = host_id.signing_key().verifying_key();
        let (mut c, c_mitm) = pipe();
        let (h_mitm, mut h) = pipe();
        let host = tokio::spawn(async move { host_accept_key(&mut h, &host_id, |_| true).await });
        // Stay on v3 but swap in the attacker's own encapsulation key.
        tokio::spawn(mitm(c_mitm, h_mitm, |msg, from_host| match msg {
            Wire::Kex {
                v,
                eph,
                id,
                sig,
                pq: Some(_),
            } if !from_host => Wire::Kex {
                v,
                eph,
                id,
                sig,
                pq: Some(fresh_encapsulation_key()),
            },
            other => other,
        }));
        assert!(client_connect_key(&mut c, &client_id, Some(host_pin), true)
            .await
            .is_err());
        assert!(host
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("client key exchange invalid"));
    }

    #[tokio::test]
    async fn a_tampered_ml_kem_exchange_in_pin_mode_fails() {
        for from_host_side in [false, true] {
            let (mut c, c_mitm) = pipe();
            let (h_mitm, mut h) = pipe();
            let host = tokio::spawn(async move { host_accept_password(&mut h, "4821").await });
            tokio::spawn(mitm(c_mitm, h_mitm, move |msg, from_host| match msg {
                Wire::Pake {
                    v,
                    msg,
                    pq: Some(_),
                } if from_host == from_host_side => Wire::Pake {
                    v,
                    msg,
                    pq: Some(if from_host {
                        fresh_ciphertext()
                    } else {
                        fresh_encapsulation_key()
                    }),
                },
                other => other,
            }));
            // Same PIN on both ends: only the PQ tampering can break it.
            assert!(client_connect_password(&mut c, "4821", true).await.is_err());
            assert!(host.await.unwrap().is_err());
        }
    }
}
