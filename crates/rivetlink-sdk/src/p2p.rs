//! A direct peer-to-peer byte stream between a client and a host.
//!
//! The relay tunnel is always opened first; this tries to replace it with a
//! direct path. Both ends learn their public address from a STUN server, swap
//! address candidates over the open relay session (`ICE_CANDIDATE` packets,
//! which the relay forwards unread), punch through their NATs and run QUIC
//! over the same UDP socket. QUIC only supplies a reliable, ordered pipe: its
//! certificate is not checked, because the direct-LAN handshake run over the
//! stream afterwards authenticates the host by its pinned key and encrypts
//! end to end, exactly as over the relay. A random token from the offer is
//! the first thing on the stream, so a stranger who finds the host's port
//! cannot take the slot. If anything fails the caller keeps the relay tunnel.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use rand_08::rngs::OsRng;
use rand_08::RngCore;
use serde::{Deserialize, Serialize};
use tokio::io::DuplexStream;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::error::{SdkError, SdkResult};

/// Bytes buffered between the caller and the QUIC stream.
const STREAM_BUFFER: usize = 256 * 1024;
const ALPN: &[u8] = b"rivetlink-p2p/1";
/// QUIC needs a server name; nothing checks it.
const SERVER_NAME: &str = "rivetlink-p2p";
const TOKEN_LEN: usize = 16;
/// Candidates sent or accepted per side.
const MAX_CANDIDATES: usize = 8;
const STUN_TRIES: u32 = 3;
const STUN_WAIT: Duration = Duration::from_millis(400);
/// Keeps NAT mappings open while a still screen sends nothing.
const KEEPALIVE: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT_MS: u32 = 30_000;
/// How long the host waits for the client to connect after answering.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(4);
/// How long the last bytes may take to reach the peer once a side is done.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);
const STUN_MAGIC: u32 = 0x2112_A442;

/// How a session reaches the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// Through the relay server.
    Relay,
    /// Directly between the two machines.
    P2p,
}

/// Carried as the `candidate` of an `ICE_CANDIDATE` packet.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "p2p", rename_all = "snake_case")]
enum Signal {
    Offer {
        token: String,
        candidates: Vec<SocketAddr>,
    },
    Answer {
        candidates: Vec<SocketAddr>,
    },
}

/// Client side: offer, wait for the host's answer, connect. `send` delivers
/// one signal to the host; `incoming` yields the host's signals. The caller
/// bounds the whole attempt with a timeout.
pub(crate) async fn connect(
    stun: &str,
    send: impl Fn(String) -> bool,
    incoming: &mut mpsc::Receiver<String>,
) -> SdkResult<DuplexStream> {
    let (socket, candidates) = bind_and_gather(Some(stun)).await?;
    let mut token = [0u8; TOKEN_LEN];
    OsRng.fill_bytes(&mut token);
    let endpoint = endpoint(socket.into_std()?, None)?;
    let offer = Signal::Offer {
        token: base64::engine::general_purpose::STANDARD.encode(token),
        candidates,
    };
    if !send(serde_json::to_string(&offer)?) {
        return Err(p2p_error("relay session closed"));
    }
    let peer = loop {
        let text = incoming
            .recv()
            .await
            .ok_or_else(|| p2p_error("relay session closed"))?;
        if let Ok(Signal::Answer { candidates }) = serde_json::from_str(&text) {
            break usable(candidates);
        }
    };
    if peer.is_empty() {
        return Err(p2p_error("host offered no usable address"));
    }

    let config = client_config()?;
    let attempts = peer.into_iter().map(|addr| {
        let connecting = endpoint.connect_with(config.clone(), addr, SERVER_NAME);
        Box::pin(async move { connecting.map_err(p2p_error)?.await.map_err(p2p_error) })
    });
    let (connection, _) = futures_util::future::select_ok(attempts).await?;
    let (mut send_stream, recv_stream) = connection.open_bi().await.map_err(p2p_error)?;
    send_stream.write_all(&token).await.map_err(p2p_error)?;

    let (caller_end, local) = tokio::io::duplex(STREAM_BUFFER);
    tokio::spawn(bridge(
        endpoint,
        connection,
        send_stream,
        recv_stream,
        local,
    ));
    Ok(caller_end)
}

/// Host side: answer `offer` through `send` and, once the client connects
/// with the offer's token, move bytes between it and `local` until either
/// side ends. An error means no direct path; `local` is then dropped.
pub async fn accept(
    stun: Option<&str>,
    offer: &str,
    send: impl FnOnce(String) -> bool,
    local: DuplexStream,
) -> SdkResult<()> {
    let Ok(Signal::Offer { token, candidates }) = serde_json::from_str(offer) else {
        return Err(p2p_error("not an offer"));
    };
    let token: [u8; TOKEN_LEN] = base64::engine::general_purpose::STANDARD
        .decode(token)
        .ok()
        .and_then(|t| t.try_into().ok())
        .ok_or_else(|| p2p_error("bad offer token"))?;
    let peer = usable(candidates);

    let (socket, ours) = bind_and_gather(stun).await?;
    // Open our NAT towards the client, so its first packets get through.
    for addr in &peer {
        let _ = socket.send_to(&[0], addr).await;
    }
    let endpoint = endpoint(socket.into_std()?, Some(server_config()?))?;
    if !send(serde_json::to_string(&Signal::Answer { candidates: ours })?) {
        return Err(p2p_error("relay session closed"));
    }

    // Connections are checked side by side, so one that never opens a
    // stream (a stranger, or a duplicate the client dropped) cannot block
    // the real one.
    let accepted = tokio::time::timeout(ACCEPT_TIMEOUT, async {
        let mut checks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                incoming = endpoint.accept() => {
                    let incoming = incoming?;
                    if checks.len() < MAX_CANDIDATES {
                        checks.spawn(check_token(incoming, token));
                    } else {
                        incoming.refuse();
                    }
                },
                // Match only `Some` here: a pattern that fails would switch
                // this branch off and miss the next check to finish.
                Some(done) = checks.join_next() => {
                    if let Ok(Some(found)) = done {
                        return Some(found);
                    }
                },
            }
        }
    })
    .await;
    let Ok(Some((connection, send_stream, recv_stream))) = accepted else {
        return Err(p2p_error("client did not connect"));
    };
    bridge(endpoint, connection, send_stream, recv_stream, local).await;
    Ok(())
}

/// The connection and its first stream, if that stream starts with `token`.
async fn check_token(
    incoming: quinn::Incoming,
    token: [u8; TOKEN_LEN],
) -> Option<(quinn::Connection, quinn::SendStream, quinn::RecvStream)> {
    let connection = incoming.await.ok()?;
    let (send, mut recv) = connection.accept_bi().await.ok()?;
    let mut got = [0u8; TOKEN_LEN];
    recv.read_exact(&mut got).await.ok()?;
    same(&got, &token).then_some((connection, send, recv))
}

/// Move bytes between `local` and the QUIC stream until either side ends.
async fn bridge(
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    local: DuplexStream,
) {
    let (mut reader, mut writer) = tokio::io::split(local);
    let upstream = async {
        let _ = tokio::io::copy(&mut reader, &mut send).await;
        let _ = send.finish();
        // The peer closes the connection once it has read everything; closing
        // it from this side first could drop data it has not read yet.
        let _ = tokio::time::timeout(FLUSH_TIMEOUT, connection.closed()).await;
    };
    let downstream = async {
        let _ = tokio::io::copy(&mut recv, &mut writer).await;
    };
    tokio::select! {
        () = upstream => {},
        () = downstream => {},
    }
    connection.close(0u32.into(), b"done");
    let _ = tokio::time::timeout(FLUSH_TIMEOUT, endpoint.wait_idle()).await;
}

/// A UDP socket plus the addresses a peer may reach it on: every local IPv4
/// address and, when a STUN server answers, the public one.
// ponytail: IPv4 only; add IPv6 candidates when dual-stack sockets are handled per OS.
async fn bind_and_gather(stun: Option<&str>) -> SdkResult<(UdpSocket, Vec<SocketAddr>)> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    let port = socket.local_addr()?.port();
    let mut candidates: Vec<SocketAddr> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|iface| match iface.ip() {
            IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_link_local() => {
                Some(SocketAddr::from((ip, port)))
            },
            _ => None,
        })
        .collect();
    if let Some(stun) = stun {
        let server = tokio::time::timeout(STUN_WAIT * STUN_TRIES, tokio::net::lookup_host(stun))
            .await
            .map_err(|_| p2p_error("STUN server name did not resolve in time"))??
            .find(SocketAddr::is_ipv4)
            .ok_or_else(|| p2p_error("STUN server has no IPv4 address"))?;
        if let Some(public) = reflexive_addr(&socket, server).await {
            if !candidates.contains(&public) {
                candidates.insert(0, public);
            }
        }
    }
    candidates.truncate(MAX_CANDIDATES);
    Ok((socket, candidates))
}

/// Drop anything a peer must not make us send to (this machine itself,
/// multicast, broadcast); cap the count.
fn usable(mut candidates: Vec<SocketAddr>) -> Vec<SocketAddr> {
    candidates.truncate(MAX_CANDIDATES);
    candidates.retain(|addr| match addr.ip() {
        IpAddr::V4(ip) => {
            addr.port() != 0
                && !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_broadcast()
        },
        IpAddr::V6(_) => false,
    });
    candidates
}

fn same(a: &[u8; TOKEN_LEN], b: &[u8; TOKEN_LEN]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Our public address as the STUN server at `server` sees it.
async fn reflexive_addr(socket: &UdpSocket, server: SocketAddr) -> Option<SocketAddr> {
    let mut txid = [0u8; 12];
    OsRng.fill_bytes(&mut txid);
    let mut request = [0u8; 20];
    request[..2].copy_from_slice(&0x0001u16.to_be_bytes()); // Binding request
    request[4..8].copy_from_slice(&STUN_MAGIC.to_be_bytes());
    request[8..].copy_from_slice(&txid);
    let mut buf = [0u8; 512];
    for _ in 0..STUN_TRIES {
        socket.send_to(&request, server).await.ok()?;
        let wait = tokio::time::sleep(STUN_WAIT);
        tokio::pin!(wait);
        loop {
            tokio::select! {
                received = socket.recv_from(&mut buf) => {
                    let Ok((n, from)) = received else { return None };
                    if from == server {
                        if let Some(addr) = parse_binding_response(buf.get(..n)?, &txid) {
                            return Some(addr);
                        }
                    }
                },
                () = &mut wait => break,
            }
        }
    }
    None
}

/// The XOR-MAPPED-ADDRESS (IPv4) of a STUN Binding success response.
fn parse_binding_response(msg: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if msg.get(..2)? != [0x01, 0x01]
        || msg.get(4..8)? != STUN_MAGIC.to_be_bytes()
        || msg.get(8..20)? != txid
    {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([*msg.get(2)?, *msg.get(3)?]));
    let mut attrs = msg.get(20..20 + len)?;
    while attrs.len() >= 4 {
        let kind = u16::from_be_bytes([attrs[0], attrs[1]]);
        let len = usize::from(u16::from_be_bytes([attrs[2], attrs[3]]));
        let value = attrs.get(4..4 + len)?;
        if kind == 0x0020 && len == 8 && value[1] == 0x01 {
            let port = u16::from_be_bytes([value[2], value[3]]) ^ 0x2112;
            let ip = u32::from_be_bytes([value[4], value[5], value[6], value[7]]) ^ STUN_MAGIC;
            return Some(SocketAddr::from((Ipv4Addr::from(ip), port)));
        }
        attrs = attrs.get((4 + len).next_multiple_of(4)..)?;
    }
    None
}

fn endpoint(
    socket: std::net::UdpSocket,
    server: Option<quinn::ServerConfig>,
) -> SdkResult<quinn::Endpoint> {
    let runtime = quinn::default_runtime().ok_or_else(|| p2p_error("no async runtime"))?;
    quinn::Endpoint::new(quinn::EndpointConfig::default(), server, socket, runtime)
        .map_err(Into::into)
}

fn transport() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(KEEPALIVE));
    transport.max_idle_timeout(Some(quinn::VarInt::from_u32(IDLE_TIMEOUT_MS).into()));
    Arc::new(transport)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn server_config() -> SdkResult<quinn::ServerConfig> {
    let cert =
        rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()]).map_err(p2p_error)?;
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(p2p_error)?
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key.into())
        .map_err(p2p_error)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(p2p_error)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(transport());
    Ok(config)
}

fn client_config() -> SdkResult<quinn::ClientConfig> {
    let provider = provider();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(p2p_error)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(p2p_error)?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(transport());
    Ok(config)
}

/// Accepts any QUIC certificate (still checking the handshake signature).
/// Safe only because the stream carries the pinned-key handshake on top.
#[derive(Debug)]
struct AnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn p2p_error(error: impl std::fmt::Display) -> SdkError {
    SdkError::Relay(format!("direct connection: {error}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A STUN Binding success response mapping to `addr`.
    fn binding_response(txid: &[u8], addr: SocketAddr) -> Vec<u8> {
        let SocketAddr::V4(addr) = addr else {
            panic!("IPv4 only")
        };
        let mut msg = vec![0x01, 0x01, 0x00, 0x0c];
        msg.extend_from_slice(&STUN_MAGIC.to_be_bytes());
        msg.extend_from_slice(txid);
        msg.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01]);
        msg.extend_from_slice(&(addr.port() ^ 0x2112).to_be_bytes());
        msg.extend_from_slice(&(u32::from(*addr.ip()) ^ STUN_MAGIC).to_be_bytes());
        msg
    }

    /// Answers every Binding request with the sender's own address.
    async fn stun_server() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                if n >= 20 {
                    let _ = socket
                        .send_to(&binding_response(&buf[8..20], from), from)
                        .await;
                }
            }
        });
        addr
    }

    #[test]
    fn parses_xor_mapped_address() {
        let txid = [7u8; 12];
        let addr: SocketAddr = "203.0.113.9:40000".parse().unwrap();
        assert_eq!(
            parse_binding_response(&binding_response(&txid, addr), &txid),
            Some(addr)
        );
        assert_eq!(
            parse_binding_response(&binding_response(&[8u8; 12], addr), &txid),
            None
        );
        let mut short = binding_response(&txid, addr);
        short.truncate(24);
        assert_eq!(parse_binding_response(&short, &txid), None);
    }

    #[test]
    fn peer_candidates_are_filtered_and_capped() {
        let many: Vec<SocketAddr> = (1..=20)
            .map(|i| SocketAddr::from(([192, 168, 1, i], 5000)))
            .collect();
        assert_eq!(usable(many).len(), MAX_CANDIDATES);
        let bad = vec![
            "0.0.0.0:5000".parse().unwrap(),
            "224.0.0.1:5000".parse().unwrap(),
            "255.255.255.255:5000".parse().unwrap(),
            "127.0.0.1:5000".parse().unwrap(),
            "10.0.0.1:0".parse().unwrap(),
            "[::1]:5000".parse().unwrap(),
        ];
        assert!(usable(bad).is_empty());
    }

    #[tokio::test]
    async fn a_direct_stream_carries_bytes_both_ways() {
        let stun = stun_server().await.to_string();
        let (to_host, mut host_rx) = mpsc::channel::<String>(4);
        let (to_client, mut client_rx) = mpsc::channel::<String>(4);
        let (mut host_app, host_local) = tokio::io::duplex(1024);

        let host_stun = stun.clone();
        let host = tokio::spawn(async move {
            let offer = host_rx.recv().await.unwrap();
            accept(
                Some(&host_stun),
                &offer,
                |answer| to_client.try_send(answer).is_ok(),
                host_local,
            )
            .await
        });
        let mut client = tokio::time::timeout(
            Duration::from_secs(10),
            connect(
                &stun,
                |offer| to_host.try_send(offer).is_ok(),
                &mut client_rx,
            ),
        )
        .await
        .unwrap()
        .unwrap();

        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        host_app.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        host_app.write_all(b"pong").await.unwrap();
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        // The client hanging up ends the host's side too.
        drop(client);
        let mut rest = Vec::new();
        host_app.read_to_end(&mut rest).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(5), host)
            .await
            .unwrap()
            .unwrap()
            .is_ok());
    }

    #[tokio::test]
    async fn a_malformed_offer_is_refused() {
        let (_app, local) = tokio::io::duplex(1024);
        let offer = serde_json::to_string(&Signal::Offer {
            token: "short".to_string(),
            candidates: Vec::new(),
        })
        .unwrap();
        assert!(accept(None, &offer, |_| true, local).await.is_err());
    }
}
