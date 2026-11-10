//! The fingerprinted TLS 1.3 client against a rustls server: every
//! fingerprint, every cipher suite, HelloRetryRequest, compressed
//! certificates, KeyUpdate and the failure paths.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ServerConfig, SupportedCipherSuite};
use sha2::{Digest, Sha256};
use sybau_common::RawSwitch;
use sybau_tls::verify::{build_verifier, VerifyOptions};
use sybau_tls::{connect, ClientConfig, Fingerprint, Trust};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_rustls::TlsAcceptor;

const HOST: &str = "sybau.test";

struct Identity {
    cert: CertificateDer<'static>,
    key: Vec<u8>,
    pin: [u8; 32],
}

fn identity() -> Identity {
    let generated = rcgen::generate_simple_self_signed(vec![HOST.to_string()]).unwrap();
    let cert = generated.cert.der().clone();
    let pin: [u8; 32] = Sha256::digest(cert.as_ref()).into();
    Identity {
        cert,
        key: generated.key_pair.serialize_der(),
        pin,
    }
}

fn provider_with(
    suites: Option<Vec<SupportedCipherSuite>>,
    groups: Option<Vec<&'static dyn rustls::crypto::SupportedKxGroup>>,
) -> Arc<rustls::crypto::CryptoProvider> {
    let mut p = rustls::crypto::ring::default_provider();
    if let Some(s) = suites {
        p.cipher_suites = s;
    }
    if let Some(g) = groups {
        p.kx_groups = g;
    }
    Arc::new(p)
}

fn server_config(
    id: &Identity,
    provider: Arc<rustls::crypto::CryptoProvider>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> ServerConfig {
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![id.cert.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key.clone())),
        )
        .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    cfg
}

fn client_config(fingerprint: &str, opts: VerifyOptions) -> ClientConfig {
    ClientConfig {
        fingerprint: Fingerprint::by_name(fingerprint).unwrap(),
        server_name: HOST.into(),
        alpn: None,
        trust: Trust::Certificate {
            verifier: build_verifier(&opts).unwrap(),
            name: ServerName::try_from(HOST).unwrap(),
        },
    }
}

fn pinned(id: &Identity) -> VerifyOptions {
    VerifyOptions {
        leaf_pins: vec![id.pin],
        ..Default::default()
    }
}

/// What the echo server observed: cipher suite and ALPN protocol.
type ServerView = tokio::task::JoinHandle<Option<(u16, Vec<u8>)>>;

/// Runs an echo server on one end of a pipe and returns the other end.
fn spawn_echo(cfg: ServerConfig) -> (DuplexStream, ServerView) {
    let (client, server) = tokio::io::duplex(1 << 16);
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let task = tokio::spawn(async move {
        let mut tls = acceptor.accept(server).await.ok()?;
        let suite: u16 = tls.get_ref().1.negotiated_cipher_suite()?.suite().into();
        let alpn = tls
            .get_ref()
            .1
            .alpn_protocol()
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        let mut buf = vec![0u8; 16384];
        loop {
            match tls.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tls.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = tls.shutdown().await;
        Some((suite, alpn))
    });
    (client, task)
}

async fn echo_roundtrip(tls: &mut sybau_tls::TlsStream<DuplexStream>) {
    for size in [1usize, 1000, 16384, 100_000] {
        let data: Vec<u8> = (0..size).map(|i| (i * 7) as u8).collect();
        let (mut r, mut w) = tokio::io::split(&mut *tls);
        let write = async {
            w.write_all(&data).await.unwrap();
            w.flush().await.unwrap();
        };
        let read = async {
            let mut got = vec![0u8; size];
            r.read_exact(&mut got).await.unwrap();
            got
        };
        let ((), got) = tokio::join!(write, read);
        assert_eq!(got, data, "echo of {size} bytes");
    }
}

#[tokio::test]
async fn every_tls13_fingerprint_completes_a_handshake() {
    let id = identity();
    let all = rustls::crypto::ring::default_provider();
    for name in sybau_tls::fingerprint::names() {
        let fp = Fingerprint::by_name(name).unwrap();
        if fp.require_tls13().is_err() {
            continue;
        }
        let cfg = server_config(&id, Arc::new(all.clone()), &[&rustls::version::TLS13]);
        let (io, server) = spawn_echo(cfg);
        let mut tls = connect(io, &client_config(name, pinned(&id)))
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(
            matches!(tls.alpn(), Some(b"h2")),
            "{name}: ALPN {:?}",
            tls.alpn()
        );
        echo_roundtrip(&mut tls).await;
        tls.shutdown().await.unwrap();
        let mut rest = Vec::new();
        tls.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        let (_, alpn) = server.await.unwrap().expect(name);
        assert_eq!(alpn, b"h2");
    }
}

#[tokio::test]
async fn all_three_cipher_suites() {
    let id = identity();
    for suite in rustls::crypto::ring::default_provider()
        .cipher_suites
        .into_iter()
        .filter(|s| s.tls13().is_some())
    {
        let expect: u16 = suite.suite().into();
        let cfg = server_config(
            &id,
            provider_with(Some(vec![suite]), None),
            &[&rustls::version::TLS13],
        );
        let (io, server) = spawn_echo(cfg);
        let mut tls = connect(io, &client_config("chrome", pinned(&id)))
            .await
            .unwrap();
        echo_roundtrip(&mut tls).await;
        tls.shutdown().await.unwrap();
        assert_eq!(server.await.unwrap().unwrap().0, expect);
    }
}

#[tokio::test]
async fn hello_retry_request_and_each_key_exchange_group() {
    let id = identity();
    // Chrome sends shares for X25519MLKEM768 and X25519; a server that
    // only knows P-256 must ask for a retry.
    for (fingerprint, group) in [
        ("chrome", rustls::crypto::ring::kx_group::SECP256R1),
        ("firefox", rustls::crypto::ring::kx_group::SECP256R1),
        ("chrome", rustls::crypto::ring::kx_group::X25519),
        ("ios", rustls::crypto::ring::kx_group::SECP256R1),
    ] {
        let cfg = server_config(
            &id,
            provider_with(None, Some(vec![group])),
            &[&rustls::version::TLS13],
        );
        let (io, server) = spawn_echo(cfg);
        let mut tls = connect(io, &client_config(fingerprint, pinned(&id)))
            .await
            .unwrap_or_else(|e| panic!("{fingerprint} with {:?}: {e}", group.name()));
        echo_roundtrip(&mut tls).await;
        tls.shutdown().await.unwrap();
        server.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn alpn_override_is_respected() {
    let id = identity();
    let cfg = server_config(&id, provider_with(None, None), &[&rustls::version::TLS13]);
    let (io, server) = spawn_echo(cfg);
    let mut config = client_config("chrome", pinned(&id));
    config.alpn = Some(vec!["http/1.1".into()]);
    let mut tls = connect(io, &config).await.unwrap();
    assert_eq!(tls.alpn(), Some(&b"http/1.1"[..]));
    tls.shutdown().await.unwrap();
    assert_eq!(server.await.unwrap().unwrap().1, b"http/1.1");
}

#[tokio::test]
async fn certificate_failures_are_reported() {
    let id = identity();
    let cfg = || server_config(&id, provider_with(None, None), &[&rustls::version::TLS13]);

    // Self-signed and not pinned: the WebPKI roots do not know it.
    let (io, _server) = spawn_echo(cfg());
    let err = connect(io, &client_config("chrome", VerifyOptions::default()))
        .await
        .err()
        .expect("must fail");
    assert!(
        err.to_string().contains("certificate verification failed"),
        "{err}"
    );

    // Wrong pin.
    let (io, _server) = spawn_echo(cfg());
    let wrong = VerifyOptions {
        leaf_pins: vec![[0u8; 32]],
        ..Default::default()
    };
    assert!(connect(io, &client_config("chrome", wrong)).await.is_err());

    // `insecure` accepts it.
    let (io, _server) = spawn_echo(cfg());
    let insecure = VerifyOptions {
        insecure: true,
        ..Default::default()
    };
    assert!(connect(io, &client_config("firefox", insecure))
        .await
        .is_ok());

    // Xray-style chain pin (one certificate: the hash of the leaf).
    let (io, _server) = spawn_echo(cfg());
    let chain = VerifyOptions {
        insecure: true,
        chain_pins: vec![id.pin],
        ..Default::default()
    };
    assert!(connect(io, &client_config("safari", chain)).await.is_ok());
}

#[tokio::test]
async fn tls12_only_server_gives_a_clear_error() {
    let id = identity();
    let cfg = server_config(&id, provider_with(None, None), &[&rustls::version::TLS12]);
    let (io, _server) = spawn_echo(cfg);
    let err = connect(io, &client_config("chrome", pinned(&id)))
        .await
        .err()
        .expect("must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    assert!(err.to_string().contains("TLS 1.2"), "{err}");

    // A fingerprint that only offers TLS 1.2 is refused before any I/O.
    let (io, _peer) = tokio::io::duplex(64);
    let err = connect(io, &client_config("360", pinned(&id)))
        .await
        .err()
        .expect("must fail");
    assert!(err.to_string().contains("only TLS 1.2"), "{err}");
}

#[tokio::test]
async fn garbage_and_truncated_servers_fail_cleanly() {
    let id = identity();
    for reply in [
        &b"HTTP/1.1 400 Bad Request\r\n\r\n"[..],
        &[0x16, 3, 3, 0xff, 0xff][..],
        &[0x15, 3, 3, 0, 2, 2, 40][..],
        &[][..],
    ] {
        let (io, mut peer) = tokio::io::duplex(1 << 16);
        let reply = reply.to_vec();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let _ = peer.read(&mut buf).await;
            let _ = peer.write_all(&reply).await;
        });
        assert!(connect(io, &client_config("chrome", pinned(&id)))
            .await
            .is_err());
    }
}

/// Server-initiated KeyUpdate in both flavours, in the middle of traffic.
#[tokio::test]
async fn key_update_from_server() {
    let id = identity();
    let cfg = server_config(&id, provider_with(None, None), &[&rustls::version::TLS13]);
    let (client, server) = tokio::io::duplex(1 << 16);
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let server = tokio::spawn(async move {
        let mut tls = acceptor.accept(server).await.unwrap();
        let mut buf = [0u8; 5];
        for round in 0..3 {
            tls.read_exact(&mut buf).await.unwrap();
            // rustls sends KeyUpdate(update_requested) and rotates its keys.
            tls.get_mut().1.refresh_traffic_keys().unwrap();
            tls.write_all(format!("pong{round}").as_bytes())
                .await
                .unwrap();
            tls.flush().await.unwrap();
        }
        tls.read_exact(&mut buf).await.unwrap();
        buf
    });
    let mut tls = connect(client, &client_config("chrome", pinned(&id)))
        .await
        .unwrap();
    for round in 0..3 {
        tls.write_all(format!("ping{round}").as_bytes())
            .await
            .unwrap();
        tls.flush().await.unwrap();
        let mut buf = [0u8; 5];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, format!("pong{round}").as_bytes());
    }
    // Our keys were rotated three times; the server must still understand us.
    tls.write_all(b"final").await.unwrap();
    tls.flush().await.unwrap();
    assert_eq!(&server.await.unwrap(), b"final");
}

/// After the switch both directions bypass TLS, and bytes that were
/// already buffered undecrypted are delivered as they are.
#[tokio::test]
async fn raw_switch_bypasses_the_record_layer() {
    let id = identity();
    let cfg = server_config(&id, provider_with(None, None), &[&rustls::version::TLS13]);
    let (client, server) = tokio::io::duplex(1 << 16);
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let server = tokio::spawn(async move {
        let mut tls = acceptor.accept(server).await.unwrap();
        tls.write_all(b"last encrypted").await.unwrap();
        tls.flush().await.unwrap();
        let mut buf = [0u8; 9];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"encrypted");
        // From here on the "server" talks on the bare transport.
        let (mut raw, _) = tls.into_inner();
        raw.write_all(b"RAW-FROM-SERVER").await.unwrap();
        let mut buf = [0u8; 15];
        raw.read_exact(&mut buf).await.unwrap();
        buf
    });
    let mut tls = connect(client, &client_config("chrome", pinned(&id)))
        .await
        .unwrap();
    tls.write_all(b"encrypted").await.unwrap();
    tls.flush().await.unwrap();
    let mut buf = [0u8; 14];
    tls.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"last encrypted");
    // Give the raw bytes time to arrive behind the last record.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    tls.switch_read_to_raw();
    tls.switch_write_to_raw();
    let mut buf = [0u8; 15];
    tls.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"RAW-FROM-SERVER");
    tls.write_all(b"RAW-FROM-CLIENT").await.unwrap();
    tls.flush().await.unwrap();
    assert_eq!(&server.await.unwrap(), b"RAW-FROM-CLIENT");
}
