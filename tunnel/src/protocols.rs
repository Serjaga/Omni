
pub mod tcp {
    use anyhow::{Context, anyhow};
    use bytes::BytesMut;
    use socket2::{SockRef, TcpKeepalive};
    use std::{io, net::{SocketAddr, SocketAddrV4, SocketAddrV6}, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpSocket, TcpStream};
    use tokio::task::JoinSet;
    use tokio::time::{sleep, timeout};
    use url::{Host, Url};
    use crate::protocols::dns::DnsResolver;
    use crate::somark::SoMark;

    pub fn configure_socket(socket: SockRef, so_mark: SoMark) -> Result<(), anyhow::Error> {
        socket.set_tcp_nodelay(true).with_context(|| format!("set no_delay: {:?}", io::Error::last_os_error()))?;
        #[cfg(not(any(target_os = "windows", target_os = "openbsd")))]
        let tcp_keepalive = TcpKeepalive::new().with_time(Duration::from_secs(60)).with_interval(Duration::from_secs(10)).with_retries(3);
        #[cfg(target_os = "windows")]
        let tcp_keepalive = TcpKeepalive::new().with_time(Duration::from_secs(60)).with_interval(Duration::from_secs(10));
        #[cfg(target_os = "openbsd")]
        let tcp_keepalive = TcpKeepalive::new().with_time(Duration::from_secs(60));
        socket.set_tcp_keepalive(&tcp_keepalive).with_context(|| format!("set tcp_keepalive: {:?}", io::Error::last_os_error()))?;
        so_mark.set_mark(socket).context("set SO_MARK")?;
        Ok(())
    }

    pub async fn connect(host: &Host<String>, port: u16, so_mark: SoMark, connect_timeout: Duration, dns_resolver: &DnsResolver) -> Result<TcpStream, anyhow::Error> {
        tracing::info!("Opening TCP connection to {host}:{port}");
        let socket_addrs: Vec<SocketAddr> = match host {
            Host::Domain(domain) => dns_resolver.lookup_host(domain.as_str(), port).await.with_context(|| format!("cannot resolve domain: {domain}"))?,
            Host::Ipv4(ip) => vec![SocketAddr::V4(SocketAddrV4::new(*ip, port))],
            Host::Ipv6(ip) => vec![SocketAddr::V6(SocketAddrV6::new(*ip, port, 0, 0))],
        };
        let mut cnx = None;
        let mut last_err = None;
        let mut join_set = JoinSet::new();
        for (ix, addr) in socket_addrs.into_iter().enumerate() {
            let socket = match &addr { SocketAddr::V4(_) => TcpSocket::new_v4(), SocketAddr::V6(_) => TcpSocket::new_v6() };
            let socket = match socket { Ok(s) => s, Err(err) => { last_err = Some(err); continue; } };
            configure_socket(SockRef::from(&socket), so_mark)?;
            let fut = async move {
                if ix > 0 { sleep(Duration::from_millis(250 * ix as u64)).await; }
                match timeout(connect_timeout, socket.connect(addr)).await {
                    Ok(Ok(s)) => Ok(Ok(s)),
                    Ok(Err(e)) => Ok(Err((addr, e))),
                    Err(e) => Err((addr, e)),
                }
            };
            join_set.spawn(fut);
        }
        while let (None, Some(res)) = (&cnx, join_set.join_next().await) {
            match res? {
                Ok(Ok(stream)) => { join_set.abort_all(); cnx = Some(stream); }
                Ok(Err((addr, err))) => { tracing::debug!("tcp connect {addr} err {err}"); last_err = Some(err); }
                Err((addr, _)) => { tracing::warn!("tcp connect {addr} timeout"); }
            }
        }
        cnx.ok_or_else(|| anyhow!("Cannot connect to tcp {host}:{port} reason {last_err:?}"))
    }

    pub async fn connect_with_http_proxy(proxy: &Url, host: &Host<String>, port: u16, so_mark: SoMark, connect_timeout: Duration, dns_resolver: &DnsResolver) -> Result<TcpStream, anyhow::Error> {
        use base64::Engine;
        let proxy_host = proxy.host().context("Cannot parse proxy host")?.to_owned();
        let proxy_port = proxy.port_or_known_default().unwrap_or(80);
        let mut socket = connect(&proxy_host, proxy_port, so_mark, connect_timeout, dns_resolver).await?;
        let authorization = if let Some((user, password)) = proxy.password().map(|p| (proxy.username(), p)) {
            let user = urlencoding::decode(user).with_context(|| format!("url decode user: {user}"))?;
            let password = urlencoding::decode(password).with_context(|| format!("url decode password: {password}"))?;
            let creds = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
            format!("Proxy-Authorization: Basic {creds}\r\n")
        } else { String::new() };
        let connect_request = format!("CONNECT {host}:{port} HTTP/1.0\r\nHost: {host}:{port}\r\n{authorization}\r\n");
        socket.write_all(connect_request.as_bytes()).await?;
        let mut buf = BytesMut::with_capacity(1024);
        loop {
            let nb = tokio::time::timeout(connect_timeout, socket.read_buf(&mut buf)).await;
            match nb {
                Ok(Ok(0)) => return Err(anyhow!("proxy closed without response")),
                Ok(Ok(_)) => {}
                Ok(Err(err)) => return Err(anyhow!("proxy read: {err}")),
                Err(_) => return Err(anyhow!("proxy connect timeout")),
            }
            static END: &[u8; 4] = b"\r\n\r\n";
            if buf.len() > 50 * 1024 || buf.windows(END.len()).any(|w| w == END) { break; }
        }
        static OK_10: &[u8] = b"HTTP/1.0 200 ";
        static OK_11: &[u8] = b"HTTP/1.1 200 ";
        if !buf.windows(OK_10.len()).any(|w| w == OK_10 || w == OK_11) {
            return Err(anyhow!("proxy invalid response: {}", String::from_utf8_lossy(&buf)));
        }
        Ok(socket)
    }
}

pub mod udp {
    use anyhow::{Context, anyhow};
    use socket2::SockRef;
    use std::{io, net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6}, pin::Pin, sync::Arc, task::{self, Poll}};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::UdpSocket;
    use tokio::task::JoinSet;
    use tokio::time::{sleep, timeout};
    use url::Host;
    use std::time::Duration;
    use crate::protocols::dns::DnsResolver;
    use crate::somark::SoMark;

    #[derive(Clone)]
    pub struct WsUdpStream { socket: Arc<UdpSocket> }
    impl WsUdpStream { pub fn new(socket: Arc<UdpSocket>) -> Self { Self { socket } } }

    impl AsyncRead for WsUdpStream {
        fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            unsafe { self.map_unchecked_mut(|x| &mut x.socket) }.poll_recv_from(cx, buf).map(|x| x.map(|_| ()))
        }
    }
    impl AsyncWrite for WsUdpStream {
        fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, io::Error>> {
            unsafe { self.map_unchecked_mut(|x| &mut x.socket) }.poll_send(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> { Poll::Ready(Ok(())) }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> { Poll::Ready(Ok(())) }
    }

    pub async fn connect(host: &Host<String>, port: u16, connect_timeout: Duration, so_mark: SoMark, dns_resolver: &DnsResolver) -> anyhow::Result<WsUdpStream> {
        let addrs: Vec<SocketAddr> = match host {
            Host::Domain(domain) => dns_resolver.lookup_host(domain.as_str(), port).await.with_context(|| format!("cannot resolve domain: {domain}"))?,
            Host::Ipv4(ip) => vec![SocketAddr::V4(SocketAddrV4::new(*ip, port))],
            Host::Ipv6(ip) => vec![SocketAddr::V6(SocketAddrV6::new(*ip, port, 0, 0))],
        };
        let mut cnx = None;
        let mut last_err = None;
        let mut join_set = JoinSet::new();
        for (ix, addr) in addrs.into_iter().enumerate() {
            let socket = match &addr {
                SocketAddr::V4(_) => UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await,
                SocketAddr::V6(_) => UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)).await,
            };
            let socket = match socket { Ok(s) => s, Err(err) => { tracing::warn!("bind udp err {err:?}"); continue; } };
            so_mark.set_mark(SockRef::from(&socket)).context("set SO_MARK on UDP")?;
            let fut = async move {
                if ix > 0 { sleep(Duration::from_millis(250 * ix as u64)).await; }
                match timeout(connect_timeout, socket.connect(addr)).await {
                    Ok(Ok(())) => Ok(Ok(socket)),
                    Ok(Err(e)) => Ok(Err((addr, e))),
                    Err(e) => Err((addr, e)),
                }
            };
            join_set.spawn(fut);
        }
        while let (None, Some(res)) = (&cnx, join_set.join_next().await) {
            match res? {
                Ok(Ok(socket)) => { join_set.abort_all(); cnx = Some(socket); }
                Ok(Err((addr, err))) => { tracing::debug!("udp {addr} err {err}"); last_err = Some(err); }
                Err((addr, _)) => { tracing::warn!("udp {addr} timeout"); }
            }
        }
        match cnx {
            Some(s) => Ok(WsUdpStream::new(Arc::new(s))),
            None => Err(anyhow!("Cannot connect to udp {host}:{port} reason {last_err:?}")),
        }
    }
}

pub mod dns {
    use anyhow::Context;
    use std::net::SocketAddr;
    use crate::somark::SoMark;

    #[derive(Clone, Debug)]
    pub struct DnsResolver { prefer_ipv6: bool }

    impl DnsResolver {
        pub fn new_from_urls(_resolvers: &[url::Url], _proxy: Option<url::Url>, _so_mark: SoMark, prefer_ipv6: bool) -> anyhow::Result<Self> {
            Ok(Self { prefer_ipv6 })
        }
        pub async fn lookup_host(&self, domain: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
            let mut addrs: Vec<SocketAddr> = tokio::net::lookup_host((domain, port)).await
                .with_context(|| format!("cannot resolve {domain}"))?
                .collect();
            if self.prefer_ipv6 { addrs.sort_by_key(|a| !a.is_ipv6()); }
            else { addrs.sort_by_key(|a| a.is_ipv6()); }
            Ok(addrs)
        }
    }
}

pub mod tls {
    pub use server::{load_certificates_from_pem, load_private_key_from_file, tls_acceptor, quic_server_config};
    pub use utils::{cn_from_certificate, find_leaf_certificate};

    mod server {
        use anyhow::{Context, anyhow};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::server::WebPkiClientVerifier;
        use rustls::server::danger::ClientCertVerifier;
        use rustls::KeyLogFile;
        use rustls::RootCertStore;
        use std::fs::File;
        use std::io::BufReader;
        use std::path::Path;
        use std::sync::Arc;
        use tokio_rustls::{rustls, TlsAcceptor};
        use tracing::{info, warn};
        use crate::server::TlsServerConfig;

        pub fn load_certificates_from_pem(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
            info!("Loading tls certificate from {:?}", path);
            let file = File::open(path)?;
            let mut reader = BufReader::new(file);
            let mut out = Vec::new();
            for cert in rustls_pemfile::certs(&mut reader) {
                match cert { Ok(c) => out.push(c), Err(err) => warn!("parse cert: {err:?}") }
            }
            Ok(out)
        }

        pub fn load_private_key_from_file(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
            info!("Loading tls private key from {:?}", path);
            let file = File::open(path)?;
            let mut reader = BufReader::new(file);
            let Some(key) = rustls_pemfile::private_key(&mut reader)? else { return Err(anyhow!("no private key in {path:?}")); };
            Ok(key)
        }

        fn client_cert_verifier(cfg: &TlsServerConfig) -> anyhow::Result<Arc<dyn ClientCertVerifier>> {
            let Some(ca_certs) = &cfg.tls_client_ca_certificates else { return Ok(WebPkiClientVerifier::no_client_auth()); };
            let mut root = RootCertStore::empty();
            for c in ca_certs.lock().iter() { root.add(c.clone()).context("add mTLS CA")?; }
            WebPkiClientVerifier::builder(Arc::new(root)).build().map_err(|e| anyhow!("mTLS client verifier: {e:?}"))
        }

        pub fn tls_acceptor(cfg: &TlsServerConfig, alpn: Option<Vec<Vec<u8>>>) -> anyhow::Result<TlsAcceptor> {
            let verifier = client_cert_verifier(cfg)?;
            let mut config = rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(cfg.tls_certificate.lock().clone(), cfg.tls_key.lock().clone_key())
                .context("invalid tls cert or key")?;
            config.key_log = Arc::new(KeyLogFile::new());
            if let Some(alpn) = alpn { config.alpn_protocols = alpn; }
            Ok(TlsAcceptor::from(Arc::new(config)))
        }

        pub fn quic_server_config(cfg: &TlsServerConfig) -> anyhow::Result<rustls::ServerConfig> {
            let provider = rustls::crypto::CryptoProvider::get_default()
                .ok_or_else(|| anyhow!("no default crypto provider"))?.clone();
            let mut config = rustls::ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .context("QUIC requires TLS1.3")?
                .with_client_cert_verifier(client_cert_verifier(cfg)?)
                .with_single_cert(cfg.tls_certificate.lock().clone(), cfg.tls_key.lock().clone_key())
                .context("invalid tls cert or key")?;
            config.key_log = Arc::new(KeyLogFile::new());
            config.alpn_protocols = vec![web_transport_quinn::ALPN.as_bytes().to_vec()];
            Ok(config)
        }
    }

    mod utils {
        use rustls::pki_types::CertificateDer;
        use x509_parser::parse_x509_certificate;
        use x509_parser::prelude::X509Certificate;

        pub fn find_leaf_certificate<'a>(certs: &'a [CertificateDer<'static>]) -> Option<X509Certificate<'a>> {
            for c in certs {
                if let Ok((_, x)) = parse_x509_certificate(c) && !x.is_ca() { return Some(x); }
            }
            None
        }
        pub fn cn_from_certificate(x: &X509Certificate) -> Option<String> {
            x.tbs_certificate.subject.iter_common_name().flat_map(|cn| cn.as_str().ok()).next().map(|s| s.to_string())
        }
    }
}
