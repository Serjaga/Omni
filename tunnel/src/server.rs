
pub use server::Server;
pub use server::ServerConfig;
pub use server::TlsServerConfig;

pub mod utils {
    use crate::RemoteAddr;
    use crate::restrictions::types::{AllowConfig, AllowReverseTunnelConfig, AllowTunnelConfig, MatchConfig, RestrictionConfig, RestrictionsRules, ReverseTunnelProtocol, TunnelProtocol};
    use crate::transport::{JWT_HEADER_PREFIX, JwtTunnelConfig, jwt_token_to_tunnel};
    use anyhow::Context;
    use bytes::Bytes;
    use derive_more::{Display, Error};
    use http_body_util::Either;
    use http_body_util::combinators::BoxBody;
    use hyper::header::{AUTHORIZATION, COOKIE, SEC_WEBSOCKET_PROTOCOL};
    use hyper::{Request, Response, StatusCode, http};
    use jsonwebtoken::TokenData;
    use std::net::IpAddr;
    use tracing::{info, warn};
    use url::Host;

    pub type HttpResponse = Response<Either<String, BoxBody<Bytes, anyhow::Error>>>;

    pub(super) fn bad_request() -> HttpResponse {
        http::Response::builder().status(StatusCode::BAD_REQUEST).body(Either::Left("Invalid request".into())).unwrap()
    }

    pub(super) fn extract_authorization<B>(req: &Request<B>) -> Option<&str> {
        req.headers().get(AUTHORIZATION)?.to_str().ok()
    }

    pub(super) fn extract_x_forwarded_for<B>(req: &Request<B>) -> Option<(IpAddr, &str)> {
        let v = req.headers().get("X-Forwarded-For")?;
        let v = v.to_str().unwrap_or_default();
        let v = v.split_once(',').map(|x| x.0).unwrap_or(v);
        v.parse().ok().map(|ip| (ip, v))
    }

    pub(super) fn extract_path_prefix(path: &str) -> Result<&str, PathPrefixErr> {
        if !path.starts_with('/') { return Err(PathPrefixErr::BadPathPrefix); }
        let (l, r) = path[1..].split_once('/').ok_or(PathPrefixErr::BadUpgradeRequest)?;
        if r.ends_with("events") { Ok(l) } else { Err(PathPrefixErr::BadUpgradeRequest) }
    }

    #[derive(Debug, Display, Error)]
    pub(super) enum PathPrefixErr {
        #[display("bad path prefix")]
        BadPathPrefix,
        #[display("bad upgrade request")]
        BadUpgradeRequest,
    }

    pub(super) fn extract_tunnel_info<B>(req: &Request<B>) -> anyhow::Result<TokenData<JwtTunnelConfig>> {
        let jwt = req.headers().get(SEC_WEBSOCKET_PROTOCOL).and_then(|h| h.to_str().ok()).and_then(|h| h.split_once(JWT_HEADER_PREFIX)).map(|(_p, jwt)| jwt)
            .or_else(|| req.headers().get(COOKIE).and_then(|h| h.to_str().ok())).unwrap_or_default();
        jwt_token_to_tunnel(jwt).with_context(|| format!("decode jwt for tunnel info {:?}", req.headers().get(SEC_WEBSOCKET_PROTOCOL)))
    }

    impl RestrictionConfig {
        #[inline]
        fn filter(&self, path_prefix: &str, authorization: Option<&str>) -> bool {
            self.r#match.iter().all(|m| match m {
                MatchConfig::Any => true,
                MatchConfig::PathPrefix(p) => p.is_match(path_prefix),
                MatchConfig::Authorization(a) => authorization.is_some_and(|v| a.is_match(v)),
            })
        }
    }

    impl AllowReverseTunnelConfig {
        #[inline]
        fn is_allowed(&self, remote: &RemoteAddr) -> bool {
            if !remote.protocol.is_reverse_tunnel() { return false; }
            if let crate::LocalProtocol::ReverseUnix { path } = &remote.protocol {
                return self.unix_path.is_match(path.to_str().unwrap_or("####INVALID####"));
            }
            if !self.port.is_empty() && !self.port.iter().any(|r| r.contains(&remote.port)) { return false; }
            if !self.protocol.is_empty() && !self.protocol.contains(&ReverseTunnelProtocol::from(&remote.protocol)) { return false; }
            match &remote.host {
                Host::Domain(_) => false,
                Host::Ipv4(ip) => self.cidr.iter().any(|c| c.contains(&IpAddr::from(*ip))),
                Host::Ipv6(ip) => self.cidr.iter().any(|c| c.contains(&IpAddr::from(*ip))),
            }
        }
    }

    impl AllowTunnelConfig {
        #[inline]
        fn is_allowed(&self, remote: &RemoteAddr) -> bool {
            if remote.protocol.is_reverse_tunnel() { return false; }
            if !self.port.is_empty() && !self.port.iter().any(|r| r.contains(&remote.port)) { return false; }
            if !self.protocol.is_empty() && !self.protocol.contains(&TunnelProtocol::from(&remote.protocol)) { return false; }
            match &remote.host {
                Host::Domain(h) => self.host.is_match(h),
                Host::Ipv4(ip) => self.cidr.iter().any(|c| c.contains(&IpAddr::from(*ip))),
                Host::Ipv6(ip) => self.cidr.iter().any(|c| c.contains(&IpAddr::from(*ip))),
            }
        }
    }

    impl AllowConfig {
        #[inline]
        fn is_allowed(&self, remote: &RemoteAddr) -> bool {
            match self {
                AllowConfig::ReverseTunnel(c) => c.is_allowed(remote),
                AllowConfig::Tunnel(c) => c.is_allowed(remote),
            }
        }
    }

    pub(super) fn validate_tunnel<'a>(remote: &RemoteAddr, path_prefix: &str, authorization: Option<&str>, restrictions: &'a RestrictionsRules) -> Option<&'a RestrictionConfig> {
        restrictions.restrictions.iter()
            .filter(|r| r.filter(path_prefix, authorization))
            .find(|r| r.allow.iter().any(|a| a.is_allowed(remote)))
    }

    pub(super) fn matches_any_restriction(path_prefix: &str, authorization: Option<&str>, restrictions: &RestrictionsRules) -> bool {
        restrictions.restrictions.iter().any(|r| r.filter(path_prefix, authorization))
    }

    // keep import of `warn` used in some cfg
    #[allow(dead_code)]
    fn _unused_warn() { warn!(""); let _ = info!(""); }
}

mod handler_http2 {
    use crate::executor::TokioExecutorRef;
    use crate::restrictions::types::RestrictionsRules;
    use crate::server::Server;
    use crate::server::utils::HttpResponse;
    use crate::transport;
    use crate::transport::http2::{Http2TransportRead, Http2TransportWrite};
    use bytes::Bytes;
    use futures_util::StreamExt;
    use http_body_util::combinators::BoxBody;
    use http_body_util::{BodyStream, Either, StreamBody};
    use hyper::body::{Frame, Incoming};
    use hyper::header::CONTENT_TYPE;
    use hyper::{Request, Response, StatusCode};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::{mpsc, oneshot};
    use tokio_stream::wrappers::ReceiverStream;
    use tracing::{Instrument, Span};

    pub(super) async fn http_server_upgrade(
        server: Server<impl TokioExecutorRef>,
        restrictions: Arc<RestrictionsRules>,
        restrict_path_prefix: Option<String>,
        client_addr: SocketAddr,
        mut req: Request<Incoming>,
    ) -> HttpResponse {
        let req_content_type = req.headers_mut().remove(CONTENT_TYPE);
        let (parts, body) = req.into_parts();
        let ws_rx = BodyStream::new(body);
        let tunnel_req = Request::from_parts(parts, ());
        let (_remote_addr, local_rx, local_tx, _need_cookie) = match server
            .handle_tunnel_request(restrictions, restrict_path_prefix, client_addr, tunnel_req)
            .await
        {
            Ok(ret) => ret,
            Err(err) => return err,
        };
        let (ws_tx, rx) = mpsc::channel::<Bytes>(1024);
        let body = BoxBody::new(StreamBody::new(ReceiverStream::new(rx).map(|s| -> anyhow::Result<Frame<Bytes>> { Ok(Frame::data(s)) })));
        let mut response = Response::builder().status(StatusCode::OK).body(Either::Right(body)).expect("response");
        let (close_tx, close_rx) = oneshot::channel::<()>();
        server.executor.spawn(transport::io::propagate_remote_to_local(local_tx, Http2TransportRead::new(ws_rx, None), close_rx).instrument(Span::current()));
        server.executor.spawn(transport::io::propagate_local_to_remote(local_rx, Http2TransportWrite::new(ws_tx), close_tx, None).instrument(Span::current()));
        if let Some(ct) = req_content_type { response.headers_mut().insert(CONTENT_TYPE, ct); }
        response
    }
}

mod handler_websocket {
    use crate::executor::TokioExecutorRef;
    use crate::restrictions::types::RestrictionsRules;
    use crate::server::Server;
    use crate::server::utils::{HttpResponse, bad_request};
    use crate::transport;
    use crate::transport::websocket::mk_websocket_tunnel;
    use http_body_util::Either;
    use http_body_util::combinators::BoxBody;
    use hyper::body::Incoming;
    use hyper::header::{HeaderValue, SEC_WEBSOCKET_PROTOCOL};
    use hyper::{Request, Response};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::oneshot;
    use tracing::{Instrument, Span, error, warn};

    pub(super) async fn ws_server_upgrade(
        server: Server<impl TokioExecutorRef>,
        restrictions: Arc<RestrictionsRules>,
        restrict_path_prefix: Option<String>,
        client_addr: SocketAddr,
        mut req: Request<Incoming>,
    ) -> HttpResponse {
        if !fastwebsockets::upgrade::is_upgrade_request(&req) {
            warn!("bad upgrade request: {}", req.uri());
            return bad_request();
        }
        let mask_frame = server.config.websocket_mask_frame;
        let mut probe_req = Request::builder()
            .method(req.method().clone()).uri(req.uri().clone()).version(req.version()).body(()).unwrap();
        *probe_req.headers_mut() = req.headers().clone();
        let (_remote_addr, local_rx, local_tx, _need_cookie) = match server
            .handle_tunnel_request(restrictions, restrict_path_prefix, client_addr, probe_req)
            .await
        {
            Ok(r) => r,
            Err(e) => return e,
        };
        let (response, fut) = match fastwebsockets::upgrade::upgrade(&mut req) {
            Ok(r) => r,
            Err(err) => { warn!("upgrade: {err} {}", req.uri()); return bad_request(); }
        };
        let executor = server.executor.clone();
        let ping_frequency = server.config.websocket_ping_frequency;
        server.executor.spawn(async move {
            let (ws_rx, ws_tx) = match fut.await {
                Ok(ws) => match mk_websocket_tunnel(ws, mask_frame) {
                    Ok(ws) => ws,
                    Err(err) => { error!("ws upgrade: {err:?}"); return Err(err); }
                },
                Err(err) => { error!("ws upgrade: {err:?}"); return Err(anyhow::Error::from(err)); }
            };
            let (close_tx, close_rx) = oneshot::channel::<()>();
            executor.spawn(transport::io::propagate_remote_to_local(local_tx, ws_rx, close_rx).instrument(Span::current()));
            let _ = transport::io::propagate_local_to_remote(local_rx, ws_tx, close_tx, ping_frequency).await;
            Ok(())
        }.instrument(Span::current()));
        let mut response = Response::from_parts(response.into_parts().0, Either::Right(BoxBody::default()));
        response.headers_mut().insert(SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_static("v1"));
        response
    }
}

mod handler_webtransport {
    use crate::executor::TokioExecutorRef;
    use crate::protocols::tls;
    use crate::restrictions::types::RestrictionsRules;
    use crate::LocalProtocol;
    use crate::server::Server;
    use crate::server::utils::{extract_path_prefix, matches_any_restriction};
    use crate::transport;
    use crate::transport::webtransport::{WebTransportRead, WebTransportUdpRead, WebTransportUdpWrite, WebTransportWrite, bind_udp_socket, mk_transport_config, read_jwt_preamble};
    use anyhow::{Context, anyhow};
    use hyper::header::{AUTHORIZATION, COOKIE, HeaderValue};
    use hyper::{Request, StatusCode};
    use std::any::Any;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::oneshot;
    use tokio_rustls::rustls::pki_types::CertificateDer;
    use tracing::{Instrument, Level, Span, debug, error, info, span, warn};
    use web_transport_quinn::quinn;
    use web_transport_quinn::quinn::crypto::rustls::QuicServerConfig;

    pub(super) async fn run_webtransport_server(server: Server<impl TokioExecutorRef>, restrictions: Arc<RestrictionsRules>) -> anyhow::Result<()> {
        let Some(tls_config) = server.config.tls.as_ref() else {
            return Err(anyhow!("webtransport requires TLS"));
        };
        let bind = server.config.bind;
        let mut endpoint = web_transport_quinn::Server::new(mk_quic_endpoint(&server, tls_config)?);
        info!("Starting OmniTunnel webtransport server on udp://{bind}");
        loop {
            let Some(request) = endpoint.accept().await else {
                warn!("webtransport endpoint closed");
                return Ok(());
            };
            let peer_addr = request.conn().remote_address();
            let span = span!(Level::INFO, "cnx", peer = peer_addr.to_string());
            info!(parent: &span, "accepting webtransport");
            let session_handler = {
                let server = server.clone();
                let restrictions = restrictions.clone();
                async move { if let Err(err) = handle_session(server, restrictions, request).await { warn!("{err:?}"); } }.instrument(span)
            };
            server.executor.spawn(session_handler);
        }
    }

    fn mk_quic_server_config(server: &Server<impl TokioExecutorRef>, tls_cfg: &crate::server::TlsServerConfig) -> anyhow::Result<quinn::ServerConfig> {
        let tls = tls::quic_server_config(tls_cfg).context("quic tls")?;
        let tls = QuicServerConfig::try_from(tls).context("quic tls config")?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(tls));
        config.transport_config(Arc::new(mk_transport_config(server.config.websocket_ping_frequency)?));
        Ok(config)
    }

    fn mk_quic_endpoint(server: &Server<impl TokioExecutorRef>, tls_cfg: &crate::server::TlsServerConfig) -> anyhow::Result<quinn::Endpoint> {
        let socket = bind_udp_socket(Some(server.config.bind), server.config.socket_so_mark).with_context(|| format!("bind UDP {}", server.config.bind))?;
        quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(mk_quic_server_config(server, tls_cfg)?), socket, Arc::new(quinn::TokioRuntime)).with_context(|| format!("quic endpoint {}", server.config.bind))
    }

    async fn handle_session(server: Server<impl TokioExecutorRef>, restrictions: Arc<RestrictionsRules>, request: web_transport_quinn::Request) -> anyhow::Result<()> {
        let restrict_path = request.conn().peer_identity().and_then(|id: Box<dyn Any>| id.downcast::<Vec<CertificateDer<'static>>>().ok()).and_then(|certs| {
            tls::find_leaf_certificate(certs.as_slice()).and_then(|c| tls::cn_from_certificate(&c))
        });
        let session_path = request.url.path().to_string();
        let session_headers = request.headers.clone();
        let client_addr = request.conn().remote_address();
        let path_prefix = match extract_path_prefix(&session_path) {
            Ok(p) => p,
            Err(err) => {
                warn!("reject wt {client_addr}: {err}: {session_path}");
                let _ = request.reject(StatusCode::BAD_REQUEST).await;
                return Ok(());
            }
        };
        if let Some(rp) = &restrict_path && path_prefix != rp {
            warn!("wt path '{path_prefix}' != restriction '{rp}'");
            let _ = request.reject(StatusCode::BAD_REQUEST).await;
            return Ok(());
        }
        let allowed = matches_any_restriction(path_prefix, session_headers.get(AUTHORIZATION).and_then(|a| a.to_str().ok()), &restrictions);
        if !allowed {
            warn!("reject wt {client_addr}: no matching restriction");
            let _ = request.reject(StatusCode::BAD_REQUEST).await;
            return Ok(());
        }
        let session = request.ok().await.with_context(|| format!("accept wt from {client_addr}"))?;
        loop {
            let (send, recv) = match session.accept_bi().await {
                Ok(s) => s,
                Err(err) => { debug!("wt session {client_addr} ended: {err}"); return Ok(()); }
            };
            let restrictions = restrictions.clone();
            let server = server.clone();
            let session = session.clone();
            let session_path = session_path.clone();
            let session_headers = session_headers.clone();
            let restrict_path = restrict_path.clone();
            let span = span!(Level::INFO, "tunnel", peer = client_addr.to_string());
            server.executor.clone().spawn(async move {
                if let Err(err) = wt_server_connect(server, restrictions, session, client_addr, restrict_path, &session_path, session_headers, (send, recv)).await {
                    warn!("{err:?}");
                }
            }.instrument(span));
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn wt_server_connect(
        server: Server<impl TokioExecutorRef>,
        restrictions: Arc<RestrictionsRules>,
        session: web_transport_quinn::Session,
        client_addr: SocketAddr,
        restrict_path: Option<String>,
        session_path: &str,
        session_headers: hyper::HeaderMap,
        (mut send, mut recv): (web_transport_quinn::SendStream, web_transport_quinn::RecvStream),
    ) -> anyhow::Result<()> {
        let jwt = tokio::time::timeout(server.config.timeout_connect, read_jwt_preamble(&mut recv)).await
            .map_err(|_| anyhow!("client {client_addr} sent no jwt within {:?}", server.config.timeout_connect))?
            .with_context(|| format!("read jwt from {client_addr}"))?;
        let mut http_req = Request::builder().method("CONNECT").uri(session_path).body(()).with_context(|| format!("bad wt path: {session_path}"))?;
        *http_req.headers_mut() = session_headers;
        http_req.headers_mut().insert(COOKIE, HeaderValue::from_str(&jwt).with_context(|| "bad jwt in wt")?);
        let (remote_addr, local_rx, local_tx, _need_cookie) = match server
            .handle_tunnel_request(restrictions, restrict_path, client_addr, http_req)
            .await
        {
            Ok(t) => t,
            Err(response) => {
                let status = response.status();
                warn!("reject wt {client_addr}: {status}");
                let _ = send.reset(status.as_u16() as u32);
                return Ok(());
            }
        };
        let (close_tx, close_rx) = oneshot::channel::<()>();
        if matches!(remote_addr.protocol, LocalProtocol::Udp { .. } | LocalProtocol::TProxyUdp { .. }) {
            server.executor.spawn(transport::io::propagate_remote_to_local(local_tx, WebTransportUdpRead::new(recv, session.clone()), close_rx).instrument(Span::current()));
            server.executor.spawn(transport::io::propagate_local_to_remote(local_rx, WebTransportUdpWrite::new(send, session), close_tx, None).instrument(Span::current()));
        } else {
            server.executor.spawn(transport::io::propagate_remote_to_local(local_tx, WebTransportRead::new(recv, session.clone()), close_rx).instrument(Span::current()));
            server.executor.spawn(transport::io::propagate_local_to_remote(local_rx, WebTransportWrite::new(send, session), close_tx, None).instrument(Span::current()));
        }
        Ok(())
    }
}

mod server {
    use crate::executor::{DefaultTokioExecutor, TokioExecutorRef};
    use crate::protocols;
    use crate::protocols::dns::DnsResolver;
    use crate::protocols::tls;
    use crate::restrictions::config_reloader::RestrictionsRulesReloader;
    use crate::restrictions::types::RestrictionsRules;
    use crate::somark::SoMark;
    use crate::server::handler_http2::http_server_upgrade;
    use crate::server::handler_websocket::ws_server_upgrade;
    use crate::server::handler_webtransport;
    use crate::server::utils::{HttpResponse, bad_request, extract_authorization, extract_path_prefix, extract_tunnel_info, extract_x_forwarded_for, validate_tunnel};
    use crate::tls_reloader::TlsReloader;
    use crate::{LocalProtocol, RemoteAddr};
    use anyhow::{Context, anyhow};
    use futures_util::FutureExt;
    use hyper::body::Incoming;
    use hyper::server::conn::{http1, http2};
    use hyper::service::service_fn;
    use hyper::{Request, StatusCode, Version, http};
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
    use parking_lot::Mutex;
    use socket2::SockRef;
    use std::fmt::{Debug, Formatter};
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tracing::{Instrument, Level, Span, error, info, span, warn};
    use url::Url;

    #[derive(Debug)]
    pub struct TlsServerConfig {
        pub tls_certificate: Mutex<Vec<CertificateDer<'static>>>,
        pub tls_key: Mutex<PrivateKeyDer<'static>>,
        pub tls_client_ca_certificates: Option<Mutex<Vec<CertificateDer<'static>>>>,
        pub tls_certificate_path: Option<PathBuf>,
        pub tls_key_path: Option<PathBuf>,
        pub tls_client_ca_certs_path: Option<PathBuf>,
    }

    pub struct ServerConfig {
        pub socket_so_mark: SoMark,
        pub bind: SocketAddr,
        pub websocket_ping_frequency: Option<Duration>,
        pub timeout_connect: Duration,
        pub websocket_mask_frame: bool,
        pub tls: Option<TlsServerConfig>,
        pub dns_resolver: DnsResolver,
        pub restriction_config: Option<PathBuf>,
        pub http_proxy: Option<Url>,
        pub remote_server_idle_timeout: Duration,
        pub enable_webtransport: bool,
    }

    impl Debug for ServerConfig {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ServerConfig")
                .field("so_mark", &self.socket_so_mark)
                .field("bind", &self.bind)
                .field("websocket_ping_frequency", &self.websocket_ping_frequency)
                .field("timeout_connect", &self.timeout_connect)
                .field("websocket_mask_frame", &self.websocket_mask_frame)
                .field("restriction_config", &self.restriction_config)
                .field("tls", &self.tls.is_some())
                .field("remote_server_idle_timeout", &self.remote_server_idle_timeout)
                .field("enable_webtransport", &self.enable_webtransport)
                .finish()
        }
    }

    #[derive(Clone)]
    pub struct Server<E: TokioExecutorRef = DefaultTokioExecutor> {
        pub config: Arc<ServerConfig>,
        pub executor: E,
    }

    impl<E: TokioExecutorRef> Server<E> {
        pub fn new(config: ServerConfig, executor: E) -> Self {
            Self { config: Arc::new(config), executor }
        }

        async fn exec_tunnel(
            &self,
            remote: RemoteAddr,
            client_addr: SocketAddr,
        ) -> anyhow::Result<(RemoteAddr, Pin<Box<dyn AsyncRead + Send>>, Pin<Box<dyn AsyncWrite + Send>>)> {
            match remote.protocol {
                LocalProtocol::Udp { timeout, .. } => {
                    if self.config.http_proxy.is_some() {
                        return Err(anyhow!("UDP tunneling не поддерживает HTTP proxy"));
                    }
                    let _ = timeout;
                    let stream = protocols::udp::connect(&remote.host, remote.port, self.config.timeout_connect, self.config.socket_so_mark, &self.config.dns_resolver).await?;
                    Ok((remote, Box::pin(stream.clone()), Box::pin(stream)))
                }
                LocalProtocol::Tcp { proxy_protocol } => {
                    let (rx, mut tx) = match &self.config.http_proxy {
                        None => {
                            let stream = protocols::tcp::connect(&remote.host, remote.port, self.config.socket_so_mark, self.config.timeout_connect, &self.config.dns_resolver).await?;
                            stream.into_split()
                        }
                        Some(proxy_url) => {
                            let stream = protocols::tcp::connect_with_http_proxy(proxy_url, &remote.host, remote.port, self.config.socket_so_mark, self.config.timeout_connect, &self.config.dns_resolver).await?;
                            stream.into_split()
                        }
                    };
                    if proxy_protocol {
                        let mut dest_addr = tx.local_addr()?;
                        if client_addr.is_ipv6() && dest_addr.is_ipv4() {
                            dest_addr = SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), dest_addr.port());
                        } else if client_addr.is_ipv4() && dest_addr.is_ipv6() {
                            dest_addr = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), dest_addr.port());
                        }
                        let header = ppp::v2::Builder::with_addresses(
                            ppp::v2::Version::Two | ppp::v2::Command::Proxy,
                            ppp::v2::Protocol::Stream,
                            (client_addr, dest_addr),
                        ).build()?;
                        let _ = tx.write_all(&header).await;
                    }
                    Ok((remote, Box::pin(rx), Box::pin(tx)))
                }
                other => Err(anyhow!("unsupported target protocol {:?}", other)),
            }
        }

        pub async fn handle_tunnel_request<B>(
            &self,
            restrictions: Arc<RestrictionsRules>,
            restrict_path_prefix: Option<String>,
            mut client_addr: SocketAddr,
            req: Request<B>,
        ) -> Result<
            (RemoteAddr, Pin<Box<dyn AsyncRead + Send>>, Pin<Box<dyn AsyncWrite + Send>>, bool),
            HttpResponse,
        >
        where B: Send
        {
            if let Some((x_forward_for, x_forward_for_str)) = extract_x_forwarded_for(&req) {
                info!("Request X-Forwarded-For: {x_forward_for:?}");
                Span::current().record("forwarded_for", x_forward_for_str);
                client_addr.set_ip(x_forward_for);
            }
            let path_prefix = extract_path_prefix(req.uri().path()).map_err(|err| {
                warn!("Rejecting: {err}: {}", req.uri());
                bad_request()
            })?;
            if let Some(restrict_path) = restrict_path_prefix && path_prefix != restrict_path {
                warn!("Client path '{path_prefix}' != restriction '{restrict_path}'");
                return Err(bad_request());
            }
            let jwt = extract_tunnel_info(&req).map_err(|err| { warn!("{}", err); bad_request() })?;
            Span::current().record("id", &jwt.claims.id);
            Span::current().record("remote", format!("{}:{}", jwt.claims.r, jwt.claims.rp));
            let remote = RemoteAddr::try_from(jwt.claims).map_err(|err| {
                warn!("bad tunnel info: {err} {}", req.uri());
                bad_request()
            })?;
            let authorization = extract_authorization(&req);
            let restriction = validate_tunnel(&remote, path_prefix, authorization, &restrictions).ok_or_else(|| {
                warn!("Rejecting: not allowed destination: {remote:?}");
                bad_request()
            })?;
            info!("Tunnel accepted due to matched restriction: {}", restriction.name);
            let _ = restriction;
            let req_protocol = remote.protocol.clone();
            let need_cookie = req_protocol.is_dynamic_reverse_tunnel();
            let tunnel = self.exec_tunnel(remote, client_addr).await.map_err(|err| {
                warn!("Rejecting: {err} {}", req.uri());
                bad_request()
            })?;
            let (remote_addr, local_rx, local_tx) = tunnel;
            info!("connected to {:?} {}:{}", req_protocol, remote_addr.host, remote_addr.port);
            Ok((remote_addr, local_rx, local_tx, need_cookie))
        }

        pub async fn serve(self, restrictions: RestrictionsRules) -> anyhow::Result<()> {
            info!("Starting OmniTunnel server on {}", self.config.bind);
            let mk_ws = |server: Server<_>, r: Arc<RestrictionsRules>, restrict: Option<String>, addr: SocketAddr| {
                move |req: Request<Incoming>| {
                    ws_server_upgrade(server.clone(), r.clone(), restrict.clone(), addr, req).map::<anyhow::Result<_>, _>(Ok).instrument(mk_span())
                }
            };
            let mk_h2 = |server: Server<_>, r: Arc<RestrictionsRules>, restrict: Option<String>, addr: SocketAddr| {
                move |req: Request<Incoming>| {
                    http_server_upgrade(server.clone(), r.clone(), restrict.clone(), addr, req).map::<anyhow::Result<_>, _>(Ok).instrument(mk_span())
                }
            };
            let mk_auto = |server: Server<_>, r: Arc<RestrictionsRules>, restrict: Option<String>, addr: SocketAddr| {
                move |req: Request<Incoming>| {
                    let server = server.clone();
                    let r = r.clone();
                    let restrict = restrict.clone();
                    async move {
                        if fastwebsockets::upgrade::is_upgrade_request(&req) {
                            ws_server_upgrade(server.clone(), r, restrict, addr, req).map::<anyhow::Result<_>, _>(Ok).await
                        } else if req.version() == Version::HTTP_2 {
                            http_server_upgrade(server, r, restrict, addr, req).map::<anyhow::Result<_>, _>(Ok).await
                        } else {
                            error!("Invalid protocol {:?}", req.version());
                            Ok(http::Response::builder().status(StatusCode::BAD_REQUEST).body(http_body_util::Either::Left("bad protocol".to_string())).unwrap())
                        }
                    }.instrument(mk_span())
                }
            };
            let mut tls_context = if let Some(tls_config) = &self.config.tls {
                let ctx = TlsContext {
                    tls_acceptor: Arc::new(tls::tls_acceptor(tls_config, Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()]))?),
                    tls_reloader: TlsReloader::new_for_server(self.config.clone())?,
                    tls_config,
                };
                Some(ctx)
            } else { None };
            let reloader = RestrictionsRulesReloader::new(restrictions, self.config.restriction_config.clone())?;
            let listener = TcpListener::bind(&self.config.bind).await.with_context(|| format!("bind {}", self.config.bind))?;
            if self.config.enable_webtransport {
                if self.config.tls.is_none() {
                    return Err(anyhow!("webtransport требует TLS"));
                }
                let server = self.clone();
                let r = reloader.restrictions_rules();
                self.executor.spawn(async move {
                    if let Err(err) = handler_webtransport::run_webtransport_server(server, r).await {
                        error!("wt server stopped: {err:?}");
                    }
                });
            }
            loop {
                let (stream, peer_addr) = match listener.accept().await {
                    Ok(r) => r,
                    Err(err) => { warn!("accept: {err:?}"); continue; }
                };
                let span = span!(Level::INFO, "cnx", peer = peer_addr.to_string());
                info!(parent: &span, "accept");
                if let Err(err) = protocols::tcp::configure_socket(SockRef::from(&stream), SoMark::new(None)) {
                    warn!("socket config: {err:?}");
                }
                let server = self.clone();
                let r = reloader.restrictions_rules();
                match tls_context.as_mut() {
                    Some(tls) => {
                        let acceptor = tls.tls_acceptor().clone();
                        let fut = async move {
                            let tls_stream = match acceptor.accept(stream).await {
                                Ok(s) => TokioIo::new(s),
                                Err(err) => { error!("tls accept: {err}"); return; }
                            };
                            let alpn = tls_stream.inner().get_ref().1.alpn_protocol().map(|a| a.to_vec());
                            let restrict_path = tls_stream.inner().get_ref().1.peer_certificates()
                                .and_then(tls::find_leaf_certificate)
                                .and_then(|c| tls::cn_from_certificate(&c));
                            match alpn.as_deref() {
                                Some(b"h2") => {
                                    let mut b = http2::Builder::new(TokioExecutor::new());
                                    b.timer(TokioTimer::new());
                                    if let Some(ping) = server.config.websocket_ping_frequency { b.keep_alive_interval(ping); }
                                    if let Err(e) = b.serve_connection(tls_stream, service_fn(mk_h2(server, r, restrict_path, peer_addr))).await {
                                        error!("h2 connection: {e:?}");
                                    }
                                }
                                _ => {
                                    if let Err(e) = http1::Builder::new()
                                        .timer(TokioTimer::new())
                                        .header_read_timeout(None)
                                        .serve_connection(tls_stream, service_fn(mk_ws(server, r, restrict_path, peer_addr)))
                                        .with_upgrades().await
                                    {
                                        error!("http/1.1 connection: {e:?}");
                                    }
                                }
                            }
                        }.instrument(span);
                        self.executor.spawn(fut);
                    }
                    None => {
                        let fut = async move {
                            let stream = TokioIo::new(stream);
                            let mut b = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                            b.http1().timer(TokioTimer::new());
                            b.http2().timer(TokioTimer::new());
                            if let Some(ping) = server.config.websocket_ping_frequency { b.http2().keep_alive_interval(ping); }
                            if let Err(e) = b.serve_connection_with_upgrades(stream, service_fn(mk_auto(server, r, None, peer_addr))).await {
                                error!("auto connection: {e:?}");
                            }
                        }.instrument(span);
                        self.executor.spawn(fut);
                    }
                }
            }
        }
    }

    fn mk_span() -> Span {
        span!(Level::INFO, "tunnel", id = tracing::field::Empty, remote = tracing::field::Empty, forwarded_for = tracing::field::Empty)
    }

    struct TlsContext<'a> {
        tls_acceptor: Arc<TlsAcceptor>,
        tls_reloader: TlsReloader,
        tls_config: &'a TlsServerConfig,
    }
    impl TlsContext<'_> {
        #[inline]
        pub fn tls_acceptor(&mut self) -> &Arc<TlsAcceptor> {
            if self.tls_reloader.should_reload_certificate() {
                match tls::tls_acceptor(self.tls_config, Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()])) {
                    Ok(a) => self.tls_acceptor = Arc::new(a),
                    Err(err) => error!("tls reload: {err:?}"),
                };
            }
            &self.tls_acceptor
        }
    }
}
