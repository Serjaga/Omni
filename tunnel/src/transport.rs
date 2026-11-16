
pub use jwt::{JWT_HEADER_PREFIX, JwtTunnelConfig, jwt_token_to_tunnel};

pub mod jwt {
    use serde::Deserialize;
    use std::sync::LazyLock;
    use std::time::SystemTime;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, TokenData};
    use url::Host;

    pub static JWT_HEADER_PREFIX: &str = "authorization.bearer.";

    static JWT_KEY: LazyLock<(Header, EncodingKey)> = LazyLock::new(|| {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos().to_ne_bytes();
        (Header::new(Algorithm::HS256), EncodingKey::from_secret(&now))
    });

    #[derive(Debug, Clone, Deserialize)]
    pub struct JwtTunnelConfig { pub id: String, pub p: crate::LocalProtocol, pub r: String, pub rp: u16 }

    pub fn jwt_token_to_tunnel(token: &str) -> anyhow::Result<TokenData<JwtTunnelConfig>> {
        let mut validation = jsonwebtoken::Validation::new(Algorithm::HS256);
        validation.insecure_disable_signature_validation();
        validation.validate_exp = false;
        validation.required_spec_claims.clear();
        let key = jsonwebtoken::DecodingKey::from_secret(b"insecure-jwt-decoding-key");
        Ok(jsonwebtoken::decode::<JwtTunnelConfig>(token, &key, &validation)?)
    }

    impl TryFrom<JwtTunnelConfig> for crate::RemoteAddr {
        type Error = anyhow::Error;
        fn try_from(jwt: JwtTunnelConfig) -> anyhow::Result<Self> {
            Ok(Self { protocol: jwt.p, host: Host::parse(&jwt.r)?, port: jwt.rp })
        }
    }

    // используется для reverse-tunnels, но мы его оставляем — некоторые клиенты зависят от формата
    #[allow(dead_code)]
    pub(crate) fn tunnel_to_jwt_token(id: uuid::Uuid, remote: &crate::RemoteAddr) -> String {
        #[derive(Serialize)]
        struct Claims<'a> { id: String, p: &'a crate::LocalProtocol, r: String, rp: u16 }
        let claims = Claims { id: id.to_string(), p: &remote.protocol, r: remote.host.to_string(), rp: remote.port };
        let (alg, secret) = JWT_KEY.deref();
        jsonwebtoken::encode(alg, &claims, secret).unwrap_or_default()
    }

    use std::ops::Deref;
    use serde::Serialize;
}

pub mod io {
    use bytes::{BufMut, BytesMut};
    use futures_util::{FutureExt, pin_mut};
    use std::future::Future;
    use std::io::ErrorKind;
    use std::pin::Pin;
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
    use tokio::select;
    use tokio::sync::{Notify, oneshot};
    use tokio::time::Instant;
    use tracing::{debug, error, info, warn};

    pub(crate) static MAX_PACKET_LENGTH: usize = 64 * 1024;

    pub trait TransportWrite: Send + 'static {
        fn buf_mut(&mut self) -> &mut BytesMut;
        fn write(&mut self) -> impl Future<Output = Result<(), std::io::Error>> + Send;
        fn ping(&mut self) -> impl Future<Output = Result<(), std::io::Error>> + Send;
        fn close(&mut self) -> impl Future<Output = Result<(), std::io::Error>> + Send;
        fn pending_operations_notify(&mut self) -> std::sync::Arc<Notify>;
        fn handle_pending_operations(&mut self) -> impl Future<Output = Result<(), std::io::Error>> + Send;
    }

    pub trait TransportRead: Send + 'static {
        fn copy(&mut self, writer: impl AsyncWrite + Unpin + Send) -> impl Future<Output = Result<(), std::io::Error>> + Send;
    }

    pub async fn propagate_local_to_remote(local_rx: impl AsyncRead, mut ws_tx: impl TransportWrite, mut close_tx: oneshot::Sender<()>, ping_frequency: Option<Duration>) -> anyhow::Result<()> {
        let _guard = scopeguard::guard((), |_| { info!("Closing local => remote tunnel"); });
        let frequency = ping_frequency.unwrap_or(Duration::from_secs(3600 * 24));
        let start_at = Instant::now().checked_add(frequency).unwrap_or_else(Instant::now);
        let timeout = tokio::time::interval_at(start_at, frequency);
        let should_close = close_tx.closed().fuse();
        let notify = ws_tx.pending_operations_notify();
        let mut has_pending_operations = notify.notified();
        let mut has_pending_operations_pin = unsafe { Pin::new_unchecked(&mut has_pending_operations) };
        pin_mut!(timeout);
        pin_mut!(should_close);
        pin_mut!(local_rx);
        loop {
            debug_assert!(ws_tx.buf_mut().chunk_mut().len() >= MAX_PACKET_LENGTH, "buffer too small");
            let read_len = select! {
                biased;
                _ = &mut has_pending_operations_pin => {
                    has_pending_operations = notify.notified();
                    has_pending_operations_pin = unsafe { Pin::new_unchecked(&mut has_pending_operations) };
                    match ws_tx.handle_pending_operations().await {
                        Ok(_) => continue,
                        Err(err) => { warn!("pending ops: {err}"); break; }
                    }
                },
                read_len = local_rx.read_buf(ws_tx.buf_mut()) => read_len,
                _ = &mut should_close => break,
                _ = timeout.tick(), if ping_frequency.is_some() => {
                    debug!("sending ping");
                    ws_tx.ping().await?;
                    continue;
                }
            };
            match read_len {
                Ok(0) => break,
                Ok(_) => {}
                Err(err) => { warn!("read from local: {err}"); break; }
            }
            if let Err(err) = ws_tx.write().await { warn!("write to tunnel: {err}"); break; }
        }
        let _ = ws_tx.close().await;
        Ok(())
    }

    pub async fn propagate_remote_to_local(local_tx: impl AsyncWrite + Send, mut ws_rx: impl TransportRead, mut close_rx: oneshot::Receiver<()>) -> anyhow::Result<()> {
        let _guard = scopeguard::guard((), |_| { info!("Closing local <= remote tunnel"); });
        pin_mut!(local_tx);
        loop {
            let msg = select! {
                biased;
                msg = ws_rx.copy(&mut local_tx) => msg,
                _ = &mut close_rx => break,
            };
            if let Err(err) = msg {
                match err.kind() {
                    ErrorKind::NotConnected => debug!("closed"),
                    ErrorKind::BrokenPipe => debug!("broken pipe"),
                    ErrorKind::UnexpectedEof => debug!("unexpected eof {err}"),
                    _ => error!("read tunnel: {err}"),
                }
                break;
            }
        }
        Ok(())
    }
}

pub mod websocket {
    use super::io::{MAX_PACKET_LENGTH, TransportRead, TransportWrite};
    use bytes::{Bytes, BytesMut};
    use fastwebsockets::{CloseCode, Frame, OpCode, Payload, Role, WebSocket, WebSocketRead, WebSocketWrite};
    use hyper::upgrade::Upgraded;
    use hyper_util::rt::TokioIo;
    use std::io::{self, ErrorKind};
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::Notify;
    use tokio::sync::mpsc::error::TrySendError;
    use tokio::sync::mpsc::{Receiver, Sender};
    use tracing::trace;

    pub struct WebsocketTransportWrite {
        inner: WebSocketWrite<tokio::io::WriteHalf<TokioIo<Upgraded>>>,
        buf: BytesMut,
        pending_operations: Receiver<Frame<'static>>,
        pending_ops_notify: Arc<Notify>,
        in_flight_ping: Arc<AtomicUsize>,
    }

    impl WebsocketTransportWrite {
        pub fn new(
            ws: WebSocketWrite<tokio::io::WriteHalf<TokioIo<Upgraded>>>,
            (ops, notify): (Receiver<Frame<'static>>, Arc<Notify>),
            ping: Arc<AtomicUsize>,
        ) -> Self {
            Self { inner: ws, buf: BytesMut::with_capacity(MAX_PACKET_LENGTH), pending_operations: ops, pending_ops_notify: notify, in_flight_ping: ping }
        }
    }

    impl TransportWrite for WebsocketTransportWrite {
        fn buf_mut(&mut self) -> &mut BytesMut { &mut self.buf }
        async fn write(&mut self) -> Result<(), io::Error> {
            let read_len = self.buf.len();
            let buf = &mut self.buf;
            if let Err(err) = self.inner.write_frame(Frame::binary(Payload::BorrowedMut(&mut buf[..read_len]))).await {
                return Err(io::Error::new(ErrorKind::ConnectionAborted, err));
            }
            if let Err(err) = self.inner.flush().await {
                return Err(io::Error::new(ErrorKind::ConnectionAborted, err));
            }
            buf.clear();
            Ok(())
        }
        async fn ping(&mut self) -> Result<(), io::Error> {
            if self.in_flight_ping.fetch_add(1, Relaxed) >= 3 {
                return Err(io::Error::new(ErrorKind::ConnectionAborted, "too many in-flight pings"));
            }
            if let Err(err) = self.inner.write_frame(Frame::new(true, OpCode::Ping, None, Payload::BorrowedMut(&mut []))).await {
                return Err(io::Error::new(ErrorKind::BrokenPipe, err));
            }
            Ok(())
        }
        async fn close(&mut self) -> Result<(), io::Error> {
            if let Err(err) = self.inner.write_frame(Frame::close(1000, &[])).await {
                return Err(io::Error::new(ErrorKind::BrokenPipe, err));
            }
            Ok(())
        }
        fn pending_operations_notify(&mut self) -> Arc<Notify> { self.pending_ops_notify.clone() }
        async fn handle_pending_operations(&mut self) -> Result<(), io::Error> {
            while let Ok(frame) = self.pending_operations.try_recv() {
                match frame.opcode {
                    OpCode::Close => { if self.inner.write_frame(frame).await.is_err() { return Err(io::Error::new(ErrorKind::ConnectionAborted, "close write")); } }
                    OpCode::Ping => { if self.inner.write_frame(Frame::pong(frame.payload)).await.is_err() { return Err(io::Error::new(ErrorKind::ConnectionAborted, "pong write")); } }
                    OpCode::Pong => { self.in_flight_ping.store(0, Relaxed); }
                    _ => unreachable!(),
                }
            }
            Ok(())
        }
    }

    pub struct WebsocketTransportRead {
        inner: WebSocketRead<tokio::io::ReadHalf<TokioIo<Upgraded>>>,
        pending_operations: Sender<Frame<'static>>,
        notify_pending_ops: Arc<Notify>,
        in_flight_ping: Arc<AtomicUsize>,
    }

    impl WebsocketTransportRead {
        pub fn new(
            ws: WebSocketRead<tokio::io::ReadHalf<TokioIo<Upgraded>>>,
            in_flight_ping: Arc<AtomicUsize>,
        ) -> (Self, (Receiver<Frame<'static>>, Arc<Notify>)) {
            let (tx, rx) = tokio::sync::mpsc::channel(10);
            let notify = Arc::new(Notify::new());
            (Self { inner: ws, pending_operations: tx, notify_pending_ops: notify.clone(), in_flight_ping }, (rx, notify))
        }
    }

    fn frame_reader(_: Frame<'_>) -> futures_util::future::Ready<anyhow::Result<()>> { futures_util::future::ready(Ok(())) }

    impl TransportRead for WebsocketTransportRead {
        async fn copy(&mut self, mut writer: impl tokio::io::AsyncWrite + Unpin + Send) -> Result<(), io::Error> {
            loop {
                let msg = match self.inner.read_frame(&mut frame_reader).await {
                    Ok(msg) => msg,
                    Err(err) => return Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
                };
                trace!("ws frame {:?}", msg.opcode);
                self.in_flight_ping.store(0, Relaxed);
                match msg.opcode {
                    OpCode::Continuation | OpCode::Text | OpCode::Binary => {
                        return match writer.write_all(msg.payload.as_ref()).await {
                            Ok(_) => Ok(()),
                            Err(err) => Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
                        };
                    }
                    OpCode::Close => {
                        let _ = self.pending_operations.send(Frame::close(CloseCode::Normal.into(), &[])).await;
                        self.notify_pending_ops.notify_waiters();
                        return Err(io::Error::new(ErrorKind::NotConnected, "ws close"));
                    }
                    OpCode::Ping => {
                        match self.pending_operations.try_send(Frame::new(true, msg.opcode, None, Payload::Owned(msg.payload.to_owned()))) {
                            Ok(()) => self.notify_pending_ops.notify_waiters(),
                            Err(TrySendError::Full(_)) => {}
                            Err(TrySendError::Closed(_)) => return Err(io::Error::new(ErrorKind::ConnectionAborted, "cannot send ping")),
                        }
                    }
                    OpCode::Pong => {
                        match self.pending_operations.try_send(Frame::pong(Payload::Borrowed(&[]))) {
                            Ok(()) => self.notify_pending_ops.notify_waiters(),
                            Err(TrySendError::Full(_)) => {}
                            Err(TrySendError::Closed(_)) => return Err(io::Error::new(ErrorKind::ConnectionAborted, "cannot send pong")),
                        }
                    }
                }
            }
        }
    }

    /// Никакого downcast — `TokioIo<Upgraded>` уже AsyncRead+AsyncWrite.
    pub fn mk_websocket_tunnel(ws: WebSocket<TokioIo<Upgraded>>, mask_frame: bool) -> anyhow::Result<(WebsocketTransportRead, WebsocketTransportWrite)> {
        let io = ws.into_inner();
        let mut ws = WebSocket::after_handshake(io, Role::Server);
        ws.set_auto_pong(false);
        ws.set_auto_close(false);
        ws.set_auto_apply_mask(mask_frame);
        let (ws_rx, ws_tx) = ws.split(|t| tokio::io::split(t));
        let in_flight_ping = Arc::new(AtomicUsize::new(0));
        let (ws_rx, pending_ops) = WebsocketTransportRead::new(ws_rx, in_flight_ping.clone());
        Ok((ws_rx, WebsocketTransportWrite::new(ws_tx, pending_ops, in_flight_ping)))
    }
}

pub mod http2 {
    use super::io::{MAX_PACKET_LENGTH, TransportRead, TransportWrite};
    use bytes::{Bytes, BytesMut};
    use http_body_util::BodyStream;
    use hyper::body::Incoming;
    use log::warn;
    use std::future::Future;
    use std::io::{self, ErrorKind};
    use tokio::io::{AsyncWrite, AsyncWriteExt};
    use tokio::sync::{Notify, mpsc};
    use tokio::task::AbortHandle;
    use tokio_stream::StreamExt;

    pub struct Http2TransportRead {
        inner: BodyStream<Incoming>,
        cnx_poller: Option<AbortHandle>,
    }
    impl Http2TransportRead {
        pub const fn new(inner: BodyStream<Incoming>, cnx_poller: Option<AbortHandle>) -> Self { Self { inner, cnx_poller } }
    }
    impl Drop for Http2TransportRead {
        fn drop(&mut self) { if let Some(t) = self.cnx_poller.as_ref() { t.abort() } }
    }
    impl TransportRead for Http2TransportRead {
        async fn copy(&mut self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), io::Error> {
            loop {
                match self.inner.next().await {
                    Some(Ok(frame)) => match frame.into_data() {
                        Ok(data) => {
                            return match writer.write_all(data.as_ref()).await {
                                Ok(_) => Ok(()),
                                Err(err) => Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
                            };
                        }
                        Err(err) => { warn!("{err:?}"); continue; }
                    },
                    Some(Err(err)) => return Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
                    None => return Err(io::Error::new(ErrorKind::BrokenPipe, "closed")),
                }
            }
        }
    }

    pub struct Http2TransportWrite { inner: mpsc::Sender<Bytes>, buf: BytesMut }
    impl Http2TransportWrite {
        pub fn new(inner: mpsc::Sender<Bytes>) -> Self { Self { inner, buf: BytesMut::with_capacity(MAX_PACKET_LENGTH * 20) } }
    }
    impl TransportWrite for Http2TransportWrite {
        fn buf_mut(&mut self) -> &mut BytesMut { &mut self.buf }
        async fn write(&mut self) -> Result<(), io::Error> {
            let data = self.buf.split().freeze();
            let ret = match self.inner.send(data).await { Ok(_) => Ok(()), Err(err) => Err(io::Error::new(ErrorKind::ConnectionAborted, err)) };
            if self.buf.capacity() < MAX_PACKET_LENGTH { self.buf.reserve(MAX_PACKET_LENGTH); }
            ret
        }
        async fn ping(&mut self) -> Result<(), io::Error> { Ok(()) }
        async fn close(&mut self) -> Result<(), io::Error> { Ok(()) }
        fn pending_operations_notify(&mut self) -> std::sync::Arc<Notify> { std::sync::Arc::new(Notify::new()) }
        fn handle_pending_operations(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send { std::future::ready(Ok(())) }
    }
}

pub mod webtransport {
    use super::io::{MAX_PACKET_LENGTH, TransportRead, TransportWrite};
    use bytes::{Bytes, BytesMut};
    use std::io::{self, ErrorKind};
    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::sync::Notify;
    use web_transport_quinn::{RecvStream, SendStream, Session};

    pub use udp::{WebTransportUdpRead, WebTransportUdpWrite};
    pub(crate) use utils::{bind_udp_socket, mk_transport_config};
    pub use utils::{read_jwt_preamble, write_jwt_preamble};

    const MAX_READ_CHUNKS: usize = 32;

    pub struct WebTransportRead { inner: RecvStream, chunks: [Bytes; MAX_READ_CHUNKS], _session: Session }
    impl WebTransportRead {
        pub fn new(inner: RecvStream, session: Session) -> Self { Self { inner, chunks: [const { Bytes::new() }; MAX_READ_CHUNKS], _session: session } }
        pub fn into_udp_stream(self) -> WebTransportUdpRead { WebTransportUdpRead::new(self.inner, self._session) }
    }
    impl TransportRead for WebTransportRead {
        async fn copy(&mut self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), io::Error> {
            let count = match self.inner.read_chunks(&mut self.chunks).await {
                Ok(Some(c)) => c,
                Ok(None) => return Err(io::Error::new(ErrorKind::BrokenPipe, "closed")),
                Err(err) => return Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
            };
            let result = write_chunks(&mut writer, &self.chunks[..count]).await;
            self.chunks[..count].fill(Bytes::new());
            result.map_err(|err| io::Error::new(ErrorKind::ConnectionAborted, err))
        }
    }

    async fn write_chunks(writer: &mut (impl AsyncWrite + Unpin), chunks: &[Bytes]) -> io::Result<()> {
        if chunks.len() == 1 || !writer.is_write_vectored() {
            for chunk in chunks { writer.write_all(chunk).await?; }
            return Ok(());
        }
        use std::io::IoSlice;
        let mut slices = [IoSlice::new(&[]); MAX_READ_CHUNKS];
        for (s, c) in slices.iter_mut().zip(chunks) { *s = IoSlice::new(c); }
        let mut slices = &mut slices[..chunks.len()];
        while !slices.is_empty() {
            let written = writer.write_vectored(slices).await?;
            if written == 0 { return Err(io::Error::new(ErrorKind::WriteZero, "wt chunk write")); }
            IoSlice::advance_slices(&mut slices, written);
        }
        Ok(())
    }

    pub struct WebTransportWrite { inner: SendStream, buf: BytesMut, _session: Session }
    impl WebTransportWrite {
        const ARENA: usize = MAX_PACKET_LENGTH * 4;
        pub fn new(inner: SendStream, session: Session) -> Self { Self { inner, buf: BytesMut::with_capacity(Self::ARENA), _session: session } }
        pub fn into_udp_stream(self) -> WebTransportUdpWrite { WebTransportUdpWrite::new(self.inner, self._session) }
    }
    impl TransportWrite for WebTransportWrite {
        fn buf_mut(&mut self) -> &mut BytesMut { &mut self.buf }
        async fn write(&mut self) -> Result<(), io::Error> {
            let chunk = self.buf.split().freeze();
            let ret = match self.inner.write_chunk(chunk).await { Ok(_) => Ok(()), Err(err) => Err(io::Error::new(ErrorKind::ConnectionAborted, err)) };
            if self.buf.capacity() < MAX_PACKET_LENGTH { self.buf.reserve(Self::ARENA); }
            ret
        }
        async fn ping(&mut self) -> Result<(), io::Error> { Ok(()) }
        async fn close(&mut self) -> Result<(), io::Error> { let _ = self.inner.finish(); Ok(()) }
        fn pending_operations_notify(&mut self) -> std::sync::Arc<Notify> { std::sync::Arc::new(Notify::new()) }
        async fn handle_pending_operations(&mut self) -> Result<(), io::Error> { Ok(()) }
    }

    mod utils {
        use super::*;
        use anyhow::{Context, anyhow};
        use socket2::SockRef;
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use web_transport_quinn::{quinn, RecvStream, SendStream};
        use crate::somark::SoMark;

        const MAX_JWT_PREAMBLE_LEN: usize = 8 * 1024;

        pub(crate) fn mk_transport_config(keep_alive_interval: Option<Duration>) -> anyhow::Result<quinn::TransportConfig> {
            let mut t = quinn::TransportConfig::default();
            t.send_fairness(false);
            t.datagram_send_buffer_size(4 * 1024 * 1024);
            t.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
            let Some(iv) = keep_alive_interval else { t.keep_alive_interval(None); t.max_idle_timeout(None); return Ok(t); };
            let idle = iv.checked_mul(3).with_context(|| format!("ping {iv:?} too large"))?;
            t.keep_alive_interval(Some(iv));
            t.max_idle_timeout(Some(idle.try_into().with_context(|| format!("ping {iv:?} too large"))?));
            Ok(t)
        }

        pub(crate) fn bind_udp_socket(bind: Option<SocketAddr>, so_mark: SoMark) -> anyhow::Result<std::net::UdpSocket> {
            let addr = bind.unwrap_or_else(|| SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)));
            let socket = match socket2::Socket::new(socket2::Domain::for_address(addr), socket2::Type::DGRAM, Some(socket2::Protocol::UDP)) {
                Ok(s) => s,
                Err(err) if bind.is_none() => {
                    tracing::debug!("no IPv6, fallback to IPv4: {err:?}");
                    return bind_udp_socket(Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))), so_mark);
                }
                Err(err) => return Err(err).with_context(|| format!("create UDP socket {addr}")),
            };
            if addr.is_ipv6() && let Err(err) = socket.set_only_v6(false) {
                tracing::debug!("dual-stack failed: {err:?}");
            }
            socket.bind(&socket2::SockAddr::from(addr)).with_context(|| format!("bind UDP {addr}"))?;
            so_mark.set_mark(SockRef::from(&socket)).context("set SO_MARK on UDP")?;
            Ok(socket.into())
        }

        pub async fn write_jwt_preamble(stream: &mut SendStream, jwt: &str) -> anyhow::Result<()> {
            let jwt = jwt.as_bytes();
            let len = u16::try_from(jwt.len()).with_context(|| format!("jwt too long: {} bytes", jwt.len()))?;
            stream.write_u16(len).await?;
            stream.write_all(jwt).await?;
            stream.flush().await?;
            Ok(())
        }

        pub async fn read_jwt_preamble(stream: &mut RecvStream) -> anyhow::Result<String> {
            let len = stream.read_u16().await? as usize;
            if len == 0 || len > MAX_JWT_PREAMBLE_LEN { return Err(anyhow!("bad jwt len {len}")); }
            let mut jwt = vec![0u8; len];
            stream.read_exact(&mut jwt).await?;
            String::from_utf8(jwt).context("jwt not utf-8")
        }
    }

    pub mod udp {
        use super::*;
        use bytes::BytesMut;
        use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
        use web_transport_quinn::{RecvStream, SendStream, Session};

        pub struct WebTransportUdpRead { inner: RecvStream, _session: Session }
        impl WebTransportUdpRead {
            pub fn new(inner: RecvStream, session: Session) -> Self { Self { inner, _session: session } }
        }
        impl TransportRead for WebTransportUdpRead {
            async fn copy(&mut self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), io::Error> {
                let length = self.inner.read_u16().await.map_err(|e| io::Error::new(ErrorKind::ConnectionAborted, e))?;
                let mut remaining = length as usize;
                let mut assembled: Option<BytesMut> = None;
                while remaining > 0 {
                    let mut chunk = self.inner.read_chunk(remaining, true).await.map_err(|e| io::Error::new(ErrorKind::ConnectionAborted, e))?.ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "closed mid-datagram"))?;
                    remaining -= chunk.bytes.len();
                    if assembled.is_none() && remaining == 0 {
                        return writer.write_all_buf(&mut chunk.bytes).await.map_err(|e| io::Error::new(ErrorKind::ConnectionAborted, e));
                    }
                    assembled.get_or_insert_with(|| BytesMut::with_capacity(length as usize)).extend_from_slice(&chunk.bytes);
                }
                match assembled {
                    Some(mut buf) => writer.write_all_buf(&mut buf).await.map_err(|e| io::Error::new(ErrorKind::ConnectionAborted, e)),
                    None => Ok(()),
                }
            }
        }

        pub struct WebTransportUdpWrite { inner: SendStream, buf: BytesMut, _session: Session }
        impl WebTransportUdpWrite {
            const ARENA: usize = MAX_PACKET_LENGTH * 2;
            pub fn new(inner: SendStream, session: Session) -> Self { Self { inner, buf: BytesMut::with_capacity(Self::ARENA), _session: session } }
        }
        impl TransportWrite for WebTransportUdpWrite {
            fn buf_mut(&mut self) -> &mut BytesMut { &mut self.buf }
            async fn write(&mut self) -> Result<(), io::Error> {
                self.inner.write_u16(self.buf.len() as u16).await.map_err(|e| io::Error::new(ErrorKind::ConnectionAborted, e))?;
                self.inner.write_chunk(self.buf.split().freeze()).await.map_err(|e| io::Error::new(ErrorKind::ConnectionAborted, e))?;
                if self.buf.capacity() < MAX_PACKET_LENGTH { self.buf.reserve(Self::ARENA); }
                Ok(())
            }
            async fn ping(&mut self) -> Result<(), io::Error> { Ok(()) }
            async fn close(&mut self) -> Result<(), io::Error> { let _ = self.inner.finish(); Ok(()) }
            fn pending_operations_notify(&mut self) -> std::sync::Arc<Notify> { std::sync::Arc::new(Notify::new()) }
            async fn handle_pending_operations(&mut self) -> Result<(), io::Error> { Ok(()) }
        }
    }
}
