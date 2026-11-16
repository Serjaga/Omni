
// src/tunnel.rs — рефакторинг: только серверная часть, только forward-туннели (TCP/UDP)
// Публичный API совместим с main.rs: TunnelServer / TunnelServerConfig / TunnelTlsServerConfig,
// handle_tunnel_request, serve, RestrictionsRules::from_path_prefix, DnsResolver::new_from_urls.

use std::{fmt, future::Future, io, net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6}, ops::RangeInclusive, path::{Path, PathBuf}, sync::Arc, time::Duration};
use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use url::{Host, Url};

// ───────────────────────────────────────────────────────────────────────────
// Топ-уровневые типы
// ───────────────────────────────────────────────────────────────────────────
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum LocalProtocol {
    Tcp { proxy_protocol: bool },
    Udp { timeout: Option<Duration> },
    Stdio { proxy_protocol: bool },
    Socks5 { timeout: Option<Duration>, credentials: Option<(String, String)> },
    TProxyTcp,
    TProxyUdp { timeout: Option<Duration> },
    HttpProxy { timeout: Option<Duration>, credentials: Option<(String, String)>, proxy_protocol: bool },
    ReverseTcp,
    ReverseUdp { timeout: Option<Duration> },
    ReverseSocks5 { timeout: Option<Duration>, credentials: Option<(String, String)> },
    ReverseHttpProxy { timeout: Option<Duration>, credentials: Option<(String, String)> },
    ReverseUnix { path: PathBuf },
    Unix { path: PathBuf, proxy_protocol: bool },
}

impl LocalProtocol {
    pub const fn is_reverse_tunnel(&self) -> bool {
        matches!(self, Self::ReverseTcp | Self::ReverseUdp { .. } | Self::ReverseSocks5 { .. } | Self::ReverseUnix { .. } | Self::ReverseHttpProxy { .. })
    }
    pub const fn is_dynamic_reverse_tunnel(&self) -> bool {
        matches!(self, Self::ReverseSocks5 { .. } | Self::ReverseHttpProxy { .. })
    }
}

impl fmt::Debug for LocalProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn redacted(c: &Option<(String, String)>) -> Option<&'static str> { c.as_ref().map(|_| "<redacted>") }
        match self {
            Self::Tcp { proxy_protocol } => f.debug_struct("Tcp").field("proxy_protocol", proxy_protocol).finish(),
            Self::Udp { timeout } => f.debug_struct("Udp").field("timeout", timeout).finish(),
            Self::Stdio { proxy_protocol } => f.debug_struct("Stdio").field("proxy_protocol", proxy_protocol).finish(),
            Self::Socks5 { timeout, credentials } => f.debug_struct("Socks5").field("timeout", timeout).field("credentials", &redacted(credentials)).finish(),
            Self::TProxyTcp => f.write_str("TProxyTcp"),
            Self::TProxyUdp { timeout } => f.debug_struct("TProxyUdp").field("timeout", timeout).finish(),
            Self::HttpProxy { timeout, credentials, proxy_protocol } => f.debug_struct("HttpProxy").field("timeout", timeout).field("credentials", &redacted(credentials)).field("proxy_protocol", proxy_protocol).finish(),
            Self::ReverseTcp => f.write_str("ReverseTcp"),
            Self::ReverseUdp { timeout } => f.debug_struct("ReverseUdp").field("timeout", timeout).finish(),
            Self::ReverseSocks5 { timeout, credentials } => f.debug_struct("ReverseSocks5").field("timeout", timeout).field("credentials", &redacted(credentials)).finish(),
            Self::ReverseHttpProxy { timeout, credentials } => f.debug_struct("ReverseHttpProxy").field("timeout", timeout).field("credentials", &redacted(credentials)).finish(),
            Self::ReverseUnix { path } => f.debug_struct("ReverseUnix").field("path", path).finish(),
            Self::Unix { path, proxy_protocol } => f.debug_struct("Unix").field("path", path).field("proxy_protocol", proxy_protocol).finish(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RemoteAddr { pub protocol: LocalProtocol, pub host: Host, pub port: u16 }

// ───────────────────────────────────────────────────────────────────────────
// SoMark
// ───────────────────────────────────────────────────────────────────────────
pub mod somark;

// ───────────────────────────────────────────────────────────────────────────
// Executor (только DefaultTokioExecutor)
// ───────────────────────────────────────────────────────────────────────────
pub mod executor;

// ───────────────────────────────────────────────────────────────────────────
// Protocols: tcp / udp / dns / tls
// ───────────────────────────────────────────────────────────────────────────
pub mod protocols;

// ───────────────────────────────────────────────────────────────────────────
// Restrictions — статический набор
// ───────────────────────────────────────────────────────────────────────────
pub mod restrictions;

// ───────────────────────────────────────────────────────────────────────────
// TLS reloader — заглушка
// ───────────────────────────────────────────────────────────────────────────
pub mod tls_reloader;

// ───────────────────────────────────────────────────────────────────────────
// Transport: JWT, IO trait-ы + пропагаторы, WS, HTTP/2, WebTransport
// ───────────────────────────────────────────────────────────────────────────
pub mod transport;

// ───────────────────────────────────────────────────────────────────────────
// Server
// ───────────────────────────────────────────────────────────────────────────
pub mod server;

// ───────────────────────────────────────────────────────────────────────────
// Ре-экспорт — совместим с main.rs
// ───────────────────────────────────────────────────────────────────────────
pub use crate::server::{Server as TunnelServer, ServerConfig as TunnelServerConfig, TlsServerConfig as TunnelTlsServerConfig};