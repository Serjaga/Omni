// ═══════════════════════════════════════════════════════════════════════════
// OmniRS main.rs — DNS + ACME + Multiplex 443/UDP (h3 сайтов + Miraj)
// Admin :800 объединён с :443 — единственный порт 443.
//
//   https://<ip>/           → admin login / admin HTML
//   https://<ip>/terminal   → терминал
//   https://<ip>/api/*      → admin API (auth: x-admin-token или cookie)
//   https://<ip>/proxy/*    → reverse proxy (было /api/*, теперь /proxy/*)
//   https://<ip>/dns-query  → DoH
//   https://<ip>/health     → health
//   https://<ip>/metrics    → Prometheus
// ═══════════════════════════════════════════════════════════════════════════
use axum::{body::{to_bytes, Body}, extract::{ConnectInfo, State}, http::{header::{self, HeaderName}, HeaderMap, Method, Request, Response, StatusCode}, middleware::{self}, Router};
use std::{collections::HashMap, error::Error, net::{IpAddr, Ipv4Addr, SocketAddr}, path::{Component, Path, PathBuf}, sync::{atomic::{AtomicU64, AtomicUsize, AtomicU32, Ordering}, Arc, Mutex, RwLock}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tower_http::{compression::CompressionLayer, timeout::TimeoutLayer};
use tower::ServiceExt;
use serde::Deserialize;
use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use quinn::crypto::rustls::QuicServerConfig;
use fastcgi_client::{Client, Params, Request as FcgiRequest};
use hyper_util::rt::TokioIo;
use tokio_util::io::ReaderStream;
use tokio_util::sync::CancellationToken;
use futures_util::{Stream, StreamExt};
use bytes::Bytes;
use h3_quinn::Connection as H3Connection;
use ipnet::IpNet;
use libc;
use serde_json::json;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

mod api;
mod modules;
mod generated_modules { include!(concat!(env!("OUT_DIR"), "/generated_modules.rs")); }
mod omni_mw;
mod installer;
use omni_db as db;
use omni_dns as dns;
use omni_security as security;
use omni_ssl as ssl;
use omni_vpn as vpn;
use omni_ikev2 as ikev2;
use omni_miraj as miraj;
use omni_tunnel as tunnel;

trait FStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> FStream for T {}

#[derive(Clone)] pub struct CachedResponse { pub status: u16, pub headers: Vec<(String, String)>, pub body: bytes::Bytes }

#[derive(Default)] pub struct Metrics { pub total_requests: AtomicU64, pub status_2xx: AtomicU64, pub status_3xx: AtomicU64, pub status_4xx: AtomicU64, pub status_5xx: AtomicU64, pub total_latency_ms: AtomicU64, pub cache_hits: AtomicU64, pub cache_misses: AtomicU64, pub failover_retries: AtomicU64, pub slow_requests: AtomicU64 }

pub struct CircuitBreaker { pub failures: AtomicU32, pub open_until: Mutex<Option<Instant>> }
impl CircuitBreaker {
    fn new() -> Self { Self { failures: AtomicU32::new(0), open_until: Mutex::new(None) } }
    fn is_open(&self) -> bool { self.open_until.lock().unwrap().map_or(false, |t| t > Instant::now()) }
    fn record_success(&self) { self.failures.store(0, Ordering::Relaxed); *self.open_until.lock().unwrap() = None; }
    fn record_failure(&self) { let n = self.failures.fetch_add(1, Ordering::Relaxed) + 1; if n >= 5 { *self.open_until.lock().unwrap() = Some(Instant::now() + Duration::from_secs(30)); } }
}

struct ConnGuard { counter: Arc<AtomicUsize> }
impl ConnGuard { fn new(c: Arc<AtomicUsize>) -> Self { c.fetch_add(1, Ordering::Relaxed); Self { counter: c } } }
impl Drop for ConnGuard { fn drop(&mut self) { self.counter.fetch_sub(1, Ordering::Relaxed); } }

struct GuardedStream<S> { inner: std::pin::Pin<Box<S>>, _guard: ConnGuard }
impl<S: Stream> Stream for GuardedStream<S> { type Item = S::Item; fn poll_next(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Self::Item>> { Stream::poll_next(self.inner.as_mut(), cx) } }

#[derive(Clone, Deserialize, Debug)]
pub struct Config {
    #[serde(default = "default_address")] pub address: String,
    #[serde(default = "default_root")] pub root: PathBuf,
    #[serde(default)] pub virtual_hosts: HashMap<String, PathBuf>,
    #[serde(default)] pub db: db::DbConfig,
    #[serde(default = "default_proxy_prefix")] pub proxy_prefix: String,
    #[serde(default)] pub backends: Vec<String>,
    #[serde(default)] pub redirects: HashMap<String, String>,
    #[serde(default = "default_admin_root")] pub admin_root: PathBuf,
    #[serde(default)] pub admin_token: String,
    #[serde(default)] pub acme_mode: ssl::AcmeMode,
    #[serde(default)] pub acme_ip: Option<String>,
    #[serde(default)] pub acme_domains: Vec<String>,
    #[serde(default = "default_h3_port")] pub h3_port: Option<u16>,
    #[serde(default)] pub fastcgi_pass: Option<String>,
    #[serde(default = "default_fastcgi_index")] pub fastcgi_index: String,
    #[serde(default)] pub admin_allowed_ips: Vec<String>,
    #[serde(default)] pub metrics_allowed_ips: Vec<String>,
    #[serde(default = "default_cache_enabled")] pub cache_enabled: bool,
    #[serde(default = "default_cache_ttl")] pub cache_ttl_secs: u64,
    #[serde(default = "default_cache_max_entries")] pub cache_max_entries: u64,
    #[serde(default = "default_request_timeout")] pub request_timeout_secs: u64,
    #[serde(default)] pub cors_allowed_origins: Vec<String>,
    #[serde(default = "default_failover_attempts")] pub failover_attempts: u64,
    #[serde(default)] pub sticky_sessions: bool,
    #[serde(default = "default_true")] pub grpc_passthrough: bool,
    #[serde(default)] pub vpn: vpn::VpnConfig,
    #[serde(default)] pub ikev2_enabled: bool,
    #[serde(default = "default_ikev2_listen")] pub ikev2_listen: String,
    #[serde(default)] pub ikev2_psk: String,
    #[serde(default = "default_ikev2_local_id")] pub ikev2_local_id: String,
    #[serde(default = "default_ikev2_remote_id")] pub ikev2_remote_id: String,
}
fn default_address() -> String { "0.0.0.0".to_string() }
fn default_root() -> PathBuf { PathBuf::from("./public") }
fn default_proxy_prefix() -> String { "/proxy".to_string() }           // ← было /api
fn default_admin_root() -> PathBuf { PathBuf::from("./admin-data") }
fn default_h3_port() -> Option<u16> { Some(443) }
fn default_fastcgi_index() -> String { "index.php".to_string() }
fn default_cache_enabled() -> bool { true }
fn default_cache_ttl() -> u64 { 60 }
fn default_cache_max_entries() -> u64 { 1000 }
fn default_request_timeout() -> u64 { 30 }
fn default_failover_attempts() -> u64 { 3 }
fn default_true() -> bool { true }
fn default_ikev2_listen() -> String { "0.0.0.0:500".into() }
fn default_ikev2_local_id() -> String { "omnirs".into() }
fn default_ikev2_remote_id() -> String { "%any".into() }

#[derive(Clone, Debug, serde::Serialize)] pub struct WireSvc { pub name: String, pub proto: String, pub addr: String, pub listener: String, pub started_at: i64, pub connections: u64, pub total_queries: u64 }

pub static WS_ACTIVE: AtomicU64 = AtomicU64::new(0);
pub static WS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub fn ws_active_count() -> (u64, u64) { (WS_ACTIVE.load(Ordering::Relaxed), WS_TOTAL.load(Ordering::Relaxed)) }

pub fn is_ssrf_target(url_or_host: &str) -> bool {
    let s = url_or_host.trim();
    if s.starts_with("file:") || s.starts_with("data:") || s.starts_with("gopher:") || s.starts_with("ftp:") { return true; }
    let host_port = if let Some(rest) = s.strip_prefix("https://") { rest } else if let Some(rest) = s.strip_prefix("http://") { rest } else { s };
    let host = host_port.split('/').next().unwrap_or("").split('@').last().unwrap_or("").split(':').next().unwrap_or("");
    if host.is_empty() { return true; }
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") { return true; }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(a) => a.is_private() || a.is_loopback() || a.is_link_local() || a.is_multicast() || a.is_broadcast() || a.octets()[0] == 0 || (a.octets()[0] == 169 && a.octets()[1] == 254),
            IpAddr::V6(a) => a.is_loopback() || a.is_unique_local() || a.is_multicast() || a.is_unspecified(),
        };
    }
    let low = host.to_lowercase();
    matches!(low.as_str(), "169.254.169.254" | "metadata.google.internal" | "metadata.aws.internal")
}

fn is_hashed_filename(path: &Path) -> bool { let name = match path.file_stem().and_then(|s| s.to_str()) { Some(n) => n, None => return false }; if let Some(idx) = name.rfind(|c: char| c == '.' || c == '-') { let hash = &name[idx + 1..]; hash.len() >= 6 && hash.chars().all(|c| c.is_ascii_hexdigit()) } else { false } }
fn is_ip_allowed(client_ip: &str, allowed: &[IpNet]) -> bool { if allowed.is_empty() { return true; } match client_ip.parse::<IpAddr>() { Ok(ip) => allowed.iter().any(|n| n.contains(&ip)), Err(_) => false } }

pub(crate) fn resolve_client_ip(headers: &HeaderMap, connect_info: Option<&ConnectInfo<SocketAddr>>) -> String {
    let trust_proxy = std::env::var("OMNIRS_TRUST_PROXY").map(|v| v == "true" || v == "1" || v == "yes").unwrap_or(false);
    if trust_proxy {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) { if let Some(first) = xff.split(',').next() { let ip = first.trim(); if !ip.is_empty() { return ip.to_string(); } } }
        if let Some(xri) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) { if !xri.is_empty() { return xri.to_string(); } }
    }
    connect_info.map(|ci| ci.0.ip().to_string()).unwrap_or_else(|| "unknown".to_string())
}

fn has_sticky_cookie(headers: &HeaderMap) -> bool { headers.get(header::COOKIE).and_then(|v| v.to_str().ok()).map_or(false, |s| s.split(';').any(|p| p.trim().starts_with("omnirs_backend="))) }
fn sticky_cookie_for(backend: &str) -> String { format!("omnirs_backend={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400", backend) }

async fn load_dns_config() -> Option<dns::DnsConfig> {
    if let Ok(path) = std::env::var("OMNIRS_DNS_CONFIG") {
        if let Ok(s) = std::fs::read_to_string(&path) {
            if let Ok(c) = toml::from_str::<dns::DnsConfig>(&s) { return Some(c); }
            if let Ok(c) = serde_json::from_str::<dns::DnsConfig>(&s) { return Some(c); }
        }
    }
    let db = db::global()?;
    let map = db.config_map().await.ok()?;
    let s_raw = |k: &str| map.get(k).map(|s| s.trim_matches(|c: char| c == '"' || c == '\'').to_string());
    let b = |k: &str, d: bool| s_raw(k).map(|v| matches!(v.as_str(), "1" | "true" | "yes")).unwrap_or(d);
    let s = |k: &str, d: &str| s_raw(k).unwrap_or_else(|| d.to_string());
    let vec_str = |k: &str| s_raw(k).and_then(|v| serde_json::from_str::<Vec<String>>(&v).ok());
    let mut cfg = dns::DnsConfig::default();
    cfg.enabled = b("dns.enabled", false);
    cfg.addr = s("dns.addr", "0.0.0.0:53");
    cfg.dot_addr = s("dns.dot_addr", "");
    cfg.doq_addr = s("dns.doq_addr", "");
    cfg.doh_path = s("dns.doh_path", "/dns-query");
    if let Some(v) = map.get("dns.zone_dir").cloned().filter(|v| !v.is_empty()) { cfg.zone_dir = Some(v); }
    if let Some(v) = vec_str("dns.forwarders") { cfg.forwarders = v; }
    cfg.recursive = b("dns.recursive", cfg.recursive);
    cfg.dnssec_sign_on_load = b("dns.dnssec_sign_on_load", cfg.dnssec_sign_on_load);
    cfg.rrl_enabled = b("dns.rrl_enabled", cfg.rrl_enabled);
    cfg.ixfr_enabled = b("dns.ixfr_enabled", cfg.ixfr_enabled);
    Some(cfg)
}

fn load_audit_log() -> Option<Arc<dns::AuditLog>> {
    let path = std::env::var("OMNIRS_AUDIT_LOG").ok()?;
    let size: u64 = std::env::var("OMNIRS_AUDIT_LOG_MAX_MB").ok().and_then(|s| s.parse().ok()).unwrap_or(100);
    dns::AuditLog::new(PathBuf::from(&path), size).ok().map(Arc::new)
}

fn log_admin_action(state: &AppState, client_ip: &str, action: &str, target: &str, result: &str, details: serde_json::Value) {
    if let Some(audit) = &state.audit {
        let token_prefix: String = state.config.admin_token.chars().take(6).collect();
        audit.append(&dns::AuditEvent { ts: dns::now(), actor_ip: client_ip.to_string(), actor_token_prefix: token_prefix, action: action.to_string(), target: target.to_string(), result: result.to_string(), details });
    }
}

impl Config {
    pub async fn load() -> Result<Self, Box<dyn Error>> {
        let db = db::global().ok_or_else(|| -> Box<dyn Error> { "database not initialized (call db::init_global() first)".into() })?;
        let map = db.config_map().await.map_err(|e| -> Box<dyn Error> { e.into() })?;
        Self::from_map(&map).await
      
    }
    async fn from_map(map: &HashMap<String, String>) -> Result<Self, Box<dyn Error>> {
    let g = |k: &str| map.get(k).map(|s| s.trim_matches(|c: char| c == '"' || c == '\'').to_string());
    let b = |k: &str, d: bool| map.get(k).map(|v| matches!(v.as_str(), "1" | "true" | "yes")).unwrap_or(d);
    let n = |k: &str, d: u64| map.get(k).and_then(|v| v.parse::<u64>().ok()).unwrap_or(d);
    let list_csv = |k: &str| g(k).map(|s| s.split(',').map(str::trim).filter(|x| !x.is_empty()).map(String::from).collect::<Vec<_>>()).unwrap_or_default();
    let list_semi = |k: &str| g(k).map(|s| s.split(';').map(str::trim).filter(|x| !x.is_empty()).map(|s| s.trim_end_matches('/').to_string()).collect::<Vec<_>>()).unwrap_or_default();
    
    let acme_mode = match g("acme_mode").as_deref() {
        Some("false") | Some("no") | Some("0") | Some("off") => ssl::AcmeMode::False,
        Some("http") => ssl::AcmeMode::Http,
        Some("tls") | Some("tls-alpn") | Some("alpn") => ssl::AcmeMode::Tls,
        Some("all") | Some("auto") | Some("true") | Some("yes") | Some("1") | Some("both") => ssl::AcmeMode::All,
        _ => ssl::AcmeMode::All,
    };
    let vpn_cfg = parse_vpn_from_map(map);
    let mut db_cfg = db::DbConfig::from_env();
    db_cfg.overlay_from_map(map);
    
    // ВОТ ЗДЕСЬ БЫЛА ОШИБКА - поля должны быть внутри Self { ... }
    let mut cfg = Self {
        address: g("address").unwrap_or_else(|| "0.0.0.0".into()),
        root: PathBuf::from(g("root").unwrap_or_else(|| "./public".into())),
        virtual_hosts: HashMap::new(), db: db_cfg,
        proxy_prefix: g("proxy_prefix").unwrap_or_else(|| "/proxy".into()),
        backends: list_semi("backends"), redirects: HashMap::new(),
        admin_root: PathBuf::from(g("admin_root").unwrap_or_else(|| ".".into())),
        admin_token: g("admin_token").unwrap_or_default(), acme_mode,
        acme_ip: g("acme_ip").filter(|s| !s.is_empty()), acme_domains: list_csv("acme_domains"),
        h3_port: g("h3_port").and_then(|s| s.parse::<u16>().ok()).or(Some(443)),
        fastcgi_pass: g("fastcgi_pass").filter(|s| !s.is_empty()),
        fastcgi_index: g("fastcgi_index").unwrap_or_else(|| "index.php".into()),
        admin_allowed_ips: list_csv("admin_allowed_ips"), metrics_allowed_ips: list_csv("metrics_allowed_ips"),
        cache_enabled: b("cache_enabled", true), cache_ttl_secs: n("cache_ttl_secs", 60), cache_max_entries: n("cache_max_entries", 1000),
        request_timeout_secs: n("request_timeout_secs", 30), cors_allowed_origins: list_csv("cors_allowed_origins"),
        failover_attempts: n("failover_attempts", 3),
        sticky_sessions: b("sticky_sessions", false), grpc_passthrough: b("grpc_passthrough", true),
        vpn: vpn_cfg,
        // --- НОВЫЕ ПОЛЯ IKEv2 ---
        ikev2_enabled: b("ikev2.enabled", false),
        ikev2_listen: g("ikev2.listen").unwrap_or_else(|| "0.0.0.0:500".into()),
        ikev2_psk: g("ikev2.psk").unwrap_or_default(),
        ikev2_local_id: g("ikev2.local_id").unwrap_or_else(|| "omnirs".into()),
        ikev2_remote_id: g("ikev2.remote_id").unwrap_or_else(|| "%any".into()),
    };
    

        if let Ok(v) = std::env::var("OMNIRS_ADDR") { cfg.address = v; }
        if let Ok(v) = std::env::var("OMNIRS_ROOT") { cfg.root = PathBuf::from(v); }
        if let Ok(v) = std::env::var("OMNIRS_PROXY_PREFIX") { cfg.proxy_prefix = v; }
        if let Ok(v) = std::env::var("OMNIRS_BACKENDS") { cfg.backends = v.split(';').map(str::trim).filter(|s| !s.is_empty()).map(|s| s.trim_end_matches('/').to_string()).collect(); }
        if let Ok(v) = std::env::var("OMNIRS_ADMIN_ROOT") { cfg.admin_root = PathBuf::from(v); }
        if let Ok(v) = std::env::var("OMNIRS_ADMIN_TOKEN") { cfg.admin_token = v; }
        if let Ok(v) = std::env::var("OMNIRS_ACME_MODE") { cfg.acme_mode = match v.to_lowercase().as_str() {
            "false" | "no" | "0" | "off" => ssl::AcmeMode::False,
            "http" => ssl::AcmeMode::Http,
            "tls" | "tls-alpn" | "alpn" => ssl::AcmeMode::Tls,
            "all" | "auto" | "true" | "yes" | "1" | "both" => ssl::AcmeMode::All,
            _ => ssl::AcmeMode::False,
        }; }
        if let Ok(v) = std::env::var("OMNIRS_ACME_IP") { cfg.acme_ip = Some(v); }
        if let Ok(v) = std::env::var("OMNIRS_ACME_DOMAINS") { cfg.acme_domains = v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect(); }
        if let Ok(v) = std::env::var("OMNIRS_H3_PORT") { cfg.h3_port = v.parse().ok(); }
        if let Ok(v) = std::env::var("OMNIRS_FASTCGI_PASS") { cfg.fastcgi_pass = Some(v); }
        if let Ok(v) = std::env::var("OMNIRS_ADMIN_ALLOWED_IPS") { cfg.admin_allowed_ips = v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect(); }
        if let Ok(v) = std::env::var("OMNIRS_METRICS_ALLOWED_IPS") { cfg.metrics_allowed_ips = v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect(); }
        if let Ok(v) = std::env::var("OMNIRS_CORS_ALLOWED_ORIGINS") { cfg.cors_allowed_origins = v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect(); }
        if let Ok(v) = std::env::var("OMNIRS_STICKY_SESSIONS") { cfg.sticky_sessions = v == "true" || v == "1" || v == "yes"; }
        if let Ok(v) = std::env::var("OMNIRS_DB_ENABLED") { cfg.db.enabled = v == "true" || v == "1" || v == "yes"; }
        if let Ok(v) = std::env::var("OMNIRS_DB_ALLOW_DDL") { cfg.db.allow_ddl = v == "true" || v == "1" || v == "yes"; }
        if let Ok(v) = std::env::var("OMNIRS_DB_ALLOW_WRITE") { cfg.db.allow_write = v == "true" || v == "1" || v == "yes"; }
        if cfg.acme_ip.is_none() {
            if let Ok(ip) = parse_bind_ip(&cfg.address) {
                let usable = match ip { IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_loopback(), IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_loopback() };
                if usable { println!("[CONFIG] acme_ip not set — derived from address: {}", ip); cfg.acme_ip = Some(ip.to_string()); }
                else { eprintln!("[CONFIG] acme_ip not set and address = {} is not a specific IP; ACME for IP disabled", cfg.address); }
            }
        } else if let (Some(acme_ip), Ok(addr_ip)) = (&cfg.acme_ip, parse_bind_ip(&cfg.address)) {
            if !addr_ip.is_unspecified() {
                if let Ok(acme_parsed) = acme_ip.parse::<IpAddr>() {
                    if addr_ip != acme_parsed { eprintln!("[CONFIG] WARN: address = {} differs from acme_ip = {}", addr_ip, acme_parsed); }
                }
            }
        }
        cfg.root = sanitize_dir_path(&cfg.root, "root", "public");
        cfg.admin_root = sanitize_admin_root(&cfg.admin_root, &cfg.root);
        cfg.root = tokio::fs::canonicalize(&cfg.root).await.map_err(|e| -> Box<dyn Error> { format!("root {:?}: cannot canonicalize: {e}", cfg.root).into() })?;
        cfg.admin_root = tokio::fs::canonicalize(&cfg.admin_root).await.map_err(|e| -> Box<dyn Error> { format!("admin_root {:?}: cannot canonicalize: {e}", cfg.admin_root).into() })?;
        if cfg.admin_root == PathBuf::from("/") { eprintln!("[CONFIG] SECURITY WARNING: admin_root = \"/\" — file manager has access to the ENTIRE filesystem!"); }
        if cfg.admin_root == cfg.root { eprintln!("[CONFIG] admin_root == root — file manager will show website files ({})", cfg.root.display()); }
        Ok(cfg)
    }
    pub fn validate(&self) -> Result<(), Box<dyn Error>> {
        if parse_bind_ip(&self.address).is_err() { return Err(format!("address must be a bare IP without port (e.g. \"0.0.0.0\"), got {:?}", self.address).into()); }
        if !self.root.exists() { return Err("Root directory does not exist".into()); }
        if !self.admin_root.exists() { return Err("Admin root directory does not exist".into()); }
        for ip in self.admin_allowed_ips.iter().chain(self.metrics_allowed_ips.iter()) {
            if ip.parse::<IpNet>().is_err() { return Err(format!("Invalid CIDR: {}", ip).into()); }
        }
        for d in &self.acme_domains { if !dns::is_valid_domain(d) { return Err(format!("Invalid domain: {}", d).into()); } }
        Ok(())
    }
}

fn parse_vpn_from_map(m: &HashMap<String, String>) -> vpn::VpnConfig {
    let get = |k: &str| m.get(k).map(|s| s.trim_matches(|c: char| c == '"' || c == '\'').to_string());
    let b = |k: &str, d: bool| get(k).map(|v| matches!(v.as_str(), "1" | "true" | "yes")).unwrap_or(d);
    let n = |k: &str, d: i64| get(k).and_then(|v| v.parse::<i64>().ok()).unwrap_or(d);
    let j = |k: &str, d: &[&str]| get(k).and_then(|v| serde_json::from_str::<Vec<String>>(&v).ok()).unwrap_or_else(|| d.iter().map(|s| s.to_string()).collect());
    vpn::VpnConfig {
        enabled: b("vpn.enabled", true),
        interface: get("vpn.interface").unwrap_or_else(|| "vpn0".into()),
        default_mtu: n("vpn.default_mtu", 1420),
        default_dns: j("vpn.default_dns", &["1.1.1.1", "2606:4700:4700::1111"]),
        default_allowed_ips: j("vpn.default_allowed_ips", &["0.0.0.0/0", "::/0"]),
        default_persistent_keepalive: n("vpn.default_persistent_keepalive", 0),
        firewall_enabled: b("vpn.firewall_enabled", false),
        acme_ip: None,
    }
}

fn is_local_ip(ip: IpAddr) -> bool { if ip.is_unspecified() || ip.is_loopback() { return true; } match std::net::UdpSocket::bind(SocketAddr::new(ip, 0)) { Ok(_) => true, Err(e) if e.raw_os_error() == Some(libc::EADDRNOTAVAIL) => false, Err(_) => true } }
fn parse_bind_ip(s: &str) -> Result<IpAddr, String> { let t = s.trim(); if let Ok(ip) = t.parse::<IpAddr>() { return Ok(ip); } if let Ok(sa) = t.parse::<SocketAddr>() { return Ok(sa.ip()); } Err(format!("invalid bind address: {t:?}")) }
fn sanitize_dir_path(p: &PathBuf, label: &str, default_name: &str) -> PathBuf { let s = p.as_os_str().to_string_lossy().trim().to_string(); if s.is_empty() || matches!(s.as_str(), "*" | "," | "?" | ";" | "\"\"" | "''" | ".") { eprintln!("[CONFIG] {label} = {s:?} looks invalid; using \"./{default_name}\""); return PathBuf::from(format!("./{default_name}")); } PathBuf::from(s) }
fn sanitize_admin_root(p: &PathBuf, root: &PathBuf) -> PathBuf { let s = p.as_os_str().to_string_lossy().trim().to_string(); if s.is_empty() || matches!(s.as_str(), "*" | "," | "?" | ";") { eprintln!("[CONFIG] admin_root = {s:?} looks invalid; falling back to root = {:?}", root); return root.clone(); } PathBuf::from(s) }

async fn auto_open_ports(ports: &[u16]) {
    let enabled = std::env::var("OMNIRS_AUTO_OPEN_PORTS").map(|v| v == "true" || v == "1" || v == "yes").unwrap_or(false);
    if !enabled { return; }
    #[cfg(unix)]
    {
        let is_root = std::process::Command::new("id").arg("-u").output().ok().and_then(|o| String::from_utf8(o.stdout).ok()).map(|s| s.trim() == "0").unwrap_or(false);
        if !is_root { eprintln!("[FIREWALL] OMNIRS_AUTO_OPEN_PORTS enabled but not running as root; skipping."); return; }
    }
    for port in ports {
        let port_s = port.to_string();
        let check = tokio::process::Command::new("iptables").args(["-C", "INPUT", "-p", "tcp", "--dport", &port_s, "-j", "ACCEPT"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().await;
        let already = matches!(check, Ok(s) if s.success());
        if already { println!("[FIREWALL] Port {} already open.", port); continue; }
        let add = tokio::process::Command::new("iptables").args(["-I", "INPUT", "-p", "tcp", "--dport", &port_s, "-j", "ACCEPT"]).status().await;
        match add { Ok(s) if s.success() => println!("[FIREWALL] Opened TCP port {}", port), _ => eprintln!("[FIREWALL] Failed to open port {} (no iptables or no permission).", port), }
    }
}

pub type SharedState = Arc<RwLock<Arc<AppState>>>;

pub struct AppState {
    pub config: Config, pub client: reqwest::Client, pub grpc_client: reqwest::Client, pub next_backend: AtomicUsize,
    pub backend_health: Arc<RwLock<HashMap<String, bool>>>, pub backend_conns: Arc<RwLock<HashMap<String, Arc<AtomicUsize>>>>, pub backend_circuits: Arc<RwLock<HashMap<String, Arc<CircuitBreaker>>>>,
    pub rate_limits: Arc<Mutex<HashMap<String, (Instant, u32)>>>, pub metrics: Arc<Metrics>, pub cache: Option<moka::future::Cache<String, CachedResponse>>,
    pub admin_allowed_ips: Arc<Vec<IpNet>>, pub metrics_allowed_ips: Arc<Vec<IpNet>>,
    pub started_at: Instant, pub dns: Option<Arc<dns::DnsServer>>, pub audit: Option<Arc<dns::AuditLog>>,
    pub backends: Arc<RwLock<Vec<String>>>, pub virtual_hosts: Arc<RwLock<HashMap<String, PathBuf>>>, pub redirects: Arc<RwLock<HashMap<String, String>>>,
    pub wire_status: Arc<RwLock<HashMap<String, WireSvc>>>,
    pub ips: Arc<security::IntrusionPrevention>, pub db: Option<Arc<db::DbManager>>, pub ssl: Option<Arc<ssl::SslManager>>,
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).pool_max_idle_per_host(64).connect_timeout(Duration::from_secs(5)).timeout(Duration::from_secs(120)).build()?;
        let grpc_client = reqwest::Client::builder().http2_prior_knowledge().redirect(reqwest::redirect::Policy::none()).pool_max_idle_per_host(64).connect_timeout(Duration::from_secs(5)).timeout(Duration::from_secs(300)).build()?;
        let backend_conns = config.backends.iter().map(|b| (b.clone(), Arc::new(AtomicUsize::new(0)))).collect();
        let backend_circuits = config.backends.iter().map(|b| (b.clone(), Arc::new(CircuitBreaker::new()))).collect();
        let cache = if config.cache_enabled { Some(moka::future::Cache::builder().time_to_live(Duration::from_secs(config.cache_ttl_secs)).max_capacity(config.cache_max_entries).build()) } else { None };
        let admin_allowed_ips = Arc::new(config.admin_allowed_ips.iter().filter_map(|s| s.parse().ok()).collect());
        let metrics_allowed_ips = Arc::new(config.metrics_allowed_ips.iter().filter_map(|s| s.parse().ok()).collect());
        let db_manager = if config.db.enabled { db::global() } else { None };
        let dns_config = load_dns_config().await;
        let dns_server = dns_config.filter(|c| c.enabled).and_then(|c| match dns::DnsServer::from_config(c) { Ok(srv) => { println!("[DNS] server initialized"); Some(Arc::new(srv)) } Err(e) => { eprintln!("[DNS] init failed: {}", e); None } });
        let audit_log = load_audit_log();
        let backends_dyn = Arc::new(RwLock::new(config.backends.clone()));
        let vhosts_dyn = Arc::new(RwLock::new(config.virtual_hosts.clone()));
        let redirects_dyn = Arc::new(RwLock::new(config.redirects.clone()));
        let ips = security::IntrusionPrevention::new(36000);
        let ssl_mgr = Arc::new(ssl::SslManager::new());
        let _ = ssl_mgr.reload_from_db().await;
        if ssl_mgr.default_cert.read().unwrap().is_none() { let _ = ssl_mgr.generate_self_signed_default(); }
        Ok(Self {
            config, client, grpc_client, next_backend: AtomicUsize::new(0),
            backend_health: Arc::new(RwLock::new(HashMap::new())),
            backend_conns: Arc::new(RwLock::new(backend_conns)),
            backend_circuits: Arc::new(RwLock::new(backend_circuits)),
            rate_limits: Arc::new(Mutex::new(HashMap::new())),
            metrics: Arc::new(Metrics::default()), cache,
            admin_allowed_ips, metrics_allowed_ips,
            started_at: Instant::now(), ips, dns: dns_server, audit: audit_log,
            backends: backends_dyn, virtual_hosts: vhosts_dyn, redirects: redirects_dyn,
            wire_status: Arc::new(RwLock::new(HashMap::new())),
            db: db_manager, ssl: Some(ssl_mgr),
        })
    }
    pub fn select_backend(&self) -> Option<String> { let backends = self.backends.read().unwrap().clone(); if backends.is_empty() { return None; } let health = self.backend_health.read().unwrap(); let conns = self.backend_conns.read().unwrap(); let circuits = self.backend_circuits.read().unwrap(); let mut candidates: Vec<&String> = backends.iter().filter(|b| *health.get(*b).unwrap_or(&true)).filter(|b| circuits.get(*b).map_or(true, |c| !c.is_open())).collect(); if candidates.is_empty() { candidates = backends.iter().filter(|b| *health.get(*b).unwrap_or(&true)).collect(); } if candidates.is_empty() { return backends.first().cloned(); } candidates.into_iter().min_by_key(|b| conns.get(*b).map(|c| c.load(Ordering::Relaxed)).unwrap_or(0)).cloned() }
    pub fn select_backends_for_failover(&self) -> Vec<String> { let backends = self.backends.read().unwrap().clone(); if backends.is_empty() { return Vec::new(); } let health = self.backend_health.read().unwrap(); let conns = self.backend_conns.read().unwrap(); let circuits = self.backend_circuits.read().unwrap(); let mut candidates: Vec<&String> = backends.iter().filter(|b| *health.get(*b).unwrap_or(&true)).filter(|b| circuits.get(*b).map_or(true, |c| !c.is_open())).collect(); if candidates.is_empty() { candidates = backends.iter().filter(|b| *health.get(*b).unwrap_or(&true)).collect(); } if candidates.is_empty() { return backends.clone(); } candidates.sort_by_key(|b| conns.get(*b).map(|c| c.load(Ordering::Relaxed)).unwrap_or(0)); candidates.into_iter().take(self.config.failover_attempts as usize).cloned().collect() }
    pub fn select_sticky_backend(&self, headers: &HeaderMap, client_ip: &str) -> Option<String> { if !self.config.sticky_sessions { return None; } let backends = self.backends.read().unwrap().clone(); if backends.is_empty() { return None; } if let Some(cookie_hdr) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) { for part in cookie_hdr.split(';') { let p = part.trim(); if let Some(rest) = p.strip_prefix("omnirs_backend=") { if backends.iter().any(|b| b == rest) { return Some(rest.to_string()); } } } } let hash = client_ip.bytes().fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64)); Some(backends[hash as usize % backends.len()].clone()) }
    pub fn select_root(&self, host: Option<&str>) -> PathBuf { let vhosts = self.virtual_hosts.read().unwrap(); dns::select_virtual_host(host, &vhosts, &self.config.root).to_path_buf() }
}

fn text_response(status: StatusCode, text: impl Into<Body>) -> Response<Body> { Response::builder().status(status).header(header::CONTENT_TYPE, "text/plain; charset=utf-8").body(text.into()).unwrap_or_else(|_| Response::new(Body::empty())) }
fn is_hop_by_hop(name: &HeaderName) -> bool { matches!(name.as_str(), "connection" | "keep-alive" | "proxy-authenticate" | "proxy-authorization" | "te" | "trailer" | "transfer-encoding" | "upgrade") }
fn connection_nominated_headers(headers: &HeaderMap) -> Vec<HeaderName> { headers.get_all(header::CONNECTION).iter().filter_map(|value| value.to_str().ok()).flat_map(|value| value.split(',')).filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok()).collect() }
fn with_alt_svc(mut response: Response<Body>, h3_port: u16) -> Response<Body> { let value = format!("h3=\":{}\"; ma=86400", h3_port); if let Ok(hv) = value.parse() { response.headers_mut().insert("alt-svc", hv); } response }
fn is_grpc_request(headers: &HeaderMap) -> bool { headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map_or(false, |v| v.starts_with("application/grpc")) }

fn health_endpoint(state: &AppState) -> Response<Body> {
    let h = state.backend_health.read().unwrap();
    let all_healthy = h.values().all(|&v| v);
    let status = if all_healthy { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    let json = format!(r#"{{"status":"{}","uptime_secs":{},"backends_total":{},"backends_healthy":{},"sticky_sessions":{},"dns_enabled":{}}}"#, if all_healthy { "ok" } else { "degraded" }, state.started_at.elapsed().as_secs(), h.len(), h.values().filter(|&&v| v).count(), state.config.sticky_sessions, state.dns.is_some());
    Response::builder().status(status).header(header::CONTENT_TYPE, "application/json").header(header::CACHE_CONTROL, "no-store").body(Body::from(json)).unwrap()
}

async fn metrics_endpoint(state: &AppState) -> Response<Body> {
    let m = &state.metrics;
    let total = m.total_requests.load(Ordering::Relaxed); let s2 = m.status_2xx.load(Ordering::Relaxed); let s3 = m.status_3xx.load(Ordering::Relaxed); let s4 = m.status_4xx.load(Ordering::Relaxed); let s5 = m.status_5xx.load(Ordering::Relaxed); let lat = m.total_latency_ms.load(Ordering::Relaxed); let avg = if total > 0 { lat as f64 / total as f64 } else { 0.0 };
    let active: usize = state.backend_conns.read().unwrap().values().map(|c| c.load(Ordering::Relaxed)).sum(); let healthy = state.backend_health.read().unwrap().values().filter(|&&v| v).count();
    let hits = m.cache_hits.load(Ordering::Relaxed); let misses = m.cache_misses.load(Ordering::Relaxed); let fo = m.failover_retries.load(Ordering::Relaxed); let slow = m.slow_requests.load(Ordering::Relaxed);
    let mut text = format!(
        "# HELP omnirs_requests_total Total requests\n# TYPE omnirs_requests_total counter\nomnirs_requests_total {}\n\
         # HELP omnirs_responses_2xx 2xx responses\n# TYPE omnirs_responses_2xx counter\nomnirs_responses_2xx {}\n\
         # HELP omnirs_responses_3xx 3xx responses\n# TYPE omnirs_responses_3xx counter\nomnirs_responses_3xx {}\n\
         # HELP omnirs_responses_4xx 4xx responses\n# TYPE omnirs_responses_4xx counter\nomnirs_responses_4xx {}\n\
         # HELP omnirs_responses_5xx 5xx responses\n# TYPE omnirs_responses_5xx counter\nomnirs_responses_5xx {}\n\
         # HELP omnirs_latency_ms_total Total latency (ms)\n# TYPE omnirs_latency_ms_total counter\nomnirs_latency_ms_total {}\n\
         # HELP omnirs_latency_ms_avg Average latency (ms)\n# TYPE omnirs_latency_ms_avg gauge\nomnirs_latency_ms_avg {:.3}\n\
         # HELP omnirs_active_connections Active backend connections\n# TYPE omnirs_active_connections gauge\nomnirs_active_connections {}\n\
         # HELP omnirs_backends_healthy Number of healthy backends\n# TYPE omnirs_backends_healthy gauge\nomnirs_backends_healthy {}\n\
         # HELP omnirs_cache_hits Cache hits\n# TYPE omnirs_cache_hits counter\nomnirs_cache_hits {}\n\
         # HELP omnirs_cache_misses Cache misses\n# TYPE omnirs_cache_misses counter\nomnirs_cache_misses {}\n\
         # HELP omnirs_failover_retries Failover retry attempts\n# TYPE omnirs_failover_retries counter\nomnirs_failover_retries {}\n\
         # HELP omnirs_slow_requests Slow requests\n# TYPE omnirs_slow_requests counter\nomnirs_slow_requests {}\n\
         # HELP omnirs_uptime_seconds Uptime (s)\n# TYPE omnirs_uptime_seconds gauge\nomnirs_uptime_seconds {}\n",
        total, s2, s3, s4, s5, lat, avg, active, healthy, hits, misses, fo, slow, state.started_at.elapsed().as_secs()
    );
    if let Some(dns) = &state.dns { text.push_str(&dns.metrics_text()); }
    text.push_str(&vpn::metrics_extra_async().await);
    Response::builder().status(StatusCode::OK).header(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8").header(header::CACHE_CONTROL, "no-store").body(Body::from(text)).unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════
// MERGED handle — admin + site + proxy on :443
// ═══════════════════════════════════════════════════════════════════════════
async fn handle(State(state): State<SharedState>, request: Request<Body>) -> Response<Body> {
    let connect_info = request.extensions().get::<ConnectInfo<SocketAddr>>().cloned();
    let request_version = request.version();
    let current_state = state.read().unwrap().clone();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let mut path = uri.path().to_string();
    if path.starts_with("http://") || path.starts_with("https://") {
        if let Ok(parsed) = path.parse::<axum::http::Uri>() { path = parsed.path().to_string(); }
    }
    let h3_port = current_state.config.h3_port.unwrap_or(443);
    let client_ip = resolve_client_ip(&headers, connect_info.as_ref());
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();

    // ── 1. VPN one-time-link
    if let Some(token) = path.strip_prefix("/cnf/") {
        if !token.is_empty() && !token.contains('/') {
            if let Some(resp) = vpn::serve_otl(token).await { return resp; }
            return text_response(StatusCode::NOT_FOUND, "invalid one-time-link");
        }
    }

    // ── 2. DNS-over-HTTPS
    if let Some(dns) = current_state.dns.clone() {
        let doh_path = dns.config.doh_path.clone();
        if path == doh_path {
            let is_h3 = request_version == axum::http::Version::HTTP_3;
            let ip = connect_info.as_ref().map(|ci| ci.0.ip()).unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
            if method == Method::POST {
                let body_bytes = match to_bytes(request.into_body(), 65535).await { Ok(b) => b, Err(_) => return text_response(StatusCode::BAD_REQUEST, "DNS body too large") };
                let result = if is_h3 { dns.handle_doh3_request(body_bytes.to_vec(), ip).await } else { dns.handle_doh_body(body_bytes.to_vec(), ip).await };
                return match result {
                    Ok(bytes) => Response::builder().status(StatusCode::OK).header(header::CONTENT_TYPE, "application/dns-message").header(header::CACHE_CONTROL, "no-store").body(Body::from(bytes)).unwrap_or_else(|_| Response::new(Body::empty())),
                    Err(e) => text_response(StatusCode::BAD_REQUEST, format!("dns: {}", e)),
                };
            } else if method == Method::GET {
                if let Some(q) = uri.query() {
                    for part in q.split('&') {
                        if let Some(b64) = part.strip_prefix("dns=") {
                            if let Ok(msg_bytes) = URL_SAFE_NO_PAD.decode(b64) {
                                let result = if is_h3 { dns.handle_doh3_request(msg_bytes, ip).await } else { dns.handle_doh_body(msg_bytes, ip).await };
                                return match result {
                                    Ok(bytes) => Response::builder().status(StatusCode::OK).header(header::CONTENT_TYPE, "application/dns-message").header(header::CACHE_CONTROL, "no-store").body(Body::from(bytes)).unwrap_or_else(|_| Response::new(Body::empty())),
                                    Err(e) => text_response(StatusCode::BAD_REQUEST, format!("dns: {}", e)),
                                };
                            }
                        }
                    }
                }
                return text_response(StatusCode::BAD_REQUEST, "missing ?dns= parameter");
            }
        }
    }

    // ── 3. Admin-area IP allowlist (для /, /api/*, /terminal, /terminal/api/*)
    let is_admin_area = path == "/" || path == "/index.html"
        || path.starts_with("/api/")
        || path == "/terminal" || path == "/terminal/"
        || path.starts_with("/terminal/api/");
    if is_admin_area && !is_ip_allowed(&client_ip, &current_state.admin_allowed_ips) {
        return text_response(StatusCode::FORBIDDEN, "Admin access denied");
    }

    // ── 4. Health / Metrics (с собственными allowlist'ами)
    if method == Method::GET && path == "/health" { return health_endpoint(&current_state); }
    if method == Method::GET && path == "/metrics" {
        if !is_ip_allowed(&client_ip, &current_state.metrics_allowed_ips) { return text_response(StatusCode::FORBIDDEN, "Forbidden"); }
        return metrics_endpoint(&current_state).await;
    }

    // ── 5. Rate limit (общий)
    {
        let mut rl = current_state.rate_limits.lock().unwrap();
        let now = Instant::now();
        let entry = rl.entry(client_ip.clone()).or_insert((now, 0));
        if now.duration_since(entry.0).as_secs() >= 1 { *entry = (now, 1); } else { entry.1 += 1; }
        if entry.1 > 100 { return with_alt_svc(text_response(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"), h3_port); }
    }

    // ── 6. Redirects
    {
        let dest_opt = current_state.redirects.read().unwrap().get(&path).cloned();
        if let Some(destination) = dest_opt {
            let resp = Response::builder().status(StatusCode::FOUND).header(header::LOCATION, destination.as_str()).body(Body::empty()).unwrap_or_else(|_| Response::new(Body::empty()));
            return with_alt_svc(resp, h3_port);
        }
    }

    // ── 7. Cache (не для admin-area)
    if !is_admin_area && method == Method::GET && path != "/health" && path != "/metrics" {
        if let Some(cache) = &current_state.cache {
            let cache_key = format!("{}|{}|{}", host, path, uri.query().unwrap_or(""));
            if let Some(cached) = cache.get(&cache_key).await {
                current_state.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                let mut b = Response::builder().status(StatusCode::from_u16(cached.status).unwrap_or(StatusCode::OK));
                for (k, v) in &cached.headers {
                    if let (Ok(name), Ok(val)) = (HeaderName::from_bytes(k.as_bytes()), header::HeaderValue::from_str(v)) { b = b.header(name, val); }
                }
                let resp = b.header("x-cache", "HIT").body(Body::from(cached.body.clone())).unwrap_or_else(|_| Response::new(Body::empty()));
                return with_alt_svc(resp, h3_port);
            }
            current_state.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
        }
    }

    // ── 8. /api/* → admin API (auth: x-admin-token или omnirs_admin cookie)
    if path.starts_with("/api/") {
        if current_state.config.admin_token.is_empty() {
            return with_alt_svc(text_response(StatusCode::SERVICE_UNAVAILABLE, "Admin disabled: set OMNIRS_ADMIN_TOKEN in DB"), h3_port);
        }
        let endpoint = path.trim_start_matches("/api/").to_string();
        let is_public_endpoint = matches!(endpoint.as_str(),
            "auth/login" | "auth/logout" | "auth/whoami" | "diag/ping" | "diag/echo" | "diag/validate_token");

        // login rate-limit (20/min)
        if endpoint == "auth/login" {
            let key = format!("admin_login:{}", client_ip);
            let mut rl = current_state.rate_limits.lock().unwrap();
            let now = Instant::now();
            let entry = rl.entry(key).or_insert((now, 0));
            if now.duration_since(entry.0).as_secs() >= 60 { *entry = (now, 1); } else { entry.1 += 1; }
            if entry.1 > 20 {
                return with_alt_svc(text_response(StatusCode::TOO_MANY_REQUESTS, "Too many login attempts (20/min)"), h3_port);
            }
        }

        if !is_public_endpoint {
            let supplied_token = headers.get("x-admin-token").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            let cookie_session = headers.get(header::COOKIE).and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(';').find_map(|p| p.trim().strip_prefix("omnirs_admin=").map(|x| x.to_string())))
                .unwrap_or_default();
            let token_ok = {
                let a = supplied_token.as_bytes();
                let b = current_state.config.admin_token.as_bytes();
                let mut d = a.len() ^ b.len();
                for i in 0..a.len().max(b.len()) {
                    d |= (a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0)) as usize;
                }
                d == 0 && !supplied_token.is_empty()
            };
            let session_ok = if !token_ok && !cookie_session.is_empty() {
                api::sessions().lock().unwrap().contains_key(&cookie_session)
            } else { false };
            if !token_ok && !session_ok {
                log_admin_action(&current_state, &client_ip, "auth_failed", "admin", "error", json!({}));
                return with_alt_svc(text_response(StatusCode::UNAUTHORIZED, "Invalid admin token or session"), h3_port);
            }
        }

        let qmap: HashMap<String, String> = uri.query().unwrap_or("").split('&')
            .filter_map(|p| p.split_once('=').map(|(k, v)| (decode_component(k), decode_component(v))))
            .collect();
        let (parts, body) = request.into_parts();
        return with_alt_svc(
            api::dispatch(current_state.clone(), parts.method, endpoint, qmap, parts.headers, body, client_ip).await,
            h3_port,
        );
    }

    // ── 9. /terminal и /terminal/api/*
    if path == "/terminal" || path == "/terminal/" {
        return with_alt_svc(terminal_response(&method), h3_port);
    }
    if path.starts_with("/terminal/api/") {
        let endpoint = path.trim_start_matches("/terminal/api/").to_string();
        let qmap: HashMap<String, String> = uri.query().unwrap_or("").split('&')
            .filter_map(|p| p.split_once('=').map(|(k, v)| (decode_component(k), decode_component(v))))
            .collect();
        let (parts, body) = request.into_parts();
        return with_alt_svc(
            api::dispatch_terminal(current_state.clone(), parts.method, endpoint, qmap, parts.headers, body, client_ip).await,
            h3_port,
        );
    }

    // ── 10. / и /index.html → admin (login-страница или HTML, если уже залогинен)
    if method == Method::GET && (path == "/" || path == "/index.html") {
        if current_state.config.admin_token.is_empty() {
            return with_alt_svc(text_response(StatusCode::SERVICE_UNAVAILABLE, "Admin disabled: set OMNIRS_ADMIN_TOKEN in DB"), h3_port);
        }
        let cookie_session = headers.get(header::COOKIE).and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(';').find_map(|p| p.trim().strip_prefix("omnirs_admin=").map(|x| x.to_string())))
            .unwrap_or_default();
        let is_authed = !cookie_session.is_empty()
            && api::sessions().lock().unwrap().contains_key(&cookie_session);
        if !is_authed {
            return with_alt_svc(terminal_response_admin_login(&method), h3_port);
        }
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-store")
            .header("x-content-type-options", "nosniff")
            .header("x-frame-options", "DENY")
            .header("referrer-policy", "no-referrer")
            .body(Body::from(ADMIN_HTML))
            .unwrap_or_else(|_| Response::new(Body::empty()));
        return with_alt_svc(resp, h3_port);
    }

    // ── 11. Reverse proxy (/proxy/*)
    let prefix = current_state.config.proxy_prefix.trim_end_matches('/');
    let is_proxy_request = !prefix.is_empty() && (path == prefix || path.starts_with(&format!("{prefix}/")));
    if is_proxy_request {
        let is_ws = headers.get(header::UPGRADE).and_then(|v| v.to_str().ok()).map_or(false, |v| v.eq_ignore_ascii_case("websocket"));
        if is_ws {
            let backend = current_state.select_backend().unwrap_or_default();
            let suffix = &path[prefix.len()..];
            let mut target = format!("{backend}{suffix}");
            if let Some(q) = uri.query() { target.push('?'); target.push_str(q); }
            return proxy_websocket(request, target).await;
        }
        let is_grpc = is_grpc_request(&headers) && current_state.config.grpc_passthrough;
        let suffix = &path[prefix.len()..];
        let query_str = uri.query().map(|q| format!("?{}", q)).unwrap_or_default();
        let sticky_backend = current_state.select_sticky_backend(&headers, &client_ip);
        let send_sticky_cookie = current_state.config.sticky_sessions && !has_sticky_cookie(&headers);
        let can_failover = (method == Method::GET || method == Method::HEAD) && !is_grpc;
        if can_failover {
            let backends = current_state.select_backends_for_failover();
            if backends.is_empty() { return with_alt_svc(text_response(StatusCode::BAD_GATEWAY, "No backend servers configured"), h3_port); }
            let mut last_resp: Option<Response<Body>> = None;
            let mut chosen_backend: Option<String> = None;
            for (idx, backend) in backends.iter().enumerate() {
                if idx > 0 { current_state.metrics.failover_retries.fetch_add(1, Ordering::Relaxed); }
                let target = format!("{}{}{}", backend, suffix, query_str);
                let mut req = current_state.client.request(method.clone(), &target);
                req = req.header("X-Forwarded-For", &client_ip).header("X-Real-IP", &client_ip).header("X-Forwarded-Proto", "https");
                if let Some(h) = headers.get(header::HOST) { req = req.header("X-Forwarded-Host", h); }
                for (n, v) in &headers {
                    if n != header::HOST && !is_hop_by_hop(n)
                        && n.as_str() != "x-forwarded-for" && n.as_str() != "x-real-ip"
                        && n.as_str() != "x-forwarded-proto" && n.as_str() != "x-forwarded-host" {
                        req = req.header(n, v);
                    }
                }
                match req.send().await {
                    Ok(r) if !r.status().is_server_error() => {
                        let status = r.status();
                        let rh = r.headers().clone();
                        let mut result = Response::new(Body::from_stream(r.bytes_stream()));
                        *result.status_mut() = status;
                        let nom = connection_nominated_headers(&rh);
                        for (n, v) in &rh { if !is_hop_by_hop(n) && !nom.contains(n) { result.headers_mut().insert(n.clone(), v.clone()); } }
                        if send_sticky_cookie { if let Ok(c) = sticky_cookie_for(backend).parse() { result.headers_mut().append(header::SET_COOKIE, c); } }
                        return with_alt_svc(result, h3_port);
                    }
                    Ok(r) => {
                        let status = r.status();
                        let rh = r.headers().clone();
                        let body = r.bytes().await.unwrap_or_default();
                        let mut result = Response::new(Body::from(body));
                        *result.status_mut() = status;
                        for (n, v) in &rh { if !is_hop_by_hop(n) { result.headers_mut().insert(n.clone(), v.clone()); } }
                        last_resp = Some(result);
                        chosen_backend = Some(backend.clone());
                    }
                    Err(_) => { last_resp = Some(text_response(StatusCode::BAD_GATEWAY, "Backend unavailable")); }
                }
            }
            let mut resp = last_resp.unwrap_or_else(|| text_response(StatusCode::BAD_GATEWAY, "All backends failed"));
            if send_sticky_cookie { if let Some(b) = chosen_backend { if let Ok(c) = sticky_cookie_for(&b).parse() { resp.headers_mut().append(header::SET_COOKIE, c); } } }
            return with_alt_svc(resp, h3_port);
        }
        let backend = match sticky_backend.or_else(|| current_state.select_backend()) { Some(b) => b, None => return with_alt_svc(text_response(StatusCode::BAD_GATEWAY, "No backend servers configured"), h3_port) };
        let conn_counter = current_state.backend_conns.read().unwrap().get(&backend).cloned().unwrap_or_else(|| Arc::new(AtomicUsize::new(0)));
        let circuit = current_state.backend_circuits.read().unwrap().get(&backend).cloned().unwrap_or_else(|| Arc::new(CircuitBreaker::new()));
        let mut target = format!("{backend}{suffix}");
        if let Some(q) = uri.query() { target.push('?'); target.push_str(q); }
        let guard = ConnGuard::new(conn_counter);
        let (parts, body) = request.into_parts();
        let nominated = connection_nominated_headers(&parts.headers);
        let body_stream = body.into_data_stream();
        let client = if is_grpc { &current_state.grpc_client } else { &current_state.client };
        let mut req = client.request(parts.method, target);
        req = req.header("X-Forwarded-For", &client_ip).header("X-Forwarded-Proto", "https").header("X-Real-IP", &client_ip);
        if let Some(h) = parts.headers.get(header::HOST) { req = req.header("X-Forwarded-Host", h); }
        for (n, v) in &parts.headers {
            if n != header::HOST && !is_hop_by_hop(n) && !nominated.contains(n)
                && n.as_str() != "x-forwarded-for" && n.as_str() != "x-real-ip"
                && n.as_str() != "x-forwarded-proto" && n.as_str() != "x-forwarded-host" {
                req = req.header(n, v);
            }
        }
        let upstream = match req.body(reqwest::Body::wrap_stream(body_stream)).send().await {
            Ok(r) => { circuit.record_success(); r }
            Err(_) => { circuit.record_failure(); drop(guard); return with_alt_svc(text_response(StatusCode::BAD_GATEWAY, "Backend server unavailable"), h3_port); }
        };
        let status = upstream.status();
        let upstream_headers = upstream.headers().clone();
        let mut result = Response::new(Body::from_stream(GuardedStream { inner: Box::pin(upstream.bytes_stream()), _guard: guard }));
        *result.status_mut() = status;
        let upstream_nominated = connection_nominated_headers(&upstream_headers);
        for (n, v) in &upstream_headers { if !is_hop_by_hop(n) && !upstream_nominated.contains(n) { result.headers_mut().insert(n.clone(), v.clone()); } }
        if send_sticky_cookie { if let Ok(c) = sticky_cookie_for(&backend).parse() { result.headers_mut().append(header::SET_COOKIE, c); } }
        return with_alt_svc(result, h3_port);
    }

    // ── 12. FastCGI
    if let Some(fcgi_pass) = &current_state.config.fastcgi_pass {
        let fcgi_root = current_state.select_root(Some(&host));
        let idx = current_state.config.fastcgi_index.clone();
        let needs_rewrite = !path.ends_with(".php");
        let is_php = if !needs_rewrite { true } else {
            let probe = if path.ends_with('/') { format!("{}{}", path, idx) } else { format!("{}/{}", path, idx) };
            tokio::fs::metadata(fcgi_root.join(probe.trim_start_matches('/'))).await.map(|m| m.is_file()).unwrap_or(false)
        };
        if is_php {
            let req = if needs_rewrite {
                let new_path = if path.ends_with('/') { format!("{}{}", path, idx) } else { format!("{}/{}", path, idx) };
                let new_uri_str = if let Some(q) = uri.query() { format!("{}?{}", new_path, q) } else { new_path.clone() };
                println!("[FastCGI] rewrite {} → {}", path, new_uri_str);
                let (mut parts, body) = request.into_parts();
                match new_uri_str.parse::<axum::http::Uri>() { Ok(u) => { parts.uri = u; Request::from_parts(parts, body) }, Err(_) => return with_alt_svc(text_response(StatusCode::BAD_REQUEST, "Bad URI"), h3_port) }
            } else { request };
            let cache_key = format!("{}|{}|{}", host, path, uri.query().unwrap_or(""));
            let resp = proxy_fastcgi(current_state.clone(), req, fcgi_pass.clone(), cache_key, client_ip.clone()).await;
            return with_alt_svc(resp, h3_port);
        }
    }

    // ── 13. Статика (последний fallback)
    if method != Method::GET && method != Method::HEAD {
        return with_alt_svc(terminal_response_status(&method, StatusCode::METHOD_NOT_ALLOWED, Some(&format!("405 method not allowed: {} {}", method, path))), h3_port);
    }
    let root = current_state.select_root(headers.get(header::HOST).and_then(|v| v.to_str().ok()));
    let mut relative = PathBuf::new();
    for component in Path::new(path.trim_start_matches('/')).components() {
        match component {
            Component::Normal(part) => relative.push(part),
            Component::CurDir => {},
            _ => return with_alt_svc(terminal_response_status(&method, StatusCode::FORBIDDEN, Some(&format!("403 forbidden: {}", path))), h3_port),
        }
    }
    let mut candidate = root.join(relative);
    if tokio::fs::metadata(&candidate).await.map(|m| m.is_dir()).unwrap_or(false) { candidate.push("index.html"); }
    let candidate = match tokio::fs::canonicalize(&candidate).await { Ok(p) => p, Err(_) => return with_alt_svc(terminal_response_status(&method, StatusCode::NOT_FOUND, Some(&format!("404 not found: {}", path))), h3_port) };
    if !candidate.starts_with(&root) { return with_alt_svc(terminal_response_status(&method, StatusCode::FORBIDDEN, Some(&format!("403 forbidden: {}", path))), h3_port); }
    let _ = match tokio::fs::metadata(&candidate).await { Ok(m) if m.is_file() => m, _ => return with_alt_svc(terminal_response_status(&method, StatusCode::NOT_FOUND, Some(&format!("404 not found: {}", path))), h3_port) };
    let accept_enc = headers.get(header::ACCEPT_ENCODING).and_then(|v| v.to_str().ok()).unwrap_or("").to_lowercase();
    let tokens: Vec<&str> = accept_enc.split(',').map(|s| s.trim().split(';').next().unwrap_or("").trim()).collect();
    let can_br = tokens.iter().any(|t| *t == "br" || *t == "*");
    let can_gzip = tokens.iter().any(|t| *t == "gzip" || *t == "*");
    let br_path = PathBuf::from(format!("{}.br", candidate.display()));
    let gz_path = PathBuf::from(format!("{}.gz", candidate.display()));
    let has_range = headers.contains_key(header::RANGE);
    let (final_path, content_enc) = if !has_range && can_br && br_path.is_file() { (br_path, Some("br")) }
        else if !has_range && can_gzip && gz_path.is_file() { (gz_path, Some("gzip")) }
        else { (candidate.clone(), None) };
    let metadata = match tokio::fs::metadata(&final_path).await { Ok(m) if m.is_file() => m, _ => return with_alt_svc(terminal_response_status(&method, StatusCode::NOT_FOUND, Some(&format!("404 not found: {}", path))), h3_port) };
    let mtime = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH).duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let etag = format!("\"{}-{}{}\"", metadata.len(), mtime, content_enc.unwrap_or(""));
    let cache_control = if is_hashed_filename(&candidate) { "public, max-age=31536000, immutable" } else { "public, max-age=3600" };
    if let Some(inm) = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        if inm == etag {
            let mut b = Response::builder().status(StatusCode::NOT_MODIFIED).header(header::ETAG, &etag).header(header::CACHE_CONTROL, cache_control);
            if let Some(enc) = content_enc { b = b.header(header::CONTENT_ENCODING, enc); }
            return b.body(Body::empty()).unwrap();
        }
    }
    let content_type = mime_guess::from_path(&candidate).first_or_octet_stream().to_string();
    if method == Method::HEAD {
        let mut b = Response::builder().status(StatusCode::OK).header(header::CONTENT_TYPE, content_type).header(header::CONTENT_LENGTH, metadata.len()).header(header::ETAG, &etag).header(header::CACHE_CONTROL, cache_control);
        if let Some(enc) = content_enc { b = b.header(header::CONTENT_ENCODING, enc); }
        return with_alt_svc(b.body(Body::empty()).unwrap(), h3_port);
    }
    if let Some(range) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        if let Some(bytes_str) = range.strip_prefix("bytes=") {
            let parts: Vec<&str> = bytes_str.split('-').collect();
            let start = parts[0].parse::<u64>().unwrap_or(0);
            let end = if parts.len() > 1 && !parts[1].is_empty() { parts[1].parse::<u64>().unwrap_or(metadata.len() - 1) } else { metadata.len() - 1 };
            if start <= end && end < metadata.len() {
                if let Ok(mut file) = tokio::fs::File::open(&final_path).await {
                    let _ = file.seek(std::io::SeekFrom::Start(start)).await;
                    let mut buffer = vec![0; (end - start + 1) as usize];
                    if file.read_exact(&mut buffer).await.is_ok() {
                        let resp = Response::builder().status(StatusCode::PARTIAL_CONTENT)
                            .header(header::CONTENT_TYPE, content_type)
                            .header(header::CONTENT_RANGE, format!("bytes {}-{}/{}", start, end, metadata.len()))
                            .header(header::CONTENT_LENGTH, buffer.len())
                            .header(header::ETAG, &etag).header(header::CACHE_CONTROL, cache_control)
                            .body(Body::from(buffer)).unwrap();
                        return with_alt_svc(resp, h3_port);
                    }
                }
            }
        }
    }
    let file = match tokio::fs::File::open(&final_path).await { Ok(f) => f, Err(_) => return with_alt_svc(text_response(StatusCode::INTERNAL_SERVER_ERROR, "Unable to read file"), h3_port) };
    let stream = ReaderStream::new(file);
    let mut b = Response::builder().status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, metadata.len())
        .header(header::ETAG, &etag).header(header::CACHE_CONTROL, cache_control);
    if let Some(enc) = content_enc { b = b.header(header::CONTENT_ENCODING, enc); }
    with_alt_svc(b.body(Body::from_stream(stream)).unwrap(), h3_port)
}

async fn proxy_websocket(mut req: Request<Body>, target: String) -> Response<Body> {
    let client_upgrade = hyper::upgrade::on(&mut req);
    let url = match reqwest::Url::parse(&target) { Ok(u) => u, Err(_) => return text_response(StatusCode::BAD_GATEWAY, "Invalid WS target URL") };
    let host = url.host_str().unwrap_or("localhost").to_string();
    let port = url.port_or_known_default().unwrap_or(80);
    let path_and_query = format!("{}{}", url.path(), url.query().map(|q| format!("?{}", q)).unwrap_or_default());
    let mut headers_to_send = String::new();
    for (k, v) in req.headers() {
        let k_str = k.as_str();
        if k_str.eq_ignore_ascii_case("host") { continue; }
        if let Ok(v_str) = v.to_str() { headers_to_send.push_str(&format!("{}: {}\r\n", k_str, v_str)); }
    }
    let mut backend_stream = match tokio::net::TcpStream::connect(format!("{}:{}", host, port)).await { Ok(s) => s, Err(e) => return text_response(StatusCode::BAD_GATEWAY, format!("WS connect error: {}", e)) };
    let req_str = format!("GET {} HTTP/1.1\r\nHost: {}\r\n{}\r\n", path_and_query, host, headers_to_send);
    if let Err(e) = backend_stream.write_all(req_str.as_bytes()).await { return text_response(StatusCode::BAD_GATEWAY, format!("WS write error: {}", e)); }
    let mut buf = vec![0; 8192];
    let n = match backend_stream.read(&mut buf).await { Ok(n) => n, Err(e) => return text_response(StatusCode::BAD_GATEWAY, format!("WS read error: {}", e)) };
    let resp_str = String::from_utf8_lossy(&buf[..n]);
    if !resp_str.starts_with("HTTP/1.1 101") && !resp_str.starts_with("HTTP/1.0 101") { return text_response(StatusCode::BAD_GATEWAY, "WS backend did not return 101"); }
    let mut res_builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    for line in resp_str.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("upgrade") || k.eq_ignore_ascii_case("connection") || k.eq_ignore_ascii_case("sec-websocket-accept") {
                res_builder = res_builder.header(k.trim(), v.trim());
            }
        }
    }
    WS_ACTIVE.fetch_add(1, Ordering::Relaxed);
    WS_TOTAL.fetch_add(1, Ordering::Relaxed);
    tokio::spawn(async move {
        if let Ok(upgraded) = client_upgrade.await {
            let mut upgraded = TokioIo::new(upgraded);
            let _ = tokio::io::copy_bidirectional(&mut upgraded, &mut backend_stream).await;
        }
        WS_ACTIVE.fetch_sub(1, Ordering::Relaxed);
    });
    res_builder.body(Body::empty()).unwrap_or_else(|_| Response::new(Body::empty()))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() { return None; }
    haystack.windows(needle.len()).position(|w| w == needle)
}

async fn proxy_fastcgi(state: Arc<AppState>, request: Request<Body>, fcgi_pass: String, cache_key: String, client_ip: String) -> Response<Body> {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let mut path = uri.path().to_string();
    if path.starts_with("http://") || path.starts_with("https://") {
        if let Ok(parsed) = path.parse::<axum::http::Uri>() { path = parsed.path().to_string(); }
    }
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("localhost").to_string();
    let root = state.select_root(Some(&host));
    let index = state.config.fastcgi_index.clone();
    let is_trailing_slash = path.ends_with('/');
    let mut candidate = root.join(path.trim_start_matches('/'));
    let is_file = tokio::fs::metadata(&candidate).await.map(|m| m.is_file()).unwrap_or(false);
    let mut script_name = path.clone();
    if !is_file {
        if is_trailing_slash { script_name = format!("{}{}", path, index); }
        else { script_name = format!("{}/{}", path, index); }
        candidate = root.join(script_name.trim_start_matches('/'));
    }
    let script_filename = candidate.to_string_lossy().to_string();
    if !tokio::fs::metadata(&candidate).await.map(|m| m.is_file()).unwrap_or(false) {
        return text_response(StatusCode::NOT_FOUND, format!("FastCGI: script not found ({})", script_filename));
    }
    println!("[FastCGI] {} {} → script={} name={}", method, path, script_filename, script_name);
    let (parts, body) = request.into_parts();
    let body_bytes = match to_bytes(body, 10 * 1024 * 1024).await { Ok(b) => b, Err(_) => return text_response(StatusCode::PAYLOAD_TOO_LARGE, "Request body too large") };
    let uri_str = uri.to_string();
    let is_https = headers.get("x-forwarded-proto").map_or(true, |v| v == "https");
    let mut params = Params::default()
        .request_method(method.as_str())
        .script_name(&script_name)
        .script_filename(&script_filename)
        .document_root(root.to_str().unwrap_or(""))
        .request_uri(&uri_str)
        .document_uri(&script_name)
        .query_string(uri.query().unwrap_or(""))
        .remote_addr(&client_ip)
        .remote_port(12345)
        .server_addr("127.0.0.1")
        .server_port(if is_https { 443 } else { 80 })
        .server_name(&host)
        .server_protocol("HTTP/1.1")
        .server_software("OmniRS")
        .gateway_interface("CGI/1.1")
        .content_type(parts.headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or(""))
        .content_length(body_bytes.len());
    params.insert("REDIRECT_STATUS".into(), "200".into());
    params.insert("HTTPS".into(), if is_https { "on".into() } else { "off".into() });
    params.insert("PATH_INFO".into(), "".into());
    if let Some(v) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) { params.insert("HTTP_COOKIE".into(), v.to_string().into()); }
    if let Some(v) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) { params.insert("HTTP_AUTHORIZATION".into(), v.to_string().into()); }
    if let Some(v) = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()) { params.insert("HTTP_USER_AGENT".into(), v.to_string().into()); }
    if let Some(v) = headers.get(header::REFERER).and_then(|v| v.to_str().ok()) { params.insert("HTTP_REFERER".into(), v.to_string().into()); }
    if let Some(v) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) { params.insert("HTTP_ACCEPT".into(), v.to_string().into()); }
    if let Some(v) = headers.get(header::ACCEPT_LANGUAGE).and_then(|v| v.to_str().ok()) { params.insert("HTTP_ACCEPT_LANGUAGE".into(), v.to_string().into()); }
    let stream: Box<dyn FStream> = if fcgi_pass.starts_with("unix:") {
        match tokio::net::UnixStream::connect(&fcgi_pass[5..]).await { Ok(s) => Box::new(s), Err(e) => return text_response(StatusCode::BAD_GATEWAY, format!("FastCGI connect error: {}", e)) }
    } else {
        match tokio::net::TcpStream::connect(&fcgi_pass).await { Ok(s) => Box::new(s), Err(e) => return text_response(StatusCode::BAD_GATEWAY, format!("FastCGI connect error: {}", e)) }
    };
    let client = Client::new_tokio(stream);
    let fcgi_request = FcgiRequest::new(params, futures_util::io::Cursor::new(body_bytes));
    let output = match client.execute_once(fcgi_request).await { Ok(out) => out, Err(e) => return text_response(StatusCode::BAD_GATEWAY, format!("FastCGI execute error: {}", e)) };
    let stdout = output.stdout.unwrap_or_default();
    let (header_end, body_start) = if let Some(pos) = find_bytes(&stdout, b"\r\n\r\n") { (pos, pos + 4) }
        else if let Some(pos) = find_bytes(&stdout, b"\n\n") { (pos, pos + 2) }
        else { (stdout.len(), stdout.len()) };
    let header_str = String::from_utf8_lossy(&stdout[..header_end]);
    let mut resp_headers = HeaderMap::new();
    let mut status = StatusCode::OK;
    for line in header_str.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let k_trim = k.trim();
            let v_trim = v.trim();
            if k_trim.eq_ignore_ascii_case("Status") {
                if let Some(code) = v_trim.split_whitespace().next().and_then(|s| s.parse::<u16>().ok()) { status = StatusCode::from_u16(code).unwrap_or(StatusCode::OK); }
            } else if let Ok(name) = HeaderName::from_bytes(k_trim.as_bytes()) {
                if let Ok(val) = v_trim.parse() { resp_headers.insert(name, val); }
            }
        }
    }
    if status == StatusCode::OK && resp_headers.contains_key(header::LOCATION) { status = StatusCode::FOUND; }
    let body_slice = &stdout[body_start..];
    if method == Method::GET && status.is_success() && body_slice.len() <= 1_048_576 {
        if let Some(cache) = &state.cache {
            let has_set_cookie = resp_headers.keys().any(|k| k.as_str().eq_ignore_ascii_case("set-cookie"));
            if !has_set_cookie {
                let hv: Vec<(String, String)> = resp_headers.iter().filter_map(|(k, v)| v.to_str().ok().map(|s| (k.as_str().to_string(), s.to_string()))).collect();
                let cached = CachedResponse { status: status.as_u16(), headers: hv, body: bytes::Bytes::copy_from_slice(body_slice) };
                let _ = cache.insert(cache_key, cached).await;
            }
        }
    }
    let mut response = Response::new(Body::from(body_slice.to_vec()));
    *response.status_mut() = status;
    for (k, v) in resp_headers.iter() { response.headers_mut().insert(k.clone(), v.clone()); }
    response
}

async fn handle_http_with_redirect(State(state): State<SharedState>, request: Request<Body>) -> Response<Body> {
    let path = request.uri().path();
    if path.starts_with("/.well-known/acme-challenge/") {
        let token = path.trim_start_matches("/.well-known/acme-challenge/").to_string();
        return serve_acme_challenge(state, token).await;
    }
    let host = dns::normalize_host(request.headers().get(header::HOST).and_then(|v| v.to_str().ok())).unwrap_or_else(|| "localhost".to_string());
    let pq = request.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let target = format!("https://{}{}", host, pq);
    Response::builder().status(StatusCode::PERMANENT_REDIRECT).header(header::LOCATION, target).body(Body::empty()).unwrap_or_else(|_| Response::new(Body::empty()))
}

// ═══════════ HTML-оболочки (в корне static/) ═══════════
mod static_assets;
use static_assets::*;
// ═══════════════════════════════════════════════════════════════════════════
// Terminal page builder
// ═══════════════════════════════════════════════════════════════════════════
fn js_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"'  => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '<'  => out.push_str("\\x3c"),
            '>'  => out.push_str("\\x3e"),
            _    => out.push(c),
        }
    }
    out
}

fn terminal_page(method: &Method, status: StatusCode, mode: Option<&str>, msg: Option<&str>) -> Response<Body> {
    let is_head = method == Method::HEAD;
    let mut parts: Vec<String> = Vec::new();
    if let Some(m) = msg  { parts.push(format!("\"message\":\"{}\"", js_escape(m))); }
    if let Some(m) = mode { parts.push(format!("\"mode\":\"{}\"",    js_escape(m))); }

    let body_bytes: Vec<u8> = if parts.is_empty() {
        TERMINAL_HTML.as_bytes().to_vec()
    } else {
        let inject = format!(
            "<script>window.__TERMINAL_BOOTSTRAP__={{{}}};</script></head>",
            parts.join(",")
        );
        TERMINAL_HTML.replacen("</head>", &inject, 1).into_bytes()
    };

    let body = if is_head { Body::empty() } else { Body::from(body_bytes.clone()) };
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CONTENT_LENGTH, body_bytes.len())
        .header(header::CACHE_CONTROL, "no-cache, must-revalidate")
        .body(body)
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn terminal_response(method: &Method) -> Response<Body> {
    terminal_page(method, StatusCode::OK, None, None)
}

fn terminal_response_status(method: &Method, status: StatusCode, msg: Option<&str>) -> Response<Body> {
    terminal_page(method, status, None, msg)
}

fn terminal_response_admin_login(method: &Method) -> Response<Body> {
    terminal_page(method, StatusCode::OK, None, None)
}


fn static_asset(name: &str) -> Option<(&'static str, &'static str)> {
    let base = name
        .strip_suffix(".js").or_else(|| name.strip_suffix(".css"))
        .or_else(|| name.strip_suffix(".html"))
        .unwrap_or(name);
    Some(match base {
        // ── Admin panel ──
        "admin/style"      => (ADMIN_ASSET_STYLE,      "text/css; charset=utf-8"),
        "admin/app"        => (ADMIN_ASSET_APP,        "text/javascript; charset=utf-8"),
        "admin/dashboard"  => (ADMIN_ASSET_DASHBOARD,  "text/javascript; charset=utf-8"),
        "admin/files"      => (ADMIN_ASSET_FILES,      "text/javascript; charset=utf-8"),
        "admin/dns"        => (ADMIN_ASSET_DNS,        "text/javascript; charset=utf-8"),
        "admin/ssl"        => (ADMIN_ASSET_SSL,        "text/javascript; charset=utf-8"),
        "admin/proxy"      => (ADMIN_ASSET_PROXY,      "text/javascript; charset=utf-8"),
        "admin/settings"   => (ADMIN_ASSET_SETTINGS,   "text/javascript; charset=utf-8"),
        "admin/db"         => (ADMIN_ASSET_DB,         "text/javascript; charset=utf-8"),
        "admin/vpn"        => (ADMIN_ASSET_VPN,        "text/javascript; charset=utf-8"),
        "admin/modules"    => (ADMIN_ASSET_MODULES,    "text/javascript; charset=utf-8"), 
        // ── Terminal ──
        "terminal/style"   => (TERMINAL_ASSET_STYLE,   "text/css; charset=utf-8"),
        "terminal/app"     => (TERMINAL_ASSET_APP,     "text/javascript; charset=utf-8"),
        "terminal/state"   => (TERMINAL_ASSET_STATE,   "text/javascript; charset=utf-8"),
        "terminal/utils"   => (TERMINAL_ASSET_UTILS,   "text/javascript; charset=utf-8"),
        "terminal/api"     => (TERMINAL_ASSET_API,     "text/javascript; charset=utf-8"),
        "terminal/views"   => (TERMINAL_ASSET_VIEWS,   "text/javascript; charset=utf-8"),
        "terminal/console" => (TERMINAL_ASSET_CONSOLE, "text/javascript; charset=utf-8"),
        "terminal/hack"    => (TERMINAL_ASSET_HACK,    "text/javascript; charset=utf-8"),
        "terminal/leak"    => (TERMINAL_ASSET_LEAK,    "text/javascript; charset=utf-8"),
        "terminal/ui"      => (TERMINAL_ASSET_UI,      "text/javascript; charset=utf-8"),
        _ => return None,
    })
}

// ACME HTTP-01: токен хранится в БД (config key `acme_challenge_<token>`), отдаём из БД — без записи на диск.
async fn serve_acme_challenge(state: SharedState, token: String) -> Response<Body> {
    let Some(db) = state.read().unwrap().db.clone() else {
        return Response::builder().status(StatusCode::NOT_FOUND).body(Body::empty()).unwrap_or_else(|_| Response::new(Body::empty()));
    };
    let key = format!("acme_challenge_{token}");
    let value = db.config_map().await.ok()
        .and_then(|m| m.get(&key).cloned())
        .unwrap_or_default();
    if value.is_empty() {
        return Response::builder().status(StatusCode::NOT_FOUND).body(Body::empty()).unwrap_or_else(|_| Response::new(Body::empty()));
    }
    Response::builder().status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(value))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

async fn serve_static(
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response<Body> {
    let (content, mime) = match static_asset(&name) {
        Some(x) => x,
        None => return text_response(StatusCode::NOT_FOUND, "asset not found"),
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, "public, max-age=60, must-revalidate")
        .body(Body::from(content))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

async fn serve_module_asset(axum::extract::Path(name): axum::extract::Path<String>) -> Response<Body> {
    let mut parts = name.splitn(2, '/');
    let id = parts.next().unwrap_or("");
    let rel = parts.next().unwrap_or("");
    let valid = !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !valid || rel.is_empty() || rel.split('/').any(|p| p == ".." || p.is_empty()) {
        return text_response(StatusCode::BAD_REQUEST, "invalid module asset path");
    }
    let base = PathBuf::from("./modules/installed").join(id);
    let path = base.join(rel);
    let Ok(canonical_base) = base.canonicalize() else { return text_response(StatusCode::NOT_FOUND, "module asset not found"); };
    let Ok(canonical) = path.canonicalize() else { return text_response(StatusCode::NOT_FOUND, "module asset not found"); };
    if !canonical.starts_with(&canonical_base) || !canonical.is_file() { return text_response(StatusCode::NOT_FOUND, "module asset not found"); }
    let data = match tokio::fs::read(&canonical).await { Ok(v) => v, Err(_) => return text_response(StatusCode::NOT_FOUND, "module asset not found") };
    let mime = mime_guess::from_path(&canonical).first_or_octet_stream().essence_str().to_string();
    Response::builder().status(StatusCode::OK).header(header::CONTENT_TYPE, mime).header(header::CACHE_CONTROL, "no-cache").body(Body::from(data)).unwrap_or_else(|_| Response::new(Body::empty()))
}
fn decode_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' { out.push(b' '); i += 1; }
        else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(a), Some(b)) = ((bytes[i+1] as char).to_digit(16), (bytes[i+2] as char).to_digit(16)) {
                out.push((a * 16 + b) as u8); i += 3;
            } else { out.push(bytes[i]); i += 1; }
        } else { out.push(bytes[i]); i += 1; }
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn start_h3_server(router: Router, resolver: Arc<ssl::SslManager>, port: u16) -> Result<(), Box<dyn Error>> {
    let mut tls_config = rustls::ServerConfig::builder().with_no_client_auth().with_cert_resolver(resolver);
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    tls_config.max_early_data_size = u32::MAX;
    let quic_config = QuicServerConfig::try_from(tls_config)?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
    let addr: SocketAddr = format!("0.0.0.0:{port}").parse()?;
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    println!("[HTTP/3] QUIC listener started on udp://{}", addr);
    while let Some(incoming) = endpoint.accept().await {
        let app = router.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_h3_connection(incoming, app).await { eprintln!("[HTTP/3] Connection error: {}", e); }
        });
    }
    Ok(())
}

async fn handle_h3_connection(incoming: quinn::Incoming, app: Router) -> Result<(), Box<dyn Error + Send + Sync>> {
    let conn = incoming.await?;
    let h3_conn = h3::server::builder().build(h3_quinn::Connection::new(conn)).await?;
    tokio::pin!(h3_conn);
    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let app = app.clone();
                tokio::spawn(async move {
                    if let Err(e) = h3_axum::serve_h3_with_axum(app, resolver).await {
                        eprintln!("[HTTP/3] Request error: {}", e);
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                if !h3_axum::is_graceful_h3_close(&e) { eprintln!("[HTTP/3] Connection error: {:?}", e); }
                break;
            }
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Multiplex 443/UDP — h3 сайтов + Miraj (Hysteria2) на одном endpoint'е
// ═══════════════════════════════════════════════════════════════════════════

fn build_multiplexed_quic_config(resolver: Arc<ssl::SslManager>, miraj_cfg: Option<&miraj::MirajConfig>) -> Result<quinn::ServerConfig, Box<dyn Error + Send + Sync>> {
    let mut tls = rustls::ServerConfig::builder().with_no_client_auth().with_cert_resolver(resolver);
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = u32::MAX;
    let quic_crypto = QuicServerConfig::try_from(tls).map_err(|e| format!("quic server config: {e}"))?;
    let mut transport = quinn::TransportConfig::default();
    if let Some(m) = miraj_cfg {
        transport.keep_alive_interval(Some(m.keepalive_interval));
        transport.max_idle_timeout(Some(quinn::IdleTimeout::try_from(m.idle_timeout).map_err(|e| format!("idle timeout: {e}"))?));
        transport.stream_receive_window(quinn::VarInt::from_u64(m.stream_window).unwrap_or(quinn::VarInt::MAX));
        transport.receive_window(quinn::VarInt::from_u64(m.conn_window).unwrap_or(quinn::VarInt::MAX));
        transport.datagram_receive_buffer_size(Some(m.max_datagram_buf));
        transport.datagram_send_buffer_size(m.max_datagram_buf);
        if m.brutal_tx > 0 {
            transport.congestion_controller_factory(Arc::new(miraj::BrutalFactory { rate: Arc::new(AtomicU64::new(m.brutal_tx)) }));
            println!("[MULTIPLEX] Brutal CC @ {} B/s", m.brutal_tx);
        } else {
            transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
            println!("[MULTIPLEX] BBR CC");
        }
    } else {
        println!("[MULTIPLEX] only h3, default quinn transport");
    }
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
}

async fn start_multiplexed_quic(addr: SocketAddr, server_config: quinn::ServerConfig, axum_app: Router, miraj_cfg: Option<Arc<miraj::MirajConfig>>, shutdown: CancellationToken) -> Result<(), Box<dyn Error + Send + Sync>> {
    let endpoint = quinn::Endpoint::server(server_config, addr).map_err(|e| format!("bind {}: {e}", addr))?;
    println!("[MULTIPLEX] QUIC listener on udp://{}", addr);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accept = endpoint.accept() => match accept {
                Some(incoming) => {
                    let app = axum_app.clone();
                    let mcfg = miraj_cfg.clone();
                    tokio::spawn(async move {
                        match incoming.await {
                            Ok(conn) => handle_multiplexed_conn(conn, app, mcfg).await,
                            Err(e) => eprintln!("[MULTIPLEX] handshake failed: {e}"),
                        }
                    });
                }
                None => break,
            }
        }
    }
    endpoint.close(0u32.into(), b"shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(5), endpoint.wait_idle()).await;
    println!("[MULTIPLEX] stopped");
    Ok(())
}

async fn handle_multiplexed_conn(conn: quinn::Connection, app: Router, miraj_cfg: Option<Arc<miraj::MirajConfig>>) {
    let h3_conn = H3Connection::new(conn.clone());
    let mut h3_server = match h3::server::Connection::new(h3_conn).await {
        Ok(s) => s,
        Err(e) => { eprintln!("[MULTIPLEX] h3 handshake failed: {e}"); return; }
    };
    loop {
        let resolver = match h3_server.accept().await {
            Ok(Some(r)) => r,
            Ok(None) => return,
            Err(e) => { eprintln!("[MULTIPLEX] h3 accept closed: {e}"); return; }
        };
        let (req, stream) = match resolver.resolve_request().await { Ok(p) => p, Err(_) => continue };
        if let Some(mcfg) = &miraj_cfg {
            if miraj::is_hysteria_auth(&req) {
                match miraj::handle_auth(stream, req, mcfg.as_ref(), conn.remote_address().ip()).await {
                    Ok(miraj::AuthResult::Ok { user_id, user_name }) => {
                        miraj::handle_authorized_connection(conn, h3_server, mcfg.clone(), user_id, user_name).await;
                        return;
                    }
                    _ => return,
                }
            }
        }
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_h3_axum_request(app, req, stream).await {
                eprintln!("[MULTIPLEX] h3 request error: {e}");
            }
        });
    }
}

async fn serve_h3_axum_request(app: Router, req: http::Request<()>, mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (parts, _) = req.into_parts();
    let mut body_buf = bytes::BytesMut::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        use bytes::Buf;
        while chunk.has_remaining() {
            let cb = chunk.chunk().to_vec();
            body_buf.extend_from_slice(&cb);
            chunk.advance(cb.len());
        }
    }
    let axum_req = axum::http::Request::from_parts(parts, axum::body::Body::from(body_buf.freeze()));
    let resp = app.oneshot(axum_req).await?;
    let (resp_parts, resp_body) = resp.into_parts();
    stream.send_response(axum::http::Response::from_parts(resp_parts, ())).await?;
    let mut data_stream = resp_body.into_data_stream();
    while let Some(chunk) = data_stream.next().await {
        match chunk {
            Ok(data) if !data.is_empty() => stream.send_data(data).await?,
            Ok(_) => {},
            Err(_) => break,
        }
    }
    stream.finish().await?;
    Ok(())
}

async fn setup_ips_logging() {
    let enabled = std::env::var("OMNIRS_IPS_LOG_PACKETS").map(|v| !(v == "0" || v == "false" || v == "off")).unwrap_or(true);
    if !enabled { println!("[IPS] iptables LOG отключён (OMNIRS_IPS_LOG_PACKETS=0)"); return; }
    let has_log = tokio::process::Command::new("iptables").args(["-C", "INPUT", "-m", "limit", "--limit", "30/min", "-j", "LOG", "--log-prefix", "OMNIRS: "]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().await.map(|s| s.success()).unwrap_or(false);
    if has_log { println!("[IPS] iptables LOG уже установлен"); }
    else {
        match tokio::process::Command::new("iptables").args(["-A", "INPUT", "-m", "limit", "--limit", "30/min", "-j", "LOG", "--log-prefix", "OMNIRS: ", "--log-level", "4"]).status().await {
            Ok(s) if s.success() => println!("[IPS] iptables LOG включён (30/мин, INPUT)"),
            _ => eprintln!("[IPS] iptables LOG не включён (нет прав root или iptables)"),
        }
    }
    let has_invalid = tokio::process::Command::new("iptables").args(["-C", "INPUT", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().await.map(|s| s.success()).unwrap_or(false);
    if !has_invalid { let _ = tokio::process::Command::new("iptables").args(["-A", "INPUT", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"]).status().await; }
    let has_synlog = tokio::process::Command::new("iptables").args(["-C", "INPUT", "-p", "tcp", "--syn", "-m", "connlimit", "--connlimit-above", "200", "--connlimit-mask", "32", "-j", "LOG", "--log-prefix", "OMNIRS: synflood "]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().await.map(|s| s.success()).unwrap_or(false);
    if !has_synlog {
        let _ = tokio::process::Command::new("iptables").args(["-A", "INPUT", "-p", "tcp", "--syn", "-m", "connlimit", "--connlimit-above", "200", "--connlimit-mask", "32", "-j", "LOG", "--log-prefix", "OMNIRS: synflood "]).status().await;
        let _ = tokio::process::Command::new("iptables").args(["-A", "INPUT", "-p", "tcp", "--syn", "-m", "connlimit", "--connlimit-above", "200", "--connlimit-mask", "32", "-j", "DROP"]).status().await;
    }
}

pub async fn start_omnirs(config: Config) -> Result<(), Box<dyn Error>> {
    config.validate()?;
    let ports_to_open: Vec<u16> = vec![80, 443, 53, 853, 1000];    // ← :800 больше не нужен
    auto_open_ports(&ports_to_open).await;
    setup_ips_logging().await;
    let request_timeout_secs = config.request_timeout_secs;
    let app_state = AppState::new(config).await?;
    let state: SharedState = Arc::new(RwLock::new(Arc::new(app_state)));
    let current_state = state.read().unwrap().clone();
init_tunnel().await;
    let mut vpn_cfg = current_state.config.vpn.clone();
    if vpn_cfg.acme_ip.is_none() { vpn_cfg.acme_ip = current_state.config.acme_ip.clone(); }
    if let Err(e) = vpn::startup(&vpn_cfg).await { eprintln!("[VPN] startup failed: {e}"); }
    vpn::start_cron();

    let cert_resolver = match &current_state.ssl {
        Some(m) => m.clone(),
        None => return Err("SSL manager missing".into()),
    };


// ── IKEv2 (добавить рядом с Miraj и Tunnel)
let ikev2_cfg = ikev2::Ikev2Config {
    enabled: current_state.config.ikev2_enabled,
    listen_addr: current_state.config.ikev2_listen.clone(),
    psk: current_state.config.ikev2_psk.clone(),
    local_id: current_state.config.ikev2_local_id.clone(),
    remote_id: current_state.config.ikev2_remote_id.clone(),
};
if ikev2_cfg.enabled {
    let ikev2_shutdown = CancellationToken::new();
    tokio::spawn(async move {
        if let Err(e) = ikev2::start_server(ikev2_cfg, ikev2_shutdown).await {
            tracing::error!("[IKEv2] server error: {e}");
        }
    });
}
  
    // ── Miraj: конфиг (используется в multiplex и/или standalone)
    let miraj_loaded: Option<Arc<miraj::MirajConfig>> = match db::global() {
        Some(db) => match db.config_map().await {
            Ok(map) => {
                let m = miraj::MirajConfig::from_map(&map);
                if m.enabled { Some(Arc::new(m)) } else { None }
            }
            Err(e) => { tracing::warn!("miraj: cannot load config: {e}"); None }
        },
        None => None,
    };
  
if let Some(m) = &miraj_loaded {
    let cfg = (**m).clone();
    let resolver = cert_resolver.clone();
    let miraj_shutdown = CancellationToken::new();
    tokio::spawn(async move {
        if let Err(e) = miraj::run(cfg, resolver, miraj_shutdown).await {
            tracing::error!("miraj: server error: {e}");
        }
    });
}
  
      
// ── Tunnel WebTransport на :808/UDP — для UDP (WireGuard)
{
    let resolver = cert_resolver.clone();
    tokio::spawn(async move {
        if let Err(e) = run_webtransport_tunnel(resolver).await {
            eprintln!("[TUNNEL] webtransport server error: {e}");
        }
    });
}
    // ── DNS-over-TLS / DNS-over-QUIC
    if let Some(dns) = current_state.dns.clone() {
        let dns_cfg = dns.config.clone();
        if !dns_cfg.dot_addr.is_empty() {
            let dns_clone = dns.clone();
            let addr = dns_cfg.dot_addr.clone();
            let res = cert_resolver.clone();
            tokio::spawn(async move { if let Err(e) = dns::start_dot_server(dns_clone, res, &addr).await { eprintln!("[DNS] DoT error: {}", e); } });
        }
        if !dns_cfg.doq_addr.is_empty() {
            let dns_clone = dns.clone();
            let addr = dns_cfg.doq_addr.clone();
            let res = cert_resolver.clone();
            tokio::spawn(async move { if let Err(e) = dns::start_doq_server(dns_clone, res, &addr).await { eprintln!("[DNS] DoQ error: {}", e); } });
        }
    }

    // ── ACME (единый цикл: и первичный выпуск, и продление — без рестарта)
ssl::spawn_renewal_loop(current_state.config.acme_mode, cert_resolver.clone());
    crate::generated_modules::start(state.clone()).await;
  
    // ── Routers
    let app = Router::new()
      .route("/static/{*name}", axum::routing::get(serve_static))
      .route("/module-assets/{*name}", axum::routing::get(serve_module_asset))
      .fallback(handle)
      .route("/tunnel", axum::routing::any(handle_tunnel_ws))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state.clone(), omni_mw::cors_mw))
        .layer(middleware::from_fn_with_state(state.clone(), omni_mw::access_log))
        .layer(CompressionLayer::new())
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(request_timeout_secs)));

    let http_redirect_app = Router::new()
        .fallback(handle_http_with_redirect)
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state.clone(), omni_mw::cors_mw))
        .layer(CompressionLayer::new())
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(request_timeout_secs)));

    let handle_axum = Handle::new();
    let has_certs = !cert_resolver.certs.read().unwrap().is_empty() || cert_resolver.default_cert.read().unwrap().is_some();
    let needs_http = matches!(current_state.config.acme_mode, ssl::AcmeMode::Http | ssl::AcmeMode::All) || !has_certs;

    let requested_ip: IpAddr = parse_bind_ip(&current_state.config.address).map_err(|e| -> Box<dyn Error> { e.into() })?;
    let bind_ip: IpAddr = if is_local_ip(requested_ip) {
        requested_ip
    } else {
        let unspecified = match requested_ip {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        };
        eprintln!("[BIND] WARN: {} не назначен интерфейсу (cloudNAT) — назначен {}; acme_ip остаётся {} для сертификата", requested_ip, unspecified, requested_ip);
        unspecified
    };
    let addr_443 = SocketAddr::new(bind_ip, 443);
    let addr_80 = SocketAddr::new(bind_ip, 80);
    println!("[BIND] requested {} → actual bind {} (:80, :443)", requested_ip, bind_ip);

    let ips_for_ssh = current_state.ips.clone();
    let ssh_whitelist: Vec<String> = std::env::var("OMNIRS_SSH_WHITELIST")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !ssh_whitelist.is_empty() { println!("[IPS] SSH whitelist: {:?}", ssh_whitelist); }
    security::start_monitors(ips_for_ssh, ssh_whitelist);

    if has_certs {
        let h3_port = current_state.config.h3_port.unwrap_or(443);

        // ── Multiplex 443/UDP — h3 сайтов + Miraj (если оба на 443)
        let miraj_multiplex: Option<Arc<miraj::MirajConfig>> = miraj_loaded.as_ref()
            .filter(|m| m.listen.port() == 443)
            .cloned();
        if h3_port == 443 || miraj_multiplex.is_some() {
            let multiplex_config = match build_multiplexed_quic_config(cert_resolver.clone(), miraj_multiplex.as_deref()) {
                Ok(c) => c,
                Err(e) => { eprintln!("[MULTIPLEX] build config failed: {e}"); return Err(e); }
            };
            let multiplex_app = app.clone();
            let multiplex_shutdown = CancellationToken::new();
            let miraj_present = miraj_multiplex.is_some();
            tokio::spawn(async move {
                if let Err(e) = start_multiplexed_quic(SocketAddr::new(bind_ip, 443), multiplex_config, multiplex_app, miraj_multiplex, multiplex_shutdown).await {
                    eprintln!("[MULTIPLEX] server error: {}", e);
                }
            });
            if miraj_present { println!("[MULTIPLEX] :443/UDP — h3 сайтов + Miraj (Hysteria2)"); }
            else { println!("[MULTIPLEX] :443/UDP — только h3 сайтов"); }
        } else if h3_port > 0 {
            let h3_router = app.clone();
            let h3_resolver = cert_resolver.clone();
            tokio::spawn(async move {
                if let Err(e) = start_h3_server(h3_router, h3_resolver, h3_port).await { eprintln!("[HTTP/3] server error: {}", e); }
            });
            println!("[HTTP/3] QUIC listener on udp://0.0.0.0:{}", h3_port);
        }

        // ── HTTP :80 (redirect + ACME)
        if needs_http {
            let app_http = http_redirect_app.clone();
            let handle_http = handle_axum.clone();
            tokio::spawn(async move {
                if let Err(e) = axum_server::bind(addr_80).handle(handle_http)
                    .serve(app_http.into_make_service_with_connect_info::<SocketAddr>()).await {
                    eprintln!("[HTTP :80] server error: {}", e);
                }
            });
            println!("[HTTP :80] ACME + redirect listener started");
        } else {
            println!("[HTTP :80] Listener disabled (acme_mode = tls)");
        }

        // ── HTTPS :443 (h2/http1.1) — единственный вход для сайта+админки+API
        let mut tls_cfg = rustls::ServerConfig::builder().with_no_client_auth().with_cert_resolver(cert_resolver.clone());
        tls_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"acme-tls/1".to_vec()];
        let rustls_config = RustlsConfig::from_config(Arc::new(tls_cfg));

        let display_ip: IpAddr = if bind_ip.is_unspecified() {
            current_state.config.acme_ip.as_deref().and_then(|s| s.parse::<IpAddr>().ok()).filter(|ip| !ip.is_unspecified()).unwrap_or(requested_ip)
        } else { bind_ip };
        let _display_host = match display_ip { IpAddr::V4(v4) => v4.to_string(), IpAddr::V6(v6) => format!("[{}]", v6) };
        println!("[HTTP :443] HTTPS listener (h2/http/1.1/acme-tls/1) — admin + site + proxy + API");
        println!("[OmniRS] All systems initialized. Press Ctrl+C to stop.");

        tokio::select! {
            res = axum_server::bind_rustls(addr_443, rustls_config).handle(handle_axum.clone())
                .serve(app.into_make_service_with_connect_info::<SocketAddr>()) => {
                if let Err(e) = res { eprintln!("[HTTP :443] Server error: {}", e); }
            }
            _ = tokio::signal::ctrl_c() => {
                println!("[OmniRS] Shutting down gracefully...");
                vpn::shutdown().await;
            }
        }
    } else {
        // Нет сертификатов — только plain HTTP на :80 (ACME выпустит и перезапустит)
        println!("[HTTP :80] No certificates, ACME disabled — plain HTTP on 0.0.0.0:80");
        println!("[OmniRS] All systems initialized. Press Ctrl+C to stop.");
        tokio::select! {
            res = axum_server::bind(addr_80).handle(handle_axum.clone())
                .serve(app.into_make_service_with_connect_info::<SocketAddr>()) => {
                if let Err(e) = res { eprintln!("[HTTP :80] Server error: {}", e); }
            }
            _ = tokio::signal::ctrl_c() => {
                println!("[OmniRS] Shutting down gracefully...");
                vpn::shutdown().await;
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,miraj=debug")),
        )
        .with_writer(std::io::stderr)
        .init();

    rustls::crypto::ring::default_provider().install_default().expect("Failed to install rustls crypto provider");

    let all_args: Vec<String> = std::env::args().collect();
    if all_args.get(1).map(|s| s.as_str()) == Some("installer") {
        let code = installer::run_installer(&all_args[2..]);
        std::process::exit(code);
    }
    if all_args.len() > 1 && all_args[1] == "config" && all_args.get(2).map(|s| s.as_str()) == Some("test") {
        if let Err(e) = db::init_global().await { eprintln!("Failed to initialize database: {}", e); std::process::exit(1); }
        match Config::load().await {
            Ok(cfg) => {
                if let Err(e) = cfg.validate() { eprintln!("Configuration is invalid: {}", e); std::process::exit(1); }
                println!("Configuration (from DB) is valid. Syntax OK.");
                std::process::exit(0);
            }
            Err(e) => { eprintln!("Failed to load configuration from DB: {}", e); std::process::exit(1); }
        }
    }

    if let Err(e) = db::init_global().await { return Err(format!("db::init_global failed: {e}").into()); }
    let config = Config::load().await?;
    start_omnirs(config).await
}

// ═══════════════════════════════════════════════════════════════════════════
// TUNNEL: встроен в :443/TCP через WS + отдельный :808/UDP для WebTransport
// ═══════════════════════════════════════════════════════════════════════════

struct TunnelState {
    server: std::sync::Arc<tunnel::TunnelServer<tunnel::executor::DefaultTokioExecutor>>,
    restrictions: std::sync::Arc<tunnel::restrictions::RestrictionsRules>,
    path_prefixes: Vec<String>,
}

static TUNNEL_STATE: std::sync::OnceLock<Option<TunnelState>> = std::sync::OnceLock::new();

async fn init_tunnel() {
    let result: Option<TunnelState> = (|| async {
        let db = db::global()?;
        let map = db.config_map().await.ok()?;
        let enabled = map
            .get("tunnel.enabled")
            .map(|v| matches!(v.as_str(), "true" | "1" | "yes" | "on"))
            .unwrap_or(false);
        if !enabled {
            println!("[TUNNEL] disabled (tunnel.enabled != true)");
            return None;
        }

        let path_prefixes: Vec<String> = map
            .get("tunnel.path_prefix")
            .cloned()
            .unwrap_or_else(|| "v1".into())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if path_prefixes.is_empty() {
            eprintln!("[TUNNEL] tunnel.path_prefix пуст — отказ");
            return None;
        }

        let allow_raw = map.get("tunnel.allow_targets").cloned().unwrap_or_default();
        let restrict_to: Vec<(String, u16)> = allow_raw
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter_map(|s| {
                let (host, port) = s.rsplit_once(':')?;
                let host = host.trim_matches(['[', ']']).to_string();
                let port = port.parse::<u16>().ok()?;
                Some((host, port))
            })
            .collect();
        if restrict_to.is_empty() {
            eprintln!("[TUNNEL] tunnel.allow_targets пуст — отказ (был бы открытый прокси)");
            return None;
        }

        let restrictions = match tunnel::restrictions::RestrictionsRules::from_path_prefix(
            &path_prefixes,
            &restrict_to,
        ) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[TUNNEL] from_path_prefix: {e}");
                return None;
            }
        };

        let dns_resolver = match tunnel::protocols::dns::DnsResolver::new_from_urls(
            &[],
            None,
            tunnel::somark::SoMark::new(None),
            true,
        ) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[TUNNEL] dns resolver: {e}");
                return None;
            }
        };

        let server = std::sync::Arc::new(tunnel::TunnelServer::new(
            tunnel::TunnelServerConfig {
                socket_so_mark: tunnel::somark::SoMark::new(None),
                bind: "127.0.0.1:0".parse().ok()?,   // dummy для WS-режима
                websocket_ping_frequency: Some(std::time::Duration::from_secs(30)),
                timeout_connect: std::time::Duration::from_secs(10),
                websocket_mask_frame: false,
                tls: None,
                dns_resolver: dns_resolver.clone(),
                restriction_config: None,
                http_proxy: None,
                remote_server_idle_timeout: std::time::Duration::from_secs(60),
                enable_webtransport: false,          // WS на :443 обрабатывается снаружи
            },
            tunnel::executor::DefaultTokioExecutor::default(),
        ));

        println!(
            "[TUNNEL] ready — WS /tunnel на :443, prefixes {:?}, allow: {}",
            path_prefixes,
            restrict_to
                .iter()
                .map(|(h, p)| format!("{h}:{p}"))
                .collect::<Vec<_>>()
                .join(", ")
        );

        Some(TunnelState {
            server,
            restrictions: std::sync::Arc::new(restrictions),
            path_prefixes,
        })
    })()
    .await;

    let _ = TUNNEL_STATE.set(result);
}

async fn handle_tunnel_ws(mut req: Request<Body>) -> Response<Body> {
    let ts = match TUNNEL_STATE.get().and_then(|x| x.as_ref()) {
        Some(s) => s,
        None => return text_response(StatusCode::NOT_FOUND, "tunnel disabled"),
    };

    if !fastwebsockets::upgrade::is_upgrade_request(&req) {
        return text_response(StatusCode::BAD_REQUEST, "websocket upgrade required");
    }

    // ── Парсим путь /tunnel/<prefix>/events (tunnel.rs ждёт /<prefix>/events)
    let path_str = req.uri().path().to_string();
    let inner_path = path_str
        .strip_prefix("/tunnel")
        .unwrap_or(&path_str)
        .to_string();
    if !inner_path.starts_with('/') || !inner_path.ends_with("/events") {
        return text_response(StatusCode::BAD_REQUEST, "bad path");
    }
    let path_prefix = match inner_path.strip_prefix('/').and_then(|s| s.split('/').next()) {
        Some(p) if !p.is_empty() => p.to_string(),
        _ => return text_response(StatusCode::BAD_REQUEST, "missing path prefix"),
    };
    if !ts.path_prefixes.iter().any(|p| p == &path_prefix) {
        return text_response(StatusCode::NOT_FOUND, "unknown path prefix");
    }

    // ── Проверяем, что протокол `v1` (tunnel_to_jwt_token кладёт его в Sec-WebSocket-Protocol)
    let has_v1 = req
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .map_or(false, |v| v.split(',').any(|s| s.trim().starts_with("v1")));
    if !has_v1 {
        return text_response(StatusCode::BAD_REQUEST, "sec-websocket-protocol v1 required");
    }

    // ── Ключ для ответа Sec-WebSocket-Accept
    let key = match req
        .headers()
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
    {
        Some(k) => k.to_string(),
        None => return text_response(StatusCode::BAD_REQUEST, "missing sec-websocket-key"),
    };

    // ── on_upgrade ДО того как into_parts() съест req
    let on_upgrade = hyper::upgrade::on(&mut req);

    // ── Пересобираем запрос с подменённым URI и пустым телом
    let (mut parts, _body) = req.into_parts();
    parts.uri = match inner_path.parse::<axum::http::Uri>() {
        Ok(u) => u,
        Err(_) => return text_response(StatusCode::BAD_REQUEST, "bad uri"),
    };
    let tunnel_req = Request::from_parts(parts, ());

    let client_addr = tunnel_req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0)
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));

    let (remote_addr, local_rx, local_tx, _need_cookie) = match ts
        .server
        .handle_tunnel_request(
            ts.restrictions.clone(),
            Some(path_prefix.clone()),
            client_addr,
            tunnel_req,
        )
        .await
    {
        Ok(v) => v,
        Err(resp) => {
            eprintln!("[TUNNEL] reject {}: {}", client_addr, resp.status());
            return text_response(resp.status(), "tunnel rejected");
        }
    };

    println!(
        "[TUNNEL] {} → {}:{}",
        client_addr, remote_addr.host, remote_addr.port
    );

    // ── Sec-WebSocket-Accept = base64(sha1(key || magic))
    let accept = {
        use base64::Engine;
        const MAGIC: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        let mut h = sha1::Sha1::new();
        use sha1::Digest;
        h.update(key.as_bytes());
        h.update(MAGIC.as_bytes());
        base64::engine::general_purpose::STANDARD.encode(h.finalize())
    };

    tokio::spawn(tunnel_ws_worker(on_upgrade, local_rx, local_tx));

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "Upgrade")
        .header("sec-websocket-accept", accept)
        .header("sec-websocket-protocol", "v1")
        .body(Body::empty())
        .unwrap()
}

async fn tunnel_ws_worker(
    on_upgrade: hyper::upgrade::OnUpgrade,
    mut local_rx: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>,
    mut local_tx: std::pin::Pin<Box<dyn tokio::io::AsyncWrite + Send>>,
) {
    let upgraded = match on_upgrade.await {
        Ok(u) => u,
        Err(e) => {
            eprintln!("[TUNNEL] upgrade error: {e}");
            return;
        }
    };

    let io = hyper_util::rt::TokioIo::new(upgraded);
    let mut ws = fastwebsockets::WebSocket::after_handshake(io, fastwebsockets::Role::Server);
    ws.set_auto_close(false);
    ws.set_auto_pong(true);
    ws.set_auto_apply_mask(false);

    let (mut ws_rx, ws_tx_raw) = ws.split(|x| tokio::io::split(x));
    let ws_tx = std::sync::Arc::new(tokio::sync::Mutex::new(ws_tx_raw));
    let mut frame_reader =
        |_: fastwebsockets::Frame<'_>| futures_util::future::ready(anyhow::Ok(()));

    let up = async {
        loop {
            let frame = match ws_rx.read_frame(&mut frame_reader).await {
                Ok(f) => f,
                Err(_) => break,
            };
            match frame.opcode {
                fastwebsockets::OpCode::Binary
                | fastwebsockets::OpCode::Continuation
                | fastwebsockets::OpCode::Text => {
                    if local_tx.write_all(frame.payload.as_ref()).await.is_err() {
                        break;
                    }
                }
                fastwebsockets::OpCode::Close => {
                    let _ = ws_tx
                        .lock()
                        .await
                        .write_frame(fastwebsockets::Frame::close(1000, &[]))
                        .await;
                    let _ = ws_tx.lock().await.flush().await;
                    break;
                }
                _ => {}
            }
        }
        let _ = local_tx.shutdown().await;
    };

    let down = async {
        let mut buf = [0u8; 65536];
        loop {
            let n = match local_rx.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let payload = fastwebsockets::Payload::Borrowed(&buf[..n]);
            if ws_tx
                .lock()
                .await
                .write_frame(fastwebsockets::Frame::binary(payload))
                .await
                .is_err()
            {
                break;
            }
            if ws_tx.lock().await.flush().await.is_err() {
                break;
            }
        }
        let _ = ws_tx
            .lock()
            .await
            .write_frame(fastwebsockets::Frame::close(1000, &[]))
            .await;
        let _ = ws_tx.lock().await.flush().await;
    };

    tokio::select! {
        _ = up => {},
        _ = down => {},
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// WebTransport tunnel на 0.0.0.0:808/UDP — только для UDP (WireGuard :888)
// ═══════════════════════════════════════════════════════════════════════════

async fn run_webtransport_tunnel(
    cert_resolver: std::sync::Arc<ssl::SslManager>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let db = db::global().ok_or("db not initialized")?;
    let map = db.config_map().await.map_err(|e| format!("{e}"))?;

    let enabled = map
        .get("tunnel.enabled")
        .map(|v| matches!(v.as_str(), "true" | "1" | "yes" | "on"))
        .unwrap_or(false);
    if !enabled {
        return Ok(());
    }

    let path_prefixes: Vec<String> = map
        .get("tunnel.path_prefix")
        .cloned()
        .unwrap_or_else(|| "v1".into())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if path_prefixes.is_empty() {
        return Ok(());
    }

    let allow_raw = map.get("tunnel.allow_targets").cloned().unwrap_or_default();
    let restrict_to: Vec<(String, u16)> = allow_raw
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| {
            let (host, port) = s.rsplit_once(':')?;
            let host = host.trim_matches(['[', ']']).to_string();
            let port = port.parse::<u16>().ok()?;
            Some((host, port))
        })
        .collect();
    if restrict_to.is_empty() {
        return Ok(());
    }

    let restrictions = tunnel::restrictions::RestrictionsRules::from_path_prefix(
        &path_prefixes,
        &restrict_to,
    )
    .map_err(|e| format!("{e}"))?;

    let dns_resolver = tunnel::protocols::dns::DnsResolver::new_from_urls(
        &[],
        None,
        tunnel::somark::SoMark::new(None),
        true,
    )
    .map_err(|e| format!("{e}"))?;

    // ── Сертификат и ключ: читаем из таблицы OmniSsl (первый домен / acme_ip)
    let (cert_pem, key_pem) = {
        let omni = {
            let conns = db.conns.read().await;
            conns
                .get("OmniDB")
                .cloned()
                .ok_or("OmniDB missing")?
        };
        let db::Pool::Sqlite(p) = &omni.pool;
        let p = p.clone();
        tokio::task::spawn_blocking(move || -> Result<(Vec<u8>, Vec<u8>), String> {
            let g = p.lock().map_err(|e| e.to_string())?;
            let row: Option<(String, String)> = g
                .query_row(
                    "SELECT cert_pem, key_pem FROM OmniSsl ORDER BY not_after DESC LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .ok();
            row.map(|(c, k)| (c.into_bytes(), k.into_bytes()))
                .ok_or_else(|| "OmniSsl: no certificates".to_string())
        })
        .await
        .map_err(|e| format!("{e}"))??
    };

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem.as_slice()))
            .filter_map(Result::ok)
            .collect();
    if certs.is_empty() {
        return Err("no certs parsed from OmniSsl.cert_pem".into());
    }
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut std::io::BufReader::new(key_pem.as_slice()))
            .map_err(|e| format!("key parse: {e}"))?
            .ok_or("no private key parsed from OmniSsl.key_pem")?;

    let _ = cert_resolver; // оставляем параметр, чтобы не менять сигнатуру в start_omnirs

    let bind: SocketAddr = "0.0.0.0:808".parse()?;

    let server = tunnel::TunnelServer::new(
        tunnel::TunnelServerConfig {
            socket_so_mark: tunnel::somark::SoMark::new(None),
            bind,
            websocket_ping_frequency: Some(std::time::Duration::from_secs(30)),
            timeout_connect: std::time::Duration::from_secs(10),
            websocket_mask_frame: false,
            tls: Some(tunnel::TunnelTlsServerConfig {
                tls_certificate: parking_lot::Mutex::new(certs),
                tls_key: parking_lot::Mutex::new(key),
                tls_client_ca_certificates: None,
                tls_certificate_path: None,
                tls_key_path: None,
                tls_client_ca_certs_path: None,
            }),
            dns_resolver,
            restriction_config: None,
            http_proxy: None,
            remote_server_idle_timeout: std::time::Duration::from_secs(60),
            enable_webtransport: true,
        },
        tunnel::executor::DefaultTokioExecutor::default(),
    );

    println!(
        "[TUNNEL] WebTransport UDP :808 — prefixes {:?}, allow UDP: {}",
        path_prefixes,
        restrict_to
            .iter()
            .map(|(h, p)| format!("{h}:{p}"))
            .collect::<Vec<_>>()
            .join(", ")
    );

    server
        .serve(restrictions)
        .await
        .map_err(|e| format!("{e}"))?;
    Ok(())
}