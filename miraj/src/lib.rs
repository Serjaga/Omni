use omni_db as db;
// src/miraj.rs — Hysteria2-совместимый сервер (QUIC + HTTP/3), единый файл.
use std::{any::Any, collections::HashMap, fmt, future::Future, io::{self, IoSliceMut}, net::{IpAddr, Ipv4Addr, SocketAddr}, pin::Pin, sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Arc, Mutex, OnceLock}, task::{Context, Poll}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use bytes::{BufMut, Bytes, BytesMut};
use h3::server::RequestStream;
use h3_quinn::Connection as H3Connection;
use quinn::{congestion::{BbrConfig, Controller, ControllerFactory}, crypto::rustls::QuicServerConfig, udp::{RecvMeta, Transmit}, AsyncUdpSocket, Connection, Endpoint, EndpointConfig, IdleTimeout, Runtime, ServerConfig as QuicServerConfigInner, TransportConfig, VarInt};
use quinn_proto::RttEstimator;
use rand::RngCore;
use rustls::server::ResolvesServerCert;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpStream, UdpSocket}, sync::{mpsc, oneshot}};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

// §1 КОНФИГУРАЦИЯ
#[derive(Clone, Debug)] pub struct MirajConfig { pub enabled: bool, pub listen: SocketAddr, pub auth_token: String, pub masquerade_url: Option<String>, pub udp_enabled: bool, pub brutal_tx: u64, pub obfs_password: String, pub gecko_enabled: bool, pub gecko_max_size: usize, pub idle_timeout: Duration, pub stream_window: u64, pub conn_window: u64, pub keepalive_interval: Duration, pub max_datagram_buf: usize, pub udp_idle_timeout: Duration, pub udp_max_sessions: usize, pub udp_defrag_timeout: Duration, pub udp_max_mtu: usize, pub auth_rate_per_min: u32 }
impl Default for MirajConfig { fn default() -> Self { Self { enabled: false, listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 808), auth_token: String::new(), masquerade_url: None, udp_enabled: true, brutal_tx: 0, obfs_password: String::new(), gecko_enabled: false, gecko_max_size: 1200, idle_timeout: Duration::from_secs(30), stream_window: 8 * 1024 * 1024, conn_window: 8 * 1024 * 1024 * 5 / 2, keepalive_interval: Duration::from_secs(10), max_datagram_buf: 1024 * 1024, udp_idle_timeout: Duration::from_secs(60), udp_max_sessions: 512, udp_defrag_timeout: Duration::from_secs(5), udp_max_mtu: 1450, auth_rate_per_min: 10 } } }
impl MirajConfig {
    pub fn from_map(m: &HashMap<String, String>) -> Self {
        let get = |k: &str| m.get(k).map(|s| s.trim_matches(|c: char| c == '"' || c == '\'').to_string());
        let b = |k: &str, d: bool| get(k).map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on")).unwrap_or(d);
        let n = |k: &str, d: u64| get(k).and_then(|v| v.parse().ok()).unwrap_or(d);
        let listen = get("miraj.listen").and_then(|s| s.parse::<SocketAddr>().ok()).unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 808));
        let auth_token = get("miraj.auth_token").filter(|s| !s.is_empty()).or_else(|| get("admin_token")).unwrap_or_default();
        Self { enabled: b("miraj.enabled", false), listen, auth_token, masquerade_url: get("miraj.masquerade_url").filter(|s| !s.is_empty()), udp_enabled: b("miraj.udp_enabled", true), brutal_tx: n("miraj.brutal_tx", 0), obfs_password: get("miraj.obfs_password").unwrap_or_default(), gecko_enabled: b("miraj.gecko_enabled", false), gecko_max_size: n("miraj.gecko_max_size", 1200) as usize, idle_timeout: Duration::from_secs(n("miraj.idle_timeout_secs", 30).max(5)), stream_window: n("miraj.stream_window", 8 * 1024 * 1024), conn_window: n("miraj.conn_window", 8 * 1024 * 1024 * 5 / 2), keepalive_interval: Duration::from_secs(n("miraj.keepalive_interval_secs", 10).max(1)), max_datagram_buf: n("miraj.max_datagram_buf", 1024 * 1024) as usize, udp_idle_timeout: Duration::from_secs(n("miraj.udp_idle_timeout_secs", 60).max(5)), udp_max_sessions: n("miraj.udp_max_sessions", 512).max(1) as usize, udp_defrag_timeout: Duration::from_secs(n("miraj.udp_defrag_timeout_secs", 5).max(1)), udp_max_mtu: n("miraj.udp_max_mtu", 1450).clamp(1200, 1500) as usize, auth_rate_per_min: n("miraj.auth_rate_per_min", 10).max(1) as u32 }
    }
}

// §2 МЕТРИКИ
pub struct MirajMetrics { pub connections_total: AtomicU64, pub connections_active: AtomicU64, pub auth_ok: AtomicU64, pub auth_fail: AtomicU64, pub tcp_streams_total: AtomicU64, pub udp_sessions_total: AtomicU64, pub tcp_bytes_up: AtomicU64, pub tcp_bytes_down: AtomicU64, pub udp_datagrams_in: AtomicU64, pub udp_datagrams_out: AtomicU64, pub masquerades: AtomicU64, pub errors_total: AtomicU64, pub udp_sessions_active: AtomicU64, pub udp_sessions_rejected: AtomicU64, pub udp_datagrams_dropped: AtomicU64, pub udp_datagrams_invalid: AtomicU64, pub auth_rate_limited: AtomicU64, pub tcp_connections_refused: AtomicU64, pub shutdown_initiated: AtomicU64 }
pub static METRICS: MirajMetrics = MirajMetrics { connections_total: AtomicU64::new(0), connections_active: AtomicU64::new(0), auth_ok: AtomicU64::new(0), auth_fail: AtomicU64::new(0), tcp_streams_total: AtomicU64::new(0), udp_sessions_total: AtomicU64::new(0), tcp_bytes_up: AtomicU64::new(0), tcp_bytes_down: AtomicU64::new(0), udp_datagrams_in: AtomicU64::new(0), udp_datagrams_out: AtomicU64::new(0), masquerades: AtomicU64::new(0), errors_total: AtomicU64::new(0), udp_sessions_active: AtomicU64::new(0), udp_sessions_rejected: AtomicU64::new(0), udp_datagrams_dropped: AtomicU64::new(0), udp_datagrams_invalid: AtomicU64::new(0), auth_rate_limited: AtomicU64::new(0), tcp_connections_refused: AtomicU64::new(0), shutdown_initiated: AtomicU64::new(0) };
impl MirajMetrics { pub fn snapshot(&self) -> serde_json::Value { serde_json::json!({ "connections_total": self.connections_total.load(Ordering::Relaxed), "connections_active": self.connections_active.load(Ordering::Relaxed), "auth_ok": self.auth_ok.load(Ordering::Relaxed), "auth_fail": self.auth_fail.load(Ordering::Relaxed), "tcp_streams_total": self.tcp_streams_total.load(Ordering::Relaxed), "udp_sessions_total": self.udp_sessions_total.load(Ordering::Relaxed), "tcp_bytes_up": self.tcp_bytes_up.load(Ordering::Relaxed), "tcp_bytes_down": self.tcp_bytes_down.load(Ordering::Relaxed), "udp_datagrams_in": self.udp_datagrams_in.load(Ordering::Relaxed), "udp_datagrams_out": self.udp_datagrams_out.load(Ordering::Relaxed), "masquerades": self.masquerades.load(Ordering::Relaxed), "errors_total": self.errors_total.load(Ordering::Relaxed), "udp_sessions_active": self.udp_sessions_active.load(Ordering::Relaxed), "udp_sessions_rejected": self.udp_sessions_rejected.load(Ordering::Relaxed), "udp_datagrams_dropped": self.udp_datagrams_dropped.load(Ordering::Relaxed), "udp_datagrams_invalid": self.udp_datagrams_invalid.load(Ordering::Relaxed), "auth_rate_limited": self.auth_rate_limited.load(Ordering::Relaxed), "tcp_connections_refused": self.tcp_connections_refused.load(Ordering::Relaxed), "shutdown_initiated": self.shutdown_initiated.load(Ordering::Relaxed) }) } }

#[derive(Default, Clone, Copy)] struct UserTrafficEntry { bytes_in: u64, bytes_out: u64 }
static USER_TRAFFIC: OnceLock<Arc<Mutex<HashMap<i64, UserTrafficEntry>>>> = OnceLock::new();
fn user_traffic() -> &'static Arc<Mutex<HashMap<i64, UserTrafficEntry>>> { USER_TRAFFIC.get_or_init(|| Arc::new(Mutex::new(HashMap::new()))) }
fn add_user_traffic(user_id: i64, bytes_in: u64, bytes_out: u64) { let mut g = user_traffic().lock().unwrap(); let e = g.entry(user_id).or_default(); e.bytes_in = e.bytes_in.saturating_add(bytes_in); e.bytes_out = e.bytes_out.saturating_add(bytes_out); }
async fn flush_user_traffic() {
    let snapshot: Vec<(i64, u64, u64)> = { let mut g = user_traffic().lock().unwrap(); if g.is_empty() { return; } let snap = g.iter().map(|(k, v)| (*k, v.bytes_in, v.bytes_out)).collect(); g.clear(); snap };
    let Some(db) = db::global() else { return };
    let p = { let conns = db.conns.read().await; let omni = match conns.get("OmniDB").cloned() { Some(o) => o, None => return }; let db::Pool::Sqlite(p) = &omni.pool; p.clone() };
    let ts = now_ts();
    let _ = tokio::task::spawn_blocking(move || { let g = match p.lock() { Ok(g) => g, Err(_) => return }; for (uid, bi, bo) in snapshot { let _ = g.execute("UPDATE miraj_users SET bytes_in = bytes_in + ?1, bytes_out = bytes_out + ?2, updated_at = ?3 WHERE id = ?4", rusqlite::params![bi as i64, bo as i64, ts, uid]); } }).await;
}
fn spawn_traffic_flusher() { tokio::spawn(async { let mut interval = tokio::time::interval(Duration::from_secs(30)); interval.tick().await; loop { interval.tick().await; flush_user_traffic().await; } }); }

struct AuthRateLimiter { attempts: Mutex<HashMap<IpAddr, (Instant, u32)>>, limit: u32, window: Duration }
impl AuthRateLimiter {
    fn new(limit: u32) -> Self { Self { attempts: Mutex::new(HashMap::new()), limit, window: Duration::from_secs(60) } }
    fn check(&self, ip: IpAddr) -> bool { let mut g = self.attempts.lock().unwrap(); let now = Instant::now(); let e = g.entry(ip).or_insert((now, 0)); if now.duration_since(e.0) >= self.window { *e = (now, 1); return true; } if e.1 >= self.limit { return false; } e.1 += 1; true }
    fn sweep(&self) { let mut g = self.attempts.lock().unwrap(); let now = Instant::now(); g.retain(|_, (t, _)| now.duration_since(*t) < self.window * 2); }
}
static AUTH_LIMITER: OnceLock<Arc<AuthRateLimiter>> = OnceLock::new();
fn auth_limiter() -> &'static Arc<AuthRateLimiter> { AUTH_LIMITER.get_or_init(|| Arc::new(AuthRateLimiter::new(10))) }
fn init_auth_limiter(per_min: u32) { let _ = AUTH_LIMITER.set(Arc::new(AuthRateLimiter::new(per_min))); tokio::spawn(async { let mut interval = tokio::time::interval(Duration::from_secs(300)); interval.tick().await; loop { interval.tick().await; auth_limiter().sweep(); } }); }

// §3 QUIC VARINT
#[inline] pub fn put_varint(buf: &mut BytesMut, v: u64) { if v <= 63 { buf.put_u8(v as u8); } else if v <= 16383 { buf.put_u8((v >> 8) as u8 | 0x40); buf.put_u8(v as u8); } else if v <= 1_073_741_823 { buf.put_u8((v >> 24) as u8 | 0x80); buf.put_u8((v >> 16) as u8); buf.put_u8((v >> 8) as u8); buf.put_u8(v as u8); } else { buf.put_u8((v >> 56) as u8 | 0xc0); buf.put_u8((v >> 48) as u8); buf.put_u8((v >> 40) as u8); buf.put_u8((v >> 32) as u8); buf.put_u8((v >> 24) as u8); buf.put_u8((v >> 16) as u8); buf.put_u8((v >> 8) as u8); buf.put_u8(v as u8); } }
#[inline] pub fn get_varint(buf: &[u8]) -> Option<(u64, usize)> { let first = *buf.first()?; let len = 1usize << (first >> 6); if buf.len() < len { return None; } let mut val = (first & 0x3f) as u64; for &b in &buf[1..len] { val = (val << 8) | b as u64; } Some((val, len)) }
#[inline] fn put_varint_slice(buf: &mut [u8], v: u64) -> usize { if v <= 63 { buf[0] = v as u8; 1 } else if v <= 16383 { buf[0] = (v >> 8) as u8 | 0x40; buf[1] = v as u8; 2 } else if v <= 1_073_741_823 { buf[0] = (v >> 24) as u8 | 0x80; buf[1] = (v >> 16) as u8; buf[2] = (v >> 8) as u8; buf[3] = v as u8; 4 } else { buf[0] = (v >> 56) as u8 | 0xc0; buf[1] = (v >> 48) as u8; buf[2] = (v >> 40) as u8; buf[3] = (v >> 32) as u8; buf[4] = (v >> 24) as u8; buf[5] = (v >> 16) as u8; buf[6] = (v >> 8) as u8; buf[7] = v as u8; 8 } }
#[inline] fn varint_len(v: u64) -> usize { if v <= 63 { 1 } else if v <= 16383 { 2 } else if v <= 1_073_741_823 { 4 } else { 8 } }

// §4 TCP FRAMING
const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;
const MAX_MESSAGE_LENGTH: u64 = 2048;
const MAX_PADDING_LENGTH: u64 = 4096;
const PADDING_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
fn random_padding(min: usize, max: usize) -> Vec<u8> { let mut rng = rand::thread_rng(); let n = if max > min { min + rng.next_u32() as usize % (max - min) } else { min }; let mut out = Vec::with_capacity(n); for _ in 0..n { out.push(PADDING_CHARS[rng.next_u32() as usize % PADDING_CHARS.len()]); } out }
#[derive(Debug)] struct TcpRequest { address: String, header_len: usize }
fn try_parse_tcp_request(buf: &[u8]) -> Result<Option<TcpRequest>, String> {
    let mut pos = 0usize;
    let (frame_type, n) = match get_varint(&buf[pos..]) { Some(v) => v, None => return Ok(None) }; pos += n;
    if frame_type != FRAME_TYPE_TCP_REQUEST { return Err(format!("bad frame type: {:#x}", frame_type)); }
    let (addr_len, n) = match get_varint(&buf[pos..]) { Some(v) => v, None => return Ok(None) }; pos += n;
    if addr_len == 0 || addr_len > MAX_MESSAGE_LENGTH { return Err(format!("bad addr length: {}", addr_len)); }
    if buf.len() < pos + addr_len as usize { return Ok(None); }
    let address = std::str::from_utf8(&buf[pos..pos + addr_len as usize]).map_err(|_| "invalid utf8 in address".to_string())?.to_string();
    pos += addr_len as usize;
    let (pad_len, n) = match get_varint(&buf[pos..]) { Some(v) => v, None => return Ok(None) }; pos += n;
    if pad_len > MAX_PADDING_LENGTH { return Err(format!("bad padding length: {}", pad_len)); }
    if buf.len() < pos + pad_len as usize { return Ok(None); }
    pos += pad_len as usize;
    Ok(Some(TcpRequest { address, header_len: pos }))
}
fn encode_tcp_response_ok() -> Bytes { let mut buf = BytesMut::with_capacity(4); buf.put_u8(0x00); put_varint(&mut buf, 0); put_varint(&mut buf, 0); buf.freeze() }
fn encode_tcp_response_err() -> Bytes { let mut buf = BytesMut::with_capacity(4); buf.put_u8(0x01); put_varint(&mut buf, 0); put_varint(&mut buf, 0); buf.freeze() }

// §5 UDP MESSAGE + DEFRAG
const MAX_UDP_SIZE: usize = 4096;
const MAX_FRAGMENTS: u8 = 64;
const MAX_FRAG_SIZE: usize = 2048;
const MAX_DEFRAG_ENTRIES: usize = 256;
const PENDING_QUEUE_CAPACITY: usize = 64;
#[derive(Clone, Debug)] struct UdpMessage { session_id: u32, packet_id: u16, frag_id: u8, frag_count: u8, addr: String, data: Vec<u8> }
impl UdpMessage {
    fn header_size(&self) -> usize { 4 + 2 + 1 + 1 + varint_len(self.addr.len() as u64) + self.addr.len() }
    fn size(&self) -> usize { self.header_size() + self.data.len() }
    fn serialize(&self, buf: &mut [u8]) -> Option<usize> { let total = self.size(); if buf.len() < total { return None; } buf[0..4].copy_from_slice(&self.session_id.to_be_bytes()); buf[4..6].copy_from_slice(&self.packet_id.to_be_bytes()); buf[6] = self.frag_id; buf[7] = self.frag_count; let mut i = 8usize; i += put_varint_slice(&mut buf[i..], self.addr.len() as u64); buf[i..i + self.addr.len()].copy_from_slice(self.addr.as_bytes()); i += self.addr.len(); buf[i..i + self.data.len()].copy_from_slice(&self.data); i += self.data.len(); Some(i) }
    fn parse(msg: &[u8]) -> Option<Self> { if msg.len() < 8 { return None; } let session_id = u32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]); let packet_id = u16::from_be_bytes([msg[4], msg[5]]); let frag_id = msg[6]; let frag_count = msg[7]; if frag_count == 0 || frag_id >= frag_count { return None; } let (addr_len, n) = get_varint(&msg[8..])?; if addr_len == 0 || addr_len > MAX_MESSAGE_LENGTH { return None; } let addr_start = 8 + n; let addr_end = addr_start + addr_len as usize; if msg.len() <= addr_end { return None; } let addr = String::from_utf8(msg[addr_start..addr_end].to_vec()).ok()?; let data = msg[addr_end..].to_vec(); Some(Self { session_id, packet_id, frag_id, frag_count, addr, data }) }
}
fn frag_udp_message(m: &UdpMessage, max_size: usize) -> Vec<UdpMessage> { if m.size() <= max_size { return vec![m.clone()]; } let max_payload = max_size.saturating_sub(m.header_size()); if max_payload == 0 { return Vec::new(); } let frag_count = (m.data.len() + max_payload - 1) / max_payload; if frag_count > MAX_FRAGMENTS as usize { return Vec::new(); } let mut frags = Vec::with_capacity(frag_count); let mut off = 0usize; let mut frag_id = 0u8; while off < m.data.len() { let end = (off + max_payload).min(m.data.len()); frags.push(UdpMessage { session_id: m.session_id, packet_id: m.packet_id, frag_id, frag_count: frag_count as u8, addr: m.addr.clone(), data: m.data[off..end].to_vec() }); off = end; frag_id += 1; } frags }
struct DefragEntry { frags: Vec<Option<UdpMessage>>, count: u8, size: usize, started_at: Instant }
struct DefragPool { entries: HashMap<u16, DefragEntry>, timeout: Duration, max_entries: usize, last_sweep: Instant }
impl DefragPool {
    fn new(timeout: Duration, max_entries: usize) -> Self { Self { entries: HashMap::new(), timeout, max_entries, last_sweep: Instant::now() } }
    fn sweep(&mut self) { if self.last_sweep.elapsed() < Duration::from_secs(1) { return; } self.last_sweep = Instant::now(); let timeout = self.timeout; let before = self.entries.len(); self.entries.retain(|_, e| e.started_at.elapsed() < timeout); let removed = before - self.entries.len(); if removed > 0 { METRICS.udp_datagrams_dropped.fetch_add(removed as u64, Ordering::Relaxed); } }
    fn feed(&mut self, m: UdpMessage) -> Option<UdpMessage> {
        self.sweep();
        if m.frag_count <= 1 { return Some(m); }
        if m.frag_count > MAX_FRAGMENTS { METRICS.udp_datagrams_dropped.fetch_add(1, Ordering::Relaxed); return None; }
        if m.frag_id >= m.frag_count { METRICS.udp_datagrams_dropped.fetch_add(1, Ordering::Relaxed); return None; }
        if m.data.len() > MAX_FRAG_SIZE { METRICS.udp_datagrams_dropped.fetch_add(1, Ordering::Relaxed); return None; }
        if self.entries.len() >= self.max_entries && !self.entries.contains_key(&m.packet_id) { METRICS.udp_datagrams_dropped.fetch_add(1, Ordering::Relaxed); return None; }
        let entry = self.entries.entry(m.packet_id).or_insert_with(|| DefragEntry { frags: vec![None; m.frag_count as usize], count: m.frag_count, size: 0, started_at: Instant::now() });
        if entry.count != m.frag_count || entry.frags.len() != m.frag_count as usize { *entry = DefragEntry { frags: vec![None; m.frag_count as usize], count: m.frag_count, size: 0, started_at: Instant::now() }; }
        let packet_id = m.packet_id;
        let idx = m.frag_id as usize;
        if entry.frags[idx].is_none() { entry.size += m.data.len(); entry.frags[idx] = Some(m); }
        if entry.frags.iter().all(|f| f.is_some()) { let mut done = self.entries.remove(&packet_id)?; let mut data = Vec::with_capacity(done.size); let mut first: Option<UdpMessage> = None; for frag in done.frags.iter_mut() { if let Some(f) = frag.take() { if first.is_none() { first = Some(f.clone()); } data.extend_from_slice(&f.data); } } let mut out = first?; out.data = data; out.frag_id = 0; out.frag_count = 1; Some(out) } else { None }
    }
}

// §6 SALAMANDER
const SALT_LEN: usize = 8;
const KEY_LEN: usize = 32;
const MIN_PSK_LEN: usize = 4;
#[derive(Clone)] struct Salamander { psk: Vec<u8> }
impl Salamander {
    fn new(psk: &[u8]) -> Option<Self> { if psk.len() < MIN_PSK_LEN { return None; } Some(Self { psk: psk.to_vec() }) }
    fn key(&self, salt: &[u8]) -> [u8; KEY_LEN] { use blake2::digest::consts::U32; use blake2::{Blake2b, Digest}; let mut h = Blake2b::<U32>::new(); h.update(&self.psk); h.update(salt); let out = h.finalize(); let mut arr = [0u8; KEY_LEN]; arr.copy_from_slice(&out[..KEY_LEN]); arr }
    fn obfuscate(&self, input: &[u8], out: &mut [u8]) -> usize { let out_len = input.len() + SALT_LEN; if out.len() < out_len { return 0; } rand::thread_rng().fill_bytes(&mut out[..SALT_LEN]); let key = self.key(&out[..SALT_LEN]); for (i, &c) in input.iter().enumerate() { out[i + SALT_LEN] = c ^ key[i % KEY_LEN]; } out_len }
    fn deobfuscate(&self, input: &[u8], out: &mut [u8]) -> usize { if input.len() <= SALT_LEN { return 0; } let out_len = input.len() - SALT_LEN; if out.len() < out_len { return 0; } let key = self.key(&input[..SALT_LEN]); for (i, &c) in input[SALT_LEN..].iter().enumerate() { out[i] = c ^ key[i % KEY_LEN]; } out_len }
}

// §7 GECKO
const GECKO_TYPE_FULL: u8 = 0x00;
const GECKO_TYPE_FRAG: u8 = 0x01;
#[derive(Default)] struct GeckoPartial { expected: u8, received: Vec<Option<Vec<u8>>>, received_count: u8 }
struct GeckoState { partial: HashMap<SocketAddr, GeckoPartial>, max_size: usize }
impl GeckoState {
    fn new(max_size: usize) -> Self { Self { partial: HashMap::new(), max_size: max_size.max(64) } }
    fn fragment(&self, packet: &[u8]) -> Vec<Vec<u8>> { if packet.len() + 1 <= self.max_size { let mut out = Vec::with_capacity(packet.len() + 1); out.push(GECKO_TYPE_FULL); out.extend_from_slice(packet); return vec![out]; } let max_payload = self.max_size.saturating_sub(3); if max_payload == 0 { return Vec::new(); } let count = (packet.len() + max_payload - 1) / max_payload; if count > 255 { let mut out = Vec::with_capacity(packet.len() + 1); out.push(GECKO_TYPE_FULL); out.extend_from_slice(packet); return vec![out]; } let mut result = Vec::with_capacity(count); let mut frag_id: u8 = 0; let mut off = 0usize; while off < packet.len() { let end = (off + max_payload).min(packet.len()); let mut frag = Vec::with_capacity(3 + end - off); frag.push(GECKO_TYPE_FRAG); frag.push(frag_id); frag.push(count as u8); frag.extend_from_slice(&packet[off..end]); result.push(frag); off = end; frag_id += 1; } result }
    fn feed(&mut self, src: SocketAddr, data: &[u8]) -> Option<Vec<u8>> { if data.is_empty() { return None; } let typ = data[0]; if typ == GECKO_TYPE_FULL { return Some(data[1..].to_vec()); } if typ != GECKO_TYPE_FRAG || data.len() < 3 { return None; } let frag_id = data[1]; let count = data[2]; let payload = &data[3..]; if count == 0 || frag_id >= count { return None; } let partial = self.partial.entry(src).or_insert_with(|| GeckoPartial { expected: count, received: vec![None; count as usize], received_count: 0 }); if partial.expected != count || partial.received.len() != count as usize { *partial = GeckoPartial { expected: count, received: vec![None; count as usize], received_count: 0 }; } let idx = frag_id as usize; if partial.received[idx].is_none() { partial.received[idx] = Some(payload.to_vec()); partial.received_count += 1; } if partial.received_count == partial.expected { let complete: Vec<u8> = partial.received.iter_mut().filter_map(|slot| slot.take()).flatten().collect(); self.partial.remove(&src); Some(complete) } else { None } }
}

// §8 BRUTAL
const SLOT_COUNT: usize = 5;
const MIN_SAMPLE_COUNT: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
#[derive(Clone, Copy, Default)] struct BrutalSlot { ts: i64, ack: u64, loss: u64 }
#[derive(Clone)] pub struct Brutal { rate: Arc<AtomicU64>, mtu: u64, base: Instant, srtt: Duration, ack_rate: f64, slots: [BrutalSlot; SLOT_COUNT] }
impl Brutal {
    fn new(rate: Arc<AtomicU64>, mtu: u16) -> Self { Self { rate, mtu: mtu as u64, base: Instant::now(), srtt: Duration::ZERO, ack_rate: 1.0, slots: [BrutalSlot::default(); SLOT_COUNT] } }
    fn secs(&self, now: Instant) -> i64 { now.saturating_duration_since(self.base).as_secs() as i64 }
    fn record(&mut self, now: Instant, ack: u64, loss: u64) { let ts = self.secs(now); let slot = &mut self.slots[(ts as usize) % SLOT_COUNT]; if slot.ts == ts { slot.ack += ack; slot.loss += loss; } else { slot.ts = ts; slot.ack = ack; slot.loss = loss; } self.update_ack_rate(ts); }
    fn update_ack_rate(&mut self, now_ts: i64) { let min_ts = now_ts - SLOT_COUNT as i64; let (mut acks, mut losses) = (0u64, 0u64); for s in &self.slots { if s.ts < min_ts { continue; } acks += s.ack; losses += s.loss; } if acks + losses < MIN_SAMPLE_COUNT { self.ack_rate = 1.0; return; } let rate = acks as f64 / (acks + losses) as f64; self.ack_rate = rate.max(MIN_ACK_RATE); }
}
impl Controller for Brutal {
    fn on_ack(&mut self, now: Instant, _sent: Instant, _bytes: u64, _app_limited: bool, rtt: &RttEstimator) { self.srtt = rtt.get(); self.record(now, 1, 0); }
    fn on_congestion_event(&mut self, now: Instant, _sent: Instant, _is_persistent_congestion: bool, lost_bytes: u64) { let lost_pkts = (lost_bytes / self.mtu.max(1)).max(1); self.record(now, 0, lost_pkts); }
    fn on_mtu_update(&mut self, new_mtu: u16) { self.mtu = new_mtu as u64; }
    fn window(&self) -> u64 { let floor = (self.mtu * 2).max(10_240); if self.srtt.is_zero() { return floor; } let bps = self.rate.load(Ordering::Relaxed) as f64; let cwnd = bps * self.srtt.as_secs_f64() / self.ack_rate; (cwnd as u64).max(floor) }
    fn clone_box(&self) -> Box<dyn Controller> { Box::new(self.clone()) }
    fn initial_window(&self) -> u64 { (self.mtu * 2).max(10_240) }
    fn into_any(self: Box<Self>) -> Box<dyn Any> { self }
}
pub struct BrutalFactory { pub rate: Arc<AtomicU64> }
impl ControllerFactory for BrutalFactory { fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> { Box::new(Brutal::new(self.rate.clone(), current_mtu)) } }

// §9 ObfsHopSocket
const SCRATCH_DATAGRAM: usize = 2048;
pub struct ObfsHopSocket { inner: Arc<dyn AsyncUdpSocket>, obfs: Option<Salamander>, gecko: Option<Arc<Mutex<GeckoState>>>, write_buf: Mutex<Vec<u8>>, recv_scratch: Mutex<(Vec<u8>, Vec<RecvMeta>)> }
impl fmt::Debug for ObfsHopSocket { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("ObfsHopSocket").field("obfs", &self.obfs.is_some()).field("gecko", &self.gecko.is_some()).finish() } }
impl ObfsHopSocket {
    fn new(inner: Arc<dyn AsyncUdpSocket>, obfs: Option<Salamander>, gecko: Option<Arc<Mutex<GeckoState>>>) -> Arc<Self> { Arc::new(Self { inner, obfs, gecko, write_buf: Mutex::new(vec![0u8; SCRATCH_DATAGRAM * 4]), recv_scratch: Mutex::new((Vec::new(), Vec::new())) }) }
    fn try_send_one(&self, packet: &[u8], dest: SocketAddr, src_ip: Option<std::net::IpAddr>) -> io::Result<()> { let fragments: Vec<Vec<u8>> = match &self.gecko { Some(g) => g.lock().unwrap().fragment(packet), None => vec![packet.to_vec()] }; for frag in fragments { let payload: Vec<u8> = match &self.obfs { Some(o) => { let mut out = vec![0u8; frag.len() + SALT_LEN]; let n = o.obfuscate(&frag, &mut out); out.truncate(n); out } None => frag }; let t = Transmit { destination: dest, ecn: None, contents: &payload, segment_size: None, src_ip }; self.inner.try_send(&t)?; } Ok(()) }
}
impl AsyncUdpSocket for ObfsHopSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> { self.inner.clone().create_io_poller() }
    fn try_send(&self, transmit: &Transmit) -> io::Result<()> { if self.obfs.is_none() && self.gecko.is_none() { return self.inner.try_send(transmit); } self.try_send_one(transmit.contents, transmit.destination, transmit.src_ip) }
    fn poll_recv(&self, cx: &mut Context<'_>, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        if self.obfs.is_none() && self.gecko.is_none() { return self.inner.poll_recv(cx, bufs, meta); }
        let count = bufs.len();
        let mut guard = self.recv_scratch.lock().unwrap();
        let (scratch, tmp_meta) = &mut *guard;
        if scratch.len() < count * SCRATCH_DATAGRAM { scratch.resize(count * SCRATCH_DATAGRAM, 0); }
        if tmp_meta.len() < count { tmp_meta.resize(count, RecvMeta::default()); }
        loop {
            let mut tmp_bufs: Vec<IoSliceMut> = scratch[..count * SCRATCH_DATAGRAM].chunks_mut(SCRATCH_DATAGRAM).map(IoSliceMut::new).collect();
            let n = match self.inner.poll_recv(cx, &mut tmp_bufs, &mut tmp_meta[..count]) { Poll::Ready(Ok(0)) => return Poll::Ready(Ok(0)), Poll::Ready(Ok(n)) => n, other => return other };
            drop(tmp_bufs);
            let mut out = 0usize;
            for k in 0..n {
                let raw_end = tmp_meta[k].len;
                let raw = &scratch[k * SCRATCH_DATAGRAM..k * SCRATCH_DATAGRAM + raw_end];
                let deobf: Vec<u8> = match &self.obfs { Some(o) => { let mut tmp = vec![0u8; raw.len()]; let m = o.deobfuscate(raw, &mut tmp); if m == 0 { continue; } tmp.truncate(m); tmp } None => raw.to_vec() };
                let packet: Option<Vec<u8>> = match &self.gecko { Some(g) => g.lock().unwrap().feed(tmp_meta[k].addr, &deobf), None => Some(deobf) };
                if let Some(pkt) = packet {
                    if pkt.len() > bufs[out].len() { continue; }
                    bufs[out][..pkt.len()].copy_from_slice(&pkt);
                    meta[out] = RecvMeta { addr: tmp_meta[k].addr, len: pkt.len(), stride: pkt.len(), ecn: tmp_meta[k].ecn, dst_ip: tmp_meta[k].dst_ip };
                    out += 1;
                }
            }
            if out > 0 { return Poll::Ready(Ok(out)); }
            return Poll::Pending;
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> { self.inner.local_addr() }
    fn max_transmit_segments(&self) -> usize { 1 }
    fn max_receive_segments(&self) -> usize { 1 }
    fn may_fragment(&self) -> bool { false }
}

// §10 AUTH
type H3ReqStream = RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
pub enum AuthResult { Ok { user_id: Option<i64>, user_name: Option<String> }, Masquerade }

/// ★ NEW: предикт — это Hysteria2 auth-запрос или что-то другое?
/// Используется в main.rs для мультиплекса 443/UDP.
pub fn is_hysteria_auth(req: &http::Request<()>) -> bool {
    req.method() == http::Method::POST
        && (req.uri().path() == "/auth" || req.uri().path() == "/auth/")
        && req.headers().contains_key("hysteria-auth")
}

fn now_ts() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0) }
fn ensure_miraj_users_table(g: &rusqlite::Connection) { let _ = g.execute("CREATE TABLE IF NOT EXISTS miraj_users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, password TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, bytes_in INTEGER NOT NULL DEFAULT 0, bytes_out INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0)", []); }
async fn lookup_miraj_user(auth_q: &str) -> Option<(i64, String)> {
    let db = db::global()?;
    let omni = { let conns = db.conns.read().await; conns.get("OmniDB").cloned()? };
    let db::Pool::Sqlite(p) = &omni.pool;
    let p = p.clone();
    let auth_q = auth_q.to_string();
    tokio::task::spawn_blocking(move || -> Option<(i64, String)> { let g = p.lock().ok()?; ensure_miraj_users_table(&g); g.query_row("SELECT id, name FROM miraj_users WHERE password = ?1 AND enabled = 1 LIMIT 1", rusqlite::params![auth_q], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))).ok() }).await.ok().flatten()
}

/// ★ CHANGED: при провале auth — отправляем masquerade-ответ сами, чтобы stream
/// не висел. Возвращаем Masquerade для сигнала вызывающему коду (main-loop
/// мультиплекса продолжит принимать сайты в том же h3-соединении).
pub async fn handle_auth(mut stream: H3ReqStream, req: http::Request<()>, cfg: &MirajConfig, peer_ip: IpAddr) -> Result<AuthResult, Box<dyn std::error::Error + Send + Sync>> {
    let auth = req.headers().get("hysteria-auth").and_then(|v| v.to_str().ok()).unwrap_or("");
    if !auth_limiter().check(peer_ip) { METRICS.auth_rate_limited.fetch_add(1, Ordering::Relaxed); METRICS.auth_fail.fetch_add(1, Ordering::Relaxed); warn!("[MIRAJ] auth rate-limited from {} (prefix={})", peer_ip, &auth.chars().take(6).collect::<String>()); let _ = handle_masquerade(stream, req, cfg).await; return Ok(AuthResult::Masquerade); }
    let mut authorized = false;
    let mut user_id: Option<i64> = None;
    let mut user_name: Option<String> = None;
    if !auth.is_empty() && auth == cfg.auth_token { authorized = true; }
    if !authorized && !auth.is_empty() { if let Some((uid, uname)) = lookup_miraj_user(auth).await { authorized = true; user_id = Some(uid); user_name = Some(uname); } }
    if authorized {
        let rx_header: String = if cfg.brutal_tx > 0 { cfg.brutal_tx.to_string() } else { "auto".to_string() };
        let padding = random_padding(64, 512);
        let padding_str = String::from_utf8_lossy(&padding).into_owned();
        let resp = http::Response::builder().status(233u16).header("Hysteria-UDP", if cfg.udp_enabled { "true" } else { "false" }).header("Hysteria-CC-RX", rx_header).header("Hysteria-Padding", padding_str).body(()).map_err(|e| format!("build response: {e}"))?;
        stream.send_response(resp).await?;
        stream.finish().await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        METRICS.auth_ok.fetch_add(1, Ordering::Relaxed);
        info!("[MIRAJ] auth ok user={:?} id={:?} peer={}", user_name, user_id, peer_ip);
        Ok(AuthResult::Ok { user_id, user_name })
    } else {
        METRICS.auth_fail.fetch_add(1, Ordering::Relaxed);
        warn!("[MIRAJ] auth fail peer={} token_prefix={}", peer_ip, &auth.chars().take(6).collect::<String>());
        let _ = handle_masquerade(stream, req, cfg).await;
        Ok(AuthResult::Masquerade)
    }
}

// §11 MASQUERADE
async fn handle_masquerade(mut stream: H3ReqStream, req: http::Request<()>, cfg: &MirajConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    METRICS.masquerades.fetch_add(1, Ordering::Relaxed);
    let upstream_base = match &cfg.masquerade_url { Some(u) => u.clone(), None => { let resp = http::Response::builder().status(404u16).header("content-type", "text/plain; charset=utf-8").body(()).map_err(|e| format!("build 404: {e}"))?; stream.send_response(resp).await?; stream.send_data(Bytes::from_static(b"Not Found")).await?; stream.finish().await?; return Ok(()); } };
    let path_and_query = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let upstream_url = if upstream_base.ends_with('/') { format!("{}{}", upstream_base, path_and_query.trim_start_matches('/')) } else { format!("{}{}", upstream_base, path_and_query) };
    let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).build()?;
    let method = reqwest::Method::from_bytes(req.method().as_str().as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut upstream = client.request(method, &upstream_url);
    for (name, value) in req.headers() { let ln = name.as_str().to_ascii_lowercase(); if matches!(ln.as_str(), "connection" | "keep-alive" | "transfer-encoding" | "upgrade" | "host") { continue; } if let Ok(v) = value.to_str() { upstream = upstream.header(name.as_str(), v); } }
    match upstream.send().await {
        Ok(resp) => { let status = resp.status().as_u16(); let mut builder = http::Response::builder().status(status); for (name, value) in resp.headers() { let ln = name.as_str().to_ascii_lowercase(); if matches!(ln.as_str(), "connection" | "keep-alive" | "transfer-encoding" | "upgrade") { continue; } builder = builder.header(name.as_str(), value.as_bytes()); } let resp_head = builder.body(()).map_err(|e| format!("build resp: {e}"))?; stream.send_response(resp_head).await?; let body_bytes = resp.bytes().await.unwrap_or_else(|_| Bytes::new()); if !body_bytes.is_empty() { stream.send_data(body_bytes).await?; } stream.finish().await?; }
        Err(e) => { warn!("miraj: masquerade upstream error: {e}"); let resp = http::Response::builder().status(502u16).body(()).map_err(|e| format!("build 502: {e}"))?; stream.send_response(resp).await?; stream.finish().await?; }
    }
    Ok(())
}

// §12 TCP
async fn handle_tcp_stream(send: quinn::SendStream, mut recv: quinn::RecvStream, cfg: Arc<MirajConfig>, user_id: Option<i64>, user_name: Option<String>, peer: SocketAddr) {
    METRICS.tcp_streams_total.fetch_add(1, Ordering::Relaxed);
    let started = Instant::now();
    let mut buf = BytesMut::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let parsed: TcpRequest = loop {
        match try_parse_tcp_request(&buf) { Ok(Some(p)) => break p, Ok(None) => {} Err(e) => { warn!("miraj: bad tcp request: {e}"); METRICS.errors_total.fetch_add(1, Ordering::Relaxed); return; } }
        let n = match recv.read(&mut tmp).await { Ok(Some(n)) if n > 0 => n, _ => { trace!("miraj: tcp stream closed before request parsed"); return; } };
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 64 * 1024 { warn!("miraj: tcp request too large"); return; }
    };
    let leftover = buf.split_off(parsed.header_len);
    let target = match TcpStream::connect(&parsed.address).await {
        Ok(t) => t,
        Err(e) => { warn!("miraj: tcp connect to {} failed: {e}", parsed.address); METRICS.errors_total.fetch_add(1, Ordering::Relaxed); METRICS.tcp_connections_refused.fetch_add(1, Ordering::Relaxed); let mut send = send; let _ = send.write_all(&encode_tcp_response_err()).await; let _ = send.finish(); return; }
    };
    let (mut target_read, mut target_write) = target.into_split();
    let mut send = send;
    if let Err(e) = send.write_all(&encode_tcp_response_ok()).await { debug!("miraj: tcp response write error: {e}"); return; }
    trace!("miraj: fast_open=tcp target={}", parsed.address);
    if !leftover.is_empty() { if let Err(e) = target_write.write_all(&leftover).await { debug!("miraj: tcp leftover to target error: {e}"); return; } }
    let send_for_down = send;
    let up_task = tokio::spawn(async move {
        let mut up_bytes: u64 = 0; let mut target_write = target_write; let mut recv = recv; let mut buf = [0u8; 8192];
        loop { match recv.read(&mut buf).await { Ok(Some(0)) | Ok(None) => break, Ok(Some(n)) => { if target_write.write_all(&buf[..n]).await.is_err() { break; } up_bytes += n as u64; } Err(_) => break } }
        let _ = target_write.shutdown().await; up_bytes
    });
    let down_task = tokio::spawn(async move {
        let mut send = send_for_down; let mut down_bytes: u64 = 0; let mut buf = [0u8; 8192];
        loop { match target_read.read(&mut buf).await { Ok(0) => break, Ok(n) => { if send.write_all(&buf[..n]).await.is_err() { break; } down_bytes += n as u64; } Err(_) => break } }
        let _ = tokio::time::timeout(Duration::from_secs(5), async { let _ = send.finish(); }).await;
        down_bytes
    });
    let up_bytes = up_task.await.unwrap_or(0);
    let down_bytes = down_task.await.unwrap_or(0);
    METRICS.tcp_bytes_up.fetch_add(up_bytes, Ordering::Relaxed);
    METRICS.tcp_bytes_down.fetch_add(down_bytes, Ordering::Relaxed);
    if let Some(uid) = user_id { add_user_traffic(uid, up_bytes, down_bytes); }
    info!("miraj: tcp done user={:?} peer={} target={} up={} down={} dur={:?}", user_name, peer, parsed.address, up_bytes, down_bytes, started.elapsed());
    let _ = &cfg;
}

// §13 UDP
struct UdpSessionState { target: SocketAddr, socket: Arc<UdpSocket>, created_at: Instant, last_active: Instant, bytes_in: u64, bytes_out: u64, datagrams_in: u64, datagrams_out: u64 }
fn compute_max_datagram(conn_max: Option<usize>, cfg_max: usize) -> usize { let upper = cfg_max.max(1200).min(1500); conn_max.unwrap_or(1200).clamp(1200, upper) }
fn upsert_session<'a>(sessions: &'a mut HashMap<u32, UdpSessionState>, session_id: u32, target: SocketAddr, cfg: &MirajConfig) -> Option<&'a mut UdpSessionState> {
    if !sessions.contains_key(&session_id) {
        let active = METRICS.udp_sessions_active.load(Ordering::Relaxed) as usize;
        if active >= cfg.udp_max_sessions { METRICS.udp_sessions_rejected.fetch_add(1, Ordering::Relaxed); return None; }
        let std_sock = match std::net::UdpSocket::bind("0.0.0.0:0") { Ok(s) => s, Err(_) => return None };
        let _ = std_sock.set_nonblocking(true);
        let arc = match UdpSocket::from_std(std_sock) { Ok(a) => Arc::new(a), Err(_) => return None };
        METRICS.udp_sessions_total.fetch_add(1, Ordering::Relaxed);
        METRICS.udp_sessions_active.fetch_add(1, Ordering::Relaxed);
        sessions.insert(session_id, UdpSessionState { target, socket: arc, created_at: Instant::now(), last_active: Instant::now(), bytes_in: 0, bytes_out: 0, datagrams_in: 0, datagrams_out: 0 });
    }
    sessions.get_mut(&session_id)
}
fn send_udp_to_conn(conn: &Connection, resp: &UdpMessage, max_datagram: usize) {
    let mut out = vec![0u8; resp.size()];
    if resp.size() <= max_datagram { if let Some(written) = resp.serialize(&mut out) { if conn.send_datagram(Bytes::copy_from_slice(&out[..written])).is_ok() { METRICS.udp_datagrams_out.fetch_add(1, Ordering::Relaxed); return; } } }
    let frags = frag_udp_message(resp, max_datagram);
    if frags.is_empty() { METRICS.udp_datagrams_dropped.fetch_add(1, Ordering::Relaxed); return; }
    for f in frags {
        let mut out = vec![0u8; f.size()];
        match f.serialize(&mut out) { Some(written) => { if conn.send_datagram(Bytes::copy_from_slice(&out[..written])).is_ok() { METRICS.udp_datagrams_out.fetch_add(1, Ordering::Relaxed); } else { METRICS.udp_datagrams_dropped.fetch_add(1, Ordering::Relaxed); } } None => { METRICS.udp_datagrams_dropped.fetch_add(1, Ordering::Relaxed); } }
    }
}
async fn handle_udp_stream(conn: Connection, mut recv: quinn::RecvStream, cfg: Arc<MirajConfig>, user_id: Option<i64>, user_name: Option<String>, peer: SocketAddr) {
    let mut defrag = DefragPool::new(cfg.udp_defrag_timeout, MAX_DEFRAG_ENTRIES);
    let mut sessions: HashMap<u32, UdpSessionState> = HashMap::new();
    let mut buf = vec![0u8; MAX_UDP_SIZE];
    let max_datagram = compute_max_datagram(conn.max_datagram_size(), cfg.udp_max_mtu);
    let (pending_tx, mut pending_rx) = mpsc::channel::<UdpMessage>(PENDING_QUEUE_CAPACITY);
    let initial = match recv.read(&mut buf).await { Ok(Some(n)) if n > 0 => Some(buf[..n].to_vec()), _ => None };
    if let Some(data) = initial { match UdpMessage::parse(&data) { Some(m) => { if let Some(full) = defrag.feed(m) { let _ = pending_tx.try_send(full); } } None => { METRICS.udp_datagrams_invalid.fetch_add(1, Ordering::Relaxed); } } }
    let mut local_in: u64 = 0;
    let mut local_out: u64 = 0;
    let mut last_sweep = Instant::now();
    loop {
        while let Ok(m) = pending_rx.try_recv() {
            METRICS.udp_datagrams_in.fetch_add(1, Ordering::Relaxed);
            let target_addr: SocketAddr = match m.addr.parse() { Ok(a) => a, Err(_) => { METRICS.udp_datagrams_dropped.fetch_add(1, Ordering::Relaxed); continue; } };
            let sess = match upsert_session(&mut sessions, m.session_id, target_addr, &cfg) { Some(s) => s, None => continue };
            if sess.socket.send_to(&m.data, target_addr).await.is_ok() {
                sess.last_active = Instant::now();
                sess.bytes_in = sess.bytes_in.saturating_add(m.data.len() as u64);
                sess.datagrams_in += 1;
                local_in = local_in.saturating_add(m.data.len() as u64);
            } else { METRICS.udp_datagrams_dropped.fetch_add(1, Ordering::Relaxed); }
        }
        if last_sweep.elapsed() >= Duration::from_secs(10) {
            last_sweep = Instant::now();
            let idle = cfg.udp_idle_timeout;
            let before = sessions.len();
            sessions.retain(|_, s| s.last_active.elapsed() < idle);
            let removed = (before - sessions.len()) as u64;
            if removed > 0 { METRICS.udp_sessions_active.fetch_sub(removed, Ordering::Relaxed); }
        }
        tokio::select! {
            dg = conn.read_datagram() => {
                match dg {
                    Ok(bytes) => match UdpMessage::parse(&bytes) {
                        Some(m) => { if let Some(full) = defrag.feed(m) { if pending_tx.try_send(full).is_err() { METRICS.udp_datagrams_dropped.fetch_add(1, Ordering::Relaxed); } } }
                        None => { METRICS.udp_datagrams_invalid.fetch_add(1, Ordering::Relaxed); }
                    },
                    Err(_) => break,
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(5)) => {
                for (sid, sess) in sessions.iter_mut() {
                    let mut rbuf = vec![0u8; MAX_UDP_SIZE];
                    loop {
                        match sess.socket.try_recv_from(&mut rbuf) {
                            Ok((0, _)) => break,
                            Ok((n, from)) => {
                                sess.last_active = Instant::now();
                                sess.bytes_out = sess.bytes_out.saturating_add(n as u64);
                                sess.datagrams_out += 1;
                                local_out = local_out.saturating_add(n as u64);
                                let resp = UdpMessage { session_id: *sid, packet_id: rand::random(), frag_id: 0, frag_count: 1, addr: from.to_string(), data: rbuf[..n].to_vec() };
                                send_udp_to_conn(&conn, &resp, max_datagram);
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        }
    }
    if let Some(uid) = user_id { add_user_traffic(uid, local_in, local_out); }
    let mut total_dg_in = 0u64; let mut total_dg_out = 0u64; let mut total_b_in = 0u64; let mut total_b_out = 0u64;
    for s in sessions.values() { total_dg_in += s.datagrams_in; total_dg_out += s.datagrams_out; total_b_in += s.bytes_in; total_b_out += s.bytes_out; }
    let before = sessions.len() as u64;
    sessions.clear();
    if before > 0 { METRICS.udp_sessions_active.fetch_sub(before, Ordering::Relaxed); }
    info!("miraj: udp done user={:?} peer={} sessions_closed={} dg_in={} dg_out={} bytes_in={} bytes_out={}", user_name, peer, before, total_dg_in, total_dg_out, total_b_in, total_b_out);
}

// §14 CONNECTION HANDLERS
struct ActiveConnGuard;
impl Drop for ActiveConnGuard { fn drop(&mut self) { METRICS.connections_active.fetch_sub(1, Ordering::Relaxed); } }

/// ★ NEW: общий QUIC-цикл (TCP bi-streams + UDP uni-streams + datagrams).
/// Вызывается и из standalone-режима (handle_connection), и из мультиплекса
/// (handle_authorized_connection после успешного auth).
pub async fn handle_quic_streams(
    conn: Connection,
    cfg: Arc<MirajConfig>,
    user_id: Option<i64>,
    user_name: Option<String>,
    peer: SocketAddr,
) {
    loop {
        tokio::select! {
            r = conn.accept_bi() => match r { Ok((send, recv)) => { let cfg_c = cfg.clone(); let uname = user_name.clone(); tokio::spawn(async move { handle_tcp_stream(send, recv, cfg_c, user_id, uname, peer).await; }); } Err(_) => break },
            r = conn.accept_uni() => match r { Ok(recv) => { if cfg.udp_enabled { let cfg_c = cfg.clone(); let conn_c = conn.clone(); let uname = user_name.clone(); tokio::spawn(async move { handle_udp_stream(conn_c, recv, cfg_c, user_id, uname, peer).await; }); } else { let mut recv = recv; let _ = recv.stop(0u32.into()); } } Err(_) => break },
            _ = conn.closed() => break,
        }
    }
}

// Standalone-режим: свой endpoint, свой h3-handler, свой auth.
async fn handle_connection(conn: Connection, cfg: Arc<MirajConfig>) {
    METRICS.connections_total.fetch_add(1, Ordering::Relaxed);
    METRICS.connections_active.fetch_add(1, Ordering::Relaxed);
    let _guard = ActiveConnGuard;
    let peer = conn.remote_address();
    info!("miraj: new connection from {peer}");
    let (auth_tx, auth_rx) = oneshot::channel::<AuthResult>();
    let cfg_h3 = cfg.clone();
    let conn_h3 = conn.clone();
    let h3_task = tokio::spawn(async move { run_h3_handler(conn_h3, peer, cfg_h3, auth_tx).await; });
    let auth_result = match auth_rx.await { Ok(r) => r, Err(_) => { let _ = h3_task.await; return; } };
    let (user_id, user_name) = match auth_result {
        AuthResult::Ok { user_id, user_name } => (user_id, user_name),
        AuthResult::Masquerade => {
            // handle_auth уже отправил masquerade-ответ клиенту.
            // h3_task завершится, когда клиент закроет соединение.
            let _ = h3_task.await;
            return;
        }
    };
    info!("miraj: {} authenticated (user={:?}), entering quic mode", peer, user_name);
    handle_quic_streams(conn, cfg, user_id, user_name, peer).await;
    debug!("miraj: connection {} closed", peer);
}

/// ★ NEW: для мультиплекса. main.rs уже принял h3_server и первый auth-запрос,
/// вызвал handle_auth(). При успехе вызывается эта функция — h3_server
/// удерживается до закрытия conn (иначе CONNECTION_CLOSE 0x100 убьёт стримы).
pub async fn handle_authorized_connection(
    conn: Connection,
    h3_server: h3::server::Connection<H3Connection, Bytes>,
    cfg: Arc<MirajConfig>,
    user_id: Option<i64>,
    user_name: Option<String>,
) {
    METRICS.connections_total.fetch_add(1, Ordering::Relaxed);
    METRICS.connections_active.fetch_add(1, Ordering::Relaxed);
    let _guard = ActiveConnGuard;
    let peer = conn.remote_address();
    info!("miraj: {} authenticated via multiplex (user={:?})", peer, user_name);

    let conn_h3 = conn.clone();
    tokio::spawn(async move {
        let _h3 = h3_server;
        conn_h3.closed().await;
    });

    handle_quic_streams(conn, cfg, user_id, user_name, peer).await;
    debug!("miraj: multiplex connection {} closed", peer);
}

// Standalone h3-handler для своего endpoint'а (не для мультиплекса).
async fn run_h3_handler(conn: Connection, peer: SocketAddr, cfg: Arc<MirajConfig>, auth_tx: oneshot::Sender<AuthResult>) {
    let h3_conn = H3Connection::new(conn.clone());
    let mut h3_server = match h3::server::Connection::new(h3_conn).await { Ok(s) => s, Err(e) => { warn!("miraj: h3 handshake failed: {e}"); let _ = auth_tx.send(AuthResult::Masquerade); return; } };
    let mut auth_tx = Some(auth_tx);
    loop {
        match h3_server.accept().await {
            Ok(Some(resolver)) => {
                let (req, stream) = match resolver.resolve_request().await { Ok(pair) => pair, Err(e) => { debug!("miraj: resolve_request error: {e}"); continue; } };
                let is_auth = is_hysteria_auth(&req);
                if is_auth && auth_tx.is_some() {
                    match handle_auth(stream, req, &cfg, peer.ip()).await {
                        Ok(ok @ AuthResult::Ok { .. }) => { if let Some(tx) = auth_tx.take() { let _ = tx.send(ok); } conn.closed().await; return; }
                        Ok(AuthResult::Masquerade) => { if let Some(tx) = auth_tx.take() { let _ = tx.send(AuthResult::Masquerade); } }
                        Err(e) => { warn!("miraj: auth handler error: {e}"); if let Some(tx) = auth_tx.take() { let _ = tx.send(AuthResult::Masquerade); } return; }
                    }
                } else { if let Err(e) = handle_masquerade(stream, req, &cfg).await { debug!("miraj: masquerade error: {e}"); } }
            }
            Ok(None) => { if let Some(tx) = auth_tx.take() { let _ = tx.send(AuthResult::Masquerade); } return; }
            Err(e) => { debug!("miraj: h3 accept closed: {e}"); if let Some(tx) = auth_tx.take() { let _ = tx.send(AuthResult::Masquerade); } return; }
        }
    }
}

// §15 SERVER RUNNER
const LISTENER_CLOSE_GRACE: Duration = Duration::from_secs(1);
#[derive(Debug)]
struct ListenerRuntime { endpoint_started: AtomicBool, retired: CancellationToken }
impl Runtime for ListenerRuntime {
    fn new_timer(&self, deadline: Instant) -> Pin<Box<dyn quinn::AsyncTimer>> { quinn::TokioRuntime.new_timer(deadline) }
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        if self.endpoint_started.swap(true, Ordering::Relaxed) { quinn::TokioRuntime.spawn(future); return; }
        let handle = tokio::spawn(future);
        let abort = handle.abort_handle();
        let retired = self.retired.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = handle => {}
                _ = async { retired.cancelled().await; tokio::time::sleep(LISTENER_CLOSE_GRACE).await; } => { abort.abort(); }
            }
        });
    }
    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> { quinn::TokioRuntime.wrap_udp_socket(socket) }
    fn now(&self) -> Instant { quinn::TokioRuntime.now() }
}

pub async fn run(cfg: MirajConfig, cert_resolver: Arc<dyn ResolvesServerCert>, shutdown: CancellationToken) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    if cfg.auth_token.is_empty() { warn!("miraj: auth_token пуст — все аутентификации будут отклоняться"); }
    init_auth_limiter(cfg.auth_rate_per_min);
    spawn_traffic_flusher();

    // ★ NEW: если порт 443 — endpoint принадлежит main.rs (мультиплекс).
    // run() просто ждёт shutdown, метрики/флашер уже запущены.
    if cfg.listen.port() == 443 {
        info!("miraj: multiplex mode on :443 — endpoint owned by main.rs");
        shutdown.cancelled().await;
        flush_user_traffic().await;
        return Ok(());
    }

    let mut tls = rustls::ServerConfig::builder().with_no_client_auth().with_cert_resolver(cert_resolver);
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_server_cfg = QuicServerConfig::try_from(tls).map_err(|e| format!("quic server config: {e}"))?;
    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(cfg.keepalive_interval));
    transport.max_idle_timeout(Some(IdleTimeout::try_from(cfg.idle_timeout).map_err(|e| format!("idle timeout: {e}"))?));
    transport.stream_receive_window(VarInt::from_u64(cfg.stream_window).unwrap_or(VarInt::MAX));
    transport.receive_window(VarInt::from_u64(cfg.conn_window).unwrap_or(VarInt::MAX));
    transport.datagram_receive_buffer_size(Some(cfg.max_datagram_buf));
    transport.datagram_send_buffer_size(cfg.max_datagram_buf);
    if cfg.brutal_tx > 0 { transport.congestion_controller_factory(Arc::new(BrutalFactory { rate: Arc::new(AtomicU64::new(cfg.brutal_tx)) })); info!("miraj: Brutal congestion control @ {} B/s", cfg.brutal_tx); } else { transport.congestion_controller_factory(Arc::new(BbrConfig::default())); info!("miraj: BBR congestion control"); }
    let mut server_config = QuicServerConfigInner::with_crypto(Arc::new(quic_server_cfg));
    server_config.transport_config(Arc::new(transport));
    let obfs = if cfg.obfs_password.is_empty() { None } else { match Salamander::new(cfg.obfs_password.as_bytes()) { Some(s) => { info!("miraj: Salamander obfuscation enabled"); Some(s) } None => { return Err("obfs password must be at least 4 bytes".into()); } } };
    let gecko = if cfg.gecko_enabled { info!("miraj: Gecko fragmentation enabled (max {} bytes)", cfg.gecko_max_size); Some(Arc::new(Mutex::new(GeckoState::new(cfg.gecko_max_size)))) } else { None };
    let std_sock = std::net::UdpSocket::bind(cfg.listen).map_err(|e| format!("bind {}: {e}", cfg.listen))?;
    std_sock.set_nonblocking(true)?;
    std_sock.set_read_timeout(Some(Duration::from_millis(100)))?;
    let retired = CancellationToken::new();
    let runtime: Arc<dyn Runtime> = Arc::new(ListenerRuntime { endpoint_started: AtomicBool::new(false), retired: retired.clone() });
    let inner_sock = runtime.wrap_udp_socket(std_sock).map_err(|e| format!("wrap udp: {e}"))?;
    let socket: Arc<dyn AsyncUdpSocket> = if obfs.is_none() && gecko.is_none() { inner_sock } else { ObfsHopSocket::new(inner_sock, obfs, gecko) };
    let endpoint = Endpoint::new_with_abstract_socket(EndpointConfig::default(), Some(server_config), socket, runtime).map_err(|e| format!("endpoint: {e}"))?;
    info!("miraj: listening on udp://{}", cfg.listen);
    { let retired = retired.clone(); let shutdown = shutdown.clone(); tokio::spawn(async move { shutdown.cancelled().await; retired.cancel(); }); }
    let cfg_arc = Arc::new(cfg);
    let mut conn_count: u64 = 0;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => { METRICS.shutdown_initiated.fetch_add(1, Ordering::Relaxed); info!("miraj: shutdown initiated after {} connections", conn_count); break; }
            accept = endpoint.accept() => match accept {
                Some(incoming) => match incoming.await { Ok(conn) => { conn_count += 1; let cfg_c = cfg_arc.clone(); tokio::spawn(async move { handle_connection(conn, cfg_c).await; }); } Err(e) => { warn!("miraj: handshake failed: {e}"); METRICS.errors_total.fetch_add(1, Ordering::Relaxed); } },
                None => { info!("miraj: endpoint closed after {} connections", conn_count); break; }
            }
        }
    }
    retired.cancel();
    endpoint.close(0u32.into(), b"shutdown");
    let _ = tokio::time::timeout(Duration::from_secs(5), endpoint.wait_idle()).await;
    flush_user_traffic().await;
    info!("miraj: shutdown complete");
    Ok(())
}

// §16 ПУБЛИЧНЫЕ УТИЛИТЫ
pub fn metrics_json() -> serde_json::Value { METRICS.snapshot() }
pub fn metrics_prometheus(prefix: &str) -> String {
    let mut s = String::with_capacity(1024);
    let kv = |name: &str, value: u64| format!("# HELP {p}{n} Miraj {n}\n# TYPE {p}{n} counter\n{p}{n} {v}\n", p = prefix, n = name, v = value);
    let gv = |name: &str, value: u64| format!("# HELP {p}{n} Miraj {n} (gauge)\n# TYPE {p}{n} gauge\n{p}{n} {v}\n", p = prefix, n = name, v = value);
    s += &kv("connections_total", METRICS.connections_total.load(Ordering::Relaxed));
    s += &gv("connections_active", METRICS.connections_active.load(Ordering::Relaxed));
    s += &kv("auth_ok", METRICS.auth_ok.load(Ordering::Relaxed));
    s += &kv("auth_fail", METRICS.auth_fail.load(Ordering::Relaxed));
    s += &kv("tcp_streams_total", METRICS.tcp_streams_total.load(Ordering::Relaxed));
    s += &kv("udp_sessions_total", METRICS.udp_sessions_total.load(Ordering::Relaxed));
    s += &kv("tcp_bytes_up", METRICS.tcp_bytes_up.load(Ordering::Relaxed));
    s += &kv("tcp_bytes_down", METRICS.tcp_bytes_down.load(Ordering::Relaxed));
    s += &kv("udp_datagrams_in", METRICS.udp_datagrams_in.load(Ordering::Relaxed));
    s += &kv("udp_datagrams_out", METRICS.udp_datagrams_out.load(Ordering::Relaxed));
    s += &kv("masquerades", METRICS.masquerades.load(Ordering::Relaxed));
    s += &kv("errors_total", METRICS.errors_total.load(Ordering::Relaxed));
    s += &gv("udp_sessions_active", METRICS.udp_sessions_active.load(Ordering::Relaxed));
    s += &kv("udp_sessions_rejected", METRICS.udp_sessions_rejected.load(Ordering::Relaxed));
    s += &kv("udp_datagrams_dropped", METRICS.udp_datagrams_dropped.load(Ordering::Relaxed));
    s += &kv("udp_datagrams_invalid", METRICS.udp_datagrams_invalid.load(Ordering::Relaxed));
    s += &kv("auth_rate_limited", METRICS.auth_rate_limited.load(Ordering::Relaxed));
    s += &kv("tcp_connections_refused", METRICS.tcp_connections_refused.load(Ordering::Relaxed));
    s += &kv("shutdown_initiated", METRICS.shutdown_initiated.load(Ordering::Relaxed));
    s
}

// §17 ADMIN API
use axum::body::Body;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use serde_json::json;
fn okj(v: serde_json::Value) -> Response<Body> { Response::builder().status(StatusCode::OK).header("content-type", "application/json").header("cache-control", "no-store").body(Body::from(v.to_string())).unwrap_or_else(|_| Response::new(Body::empty())) }
fn errj(status: StatusCode, msg: impl Into<String>) -> Response<Body> { Response::builder().status(status).header("content-type", "application/json").body(Body::from(json!({"error": msg.into()}).to_string())).unwrap_or_else(|_| Response::new(Body::empty())) }
async fn db_host(db: &Arc<db::DbManager>) -> String { let map = match db.config_map().await { Ok(m) => m, Err(_) => return "0.0.0.0".into() }; map.get("address").or_else(|| map.get("acme_ip")).map(|s| s.trim_matches(|c: char| c == '"' || c == '\'').to_string()).filter(|s| !s.is_empty() && s != "0.0.0.0").unwrap_or_else(|| "0.0.0.0".into()) }
async fn get_omni_pool() -> Result<Arc<std::sync::Mutex<rusqlite::Connection>>, Response<Body>> { let db = db::global().ok_or_else(|| errj(StatusCode::SERVICE_UNAVAILABLE, "db not initialized"))?; let omni = db.conns.read().await.get("OmniDB").cloned().ok_or_else(|| errj(StatusCode::SERVICE_UNAVAILABLE, "OmniDB missing"))?; let db::Pool::Sqlite(p) = &omni.pool; Ok(p.clone()) }
pub async fn dispatch_api(method: Method, endpoint: String, _query: HashMap<String, String>, _headers: HeaderMap, body: Bytes, _client_ip: String) -> Response<Body> {
    let ep = endpoint.as_str();
    if ep == "miraj/metrics" && method == Method::GET { return okj(metrics_json()); }
    if ep == "miraj/config" && method == Method::GET {
        let db = match db::global() { Some(d) => d, None => return errj(StatusCode::SERVICE_UNAVAILABLE, "db not initialized") };
        let map = match db.config_map().await { Ok(m) => m, Err(e) => return errj(StatusCode::INTERNAL_SERVER_ERROR, e) };
        let cfg = MirajConfig::from_map(&map);
        return okj(json!({ "enabled": cfg.enabled, "listen": cfg.listen.to_string(), "auth_token": cfg.auth_token, "masquerade_url": cfg.masquerade_url, "udp_enabled": cfg.udp_enabled, "brutal_tx": cfg.brutal_tx, "obfs_password": cfg.obfs_password, "gecko_enabled": cfg.gecko_enabled, "gecko_max_size": cfg.gecko_max_size, "idle_timeout_secs": cfg.idle_timeout.as_secs(), "udp_idle_timeout_secs": cfg.udp_idle_timeout.as_secs(), "udp_max_sessions": cfg.udp_max_sessions, "udp_defrag_timeout_secs": cfg.udp_defrag_timeout.as_secs(), "udp_max_mtu": cfg.udp_max_mtu, "auth_rate_per_min": cfg.auth_rate_per_min }));
    }
    if ep == "miraj/config" && method == Method::POST {
        let v: serde_json::Value = match serde_json::from_slice(&body) { Ok(v) => v, Err(e) => return errj(StatusCode::BAD_REQUEST, format!("json: {e}")) };
        let obj = match v.as_object() { Some(o) => o, None => return errj(StatusCode::BAD_REQUEST, "body must be object") };
        let mut items: Vec<(String, String)> = Vec::new();
        for (k, val) in obj {
            let key = match k.as_str() { "enabled" => "miraj.enabled", "listen" => "miraj.listen", "auth_token" => "miraj.auth_token", "masquerade_url" => "miraj.masquerade_url", "udp_enabled" => "miraj.udp_enabled", "brutal_tx" => "miraj.brutal_tx", "obfs_password" => "miraj.obfs_password", "gecko_enabled" => "miraj.gecko_enabled", "gecko_max_size" => "miraj.gecko_max_size", "idle_timeout_secs" => "miraj.idle_timeout_secs", "udp_idle_timeout_secs" => "miraj.udp_idle_timeout_secs", "udp_max_sessions" => "miraj.udp_max_sessions", "udp_defrag_timeout_secs" => "miraj.udp_defrag_timeout_secs", "udp_max_mtu" => "miraj.udp_max_mtu", "auth_rate_per_min" => "miraj.auth_rate_per_min", _ => continue };
            let v_str = if let Some(s) = val.as_str() { s.to_string() } else if let Some(b) = val.as_bool() { if b { "true".into() } else { "false".into() } } else if let Some(n) = val.as_u64() { n.to_string() } else if val.is_null() { String::new() } else { val.to_string() };
            items.push((key.to_string(), v_str));
        }
        let db = match db::global() { Some(d) => d, None => return errj(StatusCode::SERVICE_UNAVAILABLE, "db not initialized") };
        return match db.config_set_bulk(&items).await { Ok(_) => okj(json!({ "ok": true, "updated": items.len(), "note": "restart required to apply" })), Err(e) => errj(StatusCode::INTERNAL_SERVER_ERROR, e) };
    }
    if ep == "miraj/clients" && method == Method::GET {
        let p = match get_omni_pool().await { Ok(p) => p, Err(r) => return r };
        let result = tokio::task::spawn_blocking(move || -> Result<Vec<serde_json::Value>, String> { let g = p.lock().map_err(|e| e.to_string())?; ensure_miraj_users_table(&g); let mut stmt = g.prepare("SELECT id, name, enabled, bytes_in, bytes_out, created_at FROM miraj_users ORDER BY id ASC").map_err(|e| e.to_string())?; let rows = stmt.query_map([], |r| Ok(json!({ "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "enabled": r.get::<_, i64>(2)? == 1, "bytes_in": r.get::<_, i64>(3)?, "bytes_out": r.get::<_, i64>(4)?, "created_at": r.get::<_, i64>(5)? }))).map_err(|e| e.to_string())?; Ok(rows.filter_map(Result::ok).collect()) }).await;
        return match result { Ok(Ok(rows)) => okj(serde_json::Value::Array(rows)), Ok(Err(e)) => errj(StatusCode::INTERNAL_SERVER_ERROR, e), Err(e) => errj(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")) };
    }
    if ep == "miraj/clients" && method == Method::POST {
        let v: serde_json::Value = match serde_json::from_slice(&body) { Ok(v) => v, Err(e) => return errj(StatusCode::BAD_REQUEST, format!("json: {e}")) };
        let name = match v.get("name").and_then(|x| x.as_str()) { Some(n) if !n.trim().is_empty() => n.trim().to_string(), _ => return errj(StatusCode::BAD_REQUEST, "name required") };
        let password = generate_user_password();
        let p = match get_omni_pool().await { Ok(p) => p, Err(r) => return r };
        let name_c = name.clone();
        let password_c = password.clone();
        let ts = now_ts();
        let result = tokio::task::spawn_blocking(move || -> Result<i64, String> { let g = p.lock().map_err(|e| e.to_string())?; ensure_miraj_users_table(&g); g.execute("INSERT INTO miraj_users (name, password, enabled, created_at, updated_at) VALUES (?1, ?2, 1, ?3, ?3)", rusqlite::params![name_c, password_c, ts]).map_err(|e| format!("insert: {e}"))?; Ok(g.last_insert_rowid()) }).await;
        match result {
            Ok(Ok(id)) => { let db = db::global().unwrap(); let host = db_host(&db).await; let cfg = match db.config_map().await { Ok(m) => MirajConfig::from_map(&m), Err(_) => MirajConfig::default() }; let port = cfg.listen.port(); let uri = format!("hysteria2://{}@{}:{}?insecure=1&sni={}", password, host, port, host); return okj(json!({"ok": true, "id": id, "uri": uri})); }
            Ok(Err(e)) => return errj(StatusCode::BAD_REQUEST, e),
            Err(e) => return errj(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")),
        }
    }
    if let Some(rest) = ep.strip_prefix("miraj/clients/") {
        let mut parts = rest.splitn(2, '/');
        let id_str = parts.next().unwrap_or("");
        let action = parts.next().unwrap_or("");
        let id: i64 = match id_str.parse() { Ok(v) => v, Err(_) => return errj(StatusCode::BAD_REQUEST, "invalid id") };
        if method == Method::DELETE && action.is_empty() {
            let p = match get_omni_pool().await { Ok(p) => p, Err(r) => return r };
            let result = tokio::task::spawn_blocking(move || -> Result<(), String> { let g = p.lock().map_err(|e| e.to_string())?; g.execute("DELETE FROM miraj_users WHERE id = ?1", rusqlite::params![id]).map_err(|e| e.to_string())?; Ok(()) }).await;
            return match result { Ok(Ok(_)) => okj(json!({"ok": true})), Ok(Err(e)) => errj(StatusCode::INTERNAL_SERVER_ERROR, e), Err(e) => errj(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")) };
        }
        if method == Method::POST && (action == "enable" || action == "disable") {
            let enable = action == "enable";
            let p = match get_omni_pool().await { Ok(p) => p, Err(r) => return r };
            let ts = now_ts();
            let result = tokio::task::spawn_blocking(move || -> Result<(), String> { let g = p.lock().map_err(|e| e.to_string())?; g.execute("UPDATE miraj_users SET enabled = ?1, updated_at = ?2 WHERE id = ?3", rusqlite::params![if enable { 1 } else { 0 }, ts, id]).map_err(|e| e.to_string())?; Ok(()) }).await;
            return match result { Ok(Ok(_)) => okj(json!({"ok": true, "enabled": enable})), Ok(Err(e)) => errj(StatusCode::INTERNAL_SERVER_ERROR, e), Err(e) => errj(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")) };
        }
        if method == Method::GET && action == "uri" {
            let p = match get_omni_pool().await { Ok(p) => p, Err(r) => return r };
            let result = tokio::task::spawn_blocking(move || -> Result<Option<String>, String> { let g = p.lock().map_err(|e| e.to_string())?; Ok(g.query_row("SELECT password FROM miraj_users WHERE id = ?1", rusqlite::params![id], |r| r.get::<_, String>(0)).ok()) }).await;
            let password = match result { Ok(Ok(Some(pw))) => pw, Ok(Ok(None)) => return errj(StatusCode::NOT_FOUND, "user not found"), Ok(Err(e)) => return errj(StatusCode::INTERNAL_SERVER_ERROR, e), Err(e) => return errj(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")) };
            let db = db::global().unwrap();
            let host = db_host(&db).await;
            let cfg = match db.config_map().await { Ok(m) => MirajConfig::from_map(&m), Err(_) => MirajConfig::default() };
            let port = cfg.listen.port();
            let uri = format!("hysteria2://{}@{}:{}?insecure=1&sni={}", password, host, port, host);
            return okj(json!({"uri": uri, "port": port, "host": host}));
        }
        return errj(StatusCode::NOT_FOUND, format!("unknown miraj client action: {action}"));
    }
    errj(StatusCode::NOT_FOUND, format!("unknown miraj endpoint: {ep}"))
}
pub fn generate_user_password() -> String { use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine}; let mut bytes = [0u8; 24]; rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes); URL_SAFE_NO_PAD.encode(&bytes) }