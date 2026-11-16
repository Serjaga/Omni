use omni_core::crypto;
// src/vpn.rs — VPN для OmniRS

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use axum::body::Body;
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::Response;
use chrono::{DateTime, Utc};
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::process::Command;
use tokio::sync::Mutex;

// ===== Config =====
#[derive(Clone, Debug, Deserialize)] #[serde(default)] pub struct VpnConfig { pub enabled: bool, pub interface: String, pub default_mtu: i64, pub default_dns: Vec<String>, pub default_allowed_ips: Vec<String>, pub default_persistent_keepalive: i64, pub firewall_enabled: bool, pub acme_ip: Option<String> }
impl Default for VpnConfig { fn default() -> Self { Self { enabled: false, interface: "vpn0".into(), default_mtu: 1420, default_dns: vec!["1.1.1.1".into(), "2606:4700:4700::1111".into()], default_allowed_ips: vec!["0.0.0.0/0".into(), "::/0".into()], default_persistent_keepalive: 0, firewall_enabled: false, acme_ip: None } } }

// ===== Fixed interface names =====
pub const VPN_IFACE: &str = "vpn0";
pub const OBFS_IFACE: &str = "obfs0";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IfaceMode { Vpn, Obfs }

// ===== Models =====
#[derive(Clone, Debug, Serialize)] pub struct Client {
    pub id: i64, pub user_id: i64, pub interface_id: String, pub name: String, pub password: String,
    // obfs (:880)
    pub ipv4_address: String, pub ipv6_address: String,
    // vpn (:888)
    pub vpn_ipv4_address: String, pub vpn_ipv6_address: String,
    pub private_key: String, pub public_key: String, pub pre_shared_key: String,
    pub allowed_ips: Option<Vec<String>>, pub server_allowed_ips: Vec<String>, pub firewall_ips: Option<Vec<String>>,
    pub persistent_keepalive: i64, pub mtu: i64, pub dns: Option<Vec<String>>,
    pub server_endpoint: Option<String>, pub expires_at: Option<String>, pub enabled: i64,
    pub j_c: Option<i64>, pub j_min: Option<i64>, pub j_max: Option<i64>,
    pub i1: Option<String>, pub i2: Option<String>, pub i3: Option<String>, pub i4: Option<String>, pub i5: Option<String>,
    pub content_padding_addition: Option<String>,
    pub rekey_after_time: Option<String>,
    pub rekey_timeout: Option<String>,
    pub reject_after_time: Option<String>,
    pub keepalive_timeout: Option<String>,
    pub max_handshake_attempts: Option<String>,
    pub disable_cookies: Option<i64>,
    pub created_at: String, pub updated_at: String,
}

#[derive(Clone, Debug, Serialize)] pub struct VpnInterface {
    pub name: String, pub device: String,
    pub port: i64, pub vpn_port: i64,
    pub private_key: String, pub public_key: String,
    pub ipv4_cidr: String, pub ipv6_cidr: String,
    pub vpn_ipv4_cidr: String, pub vpn_ipv6_cidr: String,
    pub mtu: i64, pub routing_table: String, pub enabled: i64, pub firewall_enabled: i64,
    pub j_c: Option<i64>, pub j_min: Option<i64>, pub j_max: Option<i64>,
    pub s1: Option<i64>, pub s2: Option<i64>, pub s3: Option<i64>, pub s4: Option<i64>,
    pub h1: Option<String>, pub h2: Option<String>, pub h3: Option<String>, pub h4: Option<String>,
    pub i1: Option<String>, pub i2: Option<String>, pub i3: Option<String>, pub i4: Option<String>, pub i5: Option<String>,
    pub header_protection_key: Option<String>,
    pub content_padding_addition: Option<String>,
    pub rekey_after_time: Option<String>,
    pub rekey_timeout: Option<String>,
    pub reject_after_time: Option<String>,
    pub keepalive_timeout: Option<String>,
    pub max_handshake_attempts: Option<String>,
    pub random_trailers: Option<i64>,
    pub disable_cookies: Option<i64>,
    pub created_at: String, pub updated_at: String,
}

#[derive(Clone, Debug, Serialize)] pub struct Hooks { pub id: String, pub pre_up: String, pub post_up: String, pub pre_down: String, pub post_down: String }
#[derive(Clone, Debug, Serialize)] pub struct UserConfig { pub id: String, pub default_mtu: i64, pub default_persistent_keepalive: i64, pub default_dns: Vec<String>, pub default_allowed_ips: Vec<String>, pub default_j_c: Option<i64>, pub default_j_min: Option<i64>, pub default_j_max: Option<i64>, pub default_i1: Option<String>, pub default_i2: Option<String>, pub default_i3: Option<String>, pub default_i4: Option<String>, pub default_i5: Option<String>, pub host: String, pub port: i64 }
#[derive(Clone, Debug, Serialize)] pub struct OneTimeLink { pub id: i64, pub one_time_link: String, pub expires_at: String }
#[derive(Clone, Debug)] pub struct VpnDumpLine { pub public_key: String, pub endpoint: Option<String>, pub latest_handshake_at: Option<DateTime<Utc>>, pub transfer_rx: i64, pub transfer_tx: i64 }

// ===== State =====
pub struct VpnState { pub cfg: VpnConfig, pub conf_dir: String, pub firewall_lock: Mutex<()>, pub iptables_ok: AtomicBool }
static STATE: OnceLock<Option<Arc<VpnState>>> = OnceLock::new();
pub fn state() -> Option<Arc<VpnState>> { STATE.get().and_then(|s| s.clone()) }

// ===== Interface derivation helpers =====
fn vpn_interface(base: &VpnInterface) -> VpnInterface {
    let mut i = base.clone();
    i.name = VPN_IFACE.to_string();
    i.port = base.vpn_port;
    i.ipv4_cidr = base.vpn_ipv4_cidr.clone();
    i.ipv6_cidr = base.vpn_ipv6_cidr.clone();
    i.j_c = None; i.j_min = None; i.j_max = None;
    i.s1 = None; i.s2 = None; i.s3 = None; i.s4 = None;
    i.h1 = None; i.h2 = None; i.h3 = None; i.h4 = None;
    i.i1 = None; i.i2 = None; i.i3 = None; i.i4 = None; i.i5 = None;
    i.header_protection_key = None;
    i.content_padding_addition = None;
    i.rekey_after_time = None; i.rekey_timeout = None;
    i.reject_after_time = None; i.keepalive_timeout = None;
    i.max_handshake_attempts = None; i.random_trailers = None;
    i.disable_cookies = None;
    i
}

fn obfs_interface(base: &VpnInterface) -> VpnInterface {
    let mut i = base.clone();
    i.name = OBFS_IFACE.to_string();
    i
}

fn clients_for_mode(clients: &[Client], mode: IfaceMode) -> Vec<Client> {
    if mode == IfaceMode::Obfs { return clients.to_vec(); }
    clients.iter().map(|c| {
        let mut c = c.clone();
        c.ipv4_address = c.vpn_ipv4_address.clone();
        c.ipv6_address = c.vpn_ipv6_address.clone();
        c
    }).collect()
}


fn parse_range_lower_bound(s: &str) -> Option<u32> {
    let s = s.trim();
    if s.is_empty() { return None; }
    s.split('-').next().unwrap_or(s).trim().parse::<u32>().ok()
}


fn bool_flag_u8(s: &Option<i64>) -> Option<u8> { s.map(|v| if v != 0 { 1u8 } else { 0u8 }) }

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || s.len() % 2 != 0 { return None; }
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < s.len() { let b = u8::from_str_radix(&s[i..i + 2], 16).ok()?; out.push(b); i += 2; }
    Some(out)
}

// ============================================================================
// UAPI constants — под ядро 1.0.20260929+awg (AWG 1.0/1.5)
// ============================================================================
pub mod uapi;

// ============================================================================
// crypto — X25519 + base64 + keygen
// ============================================================================

// ============================================================================
// netlink
// ============================================================================
mod netlink;

// ============================================================================
// iface
// ============================================================================
mod iface;

// ============================================================================
// DB layer
// ============================================================================
pub mod db;

// ============================================================================
// Template + Config generators
// ============================================================================
fn template_replace(t: &str, iface: &VpnInterface) -> String {
    let flat = t.replace(['\r', '\n'], " ");
    flat.replace("{{ipv4Cidr}}", &iface.ipv4_cidr)
        .replace("{{ipv6Cidr}}", &iface.ipv6_cidr)
        .replace("{{device}}", &iface.device)
        .replace("{{interface}}", &iface.name)
        .replace("{{port}}", &iface.port.to_string())
        .replace("{{uiPort}}", "800")
}
fn format_endpoint(host: &str, port: i64) -> String {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<Ipv6Addr>().is_ok() { format!("[{bare}]:{port}") } else { format!("{bare}:{port}") }
}
fn clean_filename(name: &str) -> Option<String> {
    let s: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || "=+.-_".contains(c) { c } else { '-' }).collect();
    let s = s.trim_matches('-').to_string();
    let s: String = s.chars().take(32).collect();
    if s.is_empty() { None } else { Some(s) }
}

fn generate_client_config_vpn(iface: &VpnInterface, uc: &UserConfig, c: &Client) -> String {
    let v4 = if !c.vpn_ipv4_address.is_empty() { &c.vpn_ipv4_address } else { &c.ipv4_address };
    let v6 = if !c.vpn_ipv6_address.is_empty() { &c.vpn_ipv6_address } else { &c.ipv6_address };
    let address = format!("{}/32, {}/128", v4, v6);
    let mut iface_extras = String::new();
    let dns = c.dns.clone().unwrap_or_else(|| uc.default_dns.clone());
    if !dns.is_empty() { iface_extras.push_str(&format!("DNS = {}\n", dns.join(", "))); }
    iface_extras.push_str(&format!("MTU = {}\n", c.mtu));

    let allowed = c.allowed_ips.clone()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| uc.default_allowed_ips.clone())
        .join(", ");
    let allowed = if allowed.trim().is_empty() { "0.0.0.0/0, ::/0".to_string() } else { allowed };
    let endpoint = format_endpoint(&uc.host, iface.vpn_port);

    format!(
        "[Interface]\nPrivateKey = {}\nAddress = {}\n{}[Peer]\nPublicKey = {}\nPresharedKey = {}\nAllowedIPs = {}\nPersistentKeepalive = {}\nEndpoint = {}\n",
        c.private_key, address, iface_extras,
        iface.public_key, c.pre_shared_key, allowed, c.persistent_keepalive, endpoint,
    )
}

fn generate_client_config_obfs(iface: &VpnInterface, uc: &UserConfig, c: &Client) -> String {
    let address = format!("{}/32, {}/128", c.ipv4_address, c.ipv6_address);
    let mut iface_extras = String::new();
    let dns = c.dns.clone().unwrap_or_else(|| uc.default_dns.clone());
    if !dns.is_empty() { iface_extras.push_str(&format!("DNS = {}\n", dns.join(", "))); }
    iface_extras.push_str(&format!("MTU = {}\n", c.mtu));

    if let Some(v) = c.j_c.or(iface.j_c)     { iface_extras.push_str(&format!("Jc = {}\n", v)); }
    if let Some(v) = c.j_min.or(iface.j_min) { iface_extras.push_str(&format!("Jmin = {}\n", v)); }
    if let Some(v) = c.j_max.or(iface.j_max) { iface_extras.push_str(&format!("Jmax = {}\n", v)); }
    if let Some(v) = iface.s1                { iface_extras.push_str(&format!("S1 = {}\n", v)); }
    if let Some(v) = iface.s2                { iface_extras.push_str(&format!("S2 = {}\n", v)); }
    if let Some(v) = iface.s3                { iface_extras.push_str(&format!("S3 = {}\n", v)); }
    if let Some(v) = iface.s4                { iface_extras.push_str(&format!("S4 = {}\n", v)); }
    if let Some(s) = &iface.h1               { iface_extras.push_str(&format!("H1 = {}\n", s)); }
    if let Some(s) = &iface.h2               { iface_extras.push_str(&format!("H2 = {}\n", s)); }
    if let Some(s) = &iface.h3               { iface_extras.push_str(&format!("H3 = {}\n", s)); }
    if let Some(s) = &iface.h4               { iface_extras.push_str(&format!("H4 = {}\n", s)); }

    let allowed = c.allowed_ips.clone()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| uc.default_allowed_ips.clone())
        .join(", ");
    let allowed = if allowed.trim().is_empty() { "0.0.0.0/0, ::/0".to_string() } else { allowed };
    let endpoint = format_endpoint(&uc.host, iface.port);

    format!(
        "[Interface]\nPrivateKey = {}\nAddress = {}\n{}[Peer]\nPublicKey = {}\nPresharedKey = {}\nAllowedIPs = {}\nPersistentKeepalive = {}\nEndpoint = {}\n",
        c.private_key, address, iface_extras,
        iface.public_key, c.pre_shared_key, allowed, c.persistent_keepalive, endpoint,
    )
}

fn generate_amnezia_vpn_url(
    iface: &VpnInterface,
    uc: &UserConfig,
    c: &Client,
) -> Result<String, String> {
    use std::io::Write;
    let conf = generate_client_config_obfs(iface, uc, c);
    let client_ip = format!("{}/32, {}/128", c.ipv4_address, c.ipv6_address);
    let allowed_ips: Vec<String> = c.allowed_ips.clone()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| uc.default_allowed_ips.clone());

    let inner = serde_json::json!({
        "allowed_ips": allowed_ips,
        "client_ip": client_ip,
        "client_priv_key": c.private_key,
        "config": conf,
        "hostName": uc.host,
        "mtu": c.mtu.to_string(),
        "persistent_keep_alive": c.persistent_keepalive.to_string(),
        "port": iface.port.to_string(),
        "psk_key": c.pre_shared_key,
        "server_pub_key": iface.public_key,
    });
    let inner_str = inner.to_string();

    let outer = serde_json::json!({
    "containers": [{
        "container": "vpn",
        "vpn": {
            "isThirdPartyConfig": true,
            "last_config": inner_str,
            "hostName": uc.host,
            "mtu": c.mtu.to_string(),
            "port": iface.port.to_string(),
            "psk_key": c.pre_shared_key,
            "server_pub_key": iface.public_key,
        },
        "port": iface.port.to_string(),
        "transport_proto": "udp",
    }],
    "defaultContainer": "vpn",
        "description": format!("OmniRS {}", uc.host),
        "hostName": uc.host,
    });
    let outer_str = outer.to_string();

    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(outer_str.as_bytes()).map_err(|e| format!("zlib write: {e}"))?;
    let compressed = encoder.finish().map_err(|e| format!("zlib finish: {e}"))?;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    Ok(format!("vpn://{}", URL_SAFE_NO_PAD.encode(&compressed)))
}

pub fn write_server_conf(iface: &VpnInterface, clients: &[Client]) -> Result<String, String> {
    let mut lines = Vec::new();
    lines.push("[Interface]".to_string());
    lines.push(format!("PrivateKey = {}", iface.private_key));
    let cidr4: Ipv4Net = iface.ipv4_cidr.parse().map_err(|e| format!("ipv4: {e}"))?;
    let cidr6: Ipv6Net = iface.ipv6_cidr.parse().map_err(|e| format!("ipv6: {e}"))?;
    let addr4 = Ipv4Addr::from(u32::from(cidr4.network()) + 1);
    let addr6 = Ipv6Addr::from(u128::from(cidr6.network()) + 1);
    lines.push(format!("Address = {}/{}, {}/{}", addr4, cidr4.prefix_len(), addr6, cidr6.prefix_len()));
    lines.push(format!("ListenPort = {}", iface.port));
    lines.push(format!("MTU = {}", iface.mtu));
    if !iface.routing_table.is_empty() { lines.push(format!("Table = {}", iface.routing_table)); }

    if let Some(v) = iface.j_c { lines.push(format!("Jc = {}", v)); }
    if let Some(v) = iface.j_min { lines.push(format!("Jmin = {}", v)); }
    if let Some(v) = iface.j_max { lines.push(format!("Jmax = {}", v)); }
    if let Some(v) = iface.s1 { lines.push(format!("S1 = {}", v)); }
    if let Some(v) = iface.s2 { lines.push(format!("S2 = {}", v)); }
    if let Some(s) = &iface.h1 { lines.push(format!("H1 = {}", s)); }
    if let Some(s) = &iface.h2 { lines.push(format!("H2 = {}", s)); }
    if let Some(s) = &iface.h3 { lines.push(format!("H3 = {}", s)); }
    if let Some(s) = &iface.h4 { lines.push(format!("H4 = {}", s)); }

    for c in clients {
        if c.enabled == 0 { continue; }
        if c.ipv4_address.is_empty() && c.ipv6_address.is_empty() { continue; }
        lines.push(String::new());
        lines.push(format!("# Client: {} ({})", c.name, c.id));
        lines.push("[Peer]".to_string());
        lines.push(format!("PublicKey = {}", c.public_key));
        lines.push(format!("PresharedKey = {}", c.pre_shared_key));
        let mut ips = Vec::new();
        if !c.ipv4_address.is_empty() { ips.push(format!("{}/32", c.ipv4_address)); }
        if !c.ipv6_address.is_empty() { ips.push(format!("{}/128", c.ipv6_address)); }
        lines.push(format!("AllowedIPs = {}", ips.join(", ")));
        if c.persistent_keepalive > 0 { lines.push(format!("PersistentKeepalive = {}", c.persistent_keepalive)); }
    }
    let body = lines.join("\n");
    let path = format!("/etc/wireguard/{}.conf", iface.name);
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&path, &body).map_err(|e| format!("write {path}: {e}"))?;
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)); }
    Ok(path)
}

// ============================================================================
// IP allocation
// ============================================================================
fn next_ip(cidr: &str, used: &HashSet<String>) -> Result<String, String> {
    let net: ipnet::IpNet = cidr.parse().map_err(|_| format!("bad cidr: {cidr}"))?;
    match net {
        ipnet::IpNet::V4(n) => {
            let start = u32::from(n.network()); let end = u32::from(n.broadcast());
            for i in (start + 2)..=end.saturating_sub(1) { let ip = Ipv4Addr::from(i).to_string(); if !used.contains(&ip) { return Ok(ip); } }
        }
        ipnet::IpNet::V6(n) => {
            let start = u128::from(n.network()); let end = u128::from(n.broadcast());
            for offset in 2u128..=100_000 { let i = start + offset; if i >= end { break; } let ip = Ipv6Addr::from(i).to_string(); if !used.contains(&ip) { return Ok(ip); } }
        }
    }
    Err(format!("IP pool exhausted: {cidr}"))
}

// ============================================================================
// QR
// ============================================================================
fn encode_qr_svg(data: &str) -> Result<String, String> {
    use qrcode::render::svg; use qrcode::QrCode;
    let code = QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::H)
        .or_else(|_| QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::Q))
        .or_else(|_| QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::M))
        .or_else(|_| QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::L))
        .map_err(|e| format!("qr: {e}"))?;
    Ok(code.render::<svg::Color>().min_dimensions(200, 200).dark_color(svg::Color("#0e1118")).light_color(svg::Color("#ffffff")).build())
}

// ============================================================================
// DB wrappers
// ============================================================================
async fn omni_with<F, T>(_st: &VpnState, f: F) -> Result<T, String> where F: FnOnce(&rusqlite::Connection) -> rusqlite::Result<T> + Send + 'static, T: Send + 'static { tokio::task::spawn_blocking(move || { let conn = omni_db::open_omni().map_err(|e| format!("omni open: {e}"))?; f(&conn).map_err(|e| format!("omni: {e}")) }).await.map_err(|e| format!("join: {e}"))? }
async fn vpn_with<F, T>(_st: &VpnState, f: F) -> Result<T, String> where F: FnOnce(&rusqlite::Connection) -> rusqlite::Result<T> + Send + 'static, T: Send + 'static { tokio::task::spawn_blocking(move || { let conn = omni_db::open_vpn().map_err(|e| format!("vpn open: {e}"))?; f(&conn).map_err(|e| format!("vpn: {e}")) }).await.map_err(|e| format!("join: {e}"))? }
async fn both_with<F, T>(_st: &VpnState, f: F) -> Result<T, String> where F: FnOnce(&rusqlite::Connection, &rusqlite::Connection) -> rusqlite::Result<T> + Send + 'static, T: Send + 'static { tokio::task::spawn_blocking(move || { let omni = omni_db::open_omni().map_err(|e| format!("omni open: {e}"))?; let vpn = omni_db::open_vpn().map_err(|e| format!("vpn open: {e}"))?; f(&omni, &vpn).map_err(|e| format!("both: {e}")) }).await.map_err(|e| format!("join: {e}"))? }

async fn get_interface(st: &VpnState) -> Result<VpnInterface, String> { omni_with(st, |c| db::get_interface(c)).await }
async fn get_hooks(st: &VpnState) -> Result<Hooks, String> { omni_with(st, |c| db::get_hooks(c)).await }
async fn get_user_config(st: &VpnState) -> Result<UserConfig, String> { omni_with(st, |c| db::get_user_config(c)).await }
async fn list_clients(st: &VpnState) -> Result<Vec<Client>, String> { both_with(st, |o, v| db::list_clients(o, v)).await }
async fn get_client_by_id(st: &VpnState, id: i64) -> Result<Option<Client>, String> { both_with(st, move |o, v| db::find_client_by_id(o, v, id)).await }
async fn insert_client(st: &VpnState, client: Client) -> Result<i64, String> { both_with(st, move |o, v| db::insert_client(o, v, &client)).await }
async fn update_client_row(st: &VpnState, id: i64, old_name: String, client: Client) -> Result<(), String> { both_with(st, move |o, v| db::update_client(o, v, id, &old_name, &client)).await }
async fn toggle_client_row(st: &VpnState, id: i64, enabled: bool) -> Result<(), String> { both_with(st, move |o, v| db::toggle_client(o, v, id, enabled)).await }
async fn delete_client_row(st: &VpnState, id: i64) -> Result<(), String> { both_with(st, move |o, v| db::delete_client(o, v, id)).await }

async fn get_otl(_st: &VpnState, token: &str) -> Result<Option<OneTimeLink>, String> { let t = token.to_string(); let t2 = token.to_string(); let res = vpn_with(_st, move |c| db::get_otl(c, &t)).await?; Ok(res.map(|(id, exp)| OneTimeLink { id, one_time_link: t2, expires_at: exp })) }
async fn upsert_otl(st: &VpnState, id: i64, token: &str, expires_at: &str) -> Result<(), String> { let t = token.to_string(); let e = expires_at.to_string(); vpn_with(st, move |c| db::upsert_otl(c, id, &t, &e)).await }
async fn erase_otl(st: &VpnState, id: i64, _expires_at: &str) -> Result<(), String> { vpn_with(st, move |c| db::delete_otl(c, id)).await }

// ============================================================================
// Core operations
// ============================================================================
async fn save_config(st: &VpnState) -> Result<(), String> {
    let iface = get_interface(st).await?;
    let hooks = get_hooks(st).await?;
    let clients = list_clients(st).await?;
    let uc = get_user_config(st).await?;

    let vpn = vpn_interface(&iface);
    let obfs = obfs_interface(&iface);

    if let Err(e) = write_server_conf(&vpn, &clients_for_mode(&clients, IfaceMode::Vpn)) {
        eprintln!("[VPN] write_server_conf {}: {e} (continuing with netlink)", vpn.name);
    }
    if let Err(e) = write_server_conf(&obfs, &clients_for_mode(&clients, IfaceMode::Obfs)) {
        eprintln!("[VPN] write_server_conf {}: {e} (continuing with netlink)", obfs.name);
    }

    iface::setup(&iface, &hooks, &uc, &clients).await
}
async fn ensure_endpoint_host(st: &VpnState, fallback: Option<&str>) -> Result<(), String> {
    let Some(ip) = fallback else { return Ok(()); };
    let uc = get_user_config(st).await?;
    if !uc.host.is_empty() { return Ok(()); }
    let ip = ip.to_string();
    omni_with(st, move |c| c.execute("UPDATE \"OmniVPN\" SET host=?1, updated_at=CURRENT_TIMESTAMP WHERE id=1", rusqlite::params![ip]).map(|_| ())).await
}

async fn gen_obfs_defaults() -> Result<(), String> {
    let mut rng_bytes = [0u8; 32];
    {
        use std::io::Read;
        let mut f = std::fs::File::open("/dev/urandom").map_err(|e| format!("urandom: {e}"))?;
        f.read_exact(&mut rng_bytes).map_err(|e| format!("urandom read: {e}"))?;
    }
    let mut seed = u64::from_le_bytes([
        rng_bytes[0], rng_bytes[1], rng_bytes[2], rng_bytes[3],
        rng_bytes[4], rng_bytes[5], rng_bytes[6], rng_bytes[7],
    ]) ^ 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        seed ^= seed >> 12; seed ^= seed << 25; seed ^= seed >> 27;
        seed.wrapping_mul(0x2545F4914F6CDD1D)
    };
    let mut pick = |lo: u64, hi: u64| -> u64 { lo + (next() % (hi - lo + 1)) };

    let jc: u16 = pick(1, 128) as u16;
    let jmin: u16 = pick(0, 1279) as u16;
    let jmax: u16 = pick(jmin as u64, 1280) as u16;
    let s1: u16 = pick(15, 150) as u16;
    let s2: u16 = pick(15, 150) as u16;
    let mut hs = std::collections::HashSet::new();
    while hs.len() < 4 { hs.insert(pick(5, 2147483647) as u32); }
    let hs: Vec<u32> = hs.into_iter().collect();
    let (h1, h2, h3, h4) = (hs[0].to_string(), hs[1].to_string(), hs[2].to_string(), hs[3].to_string());

    let st = state().ok_or_else(|| "vpn state not initialized".to_string())?;
    omni_with(&st, move |c| {
        c.execute(
            r#"UPDATE "OmniVPN" SET
                iface_j_c=?1, iface_j_min=?2, iface_j_max=?3,
                s1=?4, s2=?5,
                h1=?6, h2=?7, h3=?8, h4=?9,
                default_j_c=?1, default_j_min=?2, default_j_max=?3,
                updated_at=CURRENT_TIMESTAMP
               WHERE id=1 AND iface_j_c IS NULL"#,
            rusqlite::params![jc, jmin, jmax, s1, s2, h1, h2, h3, h4],
        ).map(|n| {
            if n > 0 {
                eprintln!("[VPN] obfs defaults generated: Jc={} Jmin={} Jmax={} S1={} S2={} H1={} H2={} H3={} H4={}",
                    jc, jmin, jmax, s1, s2, hs[0], hs[1], hs[2], hs[3]);
            }
            ()
        })
    }).await
}

async fn init_keys(st: &VpnState) -> Result<(), String> {
    let iface = get_interface(st).await?;
    let need_regen = iface.private_key.is_empty() || iface.public_key.is_empty() || crypto::pubkey(&iface.private_key).ok().as_deref() != Some(&iface.public_key);
    if !need_regen { return Ok(()); }
    let (sk, pk, action) = if !iface.private_key.is_empty() {
        let derived = crypto::pubkey(&iface.private_key)?;
        (iface.private_key.clone(), derived, "resync pubkey from existing privkey")
    } else {
        let sk = crypto::genkey()?; let pk = crypto::pubkey(&sk)?;
        (sk, pk, "generate new keypair")
    };
    let sk_c = sk.clone(); let pk_c = pk.clone();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let c = omni_db::open_omni().map_err(|e| e.to_string())?;
        db::update_interface_keypair(&c, VPN_IFACE, &sk_c, &pk_c).map_err(|e| e.to_string())
    }).await.map_err(|e| e.to_string())??;
    eprintln!("[VPN] server keys: {} (pubkey={})", action, pk);
    Ok(())
}

// ============================================================================
// Diagnostics / Startup / shutdown / cron / HTTP helpers
// ============================================================================
fn udp_port_in_use(port: u16) -> bool {
    for path in ["/proc/net/udp", "/proc/net/udp6"] {
        if let Ok(s) = std::fs::read_to_string(path) {
            for line in s.lines().skip(1) {
                let p: Vec<&str> = line.split_whitespace().collect();
                if p.len() < 2 { continue; }
                if let Some(hex) = p[1].split(':').nth(1) {
                    if let Ok(pp) = u16::from_str_radix(hex, 16) { if pp == port { return true; } }
                }
            }
        }
    }
    false
}
fn kernel_module_loaded() -> bool {
    if std::path::Path::new("/sys/module/amneziawg").exists() || std::path::Path::new("/sys/module/wireguard").exists() { return true; }
    std::fs::read_to_string("/proc/modules").ok().map_or(false, |s| s.lines().any(|l| l.starts_with("amneziawg ") || l.starts_with("wireguard ")))
}

async fn diagnose_one(iface: &VpnInterface, clients: &[Client]) -> Value {
    let name = iface.name.clone();
    let exists = iface::iface_exists(&name).await;
    let kernel_state: Option<netlink::Device> = if exists {
        let n = name.clone();
        tokio::task::spawn_blocking(move || netlink::get_device(&n).ok()).await.ok().flatten()
    } else { None };
    let udp_listening = udp_port_in_use(iface.port as u16);
    let iptables_ok = Command::new("iptables").args(["-C", "INPUT", "-p", "udp", "--dport", &iface.port.to_string(), "-j", "ACCEPT"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().await.map(|s| s.success()).unwrap_or(false);
    let db_port = iface.port as u16;
    let kernel_port = kernel_state.as_ref().filter(|d| d.has_listen_port).map(|d| d.listen_port).unwrap_or(0);
    let kernel_has_key = kernel_state.as_ref().map(|d| d.has_private_key).unwrap_or(false);
    let peers_db = clients.iter().filter(|c| c.enabled != 0 && (!c.ipv4_address.is_empty() || !c.ipv6_address.is_empty())).count();
    let peers_kernel = kernel_state.as_ref().map(|d| d.peers.len()).unwrap_or(0);
    let mut issues: Vec<String> = Vec::new();
    if !exists { issues.push(format!("interface {} does not exist", name)); }
    if exists && !iface.private_key.is_empty() && !kernel_has_key { issues.push(format!("{}: private key in DB but not in kernel", name)); }
    if exists && kernel_port != 0 && kernel_port != db_port { issues.push(format!("{}: port mismatch DB={} kernel={}", name, db_port, kernel_port)); }
    if exists && peers_db != peers_kernel { issues.push(format!("{}: peers mismatch DB={} kernel={}", name, peers_db, peers_kernel)); }
    if kernel_port > 0 && !udp_listening { issues.push(format!("{}: UDP/{} not bound", name, kernel_port)); }
    if !iptables_ok { issues.push(format!("{}: INPUT udp/{} missing", name, db_port)); }
    json!({
        "name": name,
        "port": iface.port,
        "ipv4_cidr": iface.ipv4_cidr,
        "ipv6_cidr": iface.ipv6_cidr,
        "exists": exists,
        "udp_port_listening": udp_listening,
        "iptables_input_accept": iptables_ok,
        "kernel_listen_port": kernel_port,
        "kernel_has_private_key": kernel_has_key,
        "peers_kernel": peers_kernel,
        "peers_db": peers_db,
        "issues": issues,
    })
}

async fn diagnose(st: &VpnState) -> Result<Value, String> {
    let iface = get_interface(st).await?;
    let clients = list_clients(st).await?;
    let module_loaded = kernel_module_loaded();
    let vpn_diag = diagnose_one(&vpn_interface(&iface), &clients_for_mode(&clients, IfaceMode::Vpn)).await;
    let obfs_diag = diagnose_one(&obfs_interface(&iface), &clients_for_mode(&clients, IfaceMode::Obfs)).await;
    let mut issues: Vec<String> = Vec::new();
    if !module_loaded { issues.push("kernel module not loaded".into()); }
    for d in [&vpn_diag, &obfs_diag] {
        if let Some(arr) = d.get("issues").and_then(|v| v.as_array()) {
            for i in arr { if let Some(s) = i.as_str() { issues.push(s.to_string()); } }
        }
    }
    Ok(json!({
        "ok": issues.is_empty(),
        "issues": issues,
        "module_loaded": module_loaded,
        "obfs_status": netlink::obfs_status(),
        "vpn": vpn_diag,
        "obfs": obfs_diag,
    }))
}

pub async fn startup(config: &VpnConfig) -> Result<(), String> {
    if !config.enabled { let _ = STATE.set(None); return Ok(()); }
    let _ = std::fs::create_dir_all(omni_db::db_dir());
    let st = Arc::new(VpnState { cfg: config.clone(), conf_dir: String::new(), firewall_lock: Mutex::new(()), iptables_ok: AtomicBool::new(false) });
    let _ = STATE.set(Some(st.clone()));
    if let Ok(clients) = list_clients(&st).await { eprintln!("[VPN] init: {} client(s)", clients.len()); }
    if let Err(e) = init_keys(&st).await { eprintln!("[VPN] init_keys: {e}"); }
    let _ = ensure_endpoint_host(&st, config.acme_ip.as_deref()).await;
    if let (Ok(iface), Ok(hooks)) = (get_interface(&st).await, get_hooks(&st).await) { let _ = iface::teardown(&iface, &hooks).await; }
    if let Err(e) = save_config(&st).await { eprintln!("[VPN] initial setup failed: {e}"); }
    eprintln!("[VPN] obfs_status: {}", netlink::obfs_status());
    Ok(())
}
pub async fn shutdown() { let Some(st) = state() else { return }; if let (Ok(iface), Ok(hooks)) = (get_interface(&st).await, get_hooks(&st).await) { let _ = iface::teardown(&iface, &hooks).await; } }

pub fn start_cron() {
    tokio::spawn(async {
        let mut iv = tokio::time::interval(Duration::from_secs(60));
        iv.tick().await;
        loop {
            iv.tick().await;
            if let Some(st) = state() {
                if let Err(e) = cron_tick(&st).await { eprintln!("[VPN] cron tick failed: {e}"); }
            }
        }
    });
}

async fn cron_tick(st: &VpnState) -> Result<(), String> {
    let clients = list_clients(st).await?;
    let mut needs_save = false;
    for c in &clients {
        if c.enabled == 0 { continue; }
        let Some(exp) = &c.expires_at else { continue; };
        let Ok(dt) = DateTime::parse_from_rfc3339(exp) else { continue; };
        if Utc::now() > dt.with_timezone(&Utc) {
            match toggle_client_row(st, c.id, false).await {
                Ok(_) => { eprintln!("[VPN] cron: disabled expired client {} ({})", c.id, c.name); needs_save = true; }
                Err(e) => eprintln!("[VPN] cron: failed to disable client {}: {e}", c.id),
            }
        }
    }
    let now_rfc = Utc::now().to_rfc3339();
    let cleaned: i64 = vpn_with(st, move |conn| {
        conn.execute("DELETE FROM vpn_one_time_links WHERE expires_at < ?1", rusqlite::params![now_rfc]).map(|n| n as i64)
    }).await?;
    if cleaned > 0 { eprintln!("[VPN] cron: cleaned {} expired OTL(s)", cleaned); }
    if needs_save { save_config(st).await?; }
    Ok(())
}

fn json_ok(v: Value) -> Response<Body> { Response::builder().status(StatusCode::OK).header(header::CONTENT_TYPE, "application/json; charset=utf-8").header(header::CACHE_CONTROL, "no-store").body(Body::from(v.to_string())).unwrap_or_else(|_| Response::new(Body::empty())) }
fn text_ok(s: impl Into<String>) -> Response<Body> { Response::builder().status(StatusCode::OK).header(header::CONTENT_TYPE, "text/plain; charset=utf-8").header(header::CACHE_CONTROL, "no-store").body(Body::from(s.into())).unwrap_or_else(|_| Response::new(Body::empty())) }
fn err(status: StatusCode, msg: impl Into<String>) -> Response<Body> { let msg: String = msg.into(); Response::builder().status(status).header(header::CONTENT_TYPE, "application/json; charset=utf-8").body(Body::from(json!({"error": msg}).to_string())).unwrap_or_else(|_| Response::new(Body::empty())) }
fn file_ok(name: &str, content: String) -> Response<Body> { let mut h = axum::http::HeaderMap::new(); h.insert(header::CONTENT_TYPE, axum::http::HeaderValue::from_static("application/octet-stream")); h.insert(header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store")); if let Ok(v) = axum::http::HeaderValue::from_bytes(format!("attachment; filename=\"{name}\"").as_bytes()) { h.insert(header::CONTENT_DISPOSITION, v); } let mut resp = Response::new(Body::from(content)); *resp.headers_mut() = h; resp }
fn svg_ok(svg: String) -> Response<Body> { Response::builder().status(StatusCode::OK).header(header::CONTENT_TYPE, "image/svg+xml").header(header::CACHE_CONTROL, "no-store").body(Body::from(svg)).unwrap_or_else(|_| Response::new(Body::empty())) }
fn parse_json_bytes(bytes: &[u8]) -> Result<Value, String> { if bytes.is_empty() { return Ok(Value::Object(Default::default())); } serde_json::from_slice(bytes).map_err(|e| format!("json: {e}")) }

pub async fn serve_otl(token: &str) -> Option<Response<Body>> {
    let st = state()?;
    let link = match get_otl(&st, token).await { Ok(Some(l)) => l, _ => return None };
    if let Ok(dt) = DateTime::parse_from_rfc3339(&link.expires_at) { if Utc::now() > dt.with_timezone(&Utc) { return Some(err(StatusCode::GONE, "One Time Link expired")); } }
    let client = match get_client_by_id(&st, link.id).await { Ok(Some(c)) => c, _ => return None };
    let iface = get_interface(&st).await.ok()?;
    let uc = get_user_config(&st).await.ok()?;
    let cfg = generate_client_config_obfs(&iface, &uc, &client);
    let _ = erase_otl(&st, link.id, &link.expires_at).await;
    let name = format!("{}.conf", clean_filename(&client.name).unwrap_or_else(|| client.id.to_string()));
    Some(file_ok(&name, cfg))
}

pub async fn metrics_extra_async() -> String {
    let Some(st) = state() else { return String::new(); };
    let Ok(iface) = get_interface(&st).await else { return String::new(); };
    let Ok(clients) = list_clients(&st).await else { return String::new(); };
    let runtime = runtime_peer_map();
    let now = Utc::now();
    let mut out = String::with_capacity(2048);
    out.push_str("# HELP vpn_configured_peers Configured peers\n# TYPE vpn_configured_peers gauge\n");
    out.push_str(&format!("vpn_configured_peers{{interface=\"{}\"}} {}\n", iface.name, clients.len()));
    let enabled = clients.iter().filter(|c| c.enabled != 0).count();
    out.push_str("# HELP vpn_enabled_peers Enabled peers\n# TYPE vpn_enabled_peers gauge\n");
    out.push_str(&format!("vpn_enabled_peers{{interface=\"{}\"}} {}\n", iface.name, enabled));
    let connected = clients.iter().filter(|c| runtime.get(&c.public_key).and_then(|r| r.latest_handshake_at).map(|t| (now - t).num_seconds() < 180).unwrap_or(false)).count();
    out.push_str("# HELP vpn_connected_peers Connected\n# TYPE vpn_connected_peers gauge\n");
    out.push_str(&format!("vpn_connected_peers{{interface=\"{}\"}} {}\n", iface.name, connected));
    out.push_str("# HELP vpn_sent_bytes Per-peer sent bytes\n# TYPE vpn_sent_bytes counter\n");
    out.push_str("# HELP vpn_received_bytes Per-peer received bytes\n# TYPE vpn_received_bytes counter\n");
    out.push_str("# HELP vpn_latest_handshake_seconds Seconds since last handshake\n# TYPE vpn_latest_handshake_seconds gauge\n");
    for c in &clients {
        let rt = runtime.get(&c.public_key);
        let name_esc = c.name.replace('\\', "\\\\").replace('"', "\\\"");
        let labels = format!("interface=\"{}\",name=\"{}\",ipv4Address=\"{}\",ipv6Address=\"{}\"", iface.name, name_esc, c.ipv4_address, c.ipv6_address);
        out.push_str(&format!("vpn_sent_bytes{{{}}} {}\n", labels, rt.map(|r| r.transfer_tx).unwrap_or(0)));
        out.push_str(&format!("vpn_received_bytes{{{}}} {}\n", labels, rt.map(|r| r.transfer_rx).unwrap_or(0)));
        let hs = rt.and_then(|r| r.latest_handshake_at).map(|t| (now - t).num_seconds().max(0)).unwrap_or(0);
        out.push_str(&format!("vpn_latest_handshake_seconds{{{}}} {}\n", labels, hs));
    }
    out
}

fn runtime_peer_map() -> std::collections::HashMap<String, VpnDumpLine> {
    use std::collections::HashMap;
    let mut map: HashMap<String, VpnDumpLine> = HashMap::new();
    for iface_name in [VPN_IFACE, OBFS_IFACE] {
        if let Ok(dev) = netlink::get_device(iface_name) {
            for p in dev.peers {
                let pk_b64 = crypto::key_to_base64(&p.public_key);
                let hs = if p.last_handshake_sec > 0 { chrono::DateTime::from_timestamp(p.last_handshake_sec, 0) } else { None };
                let entry = map.entry(pk_b64.clone()).or_insert(VpnDumpLine { public_key: pk_b64.clone(), endpoint: None, latest_handshake_at: None, transfer_rx: 0, transfer_tx: 0 });
                entry.transfer_rx += p.rx_bytes as i64;
                entry.transfer_tx += p.tx_bytes as i64;
                let newer = match (entry.latest_handshake_at, hs) { (None, Some(_)) => true, (Some(c), Some(n)) => n > c, _ => false };
                if newer { entry.latest_handshake_at = hs; entry.endpoint = p.endpoint.map(|sa| sa.to_string()); }
            }
        }
    }
    map
}

pub async fn dispatch(method: Method, endpoint: String, query: HashMap<String,String>, _headers: HeaderMap, body: Body, _client_ip: String) -> Response<Body> {
    let Some(st) = state() else { return err(StatusCode::SERVICE_UNAVAILABLE, "VPN module not enabled"); };
    let body_bytes = match axum::body::to_bytes(body, 10 * 1024 * 1024).await { Ok(b) => b, Err(e) => return err(StatusCode::BAD_REQUEST, format!("body: {e}")) };
    let ep = endpoint.strip_prefix('/').unwrap_or(&endpoint);
    let ep = ep.strip_prefix("vpn/").unwrap_or(ep);
    match (method.as_str(), ep) {
        ("GET", "information") => {
            let iface = match get_interface(&st).await { Ok(i) => i, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
            json_ok(json!({
                "currentRelease": "vpn-rust-2.1",
                "latestRelease": {"version": "vpn-rust-2.1", "changelog": ""},
                "updateAvailable": false, "insecure": false,
                "firewallEnabled": iface.firewall_enabled != 0,
                "obfsStatus": netlink::obfs_status(),
                "vpnPort": iface.vpn_port,
                "obfsPort": iface.port,
            }))
        }
        ("GET", "interface") => {
    let iface = match get_interface(&st).await { Ok(i) => i, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
    let vpn_ifc = vpn_interface(&iface);
    let obfs_ifc = obfs_interface(&iface);

    let vpn_running = iface::iface_exists(&vpn_ifc.name).await;
    let obfs_running = iface::iface_exists(&obfs_ifc.name).await;

    let vpn_kernel = if vpn_running {
        let n = vpn_ifc.name.clone();
        tokio::task::spawn_blocking(move || netlink::get_device(&n).ok()).await.ok().flatten()
    } else { None };
    let obfs_kernel = if obfs_running {
        let n = obfs_ifc.name.clone();
        tokio::task::spawn_blocking(move || netlink::get_device(&n).ok()).await.ok().flatten()
    } else { None };

    let vpn_listen = vpn_kernel.as_ref().filter(|d| d.has_listen_port).map(|d| d.listen_port).unwrap_or(0);
    let obfs_listen = obfs_kernel.as_ref().filter(|d| d.has_listen_port).map(|d| d.listen_port).unwrap_or(0);
    let vpn_peers = vpn_kernel.as_ref().map(|d| d.peers.len()).unwrap_or(0);
    let obfs_peers = obfs_kernel.as_ref().map(|d| d.peers.len()).unwrap_or(0);
    let obfs_active = obfs_kernel.as_ref().map(|d| d.obfs_h1.is_some() && d.obfs_h1 != Some(1)).unwrap_or(false);

    json_ok(json!({
        "device": iface.device,
        "mtu": iface.mtu,
        "routing_table": iface.routing_table,
        "enabled": iface.enabled,
        "firewall_enabled": iface.firewall_enabled,
        "public_key": iface.public_key,
        "vpn": {
            "name": vpn_ifc.name,
            "port": vpn_ifc.port,
            "ipv4_cidr": vpn_ifc.ipv4_cidr,
            "ipv6_cidr": vpn_ifc.ipv6_cidr,
            "running": vpn_running,
            "listen_port": vpn_listen,
            "peers": vpn_peers,
        },
        "obfs": {
            "name": obfs_ifc.name,
            "port": obfs_ifc.port,
            "ipv4_cidr": obfs_ifc.ipv4_cidr,
            "ipv6_cidr": obfs_ifc.ipv6_cidr,
            "running": obfs_running,
            "listen_port": obfs_listen,
            "peers": obfs_peers,
            "obfs_active": obfs_active,
            "j_c": iface.j_c, "j_min": iface.j_min, "j_max": iface.j_max,
            "s1": iface.s1, "s2": iface.s2,
            "h1": iface.h1, "h2": iface.h2, "h3": iface.h3, "h4": iface.h4,
        },
    }))
}
        ("POST", "interface") => {
            let v = match parse_json_bytes(&body_bytes) { Ok(v) => v, Err(e) => return err(StatusCode::BAD_REQUEST, e) };
            let iface = match get_interface(&st).await { Ok(i) => i, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
            let g = |k: &str| v.get(k).and_then(|x| x.as_i64());
            let gs = |k: &str| v.get(k).and_then(|x| x.as_str()).map(String::from);
            let gb = |k: &str| v.get(k).and_then(|x| x.as_bool()).map(|b| if b { 1i64 } else { 0 });
            let device = gs("device").unwrap_or(iface.device.clone());
            let port = g("port").unwrap_or(iface.port);
            let vpn_port = g("vpnPort").unwrap_or(iface.vpn_port);
            let mtu = g("mtu").unwrap_or(iface.mtu);
            let routing = gs("routingTable").unwrap_or(iface.routing_table.clone());
            let enabled = gb("enabled").unwrap_or(iface.enabled);
            let firewall = gb("firewallEnabled").unwrap_or(iface.firewall_enabled);
            let j_c = g("jC").or(iface.j_c); let j_min = g("jMin").or(iface.j_min); let j_max = g("jMax").or(iface.j_max);
            let s1 = g("s1").or(iface.s1); let s2 = g("s2").or(iface.s2);
            let h1 = gs("h1").or(iface.h1.clone()); let h2 = gs("h2").or(iface.h2.clone());
            let h3 = gs("h3").or(iface.h3.clone()); let h4 = gs("h4").or(iface.h4.clone());
            let res = tokio::task::spawn_blocking(move || -> Result<(), String> {
                let c = omni_db::open_omni().map_err(|e| e.to_string())?;
                c.execute("UPDATE \"OmniVPN\" SET device=?1, port=?2, vpn_port=?3, iface_mtu=?4, routing_table=?5, iface_enabled=?6, firewall_enabled=?7, iface_j_c=?8, iface_j_min=?9, iface_j_max=?10, s1=?11, s2=?12, h1=?13, h2=?14, h3=?15, h4=?16, updated_at=CURRENT_TIMESTAMP WHERE id=1",
                    rusqlite::params![device, port, vpn_port, mtu, routing, enabled, firewall,
                        j_c, j_min, j_max, s1, s2, h1, h2, h3, h4]).map_err(|e| e.to_string())?;
                Ok(())
            }).await.unwrap_or_else(|e| Err(format!("join: {e}")));
            if let Err(e) = res { return err(StatusCode::INTERNAL_SERVER_ERROR, e); }
            if let Err(e) = save_config(&st).await { return err(StatusCode::INTERNAL_SERVER_ERROR, e); }
            json_ok(json!({"success": true}))
        }
        ("POST", "interface/cidr") => {
            let v = match parse_json_bytes(&body_bytes) { Ok(v) => v, Err(e) => return err(StatusCode::BAD_REQUEST, e) };
            let v4 = v.get("ipv4Cidr").and_then(|x| x.as_str()).unwrap_or("");
            let v6 = v.get("ipv6Cidr").and_then(|x| x.as_str()).unwrap_or("");
            let vpn_v4 = v.get("vpnIpv4Cidr").and_then(|x| x.as_str()).unwrap_or("");
            let vpn_v6 = v.get("vpnIpv6Cidr").and_then(|x| x.as_str()).unwrap_or("");
            if v4.parse::<Ipv4Net>().is_err() { return err(StatusCode::BAD_REQUEST, "invalid ipv4Cidr"); }
            if v6.parse::<Ipv6Net>().is_err() { return err(StatusCode::BAD_REQUEST, "invalid ipv6Cidr"); }
            if !vpn_v4.is_empty() && vpn_v4.parse::<Ipv4Net>().is_err() { return err(StatusCode::BAD_REQUEST, "invalid vpnIpv4Cidr"); }
            if !vpn_v6.is_empty() && vpn_v6.parse::<Ipv6Net>().is_err() { return err(StatusCode::BAD_REQUEST, "invalid vpnIpv6Cidr"); }
            let iface = match get_interface(&st).await { Ok(i) => i, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
            let old_v4 = iface.ipv4_cidr.clone();
            let old_v6 = iface.ipv6_cidr.clone();
            let old_vpn_v4 = iface.vpn_ipv4_cidr.clone();
            let old_vpn_v6 = iface.vpn_ipv6_cidr.clone();
            let v4s = v4.to_string(); let v6s = v6.to_string();
            let vpn_v4s = if vpn_v4.is_empty() { old_vpn_v4.clone() } else { vpn_v4.to_string() };
            let vpn_v6s = if vpn_v6.is_empty() { old_vpn_v6.clone() } else { vpn_v6.to_string() };
            let res = tokio::task::spawn_blocking(move || -> Result<(), String> {
                let c = omni_db::open_omni().map_err(|e| e.to_string())?;
                c.execute("UPDATE \"OmniVPN\" SET ipv4_cidr=?1, ipv6_cidr=?2, vpn_ipv4_cidr=?3, vpn_ipv6_cidr=?4, updated_at=CURRENT_TIMESTAMP WHERE id=1",
                    rusqlite::params![v4s, v6s, vpn_v4s, vpn_v6s]).map_err(|e| e.to_string())?;
                Ok(())
            }).await.unwrap_or_else(|e| Err(format!("join: {e}")));
            if let Err(e) = res { return err(StatusCode::INTERNAL_SERVER_ERROR, e); }
            let _ = (old_v4, old_v6, old_vpn_v4, old_vpn_v6);
            if let Err(e) = save_config(&st).await { return err(StatusCode::INTERNAL_SERVER_ERROR, e); }
            json_ok(json!({"success": true}))
        }
        ("POST", "interface/restart") => {
            if let (Ok(iface), Ok(hooks)) = (get_interface(&st).await, get_hooks(&st).await) { let _ = iface::teardown(&iface, &hooks).await; }
            match save_config(&st).await { Ok(_) => json_ok(json!({"success": true})), Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e) }
        }
        ("GET", "diagnostics") | ("GET", "diagnose") | ("GET", "health") => match diagnose(&st).await { Ok(v) => json_ok(v), Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e) },
        ("POST", "diagnose/fix") | ("POST", "repair") => match save_config(&st).await {
            Ok(_) => { let d = diagnose(&st).await.unwrap_or(json!({})); json_ok(json!({ "ok": d["ok"], "action": "save_config re-applied", "diagnostics": d })) }
            Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("repair failed: {e}")),
        },
        ("GET", "userconfig") => match get_user_config(&st).await { Ok(u) => json_ok(json!(u)), Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e) },
        ("POST", "userconfig") => {
            let v = match parse_json_bytes(&body_bytes) { Ok(v) => v, Err(e) => return err(StatusCode::BAD_REQUEST, e) };
            let uc = match get_user_config(&st).await { Ok(u) => u, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
            let host = v.get("host").and_then(|x| x.as_str()).map(String::from).unwrap_or(uc.host.clone());
            let port = v.get("port").and_then(|x| x.as_i64()).unwrap_or(uc.port);
            let mtu = v.get("defaultMtu").and_then(|x| x.as_i64()).unwrap_or(uc.default_mtu);
            let pk = v.get("defaultPersistentKeepalive").and_then(|x| x.as_i64()).unwrap_or(uc.default_persistent_keepalive);
            let dns = arr_or(&v, "defaultDns", &uc.default_dns);
            let allowed = arr_or(&v, "defaultAllowedIps", &uc.default_allowed_ips);
            if allowed.is_empty() { return err(StatusCode::BAD_REQUEST, "defaultAllowedIps empty"); }
            let dns_json = serde_json::to_string(&dns).unwrap_or_else(|_| "[]".into());
            let allowed_json = serde_json::to_string(&allowed).unwrap_or_else(|_| "[]".into());
            let res = tokio::task::spawn_blocking(move || -> Result<(), String> {
                let c = omni_db::open_omni().map_err(|e| e.to_string())?;
                c.execute("UPDATE \"OmniVPN\" SET host=?1, port=?2, default_mtu=?3, default_persistent_keepalive=?4, default_dns=?5, default_allowed_ips=?6, updated_at=CURRENT_TIMESTAMP WHERE id=1",
                    rusqlite::params![host, port, mtu, pk, dns_json, allowed_json]).map_err(|e| e.to_string())?;
                Ok(())
            }).await.unwrap_or_else(|e| Err(format!("join: {e}")));
            if let Err(e) = res { return err(StatusCode::INTERNAL_SERVER_ERROR, e); }
            json_ok(json!({"success": true}))
        }
        ("GET", "hooks") => match get_hooks(&st).await { Ok(h) => json_ok(json!({"preUp": h.pre_up, "postUp": h.post_up, "preDown": h.pre_down, "postDown": h.post_down})), Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e) },
        ("POST", "hooks") => { let _ = parse_json_bytes(&body_bytes); json_ok(json!({"success": true, "note": "hooks are not persisted in the unified schema"})) }
        ("GET", "clients") => {
            let clients = match list_clients(&st).await { Ok(c) => c, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
            let filter = query.get("filter").cloned().unwrap_or_default().to_lowercase();
            let sort = query.get("sort").cloned().unwrap_or_else(|| "asc".into());
            let mut filtered: Vec<Client> = clients.into_iter().filter(|c| filter.is_empty() || c.name.to_lowercase().contains(&filter) || c.ipv4_address.contains(&filter) || c.ipv6_address.contains(&filter) || c.vpn_ipv4_address.contains(&filter) || c.vpn_ipv6_address.contains(&filter)).collect();
            if sort == "desc" { filtered.sort_by(|a, b| b.name.cmp(&a.name)); } else { filtered.sort_by(|a, b| a.name.cmp(&b.name)); }
            let runtime = runtime_peer_map();
            let out: Vec<Value> = filtered.into_iter().map(|c| {
                let rt = runtime.get(&c.public_key);
                json!({
                    "id": c.id, "userId": c.user_id, "name": c.name,
                    "ipv4Address": c.ipv4_address, "ipv6Address": c.ipv6_address,
                    "vpnIpv4Address": c.vpn_ipv4_address, "vpnIpv6Address": c.vpn_ipv6_address,
                    "publicKey": c.public_key, "allowedIps": c.allowed_ips,
                    "serverAllowedIps": c.server_allowed_ips, "firewallIps": c.firewall_ips,
                    "expiresAt": c.expires_at, "enabled": c.enabled,
                    "password": c.password, "mtu": c.mtu, "persistentKeepalive": c.persistent_keepalive,
                    "dns": c.dns, "serverEndpoint": c.server_endpoint,
                    "createdAt": c.created_at, "updatedAt": c.updated_at,
                    "jC": c.j_c, "jMin": c.j_min, "jMax": c.j_max,
                    "latestHandshakeAt": rt.and_then(|r| r.latest_handshake_at).map(|t| t.to_rfc3339()),
                    "transferRx": rt.map(|r| r.transfer_rx).unwrap_or(0),
                    "transferTx": rt.map(|r| r.transfer_tx).unwrap_or(0),
                    "endpoint": rt.and_then(|r| r.endpoint.clone()),
                })
            }).collect();
            json_ok(Value::Array(out))
        }
        ("GET", "diagnostics/raw") => {
            let iface = match get_interface(&st).await { Ok(i) => i, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
            let name = iface.name.clone();
            match tokio::task::spawn_blocking(move || netlink::get_device_raw(&name)).await {
                Ok(Ok(bytes)) => {
                    let mut hex = String::new(); let mut ascii = String::new();
                    for (i, b) in bytes.iter().enumerate() {
                        if i % 16 == 0 { hex.push_str(&format!("\n{:04x}  ", i)); ascii.push_str(" |"); }
                        hex.push_str(&format!("{:02x} ", b));
                        ascii.push(if b.is_ascii_graphic() { *b as char } else { '.' });
                        if i % 16 == 15 { hex.push_str(&ascii); ascii.clear(); }
                    }
                    if !ascii.is_empty() { hex.push_str(&ascii); }
                    json_ok(json!({ "bytes_len": bytes.len(), "hex": hex }))
                }
                Ok(Err(e)) => err(StatusCode::BAD_GATEWAY, e.to_string()),
                Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")),
            }
        }
        ("POST", "clients") => {
            let v = match parse_json_bytes(&body_bytes) { Ok(v) => v, Err(e) => return err(StatusCode::BAD_REQUEST, e) };
            let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
            if name.is_empty() { return err(StatusCode::BAD_REQUEST, "name required"); }
            if name == "OmniVPN" { return err(StatusCode::CONFLICT, "name 'OmniVPN' is reserved"); }
            let password = v.get("password").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let mut iface = match get_interface(&st).await { Ok(i) => i, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
            let uc = match get_user_config(&st).await { Ok(u) => u, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
            let clients = match list_clients(&st).await { Ok(c) => c, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
            if iface.h1.is_none() || iface.j_c.is_none() {
                match crate::gen_obfs_defaults().await {
                    Ok(()) => { if let Ok(new_iface) = get_interface(&st).await { iface = new_iface; } }
                    Err(e) => eprintln!("[VPN] gen_obfs_defaults failed: {e}"),
                }
            }
            let used_obfs_v4: HashSet<String> = clients.iter().map(|c| c.ipv4_address.clone()).filter(|s| !s.is_empty()).collect();
            let used_obfs_v6: HashSet<String> = clients.iter().map(|c| c.ipv6_address.clone()).filter(|s| !s.is_empty()).collect();
            let used_vpn_v4: HashSet<String> = clients.iter().map(|c| c.vpn_ipv4_address.clone()).filter(|s| !s.is_empty()).collect();
            let used_vpn_v6: HashSet<String> = clients.iter().map(|c| c.vpn_ipv6_address.clone()).filter(|s| !s.is_empty()).collect();

            let obfs_v4 = match next_ip(&iface.ipv4_cidr, &used_obfs_v4) { Ok(ip) => ip, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
            let obfs_v6 = match next_ip(&iface.ipv6_cidr, &used_obfs_v6) { Ok(ip) => ip, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
            let vpn_v4 = match next_ip(&iface.vpn_ipv4_cidr, &used_vpn_v4) { Ok(ip) => ip, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
            let vpn_v6 = match next_ip(&iface.vpn_ipv6_cidr, &used_vpn_v6) { Ok(ip) => ip, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };

            let sk = match crypto::genkey() { Ok(k) => k, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, format!("genkey: {e}")) };
            let pk = match crypto::pubkey(&sk) { Ok(k) => k, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, format!("pubkey: {e}")) };
            let psk = match crypto::genpsk() { Ok(k) => k, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, format!("genpsk: {e}")) };
            let client = Client {
                id: 0, user_id: 0, interface_id: iface.name.clone(), name: name.clone(), password,
                ipv4_address: obfs_v4, ipv6_address: obfs_v6,
                vpn_ipv4_address: vpn_v4, vpn_ipv6_address: vpn_v6,
                private_key: sk, public_key: pk, pre_shared_key: psk,
                allowed_ips: None, server_allowed_ips: vec![], firewall_ips: None,
                persistent_keepalive: uc.default_persistent_keepalive, mtu: uc.default_mtu,
                dns: None, server_endpoint: None,
                expires_at: v.get("expiresAt").and_then(|x| x.as_str()).map(String::from),
                enabled: 1,
                j_c: v.get("jC").and_then(|x| x.as_i64()).or(uc.default_j_c),
                j_min: v.get("jMin").and_then(|x| x.as_i64()).or(uc.default_j_min),
                j_max: v.get("jMax").and_then(|x| x.as_i64()).or(uc.default_j_max),
                i1: None, i2: None, i3: None, i4: None, i5: None,
                content_padding_addition: None, rekey_after_time: None, rekey_timeout: None,
                reject_after_time: None, keepalive_timeout: None, max_handshake_attempts: None,
                disable_cookies: None,
                created_at: String::new(), updated_at: String::new(),
            };
            let id = match insert_client(&st, client).await { Ok(id) => id, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
            eprintln!("[VPN] client created: {} (id={})", name, id);
            if let Err(e) = save_config(&st).await { return err(StatusCode::INTERNAL_SERVER_ERROR, e); }
            json_ok(json!({"success": true, "clientId": id}))
        }
        _ if ep.starts_with("client/") => handle_client(&st, method.as_str(), ep, &body_bytes).await,
        _ => err(StatusCode::NOT_FOUND, format!("unknown endpoint: {} {}", method, ep)),
    }
}

async fn handle_client(st: &Arc<VpnState>, method: &str, ep: &str, body_bytes: &[u8]) -> Response<Body> {
    let rest = ep.strip_prefix("client/").unwrap_or("");
    let mut parts = rest.splitn(2, '/');
    let id_str = parts.next().unwrap_or("");
    let sub = parts.next().unwrap_or("");
    let id: i64 = match id_str.parse() { Ok(v) => v, Err(_) => return err(StatusCode::BAD_REQUEST, "invalid id") };
    let client = match get_client_by_id(st, id).await { Ok(Some(c)) => c, Ok(None) => return err(StatusCode::NOT_FOUND, "client not found"), Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
    match (method, sub) {
        ("GET", "") => {
            let mut c = client.clone();
            c.private_key = String::new();
            c.pre_shared_key = String::new();
            let rt = runtime_peer_map().get(&c.public_key).cloned();
            json_ok(json!({
                "id": c.id, "userId": c.user_id, "name": c.name,
                "ipv4Address": c.ipv4_address, "ipv6Address": c.ipv6_address,
                "vpnIpv4Address": c.vpn_ipv4_address, "vpnIpv6Address": c.vpn_ipv6_address,
                "publicKey": c.public_key, "allowedIps": c.allowed_ips,
                "serverAllowedIps": c.server_allowed_ips, "firewallIps": c.firewall_ips,
                "expiresAt": c.expires_at, "enabled": c.enabled,
                "mtu": c.mtu, "persistentKeepalive": c.persistent_keepalive,
                "dns": c.dns, "serverEndpoint": c.server_endpoint, "password": c.password,
                "createdAt": c.created_at, "updatedAt": c.updated_at,
                "jC": c.j_c, "jMin": c.j_min, "jMax": c.j_max,
                "latestHandshakeAt": rt.as_ref().and_then(|r| r.latest_handshake_at).map(|t| t.to_rfc3339()),
                "transferRx": rt.as_ref().map(|r| r.transfer_rx).unwrap_or(0),
                "transferTx": rt.as_ref().map(|r| r.transfer_tx).unwrap_or(0),
                "endpoint": rt.and_then(|r| r.endpoint),
            }))
        }
        ("POST", "") => {
            let v = match parse_json_bytes(body_bytes) { Ok(v) => v, Err(e) => return err(StatusCode::BAD_REQUEST, e) };
            let mut c = client.clone();
            let old_name = client.name.clone();
            let s = |k: &str, cur: &str| v.get(k).and_then(|x| x.as_str()).map(String::from).unwrap_or_else(|| cur.to_string());
            let g = |k: &str, cur: Option<i64>| v.get(k).and_then(|x| x.as_i64()).or(cur);
            let gb = |k: &str, cur: Option<i64>| v.get(k).and_then(|x| x.as_bool()).map(|b| if b { 1i64 } else { 0 }).or(cur);
            if id != 1 { c.name = s("name", &c.name); }
            c.ipv4_address = s("ipv4Address", &c.ipv4_address);
            c.ipv6_address = s("ipv6Address", &c.ipv6_address);
            if let Some(x) = v.get("vpnIpv4Address").and_then(|x| x.as_str()) { c.vpn_ipv4_address = x.to_string(); }
            if let Some(x) = v.get("vpnIpv6Address").and_then(|x| x.as_str()) { c.vpn_ipv6_address = x.to_string(); }
            c.password = s("password", &c.password);
            c.enabled = gb("enabled", Some(c.enabled)).unwrap_or(c.enabled);
            if let Some(exp) = v.get("expiresAt") { c.expires_at = if exp.is_null() { None } else { exp.as_str().map(String::from) }; }
            if let Some(arr) = v.get("allowedIps").and_then(|x| x.as_array()) { c.allowed_ips = Some(arr.iter().filter_map(|x| x.as_str().map(String::from)).collect()); }
            if let Some(arr) = v.get("serverAllowedIps").and_then(|x| x.as_array()) { c.server_allowed_ips = arr.iter().filter_map(|x| x.as_str().map(String::from)).collect(); }
            if let Some(arr) = v.get("firewallIps").and_then(|x| x.as_array()) { c.firewall_ips = Some(arr.iter().filter_map(|x| x.as_str().map(String::from)).collect()); }
            c.mtu = g("mtu", Some(c.mtu)).unwrap_or(c.mtu);
            c.persistent_keepalive = g("persistentKeepalive", Some(c.persistent_keepalive)).unwrap_or(c.persistent_keepalive);
            if let Some(arr) = v.get("dns").and_then(|x| x.as_array()) { c.dns = Some(arr.iter().filter_map(|x| x.as_str().map(String::from)).collect()); }
            if let Some(ep2) = v.get("serverEndpoint") { c.server_endpoint = if ep2.is_null() { None } else { ep2.as_str().map(String::from) }; }
            c.j_c = g("jC", c.j_c); c.j_min = g("jMin", c.j_min); c.j_max = g("jMax", c.j_max);
            if let Err(e) = update_client_row(st, id, old_name, c).await { return err(StatusCode::INTERNAL_SERVER_ERROR, e); }
            if let Err(e) = save_config(st).await { return err(StatusCode::INTERNAL_SERVER_ERROR, e); }
            json_ok(json!({"success": true}))
        }
        ("DELETE", "") => { if id == 1 { return err(StatusCode::FORBIDDEN, "Cannot delete system client OmniVPN"); } if let Err(e) = delete_client_row(st, id).await { return err(StatusCode::INTERNAL_SERVER_ERROR, e); } if let Err(e) = save_config(st).await { return err(StatusCode::INTERNAL_SERVER_ERROR, e); } json_ok(json!({"success": true})) }
        ("POST", "enable") => {
            if let Some(exp) = &client.expires_at { if let Ok(dt) = DateTime::parse_from_rfc3339(exp) { if Utc::now() > dt.with_timezone(&Utc) { return err(StatusCode::UNPROCESSABLE_ENTITY, "Client is expired. Please update the expiration date first."); } } }
            if let Err(e) = toggle_client_row(st, id, true).await { return err(StatusCode::INTERNAL_SERVER_ERROR, e); }
            if let Err(e) = save_config(st).await { return err(StatusCode::INTERNAL_SERVER_ERROR, e); }
            json_ok(json!({"success": true}))
        }
        ("POST", "disable") => { if id == 1 { return err(StatusCode::FORBIDDEN, "Cannot disable system client OmniVPN"); } if let Err(e) = toggle_client_row(st, id, false).await { return err(StatusCode::INTERNAL_SERVER_ERROR, e); } if let Err(e) = save_config(st).await { return err(StatusCode::INTERNAL_SERVER_ERROR, e); } json_ok(json!({"success": true})) }
        ("GET", "configuration") => {
            let iface = match get_interface(st).await { Ok(i) => i, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
            let uc = match get_user_config(st).await { Ok(u) => u, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
            let cfg = generate_client_config_obfs(&iface, &uc, &client);
            let name = format!("{}.conf", clean_filename(&client.name).unwrap_or_else(|| client.id.to_string()));
            file_ok(&name, cfg)
        }
        ("GET", "qrcode") => {
            let iface = match get_interface(st).await { Ok(i) => i, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
            let uc = match get_user_config(st).await { Ok(u) => u, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
            let qr_data = generate_client_config_vpn(&iface, &uc, &client);
            match encode_qr_svg(&qr_data) { Ok(svg) => svg_ok(svg), Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e) }
        }
        ("POST", "one-time-link") => {
            use rand::Rng;
            let key = format!("{}-{}", id, rand::thread_rng().gen_range(0..1000));
            let otl = format!("{:x}", crc32fast::hash(key.as_bytes()));
            let expires = (Utc::now() + chrono::Duration::seconds(300)).to_rfc3339();
            if let Err(e) = upsert_otl(st, id, &otl, &expires).await { return err(StatusCode::INTERNAL_SERVER_ERROR, e); }
            json_ok(json!({"success": true, "oneTimeLink": otl}))
        }
        _ => err(StatusCode::NOT_FOUND, format!("unknown client endpoint: {sub}")),
    }
}

fn arr_or(v: &Value, key: &str, cur: &[String]) -> Vec<String> {
    if let Some(arr) = v.get(key).and_then(|x| x.as_array()) { return arr.iter().filter_map(|x| x.as_str().map(String::from)).collect(); }
    cur.to_vec()
}