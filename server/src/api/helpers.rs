use super::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use axum::body::Body;
use axum::http::{header, StatusCode};
use axum::response::Response;
use serde_json::{json, Value};
use crate::AppState;
use omni_dns as dns;

pub(crate) fn okj(v: Value) -> Response<Body> {
    Response::builder().status(StatusCode::OK).header(CONTENT_TYPE, "application/json").body(Body::from(v.to_string())).unwrap_or_else(|_| Response::new(Body::empty()))
}
pub(crate) fn okp(ct: &str, body: Body) -> Response<Body> {
    Response::builder().status(StatusCode::OK).header(CONTENT_TYPE, ct).body(body).unwrap_or_else(|_| Response::new(Body::empty()))
}
pub(crate) fn okb(ct: &str, name: &str, data: Vec<u8>) -> Response<Body> {
    let mut b = Response::builder().status(StatusCode::OK).header(CONTENT_TYPE, ct).header(header::CACHE_CONTROL, "no-store");
    if !name.is_empty() {
        if let Ok(v) = axum::http::HeaderValue::from_bytes(format!("attachment; filename=\"{}\"", name).as_bytes()) {
            b = b.header(header::CONTENT_DISPOSITION, v);
        }
    }
    b.body(Body::from(data)).unwrap_or_else(|_| Response::new(Body::empty()))
}
pub(crate) fn err(status: StatusCode, msg: impl Into<String>) -> Response<Body> {
    let msg: String = msg.into();
    Response::builder().status(status).header(CONTENT_TYPE, "application/json").body(Body::from(json!({"error": msg}).to_string())).unwrap_or_else(|_| Response::new(Body::empty()))
}
pub(crate) fn errp(status: StatusCode, msg: impl Into<String>) -> Response<Body> { err(status, msg) }
pub(crate) fn term_404(_ctx: &ApiCtx, msg: impl Into<String>) -> Response<Body> { err(StatusCode::NOT_FOUND, msg) }

// ═══════════════════════════════════════════════════════════════════════════
// Request helpers
// ═══════════════════════════════════════════════════════════════════════════
pub(crate) fn form(ctx: &ApiCtx) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let ct = ctx.headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    if ct.contains("application/x-www-form-urlencoded") {
        if let Ok(s) = std::str::from_utf8(&ctx.body) {
            for part in s.split('&') {
                if let Some((k, v)) = part.split_once('=') {
                    out.insert(decode_url(k), decode_url(v));
                }
            }
        }
    } else if ct.contains("application/json") {
        if let Ok(v) = serde_json::from_slice::<Value>(&ctx.body) {
            if let Some(obj) = v.as_object() {
                for (k, val) in obj {
                    out.insert(k.clone(), val.as_str().map(String::from).unwrap_or_else(|| val.to_string()));
                }
            }
        }
    } else if !ctx.body.is_empty() && !ct.contains("multipart/") {
        // fallback: пытаемся как urlencoded
        if let Ok(s) = std::str::from_utf8(&ctx.body) {
            for part in s.split('&') {
                if let Some((k, v)) = part.split_once('=') {
                    out.insert(decode_url(k), decode_url(v));
                }
            }
        }
    }
    out
}
pub(crate) fn qs(ctx: &ApiCtx, k: &str) -> String { ctx.query.get(k).cloned().unwrap_or_default() }
pub(crate) fn qo(ctx: &ApiCtx, k: &str) -> Option<String> { ctx.query.get(k).cloned() }
pub(crate) fn qi(ctx: &ApiCtx, k: &str, d: u64) -> u64 { ctx.query.get(k).and_then(|s| s.parse().ok()).unwrap_or(d) }
pub(crate) fn qb(ctx: &ApiCtx, k: &str) -> bool { matches!(ctx.query.get(k).map(|s| s.as_str()), Some("1" | "true" | "yes")) }
pub(crate) fn extract_content(ctx: &ApiCtx) -> String {
    let ct = ctx.headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    if ct.contains("application/json") {
        if let Ok(v) = serde_json::from_slice::<Value>(&ctx.body) {
            if let Some(s) = v.get("content").and_then(|x| x.as_str()) {
                return s.to_string();
            }
        }
    }
    if ct.contains("application/x-www-form-urlencoded") {
        let f = form(ctx);
        if let Some(s) = f.get("content") {
            return s.clone();
        }
    }
    String::from_utf8_lossy(&ctx.body).into_owned()
}
pub(crate) fn decode_url(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' { out.push(b' '); i += 1; }
        else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(a), Some(b)) = ((bytes[i + 1] as char).to_digit(16), (bytes[i + 2] as char).to_digit(16)) {
                out.push((a * 16 + b) as u8); i += 3;
            } else { out.push(bytes[i]); i += 1; }
        } else { out.push(bytes[i]); i += 1; }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ═══════════════════════════════════════════════════════════════════════════
// Misc helpers
// ═══════════════════════════════════════════════════════════════════════════
pub(crate) fn new_id() -> String { format!("{:x}", rand::random::<u64>()) }
pub(crate) fn now_ts() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0) }
pub(crate) fn now_us() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as i64).unwrap_or(0) }
pub(crate) fn mask_secret(s: &str) -> String {
    if s.len() <= 4 { return "****".into(); }
    let chars: Vec<char> = s.chars().collect();
    let head: String = chars.iter().take(3).collect();
    let tail: String = chars.iter().rev().take(2).collect::<Vec<_>>().into_iter().rev().collect();
    format!("{}…{} ({} chars)", head, tail, s.len())
}
pub(crate) fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()).or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "unknown".into())
}
pub(crate) fn num_cpus() -> usize { std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) }
pub(crate) fn read_meminfo() -> Value {
    let mut out = serde_json::Map::new();
    if let Ok(s) = std::fs::read_to_string("/proc/meminfo") {
        for line in s.lines() {
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim().to_string();
                let val = v.trim().to_string();
                out.insert(key, json!(val));
            }
        }
    }
    Value::Object(out)
}
pub(crate) fn human_bytes(n: u64) -> String {
    if n < 1024 { return format!("{} B", n); }
    if n < 1024 * 1024 { return format!("{:.1} KB", n as f64 / 1024.0); }
    if n < 1024 * 1024 * 1024 { return format!("{:.2} MB", n as f64 / (1024.0 * 1024.0)); }
    format!("{:.2} GB", n as f64 / (1024.0 * 1024.0 * 1024.0))
}
pub(crate) fn fs_size(p: &Path) -> u64 { std::fs::metadata(p).map(|m| m.len()).unwrap_or(0) }
pub(crate) fn read_tail(p: &Path, n: usize) -> Result<Vec<String>, String> {
    let data = std::fs::read_to_string(p).map_err(|e| e.to_string())?;
    let lines: Vec<String> = data.lines().map(String::from).collect();
    let start = lines.len().saturating_sub(n);
    Ok(lines[start..].to_vec())
}
pub(crate) fn safe_rel(root: &Path, rel: &str) -> Result<PathBuf, StatusCode> {
    let mut out = root.to_path_buf();
    for c in Path::new(rel).components() {
        match c {
            std::path::Component::Normal(s) => out.push(s),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => { if !out.pop() || !out.starts_with(root) { return Err(StatusCode::FORBIDDEN); } }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {}
        }
    }
    if !out.starts_with(root) { return Err(StatusCode::FORBIDDEN); }
    Ok(out)
}
pub(crate) async fn safe_existing(root: &Path, rel: &str) -> Result<PathBuf, StatusCode> {
    let p = safe_rel(root, rel)?;
    match tokio::fs::canonicalize(&p).await {
        Ok(c) if c.starts_with(root) => Ok(c),
        _ => Err(StatusCode::NOT_FOUND),
    }
}
pub(crate) fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() { return None; }
    haystack.windows(needle.len()).position(|w| w == needle)
}
pub(crate) fn push_notif(level: &str, msg: impl Into<String>) {
    let n = Notif { ts: now_ts(), level: level.to_string(), msg: msg.into() };
    let mut g = notifs().lock().unwrap();
    g.push(n);
    let cap = 500;
    if g.len() > cap { let excess = g.len() - cap; g.drain(0..excess); }
}
pub(crate) fn require_dns(state: &AppState) -> Result<Arc<dns::DnsServer>, Response<Body>> {
    state.dns.clone().ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "dns server not initialized"))
}
pub(crate) fn is_ssrf_target(s: &str) -> bool { crate::is_ssrf_target(s) }
pub(crate) fn flatten_toml_into(prefix: &str, v: &toml::Value, out: &mut Vec<(String, String)>) { match v { toml::Value::Table(t) => for (k, vv) in t { let p = if prefix.is_empty() { k.clone() } else { format!("{}.{}", prefix, k) }; flatten_toml_into(&p, vv, out); }, toml::Value::Array(a) => { let json_arr: Vec<serde_json::Value> = a.iter().map(toml_to_json_value).collect(); let s = serde_json::to_string(&json_arr).unwrap_or_else(|_| "[]".into()); out.push((prefix.to_string(), s)); }, other => out.push((prefix.to_string(), toml_to_plain_string(other))), } }

pub(crate) fn toml_to_plain_string(v: &toml::Value) -> String { match v { toml::Value::String(s) => s.clone(), toml::Value::Integer(i) => i.to_string(), toml::Value::Float(f) => f.to_string(), toml::Value::Boolean(b) => b.to_string(), toml::Value::Datetime(d) => d.to_string(), other => other.to_string(), } }

pub(crate) fn toml_to_json_value(v: &toml::Value) -> serde_json::Value { match v { toml::Value::String(s) => serde_json::Value::String(s.clone()), toml::Value::Integer(i) => serde_json::Value::Number((*i).into()), toml::Value::Float(f) => serde_json::Number::from_f64(*f).map(serde_json::Value::Number).unwrap_or(serde_json::Value::Null), toml::Value::Boolean(b) => serde_json::Value::Bool(*b), toml::Value::Datetime(d) => serde_json::Value::String(d.to_string()), toml::Value::Array(a) => serde_json::Value::Array(a.iter().map(toml_to_json_value).collect()), toml::Value::Table(t) => serde_json::Value::Object(t.iter().map(|(k, v)| (k.clone(), toml_to_json_value(v))).collect()), } }
// ═══════════════════════════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════════════════════════
