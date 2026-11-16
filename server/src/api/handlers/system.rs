#![allow(unused_imports, unused_variables, clippy::all)]
use crate::api::*;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use axum::body::{Body, Bytes};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::{AppState, ws_active_count};
use omni_db as db;
use omni_dns as dns;
use omni_ssl as ssl;
use omni_vpn as vpn;
use omni_ikev2 as ikev2;
use omni_miraj as miraj;

pub(crate) async fn h_system_config(ctx: ApiCtx) -> Response<Body> {
    let c = &ctx.state.config;
    let safe = json!({
        "address": c.address,
        "root": c.root.to_string_lossy(),
        "admin_root": c.admin_root.to_string_lossy(),
        "admin_token": mask_secret(&c.admin_token),
        "acme_mode": format!("{:?}", c.acme_mode),
        "acme_ip": c.acme_ip,
        "acme_domains": c.acme_domains,
        "h3_port": c.h3_port,
        "fastcgi_pass": c.fastcgi_pass,
        "fastcgi_index": c.fastcgi_index,
        "admin_allowed_ips": c.admin_allowed_ips,
        "metrics_allowed_ips": c.metrics_allowed_ips,
        "cache_enabled": c.cache_enabled,
        "cache_ttl_secs": c.cache_ttl_secs,
        "cache_max_entries": c.cache_max_entries,
        "request_timeout_secs": c.request_timeout_secs,
        "cors_allowed_origins": c.cors_allowed_origins,
        "failover_attempts": c.failover_attempts,
        "sticky_sessions": c.sticky_sessions,
        "grpc_passthrough": c.grpc_passthrough,
        "backends": c.backends,
        "virtual_hosts": c.virtual_hosts.iter().map(|(k, v)| (k.clone(), v.to_string_lossy().into_owned())).collect::<HashMap<_, _>>(),
        "redirects": c.redirects,
    });
    okj(safe)
}
pub(crate) async fn h_system_config_raw(_ctx: ApiCtx) -> Response<Body> {
    let db = match db::global() { Some(d) => d, None => return err(StatusCode::SERVICE_UNAVAILABLE, "db not initialized") };
    let map = match db.config_map().await { Ok(m) => m, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
    let mut lines = String::new();
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    for k in keys { lines.push_str(&format!("{} = {}\n", k, map[k])); }
    okj(json!({"path": "OmniDB:config", "content": lines, "keys_count": map.len()}))
}
pub(crate) async fn h_system_config_validate(ctx: ApiCtx) -> Response<Body> {
    let content = extract_content(&ctx);
    // принимаем TOML (legacy UI) или JSON
    let mut items: Vec<(String, String)> = Vec::new();
    if let Ok(parsed) = content.parse::<toml::Value>() {
        flatten_toml_into("", &parsed, &mut items);
    } else if let Ok(v) = serde_json::from_str::<Value>(&content) {
        if let Some(obj) = v.as_object() {
            for (k, val) in obj {
                items.push((k.clone(), val.as_str().map(String::from).unwrap_or_else(|| val.to_string())));
            }
        }
    } else {
        return okj(json!({"valid": false, "error": "content is neither valid TOML nor JSON"}));
    }
    let mut errors: Vec<String> = Vec::new();
    for (k, v) in &items {
        if k == "address" {
            if v.parse::<IpAddr>().is_err() && v.parse::<std::net::SocketAddr>().is_err() {
                errors.push(format!("address: invalid IP ({})", v));
            }
        }
    }
    if errors.is_empty() { okj(json!({"valid": true, "keys": items.len()})) }
    else { okj(json!({"valid": false, "error": errors.join("; ")})) }
}
pub(crate) async fn h_system_config_save(ctx: ApiCtx) -> Response<Body> {
    let content = extract_content(&ctx);
    let mut items: Vec<(String, String)> = Vec::new();
    if let Ok(parsed) = content.parse::<toml::Value>() {
        flatten_toml_into("", &parsed, &mut items);
    } else if let Ok(v) = serde_json::from_str::<Value>(&content) {
        if let Some(obj) = v.as_object() {
            for (k, val) in obj {
                items.push((k.clone(), val.as_str().map(String::from).unwrap_or_else(|| val.to_string())));
            }
        }
    } else {
        return err(StatusCode::BAD_REQUEST, "content is neither valid TOML nor JSON");
    }
    if items.is_empty() { return err(StatusCode::BAD_REQUEST, "no keys to save"); }
    let db = match db::global() { Some(d) => d, None => return err(StatusCode::SERVICE_UNAVAILABLE, "db not initialized") };
    match db.config_set_bulk(&items).await {
        Ok(_) => { push_notif("info", format!("config saved to DB ({} keys)", items.len())); okj(json!({"ok": true, "updated": items.len(), "note": "restart to apply"})) }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}
pub(crate) async fn h_system_config_reload(_ctx: ApiCtx) -> Response<Body> {
    push_notif("info", "config reload requested (no-op: DB is source of truth)");
    okj(json!({"ok": true, "note": "config lives in OmniDB; restart omnirs to re-read"}))
}
pub(crate) async fn h_system_config_diff(ctx: ApiCtx) -> Response<Body> {
    let new_content = extract_content(&ctx);
    if new_content.is_empty() { return err(StatusCode::BAD_REQUEST, "content required"); }
    let db = match db::global() { Some(d) => d, None => return err(StatusCode::SERVICE_UNAVAILABLE, "db not initialized") };
    let current = match db.config_map().await { Ok(m) => m, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
    let mut items: Vec<(String, String)> = Vec::new();
    if let Ok(parsed) = new_content.parse::<toml::Value>() {
        flatten_toml_into("", &parsed, &mut items);
    } else if let Ok(v) = serde_json::from_str::<Value>(&new_content) {
        if let Some(obj) = v.as_object() {
            for (k, val) in obj {
                items.push((k.clone(), val.as_str().map(String::from).unwrap_or_else(|| val.to_string())));
            }
        }
    }
    let mut diff: Vec<Value> = Vec::new();
    for (k, v) in &items {
        let old = current.get(k).cloned().unwrap_or_default();
        if &old != v { diff.push(json!({"key": k, "old": old, "new": v})); }
    }
    okj(json!({"changes": diff.len(), "diff": diff}))
}
pub(crate) async fn h_system_config_apply(ctx: ApiCtx) -> Response<Body> { h_system_config_save(ctx).await }
pub(crate) async fn h_system_env(_ctx: ApiCtx) -> Response<Body> {
    let mut out = serde_json::Map::new();
    for (k, v) in std::env::vars() {
        if k.starts_with("OMNIRS_") || k.starts_with("OMNI_") || k.starts_with("WEB_") {
            let masked = k.to_lowercase().contains("token") || k.to_lowercase().contains("pass");
            out.insert(k.clone(), if masked { json!(mask_secret(&v)) } else { json!(v) });
        }
    }
    okj(Value::Object(out))
}
pub(crate) async fn h_system_restart(_ctx: ApiCtx) -> Response<Body> {
    push_notif("warn", "restart requested via admin");
    let _ = std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(500));
        let _ = std::process::Command::new("systemctl").args(["daemon-reload"]).status();
        let _ = std::process::Command::new("systemctl").args(["restart", "omnirs"]).status();
        std::process::exit(0);
    });
    okj(json!({"ok": true, "message": "Restart initiated"}))
}
pub(crate) async fn h_system_stop(ctx: ApiCtx) -> Response<Body> {
    let f = form(&ctx);
    if f.get("confirm").cloned().unwrap_or_default() != "yes" { return err(StatusCode::BAD_REQUEST, "confirm=yes required"); }
    push_notif("warn", "graceful stop requested");
    tokio::spawn(async { tokio::time::sleep(Duration::from_millis(500)).await; std::process::exit(0); });
    okj(json!({"ok": true, "note": "shutting down"}))
}
pub(crate) async fn h_system_ports(_ctx: ApiCtx) -> Response<Body> {
    let mut out = Vec::new();
    for (file, proto) in [("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6"), ("/proc/net/udp", "udp"), ("/proc/net/udp6", "udp6")] {
        if let Ok(content) = std::fs::read_to_string(file) {
            for (i, line) in content.lines().enumerate() {
                if i == 0 { continue; }
                let f: Vec<&str> = line.split_whitespace().collect();
                if f.len() < 4 { continue; }
                if let Some(port_hex) = f[1].split(':').nth(1) {
                    if let Ok(p) = u16::from_str_radix(port_hex, 16) {
                        if proto.starts_with("udp") || f[3] == "0A" {
                            out.push(json!({"proto": proto, "port": p, "state": if proto.starts_with("udp") { "OPEN" } else { "LISTEN" }}));
                        }
                    }
                }
            }
        }
    }
    okj(json!(out))
}
pub(crate) async fn h_system_processes(_ctx: ApiCtx) -> Response<Body> {
    let mut procs = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            let s = e.file_name().to_string_lossy().into_owned();
            if let Ok(pid) = s.parse::<u32>() {
                if let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) {
                    let f: Vec<&str> = stat.split_whitespace().collect();
                    if f.len() > 2 {
                        let comm = f[1].trim_matches(|c| c == '(' || c == ')');
                        if comm.contains("OmniRS") || comm.contains("omnirs") {
                            procs.push(json!({"pid": pid, "comm": comm}));
                        }
                    }
                }
            }
        }
    }
    okj(json!({"processes": procs, "count": procs.len()}))
}
pub(crate) async fn h_system_gc(ctx: ApiCtx) -> Response<Body> {
    let mut results = serde_json::Map::new();
    if let Some(c) = &ctx.state.cache { c.run_pending_tasks().await; results.insert("cache".into(), json!("flushed")); }
    if let Some(dns) = &ctx.state.dns {
        dns.cache.clear();
        results.insert("dns_cache".into(), json!("cleared"));
        if let Some(r) = &dns.rrl { r.sweep(); results.insert("rrl".into(), json!("swept")); }
    }
    let mut g = sessions().lock().unwrap();
    let now = now_ts();
    let before = g.len();
    g.retain(|_, s| now - s.last_seen < 86400);
    results.insert("sessions_removed".into(), json!(before - g.len()));
    okj(Value::Object(results))
}
pub(crate) async fn h_system_disk(ctx: ApiCtx) -> Response<Body> {
    let root = &ctx.state.config.root;
    let mut free_bytes = 0u64;
    let mut total_bytes = 0u64;
    #[cfg(unix)]
    {
        if let Ok(c_path) = std::ffi::CString::new(root.to_string_lossy().as_bytes()) {
            let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } == 0 {
                free_bytes = stat.f_bavail as u64 * stat.f_frsize as u64;
                total_bytes = stat.f_blocks as u64 * stat.f_frsize as u64;
            }
        }
    }
    okj(json!({ "root": root.to_string_lossy(), "free_bytes": free_bytes, "total_bytes": total_bytes, "free_human": human_bytes(free_bytes), "total_human": human_bytes(total_bytes) }))
}
pub(crate) async fn h_system_reload_dns(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let mut loaded = 0usize;
    let mut errors: Vec<String> = Vec::new();
    if let Some(dir) = &dns.config.zone_dir {
        if let Ok(mut rd) = tokio::fs::read_dir(dir).await {
            while let Ok(Some(e)) = rd.next_entry().await {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()) == Some("zone") {
                    match dns::admin_import_zone(&dns.auth, &p) {
                        Ok(()) => loaded += 1,
                        Err(e) => errors.push(format!("{}: {}", p.display(), e)),
                    }
                }
            }
        }
    }
    push_notif("info", format!("dns reload: {} zones loaded, {} errors", loaded, errors.len()));
    okj(json!({"ok": errors.is_empty(), "loaded": loaded, "errors": errors}))
}
pub(crate) async fn h_system_firewall_open(ctx: ApiCtx) -> Response<Body> {
    let f = form(&ctx);
    let ports: Vec<u16> = f.get("ports").map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect()).unwrap_or_else(|| vec![80, 443, 53, 853, 1000]);
    let enabled = std::env::var("OMNIRS_AUTO_OPEN_PORTS").or_else(|_| std::env::var("OMNI_AUTO_OPEN_PORTS")).map(|v| v == "true" || v == "1" || v == "yes").unwrap_or(false);
    if !enabled { return err(StatusCode::SERVICE_UNAVAILABLE, "OMNIRS_AUTO_OPEN_PORTS not enabled"); }
    let mut opened = Vec::new();
    let mut failed = Vec::new();
    for port in &ports {
        let ps = port.to_string();
        let r = tokio::process::Command::new("iptables").args(["-I", "INPUT", "-p", "tcp", "--dport", &ps, "-j", "ACCEPT"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().await;
        match r { Ok(s) if s.success() => opened.push(*port), _ => failed.push(*port) }
    }
    push_notif("info", format!("firewall: opened {:?}, failed {:?}", opened, failed));
    okj(json!({"ok": failed.is_empty(), "opened": opened, "failed": failed}))
}

// ═══════════════════════════════════════════════════════════════════════════
// FILES
// ═══════════════════════════════════════════════════════════════════════════
