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

pub(crate) async fn h_dns_zones_list(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    okj(json!(dns::admin_list_zones(&dns.auth)))
}
pub(crate) async fn h_dns_zones_create(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let f = form(&ctx);
    let origin = f.get("origin").cloned().unwrap_or_default();
    let ttl: u32 = f.get("ttl").and_then(|s| s.parse().ok()).unwrap_or(3600);
    if origin.is_empty() { return err(StatusCode::BAD_REQUEST, "origin required"); }
    let name = match dns::Name::from_str(&origin) { Ok(n) => n, Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()) };
    if dns.auth.zones.read().unwrap().contains_key(&name.lower()) { return err(StatusCode::CONFLICT, "zone exists"); }
    let mut zone = dns::Zone::new(name.clone());
    zone.ttl = ttl;
    dns.auth.add_zone(zone);
    push_notif("info", format!("dns zone created: {}", origin));
    okj(json!({ "ok": true }))
}
pub(crate) async fn h_dns_zone_ops(ctx: ApiCtx, rest: &str) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let parts: Vec<&str> = rest.split('/').collect();
    let origin = parts.get(0).copied().unwrap_or("");
    let op = parts.get(1).copied().unwrap_or("");
    if origin.is_empty() { return err(StatusCode::BAD_REQUEST, "origin required"); }
    let name = match dns::Name::from_str(origin) { Ok(n) => n, Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()) };
    let zone_arc = match dns.auth.find_zone(&name) { Some(z) => z, None => return term_404(&ctx, "zone not found") };
    match op {
        "" | "records" => {
            let g = zone_arc.read().unwrap();
            let mut records = Vec::new();
            for (n, entries) in &g.records {
                for (t, bucket) in entries {
                    for r in bucket {
                        records.push(json!({ "name": n.to_string(), "type": dns::rtype::name(*t), "ttl": r.ttl, "rdata": r.rdata_str() }));
                    }
                }
            }
            if op == "records" { okj(json!(records)) }
            else { okj(json!({ "origin": g.origin.to_string(), "serial": g.serial, "ttl": g.ttl, "records": records })) }
        }
        "delete" if ctx.method == Method::POST => {
            let f = form(&ctx);
            if f.get("confirm").map(|s| s.as_str()) != Some("yes") { return err(StatusCode::BAD_REQUEST, "confirm=yes"); }
            let mut g = dns.auth.zones.write().unwrap();
            g.remove(&name.lower());
            drop(g);
            push_notif("warn", format!("dns zone deleted: {}", origin));
            okj(json!({ "ok": true }))
        }
        "reload" if ctx.method == Method::POST => {
            let f = form(&ctx);
            let path = f.get("path").cloned().unwrap_or_else(|| format!("zones/{}.zone", origin.trim_end_matches('.')));
            match dns::admin_import_zone(&dns.auth, Path::new(&path)) {
                Ok(_) => okj(json!({ "ok": true, "path": path })),
                Err(e) => err(StatusCode::BAD_REQUEST, e.to_string()),
            }
        }
        "save" if ctx.method == Method::POST => {
            let root = &ctx.state.config.admin_root;
            let safe_path = format!("zones/{}.zone", origin.trim_end_matches('.'));
            let path = match safe_rel(root, &safe_path) { Ok(p) => p, Err(_) => return err(StatusCode::FORBIDDEN, "invalid zone path") };
            match dns::admin_export_zone(&dns.auth, origin) {
                Ok(text) => match tokio::fs::write(&path, &text).await {
                    Ok(_) => okj(json!({ "ok": true, "path": safe_path })),
                    Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
                },
                Err(e) => err(StatusCode::BAD_REQUEST, e.to_string()),
            }
        }
        "axfr" => {
            let g = zone_arc.read().unwrap();
            let records: Vec<Value> = g.all_records().iter().map(|r| json!({ "name": r.name.to_string(), "type": dns::rtype::name(r.rtype), "ttl": r.ttl, "rdata": r.rdata_str() })).collect();
            okj(json!({ "origin": g.origin.to_string(), "serial": g.serial, "records": records }))
        }
        "ixfr" => {
            let serial: u32 = qs(&ctx, "serial").parse().unwrap_or(0);
            let g = zone_arc.read().unwrap();
            match g.build_ixfr(serial) {
                Ok(records) => {
                    let list: Vec<Value> = records.iter().map(|r| json!({ "name": r.name.to_string(), "type": dns::rtype::name(r.rtype), "ttl": r.ttl, "rdata": r.rdata_str() })).collect();
                    okj(json!({ "from_serial": serial, "to_serial": g.serial, "records": list }))
                }
                Err(e) => term_404(&ctx, e.to_string()),
            }
        }
        "journal" => {
            let g = zone_arc.read().unwrap();
            let list: Vec<Value> = g.journal.iter().map(|c| json!({ "old_serial": c.old_serial, "new_serial": c.new_serial, "deleted": c.deleted.len(), "added": c.added.len() })).collect();
            okj(json!(list))
        }
        "serial_bump" if ctx.method == Method::POST => {
            let mut g = zone_arc.write().unwrap();
            let old = g.serial;
            g.serial = g.serial.wrapping_add(1);
            okj(json!({ "ok": true, "old": old, "new": g.serial }))
        }
        _ => term_404(&ctx, format!("unknown zone op: {op}")),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DNS records
// ═══════════════════════════════════════════════════════════════════════════
pub(crate) async fn h_dns_add(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let f = form(&ctx);
    let origin = f.get("origin").cloned().unwrap_or_default();
    let name = f.get("name").cloned().unwrap_or_default();
    let rtype = f.get("type").cloned().unwrap_or_default();
    let value = f.get("value").cloned().unwrap_or_default();
    let ttl: u32 = f.get("ttl").and_then(|s| s.parse().ok()).unwrap_or(3600);
    match dns::admin_add_record(&dns.auth, &origin, &name, &rtype, &value, ttl) {
        Ok(_) => { push_notif("info", format!("dns add {}/{} {}={}", origin, name, rtype, value)); okj(json!({"ok": true})) }
        Err(e) => err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}
pub(crate) async fn h_dns_remove(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let f = form(&ctx);
    let origin = f.get("origin").cloned().unwrap_or_default();
    let name = f.get("name").cloned().unwrap_or_default();
    let rtype = f.get("type").cloned().unwrap_or_default();
    match dns::admin_remove_record(&dns.auth, &origin, &name, &rtype) {
        Ok(removed) => { push_notif("warn", format!("dns remove {}/{}", origin, name)); okj(json!({"ok": removed})) }
        Err(e) => err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}
pub(crate) async fn h_dns_records_update(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let f = form(&ctx);
    let origin = f.get("origin").cloned().unwrap_or_default();
    let old_name = f.get("old_name").cloned().unwrap_or_default();
    let old_type = f.get("old_type").cloned().unwrap_or_default();
    let name = f.get("name").cloned().unwrap_or_default();
    let rtype = f.get("type").cloned().unwrap_or_default();
    let value = f.get("value").cloned().unwrap_or_default();
    let ttl: u32 = f.get("ttl").and_then(|s| s.parse().ok()).unwrap_or(3600);
    if origin.is_empty() || old_name.is_empty() || old_type.is_empty() || name.is_empty() || rtype.is_empty() {
        return err(StatusCode::BAD_REQUEST, "origin, old_name, old_type, name, type required");
    }
    if let Err(e) = dns::admin_remove_record(&dns.auth, &origin, &old_name, &old_type) { return err(StatusCode::BAD_REQUEST, e.to_string()); }
    match dns::admin_add_record(&dns.auth, &origin, &name, &rtype, &value, ttl) {
        Ok(_) => okj(json!({"ok": true})),
        Err(e) => err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}
pub(crate) async fn h_dns_lookup(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let name = qs(&ctx, "name");
    let t = qo(&ctx, "type").unwrap_or_else(|| "A".into());
    okj(dns::admin_lookup(&dns.auth, &name, &t))
}
pub(crate) async fn h_dns_import(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let f = form(&ctx);
    let path = f.get("path").cloned().unwrap_or_default();
    match dns::admin_import_zone(&dns.auth, Path::new(&path)) {
        Ok(_) => okj(json!({"ok": true, "path": path})),
        Err(e) => err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}
pub(crate) async fn h_dns_export(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let origin = qs(&ctx, "origin");
    match dns::admin_export_zone(&dns.auth, &origin) {
        Ok(text) => okp("text/plain; charset=utf-8", Body::from(text)),
        Err(e) => term_404(&ctx, e.to_string()),
    }
}
pub(crate) async fn h_dns_import_text(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let f = form(&ctx);
    let origin = f.get("origin").cloned().unwrap_or_default();
    let content = f.get("content").cloned().unwrap_or_else(|| String::from_utf8_lossy(&ctx.body).into_owned());
    if origin.is_empty() { return err(StatusCode::BAD_REQUEST, "origin required"); }
    let name = match dns::Name::from_str(&origin) { Ok(n) => n, Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()) };
    let mut parser = dns::ZoneParser::new(name);
    match parser.parse_str(&content) {
        Ok(zone) => { dns.auth.add_zone(zone); push_notif("info", format!("dns zone imported from text: {}", origin)); okj(json!({"ok": true})) }
        Err(e) => err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DNS cache/rrl/rpz
// ═══════════════════════════════════════════════════════════════════════════
pub(crate) async fn h_dns_cache_stats(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    okj(json!({"entries": dns.cache.len()}))
}
pub(crate) async fn h_dns_cache_clear(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    dns.cache.clear();
    push_notif("info", "dns cache cleared");
    okj(json!({"ok": true}))
}
pub(crate) async fn h_dns_cache_keys(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let limit = qi(&ctx, "limit", 100).clamp(1, 1000) as usize;
    let g = dns.cache.inner.lock().unwrap();
    let keys: Vec<&String> = g.keys().take(limit).collect();
    okj(json!({"count": keys.len(), "keys": keys}))
}
pub(crate) async fn h_dns_cache_key(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let name = qs(&ctx, "name");
    let t = qs(&ctx, "type");
    let key = format!("{}|{}", name.to_lowercase(), t);
    let mut g = dns.cache.inner.lock().unwrap();
    let removed = g.remove(&key).is_some();
    okj(json!({"ok": removed, "key": key}))
}
pub(crate) async fn h_dns_metrics(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    okp("text/plain; version=0.0.4; charset=utf-8", Body::from(dns.metrics_text()))
}
pub(crate) async fn h_dns_rrl_sweep(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    if let Some(r) = &dns.rrl { r.sweep(); okj(json!({"ok": true})) } else { okj(json!({"ok": false, "note": "rrl disabled"})) }
}
pub(crate) async fn h_dns_rrl_buckets(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let mut out = Vec::new();
    if let Some(rrl) = &dns.rrl {
        let g = rrl.buckets.lock().unwrap();
        for (k, b) in g.iter().take(200) { out.push(json!({"key": k, "count": b.count, "slipped": b.slipped})); }
    }
    okj(json!(out))
}
pub(crate) async fn h_dns_rpz_list(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let g = dns.rpz.zones.read().unwrap();
    let stats: Vec<Value> = g.iter().map(|(n, z)| {
        let z = z.read().unwrap();
        json!({"name": n, "exact": z.exact.len(), "wildcards": z.wildcards.len()})
    }).collect();
    okj(json!({"count": stats.len(), "zones": stats}))
}
pub(crate) async fn h_dns_rpz_load(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let f = form(&ctx);
    let name = f.get("name").cloned().unwrap_or_default();
    let path = f.get("path").cloned().unwrap_or_default();
    if name.is_empty() || path.is_empty() { return err(StatusCode::BAD_REQUEST, "name and path required"); }
    match dns.rpz.load_hostfile(&name, Path::new(&path)) {
        Ok(n) => okj(json!({"ok": true, "entries": n})),
        Err(e) => err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}
pub(crate) async fn h_dns_rpz_unload(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let f = form(&ctx);
    let name = f.get("name").cloned().unwrap_or_default();
    let mut g = dns.rpz.zones.write().unwrap();
    okj(json!({"ok": g.remove(&name).is_some()}))
}
pub(crate) async fn h_dns_rpz_check(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let name_s = qs(&ctx, "name");
    let name = match dns::Name::from_str(&name_s) { Ok(n) => n, Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()) };
    okj(json!({"name": name_s, "blocked": dns.rpz.blocked(&name)}))
}

// ═══════════════════════════════════════════════════════════════════════════
// DNS views/tsig/tenants
// ═══════════════════════════════════════════════════════════════════════════
pub(crate) async fn h_dns_views_list(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let g = dns.views.read().unwrap();
    let list: Vec<Value> = g.views.iter().map(|v| json!({"name": v.name, "match_cidrs": v.match_cidrs.iter().map(|c| format!("{}/{}", c.addr, c.prefix)).collect::<Vec<_>>(), "match_tsig": v.match_tsig})).collect();
    okj(json!({"default_view": g.default_view, "count": list.len(), "views": list}))
}
pub(crate) async fn h_dns_views_create(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let f = form(&ctx);
    let name = f.get("name").cloned().unwrap_or_default();
    let cidrs: Vec<dns::Cidr> = f.get("cidrs").map(|s| s.split(',').filter_map(|x| dns::Cidr::parse(x.trim()).ok()).collect()).unwrap_or_default();
    let tsig = f.get("tsig").cloned();
    if name.is_empty() { return err(StatusCode::BAD_REQUEST, "name required"); }
    let mut g = dns.views.write().unwrap();
    g.add(dns::View { name, match_cidrs: cidrs, match_tsig: tsig, zones: Vec::new() });
    okj(json!({"ok": true}))
}
pub(crate) async fn h_dns_views_delete(ctx: ApiCtx, name: String) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let mut g = dns.views.write().unwrap();
    let before = g.views.len();
    g.views.retain(|v| v.name != name);
    okj(json!({"ok": g.views.len() < before}))
}
pub(crate) async fn h_dns_tsig_list(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let g = dns.tsig.keys.read().unwrap();
    let list: Vec<Value> = g.values().map(|k| json!({"name": k.name, "algorithm": k.algorithm, "secret_len": k.secret.len()})).collect();
    okj(json!({"count": list.len(), "keys": list}))
}
pub(crate) async fn h_dns_tsig_add(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let f = form(&ctx);
    let name = f.get("name").cloned().unwrap_or_default();
    let alg = f.get("algorithm").cloned().unwrap_or_else(|| "hmac-sha256".into());
    let secret_b64 = f.get("secret_b64").cloned().unwrap_or_default();
    if name.is_empty() || secret_b64.is_empty() { return err(StatusCode::BAD_REQUEST, "name and secret_b64 required"); }
    use base64::{engine::general_purpose::STANDARD, Engine};
    let secret = match STANDARD.decode(&secret_b64) { Ok(s) => s, Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad b64: {e}")) };
    dns.tsig.add(dns::TsigKey { name, algorithm: alg, secret });
    okj(json!({"ok": true}))
}
pub(crate) async fn h_dns_tsig_delete(ctx: ApiCtx, name: String) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let mut g = dns.tsig.keys.write().unwrap();
    okj(json!({"ok": g.remove(&name).is_some()}))
}
pub(crate) async fn h_dns_tenants_list(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    match &dns.tenants {
        Some(t) => {
            let g = t.tenants.read().unwrap();
            let list: Vec<Value> = g.values().map(|t| json!({"id": t.id, "display_name": t.display_name, "allowed_cidrs": t.allowed_cidrs})).collect();
            okj(json!({"count": list.len(), "tenants": list}))
        }
        None => okj(json!({"count": 0, "tenants": []})),
    }
}
pub(crate) async fn h_dns_tenants_create(ctx: ApiCtx) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let t = match &dns.tenants { Some(t) => t, None => return err(StatusCode::SERVICE_UNAVAILABLE, "tenants not configured") };
    let f = form(&ctx);
    let id = f.get("id").cloned().unwrap_or_default();
    let display = f.get("display_name").cloned().unwrap_or_default();
    let cidrs: Vec<String> = f.get("allowed_cidrs").map(|s| s.split(',').map(|x| x.trim().to_string()).collect()).unwrap_or_default();
    if id.is_empty() { return err(StatusCode::BAD_REQUEST, "id required"); }
    t.add(dns::Tenant { id, display_name: display, allowed_cidrs: cidrs, max_zones: 100, max_records_per_zone: 10000 });
    okj(json!({"ok": true}))
}
pub(crate) async fn h_dns_tenants_delete(ctx: ApiCtx, id: String) -> Response<Body> {
    let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r };
    let t = match &dns.tenants { Some(t) => t, None => return err(StatusCode::SERVICE_UNAVAILABLE, "tenants not configured") };
    let mut g = t.tenants.write().unwrap();
    okj(json!({"ok": g.remove(&id).is_some()}))
}
pub(crate) async fn h_dns_tenants_assign(ctx: ApiCtx) -> Response<Body> { let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r }; let t = match &dns.tenants { Some(t) => t, None => return err(StatusCode::SERVICE_UNAVAILABLE, "tenants not configured") }; let f = form(&ctx); let origin = f.get("origin").cloned().unwrap_or_default(); let tenant_id = f.get("tenant_id").cloned().unwrap_or_default(); let n = match dns::Name::from_str(&origin) { Ok(n) => n, Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()) }; match t.assign_zone(&n, &tenant_id) { Ok(_) => okj(json!({"ok": true})), Err(e) => err(StatusCode::BAD_REQUEST, e.to_string()) } }

// ═══════════════════════════════════════════════════════════════════════════
// DNS DNSSEC
// ═══════════════════════════════════════════════════════════════════════════
pub(crate) async fn h_dns_dnssec_keys(ctx: ApiCtx) -> Response<Body> { let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r }; let zone = qs(&ctx, "zone"); let keys = dns.dnssec.keys.read().unwrap(); let list: Vec<Value> = if zone.is_empty() { keys.iter().flat_map(|(z, ks)| ks.iter().map(move |k| json!({"zone": z.to_string(), "key_tag": k.key_tag, "algorithm": k.algorithm, "flags": k.flags, "is_ksk": k.is_ksk}))).collect() } else { let zn = dns::Name::from_str(&zone).ok(); zn.and_then(|n| keys.get(&n.lower()).map(|ks| ks.iter().map(|k| json!({"zone": zone.clone(), "key_tag": k.key_tag, "algorithm": k.algorithm, "flags": k.flags, "is_ksk": k.is_ksk})).collect())).unwrap_or_default() }; okj(json!({"count": list.len(), "keys": list})) }

pub(crate) async fn h_dns_dnssec_generate(ctx: ApiCtx) -> Response<Body> { let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r }; let f = form(&ctx); let zone_s = f.get("zone").cloned().unwrap_or_default(); let is_ksk = f.get("is_ksk").map(|s| s == "true" || s == "1").unwrap_or(false); let zn = match dns::Name::from_str(&zone_s) { Ok(n) => n, Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()) }; match dns::DnssecKey::generate(is_ksk) { Ok(key) => { let tag = key.key_tag; dns.dnssec.add_key(zn, key); okj(json!({"ok": true, "key_tag": tag})) } Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()) } }

pub(crate) async fn h_dns_dnssec_import(ctx: ApiCtx) -> Response<Body> { let f = form(&ctx); let zone = f.get("zone").cloned().unwrap_or_default(); let pem = f.get("private_pem").cloned().unwrap_or_default(); if zone.is_empty() || pem.is_empty() { return err(StatusCode::BAD_REQUEST, "zone and private_pem required"); } use p256::pkcs8::DecodePrivateKey; let sk = match p256::ecdsa::SigningKey::from_pkcs8_pem(&pem) { Ok(k) => k, Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad pem: {e}")) }; let vk = sk.verifying_key(); let point = vk.to_encoded_point(false); let raw = point.as_bytes(); let pk = raw[1..].to_vec(); let mut rdata = Vec::with_capacity(68); rdata.extend_from_slice(&256u16.to_be_bytes()); rdata.push(3); rdata.push(13); rdata.extend_from_slice(&pk); let key_tag = dns::compute_key_tag(&rdata); use base64::{engine::general_purpose::STANDARD, Engine}; let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r }; let zn = match dns::Name::from_str(&zone) { Ok(n) => n, Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()) }; dns.dnssec.add_key(zn, dns::DnssecKey { key_tag, algorithm: 13, flags: 256, is_ksk: true, private_pem: Some(pem), public_b64: STANDARD.encode(&rdata) }); okj(json!({"ok": true, "key_tag": key_tag})) }

pub(crate) async fn h_dns_dnssec_delete(ctx: ApiCtx, tag: String) -> Response<Body> { let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r }; let tag: u16 = match tag.parse() { Ok(t) => t, Err(_) => return err(StatusCode::BAD_REQUEST, "invalid tag") }; let zone = qs(&ctx, "zone"); let mut keys = dns.dnssec.keys.write().unwrap(); let mut removed = false; if zone.is_empty() { for ks in keys.values_mut() { let before = ks.len(); ks.retain(|k| k.key_tag != tag); if ks.len() < before { removed = true; } } } else if let Ok(n) = dns::Name::from_str(&zone) { if let Some(ks) = keys.get_mut(&n.lower()) { let before = ks.len(); ks.retain(|k| k.key_tag != tag); removed = ks.len() < before; } } okj(json!({"ok": removed})) }

pub(crate) async fn h_dns_dnssec_zone(ctx: ApiCtx, rest: &str) -> Response<Body> { let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r }; let parts: Vec<&str> = rest.split('/').collect(); let origin = parts.get(0).copied().unwrap_or(""); let op = parts.get(1).copied().unwrap_or(""); let zn = match dns::Name::from_str(origin) { Ok(n) => n, Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()) }; match op { "sign" if ctx.method == Method::POST => { let zone_arc = match dns.auth.find_zone(&zn) { Some(z) => z, None => return term_404(&ctx, "zone not found") }; let mut g = zone_arc.write().unwrap(); match dns.dnssec.sign_zone(&mut g) { Ok(_) => { push_notif("info", format!("zone signed: {}", origin)); okj(json!({"ok": true})) } Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()) } }, "ds" => { let keys = dns.dnssec.keys_for(&zn); let mut out = Vec::new(); for k in keys { if k.is_ksk { if let Ok(rr) = k.ds_record(&zn, 3600) { out.push(json!({"name": rr.name.to_string(), "type": "DS", "ttl": rr.ttl, "rdata": rr.rdata_str()})); } } } okj(json!(out)) }, "dnskey" => { let keys = dns.dnssec.keys_for(&zn); let mut out = Vec::new(); for k in keys { if let Ok(rr) = k.dnskey_record(&zn, 3600) { out.push(json!({"name": rr.name.to_string(), "type": "DNSKEY", "ttl": rr.ttl, "rdata": rr.rdata_str()})); } } okj(json!(out)) }, "unsign" if ctx.method == Method::POST => { let zone_arc = match dns.auth.find_zone(&zn) { Some(z) => z, None => return term_404(&ctx, "zone not found") }; let mut g = zone_arc.write().unwrap(); for entry in g.records.values_mut() { entry.remove(&dns::rtype::RRSIG); entry.remove(&dns::rtype::NSEC); entry.remove(&dns::rtype::NSEC3); } g.rrsigs.clear(); okj(json!({"ok": true})) }, "nsec3" => { let salt = qs(&ctx, "salt").into_bytes(); let iter: u16 = qs(&ctx, "iterations").parse().unwrap_or(0); let name_s = qs(&ctx, "name"); let name = match dns::Name::from_str(&name_s) { Ok(n) => n, Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()) }; let h = dns.dnssec.nsec3_hash(&name, &salt, iter); okj(json!({"hash_hex": h.iter().map(|b| format!("{:02x}", b)).collect::<String>()})) }, _ => term_404(&ctx, format!("unknown dnssec op: {op}")) } }

// ═══════════════════════════════════════════════════════════════════════════
// DNS weighted/geo/local
// ═══════════════════════════════════════════════════════════════════════════
pub(crate) async fn h_dns_weighted_get(ctx: ApiCtx) -> Response<Body> { let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r }; let origin = qs(&ctx, "origin"); let zone_arc = match dns.auth.find_zone(&match dns::Name::from_str(&origin) { Ok(n) => n, Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()) }) { Some(z) => z, None => return term_404(&ctx, "zone not found") }; let g = zone_arc.read().unwrap(); let mut out = Vec::new(); for (n, per_type) in &g.weights { for (t, w) in per_type { out.push(json!({"name": n.to_string(), "type": dns::rtype::name(*t), "weights": w})); } } okj(json!(out)) }

pub(crate) async fn h_dns_weighted_set(ctx: ApiCtx) -> Response<Body> { let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r }; let f = form(&ctx); let origin = f.get("origin").cloned().unwrap_or_default(); let name_s = f.get("name").cloned().unwrap_or_default(); let type_s = f.get("type").cloned().unwrap_or_else(|| "A".into()); let weights_s = f.get("weights").cloned().unwrap_or_default(); let weights: Vec<u32> = weights_s.split(',').filter_map(|x| x.trim().parse().ok()).collect(); let zone_arc = match dns.auth.find_zone(&match dns::Name::from_str(&origin) { Ok(n) => n, Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()) }) { Some(z) => z, None => return term_404(&ctx, "zone not found") }; let rtype = match type_s.to_uppercase().as_str() { "A" => dns::rtype::A, "AAAA" => dns::rtype::AAAA, _ => dns::rtype::A }; let full = if name_s == "@" { origin.clone() } else { format!("{}.{}", name_s, origin.trim_end_matches('.')) }; let n = match dns::Name::from_str(&full) { Ok(n) => n, Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()) }; let mut g = zone_arc.write().unwrap(); g.weights.entry(n.lower()).or_default().insert(rtype, weights); okj(json!({"ok": true})) }

pub(crate) async fn h_dns_weighted_delete(ctx: ApiCtx) -> Response<Body> { let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r }; let f = form(&ctx); let origin = f.get("origin").cloned().unwrap_or_default(); let name_s = f.get("name").cloned().unwrap_or_default(); let type_s = f.get("type").cloned().unwrap_or_else(|| "A".into()); let zone_arc = match dns.auth.find_zone(&match dns::Name::from_str(&origin) { Ok(n) => n, Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()) }) { Some(z) => z, None => return term_404(&ctx, "zone not found") }; let rtype = match type_s.to_uppercase().as_str() { "A" => dns::rtype::A, "AAAA" => dns::rtype::AAAA, _ => dns::rtype::A }; let full = if name_s == "@" { origin.clone() } else { format!("{}.{}", name_s, origin.trim_end_matches('.')) }; let n = match dns::Name::from_str(&full) { Ok(n) => n, Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()) }; let mut g = zone_arc.write().unwrap(); let mut removed = false; if let Some(m) = g.weights.get_mut(&n.lower()) { removed = m.remove(&rtype).is_some(); } okj(json!({"ok": removed})) }

pub(crate) async fn h_dns_geo_get(ctx: ApiCtx) -> Response<Body> { let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r }; let origin = qs(&ctx, "origin"); let zone_arc = match dns.auth.find_zone(&match dns::Name::from_str(&origin) { Ok(n) => n, Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()) }) { Some(z) => z, None => return term_404(&ctx, "zone not found") }; let g = zone_arc.read().unwrap(); let mut out = Vec::new(); for (n, per_type) in &g.geo_rules { for (t, rule) in per_type { let countries: Vec<&String> = rule.by_country.keys().collect(); out.push(json!({"name": n.to_string(), "type": dns::rtype::name(*t), "countries": countries, "default": rule.default.records.len()})); } } okj(json!(out)) }

pub(crate) async fn h_dns_geo_set(ctx: ApiCtx) -> Response<Body> { let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r }; let f = form(&ctx); let origin = f.get("origin").cloned().unwrap_or_default(); let name_s = f.get("name").cloned().unwrap_or_default(); let type_s = f.get("type").cloned().unwrap_or_else(|| "A".into()); let country = f.get("country").cloned().unwrap_or_default(); if origin.is_empty() || name_s.is_empty() || country.is_empty() { return err(StatusCode::BAD_REQUEST, "origin, name, country required"); } let zone_arc = match dns.auth.find_zone(&match dns::Name::from_str(&origin) { Ok(n) => n, Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()) }) { Some(z) => z, None => return term_404(&ctx, "zone not found") }; let rtype = match type_s.to_uppercase().as_str() { "A" => dns::rtype::A, "AAAA" => dns::rtype::AAAA, _ => dns::rtype::A }; let full = if name_s == "@" { origin.clone() } else { format!("{}.{}", name_s, origin.trim_end_matches('.')) }; let n = match dns::Name::from_str(&full) { Ok(n) => n, Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()) }; let mut g = zone_arc.write().unwrap(); let rule = g.geo_rules.entry(n.lower()).or_default().entry(rtype).or_insert_with(|| dns::GeoRule { by_country: HashMap::new(), default: dns::WeightedBucket { records: vec![], weights: vec![] } }); rule.by_country.entry(country).or_insert_with(|| dns::WeightedBucket { records: vec![], weights: vec![] }); okj(json!({ "ok": true, "note": "geo rule updated" })) }

pub(crate) async fn h_dns_geo_db_info(ctx: ApiCtx) -> Response<Body> { let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r }; match &dns.geo_db { Some(g) => okj(json!({"loaded": true, "prefixes": g.prefix_map.len()})), None => okj(json!({"loaded": false})) } }

pub(crate) async fn h_dns_local_list(ctx: ApiCtx) -> Response<Body> { let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r }; okj(json!(&dns.config.local_names)) }

pub(crate) async fn h_dns_local_set(ctx: ApiCtx) -> Response<Body> { let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r }; let f = form(&ctx); let host = f.get("host").cloned().unwrap_or_default(); let ip = f.get("ip").cloned().unwrap_or_default(); if host.is_empty() || ip.is_empty() { return err(StatusCode::BAD_REQUEST, "host and ip required"); } dns.set_local_name(host, ip); okj(json!({ "ok": true, "note": "local_names updated in memory" })) }

pub(crate) async fn h_dns_local_del(ctx: ApiCtx) -> Response<Body> { let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r }; let host = qs(&ctx, "host"); if host.is_empty() { return err(StatusCode::BAD_REQUEST, "host required"); } let removed = dns.del_local_name(&host); okj(json!({ "ok": removed, "note": "local_names updated in memory" })) }

// ═══════════════════════════════════════════════════════════════════════════
// DNS dnstap / audit / resolve
// ═══════════════════════════════════════════════════════════════════════════
pub(crate) async fn h_dns_dnstap_stats(ctx: ApiCtx) -> Response<Body> { let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r }; match &dns.dnstap { Some(w) => { let sz = w.size.load(Ordering::Relaxed); okj(json!({"path": w.path.to_string_lossy(), "size": sz, "human": human_bytes(sz), "max_size": w.max_size})) } None => okj(json!({"enabled": false})) } }

pub(crate) async fn h_dns_dnstap_tail(ctx: ApiCtx) -> Response<Body> { let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r }; let n = qi(&ctx, "n", 100).clamp(1, 10000) as usize; let w = match &dns.dnstap { Some(w) => w, None => return err(StatusCode::SERVICE_UNAVAILABLE, "dnstap disabled") }; let data = match std::fs::read(&w.path) { Ok(d) => d, Err(e) => return term_404(&ctx, e.to_string()) }; let mut pos = 0usize; let mut events = Vec::new(); while pos + 4 <= data.len() { let len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize; pos += 4; if pos + len > data.len() { break; } if let Ok(ev) = serde_json::from_slice::<Value>(&data[pos..pos + len]) { events.push(ev); } pos += len; } let start = events.len().saturating_sub(n); okj(json!(&events[start..])) }

pub(crate) async fn h_dns_dnstap_rotate(ctx: ApiCtx) -> Response<Body> { let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r }; match &dns.dnstap { Some(w) => { let ts = now_ts(); let rotated = format!("{}.{}", w.path.to_string_lossy(), ts); match std::fs::rename(&w.path, &rotated) { Ok(_) => okj(json!({"ok": true, "rotated_to": rotated})), Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()) } } None => err(StatusCode::SERVICE_UNAVAILABLE, "dnstap disabled") } }

pub(crate) async fn h_dns_audit_tail(ctx: ApiCtx) -> Response<Body> { h_auth_audit_tail(ctx).await }

pub(crate) async fn h_dns_resolve(ctx: ApiCtx) -> Response<Body> { let dns = match require_dns(&ctx.state) { Ok(d) => d, Err(r) => return r }; let name_s = qs(&ctx, "name"); let type_s = qo(&ctx, "type").unwrap_or_else(|| "A".into()); let name = match dns::Name::from_str(&name_s) { Ok(n) => n, Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()) }; let rtype = match type_s.to_uppercase().as_str() { "A" => dns::rtype::A, "AAAA" => dns::rtype::AAAA, "CNAME" => dns::rtype::CNAME, "NS" => dns::rtype::NS, "MX" => dns::rtype::MX, "TXT" => dns::rtype::TXT, "SOA" => dns::rtype::SOA, "SRV" => dns::rtype::SRV, "CAA" => dns::rtype::CAA, "PTR" => dns::rtype::PTR, "DS" => dns::rtype::DS, "DNSKEY" => dns::rtype::DNSKEY, "ANY" => dns::rtype::ANY, _ => dns::rtype::A }; let req = dns::Message::new_query(rand::random::<u16>(), name.clone(), rtype); let ip = ctx.client_ip.parse().unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)); let resp = dns.handle(req, ip, &[], "admin").await; let answers: Vec<Value> = resp.answers.iter().map(|r| json!({"name": r.name.to_string(), "type": dns::rtype::name(r.rtype), "ttl": r.ttl, "rdata": r.rdata_str()})).collect(); okj(json!({"rcode": resp.rcode(), "aa": (resp.flags & 0x0400) != 0, "answers": answers, "authority": resp.authority.len()})) }

// ═══════════════════════════════════════════════════════════════════════════
// PROXY
// ═══════════════════════════════════════════════════════════════════════════
