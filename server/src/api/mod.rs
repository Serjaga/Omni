// src/api.rs — HTTP API handlers for OmniRS admin
// Все настройки в OmniDB.config (таблица key/value), config.toml больше нет.
// Сертификаты обрабатываются в ssl.rs (OmniDB.OmniSsl), endpoint'ы certs/* — там.

use crate::AppState;
use omni_db as db;
use omni_ssl as ssl;
use omni_vpn as vpn;
use omni_ikev2 as ikev2;
use omni_miraj as miraj;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;


const CONTENT_TYPE: &str = "content-type";

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════
#[derive(Clone)]
pub struct ApiCtx {
    pub state: Arc<AppState>,
    pub method: Method,
    pub endpoint: String,
    pub query: HashMap<String, String>,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub client_ip: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// Response helpers
// ═══════════════════════════════════════════════════════════════════════════

mod sess;
mod helpers;
mod auth;
pub(crate) mod handlers;
pub(crate) use sess::*;
pub(crate) use helpers::*;
pub(crate) use auth::*;
pub(crate) use handlers::*;

pub async fn dispatch(state: Arc<AppState>, method: Method, endpoint: String, query: HashMap<String, String>, headers: HeaderMap, body: Body, client_ip: String) -> Response<Body> {
    let body_limit = if endpoint.starts_with("modules/upload/") { 100 * 1024 * 1024 } else { 10 * 1024 * 1024 };
    let body_bytes = match axum::body::to_bytes(body, body_limit).await { 
        Ok(b) => b, 
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("body: {e}")) 
    };

    // ★ Делегирование к подсистемам (передаём body_bytes, где нужно)
    if endpoint.starts_with("tunnel/") || endpoint == "tunnel" {
        return db::dispatch_tunnel_api(method, endpoint, query, headers, body_bytes, client_ip).await;
    }
    if endpoint.starts_with("db/") || endpoint == "db" {
        return db::dispatch_api(state.db.clone(), method, endpoint, query, headers, body_bytes, client_ip).await;
    }
    if endpoint.starts_with("vpn/") || endpoint == "vpn" {
        return vpn::dispatch(method, endpoint, query, headers, Body::from(body_bytes), client_ip).await;
    }
    if endpoint.starts_with("certs") || endpoint == "certs" {
        return ssl::dispatch_api(state.config.acme_ip.clone(), state.config.root.clone(), state.ssl.clone(), method, endpoint, query, headers, body_bytes).await;
    }
    // ⬇️ ИСПРАВЛЕННЫЙ БЛОК IKEV2 ⬇️
    if endpoint.starts_with("ikev2/") || endpoint == "ikev2" {
        return ikev2::dispatch_api(state.config.ikev2_enabled, state.config.ikev2_listen.clone(), state.config.ikev2_psk.clone(), state.config.ikev2_local_id.clone(), state.config.ikev2_remote_id.clone(), method, endpoint, query, headers, Body::from(body_bytes), client_ip).await;
    }
    // ⬆️ КОНЕЦ ИСПРАВЛЕННОГО БЛОКА ⬆️
    if endpoint.starts_with("miraj/") || endpoint == "miraj" {
        return miraj::dispatch_api(method, endpoint, query, headers, body_bytes, client_ip).await;
    }
    
    if endpoint.starts_with("modules") || endpoint == "modules" {
        return crate::modules::handle(state, method, endpoint, body_bytes).await;
    }
    // Теперь создаем ctx и ep ПОСЛЕ того, как отработали делегаты
    let ctx = ApiCtx { state, method: method.clone(), endpoint: endpoint.clone(), query, headers, body: body_bytes, client_ip };
    if let Some(response) = crate::generated_modules::dispatch(ctx.clone()).await { return response; }
    let ep = endpoint.as_str();

    if ep == "auth/login" { return h_auth_login(ctx).await; }
    if ep == "auth/logout" { return h_auth_logout(ctx).await; }
    if ep == "auth/whoami" { return h_auth_whoami(ctx).await; }
    if ep == "auth/rotate_token" { return h_auth_rotate_token(ctx).await; }
    if ep == "auth/sessions" { return h_auth_sessions(ctx).await; }
    if ep == "auth/revoke_session" { return h_auth_revoke_session(ctx).await; }
    if ep == "auth/audit_tail" { return h_auth_audit_tail(ctx).await; }
    if ep == "auth/rotate_audit" { return h_auth_rotate_audit(ctx).await; }

    if ep == "system/config" { return h_system_config(ctx).await; }
    if ep == "system/config_raw" { return h_system_config_raw(ctx).await; }
    if ep == "system/config_validate" { return h_system_config_validate(ctx).await; }
    if ep == "system/config_save" { return h_system_config_save(ctx).await; }
    if ep == "system/config_reload" { return h_system_config_reload(ctx).await; }
    if ep == "system/config_diff" { return h_system_config_diff(ctx).await; }
    if ep == "system/config_apply" { return h_system_config_apply(ctx).await; }
    if ep == "system/env" { return h_system_env(ctx).await; }
    if ep == "system/restart" { return h_system_restart(ctx).await; }
    if ep == "system/stop" { return h_system_stop(ctx).await; }
    if ep == "system/ports" { return h_system_ports(ctx).await; }
    if ep == "system/processes" { return h_system_processes(ctx).await; }
    if ep == "system/gc" { return h_system_gc(ctx).await; }
    if ep == "system/disk" { return h_system_disk(ctx).await; }
    if ep == "system/reload_dns" { return h_system_reload_dns(ctx).await; }
    if ep == "system/firewall_open" { return h_system_firewall_open(ctx).await; }

    if ep == "files/list" { return h_files_list(ctx).await; }
    if ep == "files/read" { return h_files_read(ctx).await; }
    if ep == "files/save" { return h_files_save(ctx).await; }
    if ep == "files/mkdir" { return h_files_mkdir(ctx).await; }
    if ep == "files/delete" { return h_files_delete(ctx).await; }
    if ep == "files/rename" { return h_files_rename(ctx).await; }
    if ep == "files/move" { return h_files_move(ctx).await; }
    if ep == "files/copy" { return h_files_copy(ctx).await; }
    if ep == "files/delete_recursive" { return h_files_delete_recursive(ctx).await; }
    if ep == "files/upload" { return h_files_upload(ctx).await; }
    if ep == "files/download" { return h_files_download(ctx).await; }
    if ep == "files/chmod" { return h_files_chmod(ctx).await; }
    if ep == "files/stat" { return h_files_stat(ctx).await; }
    if ep == "files/search" { return h_files_search(ctx).await; }
    if ep == "files/disk_usage" { return h_files_disk_usage(ctx).await; }
    if ep == "files/tree" { return h_files_tree(ctx).await; }
    if ep == "files/archive" { return h_files_archive(ctx).await; }
    if ep == "files/extract" { return h_files_extract(ctx).await; }

    if ep == "cache/stats" { return h_cache_stats(ctx).await; }
    if ep == "cache/clear" { return h_cache_clear(ctx).await; }
    if ep == "cache/keys" { return h_cache_keys(ctx).await; }
    if ep == "cache/invalidate_prefix" { return h_cache_invalidate_prefix(ctx).await; }
    if ep == "cache/policy" { return h_cache_policy(ctx).await; }
    if let Some(key) = ep.strip_prefix("cache/key/") { return h_cache_key(ctx, decode_url(key)).await; }

    if ep == "dns/zones" { return h_dns_zones_list(ctx).await; }
    if ep == "dns/zones/create" { return h_dns_zones_create(ctx).await; }
    if let Some(rest) = ep.strip_prefix("dns/zones/") { return h_dns_zone_ops(ctx, rest).await; }
    if ep == "dns/add" { return h_dns_add(ctx).await; }
    if ep == "dns/remove" { return h_dns_remove(ctx).await; }
    if ep == "dns/records/update" { return h_dns_records_update(ctx).await; }
    if ep == "dns/lookup" { return h_dns_lookup(ctx).await; }
    if ep == "dns/import" { return h_dns_import(ctx).await; }
    if ep == "dns/import_text" { return h_dns_import_text(ctx).await; }
    if ep == "dns/export" { return h_dns_export(ctx).await; }
    if ep == "dns/cache/stats" { return h_dns_cache_stats(ctx).await; }
    if ep == "dns/cache/clear" { return h_dns_cache_clear(ctx).await; }
    if ep == "dns/cache/keys" { return h_dns_cache_keys(ctx).await; }
    if ep == "dns/cache/key" { return h_dns_cache_key(ctx).await; }
    if ep == "dns/metrics" { return h_dns_metrics(ctx).await; }
    if ep == "dns/rrl/sweep" { return h_dns_rrl_sweep(ctx).await; }
    if ep == "dns/rrl/buckets" { return h_dns_rrl_buckets(ctx).await; }
    if ep == "dns/rpz/list" { return h_dns_rpz_list(ctx).await; }
    if ep == "dns/rpz/load" { return h_dns_rpz_load(ctx).await; }
    if ep == "dns/rpz/unload" { return h_dns_rpz_unload(ctx).await; }
    if ep == "dns/rpz/check" { return h_dns_rpz_check(ctx).await; }
    if ep == "dns/views" { return h_dns_views_list(ctx).await; }
    if ep == "dns/views/create" { return h_dns_views_create(ctx).await; }
    if let Some(name) = ep.strip_prefix("dns/views/").and_then(|s| s.strip_suffix("/delete")) { return h_dns_views_delete(ctx, decode_url(name)).await; }
    if ep == "dns/tsig/keys" { return h_dns_tsig_list(ctx).await; }
    if ep == "dns/tsig/keys/add" { return h_dns_tsig_add(ctx).await; }
    if let Some(name) = ep.strip_prefix("dns/tsig/keys/").and_then(|s| s.strip_suffix("/delete")) { return h_dns_tsig_delete(ctx, decode_url(name)).await; }
    if ep == "dns/tenants" { return h_dns_tenants_list(ctx).await; }
    if ep == "dns/tenants/create" { return h_dns_tenants_create(ctx).await; }
    if ep == "dns/tenants/assign" { return h_dns_tenants_assign(ctx).await; }
    if let Some(id) = ep.strip_prefix("dns/tenants/").and_then(|s| s.strip_suffix("/delete")) { return h_dns_tenants_delete(ctx, decode_url(id)).await; }
    if ep == "dns/dnssec/keys" { return h_dns_dnssec_keys(ctx).await; }
    if ep == "dns/dnssec/keys/generate" { return h_dns_dnssec_generate(ctx).await; }
    if ep == "dns/dnssec/keys/import" { return h_dns_dnssec_import(ctx).await; }
    if let Some(tag) = ep.strip_prefix("dns/dnssec/keys/").and_then(|s| s.strip_suffix("/delete")) { return h_dns_dnssec_delete(ctx, tag.to_string()).await; }
    if let Some(rest) = ep.strip_prefix("dns/dnssec/zones/") { return h_dns_dnssec_zone(ctx, rest).await; }
    if ep == "dns/weighted" { return h_dns_weighted_get(ctx).await; }
    if ep == "dns/weighted/set" { return h_dns_weighted_set(ctx).await; }
    if ep == "dns/weighted/delete" { return h_dns_weighted_delete(ctx).await; }
    if ep == "dns/geo" { return h_dns_geo_get(ctx).await; }
    if ep == "dns/geo/set" { return h_dns_geo_set(ctx).await; }
    if ep == "dns/geo/db_info" { return h_dns_geo_db_info(ctx).await; }
    if ep == "dns/local_names" { return h_dns_local_list(ctx).await; }
    if ep == "dns/local_names/set" { return h_dns_local_set(ctx).await; }
    if ep == "dns/local_names/del" { return h_dns_local_del(ctx).await; }
    if ep == "dns/dnstap/stats" { return h_dns_dnstap_stats(ctx).await; }
    if ep == "dns/dnstap/tail" { return h_dns_dnstap_tail(ctx).await; }
    if ep == "dns/dnstap/rotate" { return h_dns_dnstap_rotate(ctx).await; }
    if ep == "dns/audit/tail" { return h_dns_audit_tail(ctx).await; }
    if ep == "dns/resolve" { return h_dns_resolve(ctx).await; }

    if ep == "proxy/backends" { return h_proxy_backends(ctx).await; }
    if ep == "proxy/backends/add" { return h_proxy_backends_add(ctx).await; }
    if let Some(rest) = ep.strip_prefix("proxy/backends/") { return h_proxy_backend_ops(ctx, rest).await; }
    if ep == "proxy/vhosts" { return h_proxy_vhosts(ctx).await; }
    if ep == "proxy/vhosts/set" { return h_proxy_vhosts_set(ctx).await; }
    if let Some(host) = ep.strip_prefix("proxy/vhosts/").and_then(|s| s.strip_suffix("/delete")) { return h_proxy_vhosts_delete(ctx, decode_url(host)).await; }
    if ep == "proxy/redirects" { return h_proxy_redirects(ctx).await; }
    if ep == "proxy/redirects/set" { return h_proxy_redirects_set(ctx).await; }
    if let Some(p) = ep.strip_prefix("proxy/redirects/").and_then(|s| s.strip_suffix("/delete")) { return h_proxy_redirects_delete(ctx, decode_url(p)).await; }
    if ep == "proxy/rate_limits" { return h_proxy_rate_limits(ctx).await; }
    if ep == "proxy/rate_limits/reset" { return h_proxy_rate_limits_reset(ctx).await; }
    if ep == "proxy/grpc" { return h_proxy_grpc(ctx).await; }
    if ep == "proxy/websocket/active" { return h_proxy_ws_active(ctx).await; }



    if ep == "settings" { return h_settings_get(ctx).await; }
    if ep == "settings/cache" { return h_settings_cache(ctx).await; }
    if ep == "settings/rate_limit" { return h_settings_rate_limit(ctx).await; }
    if ep == "settings/slow" { return h_settings_slow(ctx).await; }
    if ep == "settings/cors" { return h_settings_cors(ctx).await; }
    if ep == "settings/sticky" { return h_settings_sticky(ctx).await; }
    if ep == "settings/security" { return h_settings_security(ctx).await; }


    if ep == "ui/tabs" { return h_ui_tabs(ctx).await; }
    if ep == "ui/features" { return h_ui_features(ctx).await; }
    if ep == "ui/token_prefix" { return h_ui_token_prefix(ctx).await; }
    if ep == "ui/notifications" { return h_ui_notifications(ctx).await; }

    if ep == "events/sse" { return h_events_sse(ctx).await; }

    err(StatusCode::NOT_FOUND, format!("unknown endpoint: {ep}"))
}

// ═══════════════════════════════════════════════════════════════════════════
// Terminal (dispatch_terminal)
// ═══════════════════════════════════════════════════════════════════════════
pub async fn dispatch_terminal(state: Arc<AppState>, method: Method, endpoint: String, query: HashMap<String, String>, headers: HeaderMap, _body: Body, client_ip: String) -> Response<Body> {
    let ctx = ApiCtx { state, method, endpoint: endpoint.clone(), query, headers, body: Bytes::new(), client_ip };
    let _ = body_length_from(&ctx);
    match endpoint.as_str() {
        "welcome" => okj(json!({"motd": "OmniRS terminal. Type `help` for commands, `вход` to authenticate."})),
        "exec" => {
            let f = form(&ctx);
            let cmd = f.get("cmd").cloned().unwrap_or_default();
            let out: Vec<String> = if cmd.is_empty() {
                vec!["empty command".into()]
            } else {
                let mut parts = cmd.split_whitespace();
                let prog = parts.next().unwrap_or("");
                let args: Vec<&str> = parts.collect();
                let mut out: Vec<String> = Vec::new();
                match prog {
                    "help" => out.push("Commands: help, uname, uptime, whoami, echo, ls, ps, date".into()),
                    "uname" => out.push(format!("OmniRS {} {} {}", std::env::consts::OS, std::env::consts::ARCH, hostname())),
                    "uptime" => out.push(format!("{}s", ctx.state.started_at.elapsed().as_secs())),
                    "whoami" => out.push(ctx.client_ip.clone()),
                    "echo" => out.push(args.join(" ")),
                    "date" => out.push(format!("{}", now_ts())),
                    "ls" => {
                        if let Ok(mut rd) = tokio::fs::read_dir(&ctx.state.config.admin_root).await {
                            while let Ok(Some(e)) = rd.next_entry().await { out.push(e.file_name().to_string_lossy().into_owned()); }
                        }
                    }
                    "ps" => {
                        if let Ok(rd) = std::fs::read_dir("/proc") {
                            for e in rd.flatten() {
                                let s = e.file_name().to_string_lossy().into_owned();
                                if s.chars().all(|c| c.is_ascii_digit()) {
                                    if let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", s)) {
                                        let f: Vec<&str> = stat.split_whitespace().collect();
                                        if f.len() > 1 { out.push(format!("{} {}", s, f[1].trim_matches(|c| c == '(' || c == ')'))); }
                                    }
                                }
                            }
                        }
                    }
                    _ => out.push(format!("unknown command: {}", prog)),
                }
                out
            };
            okj(json!({"output": out}))
        }
        "check_token" => {
            let f = form(&ctx);
            let token = f.get("token").cloned().unwrap_or_default();
            okj(json!({"valid": token == ctx.state.config.admin_token}))
        }
        _ => err(StatusCode::NOT_FOUND, format!("unknown terminal endpoint: {endpoint}")),
    }
}

fn body_length_from(_ctx: &ApiCtx) -> usize { 0 }