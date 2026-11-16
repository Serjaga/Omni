use super::*;
use std::path::Path;
use axum::body::Body;
use axum::http::{header, StatusCode};
use axum::response::Response;
use serde_json::{json, Value};
use omni_db as db;

pub(crate) async fn h_auth_login(ctx: ApiCtx) -> Response<Body> {
    let f = form(&ctx);
    let token = f.get("token").cloned().unwrap_or_default();
    if token.is_empty() { return err(StatusCode::BAD_REQUEST, "token required"); }
    if token != ctx.state.config.admin_token {
        return err(StatusCode::UNAUTHORIZED, "invalid token");
    }
    let ip = ctx.client_ip.clone();
    let sid = new_id();
    let s = Session { id: sid.clone(), ip: ip.clone(), role: "admin".into(), created: now_ts(), last_seen: now_ts() };
    sessions().lock().unwrap().insert(sid.clone(), s);
    let cookie = format!("omnirs_admin={}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400", sid);
    push_notif("info", format!("login from {}", ip));
    Response::builder().status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header(header::SET_COOKIE, cookie)
        .body(Body::from(json!({"ok": true, "ip": ip}).to_string()))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}
pub(crate) async fn h_auth_logout(ctx: ApiCtx) -> Response<Body> {
    let f = form(&ctx);
    let id = f.get("session_id").cloned().or_else(|| {
        ctx.headers.get(header::COOKIE).and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(';').find_map(|p| p.trim().strip_prefix("omnirs_admin=").map(|x| x.to_string())))
    }).unwrap_or_default();
    if !id.is_empty() { sessions().lock().unwrap().remove(&id); }
    Response::builder().status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header(header::SET_COOKIE, "omnirs_admin=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0")
        .body(Body::from(r#"{"ok":true}"#))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}
pub(crate) async fn h_auth_whoami(ctx: ApiCtx) -> Response<Body> {
    let id = ctx.headers.get(header::COOKIE).and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(';').find_map(|p| p.trim().strip_prefix("omnirs_admin=").map(|x| x.to_string())));
    let now = now_ts();
    if let Some(id) = id {
        if let Some(s) = sessions().lock().unwrap().get_mut(&id) {
            s.last_seen = now;
            return okj(json!(s));
        }
    }
    okj(json!({"ip": ctx.client_ip, "role": "token", "session": null}))
}
pub(crate) async fn h_auth_rotate_token(ctx: ApiCtx) -> Response<Body> {
    let f = form(&ctx);
    let old = f.get("old_token").cloned().unwrap_or_default();
    if old != ctx.state.config.admin_token { return err(StatusCode::UNAUTHORIZED, "old_token mismatch"); }
    let new = new_id();
    let db = match db::global() {
        Some(d) => d,
        None => return err(StatusCode::SERVICE_UNAVAILABLE, "db not initialized"),
    };
    if let Err(e) = db.config_set("admin_token", &new).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    push_notif("warn", "admin token rotated in DB — restart required");
    okj(json!({"ok": true, "new_token": new, "note": "restart omnirs to apply; new token is in config table"}))
}
pub(crate) async fn h_auth_sessions(_ctx: ApiCtx) -> Response<Body> {
    let g = sessions().lock().unwrap();
    let v: Vec<&Session> = g.values().collect();
    okj(json!(v))
}
pub(crate) async fn h_auth_revoke_session(ctx: ApiCtx) -> Response<Body> {
    let f = form(&ctx);
    let id = f.get("session_id").cloned().unwrap_or_default();
    if id.is_empty() { return err(StatusCode::BAD_REQUEST, "session_id required"); }
    let removed = sessions().lock().unwrap().remove(&id).is_some();
    okj(json!({"ok": removed, "session_id": id}))
}
pub(crate) async fn h_auth_audit_tail(ctx: ApiCtx) -> Response<Body> {
    let n = qi(&ctx, "n", 50).clamp(1, 1000) as usize;
    let path = std::env::var("OMNIRS_AUDIT_LOG").unwrap_or_else(|_| "/var/log/omnirs/audit.log".into());
    match read_tail(Path::new(&path), n) {
        Ok(lines) => {
            let events: Vec<Value> = lines.iter().filter_map(|l| serde_json::from_str(l).ok()).collect();
            okj(json!({"path": path, "count": events.len(), "events": events}))
        }
        Err(e) => term_404(&ctx, e),
    }
}
pub(crate) async fn h_auth_rotate_audit(ctx: ApiCtx) -> Response<Body> {
    let path = std::env::var("OMNIRS_AUDIT_LOG").unwrap_or_else(|_| "/var/log/omnirs/audit.log".into());
    let p = Path::new(&path);
    if !p.exists() { return term_404(&ctx, "audit log not found"); }
    let ts = now_ts();
    let rotated = format!("{}.{}", path, ts);
    match std::fs::rename(p, &rotated) {
        Ok(()) => { let _ = std::fs::File::create(p); okj(json!({"ok": true, "rotated_to": rotated})) }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SYSTEM
// ═══════════════════════════════════════════════════════════════════════════
