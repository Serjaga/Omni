use crate::*;

pub async fn dispatch_tunnel_api(
    method: Method,
    endpoint: String,
    _query: HashMap<String, String>,
    _headers: HeaderMap,
    body: Bytes,
    _client_ip: String,
) -> Response<Body> {
    let ep = endpoint
        .trim_start_matches('/')
        .trim_start_matches("tunnel")
        .trim_start_matches('/');

    // GET /api/tunnel/clients
    if (ep.is_empty() || ep == "clients") && method == Method::GET {
        let res = tokio::task::spawn_blocking(|| -> Result<Vec<TunnelClient>, String> {
            let c = open_omni().map_err(|e| format!("open: {e}"))?;
            tunnel_list(&c).map_err(|e| e.to_string())
        })
        .await;
        return match res {
            Ok(Ok(list)) => json_ok(serde_json::json!(list)),
            Ok(Err(e)) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e),
            Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")),
        };
    }

    // POST /api/tunnel/clients
    if (ep.is_empty() || ep == "clients") && method == Method::POST {
        let v: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => return json_err(StatusCode::BAD_REQUEST, format!("json: {e}")),
        };
        let name = v
            .get("name")
            .and_then(|x| x.as_str())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if name.is_empty() {
            return json_err(StatusCode::BAD_REQUEST, "name required");
        }
        let path_prefix = v
            .get("path_prefix")
            .and_then(|x| x.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| name.clone());
        let allow_targets: Vec<String> = v
            .get("allow_targets")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let password = v
            .get("password")
            .and_then(|x| x.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(gen_tunnel_password);
        let pw_out = password.clone();
        let res = tokio::task::spawn_blocking(move || -> Result<i64, String> {
            let c = open_omni().map_err(|e| format!("open: {e}"))?;
            tunnel_create(&c, &name, &password, &path_prefix, &allow_targets)
                .map_err(|e| e.to_string())
        })
        .await;
        return match res {
            Ok(Ok(id)) => json_ok(serde_json::json!({
                "ok": true, "id": id, "password": pw_out
            })),
            Ok(Err(e)) => json_err(StatusCode::BAD_REQUEST, e),
            Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")),
        };
    }

    // /api/tunnel/clients/:id[/action]
    if let Some(rest) = ep.strip_prefix("clients/") {
        let mut parts = rest.splitn(2, '/');
        let id_str = parts.next().unwrap_or("");
        let action = parts.next().unwrap_or("");
        let id: i64 = match id_str.parse() {
            Ok(v) => v,
            Err(_) => return json_err(StatusCode::BAD_REQUEST, "invalid id"),
        };

        if action.is_empty() && method == Method::GET {
            let res = tokio::task::spawn_blocking(move || -> Result<Option<TunnelClient>, String> {
                let c = open_omni().map_err(|e| format!("open: {e}"))?;
                tunnel_get(&c, id).map_err(|e| e.to_string())
            })
            .await;
            return match res {
                Ok(Ok(Some(t))) => json_ok(serde_json::json!(t)),
                Ok(Ok(None)) => json_err(StatusCode::NOT_FOUND, "client not found"),
                Ok(Err(e)) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e),
                Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")),
            };
        }

        if action.is_empty() && method == Method::DELETE {
            let res = tokio::task::spawn_blocking(move || -> Result<(), String> {
                let c = open_omni().map_err(|e| format!("open: {e}"))?;
                tunnel_delete(&c, id).map_err(|e| e.to_string())
            })
            .await;
            return match res {
                Ok(Ok(_)) => json_ok(serde_json::json!({"ok": true})),
                Ok(Err(e)) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e),
                Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")),
            };
        }

        if method == Method::POST && (action == "enable" || action == "disable") {
            let enable = action == "enable";
            let res = tokio::task::spawn_blocking(move || -> Result<(), String> {
                let c = open_omni().map_err(|e| format!("open: {e}"))?;
                tunnel_set_enabled(&c, id, enable).map_err(|e| e.to_string())
            })
            .await;
            return match res {
                Ok(Ok(_)) => json_ok(serde_json::json!({"ok": true, "enabled": enable})),
                Ok(Err(e)) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e),
                Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")),
            };
        }

        if method == Method::POST && action == "reset" {
            let new_pw = gen_tunnel_password();
            let pw_out = new_pw.clone();
            let res = tokio::task::spawn_blocking(move || -> Result<(), String> {
                let c = open_omni().map_err(|e| format!("open: {e}"))?;
                tunnel_reset_password(&c, id, &new_pw).map_err(|e| e.to_string())
            })
            .await;
            return match res {
                Ok(Ok(_)) => json_ok(serde_json::json!({"ok": true, "password": pw_out})),
                Ok(Err(e)) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e),
                Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")),
            };
        }

        // GET /api/tunnel/clients/:id/uri — построить wss:// URI для клиента
        if method == Method::GET && action == "uri" {
            let res = tokio::task::spawn_blocking(move || -> Result<Option<TunnelClient>, String> {
                let c = open_omni().map_err(|e| format!("open: {e}"))?;
                tunnel_get(&c, id).map_err(|e| e.to_string())
            })
            .await;
            let client = match res {
                Ok(Ok(Some(c))) => c,
                Ok(Ok(None)) => return json_err(StatusCode::NOT_FOUND, "client not found"),
                Ok(Err(e)) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e),
                Err(e) => {
                    return json_err(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}"))
                }
            };
            // host: acme_ip → первый acme_domains → localhost
            let host = tokio::task::spawn_blocking(|| -> String {
                let Ok(c) = open_omni() else {
                    return "localhost".into();
                };
                let get = |k: &str| {
                    c.query_row(
                        "SELECT value FROM config WHERE key=?1",
                        rusqlite::params![k],
                        |r| r.get::<_, String>(0),
                    )
                    .ok()
                };
                if let Some(ip) = get("acme_ip").filter(|s| !s.trim().is_empty()) {
                    return ip;
                }
                if let Some(list) = get("acme_domains") {
                    if let Some(first) = list
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .find(|s| !s.is_empty())
                    {
                        return first;
                    }
                }
                "localhost".into()
            })
            .await
            .unwrap_or_else(|_| "localhost".into());
            let uri = format!(
                "wss://{}/tunnel/{}?password={}",
                host, client.path_prefix, client.password
            );
            return json_ok(serde_json::json!({
                "uri": uri,
                "path_prefix": client.path_prefix,
                "password": client.password,
            }));
        }
    }

    json_err(
        StatusCode::NOT_FOUND,
        format!("unknown tunnel endpoint: {ep}"),
    )
}

// ─── dispatch_api ──────────────────────────────────────────────────────────
pub async fn dispatch_api(db: Option<Arc<DbManager>>, method: Method, endpoint: String, qmap: HashMap<String, String>, _headers: HeaderMap, body: Bytes, _client_ip: String) -> Response<Body> {
    let mgr = match db.clone() { Some(m) => m, None => return json_err(StatusCode::SERVICE_UNAVAILABLE, "database manager not initialized") };
    
    // Убираем префиксы `/` и `db/`, чтобы можно было принимать как `db/connections`, так и `connections`
    let ep = endpoint.trim_start_matches('/').trim_start_matches("db/");

    if ep == "config" && method == Method::GET {
        return match mgr.config_map().await {
            Ok(m) => json_ok(serde_json::json!(m)),
            Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e),
        };
    }
    if ep == "config" && method == Method::POST {
        let v: serde_json::Value = match serde_json::from_slice(&body) { Ok(v) => v, Err(e) => return json_err(StatusCode::BAD_REQUEST, e.to_string()) };
        let obj = match v.as_object() { Some(o) => o, None => return json_err(StatusCode::BAD_REQUEST, "body must be an object") };
        let items: Vec<(String, String)> = obj.iter().map(|(k, v)| (k.clone(), v.as_str().map(String::from).unwrap_or_else(|| v.to_string()))).collect();
        return match mgr.config_set_bulk(&items).await {
            Ok(_) => json_ok(serde_json::json!({"ok": true, "updated": items.len()})),
            Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e),
        };
    }
    if ep.starts_with("config/") && method == Method::DELETE {
        let key = ep.trim_start_matches("config/");
        return match mgr.config_del(key).await {
            Ok(_) => json_ok(serde_json::json!({"ok": true})),
            Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e),
        };
    }

    if ep == "connections" && method == Method::GET {
        return json_ok(mgr.stats().await);
    }

    // ★ Обработка кнопки "Test"
    if ep.starts_with("connections/") && ep.ends_with("/test") {
        let id = ep.trim_start_matches("connections/").trim_end_matches("/test");
        return match mgr.test(id).await {
            Ok(latency_ms) => json_ok(serde_json::json!({"ok": true, "latency_ms": latency_ms})),
            Err(e) => json_ok(serde_json::json!({"ok": false, "error": e})),
        };
    }

    if ep == "create_database" && method == Method::POST {
        let req: CreateDbRequest = match serde_json::from_slice(&body) { Ok(r) => r, Err(e) => return json_err(StatusCode::BAD_REQUEST, format!("invalid json: {e}")) };
        let dir = match &mgr.config.db_dir { Some(d) => d, None => return json_err(StatusCode::SERVICE_UNAVAILABLE, "db_dir not configured") };
        let safe_name = req.name.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|', '.', ' '], "_");
        if safe_name.is_empty() || safe_name == "_" { return json_err(StatusCode::BAD_REQUEST, "invalid name"); }
        let file_path = Path::new(dir).join(&safe_name);
        if file_path.exists() { return json_err(StatusCode::CONFLICT, "database already exists"); }
        let path_clone = file_path.clone();
        let res = tokio::task::spawn_blocking(move || rusqlite::Connection::open(&path_clone).map_err(|e| e.to_string())).await;
        return match res {
            Ok(Ok(_)) => {
                let id = safe_name.clone();
                let cc = ConnectionConfig { id: id.clone(), name: id.clone(), kind: DbKind::Sqlite, url: format!("sqlite://{}", file_path.to_string_lossy()), readonly: false, pool_size: 5, description: String::new() };
                let _ = mgr.add_connection(cc).await;
                json_ok(serde_json::json!({"ok": true, "name": id}))
            }
            _ => json_err(StatusCode::INTERNAL_SERVER_ERROR, "failed to create database file"),
        };
    }

    if ep.starts_with("delete_database/") && method == Method::POST {
        let name = ep.trim_start_matches("delete_database/");
        if name == "OmniDB" || name == "OmniVPN" { return json_err(StatusCode::FORBIDDEN, "cannot delete system database"); }
        if name.is_empty() { return json_err(StatusCode::BAD_REQUEST, "name required"); }
        if let Some(dir) = &mgr.config.db_dir {
            let file_path = Path::new(dir).join(name);
            if file_path.exists() { let _ = std::fs::remove_file(&file_path); }
            let _ = std::fs::remove_file(Path::new(dir).join(format!("{}-wal", name)));
            let _ = std::fs::remove_file(Path::new(dir).join(format!("{}-shm", name)));
        }
        let _ = mgr.remove_connection(name).await;
        return json_ok(serde_json::json!({"ok": true}));
    }

    if ep.starts_with("export/") && method == Method::GET {
        let name = ep.trim_start_matches("export/");
        let conn = match mgr.conns.read().await.get(name).cloned() { Some(c) => c, None => return json_err(StatusCode::NOT_FOUND, "connection not found") };
        return match export_database(&conn.pool).await {
            Ok(data) => Response::builder().status(StatusCode::OK).header("content-type", "application/octet-stream").header("content-disposition", format!("attachment; filename=\"{}.db\"", name)).body(Body::from(data)).unwrap_or_else(|_| Response::new(Body::empty())),
            Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e),
        };
    }

    if ep.starts_with("import/") && method == Method::POST {
        let name = ep.trim_start_matches("import/");
        let conn = match mgr.conns.read().await.get(name).cloned() { Some(c) => c, None => return json_err(StatusCode::NOT_FOUND, "connection not found") };
        return match import_database(&conn.pool, body.to_vec()).await {
            Ok(_) => json_ok(serde_json::json!({"ok": true})),
            Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e),
        };
    }

    if ep.starts_with("connections/") && method == Method::GET {
        let rest = ep.trim_start_matches("connections/");
        if let Some((id, _)) = rest.split_once("/tables") {
            let conn = match mgr.conns.read().await.get(id).cloned() { Some(c) => c, None => return json_err(StatusCode::NOT_FOUND, "connection not found") };
            if rest.ends_with("/tables") {
                return match list_tables(&conn.pool).await {
                    Ok(t) => json_ok(serde_json::json!({"tables": t})),
                    Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
                };
            }
            if let Some((_, table_part)) = rest.split_once("/tables/") {
                if let Some((tbl, _)) = table_part.split_once("/rows") {
                    let limit = qmap.get("limit").and_then(|s| s.parse().ok()).unwrap_or(50);
                    let offset = qmap.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0);
                    let search = qmap.get("search").cloned();
                    return match get_rows(&conn.pool, tbl, limit, offset, search).await {
                        Ok(r) => json_ok(r),
                        Err(e) => json_err(StatusCode::BAD_REQUEST, e),
                    };
                }
                if let Some((tbl, _)) = table_part.split_once("/schema") {
                    return match describe_table(&conn.pool, tbl).await {
                        Ok(c) => json_ok(serde_json::json!({"columns": c})),
                        Err(e) => json_err(StatusCode::BAD_GATEWAY, e),
                    };
                }
            }
        }
    }

    if ep.starts_with("create_table/") && method == Method::POST {
        let id = ep.trim_start_matches("create_table/");
        let conn = match mgr.conns.read().await.get(id).cloned() { Some(c) => c, None => return json_err(StatusCode::NOT_FOUND, "connection not found") };
        let req: CreateTableRequest = match serde_json::from_slice(&body) { Ok(r) => r, Err(e) => return json_err(StatusCode::BAD_REQUEST, format!("invalid json: {e}")) };
        return match create_table(&conn.pool, &req.name, &req.columns).await {
            Ok(_) => json_ok(serde_json::json!({"ok": true})),
            Err(e) => json_err(StatusCode::BAD_REQUEST, e),
        };
    }

    if ep.starts_with("drop_table/") && method == Method::POST {
        let rest = ep.trim_start_matches("drop_table/");
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() == 2 {
            let id = parts[0];
            let tbl = parts[1];
            let conn = match mgr.conns.read().await.get(id).cloned() { Some(c) => c, None => return json_err(StatusCode::NOT_FOUND, "connection not found") };
            return match drop_table(&conn.pool, tbl).await {
                Ok(_) => json_ok(serde_json::json!({"ok": true})),
                Err(e) => json_err(StatusCode::BAD_REQUEST, e),
            };
        }
    }

    // Управление строками: `connections/{id}/tables/{tbl}/row`
    if ep.starts_with("connections/") {
        let parts: Vec<&str> = ep.split('/').collect();
        // 0: connections, 1: id, 2: tables, 3: table, 4: row
        if parts.len() >= 5 && parts[0] == "connections" && parts[2] == "tables" && parts[4] == "row" {
            let id = parts[1];
            let tbl = parts[3];
            let conn = match mgr.conns.read().await.get(id).cloned() { Some(c) => c, None => return json_err(StatusCode::NOT_FOUND, "connection not found") };
            
            if method == Method::POST {
                let req: RowRequest = match serde_json::from_slice(&body) { Ok(r) => r, Err(e) => return json_err(StatusCode::BAD_REQUEST, format!("invalid json: {e}")) };
                return match insert_row(&conn.pool, tbl, req).await {
                    Ok(_) => json_ok(serde_json::json!({"ok": true})),
                    Err(e) => json_err(StatusCode::BAD_REQUEST, e),
                };
            }
            if method == Method::PUT {
                let req: RowRequest = match serde_json::from_slice(&body) { Ok(r) => r, Err(e) => return json_err(StatusCode::BAD_REQUEST, format!("invalid json: {e}")) };
                return match update_row(&conn.pool, tbl, req).await {
                    Ok(_) => json_ok(serde_json::json!({"ok": true})),
                    Err(e) => json_err(StatusCode::BAD_REQUEST, e),
                };
            }
            if method == Method::DELETE {
                let pk = qmap.get("pk").cloned().unwrap_or_default();
                return match delete_row(&conn.pool, tbl, &pk).await {
                    Ok(_) => json_ok(serde_json::json!({"ok": true})),
                    Err(e) => json_err(StatusCode::BAD_REQUEST, e),
                };
            }
        }
    }

    json_err(StatusCode::NOT_FOUND, "unknown db endpoint")
}

// ── moved from vpn::db (shared SQL schema helpers) ──
pub fn client_table_name(name: &str) -> String {
    let safe: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect();
    if safe.is_empty() || safe.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(true) || safe.to_lowercase().starts_with("sqlite_") { format!("c_{}", safe) } else { safe }
}

pub fn create_client_table(conn: &rusqlite::Connection, name: &str) -> rusqlite::Result<()> {
let tbl = client_table_name(name);
conn.execute(&format!(
    "CREATE TABLE IF NOT EXISTS \"{}\" (\
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL DEFAULT 0, \
        interface_id TEXT NOT NULL DEFAULT 'vpn0', name TEXT NOT NULL, \
        password TEXT NOT NULL DEFAULT '', ipv4_address TEXT NOT NULL, ipv6_address TEXT NOT NULL, \
        vpn_ipv4_address TEXT NOT NULL DEFAULT '', vpn_ipv6_address TEXT NOT NULL DEFAULT '', \
        private_key TEXT NOT NULL, public_key TEXT NOT NULL, pre_shared_key TEXT NOT NULL, \
        allowed_ips TEXT, server_allowed_ips TEXT NOT NULL DEFAULT '[]', firewall_ips TEXT, \
        persistent_keepalive INTEGER NOT NULL DEFAULT 0, mtu INTEGER NOT NULL DEFAULT 1420, \
        dns TEXT, server_endpoint TEXT, enabled INTEGER NOT NULL DEFAULT 1, expires_at TEXT, \
        j_c INTEGER, j_min INTEGER, j_max INTEGER, \
        i1 TEXT, i2 TEXT, i3 TEXT, i4 TEXT, i5 TEXT, \
        content_padding_addition TEXT, rekey_after_time TEXT, rekey_timeout TEXT, \
        reject_after_time TEXT, keepalive_timeout TEXT, max_handshake_attempts TEXT, \
        disable_cookies INTEGER, \
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP\
    )", tbl), []).map(|_| ())
}
