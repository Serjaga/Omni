
use omni_db::{client_table_name, create_client_table};
use super::*;
use rusqlite::{params, Connection, OptionalExtension, Row};

fn gs(r: &Row, k: &str) -> Option<String> { r.get::<_, Option<String>>(k).ok().flatten() }
fn gi(r: &Row, k: &str) -> Option<i64> { r.get::<_, Option<i64>>(k).ok().flatten() }

pub fn row_to_client(r: &Row) -> rusqlite::Result<Client> {
Ok(Client {
    id: gi(r, "id").unwrap_or(0), user_id: gi(r, "user_id").unwrap_or(0),
    interface_id: gs(r, "interface_id").unwrap_or_else(|| "vpn0".into()),
    name: gs(r, "name").unwrap_or_default(),
    password: gs(r, "password").unwrap_or_default(),
    ipv4_address: gs(r, "ipv4_address").unwrap_or_default(),
    ipv6_address: gs(r, "ipv6_address").unwrap_or_default(),
    vpn_ipv4_address: gs(r, "vpn_ipv4_address").unwrap_or_default(),
    vpn_ipv6_address: gs(r, "vpn_ipv6_address").unwrap_or_default(),
    private_key: gs(r, "private_key").unwrap_or_default(),
    public_key: gs(r, "public_key").unwrap_or_default(),
    pre_shared_key: gs(r, "pre_shared_key").unwrap_or_default(),
    allowed_ips: gs(r, "allowed_ips").and_then(|s| serde_json::from_str(&s).ok()),
    server_allowed_ips: gs(r, "server_allowed_ips").and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default(),
    firewall_ips: gs(r, "firewall_ips").and_then(|s| serde_json::from_str(&s).ok()),
    persistent_keepalive: gi(r, "persistent_keepalive").unwrap_or(0),
    mtu: gi(r, "mtu").unwrap_or(1420),
    dns: gs(r, "dns").and_then(|s| serde_json::from_str(&s).ok()),
    server_endpoint: gs(r, "server_endpoint"),
    expires_at: gs(r, "expires_at"), enabled: gi(r, "enabled").unwrap_or(1),
    j_c: gi(r, "j_c"), j_min: gi(r, "j_min"), j_max: gi(r, "j_max"),
    i1: gs(r, "i1"), i2: gs(r, "i2"), i3: gs(r, "i3"), i4: gs(r, "i4"), i5: gs(r, "i5"),
    content_padding_addition: gs(r, "content_padding_addition"),
    rekey_after_time: gs(r, "rekey_after_time"),
    rekey_timeout: gs(r, "rekey_timeout"),
    reject_after_time: gs(r, "reject_after_time"),
    keepalive_timeout: gs(r, "keepalive_timeout"),
    max_handshake_attempts: gs(r, "max_handshake_attempts"),
    disable_cookies: gi(r, "disable_cookies"),
    created_at: gs(r, "created_at").unwrap_or_default(),
    updated_at: gs(r, "updated_at").unwrap_or_default(),
})
}

pub fn drop_client_table(conn: &Connection, name: &str) -> rusqlite::Result<()> { conn.execute(&format!("DROP TABLE IF EXISTS \"{}\"", client_table_name(name)), []).map(|_| ()) }

pub fn list_client_tables(conn: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT IN ('vpn_one_time_links','vpn_clients','OmniVPN') AND name NOT LIKE 'c\\_%\\_config' ESCAPE '\\'")?;
    let out: Vec<String> = stmt.query_map([], |r| r.get::<_, String>(0))?.filter_map(Result::ok).collect();
    Ok(out)
}

pub fn get_interface(conn: &Connection) -> rusqlite::Result<VpnInterface> {
    conn.query_row("SELECT * FROM \"OmniVPN\" WHERE id=1", [], |r| {
        let private_key = gs(r, "iface_private_key").unwrap_or_default();
        let public_key = if private_key.is_empty() { String::new() } else { crypto::pubkey(&private_key).unwrap_or_default() };
        Ok(VpnInterface {
            name: VPN_IFACE.into(), device: gs(r, "device").unwrap_or_else(|| "eth0".into()),
            port: gi(r, "port").unwrap_or(880),
            vpn_port: gi(r, "vpn_port").unwrap_or(888),
            private_key, public_key,
            ipv4_cidr: gs(r, "ipv4_cidr").unwrap_or_else(|| "10.80.0.0/24".into()),
            ipv6_cidr: gs(r, "ipv6_cidr").unwrap_or_else(|| "fdcc::80:0/112".into()),
            vpn_ipv4_cidr: gs(r, "vpn_ipv4_cidr").unwrap_or_else(|| "10.88.0.0/24".into()),
            vpn_ipv6_cidr: gs(r, "vpn_ipv6_cidr").unwrap_or_else(|| "fdcc::88:0/112".into()),
            mtu: gi(r, "iface_mtu").unwrap_or(1420),
            routing_table: gs(r, "routing_table").unwrap_or_else(|| "auto".into()),
            enabled: gi(r, "iface_enabled").unwrap_or(1),
            firewall_enabled: gi(r, "firewall_enabled").unwrap_or(0),
            j_c: gi(r, "iface_j_c"), j_min: gi(r, "iface_j_min"), j_max: gi(r, "iface_j_max"),
            s1: gi(r, "s1"), s2: gi(r, "s2"), s3: gi(r, "s3"), s4: gi(r, "s4"),
            h1: gs(r, "h1"), h2: gs(r, "h2"), h3: gs(r, "h3"), h4: gs(r, "h4"),
            i1: gs(r, "iface_i1"), i2: gs(r, "iface_i2"), i3: gs(r, "iface_i3"), i4: gs(r, "iface_i4"), i5: gs(r, "iface_i5"),
            header_protection_key: gs(r, "header_protection_key"),
            content_padding_addition: gs(r, "content_padding_addition"),
            rekey_after_time: gs(r, "rekey_after_time"),
            rekey_timeout: gs(r, "rekey_timeout"),
            reject_after_time: gs(r, "reject_after_time"),
            keepalive_timeout: gs(r, "keepalive_timeout"),
            max_handshake_attempts: gs(r, "max_handshake_attempts"),
            random_trailers: gi(r, "random_trailers"),
            disable_cookies: gi(r, "disable_cookies"),
            created_at: gs(r, "created_at").unwrap_or_default(),
            updated_at: gs(r, "updated_at").unwrap_or_default(),
        })
    })
}

pub fn get_hooks(_conn: &Connection) -> rusqlite::Result<Hooks> { Ok(Hooks { id: VPN_IFACE.into(), pre_up: String::new(), post_up: String::new(), pre_down: String::new(), post_down: String::new() }) }

pub fn get_user_config(conn: &Connection) -> rusqlite::Result<UserConfig> {
    conn.query_row("SELECT * FROM \"OmniVPN\" WHERE id=1", [], |r| {
        Ok(UserConfig {
            id: VPN_IFACE.into(),
            default_mtu: gi(r, "default_mtu").unwrap_or(1420),
            default_persistent_keepalive: gi(r, "default_persistent_keepalive").unwrap_or(0),
            default_dns: gs(r, "default_dns").and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_else(|| vec!["1.1.1.1".into()]),
            default_allowed_ips: gs(r, "default_allowed_ips").and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_else(|| vec!["0.0.0.0/0".into()]),
            default_j_c: gi(r, "default_j_c"), default_j_min: gi(r, "default_j_min"), default_j_max: gi(r, "default_j_max"),
            default_i1: gs(r, "default_i1"), default_i2: gs(r, "default_i2"), default_i3: gs(r, "default_i3"), default_i4: gs(r, "default_i4"), default_i5: gs(r, "default_i5"),
            host: gs(r, "host").unwrap_or_default(), port: gi(r, "port").unwrap_or(880),
        })
    })
}

pub fn update_interface_keypair(conn: &Connection, _name: &str, sk: &str, pk: &str) -> rusqlite::Result<()> {
    conn.execute("UPDATE \"OmniVPN\" SET iface_private_key=?1, iface_public_key=?2, updated_at=CURRENT_TIMESTAMP WHERE id=1", params![sk, pk])?;
    Ok(())
}

pub fn list_clients(omni_conn: &Connection, vpn_conn: &Connection) -> rusqlite::Result<Vec<Client>> {
    let mut out = Vec::new();
    if let Ok(c) = omni_conn.query_row("SELECT * FROM \"OmniVPN\" WHERE id=1", [], row_to_client) { out.push(c); }
    for tbl in list_client_tables(vpn_conn)? {
        if let Ok(c) = vpn_conn.query_row(&format!("SELECT * FROM \"{}\" LIMIT 1", tbl), [], row_to_client) { out.push(c); }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

pub fn find_client_by_id(omni_conn: &Connection, vpn_conn: &Connection, id: i64) -> rusqlite::Result<Option<Client>> {
    if let Ok(c) = omni_conn.query_row("SELECT * FROM \"OmniVPN\" WHERE id=?1 LIMIT 1", params![id], row_to_client) { return Ok(Some(c)); }
    for tbl in list_client_tables(vpn_conn)? {
        if let Ok(c) = vpn_conn.query_row(&format!("SELECT * FROM \"{}\" WHERE id=?1 LIMIT 1", tbl), params![id], row_to_client) { return Ok(Some(c)); }
    }
    Ok(None)
}

pub fn next_global_id(omni_conn: &Connection, vpn_conn: &Connection) -> rusqlite::Result<i64> {
    let mut max = 1i64;
    if let Ok(m) = omni_conn.query_row("SELECT COALESCE(MAX(id),0) FROM \"OmniVPN\"", [], |r| r.get::<_, i64>(0)) { if m > max { max = m; } }
    for tbl in list_client_tables(vpn_conn)? {
        if let Ok(m) = vpn_conn.query_row(&format!("SELECT COALESCE(MAX(id),0) FROM \"{}\"", tbl), [], |r| r.get::<_, i64>(0)) { if m > max { max = m; } }
    }
    Ok(max + 1)
}

pub fn insert_client(omni_conn: &Connection, vpn_conn: &Connection, c: &Client) -> rusqlite::Result<i64> {
let _ = omni_conn;
if c.name == "OmniVPN" { return Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT), Some("'OmniVPN' is reserved".into()))); }
create_client_table(vpn_conn, &c.name)?;
let tbl = client_table_name(&c.name);
let id = if c.id > 0 { c.id } else { next_global_id(omni_conn, vpn_conn)? };
let sql = format!(
    "INSERT INTO \"{}\" (id,user_id,interface_id,name,password,ipv4_address,ipv6_address,vpn_ipv4_address,vpn_ipv6_address,private_key,public_key,pre_shared_key,allowed_ips,server_allowed_ips,firewall_ips,persistent_keepalive,mtu,dns,server_endpoint,enabled,expires_at,j_c,j_min,j_max,i1,i2,i3,i4,i5,content_padding_addition,rekey_after_time,rekey_timeout,reject_after_time,keepalive_timeout,max_handshake_attempts,disable_cookies) \
     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33,?34,?35,?36)", tbl);
vpn_conn.execute(&sql, params![
    id, c.user_id, c.interface_id, c.name, c.password, c.ipv4_address, c.ipv6_address,
    c.vpn_ipv4_address, c.vpn_ipv6_address,
    c.private_key, c.public_key, c.pre_shared_key,
    c.allowed_ips.as_ref().map(|v| serde_json::to_string(v).unwrap_or_default()),
    serde_json::to_string(&c.server_allowed_ips).unwrap_or_else(|_| "[]".into()),
    c.firewall_ips.as_ref().map(|v| serde_json::to_string(v).unwrap_or_default()),
    c.persistent_keepalive, c.mtu,
    c.dns.as_ref().map(|v| serde_json::to_string(v).unwrap_or_default()),
    c.server_endpoint, c.enabled, c.expires_at,
    c.j_c, c.j_min, c.j_max,
    c.i1, c.i2, c.i3, c.i4, c.i5,
    c.content_padding_addition, c.rekey_after_time, c.rekey_timeout,
    c.reject_after_time, c.keepalive_timeout, c.max_handshake_attempts, c.disable_cookies,
])?;
Ok(id)
}

pub fn update_client(omni_conn: &Connection, vpn_conn: &Connection, id: i64, old_name: &str, c: &Client) -> rusqlite::Result<()> {
let is_omni = omni_conn.query_row("SELECT COUNT(*) FROM \"OmniVPN\" WHERE id=?1", params![id], |r| r.get::<_, i64>(0)).unwrap_or(0) > 0;
if is_omni {
    omni_conn.execute(
        r#"UPDATE "OmniVPN" SET
            password=?1, ipv4_address=?2, ipv6_address=?3, allowed_ips=?4,
            server_allowed_ips=?5, firewall_ips=?6, persistent_keepalive=?7,
            mtu=?8, dns=?9, server_endpoint=?10, enabled=?11, expires_at=?12,
            j_c=?13, j_min=?14, j_max=?15,
            i1=?16, i2=?17, i3=?18, i4=?19, i5=?20,
            content_padding_addition=?21, rekey_after_time=?22, rekey_timeout=?23,
            reject_after_time=?24, keepalive_timeout=?25, max_handshake_attempts=?26,
            disable_cookies=?27,
            vpn_ipv4_address=?28, vpn_ipv6_address=?29,
            updated_at=CURRENT_TIMESTAMP
           WHERE id=1"#,
        params![
            c.password, c.ipv4_address, c.ipv6_address,
            c.allowed_ips.as_ref().map(|v| serde_json::to_string(v).unwrap_or_default()),
            serde_json::to_string(&c.server_allowed_ips).unwrap_or_else(|_| "[]".into()),
            c.firewall_ips.as_ref().map(|v| serde_json::to_string(v).unwrap_or_default()),
            c.persistent_keepalive, c.mtu,
            c.dns.as_ref().map(|v| serde_json::to_string(v).unwrap_or_default()),
            c.server_endpoint, c.enabled, c.expires_at,
            c.j_c, c.j_min, c.j_max,
            c.i1, c.i2, c.i3, c.i4, c.i5,
            c.content_padding_addition, c.rekey_after_time, c.rekey_timeout,
            c.reject_after_time, c.keepalive_timeout, c.max_handshake_attempts, c.disable_cookies,
            c.vpn_ipv4_address, c.vpn_ipv6_address,
        ],
    )?;
    return Ok(());
}
if old_name != c.name {
    let old_tbl = client_table_name(old_name);
    let existing: Option<Client> = vpn_conn.query_row(&format!("SELECT * FROM \"{}\" WHERE id = ?1 LIMIT 1", old_tbl), params![id], row_to_client).optional()?;
    drop_client_table(vpn_conn, old_name)?;
    create_client_table(vpn_conn, &c.name)?;
    if existing.is_some() { insert_client(omni_conn, vpn_conn, c)?; }
} else {
    let tbl = client_table_name(&c.name);
    vpn_conn.execute(&format!("UPDATE \"{}\" SET \
        password=?1, ipv4_address=?2, ipv6_address=?3, vpn_ipv4_address=?4, vpn_ipv6_address=?5, allowed_ips=?6, \
        server_allowed_ips=?7, firewall_ips=?8, persistent_keepalive=?9, \
        mtu=?10, dns=?11, server_endpoint=?12, enabled=?13, expires_at=?14, \
        j_c=?15, j_min=?16, j_max=?17, \
        i1=?18, i2=?19, i3=?20, i4=?21, i5=?22, \
        content_padding_addition=?23, rekey_after_time=?24, rekey_timeout=?25, \
        reject_after_time=?26, keepalive_timeout=?27, max_handshake_attempts=?28, \
        disable_cookies=?29, \
        updated_at=CURRENT_TIMESTAMP WHERE id=?30", tbl),
        params![c.password, c.ipv4_address, c.ipv6_address,
            c.vpn_ipv4_address, c.vpn_ipv6_address,
            c.allowed_ips.as_ref().map(|v| serde_json::to_string(v).unwrap_or_default()),
            serde_json::to_string(&c.server_allowed_ips).unwrap_or_else(|_| "[]".into()),
            c.firewall_ips.as_ref().map(|v| serde_json::to_string(v).unwrap_or_default()),
            c.persistent_keepalive, c.mtu,
            c.dns.as_ref().map(|v| serde_json::to_string(v).unwrap_or_default()),
            c.server_endpoint, c.enabled, c.expires_at,
            c.j_c, c.j_min, c.j_max,
            c.i1, c.i2, c.i3, c.i4, c.i5,
            c.content_padding_addition, c.rekey_after_time, c.rekey_timeout,
            c.reject_after_time, c.keepalive_timeout, c.max_handshake_attempts, c.disable_cookies,
            id,
        ])?;
}
Ok(())
}

pub fn toggle_client(omni_conn: &Connection, vpn_conn: &Connection, id: i64, enabled: bool) -> rusqlite::Result<()> {
    if omni_conn.execute("UPDATE \"OmniVPN\" SET enabled=?1, updated_at=CURRENT_TIMESTAMP WHERE id=?2", params![if enabled { 1 } else { 0 }, id]).unwrap_or(0) > 0 { return Ok(()); }
    for tbl in list_client_tables(vpn_conn)? {
        if vpn_conn.execute(&format!("UPDATE \"{}\" SET enabled=?1, updated_at=CURRENT_TIMESTAMP WHERE id=?2", tbl), params![if enabled { 1 } else { 0 }, id]).unwrap_or(0) > 0 { return Ok(()); }
    }
    Ok(())
}

pub fn delete_client(_omni_conn: &Connection, vpn_conn: &Connection, id: i64) -> rusqlite::Result<()> {
    if id == 1 { return Ok(()); }
    let _ = vpn_conn.execute("DELETE FROM vpn_one_time_links WHERE client_id=?1", params![id]);
    for tbl in list_client_tables(vpn_conn)? {
        if let Ok(name) = vpn_conn.query_row(&format!("SELECT name FROM \"{}\" WHERE id=?1", tbl), params![id], |r| r.get::<_, String>(0)) {
            if name == "OmniVPN" { continue; }
            drop_client_table(vpn_conn, &name)?;
            return Ok(());
        }
    }
    Ok(())
}

pub fn get_otl(conn: &Connection, token: &str) -> rusqlite::Result<Option<(i64, String)>> {
    conn.query_row("SELECT client_id, expires_at FROM vpn_one_time_links WHERE one_time_link = ?1", params![token], |r| Ok((r.get(0)?, r.get(1)?))).optional()
}
pub fn upsert_otl(conn: &Connection, client_id: i64, token: &str, expires_at: &str) -> rusqlite::Result<()> {
    conn.execute("INSERT INTO vpn_one_time_links (id, client_id, one_time_link, expires_at) VALUES (?1, ?1, ?2, ?3) ON CONFLICT(id) DO UPDATE SET one_time_link=excluded.one_time_link, expires_at=excluded.expires_at", params![client_id, token, expires_at])?;
    Ok(())
}
pub fn delete_otl(conn: &Connection, client_id: i64) -> rusqlite::Result<()> { conn.execute("DELETE FROM vpn_one_time_links WHERE client_id=?1", params![client_id])?; Ok(()) }
