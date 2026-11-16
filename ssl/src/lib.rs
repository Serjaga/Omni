use omni_db as db;
// src/ssl.rs — TLS/ACME, хранение в OmniSsl
use axum::body::Body;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::{ecdsa::{signature::Signer, SigningKey}, pkcs8::{EncodePrivateKey, DecodePrivateKey, LineEnding}};
use rand::rngs::OsRng;
use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pemfile::{certs, private_key};
use serde::Deserialize;
use serde_json::json;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;


#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub enum AcmeMode { False, Http, Tls, #[default] All }

impl<'de> Deserialize<'de> for AcmeMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: serde::Deserializer<'de> {
        let s = String::deserialize(deserializer)?.to_lowercase();
        match s.as_str() {
            "false" | "no" | "0" | "off" => Ok(AcmeMode::False),
            "http" => Ok(AcmeMode::Http),
            "tls" | "tls-alpn" | "alpn" => Ok(AcmeMode::Tls),
            "all" | "auto" | "true" | "yes" | "1" | "both" => Ok(AcmeMode::All),
            _ => Err(serde::de::Error::custom("acme_mode must be 'false' | 'http' | 'tls' | 'all'")),
        }
    }
}

#[derive(Clone, Debug)]
pub enum AcmeIdentifier { Ip(IpAddr), Dns(String) }

impl AcmeIdentifier {
    pub fn filename(&self) -> String { match self { AcmeIdentifier::Ip(ip) => ip.to_string(), AcmeIdentifier::Dns(d) => d.clone() } }
    pub fn acme_identifier(&self) -> serde_json::Value { match self { AcmeIdentifier::Ip(ip) => json!({"type": "ip", "value": ip.to_string()}), AcmeIdentifier::Dns(d) => json!({"type": "dns", "value": d.clone()}) } }
    pub fn add_san(&self, params: &mut rcgen::CertificateParams) -> Result<(), String> { match self { AcmeIdentifier::Ip(ip) => params.subject_alt_names.push(rcgen::SanType::IpAddress(*ip)), AcmeIdentifier::Dns(d) => params.subject_alt_names.push(rcgen::SanType::DnsName(d.as_str().try_into().map_err(|e| format!("{:?}", e))?)) } Ok(()) }
    pub fn describe(&self) -> String { match self { AcmeIdentifier::Ip(ip) => format!("IP {}", ip), AcmeIdentifier::Dns(d) => format!("domain {}", d) } }
    pub fn is_ip(&self) -> bool { matches!(self, AcmeIdentifier::Ip(_)) }
}

#[derive(Clone, Copy, Debug)]
pub enum ChallengeType { Http01, TlsAlpn01 }
impl ChallengeType {
    pub fn as_str(&self) -> &'static str { match self { Self::Http01 => "HTTP-01", Self::TlsAlpn01 => "TLS-ALPN-01" } }
}

#[derive(Debug)]
pub struct SslManager {
    pub certs: Arc<RwLock<Vec<(Vec<String>, Arc<CertifiedKey>)>>>,
    pub default_cert: Arc<RwLock<Option<Arc<CertifiedKey>>>>,
    pub challenges: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>,
}

impl SslManager {
    pub fn new() -> Self {
        Self {
            certs: Arc::new(RwLock::new(Vec::new())),
            default_cert: Arc::new(RwLock::new(None)),
            challenges: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn reload_from_db(&self) -> Result<(), String> {
        let db = db::global().ok_or("db not initialized")?;
        let omni = db.conns.read().await.get("OmniDB").cloned().ok_or("OmniDB missing")?;
        let db::Pool::Sqlite(p) = &omni.pool;
        let p_read = p.clone();

        let rows = tokio::task::spawn_blocking(move || {
            let g = p_read.lock().map_err(|e| e.to_string())?;
            let mut stmt = g.prepare("SELECT domain, cert_pem, key_pem FROM \"OmniSsl\" WHERE domain != '_acme_account'").map_err(|e| e.to_string())?;
            let iter = stmt.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
            }).map_err(|e| e.to_string())?;
            let mut out = Vec::new();
            for r in iter { if let Ok(row) = r { out.push(row); } }
            Ok::<_, String>(out)
        }).await.map_err(|e| e.to_string())??;

        let mut new_certs = Vec::new();
        let mut found_default: Option<Arc<CertifiedKey>> = None;
        let mut found_default_has_ip = false;

        for (_domain, cert_pem, key_pem) in rows {
            let cert_bytes = cert_pem.as_bytes();
            let key_bytes = key_pem.as_bytes();
            let certs_vec: Vec<CertificateDer> = certs(&mut &cert_bytes[..]).filter_map(|r| r.ok()).collect();
            if certs_vec.is_empty() { continue; }

            if let Ok(Some(key)) = private_key(&mut &key_bytes[..]) {
                if let Ok(signing_key) = rustls::crypto::ring::sign::any_supported_type(&key) {
                    let ck = Arc::new(CertifiedKey::new(certs_vec, signing_key));
                    let sans: Vec<String> = extract_sans(cert_bytes);

                    let has_ip_san = sans.iter().any(|s| s.parse::<std::net::IpAddr>().is_ok());

                    if found_default.is_none() || (has_ip_san && !found_default_has_ip) {
                        found_default = Some(ck.clone());
                        found_default_has_ip = has_ip_san;
                    }
                    new_certs.push((sans, ck));
                }
            }
        }

        *self.certs.write().unwrap() = new_certs;
        if let Some(d) = found_default { *self.default_cert.write().unwrap() = Some(d); }
        Ok(())
    }

    pub fn set_challenge(&self, ident: &str, ck: Arc<CertifiedKey>) { self.challenges.write().unwrap().insert(ident.to_string(), ck); }
    pub fn remove_challenge(&self, ident: &str) { self.challenges.write().unwrap().remove(ident); }

    pub fn generate_self_signed_default(&self) -> Result<(), String> {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).map_err(|e| e.to_string())?;
        params.subject_alt_names.push(rcgen::SanType::IpAddress(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
        let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        let certs_vec: Vec<CertificateDer> = certs(&mut cert_pem.as_bytes()).filter_map(|r| r.ok()).collect();
        if let Ok(Some(key)) = private_key(&mut key_pem.as_bytes()) {
            if let Ok(signing_key) = rustls::crypto::ring::sign::any_supported_type(&key) {
                *self.default_cert.write().unwrap() = Some(Arc::new(CertifiedKey::new(certs_vec, signing_key)));
            }
        }
        Ok(())
    }
}

impl ResolvesServerCert for SslManager {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let wants_acme_tls_alpn = client_hello.alpn().map(|mut list| list.any(|a| a.eq_ignore_ascii_case(b"acme-tls/1"))).unwrap_or(false);

        if wants_acme_tls_alpn {
            let sni_opt = client_hello.server_name();
            if let Some(sni) = sni_opt {
                if let Some(ck) = self.challenges.read().unwrap().get(sni).cloned() { return Some(ck); }
                let norm = normalize_dns_name(sni);
                if norm != sni {
                    if let Some(ck) = self.challenges.read().unwrap().get(&norm).cloned() { return Some(ck); }
                }
            }
            let chals = self.challenges.read().unwrap();
            if chals.len() == 1 {
                if let Some((_id, ck)) = chals.iter().next() { return Some(ck.clone()); }
            }
            return None;
        }

        if let Some(sni) = client_hello.server_name() {
            let c = self.certs.read().unwrap();
            for (sans, ck) in c.iter() {
                if sans.iter().any(|s| s == sni) {
                    return Some(ck.clone());
                }
            }
            let norm_sni = normalize_dns_name(sni);
            for (sans, ck) in c.iter() {
                if sans.iter().any(|s| normalize_dns_name(s) == norm_sni) {
                    return Some(ck.clone());
                }
            }
        }

        self.default_cert.read().unwrap().clone()
    }
}

pub fn choose_challenge_type(mode: AcmeMode, cert_file: &std::path::Path, key_file: &std::path::Path) -> Option<ChallengeType> {
    match mode {
        AcmeMode::False => None,
        AcmeMode::Http => Some(ChallengeType::Http01),
        AcmeMode::Tls => Some(ChallengeType::TlsAlpn01),
        AcmeMode::All => { if cert_file.exists() && key_file.exists() { Some(ChallengeType::TlsAlpn01) } else { Some(ChallengeType::Http01) } }
    }
}

pub fn build_acme_tls_alpn_cert(ident: &AcmeIdentifier, key_auth: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(key_auth.as_bytes());
    let hash = hasher.finalize();
    let mut ext_content = Vec::with_capacity(34);
    ext_content.push(0x04); ext_content.push(0x20); ext_content.extend_from_slice(&hash);
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
    ident.add_san(&mut params)?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let mut ext = rcgen::CustomExtension::from_oid_content(&[1, 3, 6, 1, 5, 5, 7, 1, 31], ext_content);
    ext.set_criticality(true);
    params.custom_extensions.push(ext);
    let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;
    Ok((cert.pem().into_bytes(), key_pair.serialize_pem().into_bytes()))
}

pub fn build_certified_key_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<CertifiedKey>, String> {
    let certs_vec: Vec<CertificateDer> = certs(&mut &cert_pem[..]).filter_map(|r| r.ok()).collect();
    if certs_vec.is_empty() { return Err("no certificates in PEM".into()); }
    let key = private_key(&mut &key_pem[..]).map_err(|e| e.to_string())?.ok_or("no private key in PEM")?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| e.to_string())?;
    Ok(Arc::new(CertifiedKey::new(certs_vec, signing_key)))
}

pub fn base64url(data: &[u8]) -> String { URL_SAFE_NO_PAD.encode(data) }

pub fn sign_jws(signing_key: &SigningKey, url: &str, nonce: &str, payload: Option<&str>, kid: Option<&str>, jwk: &serde_json::Value) -> String {
    let mut header = json!({ "alg": "ES256", "url": url, "nonce": nonce });
    if let Some(k) = kid { header["kid"] = json!(k); } else { header["jwk"] = jwk.clone(); }
    let header_b64 = base64url(header.to_string().as_bytes());
    let payload_b64 = payload.map(|p| base64url(p.as_bytes())).unwrap_or_default();
    let message = format!("{}.{}", header_b64, payload_b64);
    let signature: p256::ecdsa::Signature = signing_key.sign(message.as_bytes());
    let sig_b64 = base64url(signature.to_bytes().as_ref());
    json!({ "protected": header_b64, "payload": payload_b64, "signature": sig_b64 }).to_string()
}

pub async fn fetch_nonce(client: &reqwest::Client, new_nonce_url: &str) -> Result<String, String> {
    let resp = client.head(new_nonce_url).send().await.map_err(|e| e.to_string())?;
    Ok(resp.headers().get("replay-nonce").ok_or("No nonce")?.to_str().map_err(|e| e.to_string())?.to_string())
}

pub async fn post_acme(client: &reqwest::Client, new_nonce_url: &str, signing_key: &SigningKey, jwk: &serde_json::Value, url: &str, payload: Option<&str>, kid: Option<&str>) -> Result<(String, reqwest::header::HeaderMap), String> {
    let nonce = fetch_nonce(client, new_nonce_url).await?;
    let jws = sign_jws(signing_key, url, &nonce, payload, kid, jwk);
    let resp = client.post(url).header("Content-Type", "application/jose+json").body(jws).send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() { return Err(format!("ACME Error {}: {}", status, body)); }
    Ok((body, headers))
}

pub async fn issue_certificate(ident: &AcmeIdentifier, webroot: &str, challenge_type: ChallengeType, ssl_mgr: &Arc<SslManager>) -> Result<(), String> {
    println!("[ACME] Starting {} for {}...", challenge_type.as_str(), ident.describe());
    let client = reqwest::Client::new();
    let dir_url = "https://acme-v02.api.letsencrypt.org/directory";
    let dir: serde_json::Value = client.get(dir_url).send().await.map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    let new_nonce_url = dir["newNonce"].as_str().ok_or("No newNonce")?.to_string();
    let new_acct_url = dir["newAccount"].as_str().ok_or("No newAccount")?.to_string();
    let new_order_url = dir["newOrder"].as_str().ok_or("No newOrder")?.to_string();

    let db = db::global().ok_or("db not initialized")?;
    let omni = db.conns.read().await.get("OmniDB").cloned().ok_or("OmniDB missing")?;
    let db::Pool::Sqlite(p) = &omni.pool;
    let p = p.clone();

    let p_read = p.clone();
    let acc_key_pem = tokio::task::spawn_blocking(move || -> Option<String> {
        let g = p_read.lock().ok()?;
        g.query_row("SELECT cert_pem FROM \"OmniSsl\" WHERE domain='_acme_account'", [], |r| r.get::<_, String>(0)).ok()
    }).await.ok().flatten();

    let signing_key = if let Some(pem) = acc_key_pem {
        SigningKey::from_pkcs8_pem(&pem).unwrap_or_else(|_| SigningKey::random(&mut OsRng))
    } else {
        let k = SigningKey::random(&mut OsRng);
        let pem = k.to_pkcs8_pem(LineEnding::LF).map_err(|e| e.to_string())?.to_string();
        let pem_c = pem.clone();
        let p_w1 = p.clone();
        tokio::task::spawn_blocking(move || {
            let g = p_w1.lock().map_err(|e| e.to_string())?;
            g.execute("INSERT OR REPLACE INTO \"OmniSsl\" (domain, cert_pem, key_pem) VALUES ('_acme_account', ?1, '')", rusqlite::params![pem_c]).map_err(|e| e.to_string())?;
            Ok::<_, String>(())
        }).await.map_err(|e| e.to_string())??;
        k
    };

    let verify_key = signing_key.verifying_key();
    let encoded_point = verify_key.to_encoded_point(false);
    let bytes = encoded_point.as_bytes();
    let x = &bytes[1..33];
    let y = &bytes[33..65];
    let jwk = json!({"kty": "EC", "crv": "P-256", "x": base64url(x), "y": base64url(y)});
    let jwk_string = jwk.to_string();
    let mut hasher = Sha256::new();
    hasher.update(jwk_string.as_bytes());
    let thumbprint = base64url(hasher.finalize().as_ref());

    let acct_payload = json!({"termsOfServiceAgreed": true, "contact": ["mailto:acme@omnirs.dev"]}).to_string();
    let (acct_body, acct_headers) = post_acme(&client, &new_nonce_url, &signing_key, &jwk, &new_acct_url, Some(&acct_payload), None).await?;
    let kid = acct_headers.get("location").and_then(|v| v.to_str().ok()).map(|s| s.to_string()).or_else(|| serde_json::from_str::<serde_json::Value>(&acct_body).ok().and_then(|v| v["url"].as_str().map(|s| s.to_string()))).ok_or("No account URL")?;

    let mut order_json = json!({"identifiers": [ident.acme_identifier()]});
    if ident.is_ip() { order_json["profile"] = json!("shortlived"); }
    let order_payload = order_json.to_string();
    let (order_body, order_headers) = post_acme(&client, &new_nonce_url, &signing_key, &jwk, &new_order_url, Some(&order_payload), Some(&kid)).await?;
    let order_url = order_headers.get("location").and_then(|v| v.to_str().ok()).map(|s| s.to_string()).or_else(|| serde_json::from_str::<serde_json::Value>(&order_body).ok().and_then(|v| v["url"].as_str().map(|s| s.to_string()))).ok_or("No order URL")?;
    let order: serde_json::Value = serde_json::from_str(&order_body).map_err(|e| e.to_string())?;
    let authz_url = order["authorizations"].as_array().ok_or("No authz")?[0].as_str().ok_or("No authz str")?.to_string();
    let (authz_body, _) = post_acme(&client, &new_nonce_url, &signing_key, &jwk, &authz_url, None, Some(&kid)).await?;
    let authz: serde_json::Value = serde_json::from_str(&authz_body).map_err(|e| e.to_string())?;
    let challenges = authz["challenges"].as_array().ok_or("No challenges")?;

    match challenge_type {
        ChallengeType::Http01 => {
            let http01 = challenges.iter().find(|c| c["type"] == "http-01").ok_or("No http-01 challenge offered")?;
            let token = http01["token"].as_str().ok_or("No token")?.to_string();
            let challenge_url = http01["url"].as_str().ok_or("No challenge URL")?.to_string();
            let key_auth = format!("{}.{}", token, thumbprint);
            // Токен храним в БД (не на диске) — отдаётся из БД хендлером /.well-known/acme-challenge/<token>
            if let Some(db) = db::global() { let _ = db.config_set(&format!("acme_challenge_{token}"), &key_auth).await; }
            let _ = post_acme(&client, &new_nonce_url, &signing_key, &jwk, &challenge_url, Some("{}"), Some(&kid)).await?;
            let mut ok = false;
            for _ in 0..15 {
                tokio::time::sleep(Duration::from_secs(3)).await;
                let (ab, _) = post_acme(&client, &new_nonce_url, &signing_key, &jwk, &authz_url, None, Some(&kid)).await?;
                let a: serde_json::Value = serde_json::from_str(&ab).map_err(|e| e.to_string())?;
                let status = a["status"].as_str().ok_or("No status")?;
                if status == "valid" { ok = true; break; }
                if status == "invalid" { if let Some(db) = db::global() { let _ = db.config_set(&format!("acme_challenge_{token}"), "").await; } return Err(format!("HTTP-01 challenge invalid: {}", a)); }
            }
            if let Some(db) = db::global() { let _ = db.config_set(&format!("acme_challenge_{token}"), "").await; }
            if !ok { return Err("HTTP-01 validation timeout (45s)".into()); }
        }
        ChallengeType::TlsAlpn01 => {
            let tls_alpn = challenges.iter().find(|c| c["type"] == "tls-alpn-01").ok_or("No tls-alpn-01 challenge offered")?;
            let token = tls_alpn["token"].as_str().ok_or("No token")?.to_string();
            let challenge_url = tls_alpn["url"].as_str().ok_or("No challenge URL")?.to_string();
            let key_auth = format!("{}.{}", token, thumbprint);
            let (cert_pem, key_pem) = build_acme_tls_alpn_cert(ident, &key_auth)?;
            let ck = build_certified_key_from_pem(&cert_pem, &key_pem)?;
            let challenge_id = ident.filename();
            ssl_mgr.set_challenge(&challenge_id, ck);
            let _ = post_acme(&client, &new_nonce_url, &signing_key, &jwk, &challenge_url, Some("{}"), Some(&kid)).await?;
            let mut ok = false;
            for _ in 0..15 {
                tokio::time::sleep(Duration::from_secs(3)).await;
                let (ab, _) = post_acme(&client, &new_nonce_url, &signing_key, &jwk, &authz_url, None, Some(&kid)).await?;
                let a: serde_json::Value = serde_json::from_str(&ab).map_err(|e| e.to_string())?;
                let status = a["status"].as_str().ok_or("No status")?;
                if status == "valid" { ok = true; break; }
                if status == "invalid" { ssl_mgr.remove_challenge(&challenge_id); return Err(format!("TLS-ALPN-01 challenge invalid: {}", a)); }
            }
            ssl_mgr.remove_challenge(&challenge_id);
            if !ok { return Err("TLS-ALPN-01 validation timeout (45s)".into()); }
        }
    }

    let cert_key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
    ident.add_san(&mut params)?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params.serialize_request(&cert_key_pair).map_err(|e| e.to_string())?;
    let csr_b64 = base64url(csr.der());
    let finalize_payload = json!({"csr": csr_b64}).to_string();
    let finalize_url = order["finalize"].as_str().ok_or("No finalize URL")?.to_string();
    let _ = post_acme(&client, &new_nonce_url, &signing_key, &jwk, &finalize_url, Some(&finalize_payload), Some(&kid)).await?;

    let mut cert_url = String::new();
    for _ in 0..15 {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let (ob, _) = post_acme(&client, &new_nonce_url, &signing_key, &jwk, &order_url, None, Some(&kid)).await?;
        let o: serde_json::Value = serde_json::from_str(&ob).map_err(|e| e.to_string())?;
        let status = o["status"].as_str().ok_or("No status")?;
        if status == "valid" { cert_url = o["certificate"].as_str().ok_or("No cert URL")?.to_string(); break; }
        else if status == "invalid" { return Err(format!("Order invalid: {}", o)); }
    }
    if cert_url.is_empty() { return Err("Order finalization timeout".into()); }

    let nonce = fetch_nonce(&client, &new_nonce_url).await?;
    let jws = sign_jws(&signing_key, &cert_url, &nonce, None, Some(&kid), &jwk);
    let cert_body = client.post(&cert_url).header("Content-Type", "application/jose+json").body(jws).send().await.map_err(|e| e.to_string())?.text().await.map_err(|e| e.to_string())?;

    let domain = ident.filename();
    let cert_pem = cert_body;
    let key_pem = cert_key_pair.serialize_pem();

    let p_w2 = p.clone();
    tokio::task::spawn_blocking(move || {
        let g = p_w2.lock().map_err(|e| e.to_string())?;
        g.execute("INSERT INTO \"OmniSsl\" (domain, cert_pem, key_pem, updated_at) VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP) ON CONFLICT(domain) DO UPDATE SET cert_pem=excluded.cert_pem, key_pem=excluded.key_pem, updated_at=CURRENT_TIMESTAMP", rusqlite::params![domain, cert_pem, key_pem]).map_err(|e| e.to_string())?;
        Ok::<_, String>(())
    }).await.map_err(|e| e.to_string())??;

    ssl_mgr.reload_from_db().await?;
    println!("[ACME] Certificate successfully issued and saved to DB for {}", ident.describe());
    Ok(())
}

fn json_ok(v: serde_json::Value) -> Response<Body> {
    Response::builder().status(StatusCode::OK).header("content-type", "application/json").body(Body::from(v.to_string())).unwrap()
}
fn json_err(status: StatusCode, msg: impl Into<String>) -> Response<Body> {
    Response::builder().status(status).header("content-type", "application/json").body(Body::from(json!({"error": msg.into()}).to_string())).unwrap()
}

pub async fn dispatch_api(acme_ip: Option<String>, root: std::path::PathBuf, ssl: Option<Arc<SslManager>>, method: Method, endpoint: String, qmap: HashMap<String, String>, _headers: HeaderMap, _body: axum::body::Bytes) -> Response<Body> {
    let ssl_mgr = match &ssl {
        Some(m) => m.clone(),
        None => return json_err(StatusCode::SERVICE_UNAVAILABLE, "ssl not initialized"),
    };

    if endpoint == "certs" && method == Method::GET {
        return json_ok(json!({"status": "ok", "active_certs": ssl_mgr.certs.read().unwrap().len()}));
    }
    if endpoint == "certs/acme_account" && method == Method::GET {
        return json_ok(json!({"status": "active", "provider": "Let's Encrypt"}));
    }
    if endpoint == "certs/list" && method == Method::GET {
        let db = match db::global() { Some(d) => d, None => return json_err(StatusCode::SERVICE_UNAVAILABLE, "db not initialized") };
        let omni = match db.conns.read().await.get("OmniDB").cloned() { Some(o) => o, None => return json_err(StatusCode::SERVICE_UNAVAILABLE, "OmniDB missing") };
        let db::Pool::Sqlite(p) = &omni.pool;
        let p_read = p.clone();
        let list = tokio::task::spawn_blocking(move || -> Vec<serde_json::Value> {
            let g = match p_read.lock() { Ok(g) => g, Err(_) => return Vec::new() };
            let mut stmt = match g.prepare("SELECT domain, cert_pem, key_pem FROM \"OmniSsl\" WHERE domain != '_acme_account'") { Ok(s) => s, Err(_) => return Vec::new() };
            let iter = match stmt.query_map([], |r| {
                let domain: String = r.get(0)?;
                let cert_pem: String = r.get(1)?;
                let key_pem: String = r.get(2)?;
                let mut sans = Vec::new();
                let mut nb = String::new();
                let mut na = String::new();
                let mut days_left = 0i64;
                if let Ok((_, pem)) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()) {
                    if let Ok(cert) = pem.parse_x509() {
                        let not_before = cert.validity().not_before.to_datetime();
                        let not_after = cert.validity().not_after.to_datetime();
                        nb = chrono::DateTime::from_timestamp(not_before.unix_timestamp(), 0).map(|d| d.to_rfc3339()).unwrap_or_default();
                        na = chrono::DateTime::from_timestamp(not_after.unix_timestamp(), 0).map(|d| d.to_rfc3339()).unwrap_or_default();
                        let now_ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
                        days_left = (not_after.unix_timestamp() - now_ts) / 86400;
                        for ext in cert.extensions() {
                            if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                                for gn in &san.general_names {
                                    match gn {
                                        x509_parser::extensions::GeneralName::DNSName(d) => sans.push(d.to_string()),
                                        x509_parser::extensions::GeneralName::IPAddress(ip) => {
                                            if ip.len() == 4 { sans.push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])); }
                                            else if ip.len() == 16 { sans.push("IPv6".to_string()); }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(json!({
                    "file": format!("{}.cer", domain),
                    "domain": domain,
                    "sans": sans,
                    "not_before": nb,
                    "not_after": na,
                    "days_left": days_left,
                    "size": cert_pem.len() + key_pem.len()
                }))
            }) { Ok(i) => i, Err(_) => return Vec::new() };
            iter.filter_map(Result::ok).collect::<Vec<_>>()
        }).await.unwrap_or_default();
        return json_ok(json!(list));
    }
    if endpoint.starts_with("certs/download") && method == Method::GET {
        let name = qmap.get("name").cloned().unwrap_or_default();
        let domain = name.replace(".cer", "");
        let db = match db::global() { Some(d) => d, None => return json_err(StatusCode::SERVICE_UNAVAILABLE, "db not initialized") };
        let omni = match db.conns.read().await.get("OmniDB").cloned() { Some(o) => o, None => return json_err(StatusCode::SERVICE_UNAVAILABLE, "OmniDB missing") };
        let db::Pool::Sqlite(p) = &omni.pool;
        let p_read = p.clone();
        let domain_c = domain.clone();
        let cert_pem = tokio::task::spawn_blocking(move || {
            let g = match p_read.lock() { Ok(g) => g, Err(_) => return String::new() };
            g.query_row("SELECT cert_pem FROM \"OmniSsl\" WHERE domain=?1", rusqlite::params![domain_c], |r| r.get::<_, String>(0)).unwrap_or_default()
        }).await.unwrap_or_default();
        if cert_pem.is_empty() { return json_err(StatusCode::NOT_FOUND, "cert not found"); }
        return Response::builder().status(StatusCode::OK).header("content-type", "application/x-pem-file").header("content-disposition", format!("attachment; filename=\"{}\"", name)).body(Body::from(cert_pem)).unwrap();
    }
    if endpoint == "certs/reload" && method == Method::POST {
        let _ = ssl_mgr.reload_from_db().await;
        return json_ok(json!({"ok": true}));
    }
    if endpoint == "certs/issue_ip" && method == Method::POST {
        let ip_str = match &acme_ip {
            Some(ip) => ip.clone(),
            None => return json_err(StatusCode::BAD_REQUEST, "acme_ip not configured"),
        };
        let ip = match ip_str.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => return json_err(StatusCode::BAD_REQUEST, "invalid acme_ip"),
        };
        let ident = AcmeIdentifier::Ip(ip);
        let webroot = root.to_string_lossy().to_string();
        let mgr = ssl_mgr.clone();
        tokio::spawn(async move {
            let _ = issue_certificate(&ident, &webroot, ChallengeType::TlsAlpn01, &mgr).await;
        });
        return json_ok(json!({"message": "started"}));
    }
    if endpoint == "certs/issue_domain" && method == Method::POST {
        let body_json: serde_json::Value = serde_json::from_slice(&_body).unwrap_or_default();
        let domain = match body_json["domain"].as_str() {
            Some(d) => d.to_string(),
            None => return json_err(StatusCode::BAD_REQUEST, "domain required"),
        };
        let ident = AcmeIdentifier::Dns(domain.clone());
        let webroot = root.to_string_lossy().to_string();
        let mgr = ssl_mgr.clone();
        tokio::spawn(async move {
            let _ = issue_certificate(&ident, &webroot, ChallengeType::Http01, &mgr).await;
        });
        return json_ok(json!({"message": "started"}));
    }
    if endpoint.starts_with("certs/renew") && method == Method::POST {
        let name = qmap.get("name").cloned().unwrap_or_default();
        let domain = name.replace(".cer", "");
        let is_ip = domain.parse::<IpAddr>().is_ok();
        let ident = if is_ip { AcmeIdentifier::Ip(domain.parse().unwrap()) } else { AcmeIdentifier::Dns(domain.clone()) };
        let webroot = root.to_string_lossy().to_string();
        let mgr = ssl_mgr.clone();
        tokio::spawn(async move {
            let ct = if is_ip { ChallengeType::TlsAlpn01 } else { ChallengeType::Http01 };
            let _ = issue_certificate(&ident, &webroot, ct, &mgr).await;
        });
        return json_ok(json!({"message": "renewing"}));
    }
    if endpoint.starts_with("certs/delete") && method == Method::POST {
        let name = qmap.get("name").cloned().unwrap_or_default();
        let domain = name.replace(".cer", "");
        let db = match db::global() { Some(d) => d, None => return json_err(StatusCode::SERVICE_UNAVAILABLE, "db not initialized") };
        let omni = match db.conns.read().await.get("OmniDB").cloned() { Some(o) => o, None => return json_err(StatusCode::SERVICE_UNAVAILABLE, "OmniDB missing") };
        let db::Pool::Sqlite(p) = &omni.pool;
        let p_w = p.clone();
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(g) = p_w.lock() {
                let _ = g.execute("DELETE FROM \"OmniSsl\" WHERE domain=?1", rusqlite::params![domain]);
            }
        }).await;
        let _ = ssl_mgr.reload_from_db().await;
        return json_ok(json!({"ok": true}));
    }

    json_err(StatusCode::NOT_FOUND, "unknown certs endpoint")
}

// ═══════════════════════════════════════════════════════════════════════════
// ACME bootstrap — сбор issuers, чтение существующих сертов, spawn-циклы
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Собирает список (identifier, webroot) из конфига.
/// Webroot берётся из `virtual_hosts[domain]`, иначе — общий `root`.
/// Оставлено как публичный утилитарный API (см. `spawn_renewal_loop`).
pub fn collect_issuers(
    acme_ip: Option<&str>,
    acme_domains: &[String],
    virtual_hosts: &HashMap<String, PathBuf>,
    root: &Path,
) -> Vec<(AcmeIdentifier, String)> {
    let mut issuers = Vec::new();
    if let Some(ip_str) = acme_ip {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            issuers.push((
                AcmeIdentifier::Ip(ip),
                root.to_string_lossy().to_string(),
            ));
        }
    }
    for domain in acme_domains {
        let webroot = virtual_hosts
            .get(domain)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| root.to_string_lossy().to_string());
        issuers.push((AcmeIdentifier::Dns(domain.clone()), webroot));
    }
    issuers
}

/// Читает список доменов, для которых серт уже лежит в `OmniSsl`.
/// Пустой набор — вызывающий код трактует как «всё надо выпускать».
pub async fn existing_certs_in_db() -> HashSet<String> {
    match db::global() {
        Some(db) => list_db_cert_domains(&db).await.into_iter().collect(),
        None => HashSet::new(),
    }
}

/// Deprecated: вся работа делегирована `spawn_renewal_loop`.
/// Оставлено для обратной совместимости (no-op).
pub fn spawn_initial_issuance(
    _issuers: Vec<(AcmeIdentifier, String)>,
    _existing_in_db: HashSet<String>,
    _mode: AcmeMode,
    _resolver: Arc<SslManager>,
) {
    // no-op — см. spawn_renewal_loop
}

/// Единый менеджер ACME: и первичный выпуск, и продление.
///
/// Ключевые свойства:
///   • Раз в 4 часа перечитывает конфиг из БД → подхватывает новые домены,
///     добавленные через админку, без рестарта процесса.
///   • Дополняет список issuer'ов всеми сертами из таблицы `OmniSsl` →
///     серты, выпущенные через API `/api/certs/issue_*`, тоже продлеваются.
///   • Для IP всегда использует TLS-ALPN-01 (LE не предлагает HTTP-01 для IP).
///   • Порог продления — половина срока жизни для короткоживущих сертов
///     (6-дневные IP-серты) и 7 дней для стандартных 90-дневных.
///   • После успешного выпуска вызывает `ssl_mgr.reload_from_db()`, чтобы
///     новые серты начали использоваться живыми TLS-соединениями без рестарта.
pub fn spawn_renewal_loop(mode: AcmeMode, resolver: Arc<SslManager>) {
    if mode == AcmeMode::False {
        return;
    }
    tokio::spawn(async move {
        // Дать серверу подняться и БД проинициализироваться
        tokio::time::sleep(Duration::from_secs(30)).await;
        loop {
            if let Err(e) = renewal_iteration(mode, &resolver).await {
                eprintln!("[ACME] renewal iteration failed: {e}");
            }
            tokio::time::sleep(Duration::from_secs(4 * 3600)).await;
        }
    });
}

async fn renewal_iteration(mode: AcmeMode, resolver: &Arc<SslManager>) -> Result<(), String> {
    let db = db::global().ok_or("db not initialized")?;
    let map = db.config_map().await.map_err(|e| format!("config_map: {e}"))?;

    let get_raw = |k: &str| {
        map.get(k)
            .map(|s| s.trim_matches(|c: char| c == '"' || c == '\'').to_string())
    };

    let webroot = get_raw("root").unwrap_or_else(|| "./public".into());

    // 1) Issuer'ы из конфига
    let mut issuers: Vec<(AcmeIdentifier, String)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let ip_source = get_raw("acme_ip").filter(|s| !s.is_empty())
        .or_else(|| get_raw("address").filter(|s| !s.is_empty() && s != "0.0.0.0"));
    if let Some(ip_str) = ip_source {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            let ident = AcmeIdentifier::Ip(ip);
            if seen.insert(ident.filename()) {
                issuers.push((ident, webroot.clone()));
            }
        }
    }

    if let Some(list) = get_raw("acme_domains") {
        for raw in list.split(',') {
            let d = raw.trim();
            if d.is_empty() { continue; }
            let ident = if let Ok(ip) = d.parse::<IpAddr>() {
                AcmeIdentifier::Ip(ip)
            } else {
                AcmeIdentifier::Dns(d.to_string())
            };
            if seen.insert(ident.filename()) {
                issuers.push((ident, webroot.clone()));
            }
        }
    }

    // 2) Дополняем всеми сертами из БД (в т.ч. выписанными через API)
    for domain in list_db_cert_domains(&db).await {
        let ident = if let Ok(ip) = domain.parse::<IpAddr>() {
            AcmeIdentifier::Ip(ip)
        } else {
            AcmeIdentifier::Dns(domain)
        };
        if seen.insert(ident.filename()) {
            issuers.push((ident, webroot.clone()));
        }
    }

    if issuers.is_empty() {
        return Ok(());
    }

    // 3) Проверяем и обновляем
    for (ident, wr) in &issuers {
        if !cert_needs_work(&db, &ident.filename()).await {
            continue;
        }

        let ct = if ident.is_ip() {
            // LE не предлагает HTTP-01 для IP-идентификаторов → строго TLS-ALPN-01
            ChallengeType::TlsAlpn01
        } else {
            match mode {
                AcmeMode::Http => ChallengeType::Http01,
                AcmeMode::Tls  => ChallengeType::TlsAlpn01,
                AcmeMode::All  => ChallengeType::TlsAlpn01,
                AcmeMode::False => continue,
            }
        };

        let action = if db_has_cert(&db, &ident.filename()).await {
            "Renew"
        } else {
            "Issue"
        };

        println!(
            "[ACME] {} {} via {} (webroot={})",
            action, ident.describe(), ct.as_str(), wr
        );

        match issue_certificate(ident, wr, ct, resolver).await {
            Ok(_) => println!(
                "[ACME] {} OK for {} ({})",
                action, ident.describe(), ct.as_str()
            ),
            Err(e) => eprintln!(
                "[ACME] {} FAILED for {} ({}): {}",
                action, ident.describe(), ct.as_str(), e
            ),
        }
    }

    Ok(())
}

async fn list_db_cert_domains(db: &Arc<db::DbManager>) -> Vec<String> {
    let omni = match db.conns.read().await.get("OmniDB").cloned() {
        Some(o) => o,
        None => return Vec::new(),
    };
    let db::Pool::Sqlite(p) = &omni.pool;
    let p = p.clone();
    tokio::task::spawn_blocking(move || -> Vec<String> {
        let g = match p.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let mut stmt = match g.prepare(
            "SELECT domain FROM \"OmniSsl\" WHERE domain != '_acme_account'",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let iter = match stmt.query_map([], |r| r.get::<_, String>(0)) {
            Ok(i) => i,
            Err(_) => return Vec::new(),
        };
        iter.filter_map(Result::ok).collect()
    })
    .await
    .unwrap_or_default()
}

async fn db_has_cert(db: &Arc<db::DbManager>, domain: &str) -> bool {
    let omni = match db.conns.read().await.get("OmniDB").cloned() {
        Some(o) => o,
        None => return false,
    };
    let db::Pool::Sqlite(p) = &omni.pool;
    let p = p.clone();
    let domain = domain.to_string();
    tokio::task::spawn_blocking(move || -> bool {
        let g = match p.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        g.query_row(
            "SELECT 1 FROM \"OmniSsl\" WHERE domain=?1",
            rusqlite::params![domain],
            |_| Ok(true),
        )
        .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

/// Возвращает true, если для домена нужно выпустить/обновить сертификат:
///   • серта нет в БД, ИЛИ
///   • срок его действия подходит к концу.
/// Порог: половина срока жизни для короткоживущих (<21 дня),
/// иначе 7 дней до истечения.
async fn cert_needs_work(db: &Arc<db::DbManager>, domain: &str) -> bool {
    let omni = match db.conns.read().await.get("OmniDB").cloned() {
        Some(o) => o,
        None => return false,
    };
    let db::Pool::Sqlite(p) = &omni.pool;
    let p = p.clone();
    let domain = domain.to_string();
    tokio::task::spawn_blocking(move || -> bool {
        let g = match p.lock() {
            Ok(g) => g,
            Err(_) => return true,
        };
        let cert_pem: String = match g.query_row(
            "SELECT cert_pem FROM \"OmniSsl\" WHERE domain=?1",
            rusqlite::params![domain],
            |r| r.get::<_, String>(0),
        ) {
            Ok(s) => s,
            Err(_) => return true, // нет серта — надо выпустить
        };
        let (_, pem) = match x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()) {
            Ok(v) => v,
            Err(_) => return true,
        };
        let cert = match pem.parse_x509() {
            Ok(c) => c,
            Err(_) => return true,
        };
        let nb = cert.validity().not_before.timestamp();
        let na = cert.validity().not_after.timestamp();
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let total_lifetime = (na - nb).max(1);
        let remaining = na - now_ts;
        let threshold = if total_lifetime < 21 * 86400 {
            // короткоживущий (6-дневный IP-серт) — половина срока
            total_lifetime / 2
        } else {
            // стандартный 90-дневный — 7 дней
            7 * 86400
        };
        remaining < threshold
    })
    .await
    .unwrap_or(true)
}

// ── inlined from dns (ssl не зависит от dns-крейта) ──
fn normalize_dns_name(name: &str) -> String { name.trim().trim_end_matches('.').to_ascii_lowercase() }
fn extract_sans(cert_pem: &[u8]) -> Vec<String> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    let mut out = Vec::new();
    if let Ok((_, pem)) = x509_parser::pem::parse_x509_pem(cert_pem) {
        if let Ok(cert) = pem.parse_x509() {
            for ext in cert.extensions() {
                if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                    for name in &san.general_names {
                        match name {
                            x509_parser::extensions::GeneralName::DNSName(d) => out.push(d.to_string()),
                            x509_parser::extensions::GeneralName::IPAddress(b) if b.len() == 4 => {
                                let mut a = [0u8; 4]; a.copy_from_slice(b); out.push(Ipv4Addr::from(a).to_string()); }
                            x509_parser::extensions::GeneralName::IPAddress(b) if b.len() == 16 => {
                                let mut a = [0u8; 16]; a.copy_from_slice(b); out.push(Ipv6Addr::from(a).to_string()); }
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    out
}

