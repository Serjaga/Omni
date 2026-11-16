use omni_db as db;
// src/ikev2.rs — IKEv2 (RFC 7296) сервер (PSK), чистый Rust (p521 + aes-gcm)
use axum::body::Body;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use serde_json::json;
use sha2::Sha256;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Payload as AeadPayload}, Nonce as GcmNonce};
use thiserror::Error;
// p521 0.14: используем Sec1Point и трейт Generate
use p521::{Sec1Point, PublicKey, ecdh::EphemeralSecret, elliptic_curve::Generate};

type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Error)]
pub enum IkeError {
    #[error("truncated input")]
    Truncated,
    #[error("bad length")]
    BadLength,
    #[error("no supported proposal")]
    NoProposalChosen,
    #[error("DH group mismatch")]
    DhGroupMismatch,
    #[error("authentication failed")]
    AuthFailed,
    #[error("crypto error")]
    Crypto,
}

// ─────────────────────────────────────────────────────────────
//  Фрейминг
// ─────────────────────────────────────────────────────────────
const IKE_VERSION: u8 = 0x20;
const HDR_LEN: usize = 28;
const EXCHANGE_IKE_SA_INIT: u8 = 34;
const EXCHANGE_IKE_AUTH: u8 = 35;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PayloadType {
    NoNext = 0,
    SecurityAssociation = 33,
    KeyExchange = 34,
    IdInitiator = 35,
    IdResponder = 36,
    Certificate = 37,
    Authentication = 39,
    Nonce = 40,
    Notify = 41,
    TrafficSelectorInitiator = 44,
    TrafficSelectorResponder = 45,
    Encrypted = 46,
    Configuration = 47,
    Other(u8),
}

impl PayloadType {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::NoNext,
            33 => Self::SecurityAssociation,
            34 => Self::KeyExchange,
            35 => Self::IdInitiator,
            36 => Self::IdResponder,
            37 => Self::Certificate,
            39 => Self::Authentication,
            40 => Self::Nonce,
            41 => Self::Notify,
            44 => Self::TrafficSelectorInitiator,
            45 => Self::TrafficSelectorResponder,
            46 => Self::Encrypted,
            47 => Self::Configuration,
            other => Self::Other(other),
        }
    }
    fn to_u8(self) -> u8 {
        match self {
            Self::NoNext => 0,
            Self::SecurityAssociation => 33,
            Self::KeyExchange => 34,
            Self::IdInitiator => 35,
            Self::IdResponder => 36,
            Self::Certificate => 37,
            Self::Authentication => 39,
            Self::Nonce => 40,
            Self::Notify => 41,
            Self::TrafficSelectorInitiator => 44,
            Self::TrafficSelectorResponder => 45,
            Self::Encrypted => 46,
            Self::Configuration => 47,
            Self::Other(v) => v,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Flags {
    initiator: bool,
    response: bool,
}

impl Flags {
    fn to_u8(self) -> u8 {
        let mut v = 0;
        if self.initiator { v |= 0x08; }
        if self.response { v |= 0x20; }
        v
    }
}

#[derive(Debug, Clone)]
struct IkeHeader {
    spi_i: [u8; 8],
    spi_r: [u8; 8],
    next_payload: u8,
    exchange_type: u8,
    flags: u8,
    msg_id: u32,
    length: u32,
}

impl IkeHeader {
    fn parse(buf: &[u8]) -> std::result::Result<Self, IkeError> {
        if buf.len() < HDR_LEN { return Err(IkeError::Truncated); }
        let mut spi_i = [0u8; 8]; spi_i.copy_from_slice(&buf[0..8]);
        let mut spi_r = [0u8; 8]; spi_r.copy_from_slice(&buf[8..16]);
        if buf[17] != IKE_VERSION { return Err(IkeError::BadLength); }
        Ok(Self {
            spi_i, spi_r,
            next_payload: buf[16],
            exchange_type: buf[18],
            flags: buf[19],
            msg_id: u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]),
            length: u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]),
        })
    }
    fn to_bytes(&self) -> [u8; HDR_LEN] {
        let mut b = [0u8; HDR_LEN];
        b[0..8].copy_from_slice(&self.spi_i);
        b[8..16].copy_from_slice(&self.spi_r);
        b[16] = self.next_payload;
        b[17] = IKE_VERSION;
        b[18] = self.exchange_type;
        b[19] = self.flags;
        b[20..24].copy_from_slice(&self.msg_id.to_be_bytes());
        b[24..28].copy_from_slice(&self.length.to_be_bytes());
        b
    }
}

struct RawPayload<'a> { payload_type: PayloadType, data: &'a [u8] }

fn parse_payloads(mut next: PayloadType, body: &[u8]) -> std::result::Result<Vec<RawPayload<'_>>, IkeError> {
    let mut out = Vec::new();
    let mut rest = body;
    while next != PayloadType::NoNext && !rest.is_empty() {
        if rest.len() < 4 { return Err(IkeError::Truncated); }
        let next_type = PayloadType::from_u8(rest[0]);
        let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        if len < 4 || len > rest.len() { return Err(IkeError::BadLength); }
        out.push(RawPayload { payload_type: next, data: &rest[4..len] });
        next = next_type;
        rest = &rest[len..];
    }
    Ok(out)
}

fn encode_payload_chain(payloads: &[(PayloadType, Vec<u8>)]) -> Vec<u8> {
    let mut chain = Vec::new();
    for (i, (_, body)) in payloads.iter().enumerate() {
        let next = payloads.get(i + 1).map(|(t, _)| *t).unwrap_or(PayloadType::NoNext);
        let len = (4 + body.len()) as u16;
        chain.push(next.to_u8());
        chain.push(0);
        chain.extend_from_slice(&len.to_be_bytes());
        chain.extend_from_slice(body);
    }
    chain
}

// ─────────────────────────────────────────────────────────────
//  Пейлоады
// ─────────────────────────────────────────────────────────────
struct Transform { transform_type: u8, transform_id: u16, key_length: Option<u16> }
struct Proposal { num: u8, protocol_id: u8, spi: u32, transforms: Vec<Transform> }
struct SecurityAssociation { proposals: Vec<Proposal> }

const TT_ENCR: u8 = 1;
const TT_PRF: u8 = 2;
const TT_DH: u8 = 4;
const TT_ESN: u8 = 5;
const PROTO_IKE: u8 = 1;
const PROTO_ESP: u8 = 3;

const ENCR_AES_GCM_16: u16 = 20;
const PRF_HMAC_SHA2_256: u16 = 5;
const DH_MODP_2048: u16 = 14;
const DH_ECP_521: u16 = 21;
const ESN_NONE: u16 = 0;

impl SecurityAssociation {
    fn parse(body: &[u8]) -> std::result::Result<Self, IkeError> {
        let mut off = 0;
        let mut proposals = Vec::new();
        while off < body.len() {
            if body.len() - off < 8 { break; }
            let len = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
            if len < 8 || off + len > body.len() { break; }
            let num = body[off + 4];
            let proto = body[off + 5];
            let spi_size = body[off + 6] as usize;
            let t_count = body[off + 7] as usize;
            
            let spi = if spi_size == 4 {
                u32::from_be_bytes([body[off + 8], body[off + 9], body[off + 10], body[off + 11]])
            } else { 0 };
            
            let mut toff = off + 8 + spi_size;
            let mut transforms = Vec::new();
            for _ in 0..t_count {
                if toff + 8 > off + len { break; }
                let t_len = u16::from_be_bytes([body[toff + 2], body[toff + 3]]) as usize;
                let t_type = body[toff + 4];
                let t_id = u16::from_be_bytes([body[toff + 6], body[toff + 7]]);
                let mut key_len = None;
                if t_len >= 12 {
                    let attr = u16::from_be_bytes([body[toff + 8], body[toff + 9]]) & 0x7fff;
                    if attr == 14 { key_len = Some(u16::from_be_bytes([body[toff + 10], body[toff + 11]])); }
                }
                transforms.push(Transform { transform_type: t_type, transform_id: t_id, key_length: key_len });
                toff += t_len;
            }
            proposals.push(Proposal { num, protocol_id: proto, spi, transforms });
            off += len;
        }
        Ok(Self { proposals })
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, prop) in self.proposals.iter().enumerate() {
            let mut body = Vec::new();
            for (j, t) in prop.transforms.iter().enumerate() {
                let attrs = if let Some(k) = t.key_length {
                    let mut a = vec![0x80, 0x0e]; a.extend_from_slice(&k.to_be_bytes()); a
                } else { vec![] };
                let t_len = 8 + attrs.len();
                body.push(if j + 1 == prop.transforms.len() { 0 } else { 3 });
                body.push(0);
                body.extend_from_slice(&(t_len as u16).to_be_bytes());
                body.push(t.transform_type);
                body.push(0);
                body.extend_from_slice(&t.transform_id.to_be_bytes());
                body.extend_from_slice(&attrs);
            }
            
            let spi_len = if prop.protocol_id == PROTO_ESP { 4 } else { 0 };
            let p_len = 8 + spi_len + body.len();
            
            out.push(if i + 1 == self.proposals.len() { 0 } else { 2 });
            out.push(0);
            out.extend_from_slice(&(p_len as u16).to_be_bytes());
            out.push(prop.num);
            out.push(prop.protocol_id);
            out.push(spi_len as u8);
            out.push(prop.transforms.len() as u8);
            
            if spi_len == 4 {
                out.extend_from_slice(&prop.spi.to_be_bytes());
            }
            
            out.extend_from_slice(&body);
        }
        out
    }
}

struct KeyExchange { dh_group: u16, data: Vec<u8> }
impl KeyExchange {
    fn parse(body: &[u8]) -> std::result::Result<Self, IkeError> {
        if body.len() < 4 { return Err(IkeError::Truncated); }
        Ok(Self { dh_group: u16::from_be_bytes([body[0], body[1]]), data: body[4..].to_vec() })
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.data.len());
        out.extend_from_slice(&self.dh_group.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&self.data);
        out
    }
}

struct NoncePayload { data: Vec<u8> }
impl NoncePayload {
    fn parse(body: &[u8]) -> Self { Self { data: body.to_vec() } }
    fn to_bytes(&self) -> Vec<u8> { self.data.clone() }
}

struct Notify { notify_type: u16, data: Vec<u8> }
impl Notify {
    fn status(notify_type: u16, data: Vec<u8>) -> Self {
        Self { notify_type, data }
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0);
        out.push(0);
        out.extend_from_slice(&self.notify_type.to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }
}

struct Identification { id_type: u8, data: Vec<u8> }
impl Identification {
    fn parse(body: &[u8]) -> std::result::Result<Self, IkeError> {
        if body.len() < 4 { return Err(IkeError::Truncated); }
        Ok(Self { id_type: body[0], data: body[4..].to_vec() })
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.id_type, 0, 0, 0];
        out.extend_from_slice(&self.data);
        out
    }
}

struct Authentication { method: u8, data: Vec<u8> }
impl Authentication {
    fn parse(body: &[u8]) -> std::result::Result<Self, IkeError> {
        if body.len() < 4 { return Err(IkeError::Truncated); }
        Ok(Self { method: body[0], data: body[4..].to_vec() })
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.method, 0, 0, 0];
        out.extend_from_slice(&self.data);
        out
    }
}

// ─────────────────────────────────────────────────────────────
//  Криптография
// ─────────────────────────────────────────────────────────────
fn prf(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn prf_plus(key: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut prev = Vec::new();
    let mut counter = 1u8;
    while out.len() < out_len {
        let mut input = Vec::new();
        input.extend_from_slice(&prev);
        input.extend_from_slice(seed);
        input.push(counter);
        let block = prf(key, &input);
        out.extend_from_slice(&block);
        prev = block.to_vec();
        counter = counter.saturating_add(1);
    }
    out.truncate(out_len);
    out
}

struct SessionKeys { sk_ei: Vec<u8>, sk_er: Vec<u8>, sk_pi: Vec<u8>, sk_pr: Vec<u8> }

fn derive_session_keys(shared: &[u8], ni: &[u8], nr: &[u8], spi_i: &[u8; 8], spi_r: &[u8; 8]) -> SessionKeys {
    let mut nonces = ni.to_vec();
    nonces.extend_from_slice(nr);
    let skeyseed = prf(&nonces, shared);
    
    let mut seed = nonces;
    seed.extend_from_slice(spi_i);
    seed.extend_from_slice(spi_r);
    
    let total = 32 + 36 + 36 + 32 + 32; // sk_d, sk_ei, sk_er, sk_pi, sk_pr
    let km = prf_plus(&skeyseed, &seed, total);
    
    let mut off = 32; // пропускаем sk_d
    let sk_ei = km[off..off+36].to_vec(); off += 36;
    let sk_er = km[off..off+36].to_vec(); off += 36;
    let sk_pi = km[off..off+32].to_vec(); off += 32;
    let sk_pr = km[off..off+32].to_vec();
    
    SessionKeys { sk_ei, sk_er, sk_pi, sk_pr }
}

fn ecp_521_dh(peer_pub_bytes: &[u8]) -> std::result::Result<(Vec<u8>, Vec<u8>), IkeError> {
    if peer_pub_bytes.len() != 132 { return Err(IkeError::BadLength); }

    let mut sec1 = Vec::with_capacity(133);
    sec1.push(0x04);
    sec1.extend_from_slice(peer_pub_bytes);

    let peer_public = PublicKey::from_sec1_bytes(&sec1)
        .map_err(|_| IkeError::Crypto)?;

    // В p521 0.14 / elliptic-curve 0.14 используем Generate::generate()
    // (OsRng из rand 0.8 не совместим с новым rand_core 0.9).
    let my_secret = EphemeralSecret::generate();
    // public_key() → Sec1Point, as_ref() даёт [0x04, X, Y]
    let my_public = Sec1Point::from(my_secret.public_key());
    let my_pub_bytes = my_public.as_ref()[1..].to_vec(); // 132 байта

    let shared = my_secret.diffie_hellman(&peer_public);
    let shared_bytes = shared.raw_secret_bytes().as_slice().to_vec(); // 66 байт

    Ok((my_pub_bytes, shared_bytes))
}

fn modp_dh(peer_pub_bytes: &[u8]) -> std::result::Result<(Vec<u8>, Vec<u8>), IkeError> {
    if peer_pub_bytes.len() != 256 { return Err(IkeError::BadLength); }
    const MODP_2048_P: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
    let p = BigUint::parse_bytes(MODP_2048_P.as_bytes(), 16).unwrap();
    let g = BigUint::from(2u32);
    
    let mut priv_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut priv_bytes);
    let priv_bn = BigUint::from_bytes_be(&priv_bytes);
    
    let peer_bn = BigUint::from_bytes_be(peer_pub_bytes);
    let shared_bn = peer_bn.modpow(&priv_bn, &p);
    let pub_bn = g.modpow(&priv_bn, &p);
    
    let mut shared = shared_bn.to_bytes_be();
    if shared.len() < 256 { shared.splice(0..0, vec![0; 256 - shared.len()]); }
    
    let mut my_pub = pub_bn.to_bytes_be();
    if my_pub.len() < 256 { my_pub.splice(0..0, vec![0; 256 - my_pub.len()]); }
    
    Ok((my_pub, shared))
}

fn compute_dh(group: u16, peer_pub_bytes: &[u8]) -> std::result::Result<(Vec<u8>, Vec<u8>), IkeError> {
    match group {
        DH_ECP_521 => ecp_521_dh(peer_pub_bytes),
        DH_MODP_2048 => modp_dh(peer_pub_bytes),
        _ => Err(IkeError::NoProposalChosen),
    }
}

fn build_encrypted_gcm(mut header: IkeHeader, first_inner: PayloadType, inner: &[u8], sk_e: &[u8], iv: &[u8; 8]) -> Vec<u8> {
    let mut plaintext = inner.to_vec();
    plaintext.push(0);
    
    let sk_payload_len = 4 + 8 + plaintext.len() + 16;
    header.next_payload = PayloadType::Encrypted.to_u8();
    header.length = (HDR_LEN + sk_payload_len) as u32;
    let hdr_bytes = header.to_bytes();
    
    let mut sk_gen = [0u8; 4];
    sk_gen[0] = first_inner.to_u8();
    sk_gen[2..4].copy_from_slice(&(sk_payload_len as u16).to_be_bytes());
    
    let mut aad = Vec::new();
    aad.extend_from_slice(&hdr_bytes);
    aad.extend_from_slice(&sk_gen);
    
    let cipher = Aes256Gcm::new_from_slice(&sk_e[0..32]).unwrap();
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&sk_e[32..36]);
    nonce[4..12].copy_from_slice(iv);
    
    let ct = cipher.encrypt(GcmNonce::from_slice(&nonce), AeadPayload { msg: &plaintext, aad: &aad }).unwrap();
    
    let mut out = Vec::with_capacity(HDR_LEN + sk_payload_len);
    out.extend_from_slice(&hdr_bytes);
    out.extend_from_slice(&sk_gen);
    out.extend_from_slice(iv);
    out.extend_from_slice(&ct);
    out
}

fn open_encrypted_gcm(msg: &[u8], sk_e: &[u8]) -> std::result::Result<(PayloadType, Vec<u8>), IkeError> {
    let _hdr = IkeHeader::parse(msg)?;
    let body = &msg[HDR_LEN..];
    if body.len() < 4 { return Err(IkeError::Truncated); }
    let first_inner = PayloadType::from_u8(body[0]);
    let sk_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    if body.len() < sk_len { return Err(IkeError::BadLength); }
    let iv = &body[4..12];
    let ct = &body[12..sk_len];
    let aad = &msg[..HDR_LEN + 4];
    
    let cipher = Aes256Gcm::new_from_slice(&sk_e[0..32]).unwrap();
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&sk_e[32..36]);
    nonce[4..12].copy_from_slice(iv);
    
    let plaintext = cipher.decrypt(GcmNonce::from_slice(&nonce), AeadPayload { msg: ct, aad }).map_err(|_| IkeError::AuthFailed)?;
    let pad_len = *plaintext.last().ok_or(IkeError::BadLength)? as usize;
    if pad_len + 1 > plaintext.len() { return Err(IkeError::BadLength); }
    Ok((first_inner, plaintext[..plaintext.len() - 1 - pad_len].to_vec()))
}

fn psk_auth(psk: &[u8], signed_octets: &[u8]) -> Vec<u8> {
    let key_pad = b"Key Pad for IKEv2";
    let inner = prf(psk, key_pad);
    prf(&inner, signed_octets).to_vec()
}

// ─────────────────────────────────────────────────────────────
//  Сервер
// ─────────────────────────────────────────────────────────────
#[derive(Clone, Debug)]
pub struct Ikev2Config {
    pub enabled: bool,
    pub listen_addr: String,
    pub psk: String,
    pub local_id: String,
    pub remote_id: String,
}

struct IkeSession {
    keys: SessionKeys,
    init_resp: Vec<u8>,
    init_req: Vec<u8>,
    nonce_i: Vec<u8>,
    nonce_r: Vec<u8>,
}

pub struct Ikev2Server {
    config: Ikev2Config,
    socket: UdpSocket,
    sessions: Arc<RwLock<HashMap<[u8; 8], IkeSession>>>,
}

impl Ikev2Server {
    pub async fn bind(cfg: Ikev2Config) -> Result<Self> {
        let addr: SocketAddr = cfg.listen_addr.parse().map_err(|e| format!("bad addr: {}", e))?;
        let socket = UdpSocket::bind(addr).await.map_err(|e| format!("bind {}: {}", addr, e))?;
        info!("[IKEv2] listening on udp://{}", addr);
        Ok(Self { config: cfg, socket, sessions: Arc::new(RwLock::new(HashMap::new())) })
    }

    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) -> Result<()> {
        let mut buf = [0u8; 65535];
        loop {
            tokio::select! {
                res = self.socket.recv_from(&mut buf) => match res {
                    Ok((n, peer)) => {
                        let pkt = buf[..n].to_vec();
                        let s = self.clone();
                        tokio::spawn(async move {
                            if let Err(e) = s.handle_packet(pkt, peer).await {
                                warn!("[IKEv2] error {}: {}", peer, e);
                            }
                        });
                    }
                    Err(e) => warn!("[IKEv2] recv error: {:?}", e),
                },
                _ = shutdown.cancelled() => break,
            }
        }
        Ok(())
    }

    async fn handle_packet(&self, buf: Vec<u8>, peer: SocketAddr) -> Result<()> {
        let hdr = IkeHeader::parse(&buf).map_err(|e| format!("{:?}", e))?;
        match hdr.exchange_type {
            EXCHANGE_IKE_SA_INIT => self.handle_sa_init(hdr, buf, peer).await,
            EXCHANGE_IKE_AUTH => self.handle_ike_auth(hdr, buf, peer).await,
            _ => Ok(()),
        }
    }

    async fn handle_sa_init(&self, hdr: IkeHeader, buf: Vec<u8>, peer: SocketAddr) -> Result<()> {
        {
            let s = self.sessions.read().await;
            if let Some(sess) = s.get(&hdr.spi_i) {
                let _ = self.socket.send_to(&sess.init_resp, peer).await;
                return Ok(());
            }
        }

        let payloads = parse_payloads(PayloadType::from_u8(hdr.next_payload), &buf[HDR_LEN..]).map_err(|e| format!("{:?}", e))?;
        let mut peer_pub = None;
        let mut nonce_i = None;
        let mut proposals = None;

        for p in payloads {
            match p.payload_type {
                PayloadType::SecurityAssociation => proposals = Some(SecurityAssociation::parse(p.data).map_err(|e| format!("{:?}", e))?),
                PayloadType::KeyExchange => { let ke = KeyExchange::parse(p.data).map_err(|e| format!("{:?}", e))?; peer_pub = Some((ke.dh_group, ke.data)); }
                PayloadType::Nonce => nonce_i = Some(NoncePayload::parse(p.data).data),
                _ => {}
            }
        }

        let proposals = proposals.ok_or("no SA")?;
        let (ke_group, peer_pub_bytes) = peer_pub.ok_or("no KE")?;
        let nonce_i = nonce_i.ok_or("no Nonce")?;

        // Ищем пропозал, где DH-группа совпадает с той, что прислал клиент
        let mut selected = None;
        for p in &proposals.proposals {
            let mut has_encr = false;
            let mut has_prf = false;
            let mut has_dh = false;
            for t in &p.transforms {
                if t.transform_type == TT_ENCR && t.transform_id == ENCR_AES_GCM_16 { has_encr = true; }
                if t.transform_type == TT_PRF && t.transform_id == PRF_HMAC_SHA2_256 { has_prf = true; }
                if t.transform_type == TT_DH && t.transform_id == ke_group { has_dh = true; }
            }
            if has_encr && has_prf && has_dh {
                selected = Some((p.num, ENCR_AES_GCM_16, PRF_HMAC_SHA2_256, ke_group));
                break;
            }
        }

        let (prop_num, encr, prf_alg, dh) = selected.ok_or("No supported proposal matching client's KE group")?;

        // ★ ФИКС: compute_dh возвращает IkeError, а handle_sa_init возвращает String
        let (my_pub, shared) = compute_dh(dh, &peer_pub_bytes)
            .map_err(|e| format!("{:?}", e))?;
        
        let mut spi_r = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut spi_r);
        let mut nonce_r = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_r);

        let keys = derive_session_keys(&shared, &nonce_i, &nonce_r, &hdr.spi_i, &spi_r);

        let sa_pl = SecurityAssociation {
            proposals: vec![Proposal {
                num: prop_num,
                protocol_id: PROTO_IKE,
                spi: 0,
                transforms: vec![
                    // Принудительно 256 бит, чтобы совпадать с нашим Aes256Gcm
                    Transform { transform_type: TT_ENCR, transform_id: encr, key_length: Some(256) },
                    Transform { transform_type: TT_PRF, transform_id: prf_alg, key_length: None },
                    Transform { transform_type: TT_DH, transform_id: dh, key_length: None },
                ],
            }],
        }.to_bytes();

        let ke_pl = KeyExchange { dh_group: dh, data: my_pub }.to_bytes();
        let nonce_pl = NoncePayload { data: nonce_r.clone() }.to_bytes();

        let body = encode_payload_chain(&[
            (PayloadType::SecurityAssociation, sa_pl),
            (PayloadType::KeyExchange, ke_pl),
            (PayloadType::Nonce, nonce_pl),
        ]);

        let resp_hdr = IkeHeader {
            spi_i: hdr.spi_i,
            spi_r,
            next_payload: PayloadType::SecurityAssociation.to_u8(),
            exchange_type: EXCHANGE_IKE_SA_INIT,
            flags: Flags { initiator: false, response: true }.to_u8(),
            msg_id: 0,
            length: (HDR_LEN + body.len()) as u32,
        };

        let mut resp = resp_hdr.to_bytes().to_vec();
        resp.extend_from_slice(&body);
        
        let _ = self.socket.send_to(&resp, peer).await;

        self.sessions.write().await.insert(hdr.spi_i, IkeSession {
            keys,
            init_resp: resp,
            init_req: buf,
            nonce_i,
            nonce_r,
        });

        info!("[IKEv2] SA_INIT OK for {}", peer);
        Ok(())
    }

    async fn handle_ike_auth(&self, hdr: IkeHeader, buf: Vec<u8>, peer: SocketAddr) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        let sess = sessions.get_mut(&hdr.spi_i).ok_or("no session")?;
        
        let (first_inner, inner) = open_encrypted_gcm(&buf, &sess.keys.sk_ei).map_err(|e| format!("{:?}", e))?;
        let payloads = parse_payloads(first_inner, &inner).map_err(|e| format!("{:?}", e))?;

        let mut idi = None;
        let mut auth_data = None;

        for p in payloads {
            if p.payload_type == PayloadType::IdInitiator { idi = Some(Identification::parse(p.data).map_err(|e| format!("{:?}", e))?); }
            if p.payload_type == PayloadType::Authentication { auth_data = Some(Authentication::parse(p.data).map_err(|e| format!("{:?}", e))?); }
        }

        let idi = idi.ok_or("no IDi")?;
        let auth_data = auth_data.ok_or("no AUTH")?;
        if auth_data.method != 2 { return Err("only PSK auth supported".into()); }

        let mut signed_octets = sess.init_req.clone();
        signed_octets.extend_from_slice(&sess.nonce_r);
        let prf_sk_pi = prf(&sess.keys.sk_pi, &idi.to_bytes());
        signed_octets.extend_from_slice(&prf_sk_pi);

        let expected_auth = psk_auth(self.config.psk.as_bytes(), &signed_octets);
        if auth_data.data != expected_auth {
            warn!("[IKEv2] AUTH mismatch from {}! Expected: {:02x?}, Got: {:02x?}", peer, expected_auth, auth_data.data);
            return Err("auth failed".into());
        }

        let (id_type, id_data) = if let Ok(ip) = self.config.local_id.parse::<std::net::Ipv4Addr>() {
            (1u8, ip.octets().to_vec())
        } else if let Ok(ip6) = self.config.local_id.parse::<std::net::Ipv6Addr>() {
            (5u8, ip6.octets().to_vec())
        } else {
            (2u8, self.config.local_id.as_bytes().to_vec())
        };
        let idr = Identification { id_type, data: id_data };
        
        let mut auth_payload = Authentication { method: 2, data: vec![] };
        let mut auth_signed_octets = sess.init_resp.clone();
        auth_signed_octets.extend_from_slice(&sess.nonce_i);
        let prf_sk_pr = prf(&sess.keys.sk_pr, &idr.to_bytes());
        auth_signed_octets.extend_from_slice(&prf_sk_pr);
        auth_payload.data = psk_auth(self.config.psk.as_bytes(), &auth_signed_octets);

        let esp_spi = rand::random::<u32>();
        let esp_sa = SecurityAssociation {
            proposals: vec![Proposal {
                num: 1,
                protocol_id: PROTO_ESP,
                spi: esp_spi,
                transforms: vec![
                    Transform { transform_type: TT_ENCR, transform_id: ENCR_AES_GCM_16, key_length: Some(256) },
                    Transform { transform_type: TT_ESN, transform_id: ESN_NONE, key_length: None },
                ],
            }],
        }.to_bytes();

        let ts = vec![1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255];

        let inner_payloads = encode_payload_chain(&[
            (PayloadType::IdResponder, idr.to_bytes()),
            (PayloadType::Authentication, auth_payload.to_bytes()),
            (PayloadType::SecurityAssociation, esp_sa),
            (PayloadType::TrafficSelectorInitiator, ts.clone()),
            (PayloadType::TrafficSelectorResponder, ts),
        ]);

        let mut iv = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut iv);
        
        let resp_hdr = IkeHeader {
            spi_i: hdr.spi_i,
            spi_r: hdr.spi_r,
            next_payload: PayloadType::Encrypted.to_u8(),
            exchange_type: EXCHANGE_IKE_AUTH,
            flags: Flags { initiator: false, response: true }.to_u8(),
            msg_id: 1,
            length: 0,
        };

        let resp = build_encrypted_gcm(resp_hdr, PayloadType::IdResponder, &inner_payloads, &sess.keys.sk_er, &iv);
        let _ = self.socket.send_to(&resp, peer).await;

        info!("[IKEv2] IKE_AUTH OK for {}", peer);
        Ok(())
    }
}

pub async fn start_server(cfg: Ikev2Config, shutdown: CancellationToken) -> Result<()> {
    if !cfg.enabled { return Ok(()); }
    let server = Arc::new(Ikev2Server::bind(cfg).await?);
    server.run(shutdown).await
}

// ─────────────────────────────────────────────────────────────
//  HTTP API
// ─────────────────────────────────────────────────────────────
pub async fn dispatch_api(
    ikev2_enabled: bool,
    ikev2_listen: String,
    ikev2_psk: String,
    ikev2_local_id: String,
    ikev2_remote_id: String,
    method: Method,
    endpoint: String,
    _q: HashMap<String, String>,
    _h: HeaderMap,
    body: Body,
    _ip: String,
) -> Response<Body> {
    let ep = endpoint.as_str();
    let body_bytes = match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => return err_json(StatusCode::BAD_REQUEST, format!("body: {}", e)),
    };
    if ep == "ikev2/config" && method == Method::GET {
        return ok_json(json!({
            "enabled": ikev2_enabled,
            "listen": ikev2_listen,
            "psk": ikev2_psk,
            "local_id": ikev2_local_id,
            "remote_id": ikev2_remote_id,
        }));
    }
    if ep == "ikev2/config" && method == Method::POST {
        let v: serde_json::Value = match serde_json::from_slice(&body_bytes) {
            Ok(v) => v,
            Err(e) => return err_json(StatusCode::BAD_REQUEST, format!("json: {}", e)),
        };
        let mut items = Vec::new();
        if let Some(obj) = v.as_object() {
            for (k, val) in obj {
                let key = match k.as_str() {
                    "enabled" => "ikev2.enabled",
                    "listen" => "ikev2.listen",
                    "psk" => "ikev2.psk",
                    "local_id" => "ikev2.local_id",
                    "remote_id" => "ikev2.remote_id",
                    _ => continue,
                };
                let v_str = if let Some(s) = val.as_str() { s.to_string() } else if let Some(b) = val.as_bool() { if b { "true".into() } else { "false".into() } } else { val.to_string() };
                items.push((key.to_string(), v_str));
            }
        }
        let db = match db::global() {
            Some(d) => d,
            None => return err_json(StatusCode::SERVICE_UNAVAILABLE, "db not initialized"),
        };
        return match db.config_set_bulk(&items).await {
            Ok(_) => ok_json(json!({"ok": true, "note": "restart required"})),
            Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, e),
        };
    }
    err_json(StatusCode::NOT_FOUND, "unknown ikev2 endpoint")
}

fn ok_json(v: serde_json::Value) -> Response<Body> {
    Response::builder().status(StatusCode::OK).header("content-type", "application/json").header("cache-control", "no-store").body(Body::from(v.to_string())).unwrap()
}

fn err_json(s: StatusCode, msg: impl Into<String>) -> Response<Body> {
    Response::builder().status(s).header("content-type", "application/json").body(Body::from(json!({"error": msg.into()}).to_string())).unwrap()
}