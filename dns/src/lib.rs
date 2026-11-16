
//! dns.rs — максимальный DNS-сервер для OmniRS.
//! BIND 9 + NSD + Knot + PowerDNS + Unbound + CoreDNS + dnsdist + Route 53 + AdGuard в одном.
//! Совместим с main.rs (`CertStore`, `DnsResolver`, helpers — §21 без изменений).


use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use quinn::crypto::rustls::QuicServerConfig;
// ═══════════════════════════════════════════════════════════════════════════ §2 ERRORS
#[derive(Debug)]
pub enum DnsError { Format(String), Truncated, Overflow, NotFound, Refused, ServFail, Io(std::io::Error), Unsupported(String), InvalidName(String), InvalidType(u16), InvalidClass(u16), TsigError(String), DnssecError(String), ConfigError(String) }
impl std::fmt::Display for DnsError { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { match self { Self::Format(s) => write!(f, "format: {s}"), Self::Truncated => write!(f, "truncated"), Self::Overflow => write!(f, "overflow"), Self::NotFound => write!(f, "not found"), Self::Refused => write!(f, "refused"), Self::ServFail => write!(f, "servfail"), Self::Io(e) => write!(f, "io: {e}"), Self::Unsupported(s) => write!(f, "unsupported: {s}"), Self::InvalidName(s) => write!(f, "invalid name: {s}"), Self::InvalidType(t) => write!(f, "invalid type: {t}"), Self::InvalidClass(c) => write!(f, "invalid class: {c}"), Self::TsigError(s) => write!(f, "tsig: {s}"), Self::DnssecError(s) => write!(f, "dnssec: {s}"), Self::ConfigError(s) => write!(f, "config: {s}") } } }
impl std::error::Error for DnsError {}
impl From<std::io::Error> for DnsError { fn from(e: std::io::Error) -> Self { Self::Io(e) } }
pub type DnsResult<T> = Result<T, DnsError>;

// ═══════════════════════════════════════════════════════════════════════════ §2b ACTIVE CONN GUARD (NEW)
pub struct ActiveConnGuard { pub counter: Arc<AtomicU64> }
impl ActiveConnGuard { pub fn new(c: Arc<AtomicU64>) -> Self { c.fetch_add(1, Ordering::Relaxed); Self { counter: c } } }
impl Drop for ActiveConnGuard { fn drop(&mut self) { self.counter.fetch_sub(1, Ordering::Relaxed); } }

// ═══════════════════════════════════════════════════════════════════════════ §3 CONSTANTS
pub mod rtype {
    pub const A: u16 = 1; pub const NS: u16 = 2; pub const CNAME: u16 = 5; pub const SOA: u16 = 6;
    pub const PTR: u16 = 12; pub const MX: u16 = 15; pub const TXT: u16 = 16; pub const AAAA: u16 = 28;
    pub const SRV: u16 = 33; pub const NAPTR: u16 = 35; pub const DS: u16 = 43; pub const RRSIG: u16 = 46;
    pub const NSEC: u16 = 47; pub const DNSKEY: u16 = 48; pub const NSEC3: u16 = 50; pub const NSEC3PARAM: u16 = 51;
    pub const TLSA: u16 = 52; pub const CAA: u16 = 257; pub const OPT: u16 = 41; pub const TSIG: u16 = 250;
    pub const AXFR: u16 = 252; pub const IXFR: u16 = 251; pub const ANY: u16 = 255; pub const SVCB: u16 = 64;
    pub const HTTPS: u16 = 65; pub const ALIAS: u16 = 65401;
    pub fn name(t: u16) -> &'static str { match t { A=>"A", NS=>"NS", CNAME=>"CNAME", SOA=>"SOA", PTR=>"PTR", MX=>"MX", TXT=>"TXT", AAAA=>"AAAA", SRV=>"SRV", NAPTR=>"NAPTR", DS=>"DS", RRSIG=>"RRSIG", NSEC=>"NSEC", DNSKEY=>"DNSKEY", NSEC3=>"NSEC3", NSEC3PARAM=>"NSEC3PARAM", TLSA=>"TLSA", CAA=>"CAA", OPT=>"OPT", TSIG=>"TSIG", AXFR=>"AXFR", IXFR=>"IXFR", ANY=>"ANY", SVCB=>"SVCB", HTTPS=>"HTTPS", ALIAS=>"ALIAS", _=>"TYPE" } }
}
pub mod rclass { pub const IN: u16 = 1; pub const CH: u16 = 3; pub const ANY: u16 = 255; pub const NONE: u16 = 254; }
pub mod opcode { pub const QUERY: u8 = 0; pub const NOTIFY: u8 = 4; pub const UPDATE: u8 = 5; }
pub mod rcode { pub const NOERROR: u8 = 0; pub const FORMERR: u8 = 1; pub const SERVFAIL: u8 = 2; pub const NXDOMAIN: u8 = 3; pub const NOTIMP: u8 = 4; pub const REFUSED: u8 = 5; }
pub const MAX_NAME_LEN: usize = 255; pub const MAX_LABEL_LEN: usize = 63; pub const EDNS_UDP_SIZE: u16 = 4096;
pub fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0) }

// ═══════════════════════════════════════════════════════════════════════════ §4 NAMES
#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub struct Name { pub labels: Vec<Vec<u8>> }
impl Name {
    pub fn root() -> Self { Self { labels: Vec::new() } }
    pub fn from_str(s: &str) -> DnsResult<Self> { let s = s.trim_end_matches('.'); if s.is_empty() { return Ok(Self::root()); } let mut labels = Vec::new(); for part in s.split('.') { if part.len() > MAX_LABEL_LEN { return Err(DnsError::InvalidName(format!("label too long: {}", part))); } if part.is_empty() { return Err(DnsError::InvalidName("empty label".into())); } labels.push(part.as_bytes().to_vec()); } let n = Self { labels }; if n.wire_len() > MAX_NAME_LEN { return Err(DnsError::InvalidName("name too long".into())); } Ok(n) }
    pub fn wire_len(&self) -> usize { self.labels.iter().map(|l| l.len() + 1).sum::<usize>() + 1 }
    pub fn to_string(&self) -> String { if self.labels.is_empty() { ".".into() } else { self.labels.iter().map(|l| String::from_utf8_lossy(l).into_owned()).collect::<Vec<_>>().join(".") + "." } }
    pub fn is_root(&self) -> bool { self.labels.is_empty() }
    pub fn parent(&self) -> Option<Name> { if self.labels.is_empty() { None } else { Some(Self { labels: self.labels[1..].to_vec() }) } }
    pub fn is_subdomain_of(&self, other: &Name) -> bool { if self.labels.len() < other.labels.len() { return false; } let off = self.labels.len() - other.labels.len(); for i in 0..other.labels.len() { if self.labels[off+i].to_ascii_lowercase() != other.labels[i].to_ascii_lowercase() { return false; } } true }
    pub fn lower(&self) -> Name { Name { labels: self.labels.iter().map(|l| l.iter().map(|b| b.to_ascii_lowercase()).collect()).collect() } }
    pub fn prepend(&self, label: &[u8]) -> DnsResult<Name> { let mut labels = vec![label.to_vec()]; labels.extend(self.labels.clone()); let n = Name { labels }; if n.wire_len() > MAX_NAME_LEN { return Err(DnsError::InvalidName("prepend overflow".into())); } Ok(n) }
    pub fn with_star(&self) -> Name { let mut labels = vec![b"*".to_vec()]; labels.extend(self.labels.clone()); Name { labels } }
    pub fn eq_ci(&self, other: &Name) -> bool { if self.labels.len() != other.labels.len() { return false; } for i in 0..self.labels.len() { if self.labels[i].to_ascii_lowercase() != other.labels[i].to_ascii_lowercase() { return false; } } true }
}
impl Ord for Name { fn cmp(&self, other: &Self) -> std::cmp::Ordering { let a: Vec<_> = self.labels.iter().rev().collect(); let b: Vec<_> = other.labels.iter().rev().collect(); for (x, y) in a.iter().zip(b.iter()) { let xl = x.to_ascii_lowercase(); let yl = y.to_ascii_lowercase(); match xl.cmp(&yl) { std::cmp::Ordering::Equal => {}, o => return o } } a.len().cmp(&b.len()) } }
impl PartialOrd for Name { fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(o)) } }

pub fn encode_name(buf: &mut Vec<u8>, name: &Name, compress: &mut HashMap<Vec<u8>, u16>) -> DnsResult<()> {
    let mut cur = name.clone();
    loop {
        if cur.labels.is_empty() { buf.push(0); return Ok(()); }
        let key = cur.labels.iter().flat_map(|l| l.iter().map(|b| b.to_ascii_lowercase()).collect::<Vec<_>>()).collect::<Vec<u8>>();
        if let Some(&off) = compress.get(&key) { buf.push(0xC0 | ((off >> 8) as u8)); buf.push((off & 0xff) as u8); return Ok(()); }
        if buf.len() < 0x3FFF { compress.insert(key, buf.len() as u16); }
        let l = &cur.labels[0]; if l.len() > MAX_LABEL_LEN { return Err(DnsError::InvalidName("label too long".into())); }
        buf.push(l.len() as u8); buf.extend_from_slice(l); cur = Name { labels: cur.labels[1..].to_vec() };
    }
}
pub fn decode_name(buf: &[u8], off: &mut usize) -> DnsResult<Name> {
    let mut labels = Vec::new(); let mut cur = *off; let mut jumped = false; let mut hops = 0u32;
    loop {
        if cur >= buf.len() { return Err(DnsError::Truncated); }
        let b = buf[cur];
        if b == 0 { if !jumped { *off = cur + 1; } return Ok(Name { labels }); }
        if b & 0xC0 == 0xC0 { if cur + 1 >= buf.len() { return Err(DnsError::Truncated); } let ptr = (((b & 0x3f) as usize) << 8) | (buf[cur+1] as usize); if !jumped { *off = cur + 2; } jumped = true; cur = ptr; hops += 1; if hops > 128 { return Err(DnsError::Format("name loop".into())); } continue; }
        if b & 0xC0 != 0 { return Err(DnsError::Format("bad label type".into())); }
        let l = b as usize; cur += 1; if cur + l > buf.len() { return Err(DnsError::Truncated); }
        labels.push(buf[cur..cur+l].to_vec()); cur += l; if labels.len() > 128 { return Err(DnsError::Format("too many labels".into())); }
    }
}

// ═══════════════════════════════════════════════════════════════════════════ §5 RDATA
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RData {
    A(Ipv4Addr), Aaaa(Ipv6Addr), Cname(Name), Ns(Name), Ptr(Name),
    Mx { pref: u16, exchange: Name }, Txt(Vec<Vec<u8>>),
    Soa { mname: Name, rname: Name, serial: u32, refresh: u32, retry: u32, expire: u32, minimum: u32 },
    Srv { priority: u16, weight: u16, port: u16, target: Name },
    Naptr { order: u16, preference: u16, flags: String, service: String, regexp: String, replacement: Name },
    Caa { flags: u8, tag: String, value: String },
    Ds { key_tag: u16, algorithm: u8, digest_type: u8, digest: Vec<u8> },
    Dnskey { flags: u16, protocol: u8, algorithm: u8, public_key: Vec<u8> },
    Rrsig { type_covered: u16, algorithm: u8, labels: u8, original_ttl: u32, sig_exp: u32, sig_inc: u32, key_tag: u16, signer: Name, signature: Vec<u8> },
    Nsec { next: Name, types: Vec<u16> },
    Nsec3 { hash_alg: u8, flags: u8, iterations: u16, salt: Vec<u8>, next_hashed: Vec<u8>, types: Vec<u16> },
    Tlsa { usage: u8, selector: u8, matching: u8, data: Vec<u8> },
    Svcb { priority: u16, target: Name, params: Vec<(u16, Vec<u8>)> },
    Alias(Name), Opt { options: Vec<(u16, Vec<u8>)> },
    Tsig { alg: Name, time_signed: u64, fudge: u16, mac: Vec<u8>, orig_id: u16, error: u16, other: Vec<u8> },
    Unknown(u16, Vec<u8>),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record { pub name: Name, pub rtype: u16, pub rclass: u16, pub ttl: u32, pub rdata: RData }

pub fn encode_rdata(buf: &mut Vec<u8>, rtype: u16, rd: &RData, compress: &mut HashMap<Vec<u8>, u16>) -> DnsResult<()> {
    match rd {
        RData::A(a) => buf.extend_from_slice(&a.octets()),
        RData::Aaaa(a) => buf.extend_from_slice(&a.octets()),
        RData::Cname(n) | RData::Ns(n) | RData::Ptr(n) | RData::Alias(n) => encode_name(buf, n, compress)?,
        RData::Mx { pref, exchange } => { buf.extend_from_slice(&pref.to_be_bytes()); encode_name(buf, exchange, compress)?; }
        RData::Txt(parts) => for p in parts { if p.len() > 255 { return Err(DnsError::Format("txt too long".into())); } buf.push(p.len() as u8); buf.extend_from_slice(p); },
        RData::Soa { mname, rname, serial, refresh, retry, expire, minimum } => { encode_name(buf, mname, compress)?; encode_name(buf, rname, compress)?; buf.extend_from_slice(&serial.to_be_bytes()); buf.extend_from_slice(&refresh.to_be_bytes()); buf.extend_from_slice(&retry.to_be_bytes()); buf.extend_from_slice(&expire.to_be_bytes()); buf.extend_from_slice(&minimum.to_be_bytes()); },
        RData::Srv { priority, weight, port, target } => { buf.extend_from_slice(&priority.to_be_bytes()); buf.extend_from_slice(&weight.to_be_bytes()); buf.extend_from_slice(&port.to_be_bytes()); encode_name(buf, target, compress)?; },
        RData::Naptr { order, preference, flags, service, regexp, replacement } => { buf.extend_from_slice(&order.to_be_bytes()); buf.extend_from_slice(&preference.to_be_bytes()); buf.push(flags.len() as u8); buf.extend_from_slice(flags.as_bytes()); buf.push(service.len() as u8); buf.extend_from_slice(service.as_bytes()); buf.push(regexp.len() as u8); buf.extend_from_slice(regexp.as_bytes()); encode_name(buf, replacement, compress)?; },
        RData::Caa { flags, tag, value } => { buf.push(*flags); buf.push(tag.len() as u8); buf.extend_from_slice(tag.as_bytes()); buf.extend_from_slice(value.as_bytes()); },
        RData::Ds { key_tag, algorithm, digest_type, digest } => { buf.extend_from_slice(&key_tag.to_be_bytes()); buf.push(*algorithm); buf.push(*digest_type); buf.extend_from_slice(digest); },
        RData::Dnskey { flags, protocol, algorithm, public_key } => { buf.extend_from_slice(&flags.to_be_bytes()); buf.push(*protocol); buf.push(*algorithm); buf.extend_from_slice(public_key); },
        RData::Rrsig { type_covered, algorithm, labels, original_ttl, sig_exp, sig_inc, key_tag, signer, signature } => { buf.extend_from_slice(&type_covered.to_be_bytes()); buf.push(*algorithm); buf.push(*labels); buf.extend_from_slice(&original_ttl.to_be_bytes()); buf.extend_from_slice(&sig_exp.to_be_bytes()); buf.extend_from_slice(&sig_inc.to_be_bytes()); buf.extend_from_slice(&key_tag.to_be_bytes()); encode_name(buf, signer, compress)?; buf.extend_from_slice(signature); },
        RData::Nsec { next, types } => { encode_name(buf, next, compress)?; write_type_bitmap(buf, types); },
        RData::Nsec3 { hash_alg, flags, iterations, salt, next_hashed, types } => { buf.push(*hash_alg); buf.push(*flags); buf.extend_from_slice(&iterations.to_be_bytes()); buf.push(salt.len() as u8); buf.extend_from_slice(salt); buf.push(next_hashed.len() as u8); buf.extend_from_slice(next_hashed); write_type_bitmap(buf, types); },
        RData::Tlsa { usage, selector, matching, data } => { buf.push(*usage); buf.push(*selector); buf.push(*matching); buf.extend_from_slice(data); },
        RData::Svcb { priority, target, params } => { buf.extend_from_slice(&priority.to_be_bytes()); encode_name(buf, target, compress)?; for (k, v) in params { buf.extend_from_slice(&k.to_be_bytes()); buf.extend_from_slice(&(v.len() as u16).to_be_bytes()); buf.extend_from_slice(v); } },
        RData::Opt { options } => for (code, data) in options { buf.extend_from_slice(&code.to_be_bytes()); buf.extend_from_slice(&(data.len() as u16).to_be_bytes()); buf.extend_from_slice(data); },
        RData::Tsig { alg, time_signed, fudge, mac, orig_id, error, other } => { encode_name(buf, alg, compress)?; buf.extend_from_slice(&time_signed.to_be_bytes()); buf.extend_from_slice(&fudge.to_be_bytes()); buf.extend_from_slice(&(mac.len() as u16).to_be_bytes()); buf.extend_from_slice(mac); buf.extend_from_slice(&orig_id.to_be_bytes()); buf.extend_from_slice(&error.to_be_bytes()); buf.extend_from_slice(&(other.len() as u16).to_be_bytes()); buf.extend_from_slice(other); },
        RData::Unknown(_, data) => buf.extend_from_slice(data),
    }
    let _ = rtype; Ok(())
}
pub fn decode_rdata(buf: &[u8], off: &mut usize, rtype: u16, end: usize) -> DnsResult<RData> {
    let rd = match rtype {
        rtype::A => { if *off + 4 > end { return Err(DnsError::Truncated); } let mut a = [0u8; 4]; a.copy_from_slice(&buf[*off..*off+4]); *off += 4; RData::A(Ipv4Addr::from(a)) },
        rtype::AAAA => { if *off + 16 > end { return Err(DnsError::Truncated); } let mut a = [0u8; 16]; a.copy_from_slice(&buf[*off..*off+16]); *off += 16; RData::Aaaa(Ipv6Addr::from(a)) },
        rtype::CNAME => RData::Cname(decode_name(buf, off)?),
        rtype::NS => RData::Ns(decode_name(buf, off)?),
        rtype::PTR => RData::Ptr(decode_name(buf, off)?),
        rtype::ALIAS => RData::Alias(decode_name(buf, off)?),
        rtype::MX => { if *off + 2 > end { return Err(DnsError::Truncated); } let pref = u16::from_be_bytes([buf[*off], buf[*off+1]]); *off += 2; let ex = decode_name(buf, off)?; RData::Mx { pref, exchange: ex } },
        rtype::TXT => { let mut parts = Vec::new(); while *off < end { let l = buf[*off] as usize; *off += 1; if *off + l > end { return Err(DnsError::Truncated); } parts.push(buf[*off..*off+l].to_vec()); *off += l; } RData::Txt(parts) },
        rtype::SOA => { let mname = decode_name(buf, off)?; let rname = decode_name(buf, off)?; if *off + 20 > end { return Err(DnsError::Truncated); } let serial = u32::from_be_bytes([buf[*off], buf[*off+1], buf[*off+2], buf[*off+3]]); *off += 4; let refresh = u32::from_be_bytes([buf[*off], buf[*off+1], buf[*off+2], buf[*off+3]]); *off += 4; let retry = u32::from_be_bytes([buf[*off], buf[*off+1], buf[*off+2], buf[*off+3]]); *off += 4; let expire = u32::from_be_bytes([buf[*off], buf[*off+1], buf[*off+2], buf[*off+3]]); *off += 4; let minimum = u32::from_be_bytes([buf[*off], buf[*off+1], buf[*off+2], buf[*off+3]]); *off += 4; RData::Soa { mname, rname, serial, refresh, retry, expire, minimum } },
        rtype::SRV => { if *off + 6 > end { return Err(DnsError::Truncated); } let pri = u16::from_be_bytes([buf[*off], buf[*off+1]]); *off += 2; let w = u16::from_be_bytes([buf[*off], buf[*off+1]]); *off += 2; let p = u16::from_be_bytes([buf[*off], buf[*off+1]]); *off += 2; let t = decode_name(buf, off)?; RData::Srv { priority: pri, weight: w, port: p, target: t } },
        rtype::CAA => { if *off + 2 > end { return Err(DnsError::Truncated); } let flags = buf[*off]; *off += 1; let tag_len = buf[*off] as usize; *off += 1; if *off + tag_len > end { return Err(DnsError::Truncated); } let tag = String::from_utf8_lossy(&buf[*off..*off+tag_len]).into_owned(); *off += tag_len; let value = String::from_utf8_lossy(&buf[*off..end]).into_owned(); *off = end; RData::Caa { flags, tag, value } },
        rtype::DS => { if *off + 4 > end { return Err(DnsError::Truncated); } let kt = u16::from_be_bytes([buf[*off], buf[*off+1]]); *off += 2; let alg = buf[*off]; *off += 1; let dt = buf[*off]; *off += 1; let dg = buf[*off..end].to_vec(); *off = end; RData::Ds { key_tag: kt, algorithm: alg, digest_type: dt, digest: dg } },
        rtype::DNSKEY => { if *off + 4 > end { return Err(DnsError::Truncated); } let fl = u16::from_be_bytes([buf[*off], buf[*off+1]]); *off += 2; let pr = buf[*off]; *off += 1; let alg = buf[*off]; *off += 1; let pk = buf[*off..end].to_vec(); *off = end; RData::Dnskey { flags: fl, protocol: pr, algorithm: alg, public_key: pk } },
        rtype::OPT => { let mut opts = Vec::new(); while *off + 4 <= end { let code = u16::from_be_bytes([buf[*off], buf[*off+1]]); *off += 2; let len = u16::from_be_bytes([buf[*off], buf[*off+1]]) as usize; *off += 2; if *off + len > end { return Err(DnsError::Truncated); } opts.push((code, buf[*off..*off+len].to_vec())); *off += len; } RData::Opt { options: opts } },
        _ => { let data = buf[*off..end].to_vec(); *off = end; RData::Unknown(rtype, data) }
    };
    Ok(rd)
}
fn write_type_bitmap(buf: &mut Vec<u8>, types: &[u16]) {
    let mut sorted: Vec<u16> = types.to_vec(); sorted.sort(); sorted.dedup();
    if sorted.is_empty() { return; }
    let mut windows: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
    for t in sorted { let w = (t / 256) as u8; let b = ((t % 256) / 8) as usize; let bit = t % 8; let entry = windows.entry(w).or_insert_with(|| vec![0u8; b + 1]); if b >= entry.len() { entry.resize(b + 1, 0); } entry[b] |= 1 << (7 - bit); }
    for (win, bitmap) in windows { buf.push(win); buf.push(bitmap.len() as u8); buf.extend_from_slice(&bitmap); }
}

// ═══════════════════════════════════════════════════════════════════════════ §6 MESSAGE
#[derive(Clone, Debug, Default)]
pub struct Message { pub id: u16, pub flags: u16, pub questions: Vec<Question>, pub answers: Vec<Record>, pub authority: Vec<Record>, pub additional: Vec<Record> }
#[derive(Clone, Debug)]
pub struct Question { pub name: Name, pub qtype: u16, pub qclass: u16 }
impl Message {
    pub fn new_query(id: u16, name: Name, qtype: u16) -> Self { Self { id, flags: 0x0100, questions: vec![Question { name, qtype, qclass: rclass::IN }], ..Default::default() } }
    pub fn rcode(&self) -> u8 { (self.flags & 0x0f) as u8 }
    pub fn set_rcode(&mut self, rc: u8) { self.flags = (self.flags & 0xfff0) | (rc as u16 & 0x0f); }
    pub fn set_aa(&mut self) { self.flags |= 0x0400; }
    pub fn set_ra(&mut self) { self.flags |= 0x0080; }
    pub fn encode(&self, max_size: usize) -> DnsResult<Vec<u8>> {
        let mut buf = Vec::with_capacity(512);
        buf.extend_from_slice(&self.id.to_be_bytes()); buf.extend_from_slice(&self.flags.to_be_bytes());
        buf.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.authority.len() as u16).to_be_bytes());
        buf.extend_from_slice(&(self.additional.len() as u16).to_be_bytes());
        let mut compress = HashMap::new();
        for q in &self.questions { encode_name(&mut buf, &q.name, &mut compress)?; buf.extend_from_slice(&q.qtype.to_be_bytes()); buf.extend_from_slice(&q.qclass.to_be_bytes()); }
        fn encode_rr(buf: &mut Vec<u8>, r: &Record, compress: &mut HashMap<Vec<u8>, u16>) -> DnsResult<()> { encode_name(buf, &r.name, compress)?; buf.extend_from_slice(&r.rtype.to_be_bytes()); buf.extend_from_slice(&r.rclass.to_be_bytes()); buf.extend_from_slice(&r.ttl.to_be_bytes()); let lp = buf.len(); buf.extend_from_slice(&[0,0]); let start = buf.len(); encode_rdata(buf, r.rtype, &r.rdata, compress)?; let rdl = buf.len() - start; if rdl > 0xffff { return Err(DnsError::Overflow); } buf[lp] = (rdl >> 8) as u8; buf[lp+1] = rdl as u8; Ok(()) }
        for r in &self.answers { encode_rr(&mut buf, r, &mut compress)?; }
        for r in &self.authority { encode_rr(&mut buf, r, &mut compress)?; }
        for r in &self.additional { encode_rr(&mut buf, r, &mut compress)?; }
        if buf.len() > max_size { return Err(DnsError::Overflow); }
        Ok(buf)
    }
    pub fn decode(buf: &[u8]) -> DnsResult<Self> {
        if buf.len() < 12 { return Err(DnsError::Truncated); }
        let id = u16::from_be_bytes([buf[0], buf[1]]); let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize; let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
        let ns = u16::from_be_bytes([buf[8], buf[9]]) as usize; let ar = u16::from_be_bytes([buf[10], buf[11]]) as usize;
        let mut off = 12;
        let mut questions = Vec::with_capacity(qd);
        for _ in 0..qd { let name = decode_name(buf, &mut off)?; if off + 4 > buf.len() { return Err(DnsError::Truncated); } let qtype = u16::from_be_bytes([buf[off], buf[off+1]]); off += 2; let qclass = u16::from_be_bytes([buf[off], buf[off+1]]); off += 2; questions.push(Question { name, qtype, qclass }); }
        fn decode_rr(buf: &[u8], off: &mut usize) -> DnsResult<Record> { let name = decode_name(buf, off)?; if *off + 10 > buf.len() { return Err(DnsError::Truncated); } let rtype = u16::from_be_bytes([buf[*off], buf[*off+1]]); *off += 2; let rclass = u16::from_be_bytes([buf[*off], buf[*off+1]]); *off += 2; let ttl = u32::from_be_bytes([buf[*off], buf[*off+1], buf[*off+2], buf[*off+3]]); *off += 4; let rdlen = u16::from_be_bytes([buf[*off], buf[*off+1]]) as usize; *off += 2; let end = *off + rdlen; if end > buf.len() { return Err(DnsError::Truncated); } let rd = decode_rdata(buf, off, rtype, end)?; *off = end; Ok(Record { name, rtype, rclass, ttl, rdata: rd }) }
        let mut answers = Vec::with_capacity(an); for _ in 0..an { answers.push(decode_rr(buf, &mut off)?); }
        let mut authority = Vec::with_capacity(ns); for _ in 0..ns { authority.push(decode_rr(buf, &mut off)?); }
        let mut additional = Vec::with_capacity(ar); for _ in 0..ar { additional.push(decode_rr(buf, &mut off)?); }
        Ok(Self { id, flags, questions, answers, authority, additional })
    }
    pub fn edns(&self) -> Option<&Record> { self.additional.iter().find(|r| r.rtype == rtype::OPT) }
    pub fn edns_udp_size(&self) -> u16 { self.edns().map(|r| r.rclass.max(512)).unwrap_or(512) }
    pub fn set_edns_udp_size(&mut self, size: u16) { let mut opt = Record { name: Name::root(), rtype: rtype::OPT, rclass: size, ttl: 0, rdata: RData::Opt { options: Vec::new() } }; if let Some(old) = self.additional.iter().find(|r| r.rtype == rtype::OPT) { if let RData::Opt { options } = &old.rdata { opt.rdata = RData::Opt { options: options.clone() }; } } self.additional.retain(|r| r.rtype != rtype::OPT); self.additional.push(opt); }
}

// ═══════════════════════════════════════════════════════════════════════════ §7 ZONE + PARSER
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZoneChange { pub old_serial: u32, pub new_serial: u32, pub deleted: Vec<Record>, pub added: Vec<Record> }
impl ZoneChange { pub fn empty(s: u32) -> Self { Self { old_serial: s, new_serial: s, deleted: Vec::new(), added: Vec::new() } } }

#[derive(Clone)]
pub struct Zone {
    pub origin: Name, pub ttl: u32,
    pub records: BTreeMap<Name, BTreeMap<u16, Vec<Record>>>,
    pub rrsigs: BTreeMap<Name, BTreeMap<u16, Vec<Record>>>,
    pub serial: u32, pub dirty: bool,
    pub journal: Vec<ZoneChange>, pub max_journal: usize,
    pub weights: BTreeMap<Name, BTreeMap<u16, Vec<u32>>>,
    pub geo_rules: BTreeMap<Name, BTreeMap<u16, GeoRule>>,
}
impl Zone {
    pub fn new(origin: Name) -> Self { Self { origin, ttl: 3600, records: BTreeMap::new(), rrsigs: BTreeMap::new(), serial: 1, dirty: false, journal: Vec::new(), max_journal: 1000, weights: BTreeMap::new(), geo_rules: BTreeMap::new() } }
    pub fn insert(&mut self, rr: Record) {
        let lname = rr.name.lower();
        let entry = self.records.entry(lname).or_default();
        let bucket = entry.entry(rr.rtype).or_default();
        let key = rr.rdata_str();
        let was_present = bucket.iter().any(|r| r.rdata_str() == key);
        bucket.retain(|r| r.rdata_str() != key); bucket.push(rr.clone());
        if !was_present {
            if let Some(last) = self.journal.last_mut() { last.added.push(rr); last.new_serial = self.serial; }
            else { let mut ch = ZoneChange::empty(self.serial); ch.added.push(rr); ch.new_serial = self.serial; self.journal.push(ch); }
            if self.journal.len() > self.max_journal { self.journal.remove(0); }
        }
        self.dirty = true;
    }
    pub fn remove(&mut self, name: &Name, rtype: u16) -> bool {
        let lname = name.lower();
        let removed: Vec<Record> = if let Some(entry) = self.records.get_mut(&lname) { if let Some(bucket) = entry.get_mut(&rtype) { bucket.drain(..).collect() } else { Vec::new() } } else { Vec::new() };
        if !removed.is_empty() {
            if let Some(last) = self.journal.last_mut() { last.deleted.extend(removed); last.new_serial = self.serial; }
            else { let mut ch = ZoneChange::empty(self.serial); ch.deleted.extend(removed); ch.new_serial = self.serial; self.journal.push(ch); }
            if self.journal.len() > self.max_journal { self.journal.remove(0); }
            return true;
        }
        false
    }
    pub fn find(&self, name: &Name, rtype: u16) -> Option<&Vec<Record>> { self.records.get(&name.lower()).and_then(|e| e.get(&rtype)) }
    pub fn find_any(&self, name: &Name) -> Option<&BTreeMap<u16, Vec<Record>>> { self.records.get(&name.lower()) }
    pub fn soa(&self) -> Option<&Record> { self.records.get(&self.origin.lower()).and_then(|e| e.get(&rtype::SOA)).and_then(|v| v.first()) }
    pub fn apex_exists(&self) -> bool { self.records.contains_key(&self.origin.lower()) }
    pub fn find_wildcard(&self, name: &Name, rtype: u16) -> Option<(Name, &Vec<Record>)> {
        let mut cur = name.clone();
        while let Some(parent) = cur.parent() {
            let star = parent.with_star();
            if let Some(bucket) = self.find(&star, rtype) { return Some((star, bucket)); }
            if self.find_any(&parent).is_some() { return None; }
            cur = parent;
        }
        None
    }
    pub fn all_records(&self) -> Vec<Record> { let mut out = Vec::new(); for (_, entry) in &self.records { for (_, bucket) in entry { out.extend(bucket.iter().cloned()); } } out }
    pub fn changes_since(&self, client_serial: u32) -> Vec<ZoneChange> { let mut out = Vec::new(); for ch in &self.journal { if ch.new_serial > client_serial { out.push(ch.clone()); } } out }
    pub fn build_ixfr(&self, client_serial: u32) -> DnsResult<Vec<Record>> {
        let soa = self.soa().cloned().ok_or(DnsError::NotFound)?;
        let mut out: Vec<Record> = Vec::new();
        if client_serial >= self.serial { out.push(soa); return Ok(out); }
        let changes = self.changes_since(client_serial);
        if changes.is_empty() { return Err(DnsError::NotFound); }
        out.push(soa.clone());
        for ch in &changes {
            let old_soa = if let RData::Soa { mname, rname, refresh, retry, expire, minimum, .. } = &soa.rdata {
                Record { name: soa.name.clone(), rtype: rtype::SOA, rclass: rclass::IN, ttl: soa.ttl, rdata: RData::Soa { mname: mname.clone(), rname: rname.clone(), serial: ch.old_serial, refresh: *refresh, retry: *retry, expire: *expire, minimum: *minimum } }
            } else { soa.clone() };
            out.push(old_soa); out.extend(ch.deleted.iter().cloned()); out.extend(ch.added.iter().cloned());
        }
        out.push(soa);
        Ok(out)
    }
    pub fn set_geo_rule(&mut self, name: &Name, rtype: u16, rule: GeoRule) { self.geo_rules.entry(name.lower()).or_default().insert(rtype, rule); self.dirty = true; }
    pub fn remove_geo_rule(&mut self, name: &Name, rtype: u16) -> bool { let mut removed = false; if let Some(m) = self.geo_rules.get_mut(&name.lower()) { removed = m.remove(&rtype).is_some(); } if removed { self.dirty = true; } removed }
}
impl Record {
    pub fn rdata_str(&self) -> String {
        match &self.rdata {
            RData::A(a) => a.to_string(),
            RData::Aaaa(a) => a.to_string(),
            RData::Cname(n) | RData::Ns(n) | RData::Ptr(n) | RData::Alias(n) => n.to_string(),
            RData::Mx { pref, exchange } => format!("{pref} {}", exchange.to_string()),
            RData::Txt(p) => p.iter().map(|s| String::from_utf8_lossy(s).into_owned()).collect::<Vec<_>>().join(" "),
            RData::Soa { mname, rname, serial, refresh, retry, expire, minimum } => format!("{} {} {serial} {refresh} {retry} {expire} {minimum}", mname.to_string(), rname.to_string()),
            RData::Srv { priority, weight, port, target } => format!("{priority} {weight} {port} {}", target.to_string()),
            RData::Caa { flags, tag, value } => format!("{flags} {tag} {value:?}"),
            _ => format!("{:?}", self.rdata).chars().take(64).collect(),
        }
    }
}

pub struct ZoneParser { pub origin: Name, pub default_ttl: u32, pub last_name: Option<Name> }
impl ZoneParser {
    pub fn new(origin: Name) -> Self { Self { origin, default_ttl: 3600, last_name: None } }
    pub fn parse_file(&mut self, path: &Path) -> DnsResult<Zone> { let content = std::fs::read_to_string(path)?; self.parse_str(&content) }
    pub fn parse_str(&mut self, content: &str) -> DnsResult<Zone> {
        let mut zone = Zone::new(self.origin.clone()); zone.ttl = self.default_ttl;
        for raw_line in content.lines() {
    let line = strip_comment(raw_line);
    if line.trim().is_empty() { continue; }
    let start_with_space = raw_line.starts_with(' ') || raw_line.starts_with('\t');
    if line.trim().starts_with('$') { self.handle_directive(&mut zone, line.trim())?; continue; }
    let logical = if start_with_space && self.last_name.is_some() { if let Some(last) = self.last_name.clone() { format!("{} {}", last.to_string(), line.trim()) } else { line.trim().to_string() } } else { line.trim().to_string() };
      if logical.ends_with('(') || (logical.contains(" (") && !logical.contains(')')) { continue; }
            if let Some(rr) = self.parse_record(&logical)? { self.last_name = Some(rr.name.clone()); zone.insert(rr); }
        }
        Ok(zone)
    }
    fn handle_directive(&mut self, zone: &mut Zone, line: &str) -> DnsResult<()> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() { return Ok(()); }
        match parts[0].to_uppercase().as_str() {
            "$ORIGIN" if parts.len() >= 2 => { self.origin = self.resolve_name(parts[1])?; zone.origin = self.origin.clone(); }
            "$TTL" if parts.len() >= 2 => { let ttl = parse_ttl(parts[1])?; self.default_ttl = ttl; zone.ttl = ttl; }
            _ => {}
        }
        Ok(())
    }
    fn resolve_name(&self, s: &str) -> DnsResult<Name> { if s == "@" { return Ok(self.origin.clone()); } if s.ends_with('.') { return Name::from_str(s); } Name::from_str(&format!("{}.{}", s.trim_end_matches('.'), self.origin.to_string().trim_end_matches('.'))) }
    fn parse_record(&mut self, line: &str) -> DnsResult<Option<Record>> {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() { return Ok(None); }
        let mut i = 0; let name = self.resolve_name(tokens[i])?; i += 1;
        let mut ttl = self.default_ttl;
        if i < tokens.len() && tokens[i].chars().all(|c| c.is_ascii_digit()) { ttl = parse_ttl(tokens[i])?; i += 1; }
        if i < tokens.len() && (tokens[i].eq_ignore_ascii_case("IN") || tokens[i].eq_ignore_ascii_case("CH")) { i += 1; }
        if i >= tokens.len() { return Ok(None); }
        let rtype = parse_rtype(tokens[i])?; i += 1;
        let rd = parse_rdata(rtype, &tokens[i..], &self.origin)?;
        Ok(Some(Record { name, rtype, rclass: rclass::IN, ttl, rdata: rd }))
    }
}
fn strip_comment(line: &str) -> String { let mut in_q = false; let mut out = String::new(); for c in line.chars() { if c == '"' { in_q = !in_q; out.push(c); continue; } if c == ';' && !in_q { break; } out.push(c); } out }
fn parse_ttl(s: &str) -> DnsResult<u32> {
    let s = s.to_lowercase();
    if let Ok(n) = s.parse::<u32>() { return Ok(n); }
    let mut total = 0u32; let mut num = 0u32;
    for c in s.chars() { if c.is_ascii_digit() { num = num * 10 + (c as u32 - '0' as u32); } else { let m = match c { 's' => 1, 'm' => 60, 'h' => 3600, 'd' => 86400, 'w' => 604800, _ => return Err(DnsError::Format(format!("bad ttl: {s}"))) }; total += num * m; num = 0; } }
    Ok(total + num)
}
fn parse_rtype(s: &str) -> DnsResult<u16> {
    let s = s.to_uppercase();
    Ok(match s.as_str() {
        "A" => rtype::A, "AAAA" => rtype::AAAA, "CNAME" => rtype::CNAME, "NS" => rtype::NS, "PTR" => rtype::PTR,
        "MX" => rtype::MX, "TXT" => rtype::TXT, "SOA" => rtype::SOA, "SRV" => rtype::SRV, "CAA" => rtype::CAA,
        "DS" => rtype::DS, "DNSKEY" => rtype::DNSKEY, "RRSIG" => rtype::RRSIG, "NSEC" => rtype::NSEC, "NSEC3" => rtype::NSEC3,
        "TLSA" => rtype::TLSA, "SVCB" => rtype::SVCB, "HTTPS" => rtype::HTTPS, "NAPTR" => rtype::NAPTR, "ALIAS" => rtype::ALIAS,
        _ => { if let Some(n) = s.strip_prefix("TYPE") { n.parse().map_err(|_| DnsError::Format("bad TYPE".into()))? } else { return Err(DnsError::Format(format!("unknown type: {s}"))); } }
    })
}
fn parse_rdata(rtype: u16, tokens: &[&str], origin: &Name) -> DnsResult<RData> {
    let resolve_name = |s: &str| -> DnsResult<Name> { if s == "@" { return Ok(origin.clone()); } if s.ends_with('.') { return Name::from_str(s); } Name::from_str(&format!("{}.{}", s, origin.to_string().trim_end_matches('.'))) };
    Ok(match rtype {
        rtype::A => RData::A(tokens.get(0).ok_or(DnsError::Format("A missing".into()))?.parse().map_err(|_| DnsError::Format("bad A".into()))?),
        rtype::AAAA => RData::Aaaa(tokens.get(0).ok_or(DnsError::Format("AAAA missing".into()))?.parse().map_err(|_| DnsError::Format("bad AAAA".into()))?),
        rtype::CNAME => RData::Cname(resolve_name(tokens.get(0).ok_or(DnsError::Format("CNAME missing".into()))?)?),
        rtype::NS => RData::Ns(resolve_name(tokens.get(0).ok_or(DnsError::Format("NS missing".into()))?)?),
        rtype::PTR => RData::Ptr(resolve_name(tokens.get(0).ok_or(DnsError::Format("PTR missing".into()))?)?),
        rtype::ALIAS => RData::Alias(resolve_name(tokens.get(0).ok_or(DnsError::Format("ALIAS missing".into()))?)?),
        rtype::MX => RData::Mx { pref: tokens.get(0).ok_or(DnsError::Format("MX pref".into()))?.parse().map_err(|_| DnsError::Format("bad MX pref".into()))?, exchange: resolve_name(tokens.get(1).ok_or(DnsError::Format("MX exchange".into()))?)? },
        rtype::TXT => { let mut parts = Vec::new(); for t in tokens { parts.push(t.trim_matches('"').as_bytes().to_vec()); } RData::Txt(parts) },
        rtype::SOA => { if tokens.len() < 7 { return Err(DnsError::Format("SOA needs 7".into())); } RData::Soa { mname: resolve_name(tokens[0])?, rname: resolve_name(tokens[1])?, serial: tokens[2].parse().map_err(|_| DnsError::Format("SOA serial".into()))?, refresh: parse_ttl(tokens[3])?, retry: parse_ttl(tokens[4])?, expire: parse_ttl(tokens[5])?, minimum: parse_ttl(tokens[6])? } },
        rtype::SRV => RData::Srv { priority: tokens.get(0).and_then(|s| s.parse().ok()).unwrap_or(0), weight: tokens.get(1).and_then(|s| s.parse().ok()).unwrap_or(0), port: tokens.get(2).and_then(|s| s.parse().ok()).unwrap_or(0), target: resolve_name(tokens.get(3).copied().unwrap_or("."))? },
        rtype::CAA => RData::Caa { flags: tokens.get(0).and_then(|s| s.parse().ok()).unwrap_or(0), tag: tokens.get(1).map(|s| s.to_string()).unwrap_or_default(), value: tokens.get(2).map(|s| s.trim_matches('"').to_string()).unwrap_or_default() },
        _ => RData::Unknown(rtype, Vec::new()),
    })
}

// ═══════════════════════════════════════════════════════════════════════════ §8 AUTH RESOLVER
pub struct AuthResolver { pub zones: Arc<RwLock<HashMap<Name, Arc<RwLock<Zone>>>>> }
impl AuthResolver {
    pub fn new() -> Self { Self { zones: Arc::new(RwLock::new(HashMap::new())) } }
    pub fn add_zone(&self, zone: Zone) { self.zones.write().unwrap().insert(zone.origin.lower(), Arc::new(RwLock::new(zone))); }
    pub fn find_zone(&self, name: &Name) -> Option<Arc<RwLock<Zone>>> { let mut cur = Some(name.lower()); while let Some(n) = cur { if let Some(z) = self.zones.read().unwrap().get(&n) { return Some(z.clone()); } cur = n.parent(); } None }
    pub fn query(&self, name: &Name, qtype: u16) -> AuthResponse {
        let zone = match self.find_zone(name) { Some(z) => z, None => return AuthResponse { answers: vec![], authority: vec![], rcode: rcode::REFUSED, aa: false } };
        let z = zone.read().unwrap();
        if qtype != rtype::CNAME { if let Some(bucket) = z.find(name, rtype::CNAME) { if let Some(cname) = bucket.first() { let mut answers = vec![cname.clone()]; if let RData::Cname(target) = &cname.rdata { if target != name { let mut depth = 0; let mut cur = target.clone(); while depth < 16 { if let Some(t) = z.find(&cur, qtype) { answers.extend(t.iter().cloned()); break; } if let Some(cb) = z.find(&cur, rtype::CNAME) { if let Some(c) = cb.first() { answers.push(c.clone()); if let RData::Cname(next) = &c.rdata { cur = next.clone(); depth += 1; continue; } } } break; } } } return AuthResponse { answers, authority: vec![], rcode: rcode::NOERROR, aa: true }; } } }
        if let Some(bucket) = z.find(name, qtype) { return AuthResponse { answers: bucket.clone(), authority: vec![], rcode: rcode::NOERROR, aa: true }; }
        if qtype == rtype::ANY { if let Some(any) = z.find_any(name) { let mut answers = Vec::new(); for (_, bucket) in any { answers.extend(bucket.iter().cloned()); } return AuthResponse { answers, authority: vec![], rcode: rcode::NOERROR, aa: true }; } }
        if let Some(bucket) = z.find(name, rtype::ALIAS) { if let Some(alias) = bucket.first() { if let RData::Alias(target) = &alias.rdata { if let Some(t) = z.find(target, qtype) { return AuthResponse { answers: t.clone(), authority: vec![], rcode: rcode::NOERROR, aa: true }; } } } }
        if let Some((_wc, bucket)) = z.find_wildcard(name, qtype) { let mut answers: Vec<Record> = bucket.iter().cloned().collect(); for rr in &mut answers { rr.name = name.clone(); } return AuthResponse { answers, authority: vec![], rcode: rcode::NOERROR, aa: true }; }
        if z.find_any(name).is_some() { let soa = z.soa().cloned().into_iter().collect(); return AuthResponse { answers: vec![], authority: soa, rcode: rcode::NOERROR, aa: true }; }
        let soa = z.soa().cloned().into_iter().collect();
        AuthResponse { answers: vec![], authority: soa, rcode: rcode::NXDOMAIN, aa: true }
    }
}
pub struct AuthResponse { pub answers: Vec<Record>, pub authority: Vec<Record>, pub rcode: u8, pub aa: bool }

// ═══════════════════════════════════════════════════════════════════════════ §9 CACHE
#[derive(Clone)]
pub struct CacheEntry { pub records: Vec<Record>, pub expires_at: i64, pub rcode: u8, pub stale_until: i64 }
pub struct DnsCache { pub inner: Mutex<HashMap<String, CacheEntry>>, pub max_entries: usize }
impl DnsCache {
    pub fn new(max_entries: usize) -> Self { Self { inner: Mutex::new(HashMap::new()), max_entries } }
    fn key(name: &Name, qtype: u16) -> String { format!("{}|{}", name.to_string().to_lowercase(), qtype) }
    pub fn get(&self, name: &Name, qtype: u16, serve_stale: bool) -> Option<(Vec<Record>, u8)> { let g = self.inner.lock().unwrap(); let e = g.get(&Self::key(name, qtype))?; let n = now(); if n < e.expires_at { return Some((e.records.clone(), e.rcode)); } if serve_stale && n < e.stale_until { return Some((e.records.clone(), e.rcode)); } None }
    pub fn put(&self, name: &Name, qtype: u16, records: Vec<Record>, rcode: u8, ttl: u32) { let mut g = self.inner.lock().unwrap(); if g.len() >= self.max_entries && !g.contains_key(&Self::key(name, qtype)) { if let Some(k) = g.keys().next().cloned() { g.remove(&k); } } let t = now(); g.insert(Self::key(name, qtype), CacheEntry { records, expires_at: t + ttl as i64, rcode, stale_until: t + ttl as i64 + 86400 }); }
    pub fn clear(&self) { self.inner.lock().unwrap().clear(); }
    pub fn len(&self) -> usize { self.inner.lock().unwrap().len() }
}

// ═══════════════════════════════════════════════════════════════════════════ §10 RECURSIVE (full iterative)
pub struct RecursiveResolver {
    pub cache: Arc<DnsCache>, pub forwarders: Vec<SocketAddr>,
    pub conditional: HashMap<Name, Vec<SocketAddr>>, pub root_hints: Vec<(Name, Ipv4Addr)>,
    pub timeout_ms: u64, pub qname_minimisation: bool,
}
impl RecursiveResolver {
    pub fn new() -> Self { Self { cache: Arc::new(DnsCache::new(50_000)), forwarders: Vec::new(), conditional: HashMap::new(), root_hints: default_root_hints(), timeout_ms: 2000, qname_minimisation: true } }
    pub async fn resolve(&self, name: &Name, qtype: u16) -> DnsResult<(Vec<Record>, u8)> {
        if let Some((r, rc)) = self.cache.get(name, qtype, true) { return Ok((r, rc)); }
        let mut cur = Some(name.lower());
        while let Some(n) = cur { if let Some(fwds) = self.conditional.get(&n) { for fwd in fwds { if let Ok((r, rc, _, _)) = self.query_full(*fwd, name, qtype, false).await { let ttl = r.iter().map(|x| x.ttl).min().unwrap_or(60).max(5); self.cache.put(name, qtype, r.clone(), rc, ttl); return Ok((r, rc)); } } } cur = n.parent(); }
        for fwd in &self.forwarders { if let Ok((r, rc, _, _)) = self.query_full(*fwd, name, qtype, false).await { let ttl = r.iter().map(|x| x.ttl).min().unwrap_or(60).max(5); self.cache.put(name, qtype, r.clone(), rc, ttl); return Ok((r, rc)); } }
        if let Ok((r, rc)) = self.iterative(name, qtype, 0).await { let ttl = r.iter().map(|x| x.ttl).min().unwrap_or(60).max(5); self.cache.put(name, qtype, r.clone(), rc, ttl); return Ok((r, rc)); }
        Err(DnsError::ServFail)
    }
    async fn query_full(&self, addr: SocketAddr, name: &Name, qtype: u16, tcp: bool) -> DnsResult<(Vec<Record>, u8, Vec<Record>, Vec<Record>)> {
    let mut q = Message::new_query(rand::random::<u16>(), name.clone(), qtype);
    q.set_edns_udp_size(EDNS_UDP_SIZE);
    let buf = q.encode(4096)?;
    if tcp {
        let mut s = tokio::time::timeout(Duration::from_millis(self.timeout_ms), TcpStream::connect(addr)).await.map_err(|_| DnsError::ServFail)??;
        s.write_all(&(buf.len() as u16).to_be_bytes()).await?;
        s.write_all(&buf).await?;
        let mut lb = [0u8; 2];
        s.read_exact(&mut lb).await?;
        let len = u16::from_be_bytes(lb) as usize;
        let mut resp = vec![0u8; len];
        s.read_exact(&mut resp).await?;
        let m = Message::decode(&resp)?;
        let rcode = m.rcode();
        return Ok((m.answers, rcode, m.authority, m.additional));
    }
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.send_to(&buf, addr).await?;
    let mut resp = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_millis(self.timeout_ms), sock.recv(&mut resp)).await.map_err(|_| DnsError::ServFail)??;
    let m = Message::decode(&resp[..n])?;
    if m.flags & 0x0200 != 0 { return Box::pin(self.query_full(addr, name, qtype, true)).await; }
    let rcode = m.rcode();
    Ok((m.answers, rcode, m.authority, m.additional))
}
    fn iterative<'a>(&'a self, name: &'a Name, qtype: u16, depth: u32) -> std::pin::Pin<Box<dyn std::future::Future<Output = DnsResult<(Vec<Record>, u8)>> + Send + 'a>> {
        Box::pin(async move {
            if depth > 24 { return Err(DnsError::ServFail); }
            let mut servers: Vec<IpAddr> = self.root_hints.iter().map(|(_, ip)| IpAddr::V4(*ip)).collect();
            let mut qname = if self.qname_minimisation { self.trim_to(name, 1) } else { name.clone() };
            let mut hops = 0u32;
            loop {
                if hops > 32 { return Err(DnsError::ServFail); }
                hops += 1;
                let mut next: Vec<IpAddr> = Vec::new();
                let mut got_terminal: Option<(Vec<Record>, u8)> = None;
                let mut last_rcode = rcode::SERVFAIL;
                for srv in &servers {
                    let addr = SocketAddr::new(*srv, 53);
                    let q = if self.qname_minimisation && !qname.is_subdomain_of(name) { qname.clone() } else { name.clone() };
                    let (answers, rc, authority, additional) = match self.query_full(addr, &q, qtype, false).await { Ok(x) => x, Err(_) => continue };
                    last_rcode = rc;
                    if !answers.is_empty() {
                        let mut chain = answers.clone();
                        if answers.iter().any(|r| r.rtype == rtype::CNAME) && qtype != rtype::CNAME {
                            if let Some(target) = answers.iter().find_map(|r| if let RData::Cname(t) = &r.rdata { Some(t.clone()) } else { None }) {
                                if target != *name { if let Ok((mut more, _)) = Box::pin(self.iterative(&target, qtype, depth + 1)).await { chain.append(&mut more); } }
                            }
                        }
                        got_terminal = Some((chain, rc)); break;
                    }
                    if rc == rcode::NXDOMAIN { got_terminal = Some((Vec::new(), rcode::NXDOMAIN)); break; }
                    for rr in &authority {
                        if rr.rtype == rtype::NS { if let RData::Ns(ns_name) = &rr.rdata { for add in &additional { if add.name.eq_ci(ns_name) { match &add.rdata { RData::A(a) => next.push(IpAddr::V4(*a)), RData::Aaaa(a) => next.push(IpAddr::V6(*a)), _ => {} } } } } }
                    }
                    if !next.is_empty() { break; }
                    for rr in &authority {
                        if rr.rtype == rtype::NS { if let RData::Ns(ns_name) = &rr.rdata { if let Ok((ns_ips, _)) = Box::pin(self.iterative(ns_name, rtype::A, depth + 1)).await { for r in ns_ips { match &r.rdata { RData::A(a) => next.push(IpAddr::V4(*a)), RData::Aaaa(a) => next.push(IpAddr::V6(*a)), _ => {} } } } } }
                    }
                    if !next.is_empty() { break; }
                }
                if let Some(ans) = got_terminal { return Ok(ans); }
                if next.is_empty() { return Ok((Vec::new(), last_rcode)); }
                if self.qname_minimisation && !qname.is_subdomain_of(name) { if let Some(next_label) = name.labels.iter().rev().nth(qname.labels.len()) { if let Ok(q) = qname.prepend(next_label) { qname = q; } } }
                servers = next;
            }
        })
    }
    fn trim_to(&self, name: &Name, depth: usize) -> Name { if name.labels.len() <= depth { return name.clone(); } let start = name.labels.len() - depth; Name { labels: name.labels[start..].to_vec() } }
}
fn default_root_hints() -> Vec<(Name, Ipv4Addr)> {
    let entries: &[(&str, [u8;4])] = &[("a.root-servers.net.",[198,41,0,4]),("b.root-servers.net.",[170,247,170,2]),("c.root-servers.net.",[192,33,4,12]),("d.root-servers.net.",[199,7,91,13]),("e.root-servers.net.",[192,203,230,10]),("f.root-servers.net.",[192,5,5,241]),("g.root-servers.net.",[192,112,36,4]),("h.root-servers.net.",[198,97,190,53]),("i.root-servers.net.",[192,36,148,17]),("j.root-servers.net.",[192,58,128,30]),("k.root-servers.net.",[193,0,14,129]),("l.root-servers.net.",[199,7,83,42]),("m.root-servers.net.",[202,12,27,33])];
    entries.iter().map(|(n, ip)| (Name::from_str(n).unwrap_or_else(|_| Name::root()), Ipv4Addr::from(*ip))).collect()
}

// ═══════════════════════════════════════════════════════════════════════════ §11 DNSSEC (full ECDSA P-256)
pub const DNSSEC_ALG_ECDSAP256_SHA256: u8 = 13;
pub const DNSKEY_FLAG_ZONE_KEY: u16 = 256;
pub const DNSKEY_FLAG_SECURE_ENTRY: u16 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnssecKey { pub key_tag: u16, pub algorithm: u8, pub flags: u16, pub is_ksk: bool, pub private_pem: Option<String>, pub public_b64: String }
impl DnssecKey {
    pub fn generate(is_ksk: bool) -> DnsResult<Self> {
        use p256::ecdsa::SigningKey; use rand::rngs::OsRng; use p256::pkcs8::EncodePrivateKey;
        let sk = SigningKey::random(&mut OsRng); let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false); let raw = point.as_bytes();
        let pk = raw[1..].to_vec();
        let flags = if is_ksk { DNSKEY_FLAG_ZONE_KEY | DNSKEY_FLAG_SECURE_ENTRY } else { DNSKEY_FLAG_ZONE_KEY };
        let mut rdata = Vec::with_capacity(68);
        rdata.extend_from_slice(&flags.to_be_bytes()); rdata.push(3); rdata.push(DNSSEC_ALG_ECDSAP256_SHA256);
        rdata.extend_from_slice(&pk);
        let key_tag = compute_key_tag(&rdata);
        let pem = sk.to_pkcs8_pem(p256::pkcs8::LineEnding::LF).map_err(|e| DnsError::DnssecError(e.to_string()))?.to_string();
        use base64::{engine::general_purpose::STANDARD, Engine};
        let pub_b64 = STANDARD.encode(&rdata);
        Ok(DnssecKey { key_tag, algorithm: DNSSEC_ALG_ECDSAP256_SHA256, flags, is_ksk, private_pem: Some(pem), public_b64: pub_b64 })
    }
    pub fn signing_key(&self) -> DnsResult<p256::ecdsa::SigningKey> { use p256::pkcs8::DecodePrivateKey; let pem = self.private_pem.as_ref().ok_or_else(|| DnsError::DnssecError("no private key".into()))?; p256::ecdsa::SigningKey::from_pkcs8_pem(pem).map_err(|e| DnsError::DnssecError(e.to_string())) }
    pub fn dnskey_record(&self, zone: &Name, ttl: u32) -> DnsResult<Record> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let rdata = STANDARD.decode(&self.public_b64).map_err(|_| DnsError::DnssecError("bad dnskey b64".into()))?;
        if rdata.len() < 4 { return Err(DnsError::DnssecError("dnskey too short".into())); }
        let flags = u16::from_be_bytes([rdata[0], rdata[1]]); let protocol = rdata[2]; let algorithm = rdata[3];
        let public_key = rdata[4..].to_vec();
        Ok(Record { name: zone.clone(), rtype: rtype::DNSKEY, rclass: rclass::IN, ttl, rdata: RData::Dnskey { flags, protocol, algorithm, public_key } })
    }
    pub fn ds_record(&self, zone: &Name, ttl: u32) -> DnsResult<Record> {
        use sha2::{Sha256, Digest}; use base64::{engine::general_purpose::STANDARD, Engine};
        let mut wire = Vec::new(); let mut c = HashMap::new(); encode_name(&mut wire, &zone.lower(), &mut c)?;
        let rdata = STANDARD.decode(&self.public_b64).map_err(|_| DnsError::DnssecError("bad".into()))?;
        wire.extend_from_slice(&rdata);
        let digest = Sha256::digest(&wire).to_vec();
        Ok(Record { name: zone.clone(), rtype: rtype::DS, rclass: rclass::IN, ttl, rdata: RData::Ds { key_tag: self.key_tag, algorithm: self.algorithm, digest_type: 2, digest } })
    }
}
pub fn compute_key_tag(rdata: &[u8]) -> u16 { let mut ac: u32 = 0; for (i, b) in rdata.iter().enumerate() { ac += if i & 1 == 0 { (*b as u32) << 8 } else { *b as u32 }; } ac += (ac >> 16) & 0xFFFF; (ac & 0xFFFF) as u16 }

pub fn canonical_rr(rr: &Record) -> Vec<u8> {
    let mut buf = Vec::new(); let lower = rr.name.lower(); let mut c = HashMap::new(); let _ = encode_name(&mut buf, &lower, &mut c);
    buf.extend_from_slice(&rr.rtype.to_be_bytes()); buf.extend_from_slice(&rr.rclass.to_be_bytes()); buf.extend_from_slice(&rr.ttl.to_be_bytes());
    let start = buf.len(); buf.extend_from_slice(&[0, 0]);
    let mut c2 = HashMap::new(); let _ = encode_rdata(&mut buf, rr.rtype, &rr.rdata, &mut c2);
    let len = (buf.len() - start - 2) as u16; buf[start] = (len >> 8) as u8; buf[start + 1] = len as u8;
    buf
}
pub fn sign_rrset(rrset: &[Record], key: &DnssecKey, signer: &Name, inception: u32, expiration: u32) -> DnsResult<Record> {
    if rrset.is_empty() { return Err(DnsError::DnssecError("empty rrset".into())); }
    let owner = &rrset[0].name; let covered = rrset[0].rtype;
    let labels = owner.labels.len() as u8; let orig_ttl = rrset[0].ttl;
    let mut input = Vec::new();
    input.extend_from_slice(&covered.to_be_bytes()); input.push(key.algorithm); input.push(labels);
    input.extend_from_slice(&orig_ttl.to_be_bytes()); input.extend_from_slice(&expiration.to_be_bytes());
    input.extend_from_slice(&inception.to_be_bytes()); input.extend_from_slice(&key.key_tag.to_be_bytes());
    let mut c = HashMap::new(); encode_name(&mut input, &signer.lower(), &mut c)?;
    let mut canon: Vec<Vec<u8>> = rrset.iter().map(canonical_rr).collect(); canon.sort();
    for c in canon { input.extend(c); }
    use p256::ecdsa::signature::Signer;
    let sk = key.signing_key()?;
    let sig: p256::ecdsa::Signature = sk.sign(&input);
    Ok(Record { name: owner.clone(), rtype: rtype::RRSIG, rclass: rclass::IN, ttl: orig_ttl, rdata: RData::Rrsig { type_covered: covered, algorithm: key.algorithm, labels, original_ttl: orig_ttl, sig_exp: expiration, sig_inc: inception, key_tag: key.key_tag, signer: signer.clone(), signature: sig.to_bytes().to_vec() } })
}
pub struct DnssecStore { pub keys: RwLock<HashMap<Name, Vec<DnssecKey>>>, pub trust_anchors: RwLock<Vec<Record>> }
impl DnssecStore {
    pub fn new() -> Self { Self { keys: RwLock::new(HashMap::new()), trust_anchors: RwLock::new(Vec::new()) } }
    pub fn add_key(&self, zone: Name, key: DnssecKey) { self.keys.write().unwrap().entry(zone.lower()).or_default().push(key); }
    pub fn keys_for(&self, zone: &Name) -> Vec<DnssecKey> { self.keys.read().unwrap().get(&zone.lower()).cloned().unwrap_or_default() }
    pub fn sign_zone(&self, zone: &mut Zone) -> DnsResult<()> {
        let keys = self.keys_for(&zone.origin);
        if keys.is_empty() { return Err(DnsError::DnssecError("no signing keys".into())); }
        let zsk = keys.iter().find(|k| !k.is_ksk).cloned().unwrap_or_else(|| keys[0].clone());
        let ksk = keys.iter().find(|k| k.is_ksk).cloned().unwrap_or_else(|| keys[0].clone());
        let now_ts = now() as u32; let inception = now_ts.saturating_sub(3600); let expiration = now_ts.saturating_add(30 * 86400);
        for k in [&ksk, &zsk] { let rr = k.dnskey_record(&zone.origin, zone.ttl)?; zone.insert(rr); }
        let mut names: Vec<Name> = zone.records.keys().cloned().collect(); names.sort();
        let mut nsec: Vec<(Name, Vec<u16>)> = Vec::new();
        for name in &names { let types: Vec<u16> = zone.records.get(name).map(|e| e.keys().cloned().collect()).unwrap_or_default(); nsec.push((name.clone(), types)); }
        let mut rrsig_records: Vec<Record> = Vec::new();
        for name in &names {
            let entry = zone.records.get(name).cloned().unwrap_or_default();
            for (rty, bucket) in &entry {
                if *rty == rtype::RRSIG { continue; }
                if bucket.is_empty() { continue; }
                let signer_key = if *rty == rtype::DNSKEY || *rty == rtype::SOA { &ksk } else { &zsk };
                let sig = sign_rrset(bucket, signer_key, &zone.origin, inception, expiration)?;
                rrsig_records.push(sig);
            }
        }
        for (i, (name, types)) in nsec.iter().enumerate() {
            let next = if i + 1 < nsec.len() { nsec[i + 1].0.clone() } else { zone.origin.clone() };
            let mut all_types = types.clone(); all_types.push(rtype::NSEC); all_types.push(rtype::RRSIG);
            let nsec_rr = Record { name: name.clone(), rtype: rtype::NSEC, rclass: rclass::IN, ttl: zone.ttl, rdata: RData::Nsec { next, types: all_types } };
            let sig = sign_rrset(&[nsec_rr.clone()], &zsk, &zone.origin, inception, expiration)?;
            zone.insert(nsec_rr); rrsig_records.push(sig);
        }
        for r in rrsig_records { zone.insert(r); }
        Ok(())
    }
    pub fn nsec3_hash(&self, name: &Name, salt: &[u8], iterations: u16) -> Vec<u8> {
        use sha2::{Sha256, Digest};
        let canon = name.lower().to_string().to_uppercase();
        let mut h = Sha256::new(); h.update(canon.as_bytes()); h.update(salt);
        let mut out = h.finalize().to_vec();
        for _ in 0..iterations { let mut h = Sha256::new(); h.update(&out); h.update(salt); out = h.finalize().to_vec(); }
        out
    }
    pub fn validate(&self, msg: &Message) -> DnsResult<bool> {
        let dnskey = msg.additional.iter().find(|r| r.rtype == rtype::DNSKEY);
        let dnskey = match dnskey { Some(k) => k, None => return Ok(true) };
        let (pk_bytes, alg) = match &dnskey.rdata { RData::Dnskey { public_key, algorithm, .. } => (public_key.clone(), *algorithm), _ => return Ok(true) };
        if alg != DNSSEC_ALG_ECDSAP256_SHA256 { return Ok(true); }
        use p256::ecdsa::{VerifyingKey, Signature, signature::Verifier};
        use p256::EncodedPoint;
        let mut point_bytes = Vec::with_capacity(65); point_bytes.push(0x04); point_bytes.extend_from_slice(&pk_bytes);
        let point = match EncodedPoint::from_bytes(&point_bytes) { Ok(p) => p, Err(_) => return Ok(true) };
        let vk = match VerifyingKey::from_encoded_point(&point) { Ok(k) => k, Err(_) => return Ok(true) };
        for rrsig in &msg.answers {
            if rrsig.rtype != rtype::RRSIG { continue; }
            let (cov, exp, inc, tag, signer, sig_bytes, labels) = match &rrsig.rdata { RData::Rrsig { type_covered, sig_exp, sig_inc, key_tag, signer, signature, labels, .. } => (*type_covered, *sig_exp, *sig_inc, *key_tag, signer.clone(), signature.clone(), *labels), _ => continue };
            let rrset: Vec<Record> = msg.answers.iter().filter(|r| r.rtype == cov).cloned().collect();
            if rrset.is_empty() { continue; }
            let mut input = Vec::new();
            input.extend_from_slice(&cov.to_be_bytes()); input.push(alg); input.push(labels);
            input.extend_from_slice(&rrset[0].ttl.to_be_bytes()); input.extend_from_slice(&exp.to_be_bytes());
            input.extend_from_slice(&inc.to_be_bytes()); input.extend_from_slice(&tag.to_be_bytes());
            let mut c = HashMap::new(); encode_name(&mut input, &signer.lower(), &mut c)?;
            let mut canon: Vec<Vec<u8>> = rrset.iter().map(canonical_rr).collect(); canon.sort();
            for c in canon { input.extend(c); }
            let sig = match Signature::from_slice(&sig_bytes) { Ok(s) => s, Err(_) => continue };
            if vk.verify(&input, &sig).is_ok() { return Ok(true); }
        }
        Ok(false)
    }
}

// ═══════════════════════════════════════════════════════════════════════════ §12 ACL + VIEWS
#[derive(Clone, Debug)]
pub struct Cidr { pub addr: IpAddr, pub prefix: u8 }
impl Cidr {
    pub fn parse(s: &str) -> DnsResult<Self> {
        if let Some((a, p)) = s.split_once('/') { let addr: IpAddr = a.parse().map_err(|_| DnsError::Format("bad cidr".into()))?; let prefix = p.parse().map_err(|_| DnsError::Format("bad prefix".into()))?; Ok(Self { addr, prefix }) }
        else { let addr: IpAddr = s.parse().map_err(|_| DnsError::Format("bad ip".into()))?; Ok(Self { addr, prefix: if addr.is_ipv4() { 32 } else { 128 } }) }
    }
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (&self.addr, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => { let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix) }; (u32::from(*a) & mask) == (u32::from(*b) & mask) }
            (IpAddr::V6(a), IpAddr::V6(b)) => { let a = u128::from(*a); let b = u128::from(*b); let mask = if self.prefix == 0 { 0 } else { u128::MAX << (128 - self.prefix) }; (a & mask) == (b & mask) }
            _ => false,
        }
    }
}
#[derive(Clone)]
pub struct View { pub name: String, pub match_cidrs: Vec<Cidr>, pub match_tsig: Option<String>, pub zones: Vec<PathBuf> }
pub struct ViewRegistry { pub views: Vec<View>, pub default_view: Option<String> }
impl ViewRegistry {
    pub fn new() -> Self { Self { views: Vec::new(), default_view: None } }
    pub fn add(&mut self, v: View) { self.views.push(v); }
    pub fn select(&self, client_ip: &IpAddr, tsig: Option<&str>) -> Option<&View> {
        for v in &self.views { if let Some(t) = &v.match_tsig { if Some(t.as_str()) == tsig { return Some(v); } } }
        for v in &self.views { if v.match_cidrs.iter().any(|c| c.contains(client_ip)) { return Some(v); } }
        if let Some(name) = &self.default_view { return self.views.iter().find(|v| &v.name == name); }
        self.views.first()
    }
}

// ═══════════════════════════════════════════════════════════════════════════ §13 RPZ
#[derive(Default)]
pub struct Rrpz { pub exact: HashSet<String>, pub wildcards: Vec<String> }
pub struct RpzRegistry { pub zones: RwLock<HashMap<String, Arc<RwLock<Rrpz>>>> }
impl RpzRegistry {
    pub fn new() -> Self { Self { zones: RwLock::new(HashMap::new()) } }
    pub fn load_hostfile(&self, name: &str, path: &Path) -> DnsResult<usize> {
        let mut rpz = Rrpz::default(); let content = std::fs::read_to_string(path)?; let mut count = 0;
        for line in content.lines() {
            let line = line.trim(); if line.is_empty() || line.starts_with('#') { continue; }
            let parts: Vec<&str> = line.split_whitespace().collect();
            let domain = if parts.len() >= 2 { parts[1] } else { parts[0] };
            let d = domain.trim_end_matches('.').to_lowercase();
            if d.starts_with("*.") { rpz.wildcards.push(d[2..].to_string()); } else { rpz.exact.insert(d); }
            count += 1;
        }
        self.zones.write().unwrap().insert(name.to_string(), Arc::new(RwLock::new(rpz)));
        Ok(count)
    }
    pub fn blocked(&self, name: &Name) -> bool {
        let s = name.to_string().trim_end_matches('.').to_lowercase();
        for z in self.zones.read().unwrap().values() {
            let g = z.read().unwrap();
            if g.exact.contains(&s) { return true; }
            for w in &g.wildcards { if s.ends_with(w) || s == *w { return true; } }
        }
        false
    }
}
pub fn is_private_ip(ip: &IpAddr) -> bool { match ip { IpAddr::V4(a) => a.is_private() || a.is_loopback() || a.is_link_local() || a.octets()[0] == 0, IpAddr::V6(a) => a.is_loopback() || a.is_unique_local() } }
pub fn rebinding_protected(records: &[Record], client_is_private: bool) -> Vec<Record> { if client_is_private { return records.to_vec(); } records.iter().filter(|r| match &r.rdata { RData::A(a) => !is_private_ip(&IpAddr::V4(*a)), RData::Aaaa(a) => !is_private_ip(&IpAddr::V6(*a)), _ => true }).cloned().collect() }

// ═══════════════════════════════════════════════════════════════════════════ §14 COOKIES
pub const COOKIE_OPT: u16 = 10;
pub fn make_server_cookie(client_cookie: &[u8; 8], server_secret: &[u8]) -> [u8; 8] { use sha2::{Sha256, Digest}; let mut h = Sha256::new(); h.update(server_secret); h.update(client_cookie); let d = h.finalize(); let mut out = [0u8; 8]; out.copy_from_slice(&d[..8]); out }
pub fn handle_cookie(msg: &mut Message, server_secret: &[u8]) -> bool {
    let opt = match msg.edns() { Some(o) => o, None => return true };
    let options = match &opt.rdata { RData::Opt { options } => options, _ => return true };
    let cookie_bytes = match options.iter().find(|(c, _)| *c == COOKIE_OPT) { Some((_, d)) if d.len() >= 8 => d.clone(), _ => return true };
    let mut client_c = [0u8; 8]; client_c.copy_from_slice(&cookie_bytes[..8]);
    let server_c = make_server_cookie(&client_c, server_secret);
    let mut new_cookie = Vec::with_capacity(16); new_cookie.extend_from_slice(&client_c); new_cookie.extend_from_slice(&server_c);
    if let Some(opt_mut) = msg.additional.iter_mut().find(|r| r.rtype == rtype::OPT) {
        if let RData::Opt { options } = &mut opt_mut.rdata { options.retain(|(c, _)| *c != COOKIE_OPT); options.push((COOKIE_OPT, new_cookie)); }
    }
    true
}

// ═══════════════════════════════════════════════════════════════════════════ §15 TSIG
#[derive(Clone)]
pub struct TsigKey { pub name: String, pub algorithm: String, pub secret: Vec<u8> }
pub struct TsigRegistry { pub keys: RwLock<HashMap<String, TsigKey>> }
impl TsigRegistry {
    pub fn new() -> Self { Self { keys: RwLock::new(HashMap::new()) } }
    pub fn add(&self, key: TsigKey) { self.keys.write().unwrap().insert(key.name.clone(), key); }
    pub fn verify(&self, msg: &Message, raw: &[u8]) -> DnsResult<Option<String>> {
        let tsig = msg.additional.iter().find(|r| r.rtype == rtype::TSIG);
        let tsig = match tsig { Some(t) => t, None => return Ok(None) };
        let mac = match &tsig.rdata { RData::Tsig { mac, .. } => mac.clone(), _ => return Err(DnsError::TsigError("bad tsig rdata".into())) };
        let key_name = tsig.name.to_string();
        let key = self.keys.read().unwrap().get(key_name.trim_end_matches('.')).cloned().or_else(|| self.keys.read().unwrap().get(&key_name).cloned());
        let key = match key { Some(k) => k, None => return Err(DnsError::TsigError(format!("unknown key: {key_name}"))) };
        let expected = hmac_sha256(&key.secret, raw);
        if mac.len() != expected.len() || mac != expected { return Err(DnsError::TsigError("mac mismatch".into())); }
        Ok(Some(key.name.clone()))
    }
    pub fn sign(&self, msg: &mut Message, key_name: &str, raw_without_tsig: &[u8]) -> DnsResult<()> {
        let key = self.keys.read().unwrap().get(key_name).cloned().ok_or(DnsError::TsigError("unknown".into()))?;
        let mac = hmac_sha256(&key.secret, raw_without_tsig);
        let tsig = Record { name: Name::from_str(key_name)?, rtype: rtype::TSIG, rclass: rclass::ANY, ttl: 0, rdata: RData::Tsig { alg: Name::from_str("hmac-sha256.")?, time_signed: now() as u64, fudge: 300, mac: mac.to_vec(), orig_id: msg.id, error: 0, other: Vec::new() } };
        msg.additional.push(tsig);
        Ok(())
    }
}
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest}; let block = 64;
    let mut k = [0u8; 64];
    if key.len() > block { let mut h = Sha256::new(); h.update(key); let d = h.finalize(); k[..32].copy_from_slice(&d); } else { k[..key.len()].copy_from_slice(key); }
    let mut ipad = [0x36u8; 64]; let mut opad = [0x5cu8; 64];
    for i in 0..64 { ipad[i] ^= k[i]; opad[i] ^= k[i]; }
    let mut inner = Sha256::new(); inner.update(&ipad); inner.update(msg); let ih = inner.finalize();
    let mut outer = Sha256::new(); outer.update(&opad); outer.update(&ih);
    let mut out = [0u8; 32]; out.copy_from_slice(&outer.finalize()); out
}
pub fn send_notify(_upstream: SocketAddr, zone: &Name) -> DnsResult<Vec<u8>> { let mut msg = Message::new_query(rand::random(), zone.clone(), rtype::SOA); msg.flags = 0x2000; msg.encode(512) }

// ═══════════════════════════════════════════════════════════════════════════ §16 ACME DNS-01
pub struct AcmeChallengeGuard { pub resolver: Arc<AuthResolver>, pub zone_name: Name, pub record_name: Name, pub value: String }
impl Drop for AcmeChallengeGuard { fn drop(&mut self) { if let Some(zone_arc) = self.resolver.find_zone(&self.zone_name) { if let Ok(mut zone) = zone_arc.write() { zone.remove(&self.record_name, rtype::TXT); } } } }
pub fn acme_dns01_publish(resolver: &Arc<AuthResolver>, zone: &Name, domain: &str, token_value: &str) -> DnsResult<AcmeChallengeGuard> {
    let zone_arc = resolver.find_zone(zone).ok_or(DnsError::NotFound)?;
    let record_name = Name::from_str(&format!("_acme-challenge.{}", domain))?;
    let rec = Record { name: record_name.clone(), rtype: rtype::TXT, rclass: rclass::IN, ttl: 60, rdata: RData::Txt(vec![token_value.as_bytes().to_vec()]) };
    let mut z = zone_arc.write().unwrap(); z.insert(rec);
    Ok(AcmeChallengeGuard { resolver: resolver.clone(), zone_name: zone.clone(), record_name, value: token_value.to_string() })
}

// ═══════════════════════════════════════════════════════════════════════════ §17 METRICS
#[derive(Default)]
pub struct DnsMetrics {
    pub total_queries: AtomicU64, pub responses_noerror: AtomicU64, pub responses_nxdomain: AtomicU64, pub responses_servfail: AtomicU64, pub responses_refused: AtomicU64,
    pub cache_hits: AtomicU64, pub cache_misses: AtomicU64, pub blocked: AtomicU64, pub rate_limited: AtomicU64, pub recursive_queries: AtomicU64,
    pub axfr_transfers: AtomicU64, pub ixfr_transfers: AtomicU64, pub rrl_dropped: AtomicU64, pub rrl_slipped: AtomicU64,
    pub geo_hits: AtomicU64, pub weighted_selections: AtomicU64, pub audit_events: AtomicU64, pub total_latency_us: AtomicU64,
}
impl DnsMetrics {
    pub fn to_prometheus(&self) -> String {
        let mut s = String::new();
        s += "# HELP omnirs_dns_queries_total Total DNS queries\n# TYPE omnirs_dns_queries_total counter\n";
        s += &format!("omnirs_dns_queries_total {}\n", self.total_queries.load(Ordering::Relaxed));
        s += "# HELP omnirs_dns_rcode RCODE distribution\n# TYPE omnirs_dns_rcode counter\n";
        s += &format!("omnirs_dns_rcode{{rcode=\"NOERROR\"}} {}\n", self.responses_noerror.load(Ordering::Relaxed));
        s += &format!("omnirs_dns_rcode{{rcode=\"NXDOMAIN\"}} {}\n", self.responses_nxdomain.load(Ordering::Relaxed));
        s += &format!("omnirs_dns_rcode{{rcode=\"SERVFAIL\"}} {}\n", self.responses_servfail.load(Ordering::Relaxed));
        s += &format!("omnirs_dns_rcode{{rcode=\"REFUSED\"}} {}\n", self.responses_refused.load(Ordering::Relaxed));
        s += "# HELP omnirs_dns_cache Cache hits/misses\n# TYPE omnirs_dns_cache counter\n";
        s += &format!("omnirs_dns_cache{{result=\"hit\"}} {}\n", self.cache_hits.load(Ordering::Relaxed));
        s += &format!("omnirs_dns_cache{{result=\"miss\"}} {}\n", self.cache_misses.load(Ordering::Relaxed));
        s += &format!("omnirs_dns_blocked_total {}\n", self.blocked.load(Ordering::Relaxed));
        s += &format!("omnirs_dns_rate_limited_total {}\n", self.rate_limited.load(Ordering::Relaxed));
        s += &format!("omnirs_dns_axfr_total {}\n", self.axfr_transfers.load(Ordering::Relaxed));
        s += &format!("omnirs_dns_ixfr_total {}\n", self.ixfr_transfers.load(Ordering::Relaxed));
        s += &format!("omnirs_dns_rrl_dropped_total {}\n", self.rrl_dropped.load(Ordering::Relaxed));
        s += &format!("omnirs_dns_rrl_slipped_total {}\n", self.rrl_slipped.load(Ordering::Relaxed));
        s += &format!("omnirs_dns_geo_hits_total {}\n", self.geo_hits.load(Ordering::Relaxed));
        s += &format!("omnirs_dns_weighted_selections_total {}\n", self.weighted_selections.load(Ordering::Relaxed));
        s
    }
}

// ═══════════════════════════════════════════════════════════════════════════ §18 CONFIG
#[derive(Clone, Deserialize, Debug, Default)]
pub struct DnsConfig {
    #[serde(default)] pub enabled: bool,
    #[serde(default = "dns_default_addr")] pub addr: String,
    #[serde(default)] pub tcp_addr: String,
    #[serde(default)] pub dot_addr: String,
    #[serde(default = "dns_default_doh_path")] pub doh_path: String,
    #[serde(default)] pub doq_addr: String,
    #[serde(default)] pub zone_files: Vec<String>,
    #[serde(default)] pub zone_dir: Option<String>,
    #[serde(default)] pub forwarders: Vec<String>,
    #[serde(default)] pub conditional: HashMap<String, Vec<String>>,
    #[serde(default)] pub recursive: bool,
    #[serde(default = "dns_default_true")] pub qname_minimisation: bool,
    #[serde(default)] pub allow_query: Vec<String>,
    #[serde(default)] pub allow_axfr: Vec<String>,
    #[serde(default)] pub views: Vec<DnsViewConfig>,
    #[serde(default)] pub rpz_files: Vec<String>,
    #[serde(default)] pub tsig_keys: Vec<DnsTsigConfig>,
    #[serde(default = "dns_default_ttl")] pub default_ttl: u32,
    #[serde(default = "dns_default_cache")] pub cache_entries: usize,
    #[serde(default)] pub cookie_secret: String,
    #[serde(default)] pub serve_stale: bool,
    #[serde(default)] pub rebinding_protection: bool,
    #[serde(default)] pub no_logging: bool,
    #[serde(default = "dns_default_rate")] pub rate_limit: u64,
    #[serde(default)] pub rate_limit_window_secs: u64,
    #[serde(default)] pub local_names: HashMap<String, String>,
    #[serde(default)] pub dnstap_enabled: bool,
    #[serde(default)] pub dnssec_keys: Vec<DnssecKeyConfig>,
    #[serde(default)] pub dnssec_sign_on_load: bool,
    #[serde(default)] pub ixfr_enabled: bool,
    #[serde(default)] pub rrl_enabled: bool,
    #[serde(default = "dns_default_rrl_rate")] pub rrl_rate: u32,
    #[serde(default = "dns_default_rrl_window")] pub rrl_window_secs: u64,
    #[serde(default = "dns_default_rrl_slip")] pub rrl_slip: u32,
    #[serde(default)] pub rrl_whitelist: Vec<String>,
    #[serde(default)] pub geo_db_path: Option<String>,
    #[serde(default)] pub tenants: Vec<TenantConfig>,
    #[serde(default)] pub audit_log_path: Option<String>,
    #[serde(default)] pub audit_log_max_size_mb: u64, #[serde(default)] pub omninet_zone_public: bool,
}
fn dns_default_addr() -> String { "0.0.0.0:53".into() }
fn dns_default_doh_path() -> String { "/dns-query".into() }
fn dns_default_ttl() -> u32 { 3600 }
fn dns_default_cache() -> usize { 50_000 }
fn dns_default_rate() -> u64 { 1000 }
fn dns_default_true() -> bool { true }
fn dns_default_rrl_rate() -> u32 { 5 }
fn dns_default_rrl_window() -> u64 { 1 }
fn dns_default_rrl_slip() -> u32 { 2 }
#[derive(Clone, Deserialize, Debug)]
pub struct DnsViewConfig { pub name: String, #[serde(default)] pub match_cidrs: Vec<String>, #[serde(default)] pub match_tsig: Option<String>, #[serde(default)] pub zone_files: Vec<String> }
#[derive(Clone, Deserialize, Debug)]
pub struct DnsTsigConfig { pub name: String, #[serde(default = "dns_tsig_alg")] pub algorithm: String, pub secret_b64: String }
fn dns_tsig_alg() -> String { "hmac-sha256".into() }
#[derive(Clone, Deserialize, Debug)]
pub struct DnssecKeyConfig { pub zone: String, pub private_pem_path: String, #[serde(default)] pub is_ksk: bool }
#[derive(Clone, Deserialize, Debug)]
pub struct TenantConfig { pub id: String, #[serde(default)] pub display_name: String, #[serde(default)] pub allowed_cidrs: Vec<String>, #[serde(default = "dns_default_max_zones")] pub max_zones: usize, #[serde(default = "dns_default_max_records")] pub max_records_per_zone: usize, #[serde(default)] pub zones: Vec<String> }
fn dns_default_max_zones() -> usize { 100 }
fn dns_default_max_records() -> usize { 10_000 }

// ═══════════════════════════════════════════════════════════════════════════ §24 MULTI-TENANT
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tenant { pub id: String, pub display_name: String, pub allowed_cidrs: Vec<String>, pub max_zones: usize, pub max_records_per_zone: usize }
pub struct TenantRegistry { pub tenants: RwLock<HashMap<String, Arc<Tenant>>>, pub zone_owner: RwLock<HashMap<Name, String>> }
impl TenantRegistry {
    pub fn new() -> Self { Self { tenants: RwLock::new(HashMap::new()), zone_owner: RwLock::new(HashMap::new()) } }
    pub fn add(&self, t: Tenant) { self.tenants.write().unwrap().insert(t.id.clone(), Arc::new(t)); }
    pub fn get(&self, id: &str) -> Option<Arc<Tenant>> { self.tenants.read().unwrap().get(id).cloned() }
    pub fn assign_zone(&self, origin: &Name, tenant_id: &str) -> DnsResult<()> { if !self.tenants.read().unwrap().contains_key(tenant_id) { return Err(DnsError::NotFound); } self.zone_owner.write().unwrap().insert(origin.lower(), tenant_id.to_string()); Ok(()) }
    pub fn owner_of(&self, origin: &Name) -> Option<String> { self.zone_owner.read().unwrap().get(&origin.lower()).cloned() }
    pub fn match_tenant(&self, client_ip: &IpAddr) -> Option<Arc<Tenant>> { for t in self.tenants.read().unwrap().values() { for cidr in &t.allowed_cidrs { if let Ok(c) = Cidr::parse(cidr) { if c.contains(client_ip) { return Some(t.clone()); } } } } None }
}

// ═══════════════════════════════════════════════════════════════════════════ §25 WEIGHTED + GEODNS
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightedBucket { pub records: Vec<Record>, pub weights: Vec<u32> }
impl WeightedBucket {
    pub fn pick_one(&self) -> Option<Record> {
        if self.records.is_empty() { return None; }
        if self.weights.len() != self.records.len() || self.weights.iter().all(|w| *w == 0) { return self.records.first().cloned(); }
        let total: u32 = self.weights.iter().sum();
        if total == 0 { return self.records.first().cloned(); }
        let mut n = rand::random::<u32>() % total;
        for (i, w) in self.weights.iter().enumerate() { if n < *w { return self.records.get(i).cloned(); } n = n.saturating_sub(*w); }
        self.records.last().cloned()
    }
    pub fn pick_n(&self, k: usize) -> Vec<Record> {
        let mut out: Vec<Record> = Vec::new(); let mut used: HashSet<usize> = HashSet::new();
        for _ in 0..k {
            if used.len() == self.records.len() { break; }
            let total: u32 = self.weights.iter().enumerate().filter(|(i, _)| !used.contains(i)).map(|(_, w)| *w).sum();
            if total == 0 { break; }
            let mut n = rand::random::<u32>() % total;
            for (i, w) in self.weights.iter().enumerate() { if used.contains(&i) { continue; } if n < *w { used.insert(i); out.push(self.records[i].clone()); break; } n = n.saturating_sub(*w); }
        }
        out
    }
}
#[derive(Default)]
pub struct GeoDb { pub prefix_map: Vec<(u32, u8, String)> }
impl GeoDb {
    pub fn load_country_csv(&mut self, path: &Path) -> DnsResult<usize> {
        let content = std::fs::read_to_string(path)?; let mut n = 0;
        for line in content.lines() {
            let line = line.trim(); if line.is_empty() || line.starts_with('#') { continue; }
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() < 3 { continue; }
            let (net, country) = (parts[0].trim(), parts[2].trim().to_string());
            if let Some((ip_str, len_str)) = net.split_once('/') {
                if let (Ok(ip), Ok(len)) = (ip_str.parse::<Ipv4Addr>(), len_str.parse::<u8>()) { self.prefix_map.push((u32::from(ip), len, country)); n += 1; }
            }
        }
        self.prefix_map.sort_by(|a, b| b.1.cmp(&a.1));
        Ok(n)
    }
    pub fn country_of(&self, ip: &IpAddr) -> Option<&str> {
        match ip {
            IpAddr::V4(a) => { let v = u32::from(*a); for (prefix, len, country) in &self.prefix_map { let mask = if *len == 0 { 0 } else { u32::MAX << (32 - *len) }; if (v & mask) == (*prefix & mask) { return Some(country); } } None }
            IpAddr::V6(_) => None,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeoRule { pub by_country: HashMap<String, WeightedBucket>, pub default: WeightedBucket }

// ═══════════════════════════════════════════════════════════════════════════ §26 DNSTAP
#[derive(Clone, Debug, Serialize)]
pub struct DnstapEvent { pub ts_us: u64, pub client: String, pub server: String, pub qname: String, pub qtype: String, pub rcode: u8, pub latency_us: u64, pub transport: &'static str, pub query_size: u32, pub resp_size: u32 }
pub struct DnstapWriter { pub path: PathBuf, pub file: Mutex<std::fs::File>, pub size: AtomicU64, pub max_size: u64 }
impl DnstapWriter {
    pub fn new(path: PathBuf, max_size_mb: u64) -> std::io::Result<Self> { let f = std::fs::OpenOptions::new().create(true).append(true).open(&path)?; let sz = f.metadata()?.len(); Ok(Self { path, file: Mutex::new(f), size: AtomicU64::new(sz), max_size: max_size_mb * 1024 * 1024 }) }
    pub fn write(&self, ev: &DnstapEvent) {
        let bytes = match serde_json::to_vec(ev) { Ok(b) => b, Err(_) => return };
        if self.size.load(Ordering::Relaxed) + bytes.len() as u64 > self.max_size { if let Ok(f) = std::fs::OpenOptions::new().write(true).truncate(true).open(&self.path) { *self.file.lock().unwrap() = f; self.size.store(0, Ordering::Relaxed); } }
        let mut framed = Vec::with_capacity(4 + bytes.len()); framed.extend_from_slice(&(bytes.len() as u32).to_be_bytes()); framed.extend_from_slice(&bytes);
        let mut f = self.file.lock().unwrap(); use std::io::Write; let _ = f.write_all(&framed); self.size.fetch_add(framed.len() as u64, Ordering::Relaxed);
    }
}

// ═══════════════════════════════════════════════════════════════════════════ §27 AUDIT
#[derive(Clone, Debug, Serialize)]
pub struct AuditEvent { pub ts: i64, pub actor_ip: String, pub actor_token_prefix: String, pub action: String, pub target: String, pub result: String, pub details: serde_json::Value }
pub struct AuditLog { pub file: Mutex<std::fs::File>, pub size: AtomicU64, pub max_size: u64 }
impl AuditLog {
    pub fn new(path: PathBuf, max_size_mb: u64) -> std::io::Result<Self> { let f = std::fs::OpenOptions::new().create(true).append(true).open(&path)?; let sz = f.metadata()?.len(); Ok(Self { file: Mutex::new(f), size: AtomicU64::new(sz), max_size: max_size_mb * 1024 * 1024 }) }
    pub fn append(&self, ev: &AuditEvent) {
        let line = match serde_json::to_vec(ev) { Ok(mut b) => { b.push(b'\n'); b }, Err(_) => return };
        if self.size.load(Ordering::Relaxed) + line.len() as u64 > self.max_size { self.size.store(0, Ordering::Relaxed); }
        let mut f = self.file.lock().unwrap(); use std::io::Write;
        if f.write_all(&line).is_ok() { self.size.fetch_add(line.len() as u64, Ordering::Relaxed); }
    }
}

// ═══════════════════════════════════════════════════════════════════════════ §28 RRL
#[derive(Default)]
pub struct RrlBucket { pub count: u32, pub slipped: u32, pub window_start: Option<Instant> }
pub enum RrlAction { Pass, Drop, Slip }
pub struct Rrl { pub buckets: Mutex<HashMap<String, RrlBucket>>, pub rate: u32, pub window_secs: u64, pub slip: u32, pub whitelist: Vec<Cidr>, pub ipv4_prefix: u8, pub ipv6_prefix: u8 }
impl Rrl {
    pub fn new(rate: u32, window_secs: u64, slip: u32) -> Self { Self { buckets: Mutex::new(HashMap::new()), rate, window_secs, slip, whitelist: Vec::new(), ipv4_prefix: 24, ipv6_prefix: 56 } }
    fn group_key(&self, ip: &IpAddr, qname: &Name, rcode: u8) -> String {
        let prefix = match ip {
            IpAddr::V4(a) => { let mask = if self.ipv4_prefix == 0 { 0 } else { u32::MAX << (32 - self.ipv4_prefix) }; format!("{}/{}", Ipv4Addr::from(u32::from(*a) & mask), self.ipv4_prefix) }
            IpAddr::V6(_) => { let s = ip.to_string(); let parts: Vec<&str> = s.split(':').take(4).collect(); format!("{}::/{}", parts.join(":"), self.ipv6_prefix) }
        };
        format!("{prefix}|{}|{}|{}", qname.to_string().to_lowercase(), rcode, self.rate)
    }
    pub fn check(&self, ip: &IpAddr, qname: &Name, rcode: u8) -> RrlAction {
        for c in &self.whitelist { if c.contains(ip) { return RrlAction::Pass; } }
        let key = self.group_key(ip, qname, rcode);
        let mut g = self.buckets.lock().unwrap();
        let b = g.entry(key).or_default();
        let now = Instant::now();
        if b.window_start.map_or(true, |t| now.duration_since(t).as_secs() >= self.window_secs) { b.window_start = Some(now); b.count = 0; b.slipped = 0; }
        b.count = b.count.saturating_add(1);
        if b.count <= self.rate { return RrlAction::Pass; }
        if self.slip > 0 { if b.slipped % self.slip == 0 { b.slipped = b.slipped.saturating_add(1); return RrlAction::Slip; } b.slipped = b.slipped.saturating_add(1); }
        RrlAction::Drop
    }
    pub fn sweep(&self) { let mut g = self.buckets.lock().unwrap(); let now = Instant::now(); g.retain(|_, b| b.window_start.map_or(false, |t| now.duration_since(t).as_secs() < self.window_secs * 2)); }
}

// ═══════════════════════════════════════════════════════════════════════════ §19 SERVER
pub struct DnsServer {
    pub config: DnsConfig, pub auth: Arc<AuthResolver>, pub recursive: Arc<RecursiveResolver>,
    pub views: Arc<RwLock<ViewRegistry>>, pub rpz: Arc<RpzRegistry>, pub tsig: Arc<TsigRegistry>,
    pub dnssec: Arc<DnssecStore>, pub metrics: Arc<DnsMetrics>, pub cache: Arc<DnsCache>,
    pub rate_limit: Arc<Mutex<HashMap<IpAddr, (Instant, u32)>>>,
    pub cookie_secret: Vec<u8>, pub started_at: Instant,
    pub tenants: Option<Arc<TenantRegistry>>, pub geo_db: Option<Arc<GeoDb>>, pub rrl: Option<Arc<Rrl>>,
    pub dnstap: Option<Arc<DnstapWriter>>, pub audit: Option<Arc<AuditLog>>,
    pub local_names: Arc<RwLock<HashMap<String, String>>>,
    pub active_connections: Arc<AtomicU64>, }
impl DnsServer {
    pub fn from_config(config: DnsConfig) -> DnsResult<Self> {
        let auth = Arc::new(AuthResolver::new());
        for path in &config.zone_files { load_zone_file(&auth, Path::new(path))?; }
        if let Some(dir) = &config.zone_dir { if let Ok(entries) = std::fs::read_dir(dir) { for e in entries.flatten() { if e.path().extension().map(|x| x == "zone").unwrap_or(false) { let _ = load_zone_file(&auth, &e.path()); } } } }
        let mut rec = RecursiveResolver::new();
        for f in &config.forwarders { if let Ok(addr) = f.parse() { rec.forwarders.push(addr); } }
        for (dom, fws) in &config.conditional { if let Ok(name) = Name::from_str(dom) { let addrs: Vec<SocketAddr> = fws.iter().filter_map(|s| s.parse().ok()).collect(); rec.conditional.insert(name, addrs); } }
        rec.qname_minimisation = config.qname_minimisation;
        let mut views = ViewRegistry::new();
        for v in &config.views { let cidrs: Vec<Cidr> = v.match_cidrs.iter().filter_map(|s| Cidr::parse(s).ok()).collect(); views.add(View { name: v.name.clone(), match_cidrs: cidrs, match_tsig: v.match_tsig.clone(), zones: v.zone_files.iter().map(PathBuf::from).collect() }); }
        let rpz = Arc::new(RpzRegistry::new());
        for f in &config.rpz_files { let _ = rpz.load_hostfile(f, Path::new(f)); }
        let tsig = Arc::new(TsigRegistry::new());
        for k in &config.tsig_keys { if let Ok(secret) = base64_decode(&k.secret_b64) { tsig.add(TsigKey { name: k.name.clone(), algorithm: k.algorithm.clone(), secret }); } }
        let dnssec = Arc::new(DnssecStore::new());
        for kc in &config.dnssec_keys {
            if let Ok(zone_name) = Name::from_str(&kc.zone) {
                if let Ok(pem) = std::fs::read_to_string(&kc.private_pem_path) {
                    use p256::pkcs8::DecodePrivateKey;
                    if let Ok(sk) = p256::ecdsa::SigningKey::from_pkcs8_pem(&pem) {
                        let vk = sk.verifying_key(); let point = vk.to_encoded_point(false); let raw = point.as_bytes();
                        let pk = raw[1..].to_vec();
                        let flags = if kc.is_ksk { DNSKEY_FLAG_ZONE_KEY | DNSKEY_FLAG_SECURE_ENTRY } else { DNSKEY_FLAG_ZONE_KEY };
                        let mut rdata = Vec::with_capacity(68); rdata.extend_from_slice(&flags.to_be_bytes()); rdata.push(3); rdata.push(DNSSEC_ALG_ECDSAP256_SHA256); rdata.extend_from_slice(&pk);
                        let key_tag = compute_key_tag(&rdata);
                        use base64::{engine::general_purpose::STANDARD, Engine};
                        dnssec.add_key(zone_name, DnssecKey { key_tag, algorithm: DNSSEC_ALG_ECDSAP256_SHA256, flags, is_ksk: kc.is_ksk, private_pem: Some(pem), public_b64: STANDARD.encode(&rdata) });
                    }
                }
            }
        }
        if config.dnssec_sign_on_load { let zones_snap: Vec<Arc<RwLock<Zone>>> = auth.zones.read().unwrap().values().cloned().collect(); for z in zones_snap { if let Ok(mut zone) = z.write() { let _ = dnssec.sign_zone(&mut zone); } } }
        let mut rrl_opt: Option<Arc<Rrl>> = None;
        if config.rrl_enabled { let mut r = Rrl::new(config.rrl_rate, config.rrl_window_secs, config.rrl_slip); for w in &config.rrl_whitelist { if let Ok(c) = Cidr::parse(w) { r.whitelist.push(c); } } rrl_opt = Some(Arc::new(r)); }
        let geo_db = config.geo_db_path.as_ref().and_then(|p| { let mut g = GeoDb::default(); g.load_country_csv(Path::new(p)).ok().map(|_| Arc::new(g)) });
        let tenants = if config.tenants.is_empty() { None } else { let reg = TenantRegistry::new(); for tc in &config.tenants { reg.add(Tenant { id: tc.id.clone(), display_name: tc.display_name.clone(), allowed_cidrs: tc.allowed_cidrs.clone(), max_zones: tc.max_zones, max_records_per_zone: tc.max_records_per_zone }); for z in &tc.zones { if let Ok(n) = Name::from_str(z) { let _ = reg.assign_zone(&n, &tc.id); } } } Some(Arc::new(reg)) };
        let dnstap: Option<Arc<DnstapWriter>> = None;
        let audit = config.audit_log_path.as_ref().and_then(|p| AuditLog::new(PathBuf::from(p), config.audit_log_max_size_mb.max(10)).ok().map(Arc::new));
        let cookie_secret = if config.cookie_secret.is_empty() { rand_bytes(32) } else { config.cookie_secret.as_bytes().to_vec() };
        let local_names_arc = Arc::new(RwLock::new(config.local_names.clone()));
        Ok(Self { config: config.clone(), auth, recursive: Arc::new(rec), views: Arc::new(RwLock::new(views)), rpz, tsig, dnssec, metrics: Arc::new(DnsMetrics::default()), cache: Arc::new(DnsCache::new(config.cache_entries)), rate_limit: Arc::new(Mutex::new(HashMap::new())), cookie_secret, started_at: Instant::now(), tenants, geo_db, rrl: rrl_opt, dnstap, audit, local_names: local_names_arc, active_connections: Arc::new(AtomicU64::new(0)) })
    }
    pub fn set_local_name(&self, host: String, ip: String) { self.local_names.write().unwrap().insert(host, ip); }
    pub fn del_local_name(&self, host: &str) -> bool { self.local_names.write().unwrap().remove(host).is_some() }
    pub fn list_local_names(&self) -> HashMap<String, String> { self.local_names.read().unwrap().clone() }
pub async fn handle(&self, req: Message, client_ip: IpAddr, raw: &[u8], transport: &'static str) -> Message { let start = Instant::now(); self.metrics.total_queries.fetch_add(1, Ordering::Relaxed); let mut resp = Message { id: req.id, flags: 0x8000 | (req.flags & 0x0100), questions: req.questions.clone(), ..Default::default() }; resp.set_ra(); if req.questions.is_empty() { resp.set_rcode(rcode::FORMERR); return resp; } if self.config.rate_limit > 0 { let mut rl = self.rate_limit.lock().unwrap(); let e = rl.entry(client_ip).or_insert((Instant::now(), 0)); if e.0.elapsed().as_secs() >= self.config.rate_limit_window_secs.max(1) { *e = (Instant::now(), 0); } e.1 += 1; if e.1 as u64 > self.config.rate_limit { self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed); resp.set_rcode(rcode::REFUSED); return resp; } } let tsig_key = self.tsig.verify(&req, raw).ok().flatten(); let q = req.questions[0].clone();
    if self.rpz.blocked(&q.name) { self.metrics.blocked.fetch_add(1, Ordering::Relaxed); resp.set_rcode(rcode::NXDOMAIN); return resp; }
    let local_ip_opt = { self.local_names.read().unwrap().get(&q.name.to_string().trim_end_matches('.').to_string()).cloned() };
    if let Some(ip) = local_ip_opt { if let Ok(a) = ip.parse::<Ipv4Addr>() { resp.answers.push(Record { name: q.name.clone(), rtype: rtype::A, rclass: rclass::IN, ttl: 60, rdata: RData::A(a) }); return resp; } }
    if q.qtype == rtype::AXFR || q.qtype == rtype::IXFR { resp.set_rcode(rcode::NOTIMP); return resp; }
    let _view = { let v = self.views.read().unwrap(); v.select(&client_ip, tsig_key.as_deref()).cloned() };
    if let Some(tenants) = self.tenants.as_ref() { if let Some(zone_arc) = self.auth.find_zone(&q.name) { let origin = { let g = zone_arc.read().unwrap(); g.origin.clone() }; if let Some(owner) = tenants.owner_of(&origin) { let tenant = tenants.match_tenant(&client_ip); let ok = tenant.as_ref().map(|t| t.id == owner).unwrap_or(false); if !ok { resp.set_rcode(rcode::REFUSED); return resp; } } } }
    let auth_resp = self.auth.query(&q.name, q.qtype);
    if auth_resp.aa && (auth_resp.rcode != rcode::REFUSED || !auth_resp.answers.is_empty()) {
        resp.answers = auth_resp.answers;
        if self.config.rebinding_protection { let client_private = is_private_ip(&client_ip); resp.answers = rebinding_protected(&resp.answers, client_private); }
        if let Some(zone_arc) = self.auth.find_zone(&q.name) {
            let lname = q.name.lower(); let z = zone_arc.read().unwrap();
            let country = self.geo_db.as_ref().and_then(|g| g.country_of(&client_ip).map(|s| s.to_string()));
            if let Some(geo_map) = z.geo_rules.get(&lname).and_then(|m| m.get(&q.qtype)) {
                let bucket = match &country { Some(c) => geo_map.by_country.get(c).unwrap_or(&geo_map.default), None => &geo_map.default };
                if let Some(picked) = bucket.pick_one() { resp.answers = vec![picked]; self.metrics.geo_hits.fetch_add(1, Ordering::Relaxed); }
            } else if let Some(weights) = z.weights.get(&lname).and_then(|m| m.get(&q.qtype)) {
                if !resp.answers.is_empty() { let wb = WeightedBucket { records: resp.answers.clone(), weights: weights.clone() }; if let Some(p) = wb.pick_one() { resp.answers = vec![p]; self.metrics.weighted_selections.fetch_add(1, Ordering::Relaxed); } }
            }
        }
        resp.authority = auth_resp.authority; resp.set_aa(); resp.set_rcode(auth_resp.rcode);
        self.record_rcode(&resp); handle_cookie(&mut resp, &self.cookie_secret); self.apply_rrl(&mut resp, &client_ip, &q.name); self.emit_dnstap(&resp, &client_ip, &q, transport, raw.len(), start);
        return resp;
    }
    if self.config.recursive || !self.recursive.forwarders.is_empty() {
        self.metrics.recursive_queries.fetch_add(1, Ordering::Relaxed);
        if let Ok((records, rc)) = self.recursive.resolve(&q.name, q.qtype).await {
            resp.answers = records; resp.set_rcode(rc);
            self.record_rcode(&resp); handle_cookie(&mut resp, &self.cookie_secret); self.apply_rrl(&mut resp, &client_ip, &q.name); self.emit_dnstap(&resp, &client_ip, &q, transport, raw.len(), start);
            return resp;
        }
    }
    resp.set_rcode(rcode::NXDOMAIN); self.record_rcode(&resp); handle_cookie(&mut resp, &self.cookie_secret); self.apply_rrl(&mut resp, &client_ip, &q.name); self.emit_dnstap(&resp, &client_ip, &q, transport, raw.len(), start);
    resp
    }
    fn record_rcode(&self, resp: &Message) {
        match resp.rcode() {
            rcode::NOERROR  => { self.metrics.responses_noerror.fetch_add(1, Ordering::Relaxed); }
            rcode::NXDOMAIN => { self.metrics.responses_nxdomain.fetch_add(1, Ordering::Relaxed); }
            rcode::SERVFAIL => { self.metrics.responses_servfail.fetch_add(1, Ordering::Relaxed); }
            rcode::REFUSED  => { self.metrics.responses_refused.fetch_add(1, Ordering::Relaxed); }
            _ => {}
        }
    }

    fn apply_rrl(&self, resp: &mut Message, client_ip: &IpAddr, qname: &Name) {
        let rrl = match &self.rrl {
            Some(r) => r,
            None => return,
        };
        match rrl.check(client_ip, qname, resp.rcode()) {
            RrlAction::Pass => {}
            RrlAction::Slip => {
                resp.flags |= 0x0200;
                resp.answers.clear();
                resp.authority.clear();
                self.metrics.rrl_slipped.fetch_add(1, Ordering::Relaxed);
            }
            RrlAction::Drop => {
                resp.answers.clear();
                resp.authority.clear();
                resp.set_rcode(rcode::REFUSED);
                self.metrics.rrl_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn emit_dnstap(&self, resp: &Message, client_ip: &IpAddr, q: &Question, transport: &'static str, query_size: usize, start: Instant) {
        if let Some(w) = &self.dnstap {
            w.write(&DnstapEvent { ts_us: now() as u64 * 1_000_000, client: client_ip.to_string(), server: "0.0.0.0".into(), qname: q.name.to_string(), qtype: rtype::name(q.qtype).to_string(), rcode: resp.rcode(), latency_us: start.elapsed().as_micros() as u64, transport, query_size: query_size as u32, resp_size: resp.encode(65535).map(|b| b.len() as u32).unwrap_or(0) });
        }
    }
pub async fn run_udp(self: Arc<Self>, addr: String) -> DnsResult<()> {
    let sock = Arc::new(UdpSocket::bind(&addr).await?);
    println!("[DNS] UDP listener on {}", addr);
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await { Ok(x) => x, Err(_) => continue };
        let pkt = buf[..n].to_vec();
        let me = self.clone();
        let sock_clone = sock.clone();
        tokio::spawn(async move {
            let req = match Message::decode(&pkt) { Ok(m) => m, Err(_) => return };
            let size = req.edns_udp_size() as usize;
            let resp = me.handle(req, peer.ip(), &pkt, "udp").await;
            if let Ok(out) = resp.encode(size.max(512)) {
                if out.len() > size {
                    let tc = Message { id: resp.id, flags: resp.flags | 0x0200, questions: resp.questions, ..Default::default() };
                    if let Ok(o) = tc.encode(size.max(512)) { let _ = sock_clone.send_to(&o, peer).await; return; }
                }
                let _ = sock_clone.send_to(&out, peer).await;
            }
        });
    }
}
    pub async fn run_tcp(self: Arc<Self>, addr: String) -> DnsResult<()> {
        let listener = TcpListener::bind(&addr).await?; println!("[DNS] TCP listener on {}", addr);
        loop {
            let (mut stream, peer) = match listener.accept().await { Ok(x) => x, Err(_) => continue };
            let me = self.clone();
            tokio::spawn(async move {
                let _guard = ActiveConnGuard::new(me.active_connections.clone());
                let mut lb = [0u8; 2];
                if stream.read_exact(&mut lb).await.is_err() { return; }
                let len = u16::from_be_bytes(lb) as usize;
                let mut pkt = vec![0u8; len];
                if stream.read_exact(&mut pkt).await.is_err() { return; }
                let req = match Message::decode(&pkt) { Ok(m) => m, Err(_) => return };
                let q = match req.questions.get(0).cloned() { Some(q) => q, None => return };
                if q.qtype == rtype::AXFR || q.qtype == rtype::IXFR {
                    let zone = match me.auth.find_zone(&q.name) { Some(z) => z, None => { let r = me.handle(req, peer.ip(), &pkt, "tcp").await; if let Ok(b) = r.encode(65535) { let _ = stream.write_all(&(b.len() as u16).to_be_bytes()).await; let _ = stream.write_all(&b).await; } return; } };
                    if q.qtype == rtype::IXFR {
                        let client_serial = req.authority.iter().find(|r| r.rtype == rtype::SOA).and_then(|r| if let RData::Soa { serial, .. } = &r.rdata { Some(*serial) } else { None }).unwrap_or(0);
                        let records: Vec<Record> = { let g = zone.read().unwrap(); match g.build_ixfr(client_serial) { Ok(rs) => rs, Err(_) => g.all_records() } };
                        for chunk in records.chunks(50) { let out = Message { id: req.id, flags: 0x8400, questions: vec![], answers: chunk.to_vec(), ..Default::default() }; if let Ok(b) = out.encode(65535) { let _ = stream.write_all(&(b.len() as u16).to_be_bytes()).await; let _ = stream.write_all(&b).await; } }
                        me.metrics.ixfr_transfers.fetch_add(1, Ordering::Relaxed); return;
                    }
                  }
                let resp = me.handle(req, peer.ip(), &pkt, "tcp").await;
                if let Ok(b) = resp.encode(65535) { let _ = stream.write_all(&(b.len() as u16).to_be_bytes()).await; let _ = stream.write_all(&b).await; }
            });
        }
    }
    pub async fn serve_dns_on_stream<S>(self: Arc<Self>, mut stream: S, peer: SocketAddr, transport: &'static str) -> DnsResult<()>
    where S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {
        let _guard = ActiveConnGuard::new(self.active_connections.clone());
        let mut lb = [0u8; 2]; stream.read_exact(&mut lb).await?;
        let len = u16::from_be_bytes(lb) as usize;
        if len == 0 || len > 65535 { return Err(DnsError::Format("bad length".into())); }
        let mut pkt = vec![0u8; len]; stream.read_exact(&mut pkt).await?;
        let req = Message::decode(&pkt)?;
        let resp = self.handle(req, peer.ip(), &pkt, transport).await;
        let out = resp.encode(65535)?;
        stream.write_all(&(out.len() as u16).to_be_bytes()).await?;
        stream.write_all(&out).await?; stream.flush().await?;
        Ok(())
    }
    pub async fn run_dot_tls(self: Arc<Self>, listener: TcpListener, tls_acceptor: tokio_rustls::TlsAcceptor) -> DnsResult<()> {
        println!("[DNS] DoT listener on {:?}", listener.local_addr());
        loop {
            let (stream, peer) = match listener.accept().await { Ok(x) => x, Err(_) => continue };
            let me = self.clone(); let acc = tls_acceptor.clone();
            tokio::spawn(async move { match acc.accept(stream).await { Ok(tls) => { let _ = me.serve_dns_on_stream(tls, peer, "tls").await; } Err(e) => eprintln!("[DNS] DoT TLS handshake failed: {e}") } });
        }
    }
    pub async fn serve_doq_stream(self: Arc<Self>, mut send: quinn::SendStream, mut recv: quinn::RecvStream, peer: SocketAddr) -> DnsResult<()> {
        let _guard = ActiveConnGuard::new(self.active_connections.clone());
        let mut lb = [0u8; 2]; recv.read_exact(&mut lb).await.map_err(|e| DnsError::Format(format!("doq: {e}")))?;
        let len = u16::from_be_bytes(lb) as usize;
        if len == 0 || len > 65535 { return Err(DnsError::Format("doq bad length".into())); }
        let mut pkt = vec![0u8; len]; recv.read_exact(&mut pkt).await.map_err(|e| DnsError::Format(format!("doq: {e}")))?;
        let req = Message::decode(&pkt)?;
        let resp = self.handle(req, peer.ip(), &pkt, "quic").await;
        let out = resp.encode(65535)?;
        let mut framed = Vec::with_capacity(2 + out.len()); framed.extend_from_slice(&(out.len() as u16).to_be_bytes()); framed.extend_from_slice(&out);
        send.write_all(&framed).await.map_err(|e| DnsError::Format(format!("doq: {e}")))?;
        send.finish().map_err(|e| DnsError::Format(format!("doq: {e}")))?;
        Ok(())
    }
 
    pub async fn handle_doh_body(&self, body: Vec<u8>, client_ip: IpAddr) -> DnsResult<Vec<u8>> { let req = Message::decode(&body)?; let resp = self.handle(req, client_ip, &body, "h2").await; resp.encode(65535) }
    pub async fn handle_doh3_request(&self, body: Vec<u8>, client_ip: IpAddr) -> DnsResult<Vec<u8>> { let req = Message::decode(&body)?; let resp = self.handle(req, client_ip, &body, "h3").await; resp.encode(65535) }
    pub fn metrics_text(&self) -> String { self.metrics.to_prometheus() }
    pub fn local_names_list(&self) -> HashMap<String, String> { self.local_names.read().unwrap().clone() } }

/// Запускает DNS-over-TLS (RFC 7858) листенер на `addr`.
/// `resolver` — любой `ResolvesServerCert` (в `main.rs` передаётся `Arc<SslManager>`).
pub async fn start_dot_server(
    dns: Arc<DnsServer>,
    resolver: Arc<dyn ResolvesServerCert>,
    addr: &str,
) -> DnsResult<()> {
    use tokio_rustls::TlsAcceptor;
    let sock: SocketAddr = addr.parse()
        .map_err(|e| DnsError::ConfigError(format!("bad DoT addr {addr:?}: {e}")))?;
    let listener = TcpListener::bind(sock).await?;
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"dot".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    // run_dot_tls сам напечатает фактический bound-адрес — не дублируем.
    dns.run_dot_tls(listener, acceptor).await
}

/// Запускает DNS-over-QUIC (RFC 9250) листенер на `addr`.
pub async fn start_doq_server(
    dns: Arc<DnsServer>,
    resolver: Arc<dyn ResolvesServerCert>,
    addr: &str,
) -> DnsResult<()> {
    let sock: SocketAddr = addr.parse()
        .map_err(|e| DnsError::ConfigError(format!("bad DoQ addr {addr:?}: {e}")))?;
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    tls_config.alpn_protocols = vec![b"doq".to_vec()];
    let quic_config = QuicServerConfig::try_from(tls_config)
        .map_err(|e| DnsError::ConfigError(format!("doq quic config: {e}")))?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
    let endpoint = quinn::Endpoint::server(server_config, sock)?;
    println!("[DNS] DoQ listener on {}", sock);
    while let Some(incoming) = endpoint.accept().await {
        let dns_clone = dns.clone();
        tokio::spawn(async move {
            if let Ok(conn) = incoming.await {
                let peer = conn.remote_address();
                loop {
                    match conn.accept_bi().await {
                        Ok((send, recv)) => {
                            let dns_inner = dns_clone.clone();
                            tokio::spawn(async move {
                                let _ = dns_inner.serve_doq_stream(send, recv, peer).await;
                            });
                        }
                        Err(_) => break,
                    }
                }
            }
        });
    }
    Ok(())
}


fn load_zone_file(auth: &Arc<AuthResolver>, path: &Path) -> DnsResult<()> {
    let content = std::fs::read_to_string(path)?;
    let origin = path.file_stem().and_then(|s| s.to_str()).map(|s| s.trim_end_matches(".zone").trim_end_matches(".db")).and_then(|s| Name::from_str(s).ok()).unwrap_or_else(Name::root);
    let mut parser = ZoneParser::new(origin); let zone = parser.parse_str(&content)?; auth.add_zone(zone); Ok(())
}
fn base64_decode(s: &str) -> Result<Vec<u8>, ()> { use base64::{engine::general_purpose::STANDARD, Engine}; STANDARD.decode(s).map_err(|_| ()) }
fn rand_bytes(n: usize) -> Vec<u8> { let mut v = vec![0u8; n]; for x in &mut v { *x = rand::random(); } v }

// ═══════════════════════════════════════════════════════════════════════════ §20 ADMIN
pub fn admin_list_zones(auth: &AuthResolver) -> Vec<serde_json::Value> {
    let z = auth.zones.read().unwrap();
    z.values().map(|a| { let g = a.read().unwrap(); json!({ "origin": g.origin.to_string(), "serial": g.serial, "records": g.records.values().map(|e| e.values().map(|v| v.len()).sum::<usize>()).sum::<usize>() }) }).collect()
}
pub fn admin_lookup(auth: &AuthResolver, qname: &str, qtype: &str) -> serde_json::Value {
    let name = match Name::from_str(qname) { Ok(n) => n, Err(e) => return json!({"error": e.to_string()}) };
    let rtype_v = match parse_rtype(qtype) { Ok(t) => t, Err(e) => return json!({"error": e.to_string()}) };
    let resp = auth.query(&name, rtype_v);
    json!({ "aa": resp.aa, "rcode": resp.rcode, "answers": resp.answers.iter().map(|r| json!({"name": r.name.to_string(), "type": rtype::name(r.rtype), "ttl": r.ttl, "rdata": r.rdata_str()})).collect::<Vec<_>>(), "authority": resp.authority.iter().map(|r| json!({"name": r.name.to_string(), "type": rtype::name(r.rtype), "ttl": r.ttl})).collect::<Vec<_>>() })
}
pub fn admin_add_record(auth: &AuthResolver, origin: &str, name: &str, rtype_s: &str, value: &str, ttl: u32) -> DnsResult<()> {
    let origin_n = Name::from_str(origin)?;
    let record_name = if name == "@" { origin_n.clone() } else if name.ends_with('.') { Name::from_str(name)? } else { Name::from_str(&format!("{}.{}", name, origin.trim_end_matches('.')))? };
    let rtype_v = parse_rtype(rtype_s)?;
    let rd = match rtype_v {
        rtype::A => RData::A(value.parse().map_err(|_| DnsError::Format("bad A".into()))?),
        rtype::AAAA => RData::Aaaa(value.parse().map_err(|_| DnsError::Format("bad AAAA".into()))?),
        rtype::CNAME => RData::Cname(Name::from_str(value)?),
        rtype::TXT => RData::Txt(vec![value.as_bytes().to_vec()]),
        rtype::MX => { let parts: Vec<&str> = value.split_whitespace().collect(); RData::Mx { pref: parts.get(0).and_then(|s| s.parse().ok()).unwrap_or(10), exchange: Name::from_str(parts.get(1).copied().unwrap_or("."))? } }
        _ => return Err(DnsError::Unsupported(format!("add for type {}", rtype_s))),
    };
    let zone_arc = auth.find_zone(&origin_n).ok_or(DnsError::NotFound)?;
    let mut z = zone_arc.write().unwrap();
    z.insert(Record { name: record_name, rtype: rtype_v, rclass: rclass::IN, ttl, rdata: rd });
    z.serial += 1;
    Ok(())
}
pub fn admin_remove_record(auth: &AuthResolver, origin: &str, name: &str, rtype_s: &str) -> DnsResult<bool> {
    let origin_n = Name::from_str(origin)?;
    let record_name = if name == "@" { origin_n.clone() } else { Name::from_str(&format!("{}.{}", name, origin.trim_end_matches('.')))? };
    let rtype_v = parse_rtype(rtype_s)?;
    let zone_arc = auth.find_zone(&origin_n).ok_or(DnsError::NotFound)?;
    let mut z = zone_arc.write().unwrap();
    let removed = z.remove(&record_name, rtype_v);
    if removed { z.serial += 1; }
    Ok(removed)
}
pub fn admin_import_zone(auth: &Arc<AuthResolver>, path: &Path) -> DnsResult<()> { load_zone_file(auth, path) }
pub fn admin_export_zone(auth: &AuthResolver, origin: &str) -> DnsResult<String> {
    let origin_n = Name::from_str(origin)?;
    let zone_arc = auth.find_zone(&origin_n).ok_or(DnsError::NotFound)?;
    let z = zone_arc.read().unwrap();
    let mut out = String::new();
    out.push_str(&format!("$ORIGIN {}\n$TTL {}\n", z.origin.to_string(), z.ttl));
    for (_, entry) in &z.records { for (_, bucket) in entry { for r in bucket { out.push_str(&format!("{} {} IN {} {}\n", r.name.to_string(), r.ttl, rtype::name(r.rtype), r.rdata_str())); } } }
    Ok(out)
}

// ═══════════════════════════════════════════════════════════════════════════ §21 COMPAT (main.rs)
pub type CertEntry = (Vec<String>, Arc<CertifiedKey>);
pub fn normalize_host(host: Option<&str>) -> Option<String> { let h = host?.trim(); let h = h.trim_start_matches('[').split(']').next().unwrap_or(h); let h = h.split(':').next().unwrap_or(h); let h = h.to_ascii_lowercase(); if h.is_empty() { None } else { Some(h) } }
pub fn normalize_dns_name(name: &str) -> String { name.trim().trim_end_matches('.').to_ascii_lowercase() }
pub fn is_valid_domain(domain: &str) -> bool { if domain.is_empty() || domain.contains('/') || domain.contains(' ') || !domain.contains('.') { return false; } if domain.starts_with('.') || domain.ends_with('.') { return false; } true }
pub fn is_dns_sni(sni: &str) -> bool { !sni.starts_with('[') && sni.parse::<IpAddr>().is_err() }
pub fn select_virtual_host<'a>(host: Option<&str>, vhosts: &'a HashMap<String, PathBuf>, default_root: &'a Path) -> &'a Path { if let Some(h) = normalize_host(host) { if let Some(p) = vhosts.get(&h) { return p.as_path(); } } default_root }
pub fn extract_sans(cert_pem: &[u8]) -> Vec<String> { let mut out = Vec::new(); if let Ok((_, pem)) = x509_parser::pem::parse_x509_pem(cert_pem) { if let Ok(cert) = pem.parse_x509() { for ext in cert.extensions() { if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() { for name in &san.general_names { match name { x509_parser::extensions::GeneralName::DNSName(d) => out.push(d.to_string()), x509_parser::extensions::GeneralName::IPAddress(b) if b.len() == 4 => { let mut a = [0u8; 4]; a.copy_from_slice(b); out.push(Ipv4Addr::from(a).to_string()); }, x509_parser::extensions::GeneralName::IPAddress(b) if b.len() == 16 => { let mut a = [0u8; 16]; a.copy_from_slice(b); out.push(Ipv6Addr::from(a).to_string()); }, _ => {} } } } } } } out }
#[derive(Debug, Default)]
pub struct CertStore { pub certs: RwLock<Vec<CertEntry>>, pub default_cert: RwLock<Option<Arc<CertifiedKey>>> }
impl CertStore {
    pub fn new() -> Self { Self::default() }
    pub fn len(&self) -> usize { self.certs.read().unwrap().len() }
    pub fn is_empty(&self) -> bool { self.certs.read().unwrap().is_empty() && self.default_cert.read().unwrap().is_none() }
    pub fn find_by_sni(&self, sni: &str) -> Option<Arc<CertifiedKey>> { let target = normalize_dns_name(sni); let guard = self.certs.read().unwrap(); for (sans, ck) in guard.iter() { if sans.iter().any(|s| normalize_dns_name(s) == target) { return Some(ck.clone()); } } None }
    pub fn get_default(&self) -> Option<Arc<CertifiedKey>> { self.default_cert.read().unwrap().clone() }
    pub fn resolve_sni(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> { if let Some(name) = sni { if is_dns_sni(name) { if let Some(ck) = self.find_by_sni(name) { return Some(ck); } } } self.get_default() }
    pub fn replace(&self, certs: Vec<CertEntry>, default: Option<Arc<CertifiedKey>>) { *self.certs.write().unwrap() = certs; *self.default_cert.write().unwrap() = default; }
}
#[derive(Debug)]
pub struct DnsResolver { pub store: Arc<CertStore> }
impl DnsResolver { pub fn new(store: Arc<CertStore>) -> Self { Self { store } } }
impl ResolvesServerCert for DnsResolver { fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> { self.store.resolve_sni(hello.server_name()) } }
