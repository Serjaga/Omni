
use super::uapi;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering as AOrd};

const NLM_F_REQUEST: u16 = 0x01; const NLM_F_ACK: u16 = 0x04; const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2; const NLMSG_DONE: u16 = 3; const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3; const CTRL_ATTR_FAMILY_ID: u16 = 1; const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const AF_NETLINK: i32 = 16; const NETLINK_GENERIC: i32 = 16; const SOCK_RAW: i32 = 3;
const CMD_GET_DEVICE: u8 = 0; const CMD_SET_DEVICE: u8 = 1;

const KERNEL_FAMILY: &[u8] = b"amneziawg\0";
const KERNEL_FAMILY_FALLBACK: &[u8] = b"wireguard\0";
const AF_INET_U16: u16 = 2; const AF_INET6_U16: u16 = 10;

static EXTENDED_V2: AtomicU8 = AtomicU8::new(0);

#[repr(C)] struct SockaddrNl { nl_family: u16, nl_pad: u16, nl_pid: u32, nl_groups: u32 }

#[derive(Clone, Debug, Default)] pub struct AllowedIp { pub family: u16, pub ip: [u8; 16], pub cidr: u8, pub flags: u32 }
impl AllowedIp {
    pub fn to_string(&self) -> String {
        if self.family == AF_INET_U16 {
            format!("{}/{}", Ipv4Addr::new(self.ip[0], self.ip[1], self.ip[2], self.ip[3]), self.cidr)
        } else {
            format!("{}/{}", Ipv6Addr::from(self.ip), self.cidr)
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Peer {
pub public_key: [u8; 32],
pub preshared_key: [u8; 32],
pub has_preshared_key: bool,
pub flags: u32,
pub endpoint: Option<SocketAddr>,
pub persistent_keepalive: u16,
pub has_persistent_keepalive: bool,
pub last_handshake_sec: i64,
pub rx_bytes: u64,
pub tx_bytes: u64,
pub allowed_ips: Vec<AllowedIp>,
}

#[derive(Clone, Debug, Default)]
pub struct Device {
pub name: String, pub ifindex: u32,
pub has_private_key: bool, pub private_key: [u8; 32],
pub has_public_key: bool, pub public_key: [u8; 32],
pub listen_port: u16, pub has_listen_port: bool,
pub fwmark: u32, pub has_fwmark: bool,
pub replace_peers: bool,
pub peers: Vec<Peer>,
pub obfs_jc: Option<u32>, pub obfs_jmin: Option<u32>, pub obfs_jmax: Option<u32>,
pub obfs_s1: Option<u16>, pub obfs_s2: Option<u16>, pub obfs_s3: Option<u16>, pub obfs_s4: Option<u16>,
pub obfs_h1: Option<u32>, pub obfs_h2: Option<u32>, pub obfs_h3: Option<u32>, pub obfs_h4: Option<u32>,
pub obfs_i1_raw: Option<String>, pub obfs_i2_raw: Option<String>,
pub obfs_i3_raw: Option<String>, pub obfs_i4_raw: Option<String>, pub obfs_i5_raw: Option<String>,
}

#[inline] fn align4(n: usize) -> usize { (n + 3) & !3 }
fn push_u16(buf: &mut Vec<u8>, v: u16) { buf.extend_from_slice(&v.to_ne_bytes()); }
fn push_u32(buf: &mut Vec<u8>, v: u32) { buf.extend_from_slice(&v.to_ne_bytes()); }
fn pad(buf: &mut Vec<u8>, to: usize) { while buf.len() < to { buf.push(0); } }
fn push_nlmsg(buf: &mut Vec<u8>, msg_type: u16, flags: u16, seq: u32, pid: u32) -> usize {
    let start = buf.len(); push_u32(buf, 0); push_u16(buf, msg_type); push_u16(buf, flags);
    push_u32(buf, seq); push_u32(buf, pid); start
}
fn push_genl(buf: &mut Vec<u8>, cmd: u8, version: u8) { buf.push(cmd); buf.push(version); push_u16(buf, 0); }
fn push_attr(buf: &mut Vec<u8>, attr_type: u16, data: &[u8]) {
    push_u16(buf, (4 + data.len()) as u16);
    push_u16(buf, attr_type);
    buf.extend_from_slice(data);
    pad(buf, align4(buf.len()));
}
fn push_attr_u8(buf: &mut Vec<u8>, t: u16, v: u8) { push_attr(buf, t, &[v]); }
fn push_attr_u16(buf: &mut Vec<u8>, t: u16, v: u16) { push_attr(buf, t, &v.to_ne_bytes()); }
fn push_attr_u32(buf: &mut Vec<u8>, t: u16, v: u32) { push_attr(buf, t, &v.to_ne_bytes()); }
fn push_attr_strz(buf: &mut Vec<u8>, t: u16, s: &str) { let mut d = s.as_bytes().to_vec(); d.push(0); push_attr(buf, t, &d); }
fn push_attr_nest_start(buf: &mut Vec<u8>, t: u16) -> usize {
    const NLA_F_NESTED: u16 = 0x8000;
    let start = buf.len(); push_u16(buf, 0); push_u16(buf, t | NLA_F_NESTED); start
}
fn push_attr_nest_end(buf: &mut Vec<u8>, start: usize) {
    let len = (buf.len() - start) as u16;
    buf[start..start+2].copy_from_slice(&len.to_ne_bytes());
}
fn push_attr_sockaddr(buf: &mut Vec<u8>, t: u16, sa: &SocketAddr) {
    match sa {
        SocketAddr::V4(v4) => {
            let mut d = Vec::with_capacity(16);
            d.extend_from_slice(&AF_INET_U16.to_ne_bytes());
            d.extend_from_slice(&v4.port().to_be_bytes());
            d.extend_from_slice(&v4.ip().octets());
            d.extend_from_slice(&[0u8; 8]);
            push_attr(buf, t, &d);
        }
        SocketAddr::V6(v6) => {
            let mut d = Vec::with_capacity(28);
            d.extend_from_slice(&AF_INET6_U16.to_ne_bytes());
            d.extend_from_slice(&v6.port().to_be_bytes());
            d.extend_from_slice(&v6.flowinfo().to_ne_bytes());
            d.extend_from_slice(&v6.ip().octets());
            d.extend_from_slice(&v6.scope_id().to_ne_bytes());
            push_attr(buf, t, &d);
        }
    }
}
fn finish_nlmsg(buf: &mut Vec<u8>, start: usize) {
    let len = (buf.len() - start) as u32;
    buf[start..start+4].copy_from_slice(&len.to_ne_bytes());
}

fn push_attr_u32_opt(buf: &mut Vec<u8>, t: u16, v: Option<u32>) { if let Some(x) = v { push_attr_u32(buf, t, x); } }
fn push_attr_u16_opt(buf: &mut Vec<u8>, t: u16, v: Option<u16>) { if let Some(x) = v { push_attr_u16(buf, t, x); } }

   fn push_h_range(buf: &mut Vec<u8>, attr: u16, value: Option<u32>) {
if let Some(v) = value {
    push_attr_strz(buf, attr, &v.to_string());
}
}

fn nul_string(v: &[u8]) -> Option<String> {
let nul = v.iter().position(|&b| b == 0).unwrap_or(v.len());
if nul == 0 { return None; }
Some(String::from_utf8_lossy(&v[..nul]).into_owned())
}

fn sock_open() -> io::Result<i32> {
    let fd = unsafe { libc::socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC) };
    if fd < 0 { return Err(io::Error::last_os_error()); }
    let sa = SockaddrNl { nl_family: AF_NETLINK as u16, nl_pad: 0, nl_pid: 0, nl_groups: 0 };
    let r = unsafe {
        libc::bind(fd, &sa as *const _ as *const libc::sockaddr,
                   std::mem::size_of::<SockaddrNl>() as u32)
    };
    if r < 0 { let e = io::Error::last_os_error(); unsafe { libc::close(fd); } return Err(e); }
    Ok(fd)
}
fn send_msg(fd: i32, buf: &[u8]) -> io::Result<()> {
    let sa = SockaddrNl { nl_family: AF_NETLINK as u16, nl_pad: 0, nl_pid: 0, nl_groups: 0 };
    let r = unsafe {
        libc::sendto(fd, buf.as_ptr() as *const _, buf.len(), 0,
                     &sa as *const _ as *const libc::sockaddr,
                     std::mem::size_of::<SockaddrNl>() as u32)
    };
    if r < 0 { return Err(io::Error::last_os_error()); }
    Ok(())
}
fn recv_msg(fd: i32, buf: &mut [u8]) -> io::Result<usize> {
    let r = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
    if r < 0 { return Err(io::Error::last_os_error()); }
    Ok(r as usize)
}
static SEQ: AtomicU32 = AtomicU32::new(1);
fn next_seq() -> u32 { SEQ.fetch_add(1, AOrd::Relaxed) }
fn parse_nlmsg_err(data: &[u8]) -> io::Result<()> {
    if data.len() < 4 { return Ok(()); }
    let err = i32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
    if err == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(-err)) }
}

const EINVAL: i32 = 22; const ENOTSUP: i32 = 95; const ERANGE: i32 = 34;
fn is_unsupported_attr(e: &io::Error) -> bool {
matches!(e.raw_os_error(), Some(EINVAL) | Some(ENOTSUP) | Some(ERANGE))
}

// ─── resolve family by iface name ──────────────────────────────
fn resolve_family(fd: i32, name: &[u8]) -> io::Result<u16> {
    let mut buf = Vec::with_capacity(64);
    let seq = next_seq();
    let start = push_nlmsg(&mut buf, GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK, seq, 0);
    push_genl(&mut buf, CTRL_CMD_GETFAMILY, 1);
    push_attr(&mut buf, CTRL_ATTR_FAMILY_NAME, name);
    finish_nlmsg(&mut buf, start);
    send_msg(fd, &buf)?;
    let mut family_id: Option<u16> = None;
    let mut rbuf = vec![0u8; 8192];
    loop {
        let n = recv_msg(fd, &mut rbuf)?;
        let mut off = 0usize;
        let mut ack_seen = false;
        while off + 16 <= n {
            let mlen = u32::from_ne_bytes([rbuf[off], rbuf[off+1], rbuf[off+2], rbuf[off+3]]) as usize;
            let mtype = u16::from_ne_bytes([rbuf[off+4], rbuf[off+5]]);
            let mseq = u32::from_ne_bytes([rbuf[off+8], rbuf[off+9], rbuf[off+10], rbuf[off+11]]);
            if mlen < 16 || off + mlen > n { break; }
            if mseq != seq { off += align4(mlen); continue; }
            if mtype == NLMSG_ERROR {
                let ed = &rbuf[off+16..off+mlen];
                if ed.len() >= 4 {
                    let err = i32::from_ne_bytes([ed[0], ed[1], ed[2], ed[3]]);
                    if err != 0 { return Err(io::Error::from_raw_os_error(-err)); }
                }
                ack_seen = true;
            } else if mtype == GENL_ID_CTRL {
                let mut a = off + 20;
                while a + 4 <= off + mlen {
                    let alen = u16::from_ne_bytes([rbuf[a], rbuf[a+1]]) as usize;
                    let atype = u16::from_ne_bytes([rbuf[a+2], rbuf[a+3]]);
                    if alen < 4 || a + alen > off + mlen { break; }
                    if atype == CTRL_ATTR_FAMILY_ID && alen >= 6 {
                        family_id = Some(u16::from_ne_bytes([rbuf[a+4], rbuf[a+5]]));
                    }
                    a += align4(alen);
                }
            }
            off += align4(mlen);
        }
        if ack_seen {
            return family_id.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "family id missing"));
        }
    }
}

/// vpn0 → wireguard, obfs0 → amneziawg. Второе поле — is_amnezia.
fn resolve_family_for(fd: i32, iface_name: &str) -> io::Result<(u16, bool)> {
    if iface_name.starts_with("obfs") {
        resolve_family(fd, KERNEL_FAMILY).map(|f| (f, true))
    } else {
        resolve_family(fd, KERNEL_FAMILY_FALLBACK).map(|f| (f, false))
    }
}

fn parse_attrs(data: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 4 <= data.len() {
        let alen = u16::from_ne_bytes([data[off], data[off+1]]) as usize;
        let atype = u16::from_ne_bytes([data[off+2], data[off+3]]);
        if alen < 4 || off + alen > data.len() { break; }
        out.push((atype & 0x3FFF, data[off+4..off+alen].to_vec()));
        off += align4(alen);
    }
    out
}

// ─── get raw/device ────────────────────────────────────────────
pub fn get_device_raw(name: &str) -> io::Result<Vec<u8>> {
    let fd = sock_open()?;
    let (family, _is_amnezia) = match resolve_family_for(fd, name) {
        Ok(x) => x,
        Err(e) => { unsafe { libc::close(fd); } return Err(e); }
    };
    let mut buf = Vec::with_capacity(128);
    let seq = next_seq();
    let start = push_nlmsg(&mut buf, family, NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP, seq, 0);
    push_genl(&mut buf, CMD_GET_DEVICE, uapi::GENL_VERSION);
    push_attr_strz(&mut buf, uapi::DEV_A_IFNAME, name);
    finish_nlmsg(&mut buf, start);
    send_msg(fd, &buf)?;
    let mut rbuf = vec![0u8; 65536];
    let n = recv_msg(fd, &mut rbuf)?;
    unsafe { libc::close(fd); }
    Ok(rbuf[..n].to_vec())
}

fn parse_sockaddr(data: &[u8]) -> Option<SocketAddr> {
    if data.len() < 8 { return None; }
    let family = u16::from_ne_bytes([data[0], data[1]]);
    if family == AF_INET_U16 && data.len() >= 16 {
        let port = u16::from_be_bytes([data[2], data[3]]);
        return Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(data[4], data[5], data[6], data[7]), port,
        )));
    }
    if family == AF_INET6_U16 && data.len() >= 28 {
        let port = u16::from_be_bytes([data[2], data[3]]);
        let flowinfo = u32::from_ne_bytes([data[4], data[5], data[6], data[7]]);
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&data[8..24]);
        let scope = u32::from_ne_bytes([data[24], data[25], data[26], data[27]]);
        return Some(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(ip), port, flowinfo, scope,
        )));
    }
    None
}

fn parse_allowedip(data: &[u8]) -> AllowedIp {
    let mut a = AllowedIp::default();
    for (t, v) in parse_attrs(data) {
        match t {
            uapi::AIP_A_FAMILY if v.len() >= 2 => a.family = u16::from_ne_bytes([v[0], v[1]]),
            uapi::AIP_A_IPADDR => {
                if v.len() == 4 { a.ip[..4].copy_from_slice(&v); }
                else if v.len() == 16 { a.ip.copy_from_slice(&v); }
            }
            uapi::AIP_A_CIDR_MASK if !v.is_empty() => a.cidr = v[0],
            uapi::AIP_A_FLAGS if v.len() >= 4 => a.flags = u32::from_ne_bytes([v[0], v[1], v[2], v[3]]),
            _ => {}
        }
    }
    a
}

fn parse_u32_attr(attrs: &[(u16, Vec<u8>)], target: u16) -> Option<u32> {
    for (t, v) in attrs {
        if *t != target { continue; }
        if v.len() == 4 {
            return Some(u32::from_ne_bytes([v[0], v[1], v[2], v[3]]));
        }
        if v.len() >= 2 && v.len() < 4 {
            return Some(u16::from_ne_bytes([v[0], v[1]]) as u32);
        }
        if let Some(nul) = v.iter().position(|&b| b == 0) {
            let s = String::from_utf8_lossy(&v[..nul]);
            let first = s.split('-').next().unwrap_or(&s).trim();
            if let Ok(n) = first.parse::<u32>() { return Some(n); }
        }
    }
    None
}

fn parse_peer(data: &[u8]) -> Peer {
    let mut p = Peer::default();
    let attrs = parse_attrs(data);
    for (t, v) in &attrs {
        match *t {
            uapi::PEER_A_PUBLIC_KEY if v.len() == 32 => p.public_key.copy_from_slice(v),
            uapi::PEER_A_PRESHARED_KEY if v.len() == 32 => {
                p.preshared_key.copy_from_slice(v);
                p.has_preshared_key = !v.iter().all(|&b| b == 0);
            }
            uapi::PEER_A_FLAGS if v.len() >= 4 => p.flags = u32::from_ne_bytes([v[0], v[1], v[2], v[3]]),
            uapi::PEER_A_ENDPOINT => p.endpoint = parse_sockaddr(v),
            uapi::PEER_A_PERSISTENT_KEEPALIVE_INTERVAL if v.len() >= 2 => {
                p.persistent_keepalive = u16::from_ne_bytes([v[0], v[1]]);
                p.has_persistent_keepalive = p.persistent_keepalive > 0;
            }
            uapi::PEER_A_LAST_HANDSHAKE_TIME if v.len() >= 8 => {
                p.last_handshake_sec = i64::from_ne_bytes([
                    v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],
                ]);
            }
            uapi::PEER_A_RX_BYTES if v.len() >= 8 => p.rx_bytes = u64::from_ne_bytes([
                v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],
            ]),
            uapi::PEER_A_TX_BYTES if v.len() >= 8 => p.tx_bytes = u64::from_ne_bytes([
                v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],
            ]),
            uapi::PEER_A_ALLOWEDIPS => {
                for (_i, nested) in parse_attrs(v) {
                    p.allowed_ips.push(parse_allowedip(&nested));
                }
            }
            _ => {}
        }
    }
    p
}

fn parse_device(data: &[u8], fallback_name: &str) -> Device {
let mut d = Device::default();
d.name = fallback_name.to_string();
let attrs = parse_attrs(data);
for (t, v) in &attrs {
    match *t {
        uapi::DEV_A_IFINDEX if v.len() >= 4 => d.ifindex = u32::from_ne_bytes([v[0], v[1], v[2], v[3]]),
        uapi::DEV_A_IFNAME => {
            if let Some(s) = nul_string(v) { d.name = s; }
        }
        uapi::DEV_A_PRIVATE_KEY if v.len() == 32 => { d.private_key.copy_from_slice(v); d.has_private_key = true; }
        uapi::DEV_A_PUBLIC_KEY if v.len() == 32 => { d.public_key.copy_from_slice(v); d.has_public_key = true; }
        uapi::DEV_A_FLAGS if v.len() >= 4 => d.replace_peers = u32::from_ne_bytes([v[0], v[1], v[2], v[3]]) & uapi::DEV_F_REPLACE_PEERS != 0,
        uapi::DEV_A_LISTEN_PORT if v.len() >= 2 => { d.listen_port = u16::from_ne_bytes([v[0], v[1]]); d.has_listen_port = true; }
        uapi::DEV_A_FWMARK if v.len() >= 4 => { d.fwmark = u32::from_ne_bytes([v[0], v[1], v[2], v[3]]); d.has_fwmark = true; }
        uapi::DEV_A_PEERS => {
            for (_i, nested) in parse_attrs(v) { d.peers.push(parse_peer(&nested)); }
        }
        uapi::DEV_A_JC if v.len() >= 2 => d.obfs_jc = Some(u16::from_ne_bytes([v[0], v[1]]) as u32),
        uapi::DEV_A_JMIN if v.len() >= 2 => d.obfs_jmin = Some(u16::from_ne_bytes([v[0], v[1]]) as u32),
        uapi::DEV_A_JMAX if v.len() >= 2 => d.obfs_jmax = Some(u16::from_ne_bytes([v[0], v[1]]) as u32),
        uapi::DEV_A_S1 if v.len() >= 2 => d.obfs_s1 = Some(u16::from_ne_bytes([v[0], v[1]])),
        uapi::DEV_A_S2 if v.len() >= 2 => d.obfs_s2 = Some(u16::from_ne_bytes([v[0], v[1]])),
        uapi::DEV_A_S3 if v.len() >= 2 => d.obfs_s3 = Some(u16::from_ne_bytes([v[0], v[1]])),
        uapi::DEV_A_S4 if v.len() >= 2 => d.obfs_s4 = Some(u16::from_ne_bytes([v[0], v[1]])),
        uapi::DEV_A_I1 => { if let Some(s) = nul_string(v) { d.obfs_i1_raw = Some(s); } }
        uapi::DEV_A_I2 => { if let Some(s) = nul_string(v) { d.obfs_i2_raw = Some(s); } }
        uapi::DEV_A_I3 => { if let Some(s) = nul_string(v) { d.obfs_i3_raw = Some(s); } }
        uapi::DEV_A_I4 => { if let Some(s) = nul_string(v) { d.obfs_i4_raw = Some(s); } }
        uapi::DEV_A_I5 => { if let Some(s) = nul_string(v) { d.obfs_i5_raw = Some(s); } }
        _ => {}
    }
}
d.obfs_h1 = parse_u32_attr(&attrs, uapi::DEV_A_H1);
d.obfs_h2 = parse_u32_attr(&attrs, uapi::DEV_A_H2);
d.obfs_h3 = parse_u32_attr(&attrs, uapi::DEV_A_H3);
d.obfs_h4 = parse_u32_attr(&attrs, uapi::DEV_A_H4);
d
}

pub fn get_device(name: &str) -> io::Result<Device> {
    let fd = sock_open()?;
    let (family, _is_amnezia) = match resolve_family_for(fd, name) {
        Ok(x) => x,
        Err(e) => { unsafe { libc::close(fd); } return Err(e); }
    };
    let mut buf = Vec::with_capacity(128);
    let seq = next_seq();
    let start = push_nlmsg(&mut buf, family, NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP, seq, 0);
    push_genl(&mut buf, CMD_GET_DEVICE, uapi::GENL_VERSION);
    push_attr_strz(&mut buf, uapi::DEV_A_IFNAME, name);
    finish_nlmsg(&mut buf, start);
    send_msg(fd, &buf)?;
    let mut rbuf = vec![0u8; 65536];
    let mut device: Option<Device> = None;
    loop {
        let n = match recv_msg(fd, &mut rbuf) {
            Ok(n) => n,
            Err(e) => { unsafe { libc::close(fd); } return Err(e); }
        };
        let mut off = 0usize;
        while off + 16 <= n {
            let mlen = u32::from_ne_bytes([rbuf[off], rbuf[off+1], rbuf[off+2], rbuf[off+3]]) as usize;
            let mtype = u16::from_ne_bytes([rbuf[off+4], rbuf[off+5]]);
            if mlen < 16 || off + mlen > n { break; }
            if mtype == NLMSG_ERROR {
                let e = parse_nlmsg_err(&rbuf[off+16..off+mlen]);
                unsafe { libc::close(fd); }
                return e.map(|_| Device::default());
            }
            if mtype == NLMSG_DONE {
                unsafe { libc::close(fd); }
                return device.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "device not found"));
            }
            if mtype == family {
                device = Some(parse_device(&rbuf[off+20..off+mlen], name));
            }
            off += align4(mlen);
        }
    }
}

pub fn set_device(dev: &Device) -> io::Result<()> {
let fd = sock_open()?;
let result = (|| -> io::Result<()> {
    let (family, is_amnezia) = resolve_family_for(fd, &dev.name)?;

    // vpn0: обычный wireguard, всегда level=0, кэш не трогаем.
    if !is_amnezia {
        return send_set_device(fd, dev, family, 0);
    }

    // obfs0: amneziawg, fallback level=1 → level=0.
    let cached = EXTENDED_V2.load(AOrd::Relaxed);
    let try_levels: &[u8] = match cached {
        2 => &[0],
        _ => &[1, 0],
    };

    let mut last_err: Option<io::Error> = None;
    for &level in try_levels {
        match send_set_device(fd, dev, family, level) {
            Ok(_) => {
                if cached == 0 {
                    if level == 0 {
                        EXTENDED_V2.store(2, AOrd::Relaxed);
                        eprintln!("[VPN] obfs rejected — running as vpn");
                    } else {
                        EXTENDED_V2.store(1, AOrd::Relaxed);
                    }
                }
                return Ok(());
            }
            Err(e) if is_unsupported_attr(&e) => {
                eprintln!("[VPN] obfs level {} rejected ({:?}), trying lower", level, e);
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "all obfs levels failed")))
})();
unsafe { libc::close(fd); }
result
}

fn send_set_device(fd: i32, dev: &Device, family: u16, level: u8) -> io::Result<()> {
let mut buf = Vec::with_capacity(1024);
let seq = next_seq();
let start = push_nlmsg(&mut buf, family, NLM_F_REQUEST | NLM_F_ACK, seq, 0);
push_genl(&mut buf, CMD_SET_DEVICE, uapi::GENL_VERSION);
push_attr_strz(&mut buf, uapi::DEV_A_IFNAME, &dev.name);

let mut dev_flags = 0u32;
if dev.replace_peers { dev_flags |= uapi::DEV_F_REPLACE_PEERS; }
if dev_flags != 0 { push_attr_u32(&mut buf, uapi::DEV_A_FLAGS, dev_flags); }
if dev.has_private_key { push_attr(&mut buf, uapi::DEV_A_PRIVATE_KEY, &dev.private_key); }
if dev.has_listen_port { push_attr_u16(&mut buf, uapi::DEV_A_LISTEN_PORT, dev.listen_port); }
if dev.has_fwmark { push_attr_u32(&mut buf, uapi::DEV_A_FWMARK, dev.fwmark); }

if level >= 1 {
    push_attr_u16_opt(&mut buf, uapi::DEV_A_JC,   dev.obfs_jc.map(|v| v as u16));
    push_attr_u16_opt(&mut buf, uapi::DEV_A_JMIN, dev.obfs_jmin.map(|v| v as u16));
    push_attr_u16_opt(&mut buf, uapi::DEV_A_JMAX, dev.obfs_jmax.map(|v| v as u16));
    push_attr_u16_opt(&mut buf, uapi::DEV_A_S1,   dev.obfs_s1);
    push_attr_u16_opt(&mut buf, uapi::DEV_A_S2,   dev.obfs_s2);
    push_attr_u16_opt(&mut buf, uapi::DEV_A_S3,   dev.obfs_s3);
    push_attr_u16_opt(&mut buf, uapi::DEV_A_S4,   dev.obfs_s4);
    push_h_range(&mut buf, uapi::DEV_A_H1, dev.obfs_h1);
    push_h_range(&mut buf, uapi::DEV_A_H2, dev.obfs_h2);
    push_h_range(&mut buf, uapi::DEV_A_H3, dev.obfs_h3);
    push_h_range(&mut buf, uapi::DEV_A_H4, dev.obfs_h4);
    if let Some(s) = &dev.obfs_i1_raw { if !s.is_empty() { push_attr_strz(&mut buf, uapi::DEV_A_I1, s); } }
    if let Some(s) = &dev.obfs_i2_raw { if !s.is_empty() { push_attr_strz(&mut buf, uapi::DEV_A_I2, s); } }
    if let Some(s) = &dev.obfs_i3_raw { if !s.is_empty() { push_attr_strz(&mut buf, uapi::DEV_A_I3, s); } }
    if let Some(s) = &dev.obfs_i4_raw { if !s.is_empty() { push_attr_strz(&mut buf, uapi::DEV_A_I4, s); } }
    if let Some(s) = &dev.obfs_i5_raw { if !s.is_empty() { push_attr_strz(&mut buf, uapi::DEV_A_I5, s); } }
}

    if !dev.peers.is_empty() {
    let peers_start = push_attr_nest_start(&mut buf, uapi::DEV_A_PEERS);
    for peer in &dev.peers {
        let peer_start = push_attr_nest_start(&mut buf, 0);
        push_attr(&mut buf, uapi::PEER_A_PUBLIC_KEY, &peer.public_key);

        let mut peer_flags = peer.flags;
        if peer_flags & uapi::PEER_F_REPLACE_ALLOWEDIPS == 0 && !peer.allowed_ips.is_empty() {
            peer_flags |= uapi::PEER_F_REPLACE_ALLOWEDIPS;
        }
        if peer_flags != 0 { push_attr_u32(&mut buf, uapi::PEER_A_FLAGS, peer_flags); }

        if peer.has_preshared_key { push_attr(&mut buf, uapi::PEER_A_PRESHARED_KEY, &peer.preshared_key); }
        if let Some(sa) = peer.endpoint { push_attr_sockaddr(&mut buf, uapi::PEER_A_ENDPOINT, &sa); }
        if peer.has_persistent_keepalive {
            push_attr_u16(&mut buf, uapi::PEER_A_PERSISTENT_KEEPALIVE_INTERVAL, peer.persistent_keepalive);
        }

        if !peer.allowed_ips.is_empty() {
            let aips_start = push_attr_nest_start(&mut buf, uapi::PEER_A_ALLOWEDIPS);
            for aip in &peer.allowed_ips {
                let aip_start = push_attr_nest_start(&mut buf, 0);
                push_attr_u16(&mut buf, uapi::AIP_A_FAMILY, aip.family);
                if aip.family == AF_INET_U16 {
                    push_attr(&mut buf, uapi::AIP_A_IPADDR, &aip.ip[..4]);
                } else {
                    push_attr(&mut buf, uapi::AIP_A_IPADDR, &aip.ip[..]);
                }
                push_attr_u8(&mut buf, uapi::AIP_A_CIDR_MASK, aip.cidr);
                if aip.flags != 0 { push_attr_u32(&mut buf, uapi::AIP_A_FLAGS, aip.flags); }
                push_attr_nest_end(&mut buf, aip_start);
            }
            push_attr_nest_end(&mut buf, aips_start);
        }
        push_attr_nest_end(&mut buf, peer_start);
    }
    push_attr_nest_end(&mut buf, peers_start);
}

finish_nlmsg(&mut buf, start);
send_msg(fd, &buf)?;
let mut rbuf = vec![0u8; 8192];
loop {
    let n = recv_msg(fd, &mut rbuf)?;
    let mut off = 0usize;
    let mut found: Option<io::Result<()>> = None;
    while off + 16 <= n {
        let mlen = u32::from_ne_bytes([rbuf[off], rbuf[off+1], rbuf[off+2], rbuf[off+3]]) as usize;
        let mtype = u16::from_ne_bytes([rbuf[off+4], rbuf[off+5]]);
        let mseq = u32::from_ne_bytes([rbuf[off+8], rbuf[off+9], rbuf[off+10], rbuf[off+11]]);
        if mlen < 16 || off + mlen > n { break; }
        if mtype == NLMSG_ERROR && mseq == seq {
            let ed = &rbuf[off+16..off+mlen];
            if ed.len() >= 4 {
                let err = i32::from_ne_bytes([ed[0], ed[1], ed[2], ed[3]]);
                found = Some(if err == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(-err)) });
            } else {
                found = Some(Ok(()));
            }
        }
        off += align4(mlen);
    }
    if let Some(r) = found { return r; }
}
}

pub fn ip_from_cidr(s: &str) -> Option<AllowedIp> {
    let (ip_part, cidr_part) = s.split_once('/')?;
    let cidr: u8 = cidr_part.parse().ok()?;
    let mut aip = AllowedIp { cidr, ..Default::default() };
    if let Ok(v4) = ip_part.parse::<Ipv4Addr>() {
        aip.family = AF_INET_U16;
        aip.ip[..4].copy_from_slice(&v4.octets());
    } else if let Ok(v6) = ip_part.parse::<Ipv6Addr>() {
        aip.family = AF_INET6_U16;
        aip.ip.copy_from_slice(&v6.octets());
    } else {
        return None;
    }
    Some(aip)
}

pub fn obfs_status() -> &'static str {
    match EXTENDED_V2.load(AOrd::Relaxed) {
        1 => "obfs",
        2 => "vpn",
        _ => "unknown (not yet probed)",
    }
}
