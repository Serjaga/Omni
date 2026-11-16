const MASK51: u64 = (1u64 << 51) - 1;
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[inline] fn fe_add(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] { [a[0].wrapping_add(b[0]), a[1].wrapping_add(b[1]), a[2].wrapping_add(b[2]), a[3].wrapping_add(b[3]), a[4].wrapping_add(b[4])] }
#[inline] fn fe_sub(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
    const ADJ0: u64 = (1u64 << 52) - 38; const ADJ1: u64 = (1u64 << 52) - 2;
    [a[0].wrapping_add(ADJ0).wrapping_sub(b[0]), a[1].wrapping_add(ADJ1).wrapping_sub(b[1]), a[2].wrapping_add(ADJ1).wrapping_sub(b[2]), a[3].wrapping_add(ADJ1).wrapping_sub(b[3]), a[4].wrapping_add(ADJ1).wrapping_sub(b[4])]
}
#[inline] fn fe_mul(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
    const M: u128 = 0x7_FFFF_FFFF_FFFF;
    let (a0,a1,a2,a3,a4) = (a[0] as u128, a[1] as u128, a[2] as u128, a[3] as u128, a[4] as u128);
    let (b0,b1,b2,b3,b4) = (b[0] as u128, b[1] as u128, b[2] as u128, b[3] as u128, b[4] as u128);
    let (b1_19, b2_19, b3_19, b4_19) = (b1 * 19, b2 * 19, b3 * 19, b4 * 19);
    let mut r0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
    let mut r1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
    let mut r2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
    let mut r3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
    let mut r4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
    let mut c: u128;
    c = r0 >> 51; r0 &= M; r1 += c;
    c = r1 >> 51; r1 &= M; r2 += c;
    c = r2 >> 51; r2 &= M; r3 += c;
    c = r3 >> 51; r3 &= M; r4 += c;
    c = r4 >> 51; r4 &= M; r0 += c * 19;
    c = r0 >> 51; r0 &= M; r1 += c;
    [r0 as u64, r1 as u64, r2 as u64, r3 as u64, r4 as u64]
}
#[inline] fn fe_sq(a: &[u64; 5]) -> [u64; 5] { fe_mul(a, a) }
#[inline] fn fe_mul121666(a: &[u64; 5]) -> [u64; 5] {
    const M: u128 = 0x7_FFFF_FFFF_FFFF; const C: u128 = 121666;
    let mut r0 = (a[0] as u128) * C; let mut r1 = (a[1] as u128) * C; let mut r2 = (a[2] as u128) * C;
    let mut r3 = (a[3] as u128) * C; let mut r4 = (a[4] as u128) * C;
    let mut c: u128;
    c = r0 >> 51; r0 &= M; r1 += c;
    c = r1 >> 51; r1 &= M; r2 += c;
    c = r2 >> 51; r2 &= M; r3 += c;
    c = r3 >> 51; r3 &= M; r4 += c;
    c = r4 >> 51; r4 &= M; r0 += c * 19;
    c = r0 >> 51; r0 &= M; r1 += c;
    [r0 as u64, r1 as u64, r2 as u64, r3 as u64, r4 as u64]
}
#[inline] fn fe_invert(z: &[u64; 5]) -> [u64; 5] {
    let z2 = fe_sq(z); let z4 = fe_sq(&z2); let z8 = fe_sq(&z4);
    let z9 = fe_mul(&z8, z); let z11 = fe_mul(&z9, &z2); let z22 = fe_sq(&z11);
    let z_5_0 = fe_mul(&z22, &z9);
    let mut t = fe_sq(&z_5_0); let mut i = 1; while i < 5 { t = fe_sq(&t); i += 1; } let z_10_5 = fe_mul(&t, &z_5_0);
    let mut t = fe_sq(&z_10_5); let mut i = 1; while i < 10 { t = fe_sq(&t); i += 1; } let z_20_10 = fe_mul(&t, &z_10_5);
    let mut t = fe_sq(&z_20_10); let mut i = 1; while i < 20 { t = fe_sq(&t); i += 1; } let z_40_20 = fe_mul(&t, &z_20_10);
    let mut t = fe_sq(&z_40_20); let mut i = 1; while i < 10 { t = fe_sq(&t); i += 1; } let z_50_10 = fe_mul(&t, &z_10_5);
    let mut t = fe_sq(&z_50_10); let mut i = 1; while i < 50 { t = fe_sq(&t); i += 1; } let z_100_50 = fe_mul(&t, &z_50_10);
    let mut t = fe_sq(&z_100_50); let mut i = 1; while i < 100 { t = fe_sq(&t); i += 1; } let z_200_100 = fe_mul(&t, &z_100_50);
    let mut t = fe_sq(&z_200_100); let mut i = 1; while i < 50 { t = fe_sq(&t); i += 1; } let z_250_50 = fe_mul(&t, &z_50_10);
    let mut t = fe_sq(&z_250_50); let mut i = 1; while i < 5 { t = fe_sq(&t); i += 1; }
    fe_mul(&t, &z11)
}
#[inline] fn fe_cswap(a: &mut [u64; 5], b: &mut [u64; 5], swap: u64) { let mask = 0u64.wrapping_sub(swap); let mut i = 0; while i < 5 { let t = mask & (a[i] ^ b[i]); a[i] ^= t; b[i] ^= t; i += 1; } }
#[inline] fn fe_from_bytes(s: &[u8; 32]) -> [u64; 5] {
    #[inline] fn load8(s: &[u8; 32], i: usize) -> u64 { u64::from_le_bytes([s[i],s[i+1],s[i+2],s[i+3],s[i+4],s[i+5],s[i+6],s[i+7]]) }
    let mut h0 = load8(s, 0); let mut h1 = load8(s, 6) >> 3; let mut h2 = load8(s, 12) >> 6;
    let mut h3 = load8(s, 19) >> 1; let mut h4 = load8(s, 24) >> 12;
    h0 &= MASK51; h1 &= MASK51; h2 &= MASK51; h3 &= MASK51; h4 &= MASK51;
    [h0, h1, h2, h3, h4]
}
#[inline] fn fe_to_bytes(h: &[u64; 5]) -> [u8; 32] {
    let mut h = *h; let mut c: u64;
    c = h[0] >> 51; h[0] &= MASK51; h[1] += c;
    c = h[1] >> 51; h[1] &= MASK51; h[2] += c;
    c = h[2] >> 51; h[2] &= MASK51; h[3] += c;
    c = h[3] >> 51; h[3] &= MASK51; h[4] += c;
    c = h[4] >> 51; h[4] &= MASK51; h[0] += c * 19;
    c = h[0] >> 51; h[0] &= MASK51; h[1] += c;
    let mut q; q = (h[0] + 19) >> 51; q = (h[1] + q) >> 51; q = (h[2] + q) >> 51; q = (h[3] + q) >> 51; q = (h[4] + q) >> 51;
    h[0] += 19 * q;
    c = h[0] >> 51; h[0] &= MASK51; h[1] += c;
    c = h[1] >> 51; h[1] &= MASK51; h[2] += c;
    c = h[2] >> 51; h[2] &= MASK51; h[3] += c;
    c = h[3] >> 51; h[3] &= MASK51; h[4] += c;
    let s0 = h[0] | (h[1] << 51); let s1 = (h[1] >> 13) | (h[2] << 38);
    let s2 = (h[2] >> 26) | (h[3] << 25); let s3 = (h[3] >> 39) | (h[4] << 12);
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&s0.to_le_bytes()); out[8..16].copy_from_slice(&s1.to_le_bytes());
    out[16..24].copy_from_slice(&s2.to_le_bytes()); out[24..32].copy_from_slice(&s3.to_le_bytes());
    out
}
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar; k[0] &= 248; k[31] &= 127; k[31] |= 64;
    let x1 = fe_from_bytes(point);
    let mut x2 = [0u64; 5]; x2[0] = 1; let mut z2 = [0u64; 5];
    let mut x3 = x1; let mut z3 = [0u64; 5]; z3[0] = 1;
    let mut swap = 0u64; let mut pos = 254i32;
    while pos >= 0 {
        let bit = ((k[(pos as usize) / 8] >> ((pos as usize) & 7)) & 1) as u64;
        swap ^= bit;
        fe_cswap(&mut x2, &mut x3, swap); fe_cswap(&mut z2, &mut z3, swap);
        swap = bit;
        let a = fe_add(&x2, &z2); let aa = fe_sq(&a);
        let xb = fe_sub(&x2, &z2); let bb = fe_sq(&xb);
        let e = fe_sub(&aa, &bb);
        let c = fe_add(&x3, &z3); let d = fe_sub(&x3, &z3);
        let da = fe_mul(&d, &a); let cb = fe_mul(&c, &xb);
        x3 = fe_sq(&fe_add(&da, &cb)); z3 = fe_mul(&x1, &fe_sq(&fe_sub(&da, &cb)));
        x2 = fe_mul(&aa, &bb);
        z2 = fe_mul(&e, &fe_add(&bb, &fe_mul121666(&e)));
        pos -= 1;
    }
    fe_cswap(&mut x2, &mut x3, swap); fe_cswap(&mut z2, &mut z3, swap);
    let inv = fe_invert(&z2);
    fe_to_bytes(&fe_mul(&x2, &inv))
}
pub fn curve25519_generate_public(secret: &[u8; 32]) -> [u8; 32] { let mut base = [0u8; 32]; base[0] = 9; x25519(secret, &base) }
pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4); let mut i = 0;
    while i + 3 <= data.len() {
        let (b0, b1, b2) = (data[i], data[i + 1], data[i + 2]);
        out.push(B64[(b0 >> 2) as usize] as char);
        out.push(B64[(((b0 << 4) | (b1 >> 4)) & 63) as usize] as char);
        out.push(B64[(((b1 << 2) | (b2 >> 6)) & 63) as usize] as char);
        out.push(B64[(b2 & 63) as usize] as char);
        i += 3;
    }
    match data.len() - i {
        1 => { let b0 = data[i]; out.push(B64[(b0 >> 2) as usize] as char); out.push(B64[((b0 << 4) & 63) as usize] as char); out.push('='); out.push('='); }
        2 => { let (b0, b1) = (data[i], data[i + 1]); out.push(B64[(b0 >> 2) as usize] as char); out.push(B64[(((b0 << 4) | (b1 >> 4)) & 63) as usize] as char); out.push(B64[((b1 << 2) & 63) as usize] as char); out.push('='); }
        _ => {}
    }
    out
}
fn b64_val(c: u8) -> Option<u8> { match c { b'A'..=b'Z' => Some(c - b'A'), b'a'..=b'z' => Some(c - b'a' + 26), b'0'..=b'9' => Some(c - b'0' + 52), b'+' => Some(62), b'/' => Some(63), _ => None } }
pub fn b64_decode(s: &[u8]) -> Option<Vec<u8>> {
    if s.len() % 4 != 0 { return None; }
    let mut out = Vec::with_capacity(s.len() / 4 * 3); let mut i = 0;
    while i < s.len() {
        let v0 = b64_val(s[i])?; let v1 = b64_val(s[i + 1])?;
        let v2 = if s[i + 2] == b'=' { 0 } else { b64_val(s[i + 2])? };
        let v3 = if s[i + 3] == b'=' { 0 } else { b64_val(s[i + 3])? };
        out.push((v0 << 2) | (v1 >> 4));
        if s[i + 2] != b'=' { out.push((v1 << 4) | (v2 >> 2)); }
        if s[i + 3] != b'=' { out.push((v2 << 6) | v3); }
        i += 4;
    }
    Some(out)
}
pub fn key_to_base64(key: &[u8; 32]) -> String { b64_encode(key) }
pub fn key_from_base64(s: &[u8]) -> Option<[u8; 32]> { let v = b64_decode(s)?; if v.len() != 32 { return None; } let mut out = [0u8; 32]; out.copy_from_slice(&v); Some(out) }
pub fn key_to_hex(key: &[u8; 32]) -> String { let mut s = String::with_capacity(64); for b in key { s.push_str(&format!("{:02x}", b)); } s }
pub fn key_from_hex(s: &str) -> Option<[u8; 32]> { if s.len() != 64 { return None; } let mut key = [0u8; 32]; let mut i = 0; while i < 32 { key[i] = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?; i += 1; } Some(key) }
pub fn key_is_zero(key: &[u8; 32]) -> bool { key.iter().all(|&b| b == 0) }
fn getrandom(buf: &mut [u8]) -> Result<(), String> { use std::io::Read; let mut f = std::fs::File::open("/dev/urandom").map_err(|e| format!("open /dev/urandom: {e}"))?; f.read_exact(buf).map_err(|e| format!("read urandom: {e}")) }
pub fn genkey() -> Result<String, String> { let mut key = [0u8; 32]; getrandom(&mut key)?; key[0] &= 248; key[31] = (key[31] & 127) | 64; Ok(key_to_base64(&key)) }
pub fn genpsk() -> Result<String, String> { let mut key = [0u8; 32]; getrandom(&mut key)?; Ok(key_to_base64(&key)) }
pub fn pubkey(sk_b64: &str) -> Result<String, String> { let sk = key_from_base64(sk_b64.trim().as_bytes()).ok_or_else(|| "invalid base64 private key".to_string())?; Ok(key_to_base64(&curve25519_generate_public(&sk))) }
