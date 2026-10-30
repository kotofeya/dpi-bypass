//! Decrypts a client QUIC v1 Initial packet (RFC 9001 §5) just far enough to read the SNI,
//! so Engine A can drop QUIC only for YouTube and leave everything else alone.

use super::tls;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt};
use aes::Aes128;
use aes_gcm::{aead::{Aead, Payload}, Aes128Gcm, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;

const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

fn varint(b: &[u8], i: &mut usize) -> Option<u64> {
    let f = *b.get(*i)?;
    let l = 1usize << (f >> 6);
    let mut v = (f & 0x3f) as u64;
    for k in 1..l {
        v = (v << 8) | *b.get(*i + k)? as u64;
    }
    *i += l;
    Some(v)
}

fn expand_label(hk: &Hkdf<Sha256>, label: &str, out: &mut [u8]) {
    let mut info = Vec::new();
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());
    info.push(0);
    hk.expand(&info, out).expect("hkdf len");
}

pub fn initial_sni(p: &[u8]) -> Option<String> {
    let b0 = *p.first()?;
    if b0 & 0x80 == 0 || b0 & 0x30 != 0 {
        return None; // not a long-header Initial
    }
    if u32::from_be_bytes(p.get(1..5)?.try_into().ok()?) != 1 {
        return None; // QUIC v1 only
    }
    let mut i = 5;
    let dl = *p.get(i)? as usize;
    i += 1;
    let dcid = p.get(i..i + dl)?;
    i += dl;
    let sl = *p.get(i)? as usize;
    i += 1 + sl;
    let tl = varint(p, &mut i)? as usize;
    i += tl;
    let len = varint(p, &mut i)? as usize;
    let pn_off = i;
    if len < 20 || pn_off + len > p.len() {
        return None;
    }

    let (_, hk) = Hkdf::<Sha256>::extract(Some(&SALT_V1), dcid);
    let mut cs = [0u8; 32];
    expand_label(&hk, "client in", &mut cs);
    let ck = Hkdf::<Sha256>::from_prk(&cs).ok()?;
    let (mut key, mut iv, mut hp) = ([0u8; 16], [0u8; 12], [0u8; 16]);
    expand_label(&ck, "quic key", &mut key);
    expand_label(&ck, "quic iv", &mut iv);
    expand_label(&ck, "quic hp", &mut hp);

    // header protection removal
    let sample = p.get(pn_off + 4..pn_off + 20)?;
    let mut blk = GenericArray::clone_from_slice(sample);
    Aes128::new(GenericArray::from_slice(&hp)).encrypt_block(&mut blk);
    let first = b0 ^ (blk[0] & 0x0f);
    let pnl = ((first & 3) + 1) as usize;
    let mut hdr = p[..pn_off + pnl].to_vec();
    hdr[0] = first;
    let mut pn = 0u64;
    for k in 0..pnl {
        hdr[pn_off + k] ^= blk[1 + k];
        pn = (pn << 8) | hdr[pn_off + k] as u64;
    }
    let mut nonce = iv;
    for k in 0..8 {
        nonce[4 + k] ^= (pn >> (56 - 8 * k)) as u8;
    }

    let ct = p.get(pn_off + pnl..pn_off + len)?;
    let pt = Aes128Gcm::new(GenericArray::from_slice(&key))
        .decrypt(GenericArray::from_slice(&nonce), Payload { msg: ct, aad: &hdr })
        .ok()?;

    // reassemble CRYPTO frames
    let mut buf = vec![0u8; 4096];
    let mut have = 0usize;
    let mut j = 0usize;
    while j < pt.len() {
        match varint(&pt, &mut j)? {
            0 | 1 => {}
            6 => {
                let off = varint(&pt, &mut j)? as usize;
                let l = varint(&pt, &mut j)? as usize;
                let d = pt.get(j..j + l)?;
                if off + l <= buf.len() {
                    buf[off..off + l].copy_from_slice(d);
                    have = have.max(off + l);
                }
                j += l;
            }
            _ => break,
        }
    }
    tls::parse_handshake(&buf[..have], 0).map(|h| h.sni)
}
