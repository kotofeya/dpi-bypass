//! Decrypts client QUIC v1 Initial packets (RFC 9001 §5) just far enough to read the SNI, so
//! Engine A can drop QUIC only for target hosts (the app then falls back to TCP/TLS).
//!
//! Chrome's ClientHello (post-quantum key share, shuffled extensions) does not fit in one
//! Initial packet and the SNI is often in the second one, so CRYPTO fragments are collected per
//! connection (keyed by the client's destination connection id) until the name is visible.

use super::tls;
use std::collections::HashMap;
use std::time::{Duration, Instant};
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

/// Initial packet keys: (key, iv, header-protection key) for the client direction.
fn client_keys(dcid: &[u8]) -> Option<([u8; 16], [u8; 12], [u8; 16])> {
    let (_, hk) = Hkdf::<Sha256>::extract(Some(&SALT_V1), dcid);
    let mut cs = [0u8; 32];
    expand_label(&hk, "client in", &mut cs);
    let ck = Hkdf::<Sha256>::from_prk(&cs).ok()?;
    let (mut key, mut iv, mut hp) = ([0u8; 16], [0u8; 12], [0u8; 16]);
    expand_label(&ck, "quic key", &mut key);
    expand_label(&ck, "quic iv", &mut iv);
    expand_label(&ck, "quic hp", &mut hp);
    Some((key, iv, hp))
}

/// CRYPTO frames of one client Initial packet.
pub struct Crypto {
    pub dcid: Vec<u8>,
    /// (offset in the crypto stream, data)
    pub frags: Vec<(usize, Vec<u8>)>,
}

/// Decrypts a QUIC v1 client Initial. `None` for anything else (short headers, other versions,
/// packets that do not decrypt).
pub fn initial_crypto(p: &[u8]) -> Option<Crypto> {
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

    let (key, iv, hp) = client_keys(dcid)?;

    // header protection removal
    let sample = p.get(pn_off + 4..pn_off + 20)?;
    let mut blk = GenericArray::clone_from_slice(sample);
    Aes128::new(GenericArray::from_slice(&hp)).encrypt_block(&mut blk);
    let first = b0 ^ (blk[0] & 0x0f);
    let pnl = ((first & 3) + 1) as usize;
    let mut hdr = p.get(..pn_off + pnl)?.to_vec();
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

    let mut frags = Vec::new();
    let mut j = 0usize;
    while j < pt.len() {
        let Some(ty) = varint(&pt, &mut j) else { break };
        match ty {
            0 | 1 => {}
            6 => {
                let (Some(off), Some(l)) = (varint(&pt, &mut j), varint(&pt, &mut j)) else { break };
                let (off, l) = (off as usize, l as usize);
                let Some(d) = pt.get(j..j + l) else { break };
                frags.push((off, d.to_vec()));
                j += l;
            }
            _ => break,
        }
    }
    Some(Crypto { dcid: dcid.to_vec(), frags })
}

const MAX_CRYPTO: usize = 8192;
const FLOW_TTL: Duration = Duration::from_secs(60);
const MAX_FLOWS: usize = 2048;

enum Verdict {
    /// still collecting the hello
    Collecting { buf: Vec<u8>, ranges: Vec<(usize, usize)> },
    Drop,
    Allow,
}

/// Length of the gap-free prefix covered by `ranges`.
fn prefix(ranges: &[(usize, usize)]) -> usize {
    let mut r = ranges.to_vec();
    r.sort_unstable();
    let mut end = 0;
    for (a, b) in r {
        if a > end {
            break;
        }
        end = end.max(b);
    }
    end
}

#[derive(Default)]
pub struct QuicTracker {
    flows: HashMap<Vec<u8>, (Instant, Verdict)>,
}

impl QuicTracker {
    /// Should this outbound UDP/443 datagram be dropped? Once a connection is found to target a
    /// host, every packet of it is dropped (also retransmissions of the first one).
    pub fn should_drop(&mut self, p: &[u8], now: Instant, is_target: impl Fn(&str) -> bool) -> Option<bool> {
        let c = initial_crypto(p)?;
        if self.flows.len() > MAX_FLOWS {
            self.flows.retain(|_, (t, _)| now.duration_since(*t) < FLOW_TTL);
        }
        let (seen, v) = self
            .flows
            .entry(c.dcid)
            .or_insert_with(|| (now, Verdict::Collecting { buf: vec![0; MAX_CRYPTO], ranges: Vec::new() }));
        *seen = now;
        match v {
            Verdict::Drop => Some(true),
            Verdict::Allow => Some(false),
            Verdict::Collecting { buf, ranges } => {
                for (off, d) in c.frags {
                    if off + d.len() <= MAX_CRYPTO {
                        buf[off..off + d.len()].copy_from_slice(&d);
                        ranges.push((off, off + d.len()));
                    }
                }
                let Some(h) = tls::parse_handshake(&buf[..prefix(ranges)], 0) else { return Some(false) };
                let target = is_target(&h.sni);
                tracing::debug!("QUIC {} {}", h.sni, if target { "dropped -> TCP fallback" } else { "allowed" });
                *v = if target { Verdict::Drop } else { Verdict::Allow };
                Some(target)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::generic_array::GenericArray as GA;

    /// Builds a client Initial the way a QUIC stack does (pn 0, 1-byte packet number).
    fn initial(dcid: &[u8], pn: u8, frags: &[(usize, &[u8])]) -> Vec<u8> {
        let mut pt = Vec::new();
        for (off, d) in frags {
            pt.push(6);
            pt.extend_from_slice(&(0x4000 | *off as u16).to_be_bytes());
            pt.extend_from_slice(&(0x4000 | d.len() as u16).to_be_bytes());
            pt.extend_from_slice(d);
        }
        pt.resize(pt.len().max(1162), 0); // PADDING
        let (key, iv, hp) = client_keys(dcid).unwrap();
        let mut hdr = vec![0xc0, 0, 0, 0, 1, dcid.len() as u8];
        hdr.extend_from_slice(dcid);
        hdr.extend_from_slice(&[0, 0]); // scid len 0, token len 0
        hdr.extend_from_slice(&(0x4000 | (1 + pt.len() + 16) as u16).to_be_bytes());
        let pn_off = hdr.len();
        hdr.push(pn);
        let mut nonce = iv;
        nonce[11] ^= pn;
        let ct = Aes128Gcm::new(GA::from_slice(&key))
            .encrypt(GA::from_slice(&nonce), Payload { msg: &pt, aad: &hdr })
            .unwrap();
        let mut pkt = hdr;
        pkt.extend_from_slice(&ct);
        let mut blk = GenericArray::clone_from_slice(&pkt[pn_off + 4..pn_off + 20]);
        Aes128::new(GenericArray::from_slice(&hp)).encrypt_block(&mut blk);
        pkt[0] ^= blk[0] & 0x0f;
        pkt[pn_off] ^= blk[1];
        pkt
    }

    fn yt(p: &str) -> bool {
        p.ends_with("youtube.com")
    }

    #[test]
    fn decrypts_one_packet_hello() {
        let hello = tls::build_fake_client_hello("www.youtube.com");
        let pkt = initial(&[1, 2, 3, 4, 5, 6, 7, 8], 0, &[(0, &hello[5..])]);
        let c = initial_crypto(&pkt).unwrap();
        assert_eq!(c.frags.len(), 1);
        let mut t = QuicTracker::default();
        assert_eq!(t.should_drop(&pkt, Instant::now(), yt), Some(true));
    }

    #[test]
    fn sni_in_second_packet_drops_the_connection() {
        let hello = tls::build_probe_client_hello("www.youtube.com", 1500);
        let body = &hello[5..];
        let dcid = [9u8; 8];
        let p1 = initial(&dcid, 0, &[(0, &body[..1000])]);
        let p2 = initial(&dcid, 1, &[(1000, &body[1000..])]);
        let (mut t, now) = (QuicTracker::default(), Instant::now());
        assert_eq!(t.should_drop(&p1, now, yt), Some(false)); // SNI not visible yet
        assert_eq!(t.should_drop(&p2, now, yt), Some(true));
        assert_eq!(t.should_drop(&p1, now, yt), Some(true)); // retransmission
        // another connection to another host is left alone
        let other = tls::build_probe_client_hello("example.org", 1500);
        let q1 = initial(&[7u8; 8], 0, &[(0, &other[5..1005])]);
        let q2 = initial(&[7u8; 8], 1, &[(1000, &other[1005..])]);
        assert_eq!(t.should_drop(&q1, now, yt), Some(false));
        assert_eq!(t.should_drop(&q2, now, yt), Some(false));
        assert_eq!(t.should_drop(b"\x40\x01\x02\x03", now, yt), None); // short header
    }
}
