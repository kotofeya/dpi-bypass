//! MTProto "obfuscated2" transport (AES-256-CTR) and Telegram address -> DC mapping.
//!
//! Init block (64 bytes): [0..8) random | [8..40) key | [40..56) iv | [56..60) proto tag |
//! [60..62) dc id (i16 LE, negative = media DC, +10000 = test DC) | [62..64) random.
//! The whole block is AES-256-CTR encrypted with key/iv; bytes 56..64 go on the wire encrypted,
//! the rest in clear. The opposite direction uses key/iv taken from bytes 8..56 reversed.
//! With an MTProxy secret each key becomes sha256(key || secret).

use ctr::cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, Ipv6Addr};

pub type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtoTag {
    Abridged,
    Intermediate,
    Padded,
}

impl ProtoTag {
    pub fn bytes(self) -> [u8; 4] {
        match self {
            ProtoTag::Abridged => [0xef; 4],
            ProtoTag::Intermediate => [0xee; 4],
            ProtoTag::Padded => [0xdd; 4],
        }
    }
    pub fn from_bytes(b: [u8; 4]) -> Option<Self> {
        match b {
            [0xef, 0xef, 0xef, 0xef] => Some(ProtoTag::Abridged),
            [0xee, 0xee, 0xee, 0xee] => Some(ProtoTag::Intermediate),
            [0xdd, 0xdd, 0xdd, 0xdd] => Some(ProtoTag::Padded),
            _ => None,
        }
    }
}

/// A decoded client init: the peer's protocol and DC plus both stream ciphers positioned
/// right after the 64-byte header.
pub struct ClientInit {
    pub tag: ProtoTag,
    pub dc: i16,
    /// decrypts client -> us
    pub dec: Aes256Ctr,
    /// encrypts us -> client
    pub enc: Aes256Ctr,
}

/// A fresh init towards an upstream (gateway / DC) without secret.
pub struct UpstreamInit {
    pub raw: [u8; 64],
    /// encrypts us -> upstream (already advanced past the header)
    pub enc: Aes256Ctr,
    /// decrypts upstream -> us
    pub dec: Aes256Ctr,
}

fn key_material(init: &[u8; 64], secret: Option<&[u8; 16]>) -> ([u8; 32], [u8; 16], [u8; 32], [u8; 16]) {
    let mut rev: [u8; 48] = init[8..56].try_into().unwrap();
    rev.reverse();
    let mk = |raw: &[u8]| -> [u8; 32] {
        match secret {
            Some(s) => {
                let mut h = Sha256::new();
                h.update(raw);
                h.update(s);
                h.finalize().into()
            }
            None => raw.try_into().unwrap(),
        }
    };
    (mk(&init[8..40]), init[40..56].try_into().unwrap(), mk(&rev[..32]), rev[32..48].try_into().unwrap())
}

/// Decrypts and validates a client's init. `None` if it is not obfuscated2 (wrong key/secret,
/// or another protocol altogether).
pub fn parse_init(init: &[u8; 64], secret: Option<&[u8; 16]>) -> Option<ClientInit> {
    let (dk, div, ek, eiv) = key_material(init, secret);
    let mut dec = Aes256Ctr::new(&dk.into(), &div.into());
    let mut plain = *init;
    dec.apply_keystream(&mut plain);
    let tag = ProtoTag::from_bytes([plain[56], plain[57], plain[58], plain[59]])?;
    let dc = i16::from_le_bytes([plain[60], plain[61]]);
    Some(ClientInit { tag, dc, dec, enc: Aes256Ctr::new(&ek.into(), &eiv.into()) })
}

/// First words a valid init must not start with (they would look like another protocol).
fn reserved_start(init: &[u8; 64]) -> bool {
    init[0] == 0xef
        || init[4..8] == [0, 0, 0, 0]
        || matches!(
            [init[0], init[1], init[2], init[3]],
            [0x48, 0x45, 0x41, 0x44] // HEAD
                | [0x50, 0x4f, 0x53, 0x54] // POST
                | [0x47, 0x45, 0x54, 0x20] // GET
                | [0x4f, 0x50, 0x54, 0x49] // OPTI
                | [0xdd, 0xdd, 0xdd, 0xdd]
                | [0xee, 0xee, 0xee, 0xee]
                | [0x16, 0x03, 0x01, 0x02]
        )
}

/// Builds a client-side init (no secret) for `tag` / `dc`.
pub fn generate_init(tag: ProtoTag, dc: i16) -> UpstreamInit {
    let mut init = [0u8; 64];
    loop {
        init.iter_mut().for_each(|b| *b = fastrand::u8(..));
        if !reserved_start(&init) {
            break;
        }
    }
    init[56..60].copy_from_slice(&tag.bytes());
    init[60..62].copy_from_slice(&dc.to_le_bytes());

    let (k, iv, rk, riv) = key_material(&init, None);
    let mut enc = Aes256Ctr::new(&k.into(), &iv.into());
    let dec = Aes256Ctr::new(&rk.into(), &riv.into());
    let mut encrypted = init;
    enc.apply_keystream(&mut encrypted); // `enc` now sits at offset 64, ready for payload
    let mut raw = init;
    raw[56..64].copy_from_slice(&encrypted[56..64]);
    UpstreamInit { raw, enc, dec }
}

/// Non-obfuscated MTProto transports announce themselves with a marker:
/// 0xef (abridged) or 4 x 0xee / 0xdd (intermediate / padded intermediate).
/// Returns the protocol and the marker length to strip.
pub fn plain_transport(first: &[u8]) -> Option<(ProtoTag, usize)> {
    match first {
        [0xef, ..] => Some((ProtoTag::Abridged, 1)),
        [0xee, 0xee, 0xee, 0xee, ..] => Some((ProtoTag::Intermediate, 4)),
        [0xdd, 0xdd, 0xdd, 0xdd, ..] => Some((ProtoTag::Padded, 4)),
        _ => None,
    }
}

// ------------------------------------------------------------------ addresses

/// Telegram's IPv4 networks (AS62041 / AS59930 / AS44907 / AS62014 / AS211157).
pub const TELEGRAM_V4: &[([u8; 4], u8)] = &[
    ([149, 154, 160, 0], 20),
    ([91, 108, 4, 0], 22),
    ([91, 108, 8, 0], 22),
    ([91, 108, 12, 0], 22),
    ([91, 108, 16, 0], 22),
    ([91, 108, 20, 0], 22),
    ([91, 108, 56, 0], 22),
    ([91, 105, 192, 0], 23),
    ([95, 161, 64, 0], 20),
    ([185, 76, 151, 0], 24),
];

/// Telegram's IPv6 networks.
pub const TELEGRAM_V6: &[([u16; 8], u8)] = &[
    ([0x2001, 0x0b28, 0xf23c, 0, 0, 0, 0, 0], 47), // 2001:b28:f23c:: - 2001:b28:f23f::
    ([0x2001, 0x0b28, 0xf23e, 0, 0, 0, 0, 0], 47),
    ([0x2001, 0x067c, 0x04e8, 0, 0, 0, 0, 0], 48),
    ([0x2a0a, 0xf280, 0, 0, 0, 0, 0, 0], 32),
];

fn in_v4(ip: Ipv4Addr, net: [u8; 4], bits: u8) -> bool {
    let mask = if bits == 0 { 0 } else { !0u32 << (32 - bits as u32) };
    u32::from(ip) & mask == u32::from_be_bytes(net) & mask
}

pub fn is_telegram_v4(ip: Ipv4Addr) -> bool {
    TELEGRAM_V4.iter().any(|(n, b)| in_v4(ip, *n, *b))
}

pub fn is_telegram_v6(ip: Ipv6Addr) -> bool {
    let x = u128::from(ip);
    TELEGRAM_V6.iter().any(|(n, b)| {
        let mask = if *b == 0 { 0 } else { !0u128 << (128 - *b as u32) };
        x & mask == u128::from(Ipv6Addr::from(*n)) & mask
    })
}

/// First and last address of each Telegram IPv4 network (for WinDivert filters).
pub fn telegram_v4_ranges() -> Vec<(Ipv4Addr, Ipv4Addr)> {
    TELEGRAM_V4
        .iter()
        .map(|(n, b)| {
            let mask = !0u32 << (32 - *b as u32);
            let lo = u32::from_be_bytes(*n) & mask;
            (Ipv4Addr::from(lo), Ipv4Addr::from(lo | !mask))
        })
        .collect()
}

/// Known production DC addresses, most specific first:
/// (first, last, dc). Derived from Telegram's built-in DC options.
const DC_MAP: &[([u8; 4], [u8; 4], u8)] = &[
    ([149, 154, 175, 100], [149, 154, 175, 119], 3),
    ([149, 154, 167, 91], [149, 154, 167, 99], 4),
    ([149, 154, 175, 0], [149, 154, 175, 255], 1),
    ([149, 154, 167, 0], [149, 154, 167, 255], 2),
    ([149, 154, 164, 0], [149, 154, 166, 255], 4),
    ([149, 154, 171, 0], [149, 154, 171, 255], 5),
    ([91, 108, 56, 0], [91, 108, 59, 255], 5),
    ([91, 108, 4, 0], [91, 108, 7, 255], 4),
    ([91, 108, 12, 0], [91, 108, 15, 255], 3),
    ([91, 108, 8, 0], [91, 108, 11, 255], 2),
    ([95, 161, 64, 0], [95, 161, 79, 255], 2),
];

/// Best-effort DC for a Telegram server address (used when the init carries no DC id,
/// or for non-obfuscated transports).
pub fn dc_for_ip(ip: Ipv4Addr) -> Option<u8> {
    let x = u32::from(ip);
    DC_MAP
        .iter()
        .find(|(lo, hi, _)| u32::from_be_bytes(*lo) <= x && x <= u32::from_be_bytes(*hi))
        .map(|(_, _, dc)| *dc)
}

/// Resolve the DC a flow is meant for: `(dc 1..=5, media)`. Test DCs (|dc| > 10000) and
/// unknown addresses yield `None` (the caller then connects directly).
pub fn resolve_dc(init_dc: i16, server: Option<Ipv4Addr>) -> Option<(u8, bool)> {
    let media = init_dc < 0;
    let id = init_dc.unsigned_abs();
    if (1..=5).contains(&id) {
        return Some((id as u8, media));
    }
    if id > 5 {
        return None; // test DC or something we cannot bridge
    }
    server.and_then(dc_for_ip).map(|d| (d, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_init_parses_back() {
        for (tag, dc) in [(ProtoTag::Abridged, 2i16), (ProtoTag::Intermediate, -4), (ProtoTag::Padded, 5)] {
            let mut up = generate_init(tag, dc);
            let mut parsed = parse_init(&up.raw, None).expect("valid init");
            assert_eq!(parsed.tag, tag);
            assert_eq!(parsed.dc, dc);

            // client -> server payload
            let msg = b"hello mtproto payload".to_vec();
            let mut wire = msg.clone();
            up.enc.apply_keystream(&mut wire);
            assert_ne!(wire, msg);
            parsed.dec.apply_keystream(&mut wire);
            assert_eq!(wire, msg);

            // server -> client payload
            let mut back = b"reply".to_vec();
            parsed.enc.apply_keystream(&mut back);
            up.dec.apply_keystream(&mut back);
            assert_eq!(back, b"reply");
        }
    }

    #[test]
    fn secret_changes_keys() {
        let up = generate_init(ProtoTag::Padded, 2);
        // a secret-less init must not validate as an MTProxy init (overwhelmingly likely)
        let secret = [7u8; 16];
        if let Some(p) = parse_init(&up.raw, Some(&secret)) {
            assert!(p.dc != 2 || p.tag != ProtoTag::Padded);
        }
    }

    #[test]
    fn random_bytes_rarely_validate() {
        let mut hits = 0;
        for _ in 0..2000 {
            let mut b = [0u8; 64];
            b.iter_mut().for_each(|x| *x = fastrand::u8(..));
            hits += parse_init(&b, None).is_some() as u32;
        }
        assert_eq!(hits, 0);
    }

    #[test]
    fn plain_markers() {
        assert_eq!(plain_transport(&[0xef, 1, 2]), Some((ProtoTag::Abridged, 1)));
        assert_eq!(plain_transport(&[0xee; 8]), Some((ProtoTag::Intermediate, 4)));
        assert_eq!(plain_transport(&[0xdd; 4]), Some((ProtoTag::Padded, 4)));
        assert_eq!(plain_transport(&[0x16, 3, 1]), None);
    }

    #[test]
    fn address_mapping() {
        assert!(is_telegram_v4(Ipv4Addr::new(149, 154, 167, 51)));
        assert!(is_telegram_v4(Ipv4Addr::new(91, 108, 56, 130)));
        assert!(!is_telegram_v4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(is_telegram_v6("2001:b28:f23d:f001::a".parse().unwrap()));
        assert!(is_telegram_v6("2001:67c:4e8:f002::a".parse().unwrap()));
        assert!(!is_telegram_v6("2606:4700::1111".parse().unwrap()));

        assert_eq!(dc_for_ip(Ipv4Addr::new(149, 154, 175, 50)), Some(1));
        assert_eq!(dc_for_ip(Ipv4Addr::new(149, 154, 167, 51)), Some(2));
        assert_eq!(dc_for_ip(Ipv4Addr::new(149, 154, 175, 100)), Some(3));
        assert_eq!(dc_for_ip(Ipv4Addr::new(149, 154, 167, 91)), Some(4));
        assert_eq!(dc_for_ip(Ipv4Addr::new(91, 108, 56, 100)), Some(5));
        assert_eq!(dc_for_ip(Ipv4Addr::new(1, 1, 1, 1)), None);

        assert_eq!(resolve_dc(-2, None), Some((2, true)));
        assert_eq!(resolve_dc(10002, None), None);
        assert_eq!(resolve_dc(0, Some(Ipv4Addr::new(149, 154, 175, 100))), Some((3, false)));

        let r = telegram_v4_ranges();
        assert_eq!(r[0], (Ipv4Addr::new(149, 154, 160, 0), Ipv4Addr::new(149, 154, 175, 255)));
    }
}
