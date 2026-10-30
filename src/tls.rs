//! Minimal TLS ClientHello parser (SNI + offset) and fake ClientHello builder.

pub struct Hello {
    pub sni: String,
    /// offset of the hostname bytes relative to the start of the slice that was parsed
    /// (for `parse_client_hello`: relative to the TLS record, i.e. TCP payload start)
    pub sni_off: usize,
}

fn be16(p: &[u8], i: usize) -> Option<usize> {
    Some(u16::from_be_bytes([*p.get(i)?, *p.get(i + 1)?]) as usize)
}

/// `p` starts at the Handshake header (type=1). Tolerates truncation after the SNI extension,
/// which matters for big (post-quantum) ClientHellos split over several TCP segments.
pub fn parse_handshake(p: &[u8], base: usize) -> Option<Hello> {
    if *p.first()? != 1 {
        return None;
    }
    let mut i = 4 + 2 + 32; // hs header + legacy_version + random
    let sid = *p.get(i)? as usize;
    i += 1 + sid;
    let cs = be16(p, i)?;
    i += 2 + cs;
    let cm = *p.get(i)? as usize;
    i += 1 + cm;
    let el = be16(p, i)?;
    i += 2;
    let end = p.len().min(i + el);
    while i + 4 <= end {
        let et = be16(p, i)?;
        let l = be16(p, i + 2)?;
        i += 4;
        if et == 0 {
            // server_name_list: len(2) | type(1) | name_len(2) | name
            let nl = be16(p, i + 3)?;
            let s = i + 5;
            let name = p.get(s..s + nl)?;
            let sni = std::str::from_utf8(name).ok()?.to_string();
            return Some(Hello { sni, sni_off: base + s });
        }
        i += l;
    }
    None
}

/// `p` = TCP payload starting with a TLS record.
pub fn parse_client_hello(p: &[u8]) -> Option<Hello> {
    if p.len() < 10 || p[0] != 0x16 || p[1] != 3 {
        return None;
    }
    parse_handshake(&p[5..], 5)
}

fn push_ext(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
    out.extend_from_slice(&ty.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// Plausible TLS 1.3 ClientHello carrying `sni`; used as the decoy payload for fakes.
pub fn build_fake_client_hello(sni: &str) -> Vec<u8> {
    let name = sni.as_bytes();
    let mut sn = Vec::new();
    sn.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sn.push(0);
    sn.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sn.extend_from_slice(name);

    let mut ext = Vec::new();
    push_ext(&mut ext, 0x0000, &sn);
    push_ext(&mut ext, 0x000a, &[0, 4, 0, 0x1d, 0, 0x17]);
    push_ext(&mut ext, 0x000d, &[0, 8, 4, 3, 8, 4, 4, 1, 5, 3]);
    push_ext(&mut ext, 0x002b, &[2, 3, 4]);
    let mut ks = vec![0, 36, 0, 0x1d, 0, 32];
    ks.extend((0..32).map(|_| fastrand::u8(..)));
    push_ext(&mut ext, 0x0033, &ks);

    let mut body = vec![3, 3];
    body.extend((0..32).map(|_| fastrand::u8(..)));
    body.push(32);
    body.extend((0..32).map(|_| fastrand::u8(..)));
    body.extend_from_slice(&[0, 6, 0x13, 0x01, 0x13, 0x02, 0xc0, 0x2b]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let bl = body.len();
    let mut hs = vec![1, (bl >> 16) as u8, (bl >> 8) as u8, bl as u8];
    hs.extend_from_slice(&body);

    let mut rec = vec![0x16, 3, 1];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}
