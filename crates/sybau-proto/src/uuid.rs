//! UUID parsing as done by Xray: a canonical UUID, or any other string
//! mapped to a UUIDv5 in the nil namespace.

use sha1::{Digest, Sha1};

/// Parses `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (dashes optional).
pub fn parse_strict(s: &str) -> Option<[u8; 16]> {
    let hex: Vec<u8> = s.bytes().filter(|b| *b != b'-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, pair) in hex.chunks(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// Accepts a UUID or, like Xray, an arbitrary string of up to 30 bytes
/// that is turned into a UUIDv5 (namespace: nil UUID).
pub fn parse(s: &str) -> Option<[u8; 16]> {
    if let Some(id) = parse_strict(s) {
        return Some(id);
    }
    if s.is_empty() || s.len() > 30 {
        return None;
    }
    let mut h = Sha1::new();
    h.update([0u8; 16]);
    h.update(s.as_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out[6] = (out[6] & 0x0f) | 0x50;
    out[8] = (out[8] & 0x3f) | 0x80;
    Some(out)
}

pub fn format(id: &[u8; 16]) -> String {
    let h: String = id.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_roundtrip() {
        let s = "b831381d-6324-4d53-ad4f-8cda48b30811";
        assert_eq!(format(&parse(s).unwrap()), s);
        assert_eq!(parse("b831381d63244d53ad4f8cda48b30811"), parse(s));
    }

    #[test]
    fn free_form_strings_map_like_xray() {
        // `xray uuid -i example` prints this value.
        assert_eq!(
            format(&parse("example").unwrap()),
            "feb54431-301b-52bb-a6dd-e1e93e81bb9e"
        );
        assert!(parse("").is_none());
        assert!(parse(&"x".repeat(31)).is_none());
    }
}
