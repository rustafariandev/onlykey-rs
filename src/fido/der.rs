//! Minimal DER parsing for the ECDSA signature an authenticator returns.
//!
//! CTAP2 returns an ECDSA assertion as an ASN.1 DER `SEQUENCE` of two
//! `INTEGER`s. SSH wants the two scalars back as fixed-width fields (the
//! `sk-ecdsa` signature carries them as mpints), so this only has to
//! understand that one shape.

use super::FidoError;

/// Parse `SEQUENCE { INTEGER r, INTEGER s }` and return `r` and `s`, each
/// left-padded to 32 bytes.
pub fn parse_ecdsa(der: &[u8]) -> Result<([u8; 32], [u8; 32]), FidoError> {
    let mut outer = der;
    let body = read(0x30, &mut outer)?;
    if !outer.is_empty() {
        return Err(FidoError::Signature);
    }
    let mut inner = body;
    let r = read(0x02, &mut inner)?;
    let s = read(0x02, &mut inner)?;
    if !inner.is_empty() {
        return Err(FidoError::Signature);
    }
    Ok((scalar(r)?, scalar(s)?))
}

/// Read one tag-length-value and return its value, advancing `input`.
fn read<'a>(tag: u8, input: &mut &'a [u8]) -> Result<&'a [u8], FidoError> {
    let (&actual, rest) = input.split_first().ok_or(FidoError::Signature)?;
    if actual != tag {
        return Err(FidoError::Signature);
    }
    let (&first, rest) = rest.split_first().ok_or(FidoError::Signature)?;
    let (len, rest) = if first & 0x80 == 0 {
        (first as usize, rest)
    } else {
        let width = (first & 0x7f) as usize;
        if width == 0 || width > 2 || rest.len() < width {
            return Err(FidoError::Signature);
        }
        let (bytes, rest) = rest.split_at(width);
        let len = bytes.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize);
        (len, rest)
    };
    if rest.len() < len {
        return Err(FidoError::Signature);
    }
    let (value, rest) = rest.split_at(len);
    *input = rest;
    Ok(value)
}

/// A DER INTEGER as a 32-byte big-endian scalar, stripping the sign byte.
fn scalar(bytes: &[u8]) -> Result<[u8; 32], FidoError> {
    let bytes = match bytes.first() {
        Some(0) => &bytes[1..],
        _ => bytes,
    };
    if bytes.len() > 32 {
        return Err(FidoError::Signature);
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der(r: &[u8], s: &[u8]) -> Vec<u8> {
        let mut int_r = vec![0x02, r.len() as u8];
        int_r.extend_from_slice(r);
        let mut int_s = vec![0x02, s.len() as u8];
        int_s.extend_from_slice(s);
        let mut body = int_r;
        body.extend_from_slice(&int_s);
        let mut out = vec![0x30, body.len() as u8];
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn parses_with_a_leading_sign_byte() {
        // A high-bit scalar carries a leading 0x00 sign byte in DER.
        let r = vec![0x00, 0x80, 0x01];
        let s = vec![0x01; 32];
        let (got_r, got_s) = parse_ecdsa(&der(&r, &s)).unwrap();
        assert_eq!(got_r[30], 0x80);
        assert_eq!(got_r[31], 0x01);
        assert_eq!(got_r[..30], [0u8; 30]);
        assert_eq!(got_s, [0x01; 32]);
    }

    #[test]
    fn left_pads_a_short_scalar() {
        let (r, s) = parse_ecdsa(&der(&[0x05], &[0x06, 0x07])).unwrap();
        assert_eq!(r[31], 5);
        assert_eq!(s[30..], [6, 7]);
    }

    #[test]
    fn rejects_trailing_and_oversized_data() {
        assert!(parse_ecdsa(&[]).is_err());
        let mut bad = der(&[1], &[2]);
        bad.push(0);
        assert!(parse_ecdsa(&bad).is_err());
        assert!(parse_ecdsa(&der(&[0x01; 33], &[0x02])).is_err());
    }
}
