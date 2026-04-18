//! Lightweight L7 protocol detection by first-byte signatures.
//!
//! These heuristics are intentionally simple and cheap. They are used only
//! for profile selection and coarse filtering decisions.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L7Protocol {
    Unknown,
    Stun,
    Discord,
}

pub fn detect_l7(payload: &[u8]) -> L7Protocol {
    if looks_like_stun(payload) {
        return L7Protocol::Stun;
    }
    if looks_like_discord(payload) {
        return L7Protocol::Discord;
    }
    L7Protocol::Unknown
}

pub fn looks_like_stun(payload: &[u8]) -> bool {
    // STUN header: min 20 bytes, top 2 bits in type are zero,
    // magic cookie at bytes 4..8 equals 0x2112A442.
    if payload.len() < 20 {
        return false;
    }
    payload[0] & 0b1100_0000 == 0 && payload[4..8] == [0x21, 0x12, 0xA4, 0x42]
}

fn looks_like_discord(payload: &[u8]) -> bool {
    looks_like_discord_rtp(payload) || looks_like_discord_dtls(payload)
}

fn looks_like_discord_rtp(payload: &[u8]) -> bool {
    // Discord voice often uses RTP with dynamic payload types around 120.
    if payload.len() < 12 {
        return false;
    }
    let version_ok = (payload[0] & 0b1100_0000) == 0b1000_0000;
    let pt = payload[1] & 0x7f;
    version_ok && matches!(pt, 0x78..=0x7a)
}

fn looks_like_discord_dtls(payload: &[u8]) -> bool {
    // DTLS record header used by Discord voice transport.
    if payload.len() < 13 {
        return false;
    }
    let content_type = payload[0];
    let version_major = payload[1];
    let version_minor = payload[2];
    matches!(content_type, 20..=23) && version_major == 0xfe && matches!(version_minor, 0xfd | 0xff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_l7_stun() {
        let mut payload = [0u8; 20];
        payload[0] = 0x00;
        payload[1] = 0x01;
        payload[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        assert_eq!(detect_l7(&payload), L7Protocol::Stun);
    }

    #[test]
    fn test_detect_l7_discord_rtp() {
        let mut payload = [0u8; 12];
        payload[0] = 0x80;
        payload[1] = 0x78;
        assert_eq!(detect_l7(&payload), L7Protocol::Discord);
    }

    #[test]
    fn test_detect_l7_discord_dtls() {
        let mut payload = [0u8; 13];
        payload[0] = 22;
        payload[1] = 0xfe;
        payload[2] = 0xfd;
        assert_eq!(detect_l7(&payload), L7Protocol::Discord);
    }

    #[test]
    fn test_detect_l7_unknown() {
        let payload = [0x16, 0x03, 0x01, 0x00, 0x20];
        assert_eq!(detect_l7(&payload), L7Protocol::Unknown);
    }
}
