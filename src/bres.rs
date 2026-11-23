use anyhow::{Result, bail};
use sha3::{Digest, Sha3_384};

const CHACHA_CONST: [u32; 4] = [0x6170_7865, 0x3320_646E, 0x7962_2D32, 0x6B20_6574];

#[inline]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

pub fn chacha8_block(initial: &[u32; 16]) -> [u8; 64] {
    let mut s = *initial;
    for _ in 0..4 {
        // Column rounds
        quarter_round(&mut s, 0, 4, 8, 12);
        quarter_round(&mut s, 1, 5, 9, 13);
        quarter_round(&mut s, 2, 6, 10, 14);
        quarter_round(&mut s, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(&mut s, 0, 5, 10, 15);
        quarter_round(&mut s, 1, 6, 11, 12);
        quarter_round(&mut s, 2, 7, 8, 13);
        quarter_round(&mut s, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = s[i].wrapping_add(initial[i]).to_le_bytes();
        out[i * 4..i * 4 + 4].copy_from_slice(&word);
    }
    out
}

pub fn encode_utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

pub fn decode_utf16le_lossy(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let trimmed_len = units
        .iter()
        .rposition(|&u| u != 0)
        .map(|i| i + 1)
        .unwrap_or(0);
    String::from_utf16_lossy(&units[..trimmed_len])
}

pub fn decode_bres_root(text_resource: &[u8]) -> Result<String> {
    let text = decode_utf16le_lossy(text_resource);
    let marker = "bres://./";
    let Some(rest) = text.strip_prefix(marker) else {
        bail!("unexpected TEXT/127 bres root string: {text:?}");
    };
    let key = rest.trim_matches('/').to_string();
    if key.is_empty() {
        bail!("empty bres path key in TEXT/127: {text:?}");
    }
    Ok(key)
}

pub fn bres_key_from_url(url: &str) -> Result<String> {
    let marker = "bres://./";
    let Some(rest) = url.strip_prefix(marker) else {
        bail!("not a local bres URL: {url:?}");
    };
    let key = rest.split('/').next().unwrap_or("").to_string();
    if key.is_empty() {
        bail!("empty bres key in URL: {url:?}");
    }
    Ok(key)
}

#[derive(Debug, Clone, Copy)]
pub struct BresCipherParams {
    pub key_words: [u32; 8],
    pub nonce_words: [u32; 2],
    pub ctr_base: u32,
    pub ctr_high: u32,
}

impl BresCipherParams {
    pub fn derive(path_key: &str, salt: &[u8]) -> Self {
        let mut hasher = Sha3_384::new();
        hasher.update(encode_utf16le(path_key));
        hasher.update(salt);
        let digest = hasher.finalize();
        Self::from_digest(&digest)
    }

    pub fn derive_with_prefix_hasher(prefix_hasher: &Sha3_384, salt: &[u8]) -> Self {
        let mut hasher = prefix_hasher.clone();
        hasher.update(salt);
        let digest = hasher.finalize();
        Self::from_digest(&digest)
    }

    fn from_digest(digest: &[u8]) -> Self {
        let mut key_words = [0u32; 8];
        for i in 0..8 {
            key_words[i] = u32::from_le_bytes(digest[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let nonce_words = [
            u32::from_le_bytes(digest[32..36].try_into().unwrap()),
            u32::from_le_bytes(digest[36..40].try_into().unwrap()),
        ];
        let ctr_base = u32::from_le_bytes(digest[40..44].try_into().unwrap());
        let ctr_high = u32::from_le_bytes(digest[44..48].try_into().unwrap());
        Self {
            key_words,
            nonce_words,
            ctr_base,
            ctr_high,
        }
    }

    #[inline]
    pub fn keystream_block(&self, block_num: u32) -> [u8; 64] {
        let state = [
            CHACHA_CONST[0],
            CHACHA_CONST[1],
            CHACHA_CONST[2],
            CHACHA_CONST[3],
            self.key_words[0],
            self.key_words[1],
            self.key_words[2],
            self.key_words[3],
            self.key_words[4],
            self.key_words[5],
            self.key_words[6],
            self.key_words[7],
            self.ctr_base ^ block_num,
            self.ctr_high,
            self.nonce_words[0],
            self.nonce_words[1],
        ];
        chacha8_block(&state)
    }
}

pub fn decrypt_bres(ciphertext: &[u8], path_key: &str, salt: &[u8]) -> Vec<u8> {
    let params = BresCipherParams::derive(path_key, salt);
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for (bn, chunk) in ciphertext.chunks(64).enumerate() {
        let ks = params.keystream_block(bn as u32);
        for (i, &b) in chunk.iter().enumerate() {
            plaintext.push(b ^ ks[i]);
        }
    }
    plaintext
}

/// Fast verification of a candidate 0x2000-byte bres salt by decrypting only the first 8 bytes
/// of STARTUP.TJS and checking for `TJS2100\0`.
pub fn verify_startup_salt_fast(
    startup_prefix_hasher: &Sha3_384,
    startup_cipher_head: &[u8; 8],
    salt: &[u8],
) -> bool {
    let params = BresCipherParams::derive_with_prefix_hasher(startup_prefix_hasher, salt);
    let ks = params.keystream_block(0);
    let expected = b"TJS2100\0";
    for i in 0..8 {
        if (startup_cipher_head[i] ^ ks[i]) != expected[i] {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_bres_root() {
        let raw = encode_utf16le("bres://./9kpzeqme93usra66re54h69ymi/\0");
        assert_eq!(
            decode_bres_root(&raw).unwrap(),
            "9kpzeqme93usra66re54h69ymi"
        );
    }

    #[test]
    fn test_bres_roundtrip_and_fast_verify() {
        let salt = vec![0x42u8; 0x2000];
        let key = "9kpzeqme93usra66re54h69ymi";
        let plain = b"TJS2100\0hello kirikiri world payload test data 0123456789abcdef";
        let cipher = decrypt_bres(plain, key, &salt);
        assert_ne!(&cipher[..8], b"TJS2100\0");
        let recovered = decrypt_bres(&cipher, key, &salt);
        assert_eq!(recovered.as_slice(), plain.as_slice());

        let mut h = Sha3_384::new();
        h.update(encode_utf16le(key));
        let head: [u8; 8] = cipher[..8].try_into().unwrap();
        assert!(verify_startup_salt_fast(&h, &head, &salt));
    }
}
