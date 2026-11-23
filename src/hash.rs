use crate::bres::encode_utf16le;
use blake2::digest::Mac;
use blake2::{Blake2s256, Blake2sMac256, Digest};

#[inline]
fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);

    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;

    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;

    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

/// Standard SipHash-2-4 returning 8 bytes in little-endian order (matching Hxv4 `domain_hash`).
pub fn siphash24(data: &[u8], key: &[u8; 16]) -> [u8; 8] {
    let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());

    let mut v0 = k0 ^ 0x736f_6d65_7073_6575;
    let mut v1 = k1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = k0 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = k1 ^ 0x7465_6462_7974_6573;

    let mut chunks = data.chunks_exact(8);
    for chunk in chunks.by_ref() {
        let m = u64::from_le_bytes(chunk.try_into().unwrap());
        v3 ^= m;
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }

    let rem = chunks.remainder();
    let mut b = ((data.len() & 0xFF) as u64) << 56;
    for (i, &byte) in rem.iter().enumerate() {
        b |= (byte as u64) << (8 * i);
    }

    v3 ^= b;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= b;

    v2 ^= 0xFF;
    for _ in 0..4 {
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }

    (v0 ^ v1 ^ v2 ^ v3).to_le_bytes()
}

#[derive(Debug, Clone)]
pub struct Hxv4Hasher {
    pub media_name: String,
    pub hash_key: Option<[u8; 32]>,
    pub keyed: bool,
}

impl Default for Hxv4Hasher {
    fn default() -> Self {
        Self {
            media_name: "xp3hnp".to_string(),
            hash_key: None,
            keyed: false,
        }
    }
}

impl Hxv4Hasher {
    pub fn new(media_name: impl Into<String>, hash_key: Option<[u8; 32]>, keyed: bool) -> Self {
        Self {
            media_name: media_name.into(),
            hash_key,
            keyed,
        }
    }

    /// Compute 8-byte Hxv4 `domain_hash` (`pathHash`).
    /// Note: `"/"` is normalized to `""` to match Hxv4 root domain convention.
    pub fn path_hash_bytes(&self, pathname: &str) -> [u8; 8] {
        let norm = if pathname == "/" { "" } else { pathname };
        let mut data = encode_utf16le(norm);
        if !self.media_name.is_empty() {
            data.extend_from_slice(&encode_utf16le(&self.media_name));
        }
        let mut key = [0u8; 16];
        if self.keyed {
            if let Some(hk) = self.hash_key {
                key.copy_from_slice(&hk[..16]);
            }
        }
        siphash24(&data, &key)
    }

    pub fn path_hash_hex(&self, pathname: &str) -> String {
        hex::encode(self.path_hash_bytes(pathname))
    }

    /// Compute 32-byte Hxv4 `file_hash` (`fileHash`).
    pub fn file_hash_bytes(&self, filename: &str) -> [u8; 32] {
        let mut data = encode_utf16le(filename);
        if !self.media_name.is_empty() {
            data.extend_from_slice(&encode_utf16le(&self.media_name));
        }
        if self.keyed {
            if let Some(hk) = self.hash_key {
                let mut mac = Blake2sMac256::new_from_slice(&hk).expect("valid 32-byte key");
                mac.update(&data);
                let out = mac.finalize().into_bytes();
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&out);
                return arr;
            }
        }
        let mut hasher = Blake2s256::new();
        hasher.update(&data);
        let out = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    }

    pub fn file_hash_hex(&self, filename: &str) -> String {
        hex::encode(self.file_hash_bytes(filename))
    }
}

pub fn is_path_hash_hex(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn is_file_hash_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_hxv4_root_path_hash() {
        let hasher = Hxv4Hasher::default();
        assert_eq!(hasher.path_hash_hex(""), "94d4a97c61498621");
        assert_eq!(hasher.path_hash_hex("/"), "94d4a97c61498621");
    }

    #[test]
    fn test_file_hash_deterministic() {
        let hasher = Hxv4Hasher::default();
        let h = hasher.file_hash_hex("startup.tjs");
        assert_eq!(h.len(), 64);
        assert!(is_file_hash_hex(&h));
    }
}
