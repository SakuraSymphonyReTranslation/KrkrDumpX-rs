use anyhow::{Result, bail};
use blake2::Blake2sMac256;
use blake2::digest::{KeyInit, Mac};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum PbdValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Octet(Vec<u8>),
    Array(Vec<PbdValue>),
    Dict(BTreeMap<String, PbdValue>),
}

impl PbdValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            PbdValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            PbdValue::Int(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[PbdValue]> {
        match self {
            PbdValue::Array(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&BTreeMap<String, PbdValue>> {
        match self {
            PbdValue::Dict(m) => Some(m),
            _ => None,
        }
    }
}

// =============================================================================
// Pure-Rust XXH32 (used for PackinOne TJS/4s0 ChaCha nonce derivation)
// =============================================================================

fn xxh32(input: &[u8], seed: u32) -> u32 {
    const P1: u32 = 0x9E37_79B1;
    const P2: u32 = 0x85EB_CA77;
    const P3: u32 = 0xC2B2_AE3D;
    const P4: u32 = 0x27D4_EB2F;
    const P5: u32 = 0x1656_67B1;

    let len = input.len();
    let mut p = 0usize;
    let mut h32: u32;

    if len >= 16 {
        let mut v1 = seed.wrapping_add(P1).wrapping_add(P2);
        let mut v2 = seed.wrapping_add(P2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(P1);

        while p + 16 <= len {
            let k1 = u32::from_le_bytes(input[p..p + 4].try_into().unwrap());
            let k2 = u32::from_le_bytes(input[p + 4..p + 8].try_into().unwrap());
            let k3 = u32::from_le_bytes(input[p + 8..p + 12].try_into().unwrap());
            let k4 = u32::from_le_bytes(input[p + 12..p + 16].try_into().unwrap());
            v1 = v1.wrapping_add(k1.wrapping_mul(P2)).rotate_left(13).wrapping_mul(P1);
            v2 = v2.wrapping_add(k2.wrapping_mul(P2)).rotate_left(13).wrapping_mul(P1);
            v3 = v3.wrapping_add(k3.wrapping_mul(P2)).rotate_left(13).wrapping_mul(P1);
            v4 = v4.wrapping_add(k4.wrapping_mul(P2)).rotate_left(13).wrapping_mul(P1);
            p += 16;
        }
        h32 = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
    } else {
        h32 = seed.wrapping_add(P5);
    }

    h32 = h32.wrapping_add(len as u32);

    while p + 4 <= len {
        let k = u32::from_le_bytes(input[p..p + 4].try_into().unwrap());
        h32 = h32.wrapping_add(k.wrapping_mul(P3)).rotate_left(17).wrapping_mul(P4);
        p += 4;
    }

    while p < len {
        h32 = h32
            .wrapping_add((input[p] as u32).wrapping_mul(P5))
            .rotate_left(11)
            .wrapping_mul(P1);
        p += 1;
    }

    h32 ^= h32 >> 15;
    h32 = h32.wrapping_mul(P2);
    h32 ^= h32 >> 13;
    h32 = h32.wrapping_mul(P3);
    h32 ^= h32 >> 16;
    h32
}

// =============================================================================
// PackinOne TJS/4s0 stream decrypt (BLAKE2s + XXH32 + ChaCha + xorshift32)
// and framed rolling-dictionary LZ4 stream decompression
// =============================================================================

fn four_s0_crypt_params(field: u16) -> Result<(u32, u32)> {
    match field {
        1 => Ok((8, 0x10)),
        2 => Ok((0xC, 8)),
        3 => Ok((0x14, 4)),
        4 => Ok((8, 1)),
        5 => Ok((0xC, 1)),
        6 => Ok((0x14, 1)),
        _ => bail!("unsupported TJS/4s0 crypt field: {field}"),
    }
}

fn four_s0_derive_key(seed: u32, iv: &[u8]) -> Result<[u8; 32]> {
    let mut mac = <Blake2sMac256 as KeyInit>::new_from_slice(&seed.to_le_bytes())
        .map_err(|e| anyhow::anyhow!("blake2s key init failed: {e}"))?;
    Mac::update(&mut mac, iv);
    let out = Mac::finalize(mac).into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    Ok(key)
}

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

fn chacha_block_rounds(
    key: &[u8; 32],
    nonce_lo: u32,
    nonce_hi: u32,
    block_counter: u64,
    rounds: u32,
) -> [u8; 64] {
    let mut st = [0u32; 16];
    st[0] = 0x6170_7865;
    st[1] = 0x3320_646E;
    st[2] = 0x7962_2D32;
    st[3] = 0x6B20_6574;
    for i in 0..8 {
        st[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    st[12] = block_counter as u32;
    st[13] = (block_counter >> 32) as u32;
    st[14] = nonce_lo;
    st[15] = nonce_hi;

    let mut x = st;
    let mut r = rounds;
    while r >= 2 {
        quarter_round(&mut x, 0, 4, 8, 12);
        quarter_round(&mut x, 1, 5, 9, 13);
        quarter_round(&mut x, 2, 6, 10, 14);
        quarter_round(&mut x, 3, 7, 11, 15);
        quarter_round(&mut x, 0, 5, 10, 15);
        quarter_round(&mut x, 1, 6, 11, 12);
        quarter_round(&mut x, 2, 7, 8, 13);
        quarter_round(&mut x, 3, 4, 9, 14);
        r -= 2;
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&x[i].wrapping_add(st[i]).to_le_bytes());
    }
    out
}

#[inline]
fn xorshift32(mut x: u32, fallback: u32) -> u32 {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    if x == 0 { fallback } else { x }
}

fn gen_ks_buffer(
    key: &[u8; 32],
    nonce_lo: u32,
    nonce_hi: u32,
    block_counter: u64,
    expand: u32,
    rounds: u32,
    fallback: u32,
) -> Vec<u8> {
    let block = chacha_block_rounds(key, nonce_lo, nonce_hi, block_counter, rounds);
    if expand <= 1 {
        return block.to_vec();
    }
    let mut words = Vec::with_capacity((expand as usize) * 16);
    for i in 0..16 {
        words.push(u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap()));
    }
    let mut src_i = 0usize;
    let extra_groups = (expand as usize) * 4 - 4;
    for _ in 0..extra_groups {
        for _ in 0..4 {
            let w = words[src_i];
            src_i += 1;
            words.push(xorshift32(w, fallback));
        }
    }
    let mut out = Vec::with_capacity(words.len() * 4);
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

fn four_s0_decrypt(body: &[u8], seed: u32, iv: &[u8], crypt: u16) -> Result<Vec<u8>> {
    let (rounds, expand) = four_s0_crypt_params(crypt)?;
    let key = four_s0_derive_key(seed, iv)?;
    let nonce_lo = xxh32(iv, seed);
    let nonce_hi = seed;
    let mut fallback = nonce_hi ^ nonce_lo;
    if fallback == 0 {
        fallback = if seed != 0 { seed } else { 0xFFFF_FFFF };
    }

    let mut out = Vec::with_capacity(body.len());
    let mut produced = 0usize;
    let mut bc = 0u64;
    while produced < body.len() {
        let ks = gen_ks_buffer(&key, nonce_lo, nonce_hi, bc, expand, rounds, fallback);
        let n = ks.len().min(body.len() - produced);
        for i in 0..n {
            out.push(body[produced + i] ^ ks[i]);
        }
        produced += n;
        bc += 1;
    }
    Ok(out)
}

fn lz4_decompress_chunk_with_dict(chunk: &[u8], dict: &[u8]) -> Option<Vec<u8>> {
    let sizes = [
        4096usize,
        2048,
        1024,
        512,
        256,
        chunk.len().saturating_mul(4),
        chunk.len().saturating_mul(8),
        65536,
    ];
    for &max_out in &sizes {
        if max_out == 0 {
            continue;
        }
        let res = if dict.is_empty() {
            lz4_flex::block::decompress(chunk, max_out)
        } else {
            lz4_flex::block::decompress_with_dict(chunk, max_out, dict)
        };
        if let Ok(decoded) = res {
            return Some(decoded);
        }
    }
    None
}

/// Decompress PackinOne framed LZ4 stream: `[u16 LE csize][LZ4 block]*` with 64 KiB rolling dict.
fn four_s0_lz4_stream_decompress(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let mut pos = 0usize;
    let mut out = Vec::new();
    while pos + 2 <= data.len() {
        let csize = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
        if csize == 0 || pos + 2 + csize > data.len() {
            break;
        }
        let chunk = &data[pos + 2..pos + 2 + csize];
        let dict: &[u8] = if out.len() > 65536 {
            &out[out.len() - 65536..]
        } else {
            &out[..]
        };
        let got = lz4_decompress_chunk_with_dict(chunk, dict).or_else(|| {
            if !dict.is_empty() {
                lz4_decompress_chunk_with_dict(chunk, &[])
            } else {
                None
            }
        });
        let Some(block) = got else {
            break;
        };
        out.extend_from_slice(&block);
        pos += 2 + csize;
    }

    if out.is_empty() {
        if let Ok(d) = lz4_flex::block::decompress(data, 1 << 20) {
            return Ok(d);
        }
        if data.len() > 2 {
            if let Ok(d) = lz4_flex::block::decompress(&data[2..], 1 << 20) {
                return Ok(d);
            }
        }
        bail!(
            "failed to decompress TJS/4s0 LZ4 stream (consumed={pos}, len={})",
            data.len()
        );
    }
    Ok(out)
}

// =============================================================================
// TypeByte checkers & Variant stream reader (TJS/ns0 & TJS/4s0)
// =============================================================================

trait TypeCheck {
    fn next_check_byte(&mut self, typ_byte: u8) -> u8;
}

struct Ns0ByteChecker {
    seed: [u8; 4],
}

impl Ns0ByteChecker {
    fn new(seed: u32) -> Self {
        Self {
            seed: seed.to_le_bytes(),
        }
    }

    fn step(&mut self) {
        let a = self.seed[0] ^ self.seed[0].wrapping_mul(2);
        let mut b = a;
        b >>= 2;
        b ^= self.seed[2];
        b >>= 3;
        b ^= self.seed[2];
        b ^= a;
        self.seed[0] = self.seed[1];
        self.seed[1] = self.seed[2];
        self.seed[2] = b;
    }
}

impl TypeCheck for Ns0ByteChecker {
    fn next_check_byte(&mut self, typ_byte: u8) -> u8 {
        if typ_byte == 0 {
            return self.seed[2];
        }
        self.step();
        self.seed[2]
    }
}

struct FourS0ByteChecker {
    b0: u8,
    b1: u8,
    b2: u8,
}

impl FourS0ByteChecker {
    fn new(seed: u32) -> Self {
        Self {
            b0: ((seed >> 24) as u8) ^ (seed as u8),
            b1: (seed >> 8) as u8,
            b2: (seed >> 16) as u8,
        }
    }

    fn step(&mut self) -> u8 {
        let t = self.b0 ^ self.b0.wrapping_shl(1);
        self.b0 = self.b1;
        self.b1 = self.b2;
        self.b2 = self.b2 ^ (self.b2 >> 3) ^ t ^ (t >> 5);
        self.b2
    }
}

impl TypeCheck for FourS0ByteChecker {
    fn next_check_byte(&mut self, typ_byte: u8) -> u8 {
        if typ_byte == 0 {
            self.b2
        } else {
            self.step()
        }
    }
}

struct VariantReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> VariantReader<'a> {
    fn new(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos }
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let slice = self
            .data
            .get(self.pos..self.pos + n)
            .ok_or_else(|| anyhow::anyhow!("truncated PBD stream at 0x{:x}", self.pos))?;
        self.pos += n;
        Ok(slice)
    }

    fn read_u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.read_bytes(2)?.try_into().unwrap()))
    }

    fn read_u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read_bytes(4)?.try_into().unwrap()))
    }

    fn read_i64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.read_bytes(8)?.try_into().unwrap()))
    }

    fn read_f64(&mut self) -> Result<f64> {
        Ok(f64::from_le_bytes(self.read_bytes(8)?.try_into().unwrap()))
    }

    fn read_utf16le_string(&mut self) -> Result<String> {
        let char_len = self.read_u32()? as usize;
        if char_len > 1_000_000 {
            bail!("implausible PBD string length {char_len}");
        }
        let raw = self.read_bytes(char_len * 2)?;
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Ok(String::from_utf16_lossy(&units))
    }

    fn read_value<C: TypeCheck>(&mut self, checker: &mut C, depth: usize) -> Result<PbdValue> {
        if depth > 64 {
            bail!("PBD recursion limit exceeded");
        }
        let typ = self.read_u16()?;
        let typ_byte = (typ & 0xFF) as u8;
        let check_byte = (typ >> 8) as u8;
        let expected = checker.next_check_byte(typ_byte);
        if check_byte != expected {
            bail!(
                "PBD TypeByte check mismatch at 0x{:x}: typ=0x{typ_byte:02x}, expected=0x{expected:02x}, got=0x{check_byte:02x}",
                self.pos - 2
            );
        }

        match typ_byte {
            0 => Ok(PbdValue::Null),
            2 => Ok(PbdValue::String(self.read_utf16le_string()?)),
            3 => {
                let len = self.read_u32()? as usize;
                Ok(PbdValue::Octet(self.read_bytes(len)?.to_vec()))
            }
            4 => Ok(PbdValue::Int(self.read_i64()?)),
            5 => Ok(PbdValue::Float(self.read_f64()?)),
            0x81 => {
                let count = self.read_u32()? as usize;
                if count > 1_000_000 {
                    bail!("implausible PBD array count {count}");
                }
                let mut arr = Vec::with_capacity(count);
                for _ in 0..count {
                    arr.push(self.read_value(checker, depth + 1)?);
                }
                Ok(PbdValue::Array(arr))
            }
            0xC1 => {
                let count = self.read_u32()? as usize;
                if count > 1_000_000 {
                    bail!("implausible PBD dict count {count}");
                }
                let mut map = BTreeMap::new();
                for _ in 0..count {
                    let key = self.read_utf16le_string()?;
                    let val = self.read_value(checker, depth + 1)?;
                    map.insert(key, val);
                }
                Ok(PbdValue::Dict(map))
            }
            other => bail!("unsupported PBD variant tag 0x{other:02x} at 0x{:x}", self.pos - 2),
        }
    }
}

/// Parse a Kirikiri `.pbd` binary data file (`TJS/ns0\0` or PackinOne encrypted+LZ4 `TJS/4s0\0`).
pub fn parse_pbd(data: &[u8]) -> Result<PbdValue> {
    if data.len() < 16 || &data[0..4] != b"TJS/" {
        bail!("not a TJS/ns0 or TJS/4s0 PBD file");
    }

    let check = &data[4..8];
    let is_4s0 = match check {
        b"4s0\0" => true,
        b"ns0\0" => false,
        _ => bail!("unsupported PBD format header {:?}", &data[0..8]),
    };

    let seed = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let crypt = u16::from_le_bytes(data[12..14].try_into().unwrap());
    let iv_len = u16::from_le_bytes(data[14..16].try_into().unwrap()) as usize;

    if is_4s0 {
        if 16 + iv_len > data.len() {
            bail!("TJS/4s0 IV length {iv_len} exceeds file size");
        }
        let iv = &data[16..16 + iv_len];
        let body = &data[16 + iv_len..];
        let decrypted = if crypt != 0 {
            four_s0_decrypt(body, seed, iv, crypt)?
        } else {
            body.to_vec()
        };
        let plain = four_s0_lz4_stream_decompress(&decrypted)?;

        // Try PackinOne checker first, then standard ns0 checker as fallback
        let mut checker4 = FourS0ByteChecker::new(seed);
        if let Ok(val) = VariantReader::new(&plain, 0).read_value(&mut checker4, 0) {
            return Ok(val);
        }
        let mut checker_ns0 = Ns0ByteChecker::new(seed);
        VariantReader::new(&plain, 0).read_value(&mut checker_ns0, 0)
    } else {
        let mut checker = Ns0ByteChecker::new(seed);
        VariantReader::new(data, 16).read_value(&mut checker, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_four_s0_key_schedule_known_vector() {
        let seed = 0x1435_3CC6u32;
        let key = four_s0_derive_key(seed, b"").unwrap();
        assert_eq!(
            hex::encode(key),
            "2fca145d50b8cb030395f0868c49ed85aa0280c6d0b844c09673351e64408aed"
        );
        let xx = xxh32(b"", seed);
        assert_eq!(xx, 0x9848_23D3);
        let ks = gen_ks_buffer(&key, xx, seed, 0, 0x10, 8, seed ^ xx);
        assert_eq!(
            hex::encode(&ks[..16]),
            "2e9d7adaabc57ee65d0d4f2b440895d5"
        );
    }
}
