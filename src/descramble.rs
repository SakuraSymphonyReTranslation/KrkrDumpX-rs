use anyhow::{Result, bail};
use flate2::read::ZlibDecoder;
use std::io::Read;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrambleMode {
    Mode0Xor,
    Mode1BitSwap,
    Mode2Zlib,
}

pub fn detect_scramble_mode(data: &[u8]) -> Option<ScrambleMode> {
    if data.len() < 5 || data[0] != 0xFE || data[1] != 0xFE || data[3] != 0xFF || data[4] != 0xFE {
        return None;
    }
    match data[2] {
        0 => Some(ScrambleMode::Mode0Xor),
        1 => Some(ScrambleMode::Mode1BitSwap),
        2 => Some(ScrambleMode::Mode2Zlib),
        _ => None,
    }
}

/// Descramble Kirikiri scrambled UTF-16LE text (`FE FE <mode> FF FE ...`),
/// returning `(mode, descrambled_utf16le_bytes_without_bom)`.
pub fn descramble_bytes(data: &[u8]) -> Result<(ScrambleMode, Vec<u8>)> {
    let Some(mode) = detect_scramble_mode(data) else {
        bail!("data does not have a valid Kirikiri scrambled text header (FE FE xx FF FE)");
    };

    let body = &data[5..];
    match mode {
        ScrambleMode::Mode0Xor => {
            let mut out = body.to_vec();
            let pairs = out.len() / 2;
            for i in 0..pairs {
                let lo = out[i * 2];
                let hi = out[i * 2 + 1];
                if hi == 0 && lo < 0x20 {
                    continue;
                }
                out[i * 2 + 1] = hi ^ (lo & 0xFE);
                out[i * 2] = lo ^ 1;
            }
            Ok((mode, out))
        }
        ScrambleMode::Mode1BitSwap => {
            let mut out = body.to_vec();
            let pairs = out.len() / 2;
            for i in 0..pairs {
                let c = u16::from_le_bytes([out[i * 2], out[i * 2 + 1]]);
                let swapped = ((c & 0xAAAA) >> 1) | ((c & 0x5555) << 1);
                let b = swapped.to_le_bytes();
                out[i * 2] = b[0];
                out[i * 2 + 1] = b[1];
            }
            Ok((mode, out))
        }
        ScrambleMode::Mode2Zlib => {
            // Header after FE FE 02 FF FE: i64 compressed_len, i64 uncompressed_len, then zlib stream
            if data.len() < 23 {
                bail!("mode2 scrambled text header too short");
            }
            let mut decoder = ZlibDecoder::new(&data[21..]);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out)?;
            Ok((mode, out))
        }
    }
}

/// Decode a Kirikiri text buffer (scrambled UTF-16LE, UTF-16LE with BOM, UTF-8 with/without BOM,
/// or BOM-less UTF-16LE) into a Rust `String`.
pub fn decode_kirikiri_text(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return Some(String::new());
    }

    if let Ok((_, descrambled)) = descramble_bytes(data) {
        return Some(utf16le_to_string(&descrambled));
    }

    if data.starts_with(&[0xFF, 0xFE]) {
        return Some(utf16le_to_string(&data[2..]));
    }

    if data.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return std::str::from_utf8(&data[3..]).ok().map(|s| s.to_string());
    }

    if let Ok(s) = std::str::from_utf8(data) {
        // Ensure it is plausibly text (very few NUL/control bytes)
        let bad = s
            .bytes()
            .take(512)
            .filter(|&b| b == 0 || (b < 0x20 && !matches!(b, b'\t' | b'\r' | b'\n')))
            .count();
        if bad == 0 {
            return Some(s.to_string());
        }
    }

    // Heuristic: BOM-less UTF-16LE (many even-indexed ASCII bytes paired with 0x00 high bytes)
    if data.len() >= 4 && data.len() % 2 == 0 {
        let sample = &data[..data.len().min(256)];
        let ascii_u16_pairs = sample
            .chunks_exact(2)
            .filter(|c| c[1] == 0 && (c[0].is_ascii_graphic() || matches!(c[0], b' ' | b'\t' | b'\r' | b'\n')))
            .count();
        if ascii_u16_pairs * 2 >= sample.len() / 2 {
            return Some(utf16le_to_string(data));
        }
    }

    None
}

fn utf16le_to_string(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let s = String::from_utf16_lossy(&units);
    s.trim_start_matches('\u{feff}').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode0_and_mode1_roundtrip() {
        let text = "hello\r\nworld";
        let utf16: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();

        // Mode 1 is self-inverse
        let mut m1 = vec![0xFE, 0xFE, 0x01, 0xFF, 0xFE];
        for c in utf16.chunks_exact(2) {
            let v = u16::from_le_bytes([c[0], c[1]]);
            let s = ((v & 0xAAAA) >> 1) | ((v & 0x5555) << 1);
            m1.extend_from_slice(&s.to_le_bytes());
        }
        assert_eq!(decode_kirikiri_text(&m1).as_deref(), Some(text));

        // Mode 0 inverse check
        let mut m0 = vec![0xFE, 0xFE, 0x00, 0xFF, 0xFE];
        for c in utf16.chunks_exact(2) {
            let (mut lo, mut hi) = (c[0], c[1]);
            if !(hi == 0 && lo < 0x20) {
                lo ^= 1;
                hi ^= lo & 0xFE;
            }
            m0.push(lo);
            m0.push(hi);
        }
        assert_eq!(decode_kirikiri_text(&m0).as_deref(), Some(text));
    }
}
