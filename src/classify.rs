use crate::descramble::{ScrambleMode, detect_scramble_mode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileTypeInfo {
    pub label: &'static str,
    pub extension: &'static str,
}

impl FileTypeInfo {
    const fn new(label: &'static str, extension: &'static str) -> Self {
        Self { label, extension }
    }

    pub fn is_recognized_header(self) -> bool {
        !matches!(
            self.label,
            "Unknown binary (.bin)"
                | "All zeros (empty/unfiltered?)"
                | "Null-padded binary (.bin)"
        )
    }
}

/// Classify an extracted file buffer by its magic bytes/header (matching and extending `scan_headers.py`).
pub fn classify_bytes(data: &[u8]) -> FileTypeInfo {
    if data.is_empty() {
        return FileTypeInfo::new("Empty file", "bin");
    }

    if data.starts_with(b"TJS2100\0") {
        return FileTypeInfo::new("TJS2 bytecode (.tjs)", "tjs");
    }
    if data.starts_with(b"\x89PNG\r\n\x1a\n") || data.starts_with(b"\x89PNG") {
        return FileTypeInfo::new("PNG image (.png)", "png");
    }
    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return FileTypeInfo::new("JPEG image (.jpg)", "jpg");
    }
    if data.starts_with(b"TLGref") {
        return FileTypeInfo::new("TLG reference image (.tlg)", "tlg");
    }
    if data.starts_with(b"TLG0") || data.starts_with(b"TLG5.0") || data.starts_with(b"TLG6.0") {
        return FileTypeInfo::new("TLG image (.tlg)", "tlg");
    }
    if data.starts_with(b"OggS") {
        let head = &data[..data.len().min(64)];
        if head.windows(8).any(|w| w == b"OpusHead") {
            return FileTypeInfo::new("Opus/OGG audio (.opus)", "opus");
        }
        return FileTypeInfo::new("OGG audio (.ogg)", "ogg");
    }
    if data.starts_with(b"Opus") {
        return FileTypeInfo::new("Opus audio (.opus)", "opus");
    }
    if data.starts_with(b"RIFF") && data.len() >= 12 {
        if &data[8..12] == b"WAVE" {
            return FileTypeInfo::new("RIFF/WAVE audio (.wav)", "wav");
        }
        if &data[8..12] == b"WEBP" {
            return FileTypeInfo::new("WebP image (.webp)", "webp");
        }
        return FileTypeInfo::new("RIFF media (.riff)", "riff");
    }
    if data.starts_with(b"AMV1") {
        return FileTypeInfo::new("AMV video (.amv)", "amv");
    }
    if data.starts_with(&[0x30, 0x26, 0xB2, 0x75]) {
        return FileTypeInfo::new("WMV/ASF video (.wmv)", "wmv");
    }
    if data.len() >= 8 && &data[4..8] == b"ftyp" {
        return FileTypeInfo::new("MP4 video (.mp4)", "mp4");
    }
    if data.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        return FileTypeInfo::new("WebM/MKV video (.webm)", "webm");
    }
    if data.starts_with(b"MZ") {
        return FileTypeInfo::new("PE/DLL executable (.dll)", "dll");
    }
    if data.starts_with(&[0x1B, 0x4C, 0x4A, 0x01]) {
        return FileTypeInfo::new("KAG scenario (.ks)", "ks");
    }
    if data.starts_with(b"XBND") {
        return FileTypeInfo::new("XBND bundle (.xbnd)", "xbnd");
    }
    if data.starts_with(b"PSB\0") {
        return FileTypeInfo::new("PSB container (.psb)", "psb");
    }
    if data.starts_with(b"mdf\0") {
        return FileTypeInfo::new("MDF/PSB compressed (.psb)", "psb");
    }
    if data.starts_with(b"TJS/ns0") {
        return FileTypeInfo::new("TJS/ns0 binary data (.pbd)", "pbd");
    }
    if data.starts_with(b"TJS/4s0") {
        return FileTypeInfo::new("TJS/4s0 compressed data (.pbd)", "pbd");
    }
    if data.starts_with(b"OTTO") {
        return FileTypeInfo::new("OpenType font (.otf)", "otf");
    }
    if data.len() >= 16 && data.starts_with(&[0x00, 0x01, 0x00, 0x00]) {
        let head = &data[12..data.len().min(128)];
        if head.windows(4).any(|w| matches!(w, b"GSUB" | b"head" | b"cmap" | b"glyf")) {
            return FileTypeInfo::new("TrueType font (.ttf)", "ttf");
        }
    }
    if data.starts_with(b"TVP pre-rendered") {
        return FileTypeInfo::new("TVP pre-rendered font (.tft)", "tft");
    }
    if data.starts_with(b"#2.") || data.starts_with(b"# 2.") {
        return FileTypeInfo::new("SLI loop info (.sli)", "sli");
    }
    if let Some(mode) = detect_scramble_mode(data) {
        return match mode {
            ScrambleMode::Mode0Xor => {
                FileTypeInfo::new("Kirikiri scrambled text (mode0_xor)", "txt")
            }
            ScrambleMode::Mode1BitSwap => {
                FileTypeInfo::new("Kirikiri scrambled text (mode1_bitswap)", "txt")
            }
            ScrambleMode::Mode2Zlib => {
                FileTypeInfo::new("Kirikiri scrambled text (mode2_zlib)", "txt")
            }
        };
    }
    if data.starts_with(b"BM") && data.len() >= 14 {
        let bmp_size = u32::from_le_bytes(data[2..6].try_into().unwrap()) as usize;
        if bmp_size == data.len() {
            return FileTypeInfo::new("BMP image (.bmp)", "bmp");
        }
    }
    if data.starts_with(&[0xFF, 0xFE]) {
        return FileTypeInfo::new("UTF-16LE text (.txt)", "txt");
    }
    if data.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return FileTypeInfo::new("UTF-8 text (.txt)", "txt");
    }
    if data.len() >= 4 && data[..4] == [0, 0, 0, 0] {
        let sample = &data[..data.len().min(32)];
        if sample.iter().all(|&b| b == 0) {
            return FileTypeInfo::new("All zeros (empty/unfiltered?)", "bin");
        }
        return FileTypeInfo::new("Null-padded binary (.bin)", "bin");
    }

    // Plain ASCII/UTF-8 text detection
    let sample = &data[..data.len().min(256)];
    if std::str::from_utf8(sample).is_ok()
        && sample
            .iter()
            .all(|&b| b >= 0x20 || matches!(b, b'\t' | b'\r' | b'\n'))
    {
        return FileTypeInfo::new("Plain UTF-8 text (.txt)", "txt");
    }

    FileTypeInfo::new("Unknown binary (.bin)", "bin")
}
