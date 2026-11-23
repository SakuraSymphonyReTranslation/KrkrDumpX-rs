use crate::bres::{encode_utf16le, verify_startup_salt_fast};
use crate::pe::{PeImage, read_file_offset, read_u32_le};
use anyhow::{Result, bail};
use sha3::{Digest, Sha3_384};
use std::collections::HashSet;
use std::path::Path;

pub const SALT_SIZE: usize = 0x2000;

#[derive(Debug, Clone)]
pub struct SaltCandidate {
    pub kind: &'static str,
    pub salt_offset: usize,
    pub salt_rva: Option<u32>,
    pub salt_va: Option<u64>,
    pub code_rva: Option<u32>,
    pub anchor_name: Option<&'static str>,
    pub anchor_rva: Option<u32>,
    pub anchor_offset: Option<usize>,
}

impl SaltCandidate {
    pub fn source_label(&self, path: &Path) -> String {
        let mut parts = Vec::new();
        if let Some(va) = self.salt_va {
            parts.push(format!("VA 0x{va:x}"));
        }
        if let Some(rva) = self.salt_rva {
            parts.push(format!("RVA 0x{rva:x}"));
        }
        parts.push(format!("file offset 0x{:x}", self.salt_offset));
        let salt_desc = parts.join(" / ");

        if self.kind == "code_assignment" {
            let code = self
                .code_rva
                .map(|r| format!("code RVA 0x{r:x}"))
                .unwrap_or_else(|| "code assignment".to_string());
            return format!("{}:auto {code} salt {salt_desc}", path.display());
        }

        let anchor = self.anchor_name.unwrap_or(self.kind);
        if let Some(rva) = self.anchor_rva {
            format!(
                "{}:auto {anchor} anchor RVA 0x{rva:x} salt {salt_desc}",
                path.display()
            )
        } else if let Some(off) = self.anchor_offset {
            format!(
                "{}:auto {anchor} anchor file offset 0x{off:x} salt {salt_desc}",
                path.display()
            )
        } else {
            format!("{}:auto {anchor} salt {salt_desc}", path.display())
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SaltOverride<'a> {
    pub salt_file: Option<&'a Path>,
    pub salt_rva: Option<u32>,
    pub salt_file_offset: Option<u64>,
    pub allow_full_scan: bool,
}

fn find_subslice_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    let mut positions = Vec::new();
    let mut start = 0;
    while start + needle.len() <= haystack.len() {
        if let Some(rel) = haystack[start..]
            .windows(needle.len())
            .position(|w| w == needle)
        {
            let pos = start + rel;
            positions.push(pos);
            start = pos + 1;
        } else {
            break;
        }
    }
    positions
}

fn make_candidate(
    image: &PeImage,
    kind: &'static str,
    salt_offset: usize,
    seen: &mut HashSet<usize>,
    code_rva: Option<u32>,
    anchor_offset: Option<usize>,
    anchor_name: Option<&'static str>,
) -> Option<SaltCandidate> {
    if seen.contains(&salt_offset) || salt_offset + SALT_SIZE > image.data.len() {
        return None;
    }
    let salt_rva = image.offset_to_rva(salt_offset).ok()?;
    let salt_va = Some(image.image_base + salt_rva as u64);
    let anchor_rva = anchor_offset.and_then(|o| image.offset_to_rva(o).ok());
    seen.insert(salt_offset);
    Some(SaltCandidate {
        kind,
        salt_offset,
        salt_rva: Some(salt_rva),
        salt_va,
        code_rva,
        anchor_name,
        anchor_rva,
        anchor_offset,
    })
}

/// Strategy 1: Scan x86 code for `mov dword ptr [ptr_global], salt_va; ...; mov dword ptr [size_global], 0x2000`.
pub fn iter_salt_assignment_candidates(image: &PeImage) -> Vec<SaltCandidate> {
    let data = &image.data;
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    if data.len() < 20 {
        return out;
    }

    for off in 0..data.len() - 20 {
        if data[off] != 0xC7 || data[off + 1] != 0x05 {
            continue;
        }
        let Ok(salt_va_u32) = read_u32_le(data, off + 6) else {
            continue;
        };
        let salt_va = salt_va_u32 as u64;
        let Some(salt_rva) = image.va_to_rva(salt_va) else {
            continue;
        };
        let Ok(salt_offset) = image.rva_to_offset(salt_rva) else {
            continue;
        };
        if salt_offset + SALT_SIZE > data.len() || seen.contains(&salt_offset) {
            continue;
        }

        let window_end = (off + 64).min(data.len() - 10);
        for size_off in (off + 10)..window_end {
            if data[size_off] != 0xC7 || data[size_off + 1] != 0x05 {
                continue;
            }
            if read_u32_le(data, size_off + 6).ok() == Some(SALT_SIZE as u32) {
                let code_rva = image.offset_to_rva(off).ok().or(Some(off as u32));
                if let Some(cand) = make_candidate(
                    image,
                    "code_assignment",
                    salt_offset,
                    &mut seen,
                    code_rva,
                    None,
                    None,
                ) {
                    out.push(cand);
                }
                break;
            }
        }
    }

    out
}

/// Strategy 2: Packed data-neighborhood heuristics (`V2Link\0\0` and `forcedataxp3\0`).
pub fn iter_packed_neighborhood_candidates(image: &PeImage) -> Vec<SaltCandidate> {
    let data = &image.data;
    let mut seen = HashSet::new();
    let mut out = Vec::new();

    for anchor in find_subslice_all(data, b"V2Link\0\0") {
        if anchor >= SALT_SIZE {
            if let Some(c) = make_candidate(
                image,
                "packed_neighborhood",
                anchor - SALT_SIZE,
                &mut seen,
                None,
                Some(anchor),
                Some("V2Link-before"),
            ) {
                out.push(c);
            }
        }
    }

    let marker = b"forcedataxp3\0";
    for anchor in find_subslice_all(data, marker) {
        let window_start = (anchor + marker.len() + 0xF) & !0xF;
        let window_end = (anchor + 0x100).min(data.len().saturating_sub(SALT_SIZE));
        let mut offset = window_start;
        while offset <= window_end {
            if let Some(c) = make_candidate(
                image,
                "packed_neighborhood",
                offset,
                &mut seen,
                None,
                Some(anchor),
                Some("forcedataxp3-near"),
            ) {
                out.push(c);
            }
            offset += 0x10;
        }
    }

    out
}

pub fn iter_auto_salt_candidates(image: &PeImage) -> Vec<SaltCandidate> {
    let mut seen = HashSet::new();
    let mut all = Vec::new();
    for cand in iter_salt_assignment_candidates(image)
        .into_iter()
        .chain(iter_packed_neighborhood_candidates(image))
    {
        if seen.insert(cand.salt_offset) {
            all.push(cand);
        }
    }
    all
}

/// Locate and cryptographically verify the 8192-byte bres salt against encrypted STARTUP.TJS.
pub fn recover_verified_salt(
    exe: &PeImage,
    startup_cipher: &[u8],
    startup_key: &str,
    overrides: &SaltOverride<'_>,
) -> Result<(Vec<u8>, String)> {
    if startup_cipher.len() < 8 {
        bail!("STARTUP.TJS ciphertext is too short ({} bytes)", startup_cipher.len());
    }
    let cipher_head: [u8; 8] = startup_cipher[..8].try_into().unwrap();
    let mut prefix_hasher = Sha3_384::new();
    prefix_hasher.update(encode_utf16le(startup_key));

    // 1. Explicit overrides
    if let Some(salt_file) = overrides.salt_file {
        let salt = std::fs::read(salt_file)?;
        if salt.len() != SALT_SIZE {
            bail!(
                "{} is {} bytes; expected {SALT_SIZE}",
                salt_file.display(),
                salt.len()
            );
        }
        if !verify_startup_salt_fast(&prefix_hasher, &cipher_head, &salt) {
            bail!(
                "explicit salt file {} did not decrypt STARTUP.TJS to TJS2100\\0",
                salt_file.display()
            );
        }
        return Ok((salt, salt_file.display().to_string()));
    }

    if let Some(offset) = overrides.salt_file_offset {
        let salt = read_file_offset(&exe.path, offset, SALT_SIZE)?;
        if !verify_startup_salt_fast(&prefix_hasher, &cipher_head, &salt) {
            bail!("explicit --salt-file-offset 0x{offset:x} did not decrypt STARTUP.TJS to TJS2100\\0");
        }
        return Ok((
            salt,
            format!("{}:file offset 0x{offset:x}", exe.path.display()),
        ));
    }

    if let Some(rva) = overrides.salt_rva {
        let salt = exe.read_rva(rva, SALT_SIZE)?.to_vec();
        if !verify_startup_salt_fast(&prefix_hasher, &cipher_head, &salt) {
            bail!("explicit --salt-rva 0x{rva:x} did not decrypt STARTUP.TJS to TJS2100\\0");
        }
        return Ok((salt, format!("{}:RVA 0x{rva:x}", exe.path.display())));
    }

    // 2. Fast heuristic candidates (code assignment + packed neighborhood)
    let candidates = iter_auto_salt_candidates(exe);
    for cand in &candidates {
        let slice = &exe.data[cand.salt_offset..cand.salt_offset + SALT_SIZE];
        if verify_startup_salt_fast(&prefix_hasher, &cipher_head, slice) {
            return Ok((slice.to_vec(), cand.source_label(&exe.path)));
        }
    }

    // 3. Fallback aligned scan across PE data sections (0x1000, then 0x100)
    if overrides.allow_full_scan {
        for &alignment in &[0x1000usize, 0x100usize] {
            if let Some((offset, salt)) =
                scan_pe_aligned(exe, &prefix_hasher, &cipher_head, alignment)
            {
                let rva_note = exe
                    .offset_to_rva(offset)
                    .map(|r| format!("RVA 0x{r:x} / "))
                    .unwrap_or_default();
                return Ok((
                    salt,
                    format!(
                        "{}:scan(0x{alignment:x}) {rva_note}file offset 0x{offset:x}",
                        exe.path.display()
                    ),
                ));
            }
        }
    }

    bail!(
        "could not locate a valid 0x2000-byte bres salt in {} (checked {} heuristic candidates); \
         pass --salt-rva, --salt-file-offset, or --salt-file",
        exe.path.display(),
        candidates.len()
    )
}

fn scan_pe_aligned(
    exe: &PeImage,
    prefix_hasher: &Sha3_384,
    cipher_head: &[u8; 8],
    alignment: usize,
) -> Option<(usize, Vec<u8>)> {
    let data = &exe.data;
    if data.len() < SALT_SIZE {
        return None;
    }
    let mut off = 0usize;
    while off + SALT_SIZE <= data.len() {
        let slice = &data[off..off + SALT_SIZE];
        if verify_startup_salt_fast(prefix_hasher, cipher_head, slice) {
            return Some((off, slice.to_vec()));
        }
        off += alignment;
    }
    None
}
