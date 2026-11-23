use crate::filter::FilterRuntimeState;
use anyhow::{Context, Result, bail};
use flate2::read::ZlibDecoder;
use serde::Serialize;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

pub const XP3_MAGIC: &[u8; 11] = b"XP3\r\n \n\x1a\x8bg\x01";

#[derive(Debug, Clone, Serialize)]
pub struct Xp3Segment {
    pub flags: u32,
    pub offset: u64,
    pub original_size: u64,
    pub archived_size: u64,
}

impl Xp3Segment {
    #[inline]
    pub fn is_compressed(&self) -> bool {
        (self.flags & 1) != 0
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Xp3Entry {
    pub index: usize,
    pub name: String,
    pub flags: u32,
    pub original_size: u64,
    pub archived_size: u64,
    pub adler32: Option<u32>,
    pub segments: Vec<Xp3Segment>,
}

impl Xp3Entry {
    #[inline]
    pub fn is_protected(&self) -> bool {
        (self.flags & 0x8000_0000) != 0
    }

    pub fn is_warning_entry(&self) -> bool {
        self.index == 0
            && self.flags == 0
            && self.segments.len() == 1
            && self.segments[0].original_size < self.original_size
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Hxv4Descriptor {
    pub offset: u64,
    pub size: u32,
    pub flags: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct Xp3ArchiveInfo {
    pub path: String,
    pub size: u64,
    pub header_index_offset: u64,
    pub resolved_index_offset: u64,
    pub index_compressed_size: u64,
    pub index_original_size: u64,
    pub entry_count: usize,
    pub has_hxv4: bool,
}

#[derive(Debug)]
pub struct ExtractedEntry {
    pub data: Vec<u8>,
    pub adler32: u32,
    pub adler_ok: Option<bool>,
    pub filter_applied: bool,
    pub filter_needed: bool,
}

pub struct Xp3Archive {
    pub path: PathBuf,
    file: File,
    pub info: Xp3ArchiveInfo,
    pub entries: Vec<Xp3Entry>,
    pub hxv4_descriptor: Option<Hxv4Descriptor>,
}

/// Exact RFC 1950 Adler-32 matching `zlib.adler32(data) & 0xFFFFFFFF`.
pub fn calc_adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;

    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += byte as u32;
            b += a;
        }
        a %= MOD_ADLER;
        b %= MOD_ADLER;
    }

    (b << 16) | a
}

fn read_u16(data: &[u8], off: usize) -> Result<u16> {
    let b: [u8; 2] = data
        .get(off..off + 2)
        .ok_or_else(|| anyhow::anyhow!("truncated XP3 u16 at 0x{off:x}"))?
        .try_into()?;
    Ok(u16::from_le_bytes(b))
}

fn read_u32(data: &[u8], off: usize) -> Result<u32> {
    let b: [u8; 4] = data
        .get(off..off + 4)
        .ok_or_else(|| anyhow::anyhow!("truncated XP3 u32 at 0x{off:x}"))?
        .try_into()?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64(data: &[u8], off: usize) -> Result<u64> {
    let b: [u8; 8] = data
        .get(off..off + 8)
        .ok_or_else(|| anyhow::anyhow!("truncated XP3 u64 at 0x{off:x}"))?
        .try_into()?;
    Ok(u64::from_le_bytes(b))
}

fn inflate_zlib(raw: &[u8], expected_size: Option<usize>) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(raw);
    let mut out = match expected_size {
        Some(cap) => Vec::with_capacity(cap.min(64 * 1024 * 1024)),
        None => Vec::new(),
    };
    decoder.read_to_end(&mut out)?;
    if let Some(exp) = expected_size {
        if out.len() != exp {
            bail!("zlib inflated size mismatch: got {}, expected {exp}", out.len());
        }
    }
    Ok(out)
}

impl Xp3Archive {
    pub fn open(path: &Path) -> Result<Self> {
        let mut file =
            File::open(path).with_context(|| format!("failed to open XP3 {}", path.display()))?;
        let file_size = file.metadata()?.len();
        if file_size < 19 {
            bail!("{} is too small to be an XP3 archive ({file_size} bytes)", path.display());
        }

        let header_len = (file_size as usize).min(0x28);
        let mut hdr = vec![0u8; header_len];
        file.read_exact(&mut hdr)?;
        if &hdr[..11] != XP3_MAGIC {
            bail!("{} does not start with XP3 magic", path.display());
        }

        let header_index_offset = read_u64(&hdr, 11)?;
        if header_index_offset >= file_size {
            bail!(
                "{}: XP3 index offset 0x{header_index_offset:x} exceeds file size 0x{file_size:x}",
                path.display()
            );
        }

        // Custom Kirikiri Hxv4 variant puts 0x17 in +0x0B and real index offset at +0x20.
        let resolved_index_offset = if header_index_offset == 0x17 && hdr.len() >= 0x28 {
            let cand = read_u64(&hdr, 0x20)?;
            if cand > 0 && cand < file_size {
                cand
            } else {
                header_index_offset
            }
        } else {
            header_index_offset
        };

        file.seek(SeekFrom::Start(resolved_index_offset))?;
        let mut flag_buf = [0u8; 1];
        file.read_exact(&mut flag_buf)?;
        let flag = flag_buf[0];

        let (index_compressed_size, index_original_size, index_bytes) = match flag {
            0 => {
                let mut sz_buf = [0u8; 8];
                file.read_exact(&mut sz_buf)?;
                let sz = u64::from_le_bytes(sz_buf);
                let mut raw = vec![0u8; sz as usize];
                file.read_exact(&mut raw)?;
                (sz, sz, raw)
            }
            1 => {
                let mut sz_buf = [0u8; 16];
                file.read_exact(&mut sz_buf)?;
                let comp_sz = u64::from_le_bytes(sz_buf[0..8].try_into().unwrap());
                let orig_sz = u64::from_le_bytes(sz_buf[8..16].try_into().unwrap());
                let mut raw = vec![0u8; comp_sz as usize];
                file.read_exact(&mut raw)?;
                let inflated = inflate_zlib(&raw, Some(orig_sz as usize))
                    .with_context(|| format!("failed to decompress XP3 index of {}", path.display()))?;
                (comp_sz, orig_sz, inflated)
            }
            other => bail!(
                "{}: unsupported XP3 index flag 0x{other:02x} at 0x{resolved_index_offset:x}",
                path.display()
            ),
        };

        let (entries, hxv4_descriptor) = parse_index(&index_bytes)?;
        let info = Xp3ArchiveInfo {
            path: path.display().to_string(),
            size: file_size,
            header_index_offset,
            resolved_index_offset,
            index_compressed_size,
            index_original_size,
            entry_count: entries.len(),
            has_hxv4: hxv4_descriptor.is_some(),
        };

        Ok(Self {
            path: path.to_path_buf(),
            file,
            info,
            entries,
            hxv4_descriptor,
        })
    }

    pub fn read_slice(&mut self, offset: u64, size: usize) -> Result<Vec<u8>> {
        if offset.saturating_add(size as u64) > self.info.size {
            bail!(
                "{}: read range 0x{offset:x}..+0x{size:x} exceeds archive size 0x{:x}",
                self.path.display(),
                self.info.size
            );
        }
        self.file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; size];
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Read and decompress all segments of an entry, returning `(logical_offset, bytes)` chunks.
    pub fn read_entry_chunks(&mut self, entry: &Xp3Entry) -> Result<Vec<(u64, Vec<u8>)>> {
        let mut chunks = Vec::with_capacity(entry.segments.len());
        let mut logical_offset = 0u64;

        for seg in &entry.segments {
            let raw = self.read_slice(seg.offset, seg.archived_size as usize)?;
            let chunk = if seg.is_compressed() {
                inflate_zlib(&raw, Some(seg.original_size as usize)).with_context(|| {
                    format!(
                        "zlib inflate failed for entry #{} ({:?}) in {}",
                        entry.index,
                        entry.name,
                        self.path.display()
                    )
                })?
            } else {
                raw
            };
            let len = chunk.len() as u64;
            chunks.push((logical_offset, chunk));
            logical_offset += len;
        }

        Ok(chunks)
    }

    /// Extract a single entry, applying `filter_state` when needed, and verifying Adler32.
    pub fn extract_entry(
        &mut self,
        entry: &Xp3Entry,
        filter_state: Option<&FilterRuntimeState>,
    ) -> Result<ExtractedEntry> {
        let mut chunks = self.read_entry_chunks(entry)?;

        // Check if raw post-zlib bytes already match Adler32 (e.g., unprotected entry like startup.tjs)
        let mut skip_filter = false;
        if let Some(expected_adler) = entry.adler32 {
            let raw_len: usize = chunks.iter().map(|(_, c)| c.len()).sum();
            let mut raw_all = Vec::with_capacity(raw_len);
            for (_, c) in &chunks {
                raw_all.extend_from_slice(c);
            }
            if calc_adler32(&raw_all) == expected_adler {
                skip_filter = true;
            }
        }

        let mut filter_applied = false;
        if !skip_filter {
            if let Some(fs) = filter_state {
                for (offset, chunk) in &mut chunks {
                    filter_applied |= fs.apply(chunk, *offset);
                }
            }
        }

        let total_len: usize = chunks.iter().map(|(_, c)| c.len()).sum();
        let mut data = Vec::with_capacity(total_len);
        for (_, c) in chunks {
            data.extend_from_slice(&c);
        }

        if data.len() as u64 != entry.original_size {
            bail!(
                "entry #{} ({:?}) size mismatch: got {}, expected {}",
                entry.index,
                entry.name,
                data.len(),
                entry.original_size
            );
        }

        let actual = calc_adler32(&data);
        let adler_ok = entry.adler32.map(|exp| actual == exp);
        let filter_needed = entry.is_protected() && adler_ok == Some(false) && !filter_applied;

        Ok(ExtractedEntry {
            data,
            adler32: actual,
            adler_ok,
            filter_applied,
            filter_needed,
        })
    }
}

fn parse_index(index: &[u8]) -> Result<(Vec<Xp3Entry>, Option<Hxv4Descriptor>)> {
    let mut entries = Vec::new();
    let mut hxv4_descriptor = None;
    let mut cursor = 0usize;

    while cursor + 12 <= index.len() {
        let tag = &index[cursor..cursor + 4];
        let chunk_size = read_u64(index, cursor + 4)? as usize;
        cursor += 12;
        let chunk = index
            .get(cursor..cursor + chunk_size)
            .ok_or_else(|| anyhow::anyhow!("truncated XP3 index chunk at 0x{cursor:x}"))?;
        cursor += chunk_size;

        if tag == b"Hxv4" {
            if chunk.len() < 14 {
                bail!("truncated Hxv4 descriptor ({} bytes)", chunk.len());
            }
            hxv4_descriptor = Some(Hxv4Descriptor {
                offset: read_u64(chunk, 0)?,
                size: read_u32(chunk, 8)?,
                flags: read_u16(chunk, 12)?,
            });
            continue;
        }

        if tag != b"File" {
            continue;
        }

        let mut name = String::new();
        let mut flags = 0u32;
        let mut original_size = 0u64;
        let mut archived_size = 0u64;
        let mut adler32 = None;
        let mut segments = Vec::new();

        let mut sub = 0usize;
        while sub + 12 <= chunk.len() {
            let sub_tag = &chunk[sub..sub + 4];
            let sub_size = read_u64(chunk, sub + 4)? as usize;
            sub += 12;
            let body = chunk
                .get(sub..sub + sub_size)
                .ok_or_else(|| anyhow::anyhow!("truncated XP3 File subchunk"))?;
            sub += sub_size;

            if sub_tag == b"info" && body.len() >= 22 {
                flags = read_u32(body, 0)?;
                original_size = read_u64(body, 4)?;
                archived_size = read_u64(body, 12)?;
                let name_len = read_u16(body, 20)? as usize;
                let name_end = (22 + name_len * 2).min(body.len());
                let units: Vec<u16> = body[22..name_end]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                name = String::from_utf16_lossy(&units);
            } else if sub_tag == b"segm" {
                let mut seg_off = 0usize;
                while seg_off + 28 <= body.len() {
                    segments.push(Xp3Segment {
                        flags: read_u32(body, seg_off)?,
                        offset: read_u64(body, seg_off + 4)?,
                        original_size: read_u64(body, seg_off + 12)?,
                        archived_size: read_u64(body, seg_off + 20)?,
                    });
                    seg_off += 28;
                }
            } else if sub_tag == b"adlr" && body.len() >= 4 {
                adler32 = Some(read_u32(body, 0)?);
            }
        }

        let idx = entries.len();
        entries.push(Xp3Entry {
            index: idx,
            name,
            flags,
            original_size,
            archived_size,
            adler32,
            segments,
        });
    }

    Ok((entries, hxv4_descriptor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adler32_known_vectors() {
        assert_eq!(calc_adler32(b""), 1);
        assert_eq!(calc_adler32(b"Wikipedia"), 0x11E6_0398);
    }
}
