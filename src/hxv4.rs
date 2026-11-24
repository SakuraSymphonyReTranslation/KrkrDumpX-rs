use crate::drip::DripProgram;
use crate::filter::FilterRuntimeState;
use crate::xp3::{Hxv4Descriptor, Xp3Archive, Xp3Entry, hxv4_fake_id};
use anyhow::{Context, Result, bail};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use serde::Serialize;
use std::collections::HashMap;
use std::io::{Read, Write};

#[derive(Debug, Clone, Serialize)]
pub struct Hxv4Record {
    pub domain_hash: String,
    pub file_hash: String,
    pub record_index: usize,
    pub packed: u32,
    pub archive_slot: u16,
    pub filter_flag: u16,
    pub key: u64,
    pub xp3_entry_index: Option<usize>,
    pub xp3_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Hxv4Table {
    pub descriptor: Hxv4Descriptor,
    pub records: Vec<Hxv4Record>,
}

impl Hxv4Table {
    pub fn build_filter_states(
        &self,
        entry_count: usize,
        drip: &DripProgram,
        force_open_flag: Option<u16>,
    ) -> Result<HashMap<usize, FilterRuntimeState>> {
        let open_flag = force_open_flag.unwrap_or(self.descriptor.flags & 1);
        let mut states = HashMap::with_capacity(self.records.len());
        for rec in &self.records {
            if rec.archive_slot != 0 {
                continue;
            }
            let Some(idx) = rec.xp3_entry_index else {
                continue;
            };
            if idx >= entry_count {
                continue;
            }
            let seed_state = drip.build_filter_state(rec.key, open_flag)?;
            states.insert(idx, FilterRuntimeState::from_seed_state(&seed_state));
        }
        Ok(states)
    }
}

pub fn decrypt_hxv4_payload(
    encrypted: &[u8],
    flags: u16,
    drip: &DripProgram,
) -> Result<Vec<u8>> {
    if encrypted.len() < 21 {
        bail!("truncated Hxv4 encrypted payload ({} bytes)", encrypted.len());
    }
    let tag: &[u8; 16] = encrypted[..16].try_into().unwrap();
    let mut buffer = encrypted[16..].to_vec();
    let nonce = drip.nonce_for_flags(flags);

    let cipher = XChaCha20Poly1305::new(drip.hxv4_key.as_slice().into());
    cipher
        .decrypt_in_place_detached(nonce.into(), b"", &mut buffer, tag.into())
        .map_err(|_| {
            anyhow::anyhow!(
                "XChaCha20-Poly1305 authentication failed for Hxv4 payload (flags=0x{flags:x}); \
                 check that drip_program matches this game's EXE/DLL"
            )
        })?;

    Ok(buffer)
}

/// Compress and encrypt a serialized Hxv4 TJS binary table with XChaCha20-Poly1305.
/// Output layout: `16-byte Poly1305 tag || XChaCha20 ciphertext(u32_le(orig_len) || zlib(table_blob))`.
pub fn encrypt_hxv4_payload(
    table_blob: &[u8],
    flags: u16,
    drip: &DripProgram,
    compression_level: u32,
) -> Result<Vec<u8>> {
    let orig_len = u32::try_from(table_blob.len())
        .map_err(|_| anyhow::anyhow!("Hxv4 table exceeds 4 GiB limit"))?;

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(compression_level.min(9)));
    encoder.write_all(table_blob)?;
    let compressed = encoder.finish()?;

    let mut buffer = Vec::with_capacity(4 + compressed.len());
    buffer.extend_from_slice(&orig_len.to_le_bytes());
    buffer.extend_from_slice(&compressed);

    let nonce = drip.nonce_for_flags(flags);
    let cipher = XChaCha20Poly1305::new(drip.hxv4_key.as_slice().into());
    let tag = cipher
        .encrypt_in_place_detached(nonce.into(), b"", &mut buffer)
        .map_err(|_| anyhow::anyhow!("XChaCha20-Poly1305 encryption failed for Hxv4 payload"))?;

    let mut out = Vec::with_capacity(16 + buffer.len());
    out.extend_from_slice(tag.as_slice());
    out.extend_from_slice(&buffer);
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct Hxv4WriteEntry {
    pub domain_hash: [u8; 8],
    pub file_hash: [u8; 32],
    pub entry_id: u32,
    pub key: u64,
}

struct TjsBeWriter {
    buf: Vec<u8>,
}

impl TjsBeWriter {
    fn new(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    fn write_array_header(&mut self, count: usize) {
        self.buf.push(0x81);
        self.buf.extend_from_slice(&(count as i32).to_be_bytes());
    }

    fn write_octet(&mut self, bytes: &[u8]) {
        self.buf.push(0x03);
        self.buf
            .extend_from_slice(&(bytes.len() as i32).to_be_bytes());
        self.buf.extend_from_slice(bytes);
    }

    fn write_int(&mut self, value: i64) {
        self.buf.push(0x04);
        self.buf.extend_from_slice(&value.to_be_bytes());
    }
}

/// Serialize Hxv4 entries into Kirikiri's big-endian TJS binary variant format.
pub fn encode_hxv4_records(entries: &[Hxv4WriteEntry]) -> Vec<u8> {
    let mut group_order: Vec<([u8; 8], Vec<&Hxv4WriteEntry>)> = Vec::new();
    let mut group_idx: HashMap<[u8; 8], usize> = HashMap::new();

    for entry in entries {
        if let Some(&idx) = group_idx.get(&entry.domain_hash) {
            group_order[idx].1.push(entry);
        } else {
            let idx = group_order.len();
            group_idx.insert(entry.domain_hash, idx);
            group_order.push((entry.domain_hash, vec![entry]));
        }
    }

    let est_size = 16 + group_order.len() * 20 + entries.len() * 64;
    let mut w = TjsBeWriter::new(est_size);
    w.write_array_header(group_order.len() * 2);
    for (domain_hash, items) in &group_order {
        w.write_octet(domain_hash);
        w.write_array_header(items.len() * 2);
        for item in items {
            w.write_octet(&item.file_hash);
            w.write_array_header(2);
            w.write_int(item.entry_id as i64);
            w.write_int(item.key as i64);
        }
    }
    w.buf
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum TjsBeValue {
    Null,
    String(String),
    Octet(Vec<u8>),
    Int(i64),
    Float(f64),
    Array(Vec<TjsBeValue>),
    Dict(Vec<(String, TjsBeValue)>),
}

struct TjsBeReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> TjsBeReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let slice = self
            .data
            .get(self.pos..self.pos + n)
            .ok_or_else(|| anyhow::anyhow!("truncated TJS BE binary payload at 0x{:x}", self.pos))?;
        self.pos += n;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_i32(&mut self) -> Result<i32> {
        Ok(i32::from_be_bytes(self.read_bytes(4)?.try_into().unwrap()))
    }

    fn read_i64(&mut self) -> Result<i64> {
        Ok(i64::from_be_bytes(self.read_bytes(8)?.try_into().unwrap()))
    }

    fn read_f64(&mut self) -> Result<f64> {
        Ok(f64::from_be_bytes(self.read_bytes(8)?.try_into().unwrap()))
    }

    fn read_string(&mut self) -> Result<String> {
        let chars = self.read_i32()?;
        if chars < 0 {
            bail!("negative TJS BE string length {chars}");
        }
        let raw = self.read_bytes((chars as usize) * 2)?;
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        Ok(String::from_utf16_lossy(&units))
    }

    fn read_value(&mut self) -> Result<TjsBeValue> {
        let tag = self.read_u8()? as i8;
        match tag {
            0 | 1 => Ok(TjsBeValue::Null),
            2 => Ok(TjsBeValue::String(self.read_string()?)),
            3 => {
                let sz = self.read_i32()?;
                if sz < 0 {
                    bail!("negative TJS BE octet length {sz}");
                }
                Ok(TjsBeValue::Octet(self.read_bytes(sz as usize)?.to_vec()))
            }
            4 => Ok(TjsBeValue::Int(self.read_i64()?)),
            5 => Ok(TjsBeValue::Float(self.read_f64()?)),
            -127 => {
                let count = self.read_i32()?;
                if count < 0 {
                    bail!("negative TJS BE array length {count}");
                }
                let mut items = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    items.push(self.read_value()?);
                }
                Ok(TjsBeValue::Array(items))
            }
            -63 => {
                let count = self.read_i32()?;
                if count < 0 {
                    bail!("negative TJS BE dict length {count}");
                }
                let mut items = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    let k = self.read_string()?;
                    let v = self.read_value()?;
                    items.push((k, v));
                }
                Ok(TjsBeValue::Dict(items))
            }
            other => bail!(
                "unsupported TJS BE binary tag {other} at 0x{:x}",
                self.pos - 1
            ),
        }
    }
}

pub fn parse_hxv4_table(archive: &mut Xp3Archive, drip: &DripProgram) -> Result<Option<Hxv4Table>> {
    let Some(descriptor) = archive.hxv4_descriptor else {
        return Ok(None);
    };
    let encrypted = archive
        .read_slice(descriptor.offset, descriptor.size as usize)
        .context("failed to read encrypted Hxv4 payload from XP3")?;
    let decrypted = decrypt_hxv4_payload(&encrypted, descriptor.flags, drip)?;
    if decrypted.len() < 4 {
        bail!("truncated decrypted Hxv4 payload ({} bytes)", decrypted.len());
    }
    let uncompressed_size = u32::from_le_bytes(decrypted[..4].try_into().unwrap()) as usize;
    let mut decoder = ZlibDecoder::new(&decrypted[4..]);
    let mut table_blob = Vec::with_capacity(uncompressed_size);
    decoder
        .read_to_end(&mut table_blob)
        .context("failed to zlib-decompress Hxv4 table")?;
    if table_blob.len() != uncompressed_size {
        bail!(
            "Hxv4 table uncompressed size mismatch: got {}, expected {uncompressed_size}",
            table_blob.len()
        );
    }

    let records = decode_hxv4_records(&table_blob, &archive.entries)?;
    Ok(Some(Hxv4Table {
        descriptor,
        records,
    }))
}

pub fn decode_hxv4_records(table_blob: &[u8], entries: &[Xp3Entry]) -> Result<Vec<Hxv4Record>> {
    let root = TjsBeReader::new(table_blob).read_value()?;
    let TjsBeValue::Array(top) = root else {
        bail!("unexpected Hxv4 table root type (expected Array)");
    };
    if top.len() % 2 != 0 {
        bail!("unexpected Hxv4 table length {} (must be even)", top.len());
    }

    let entry_base = if entries.len() > 1 && entries[1].name == "startup.tjs" {
        1usize
    } else {
        0usize
    };
    let fake_id_to_index: HashMap<u64, usize> = entries
        .iter()
        .enumerate()
        .filter_map(|(i, e)| hxv4_fake_id(&e.name).map(|id| (id, i)))
        .collect();

    let mut records = Vec::new();
    for pair in top.chunks_exact(2) {
        let TjsBeValue::Octet(domain_raw) = &pair[0] else {
            bail!("unexpected Hxv4 domain_hash type");
        };
        let TjsBeValue::Array(group) = &pair[1] else {
            bail!("unexpected Hxv4 group type");
        };
        if domain_raw.len() != 8 || group.len() % 2 != 0 {
            bail!(
                "unexpected Hxv4 group shape (domain_len={}, group_len={})",
                domain_raw.len(),
                group.len()
            );
        }
        let mut domain_hash_bytes = [0u8; 8];
        domain_hash_bytes.copy_from_slice(domain_raw);
        let domain_hash_hex = hex::encode(domain_hash_bytes);

        for item in group.chunks_exact(2) {
            let TjsBeValue::Octet(file_raw) = &item[0] else {
                bail!("unexpected Hxv4 file_hash type");
            };
            let TjsBeValue::Array(meta) = &item[1] else {
                bail!("unexpected Hxv4 record metadata type");
            };
            if file_raw.len() != 32 || meta.len() != 2 {
                bail!(
                    "unexpected Hxv4 record shape (file_len={}, meta_len={})",
                    file_raw.len(),
                    meta.len()
                );
            }
            let (TjsBeValue::Int(packed_i64), TjsBeValue::Int(key_i64)) = (&meta[0], &meta[1])
            else {
                bail!("unexpected Hxv4 record integer pair");
            };

            let mut file_hash_bytes = [0u8; 32];
            file_hash_bytes.copy_from_slice(file_raw);
            let packed_u64 = *packed_i64 as u64;
            let entry_id = (packed_u64 & 0xFFFF_FFFF) as u32;
            let high32 = (packed_u64 >> 32) as u32;
            let archive_slot = ((high32 >> 16) & 0xFFFF) as u16;
            let filter_flag = (entry_id & 0xFFFF) as u16;
            let xp3_entry_index = if archive_slot == 0 {
                fake_id_to_index
                    .get(&(entry_id as u64))
                    .copied()
                    .or_else(|| Some((entry_id as usize) + entry_base))
            } else {
                None
            };
            let xp3_name = xp3_entry_index
                .and_then(|i| entries.get(i))
                .map(|e| e.name.clone());

            records.push(Hxv4Record {
                domain_hash: domain_hash_hex.clone(),
                file_hash: hex::encode(file_hash_bytes),
                record_index: records.len(),
                packed: entry_id,
                archive_slot,
                filter_flag,
                key: *key_i64 as u64,
                xp3_entry_index,
                xp3_name,
            });
        }
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xp3::hxv4_fake_name;

    #[test]
    fn test_hxv4_record_encode_decode_roundtrip() {
        let write_entries = vec![
            Hxv4WriteEntry {
                domain_hash: [0x94, 0xd4, 0xa9, 0x7c, 0x61, 0x49, 0x86, 0x21],
                file_hash: [0x11; 32],
                entry_id: 1,
                key: 0x0123_4567_89ab_cdef,
            },
            Hxv4WriteEntry {
                domain_hash: [0x94, 0xd4, 0xa9, 0x7c, 0x61, 0x49, 0x86, 0x21],
                file_hash: [0x22; 32],
                entry_id: 2,
                key: 0xfedc_ba98_7654_3210,
            },
            Hxv4WriteEntry {
                domain_hash: [0xa8, 0x42, 0xa3, 0xc4, 0x82, 0xdc, 0x5e, 0x81],
                file_hash: [0x33; 32],
                entry_id: 70_000,
                key: 0xdead_beef_cafe_babe,
            },
        ];

        let blob = encode_hxv4_records(&write_entries);
        let dummy_entries = vec![
            Xp3Entry {
                index: 0,
                name: hxv4_fake_name(0),
                flags: 0,
                original_size: 128,
                archived_size: 128,
                adler32: None,
                segments: vec![],
            },
            Xp3Entry {
                index: 1,
                name: hxv4_fake_name(1),
                flags: 0x8000_0000,
                original_size: 0,
                archived_size: 0,
                adler32: None,
                segments: vec![],
            },
            Xp3Entry {
                index: 2,
                name: hxv4_fake_name(2),
                flags: 0x8000_0000,
                original_size: 0,
                archived_size: 0,
                adler32: None,
                segments: vec![],
            },
            Xp3Entry {
                index: 3,
                name: hxv4_fake_name(70_000),
                flags: 0x8000_0000,
                original_size: 0,
                archived_size: 0,
                adler32: None,
                segments: vec![],
            },
        ];

        let decoded = decode_hxv4_records(&blob, &dummy_entries).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].domain_hash, "94d4a97c61498621");
        assert_eq!(decoded[0].file_hash, hex::encode([0x11u8; 32]));
        assert_eq!(decoded[0].packed, 1);
        assert_eq!(decoded[0].key, 0x0123_4567_89ab_cdef);
        assert_eq!(decoded[0].xp3_entry_index, Some(1));
        assert_eq!(decoded[1].key, 0xfedc_ba98_7654_3210);
        assert_eq!(decoded[1].xp3_entry_index, Some(2));
        assert_eq!(decoded[2].packed, 70_000);
        assert_eq!(decoded[2].xp3_entry_index, Some(3));
    }
}
