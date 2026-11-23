use crate::drip::DripProgram;
use crate::filter::FilterRuntimeState;
use crate::xp3::{Hxv4Descriptor, Xp3Archive, Xp3Entry};
use anyhow::{Context, Result, bail};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use flate2::read::ZlibDecoder;
use serde::Serialize;
use std::collections::HashMap;
use std::io::Read;

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
            let packed = *packed_i64 as u32;
            let archive_slot = ((packed >> 16) & 0xFFFF) as u16;
            let filter_flag = (packed & 0xFFFF) as u16;
            let xp3_entry_index = if archive_slot == 0 {
                Some((filter_flag as usize) + entry_base)
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
                packed,
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
