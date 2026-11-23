use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const DRIP_OP_ADD_IMM: u32 = 0x17C50;
pub const DRIP_OP_RECURSE: u32 = 0x17C60;
pub const DRIP_OP_ADD_SCRATCH: u32 = 0x17CB0;
pub const DRIP_OP_MUL_SCRATCH: u32 = 0x17CD0;
pub const DRIP_OP_SCRATCH_MINUS_RESULT: u32 = 0x17CF0;
pub const DRIP_OP_SHL_SCRATCH: u32 = 0x17D10;
pub const DRIP_OP_SHR_SCRATCH: u32 = 0x17D30;
pub const DRIP_OP_SUB_SCRATCH: u32 = 0x17D50;
pub const DRIP_OP_BIT_SHUFFLE: u32 = 0x17D70;
pub const DRIP_OP_SET_IMM: u32 = 0x17DA0;
pub const DRIP_OP_SET_SEED: u32 = 0x17DB0;
pub const DRIP_OP_DEC: u32 = 0x17DD0;
pub const DRIP_OP_INC: u32 = 0x17DE0;
pub const DRIP_OP_NEG: u32 = 0x17DF0;
pub const DRIP_OP_NOT: u32 = 0x17E00;
pub const DRIP_OP_TABLE_IMM: u32 = 0x17E10;
pub const DRIP_OP_TABLE_MASKED: u32 = 0x17E30;
pub const DRIP_OP_SUB_IMM: u32 = 0x17E50;
pub const DRIP_OP_STORE_SCRATCH: u32 = 0x17E60;
pub const DRIP_OP_XOR_IMM: u32 = 0x17E80;
pub const DRIP_OP_STOP: u32 = 0x51D90;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DripLaneJson {
    pub index: usize,
    #[serde(default)]
    pub begin_va: u32,
    #[serde(default)]
    pub end_va: u32,
    #[serde(default)]
    pub current_va: u32,
    #[serde(default)]
    pub ctx_va: u32,
    pub records: Vec<[u32; 2]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DripProgramJson {
    pub version: u32,
    #[serde(default)]
    pub source_module: String,
    #[serde(default)]
    pub source_module_base: u32,
    #[serde(default)]
    pub manager_va: u32,
    #[serde(default)]
    pub drip_impl_va: u32,
    pub hxv4_key: String,
    pub hxv4_nonce0: String,
    pub hxv4_nonce1: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_name: Option<String>,
    pub holder_words: Vec<u32>,
    #[serde(default)]
    pub context_va: u32,
    pub context_u32: Vec<u32>,
    #[serde(default)]
    pub callback_rva_base: u32,
    pub lanes: Vec<DripLaneJson>,
}

#[derive(Debug, Clone)]
pub struct DripProgram {
    pub raw_json: DripProgramJson,
    pub hxv4_key: [u8; 32],
    pub hxv4_nonce0: [u8; 24],
    pub hxv4_nonce1: [u8; 24],
    pub hash_key: Option<[u8; 32]>,
    pub media_name: String,
    pub holder_words: Vec<u32>,
    pub context_u32: Vec<u32>,
    pub lanes: Vec<Vec<(u32, u32)>>,
}

impl DripProgram {
    pub fn from_json(payload: DripProgramJson) -> Result<Self> {
        if payload.lanes.len() != 128 {
            bail!(
                "Drip program must contain 128 lanes, got {}",
                payload.lanes.len()
            );
        }
        if payload.holder_words.len() < 6 {
            bail!(
                "Drip program holder_words is truncated ({} words, need >= 6)",
                payload.holder_words.len()
            );
        }

        let key_bytes = hex::decode(&payload.hxv4_key).context("invalid hxv4_key hex")?;
        if key_bytes.len() != 32 {
            bail!("hxv4_key must be 32 bytes, got {}", key_bytes.len());
        }
        let mut hxv4_key = [0u8; 32];
        hxv4_key.copy_from_slice(&key_bytes);

        let n0_bytes = hex::decode(&payload.hxv4_nonce0).context("invalid hxv4_nonce0 hex")?;
        if n0_bytes.len() < 24 {
            bail!("hxv4_nonce0 must be >= 24 bytes, got {}", n0_bytes.len());
        }
        let mut hxv4_nonce0 = [0u8; 24];
        hxv4_nonce0.copy_from_slice(&n0_bytes[..24]);

        let n1_bytes = hex::decode(&payload.hxv4_nonce1).context("invalid hxv4_nonce1 hex")?;
        if n1_bytes.len() < 24 {
            bail!("hxv4_nonce1 must be >= 24 bytes, got {}", n1_bytes.len());
        }
        let mut hxv4_nonce1 = [0u8; 24];
        hxv4_nonce1.copy_from_slice(&n1_bytes[..24]);

        let hash_key = match &payload.hash_key {
            Some(s) if !s.is_empty() => {
                let raw = hex::decode(s).context("invalid hash_key hex")?;
                if raw.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&raw);
                    Some(arr)
                } else {
                    None
                }
            }
            _ => None,
        };

        let lanes: Vec<Vec<(u32, u32)>> = payload
            .lanes
            .iter()
            .map(|l| l.records.iter().map(|r| (r[0], r[1])).collect())
            .collect();

        let media_name = payload
            .media_name
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "xp3hnp".to_string());

        let holder_words = payload.holder_words.clone();
        let context_u32 = payload.context_u32.clone();

        Ok(Self {
            raw_json: payload,
            hxv4_key,
            hxv4_nonce0,
            hxv4_nonce1,
            hash_key,
            media_name,
            holder_words,
            context_u32,
            lanes,
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read drip program {}", path.display()))?;
        let payload: DripProgramJson = serde_json::from_str(&text)
            .with_context(|| format!("failed to parse drip program JSON {}", path.display()))?;
        Self::from_json(payload)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let json = serde_json::to_string_pretty(&self.raw_json)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    #[inline]
    pub fn nonce_for_flags(&self, flags: u16) -> &[u8; 24] {
        if (flags & 1) == 0 {
            &self.hxv4_nonce0
        } else {
            &self.hxv4_nonce1
        }
    }

    #[inline]
    fn context_value(&self, index: u32) -> Result<u32> {
        self.context_u32
            .get(index as usize)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("Drip context index out of range: 0x{index:x}"))
    }

    fn eval_records(
        &self,
        records: &[(u32, u32)],
        mut pc: usize,
        mut result: u32,
        seed: u32,
        mut scratch: u32,
    ) -> Result<(u32, usize)> {
        while pc < records.len() {
            let (param, op) = records[pc];
            pc += 1;

            match op {
                DRIP_OP_STOP => break,
                DRIP_OP_RECURSE => {
                    let (nested_res, next_pc) =
                        self.eval_records(records, pc, result, seed, scratch)?;
                    result = nested_res;
                    pc = next_pc;
                }
                DRIP_OP_ADD_IMM => result = result.wrapping_add(param),
                DRIP_OP_ADD_SCRATCH => result = result.wrapping_add(scratch),
                DRIP_OP_MUL_SCRATCH => result = result.wrapping_mul(scratch),
                DRIP_OP_SCRATCH_MINUS_RESULT => result = scratch.wrapping_sub(result),
                DRIP_OP_SHL_SCRATCH => result = result.wrapping_shl(scratch & 0xF),
                DRIP_OP_SHR_SCRATCH => result = result.wrapping_shr(scratch & 0xF),
                DRIP_OP_SUB_SCRATCH => result = result.wrapping_sub(scratch),
                DRIP_OP_BIT_SHUFFLE => {
                    result = (result & !param).wrapping_shl(1) | ((param >> 1) & (result >> 1));
                }
                DRIP_OP_SET_IMM => result = param,
                DRIP_OP_SET_SEED => result = seed,
                DRIP_OP_DEC => result = result.wrapping_sub(1),
                DRIP_OP_INC => result = result.wrapping_add(1),
                DRIP_OP_NEG => result = result.wrapping_neg(),
                DRIP_OP_NOT => result = !result,
                DRIP_OP_TABLE_IMM => result = self.context_value(param)?,
                DRIP_OP_TABLE_MASKED => result = self.context_value(param & result)?,
                DRIP_OP_SUB_IMM => result = result.wrapping_sub(param),
                DRIP_OP_STORE_SCRATCH => scratch = result,
                DRIP_OP_XOR_IMM => result ^= param,
                _ => bail!("unknown Drip op callback RVA: 0x{op:x}"),
            }
        }
        Ok((result, pc))
    }

    pub fn eval_lane(&self, lane_index: usize, seed: u32) -> Result<u32> {
        let records = self
            .lanes
            .get(lane_index)
            .ok_or_else(|| anyhow::anyhow!("Drip lane index out of range: {lane_index}"))?;
        let (res, _) = self.eval_records(records, 0, 0, seed, 0)?;
        Ok(res)
    }

    pub fn get64_from_u32(&self, value: u32) -> Result<u64> {
        let lane_index = (value & 0x7F) as usize;
        let seed = value >> 7;
        let lo = self.eval_lane(lane_index, seed)? as u64;
        let hi = self.eval_lane(lane_index, !seed)? as u64;
        Ok(lo | (hi << 32))
    }

    /// Derive the 48-byte `FilterImpl` seed state from an Hxv4 record's 64-bit resource key
    /// and the Hxv4 descriptor's `open_flag` (`descriptor.flags & 1`).
    pub fn build_filter_state(&self, key: u64, open_flag: u16) -> Result<[u8; 48]> {
        let mut key_lo = key as u32;
        let mut key_hi = (key >> 32) as u32;
        if (open_flag & 1) == 0 {
            key_lo ^= self.holder_words[2];
            key_hi ^= self.holder_words[3];
        }
        let key64 = (key_lo as u64) | ((key_hi as u64) << 32);

        let mut state = [0u8; 48];
        state[0..8].copy_from_slice(&self.get64_from_u32(key_lo)?.to_le_bytes());
        state[8..16].copy_from_slice(&self.get64_from_u32(key_hi)?.to_le_bytes());

        let bulk_offset = (self.holder_words[5] as u64)
            .wrapping_add((self.holder_words[4] as u64) & (key64 >> 16));
        state[16..20].copy_from_slice(&(bulk_offset as u32).to_le_bytes());
        state[20..24].copy_from_slice(&0u32.to_le_bytes());

        let mut cur = !key64;
        let mut bitpos: i32 = -1;
        let mut out = 24usize;
        while out < 40 {
            if bitpos < 0 {
                cur = !self.get64_from_u32(cur as u32)?;
                bitpos = 64;
            } else {
                state[out] = ((cur >> (bitpos as u32)) & 0xFF) as u8;
                out += 1;
            }
            bitpos -= 8;
        }

        state[44] = 1;
        state[45] = 0;
        Ok(state)
    }
}
