use anyhow::{Result, bail};
use flate2::read::ZlibDecoder;
use std::collections::BTreeMap;
use std::io::Read;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum PsbValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    IntArray(Vec<u64>),
    String(String),
    Resource(u64),
    List(Vec<PsbValue>),
    Object(BTreeMap<String, PsbValue>),
}

impl PsbValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            PsbValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, PsbValue>> {
        match self {
            PsbValue::Object(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&[PsbValue]> {
        match self {
            PsbValue::List(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&PsbValue> {
        self.as_object()?.get(key)
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PsbHeader {
    pub version: u16,
    pub encrypt: u16,
    pub offset_names: usize,
    pub offset_strings: usize,
    pub offset_strings_data: usize,
    pub offset_entries: usize,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ParsedPsb {
    pub header: PsbHeader,
    pub names: Vec<String>,
    pub strings: Vec<String>,
    pub root: PsbValue,
}

impl ParsedPsb {
    pub fn kind_extension(&self) -> &'static str {
        if let Some(obj) = self.root.as_object() {
            if obj.contains_key("scenes") && obj.contains_key("name") {
                return "scn";
            }
            if obj.contains_key("width") && obj.contains_key("height") && obj.contains_key("layers")
            {
                return "pimg";
            }
            if obj.get("id").and_then(|v| v.as_str()) == Some("motion") {
                return "mtn";
            }
        }
        "psb"
    }
}

/// Unwrap an `mdf\0` zlib-compressed PSB buffer, or return a slice of raw `PSB\0`.
pub fn unwrap_mdf_if_needed(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.starts_with(b"mdf\0") {
        if raw.len() < 8 {
            bail!("truncated MDF header");
        }
        let uncomp_len = u32::from_le_bytes(raw[4..8].try_into().unwrap()) as usize;
        let mut decoder = ZlibDecoder::new(&raw[8..]);
        let mut out = Vec::with_capacity(uncomp_len.min(32 * 1024 * 1024));
        decoder.read_to_end(&mut out)?;
        Ok(out)
    } else if raw.starts_with(b"PSB\0") {
        Ok(raw.to_vec())
    } else {
        bail!("buffer is neither PSB\\0 nor mdf\\0")
    }
}

struct PsbArray {
    end: usize,
    values: Vec<u64>,
}

#[allow(dead_code)]
struct PsbParser<'a> {
    data: &'a [u8],
    header: PsbHeader,
    names: Vec<String>,
    strings: Vec<String>,
}

impl<'a> PsbParser<'a> {
    fn read_uint_n(data: &[u8], offset: usize, size: usize) -> Result<u64> {
        if size == 0 {
            return Ok(0);
        }
        if size > 8 || offset + size > data.len() {
            bail!("PSB integer read out of bounds (off=0x{offset:x}, size={size})");
        }
        let mut buf = [0u8; 8];
        buf[..size].copy_from_slice(&data[offset..offset + size]);
        Ok(u64::from_le_bytes(buf))
    }

    fn read_psb_array(data: &[u8], offset: usize) -> Result<PsbArray> {
        if offset >= data.len() {
            bail!("PSB array offset 0x{offset:x} out of bounds");
        }
        let mut cursor = offset;
        let count_type = data[cursor];
        cursor += 1;
        if count_type < 0x0D || count_type > 0x14 {
            bail!("invalid PSB array count type 0x{count_type:02x} at 0x{offset:x}");
        }
        let count_width = (count_type - 0x0C) as usize;
        let count = Self::read_uint_n(data, cursor, count_width)? as usize;
        cursor += count_width;

        if cursor >= data.len() {
            bail!("truncated PSB array entry type at 0x{cursor:x}");
        }
        let entry_type = data[cursor];
        cursor += 1;
        if entry_type < 0x0D || entry_type > 0x14 {
            bail!("invalid PSB array entry type 0x{entry_type:02x} at 0x{:x}", cursor - 1);
        }
        let entry_width = (entry_type - 0x0C) as usize;

        if count > 4_000_000 || cursor + count.saturating_mul(entry_width) > data.len() {
            bail!("PSB array length {count} exceeds file bounds");
        }

        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(Self::read_uint_n(data, cursor, entry_width)?);
            cursor += entry_width;
        }
        Ok(PsbArray {
            end: cursor,
            values,
        })
    }

    fn decode_names(data: &[u8], offset_names: usize) -> Result<Vec<String>> {
        let a1 = Self::read_psb_array(data, offset_names)?;
        let a2 = Self::read_psb_array(data, a1.end)?;
        let a3 = Self::read_psb_array(data, a2.end)?;

        let mut names = Vec::with_capacity(a3.values.len());
        for &start_idx in &a3.values {
            let mut accum = Vec::new();
            let a = start_idx as usize;
            let Some(&b_val) = a2.values.get(a) else {
                bail!("PSB name b-tree index out of bounds");
            };
            let mut b = b_val as usize;
            let mut steps = 0usize;
            loop {
                if steps > 512 {
                    bail!("PSB name b-tree loop exceeded safety limit");
                }
                steps += 1;
                let Some(&c_val) = a2.values.get(b) else {
                    bail!("PSB name b-tree parent index out of bounds");
                };
                let c = c_val as usize;
                let Some(&d_val) = a1.values.get(c) else {
                    bail!("PSB name b-tree offset index out of bounds");
                };
                let ch = b.wrapping_sub(d_val as usize) as u8;
                accum.push(ch);
                b = c;
                if b == 0 {
                    break;
                }
            }
            accum.reverse();
            names.push(String::from_utf8_lossy(&accum).into_owned());
        }
        Ok(names)
    }

    fn decode_strings(
        data: &[u8],
        offset_strings: usize,
        offset_strings_data: usize,
    ) -> Result<Vec<String>> {
        let offsets = Self::read_psb_array(data, offset_strings)?;
        let mut strings = Vec::with_capacity(offsets.values.len());
        for &rel in &offsets.values {
            let start = offset_strings_data.saturating_add(rel as usize);
            if start >= data.len() {
                strings.push(String::new());
                continue;
            }
            let end = data[start..]
                .iter()
                .position(|&b| b == 0)
                .map(|r| start + r)
                .unwrap_or(data.len());
            strings.push(String::from_utf8_lossy(&data[start..end]).into_owned());
        }
        Ok(strings)
    }

    fn parse_value(&self, offset: usize, depth: usize) -> Result<PsbValue> {
        if depth > 64 {
            bail!("PSB recursion depth limit exceeded");
        }
        if offset >= self.data.len() {
            bail!("PSB value offset 0x{offset:x} out of bounds");
        }
        let tag = self.data[offset];
        let cursor = offset + 1;

        match tag {
            0x01 => Ok(PsbValue::Null),
            0x02 => Ok(PsbValue::Bool(false)),
            0x03 => Ok(PsbValue::Bool(true)),
            0x04..=0x0C => {
                let size = (tag - 0x04) as usize;
                if size == 0 {
                    return Ok(PsbValue::Int(0));
                }
                let raw = Self::read_uint_n(self.data, cursor, size)?;
                let signed = if size < 8 {
                    let sign_bit = 1u64 << (size * 8 - 1);
                    if (raw & sign_bit) != 0 {
                        (raw | (!0u64 << (size * 8))) as i64
                    } else {
                        raw as i64
                    }
                } else {
                    raw as i64
                };
                Ok(PsbValue::Int(signed))
            }
            0x0D..=0x14 => {
                let arr = Self::read_psb_array(self.data, offset)?;
                Ok(PsbValue::IntArray(arr.values))
            }
            0x15..=0x18 => {
                let size = (tag - 0x14) as usize;
                let idx = Self::read_uint_n(self.data, cursor, size)? as usize;
                let s = self.strings.get(idx).cloned().unwrap_or_default();
                Ok(PsbValue::String(s))
            }
            0x19..=0x1C => {
                let size = (tag - 0x18) as usize;
                let idx = Self::read_uint_n(self.data, cursor, size)?;
                Ok(PsbValue::Resource(idx))
            }
            0x1D => Ok(PsbValue::Float(0.0)),
            0x1E => {
                let bytes: [u8; 4] = self
                    .data
                    .get(cursor..cursor + 4)
                    .ok_or_else(|| anyhow::anyhow!("truncated PSB f32"))?
                    .try_into()?;
                Ok(PsbValue::Float(f32::from_le_bytes(bytes) as f64))
            }
            0x1F => {
                let bytes: [u8; 8] = self
                    .data
                    .get(cursor..cursor + 8)
                    .ok_or_else(|| anyhow::anyhow!("truncated PSB f64"))?
                    .try_into()?;
                Ok(PsbValue::Float(f64::from_le_bytes(bytes)))
            }
            0x20 => {
                let offsets = Self::read_psb_array(self.data, cursor)?;
                let base = offsets.end;
                let mut list = Vec::with_capacity(offsets.values.len());
                for &rel in &offsets.values {
                    list.push(self.parse_value(base.saturating_add(rel as usize), depth + 1)?);
                }
                Ok(PsbValue::List(list))
            }
            0x21 => {
                let name_indices = Self::read_psb_array(self.data, cursor)?;
                let offsets = Self::read_psb_array(self.data, name_indices.end)?;
                let base = offsets.end;
                let mut map = BTreeMap::new();
                for (&name_idx, &rel) in name_indices.values.iter().zip(offsets.values.iter()) {
                    let key = self
                        .names
                        .get(name_idx as usize)
                        .cloned()
                        .unwrap_or_else(|| format!("_{name_idx}"));
                    let val = self.parse_value(base.saturating_add(rel as usize), depth + 1)?;
                    map.insert(key, val);
                }
                Ok(PsbValue::Object(map))
            }
            other => bail!("unsupported PSB value tag 0x{other:02x} at 0x{offset:x}"),
        }
    }
}

pub fn parse_psb(raw: &[u8]) -> Result<ParsedPsb> {
    let data = unwrap_mdf_if_needed(raw)?;
    if data.len() < 40 || &data[0..4] != b"PSB\0" {
        bail!("invalid PSB header");
    }

    let version = u16::from_le_bytes(data[4..6].try_into().unwrap());
    let encrypt = u16::from_le_bytes(data[6..8].try_into().unwrap());
    if encrypt != 0 {
        bail!("PSB uses encrypted section tables (encrypt=0x{encrypt:x})");
    }

    let offset_names = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;
    let offset_strings = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
    let offset_strings_data = u32::from_le_bytes(data[20..24].try_into().unwrap()) as usize;
    let offset_entries = u32::from_le_bytes(data[36..40].try_into().unwrap()) as usize;

    let header = PsbHeader {
        version,
        encrypt,
        offset_names,
        offset_strings,
        offset_strings_data,
        offset_entries,
    };

    let names = PsbParser::decode_names(&data, header.offset_names)?;
    let strings =
        PsbParser::decode_strings(&data, header.offset_strings, header.offset_strings_data)?;

    let parser = PsbParser {
        data: &data,
        header: header.clone(),
        names: names.clone(),
        strings: strings.clone(),
    };

    let root = parser.parse_value(header.offset_entries, 0)?;

    Ok(ParsedPsb {
        header,
        names,
        strings,
        root,
    })
}
