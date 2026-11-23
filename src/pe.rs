use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

impl Section {
    pub fn mapped_size(&self) -> u32 {
        self.virtual_size.max(self.raw_size)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResourceId {
    Id(u32),
    Name(String),
}

impl ResourceId {
    pub fn parse(s: &str) -> Self {
        if let Ok(v) = parse_u32_radix(s) {
            ResourceId::Id(v)
        } else {
            ResourceId::Name(s.to_string())
        }
    }

    pub fn matches(&self, other: &Self) -> bool {
        match (self, other) {
            (ResourceId::Id(a), ResourceId::Id(b)) => a == b,
            (ResourceId::Name(a), ResourceId::Name(b)) => a.eq_ignore_ascii_case(b),
            _ => false,
        }
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResourceId::Id(v) => write!(f, "{v}"),
            ResourceId::Name(s) => write!(f, "{s}"),
        }
    }
}

pub fn parse_resource_ref(spec: &str) -> Result<(ResourceId, ResourceId)> {
    let parts: Vec<&str> = spec.split('/').collect();
    if parts.len() != 2 {
        bail!("resource reference must be TYPE/NAME, e.g. 10/STARTUP.TJS, got {spec:?}");
    }
    Ok((ResourceId::parse(parts[0]), ResourceId::parse(parts[1])))
}

pub fn parse_u32_radix(s: &str) -> Result<u32> {
    let trimmed = s.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        Ok(u32::from_str_radix(hex, 16)?)
    } else {
        Ok(trimmed.parse::<u32>()?)
    }
}

pub fn parse_u64_radix(s: &str) -> Result<u64> {
    let trimmed = s.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        Ok(u64::from_str_radix(hex, 16)?)
    } else {
        Ok(trimmed.parse::<u64>()?)
    }
}

#[inline]
pub fn read_u16_le(data: &[u8], off: usize) -> Result<u16> {
    let bytes: [u8; 2] = data
        .get(off..off + 2)
        .ok_or_else(|| anyhow::anyhow!("out of bounds reading u16 at 0x{off:x}"))?
        .try_into()?;
    Ok(u16::from_le_bytes(bytes))
}

#[inline]
pub fn read_u32_le(data: &[u8], off: usize) -> Result<u32> {
    let bytes: [u8; 4] = data
        .get(off..off + 4)
        .ok_or_else(|| anyhow::anyhow!("out of bounds reading u32 at 0x{off:x}"))?
        .try_into()?;
    Ok(u32::from_le_bytes(bytes))
}

#[inline]
pub fn read_u64_le(data: &[u8], off: usize) -> Result<u64> {
    let bytes: [u8; 8] = data
        .get(off..off + 8)
        .ok_or_else(|| anyhow::anyhow!("out of bounds reading u64 at 0x{off:x}"))?
        .try_into()?;
    Ok(u64::from_le_bytes(bytes))
}

#[allow(dead_code)]
pub struct PeImage {
    pub path: PathBuf,
    pub data: Vec<u8>,
    pub is_64bit: bool,
    pub image_base: u64,
    pub resource_rva: u32,
    pub resource_size: u32,
    pub sections: Vec<Section>,
}

impl PeImage {
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)
            .with_context(|| format!("failed to read PE file {}", path.display()))?;
        Self::from_bytes(path.to_path_buf(), data)
    }

    pub fn from_bytes(path: PathBuf, data: Vec<u8>) -> Result<Self> {
        if data.len() < 0x40 || &data[0..2] != b"MZ" {
            bail!("{} is not a valid PE/MZ executable", path.display());
        }
        let pe_off = read_u32_le(&data, 0x3C)? as usize;
        if data.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
            bail!("{} missing PE\\0\\0 signature at 0x{pe_off:x}", path.display());
        }

        let coff = pe_off + 4;
        let section_count = read_u16_le(&data, coff + 2)? as usize;
        let optional_size = read_u16_le(&data, coff + 16)? as usize;
        let optional = coff + 20;
        let magic = read_u16_le(&data, optional)?;

        let (is_64bit, image_base, data_dir) = match magic {
            0x10B => (false, read_u32_le(&data, optional + 28)? as u64, optional + 96),
            0x20B => (true, read_u64_le(&data, optional + 24)?, optional + 112),
            _ => bail!(
                "{} has unsupported PE optional header magic 0x{magic:x}",
                path.display()
            ),
        };

        let resource_rva = if data_dir + 24 <= optional + optional_size {
            read_u32_le(&data, data_dir + 16)?
        } else {
            0
        };
        let resource_size = if data_dir + 24 <= optional + optional_size {
            read_u32_le(&data, data_dir + 20)?
        } else {
            0
        };

        let mut sections = Vec::with_capacity(section_count);
        let section_table = optional + optional_size;
        for i in 0..section_count {
            let off = section_table + i * 40;
            let raw_name = data
                .get(off..off + 8)
                .ok_or_else(|| anyhow::anyhow!("truncated section header {i}"))?;
            let nul = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&raw_name[..nul]).into_owned();
            let virtual_size = read_u32_le(&data, off + 8)?;
            let virtual_address = read_u32_le(&data, off + 12)?;
            let raw_size = read_u32_le(&data, off + 16)?;
            let raw_offset = read_u32_le(&data, off + 20)?;
            let characteristics = read_u32_le(&data, off + 36)?;
            sections.push(Section {
                name,
                virtual_address,
                virtual_size,
                raw_offset,
                raw_size,
                characteristics,
            });
        }

        Ok(Self {
            path,
            data,
            is_64bit,
            image_base,
            resource_rva,
            resource_size,
            sections,
        })
    }

    pub fn rva_to_offset(&self, rva: u32) -> Result<usize> {
        for sec in &self.sections {
            let start = sec.virtual_address;
            let end = start.saturating_add(sec.mapped_size());
            if rva >= start && rva < end {
                let rel = (rva - start) as usize;
                let off = (sec.raw_offset as usize).saturating_add(rel);
                if off <= self.data.len() {
                    return Ok(off);
                }
            }
        }
        bail!("RVA 0x{rva:x} is not mapped in {}", self.path.display())
    }

    pub fn offset_to_rva(&self, offset: usize) -> Result<u32> {
        for sec in &self.sections {
            let start = sec.raw_offset as usize;
            let end = start.saturating_add(sec.raw_size as usize);
            if offset >= start && offset < end {
                return Ok(sec.virtual_address + (offset - start) as u32);
            }
        }
        bail!(
            "file offset 0x{offset:x} is not mapped in {}",
            self.path.display()
        )
    }

    pub fn va_to_rva(&self, va: u64) -> Option<u32> {
        if va < self.image_base {
            return None;
        }
        u32::try_from(va - self.image_base).ok()
    }

    pub fn read_rva(&self, rva: u32, size: usize) -> Result<&[u8]> {
        let off = self.rva_to_offset(rva)?;
        self.data
            .get(off..off + size)
            .ok_or_else(|| anyhow::anyhow!("RVA 0x{rva:x} (+0x{size:x}) exceeds file size"))
    }

    pub fn resources(&self) -> Result<BTreeMap<(ResourceId, ResourceId, ResourceId), Vec<u8>>> {
        let mut out = BTreeMap::new();
        if self.resource_rva == 0 {
            return Ok(out);
        }
        let resource_off = self.rva_to_offset(self.resource_rva)?;
        let mut path_stack = Vec::new();
        self.walk_resource_dir(resource_off, 0, &mut path_stack, &mut out, 0)?;
        Ok(out)
    }

    fn read_resource_name(&self, resource_off: usize, name_rel: u32) -> Result<String> {
        let off = resource_off + name_rel as usize;
        let len = read_u16_le(&self.data, off)? as usize;
        let raw = self
            .data
            .get(off + 2..off + 2 + len * 2)
            .ok_or_else(|| anyhow::anyhow!("truncated PE resource name at 0x{off:x}"))?;
        let u16s: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Ok(String::from_utf16_lossy(&u16s))
    }

    fn walk_resource_dir(
        &self,
        resource_off: usize,
        dir_rel: u32,
        path_stack: &mut Vec<ResourceId>,
        out: &mut BTreeMap<(ResourceId, ResourceId, ResourceId), Vec<u8>>,
        depth: usize,
    ) -> Result<()> {
        if depth > 6 {
            return Ok(());
        }
        let base = resource_off + dir_rel as usize;
        let named = read_u16_le(&self.data, base + 12)? as usize;
        let ids = read_u16_le(&self.data, base + 14)? as usize;
        let total = named + ids;

        for i in 0..total {
            let entry = base + 16 + i * 8;
            let name_raw = read_u32_le(&self.data, entry)?;
            let child = read_u32_le(&self.data, entry + 4)?;

            let id = if name_raw & 0x8000_0000 != 0 {
                ResourceId::Name(self.read_resource_name(resource_off, name_raw & 0x7FFF_FFFF)?)
            } else {
                ResourceId::Id(name_raw)
            };

            path_stack.push(id);
            if child & 0x8000_0000 != 0 {
                self.walk_resource_dir(
                    resource_off,
                    child & 0x7FFF_FFFF,
                    path_stack,
                    out,
                    depth + 1,
                )?;
            } else if path_stack.len() == 3 {
                let data_entry = resource_off + child as usize;
                let rva = read_u32_le(&self.data, data_entry)?;
                let size = read_u32_le(&self.data, data_entry + 4)? as usize;
                if let Ok(bytes) = self.read_rva(rva, size) {
                    let key = (
                        path_stack[0].clone(),
                        path_stack[1].clone(),
                        path_stack[2].clone(),
                    );
                    out.insert(key, bytes.to_vec());
                }
            }
            path_stack.pop();
        }
        Ok(())
    }
}

pub fn find_resource<'a>(
    resources: &'a BTreeMap<(ResourceId, ResourceId, ResourceId), Vec<u8>>,
    res_type: &ResourceId,
    res_name: &ResourceId,
) -> Result<&'a [u8]> {
    for ((ty, name, _lang), data) in resources {
        if ty.matches(res_type) && name.matches(res_name) {
            return Ok(data.as_slice());
        }
    }
    let sample: Vec<String> = resources
        .keys()
        .take(12)
        .map(|(t, n, l)| format!("{t}/{n}/{l}"))
        .collect();
    if sample.is_empty() {
        bail!("resource {res_type}/{res_name} was not found; PE has no parsed resources");
    }
    bail!(
        "resource {res_type}/{res_name} was not found; available resources include: {}",
        sample.join(", ")
    )
}

pub fn find_optional_resource<'a>(
    resources: &'a BTreeMap<(ResourceId, ResourceId, ResourceId), Vec<u8>>,
    res_type: &ResourceId,
    res_name: &ResourceId,
) -> Option<&'a [u8]> {
    find_resource(resources, res_type, res_name).ok()
}

pub fn read_file_offset(path: &Path, offset: u64, size: usize) -> Result<Vec<u8>> {
    let mut f = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; size];
    f.read_exact(&mut buf).with_context(|| {
        format!(
            "{}: failed to read {size} bytes at offset 0x{offset:x}",
            path.display()
        )
    })?;
    Ok(buf)
}
