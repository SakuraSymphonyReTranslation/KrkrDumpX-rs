use crate::bres::{bres_key_from_url, decode_bres_root, decode_utf16le_lossy, decrypt_bres};
use crate::pe::{PeImage, ResourceId, find_optional_resource, find_resource, read_u16_le};
use crate::salt::{SaltOverride, recover_verified_salt};
use crate::tjs2::{Tjs2Bytecode, derive_media_name};
use anyhow::{Context, Result, bail};
use flate2::read::ZlibDecoder;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const DEFAULT_TABLE_RVA: u32 = 0x80E38;
pub const DEFAULT_BOOTSTRAP_ZLIB_OFFSET: usize = 8;

pub fn default_startup_resource() -> (ResourceId, ResourceId) {
    (ResourceId::Id(10), ResourceId::Name("STARTUP.TJS".into()))
}

pub fn default_bootstrap_resource() -> (ResourceId, ResourceId) {
    (ResourceId::Id(10), ResourceId::Name("BOOTSTRAP".into()))
}

pub fn default_text_resource() -> (ResourceId, ResourceId) {
    (ResourceId::Name("TEXT".into()), ResourceId::Id(127))
}

pub fn default_plugin_resource() -> (ResourceId, ResourceId) {
    (ResourceId::Id(10), ResourceId::Name("PLUGIN".into()))
}

#[derive(Debug, Clone)]
pub struct StaticRecoveryOptions<'a> {
    pub startup_resource: (ResourceId, ResourceId),
    pub bootstrap_resource: (ResourceId, ResourceId),
    pub text_resource: (ResourceId, ResourceId),
    pub plugin_resource: (ResourceId, ResourceId),
    pub salt_override: SaltOverride<'a>,
    pub table_rva: Option<u32>,
    pub bootstrap_zlib_offset: usize,
    pub bootstrap_prefix_override: Option<String>,
    pub archive_seed_override: Option<Vec<u8>>,
    pub verbose: bool,
}

impl<'a> Default for StaticRecoveryOptions<'a> {
    fn default() -> Self {
        Self {
            startup_resource: default_startup_resource(),
            bootstrap_resource: default_bootstrap_resource(),
            text_resource: default_text_resource(),
            plugin_resource: default_plugin_resource(),
            salt_override: SaltOverride {
                allow_full_scan: true,
                ..Default::default()
            },
            table_rva: None,
            bootstrap_zlib_offset: DEFAULT_BOOTSTRAP_ZLIB_OFFSET,
            bootstrap_prefix_override: None,
            archive_seed_override: None,
            verbose: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StaticRecoveryArtifacts {
    pub exe_path: PathBuf,
    pub salt: Vec<u8>,
    pub salt_source: String,
    pub salt_sha256: String,
    pub startup_key: String,
    pub startup_cipher: Vec<u8>,
    pub startup_plain: Vec<u8>,
    pub bootstrap_url: String,
    pub bootstrap_key: String,
    pub bootstrap_cipher: Vec<u8>,
    pub bootstrap_plain: Vec<u8>,
    pub bootstrap_zlib_offset: usize,
    pub dll_bytes: Vec<u8>,
    pub plugin_resource: Option<Vec<u8>>,
    pub table_rva: u32,
    pub config_table: BTreeMap<String, Vec<u8>>,
    pub bootstrap_prefix: String,
    pub bootstrap_prefix_source: String,
    pub warning: String,
    pub final_bootstrap: String,
    pub archive_unique_key: String,
    pub media_name: String,
    pub startup_strings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct StaticRecoverySummary {
    pub exe: String,
    pub salt_source: String,
    pub salt_sha256: String,
    pub startup_key: String,
    pub bootstrap_url: String,
    pub bootstrap_key: String,
    pub bootstrap_zlib_offset: usize,
    pub dll_table_rva: String,
    pub bootstrap_prefix: String,
    pub bootstrap_prefix_source: String,
    pub warning: String,
    pub final_bootstrap: String,
    pub archive_unique_key: String,
    pub media_name: String,
}

impl StaticRecoveryArtifacts {
    pub fn summary(&self) -> StaticRecoverySummary {
        StaticRecoverySummary {
            exe: self.exe_path.display().to_string(),
            salt_source: self.salt_source.clone(),
            salt_sha256: self.salt_sha256.clone(),
            startup_key: self.startup_key.clone(),
            bootstrap_url: self.bootstrap_url.clone(),
            bootstrap_key: self.bootstrap_key.clone(),
            bootstrap_zlib_offset: self.bootstrap_zlib_offset,
            dll_table_rva: format!("0x{:x}", self.table_rva),
            bootstrap_prefix: self.bootstrap_prefix.clone(),
            bootstrap_prefix_source: self.bootstrap_prefix_source.clone(),
            warning: self.warning.clone(),
            final_bootstrap: self.final_bootstrap.clone(),
            archive_unique_key: self.archive_unique_key.clone(),
            media_name: self.media_name.clone(),
        }
    }

    pub fn write_intermediates(&self, dir: &Path) -> Result<PathBuf> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("bres_salt.bin"), &self.salt)?;
        std::fs::write(dir.join("STARTUP_TJS.rcdata.bin"), &self.startup_cipher)?;
        std::fs::write(dir.join("STARTUP.TJS.dec"), &self.startup_plain)?;
        std::fs::write(dir.join("BOOTSTRAP.rcdata.bin"), &self.bootstrap_cipher)?;
        std::fs::write(dir.join("BOOTSTRAP.dec"), &self.bootstrap_plain)?;
        let dll_path = dir.join("bootstrap.dll");
        std::fs::write(&dll_path, &self.dll_bytes)?;
        if let Some(plugin) = &self.plugin_resource {
            std::fs::write(dir.join("PLUGIN.rcdata.bin"), plugin)?;
        }
        let summary_json = serde_json::to_string_pretty(&self.summary())?;
        std::fs::write(dir.join("static_recover.summary.json"), summary_json)?;
        Ok(dll_path)
    }
}

pub fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

pub fn decompress_bootstrap_dll(
    bootstrap_plain: &[u8],
    preferred_offset: usize,
) -> Result<(usize, Vec<u8>)> {
    if preferred_offset < bootstrap_plain.len() {
        if let Ok(dll) = zlib_decompress(&bootstrap_plain[preferred_offset..]) {
            if dll.starts_with(b"MZ") {
                return Ok((preferred_offset, dll));
            }
        }
    }

    // Auto-probe first 64 bytes for a valid zlib header decompressing to an MZ PE DLL
    let scan_limit = bootstrap_plain.len().min(64);
    for off in 0..scan_limit {
        if off == preferred_offset {
            continue;
        }
        if bootstrap_plain[off] == 0x78
            && matches!(
                bootstrap_plain.get(off + 1),
                Some(0x01 | 0x5E | 0x9C | 0xDA)
            )
        {
            if let Ok(dll) = zlib_decompress(&bootstrap_plain[off..]) {
                if dll.starts_with(b"MZ") {
                    return Ok((off, dll));
                }
            }
        }
    }

    bail!(
        "BOOTSTRAP decrypted ({} bytes) but did not zlib-decompress to a valid PE DLL (tried offset {} and probed 0..64)",
        bootstrap_plain.len(),
        preferred_offset
    )
}

fn try_parse_config_table_at(data: &[u8], start_off: usize) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut result = BTreeMap::new();
    let mut cursor = start_off;
    let mut entries = 0usize;

    while cursor < data.len() && entries < 64 {
        let Some(rel_nul) = data[cursor..].iter().position(|&b| b == 0) else {
            bail!("unterminated DLL config label at 0x{cursor:x}");
        };
        if rel_nul == 0 {
            break;
        }
        if rel_nul > 64 {
            bail!("implausibly long DLL config label ({rel_nul} bytes)");
        }
        let label_bytes = &data[cursor..cursor + rel_nul];
        if !label_bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            bail!("non-ASCII DLL config label at 0x{cursor:x}");
        }
        let label = std::str::from_utf8(label_bytes)?.to_string();
        cursor += rel_nul + 1;
        let len = read_u16_le(data, cursor)? as usize;
        cursor += 2;
        if cursor + len > data.len() {
            bail!("DLL config value for {label:?} exceeds file size");
        }
        result.insert(label, data[cursor..cursor + len].to_vec());
        cursor += len;
        entries += 1;
    }

    for required in ["PARAMS", "UNIQUE", "WARNING"] {
        if !result.contains_key(required) {
            bail!("DLL config table missing required label {required:?}");
        }
    }

    Ok(result)
}

/// Parse the `label\0 + u16 len + value` config table inside `bootstrap.dll`.
/// Checks explicit/default RVA `0x80E38` first, then automatically scans the PE for `PARAMS\0`.
pub fn parse_dll_config_table(
    dll_bytes: &[u8],
    explicit_table_rva: Option<u32>,
) -> Result<(u32, BTreeMap<String, Vec<u8>>)> {
    let pe = PeImage::from_bytes(PathBuf::from("bootstrap.dll"), dll_bytes.to_vec())?;
    let preferred_rva = explicit_table_rva.unwrap_or(DEFAULT_TABLE_RVA);

    if let Ok(off) = pe.rva_to_offset(preferred_rva) {
        if let Ok(table) = try_parse_config_table_at(&pe.data, off) {
            return Ok((preferred_rva, table));
        }
    }

    if let Some(rva) = explicit_table_rva {
        bail!("failed to parse DLL config table at explicit --table-rva 0x{rva:x}");
    }

    // Automatic fallback: scan for `PARAMS\0` anywhere in bootstrap.dll
    let needle = b"PARAMS\0";
    let mut start = 0usize;
    while start + needle.len() < pe.data.len() {
        if let Some(rel) = pe.data[start..]
            .windows(needle.len())
            .position(|w| w == needle)
        {
            let pos = start + rel;
            if let Ok(table) = try_parse_config_table_at(&pe.data, pos) {
                let rva = pe.offset_to_rva(pos).unwrap_or(pos as u32);
                return Ok((rva, table));
            }
            start = pos + 1;
        } else {
            break;
        }
    }

    bail!("could not locate DLL config table (PARAMS/UNIQUE/WARNING) in bootstrap.dll")
}

/// Run the static key recovery pipeline against a Kirikiri `.exe`.
pub fn recover_static_from_exe(
    exe_path: &Path,
    opts: &StaticRecoveryOptions<'_>,
) -> Result<StaticRecoveryArtifacts> {
    let exe = PeImage::load(exe_path)?;
    if opts.verbose {
        eprintln!(
            "[debug] loaded PE {}: sections={} resource_rva=0x{:x}",
            exe_path.display(),
            exe.sections.len(),
            exe.resource_rva
        );
    }

    let resources = exe.resources()?;
    let startup_cipher = find_resource(
        &resources,
        &opts.startup_resource.0,
        &opts.startup_resource.1,
    )
    .context("missing STARTUP.TJS PE resource")?
    .to_vec();
    let bootstrap_cipher = find_resource(
        &resources,
        &opts.bootstrap_resource.0,
        &opts.bootstrap_resource.1,
    )
    .context("missing BOOTSTRAP PE resource")?
    .to_vec();
    let text_resource = find_resource(&resources, &opts.text_resource.0, &opts.text_resource.1)
        .context("missing TEXT/127 PE resource")?;
    let plugin_resource = find_optional_resource(
        &resources,
        &opts.plugin_resource.0,
        &opts.plugin_resource.1,
    )
    .map(|b| b.to_vec());

    let startup_key = decode_bres_root(text_resource)?;
    let (salt, salt_source) =
        recover_verified_salt(&exe, &startup_cipher, &startup_key, &opts.salt_override)?;
    let salt_sha256 = hex::encode(Sha256::digest(&salt));

    let startup_plain = decrypt_bres(&startup_cipher, &startup_key, &salt);
    if !startup_plain.starts_with(b"TJS2100\0") {
        bail!("STARTUP.TJS did not decrypt to TJS2100\\0");
    }

    if opts.verbose {
        eprintln!(
            "[debug] STARTUP.TJS decrypted ({} bytes), salt_source={}",
            startup_plain.len(),
            salt_source
        );
    }

    let tjs = Tjs2Bytecode::parse(&startup_plain)?;
    let bootstrap_url = tjs.find_bootstrap_url()?;
    let bootstrap_key = bres_key_from_url(&bootstrap_url)?;

    let (bootstrap_prefix, prefix_source) = if let Some(ref ov) = opts.bootstrap_prefix_override {
        (ov.clone(), "CLI --bootstrap-prefix".to_string())
    } else {
        let (p, src) = tjs.resolve_bootstrap_prefix()?;
        (p, src.to_string())
    };

    let bootstrap_plain = decrypt_bres(&bootstrap_cipher, &bootstrap_key, &salt);
    let (actual_zlib_offset, dll_bytes) =
        decompress_bootstrap_dll(&bootstrap_plain, opts.bootstrap_zlib_offset)?;

    if opts.verbose {
        eprintln!(
            "[debug] BOOTSTRAP decrypted ({} bytes), zlib_offset={}, dll_bytes={}",
            bootstrap_plain.len(),
            actual_zlib_offset,
            dll_bytes.len()
        );
    }

    let (table_rva, config_table) = parse_dll_config_table(&dll_bytes, opts.table_rva)?;
    let unique_raw = config_table
        .get("UNIQUE")
        .ok_or_else(|| anyhow::anyhow!("DLL config table missing UNIQUE"))?;
    let warning_raw = config_table
        .get("WARNING")
        .ok_or_else(|| anyhow::anyhow!("DLL config table missing WARNING"))?;

    let archive_unique_key = decode_utf16le_lossy(unique_raw);
    let warning_end = warning_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(warning_raw.len());
    let warning = String::from_utf8_lossy(&warning_raw[..warning_end]).into_owned();
    let final_bootstrap = format!("{bootstrap_prefix}{warning}");
    let media_name = derive_media_name(&bootstrap_prefix);

    Ok(StaticRecoveryArtifacts {
        exe_path: exe_path.to_path_buf(),
        salt,
        salt_source,
        salt_sha256,
        startup_key,
        startup_cipher,
        startup_plain,
        bootstrap_url,
        bootstrap_key,
        bootstrap_cipher,
        bootstrap_plain,
        bootstrap_zlib_offset: actual_zlib_offset,
        dll_bytes,
        plugin_resource,
        table_rva,
        config_table,
        bootstrap_prefix,
        bootstrap_prefix_source: prefix_source,
        warning,
        final_bootstrap,
        archive_unique_key,
        media_name,
        startup_strings: tjs.strings,
    })
}
