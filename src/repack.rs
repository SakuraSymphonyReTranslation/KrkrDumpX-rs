use crate::cli::CompressionMode;
use crate::drip::DripProgram;
use crate::filter::FilterRuntimeState;
use crate::hash::{Hxv4Hasher, is_file_hash_hex, is_path_hash_hex};
use crate::hxv4::{Hxv4WriteEntry, encode_hxv4_records, encrypt_hxv4_payload, parse_hxv4_table};
use crate::xp3::{XP3_MAGIC, Xp3Archive, calc_adler32, hxv4_fake_name};
use anyhow::{Context, Result, bail};
use flate2::Compression;
use flate2::write::ZlibEncoder;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use walkdir::WalkDir;

const XP3_HEADER_SIZE: u64 = 0x28;
const XP3_MINOR_HEADER_OFFSET: u64 = 0x17;
const XP3_MINOR_VERSION: u32 = 1;
const XP3_INDEX_CONTINUE: u8 = 0x80;
const XP3_FILE_PROTECTED: u32 = 0x8000_0000;

const WARNING_TEXT: &[u8] = b"Warning: Extracting this archive may infringe on author's rights.\n";
const WARNING_TOTAL_SIZE: usize = 128;

#[derive(Debug, Clone)]
pub struct RepackOptions {
    pub compress: CompressionMode,
    pub compression_level: u32,
    pub raw_index: bool,
    pub open_flag: u16,
    pub preserve_case: bool,
    pub raw_hashes: bool,
    pub keyed_hash: bool,
    pub show_progress: bool,
}

impl Default for RepackOptions {
    fn default() -> Self {
        Self {
            compress: CompressionMode::Auto,
            compression_level: 6,
            raw_index: false,
            open_flag: 0,
            preserve_case: false,
            raw_hashes: false,
            keyed_hash: false,
            show_progress: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RepackSummary {
    pub output_path: PathBuf,
    pub file_count: usize,
    pub domain_count: usize,
    pub compressed_count: usize,
    pub total_original_bytes: u64,
    pub total_archived_bytes: u64,
    pub archive_size: u64,
    pub hxv4_offset: u64,
    pub hxv4_size: u32,
    pub index_offset: u64,
    pub expected_hashes: Vec<([u8; 8], [u8; 32], u32)>,
}

struct InputFileItem {
    disk_path: PathBuf,
    rel_dir: String,
    file_name: String,
    domain_hash: [u8; 8],
    file_hash: [u8; 32],
}

struct WrittenFileEntry {
    name: String,
    flags: u32,
    original_size: u64,
    archived_size: u64,
    adler32: u32,
    seg_flags: u32,
    seg_offset: u64,
    seg_original_size: u64,
    seg_archived_size: u64,
}

fn is_already_compressed_ext(file_name: &str) -> bool {
    let Some((_, ext)) = file_name.rsplit_once('.') else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "png"
            | "jpg"
            | "jpeg"
            | "webp"
            | "gif"
            | "opus"
            | "ogg"
            | "mp3"
            | "m4a"
            | "mp4"
            | "wmv"
            | "avi"
            | "mkv"
            | "mpg"
            | "mpeg"
            | "zip"
            | "7z"
            | "rar"
            | "gz"
            | "bz2"
            | "xz"
            | "lz4"
            | "mdf"
    )
}

fn derive_entry_key(domain_hash: &[u8; 8], file_hash: &[u8; 32], entry_id: u32, adler32: u32) -> u64 {
    let mut h = Sha256::new();
    h.update(b"KrkrDumpX-rs:hxv4-entry-key:v1");
    h.update(domain_hash);
    h.update(file_hash);
    h.update(entry_id.to_le_bytes());
    h.update(adler32.to_le_bytes());
    let digest = h.finalize();
    let key = u64::from_le_bytes(digest[0..8].try_into().unwrap());
    if key == 0 { 0x9E37_79B9_7F4A_7C15 } else { key }
}

fn decode_hex_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    let raw = hex::decode(s).ok()?;
    if raw.len() != N {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&raw);
    Some(out)
}

fn compute_entry_hashes(
    rel_dir: &str,
    file_name: &str,
    hasher: &Hxv4Hasher,
    preserve_case: bool,
    raw_hashes: bool,
) -> ([u8; 8], [u8; 32]) {
    let norm_dir = if preserve_case {
        rel_dir.to_string()
    } else {
        rel_dir.to_ascii_lowercase()
    };
    let norm_file = if preserve_case {
        file_name.to_string()
    } else {
        file_name.to_ascii_lowercase()
    };

    let domain_hash = if raw_hashes {
        let trimmed = norm_dir.trim_end_matches('/');
        if !trimmed.contains('/') && is_path_hash_hex(trimmed) {
            decode_hex_array::<8>(trimmed).unwrap_or_else(|| hasher.path_hash_bytes(&norm_dir))
        } else {
            hasher.path_hash_bytes(&norm_dir)
        }
    } else {
        hasher.path_hash_bytes(&norm_dir)
    };

    let file_hash = if raw_hashes {
        let stem = norm_file.split('.').next().unwrap_or(&norm_file);
        if is_file_hash_hex(&norm_file) {
            decode_hex_array::<32>(&norm_file)
                .unwrap_or_else(|| hasher.file_hash_bytes(&norm_file))
        } else if is_file_hash_hex(stem) {
            decode_hex_array::<32>(stem).unwrap_or_else(|| hasher.file_hash_bytes(&norm_file))
        } else {
            hasher.file_hash_bytes(&norm_file)
        }
    } else {
        hasher.file_hash_bytes(&norm_file)
    };

    (domain_hash, file_hash)
}

fn collect_input_files(
    input_dir: &Path,
    output_path: &Path,
    hasher: &Hxv4Hasher,
    opts: &RepackOptions,
) -> Result<Vec<InputFileItem>> {
    if !input_dir.exists() {
        bail!("input directory does not exist: {}", input_dir.display());
    }
    if !input_dir.is_dir() {
        bail!("input path is not a directory: {}", input_dir.display());
    }

    let output_canon = std::fs::canonicalize(output_path).ok();
    let mut raw_paths: Vec<(String, String, PathBuf)> = Vec::new();

    for entry in WalkDir::new(input_dir).follow_links(false) {
        let entry = entry.with_context(|| {
            format!("failed to read directory entry under {}", input_dir.display())
        })?;
        if !entry.file_type().is_file() {
            continue;
        }
        let disk_path = entry.path().to_path_buf();
        if let Some(ref out_c) = output_canon {
            if let Ok(cur_c) = std::fs::canonicalize(&disk_path) {
                if cur_c == *out_c {
                    continue;
                }
            }
        }

        let rel = disk_path
            .strip_prefix(input_dir)
            .context("failed to compute relative path inside input directory")?;

        let mut parts: Vec<String> = Vec::new();
        for comp in rel.components() {
            if let Component::Normal(os) = comp {
                let s = os
                    .to_str()
                    .ok_or_else(|| {
                        anyhow::anyhow!("non-UTF-8 path component in {}", disk_path.display())
                    })?
                    .to_string();
                parts.push(s);
            }
        }
        if parts.is_empty() {
            continue;
        }

        let file_name = parts.pop().unwrap();
        let rel_dir = if parts.is_empty() {
            String::new()
        } else {
            let mut joined = parts.join("/");
            joined.push('/');
            joined
        };

        raw_paths.push((rel_dir, file_name, disk_path));
    }

    if raw_paths.is_empty() {
        bail!("no files found inside {}", input_dir.display());
    }

    // Root files first, then directories and filenames in deterministic ASCII-lowercase order.
    raw_paths.sort_by(|a, b| {
        let a_root = a.0.is_empty();
        let b_root = b.0.is_empty();
        b_root
            .cmp(&a_root)
            .then_with(|| a.0.to_ascii_lowercase().cmp(&b.0.to_ascii_lowercase()))
            .then_with(|| a.1.to_ascii_lowercase().cmp(&b.1.to_ascii_lowercase()))
            .then_with(|| a.0.cmp(&b.0))
            .then_with(|| a.1.cmp(&b.1))
    });

    let mut seen: HashMap<([u8; 8], [u8; 32]), String> = HashMap::with_capacity(raw_paths.len());
    let mut items = Vec::with_capacity(raw_paths.len());

    for (rel_dir, file_name, disk_path) in raw_paths {
        let (domain_hash, file_hash) = compute_entry_hashes(
            &rel_dir,
            &file_name,
            hasher,
            opts.preserve_case,
            opts.raw_hashes,
        );
        let logical = format!("{rel_dir}{file_name}");
        if let Some(prev) = seen.insert((domain_hash, file_hash), logical.clone()) {
            bail!(
                "duplicate Hxv4 hash for {:?} and {:?} (use --preserve-case if intentional)",
                prev,
                logical
            );
        }
        items.push(InputFileItem {
            disk_path,
            rel_dir,
            file_name,
            domain_hash,
            file_hash,
        });
    }

    Ok(items)
}

fn write_xp3_header_placeholder(w: &mut impl Write) -> Result<()> {
    let mut hdr = [0u8; XP3_HEADER_SIZE as usize];
    hdr[0..11].copy_from_slice(XP3_MAGIC);
    hdr[11..19].copy_from_slice(&XP3_MINOR_HEADER_OFFSET.to_le_bytes());
    hdr[19..23].copy_from_slice(&XP3_MINOR_VERSION.to_le_bytes());
    hdr[23] = XP3_INDEX_CONTINUE;
    // [24..32] = 0 (index size), [32..40] = 0 (patched with real index offset at end)
    w.write_all(&hdr)?;
    Ok(())
}

fn build_warning_blob() -> Vec<u8> {
    let mut blob = vec![0u8; WARNING_TOTAL_SIZE];
    let n = WARNING_TEXT.len().min(WARNING_TOTAL_SIZE);
    blob[..n].copy_from_slice(&WARNING_TEXT[..n]);
    blob
}

fn serialize_xp3_index(
    hxv4_offset: u64,
    hxv4_size: u32,
    hxv4_flags: u16,
    entries: &[WrittenFileEntry],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + entries.len() * 112);

    // Top-level Hxv4 descriptor chunk (matches official archive chunk order)
    out.extend_from_slice(b"Hxv4");
    out.extend_from_slice(&14u64.to_le_bytes());
    out.extend_from_slice(&hxv4_offset.to_le_bytes());
    out.extend_from_slice(&hxv4_size.to_le_bytes());
    out.extend_from_slice(&hxv4_flags.to_le_bytes());

    let mut sub = Vec::with_capacity(128);
    for entry in entries {
        sub.clear();

        // 1) adlr subchunk (4 bytes)
        sub.extend_from_slice(b"adlr");
        sub.extend_from_slice(&4u64.to_le_bytes());
        sub.extend_from_slice(&entry.adler32.to_le_bytes());

        // 2) segm subchunk (28 bytes)
        sub.extend_from_slice(b"segm");
        sub.extend_from_slice(&28u64.to_le_bytes());
        sub.extend_from_slice(&entry.seg_flags.to_le_bytes());
        sub.extend_from_slice(&entry.seg_offset.to_le_bytes());
        sub.extend_from_slice(&entry.seg_original_size.to_le_bytes());
        sub.extend_from_slice(&entry.seg_archived_size.to_le_bytes());

        // 3) info subchunk (22 + name_len*2 + 2 bytes UTF-16 NUL terminator)
        let name_units: Vec<u16> = entry.name.encode_utf16().collect();
        let info_len = 22 + name_units.len() * 2 + 2;
        sub.extend_from_slice(b"info");
        sub.extend_from_slice(&(info_len as u64).to_le_bytes());
        sub.extend_from_slice(&entry.flags.to_le_bytes());
        sub.extend_from_slice(&entry.original_size.to_le_bytes());
        sub.extend_from_slice(&entry.archived_size.to_le_bytes());
        sub.extend_from_slice(&(name_units.len() as u16).to_le_bytes());
        for unit in name_units {
            sub.extend_from_slice(&unit.to_le_bytes());
        }
        sub.extend_from_slice(&0u16.to_le_bytes());

        out.extend_from_slice(b"File");
        out.extend_from_slice(&(sub.len() as u64).to_le_bytes());
        out.extend_from_slice(&sub);
    }

    out
}

pub fn repack_directory_to_hxv4_xp3(
    input_dir: &Path,
    output_path: &Path,
    drip: &DripProgram,
    opts: &RepackOptions,
) -> Result<RepackSummary> {
    let hasher = Hxv4Hasher::new(drip.media_name.clone(), drip.hash_key, opts.keyed_hash);
    let items = collect_input_files(input_dir, output_path, &hasher, opts)?;

    if items.len() >= u32::MAX as usize {
        bail!("too many input files ({}) for XP3 Hxv4 table", items.len());
    }

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let file = File::create(output_path)
        .with_context(|| format!("failed to create output XP3 {}", output_path.display()))?;
    let mut writer = BufWriter::with_capacity(256 * 1024, file);

    write_xp3_header_placeholder(&mut writer)?;
    let mut offset = XP3_HEADER_SIZE;

    let mut written_entries = Vec::with_capacity(items.len() + 1);
    let mut hxv4_entries = Vec::with_capacity(items.len());
    let mut expected_hashes = Vec::with_capacity(items.len());
    let mut domains = HashSet::new();

    // Entry #0: protected-archive warning entry (synthetic ID 0 -> U+5000)
    let warning_blob = build_warning_blob();
    let warning_offset = offset;
    writer.write_all(&warning_blob)?;
    offset += warning_blob.len() as u64;
    written_entries.push(WrittenFileEntry {
        name: hxv4_fake_name(0),
        flags: 0,
        original_size: warning_blob.len() as u64,
        archived_size: warning_blob.len() as u64,
        adler32: calc_adler32(&warning_blob),
        seg_flags: 0,
        seg_offset: warning_offset,
        seg_original_size: WARNING_TEXT.len() as u64,
        seg_archived_size: WARNING_TEXT.len() as u64,
    });

    let pb = if opts.show_progress {
        let pb = ProgressBar::new(items.len() as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "  packing [{bar:32.cyan/blue}] {pos}/{len} ({percent}%) {msg}",
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        Some(pb)
    } else {
        None
    };

    let open_flag = opts.open_flag & 1;
    let level = Compression::new(opts.compression_level.min(9));
    let mut compressed_count = 0usize;
    let mut total_original_bytes = 0u64;
    let mut total_archived_bytes = 0u64;

    for (idx, item) in items.iter().enumerate() {
        let entry_id = (idx + 1) as u32;
        let mut data = std::fs::read(&item.disk_path)
            .with_context(|| format!("failed to read input file {}", item.disk_path.display()))?;
        let orig_size = data.len() as u64;
        let adler32 = calc_adler32(&data);

        let entry_key = derive_entry_key(&item.domain_hash, &item.file_hash, entry_id, adler32);
        let seed_state = drip.build_filter_state(entry_key, open_flag)?;
        let filter = FilterRuntimeState::from_seed_state(&seed_state);
        filter.apply(&mut data, 0);

        let should_try_compress = match opts.compress {
            CompressionMode::Never => false,
            CompressionMode::Always => !data.is_empty(),
            CompressionMode::Auto => !data.is_empty() && !is_already_compressed_ext(&item.file_name),
        };

        let (stored, seg_flags) = if should_try_compress {
            let mut enc = ZlibEncoder::new(Vec::new(), level);
            enc.write_all(&data)?;
            let comp = enc.finish()?;
            if opts.compress == CompressionMode::Always || comp.len() < data.len() {
                compressed_count += 1;
                (comp, 1u32)
            } else {
                (data, 0u32)
            }
        } else {
            (data, 0u32)
        };

        let seg_offset = offset;
        let arch_size = stored.len() as u64;
        writer.write_all(&stored)?;
        offset += arch_size;

        total_original_bytes += orig_size;
        total_archived_bytes += arch_size;
        domains.insert(item.domain_hash);

        written_entries.push(WrittenFileEntry {
            name: hxv4_fake_name(entry_id as u64),
            flags: XP3_FILE_PROTECTED,
            original_size: orig_size,
            archived_size: arch_size,
            adler32,
            seg_flags,
            seg_offset,
            seg_original_size: orig_size,
            seg_archived_size: arch_size,
        });

        hxv4_entries.push(Hxv4WriteEntry {
            domain_hash: item.domain_hash,
            file_hash: item.file_hash,
            entry_id,
            key: entry_key,
        });
        expected_hashes.push((item.domain_hash, item.file_hash, entry_id));

        if let Some(ref bar) = pb {
            if idx % 16 == 0 || idx + 1 == items.len() {
                bar.set_message(format!("{}{}", item.rel_dir, item.file_name));
            }
            bar.inc(1);
        }
    }

    if let Some(bar) = pb {
        bar.finish_and_clear();
    }

    // Write encrypted Hxv4 lookup table immediately after file data
    let hxv4_offset = offset;
    let table_blob = encode_hxv4_records(&hxv4_entries);
    let encrypted_hxv4 =
        encrypt_hxv4_payload(&table_blob, opts.open_flag, drip, opts.compression_level)?;
    let hxv4_size = u32::try_from(encrypted_hxv4.len())
        .map_err(|_| anyhow::anyhow!("encrypted Hxv4 table exceeds 4 GiB"))?;
    writer.write_all(&encrypted_hxv4)?;
    offset += encrypted_hxv4.len() as u64;

    // Write XP3 index immediately after Hxv4 payload
    let index_offset = offset;
    let index_raw = serialize_xp3_index(hxv4_offset, hxv4_size, opts.open_flag, &written_entries);
    if opts.raw_index {
        writer.write_all(&[0u8])?;
        writer.write_all(&(index_raw.len() as u64).to_le_bytes())?;
        writer.write_all(&index_raw)?;
        offset += 9 + index_raw.len() as u64;
    } else {
        let mut enc = ZlibEncoder::new(Vec::new(), level);
        enc.write_all(&index_raw)?;
        let index_comp = enc.finish()?;
        writer.write_all(&[1u8])?;
        writer.write_all(&(index_comp.len() as u64).to_le_bytes())?;
        writer.write_all(&(index_raw.len() as u64).to_le_bytes())?;
        writer.write_all(&index_comp)?;
        offset += 17 + index_comp.len() as u64;
    }

    // Patch real XP3 index offset at +0x20
    writer.flush()?;
    let mut inner = writer.into_inner()?;
    inner.seek(SeekFrom::Start(0x20))?;
    inner.write_all(&index_offset.to_le_bytes())?;
    inner.flush()?;

    Ok(RepackSummary {
        output_path: output_path.to_path_buf(),
        file_count: items.len(),
        domain_count: domains.len(),
        compressed_count,
        total_original_bytes,
        total_archived_bytes,
        archive_size: offset,
        hxv4_offset,
        hxv4_size,
        index_offset,
        expected_hashes,
    })
}

/// Re-open a written Hxv4 XP3 archive, authenticate its Hxv4 table, and decrypt/verify every entry.
pub fn verify_repacked_xp3(
    xp3_path: &Path,
    drip: &DripProgram,
    expected: &[([u8; 8], [u8; 32], u32)],
) -> Result<usize> {
    let mut archive = Xp3Archive::open(xp3_path)?;
    let table = parse_hxv4_table(&mut archive, drip)?
        .ok_or_else(|| anyhow::anyhow!("repacked XP3 is missing Hxv4 table"))?;

    if table.records.len() != expected.len() {
        bail!(
            "Hxv4 record count mismatch: got {}, expected {}",
            table.records.len(),
            expected.len()
        );
    }

    let filter_states = table.build_filter_states(archive.entries.len(), drip, None)?;
    let mut by_pair: HashMap<(&str, &str), usize> = HashMap::with_capacity(table.records.len());
    for rec in &table.records {
        let idx = rec
            .xp3_entry_index
            .ok_or_else(|| anyhow::anyhow!("Hxv4 record {} has no XP3 entry mapping", rec.record_index))?;
        by_pair.insert((&rec.domain_hash, &rec.file_hash), idx);
    }

    let mut verified = 0usize;
    let entries_snapshot = archive.entries.clone();
    for (dom, fh, entry_id) in expected {
        let dom_hex = hex::encode(dom);
        let fh_hex = hex::encode(fh);
        let Some(&entry_idx) = by_pair.get(&(dom_hex.as_str(), fh_hex.as_str())) else {
            bail!(
                "missing Hxv4 lookup entry for domain={dom_hex} file={fh_hex} (id={entry_id})"
            );
        };
        let entry = &entries_snapshot[entry_idx];
        let fs = filter_states.get(&entry_idx);
        let ext = archive.extract_entry(entry, fs)?;
        if ext.adler_ok != Some(true) {
            bail!(
                "Adler32 verification failed for repacked entry #{entry_idx} (id={entry_id})"
            );
        }
        if ext.filter_needed {
            bail!(
                "filter missing for repacked entry #{entry_idx} (id={entry_id})"
            );
        }
        verified += 1;
    }

    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drip::{
        DRIP_OP_ADD_IMM, DRIP_OP_SET_SEED, DRIP_OP_STOP, DRIP_OP_XOR_IMM, DripLaneJson,
        DripProgramJson,
    };

    fn make_test_drip() -> DripProgram {
        let lanes: Vec<DripLaneJson> = (0..128)
            .map(|i| DripLaneJson {
                index: i,
                begin_va: 0,
                end_va: 0,
                current_va: 0,
                ctx_va: 0,
                records: vec![
                    [0, DRIP_OP_SET_SEED],
                    [0x1357_9BDFu32.wrapping_add((i as u32).wrapping_mul(0x0101_0101)), DRIP_OP_XOR_IMM],
                    [0x2468_ACE1u32.wrapping_add(i as u32), DRIP_OP_ADD_IMM],
                    [0, DRIP_OP_STOP],
                ],
            })
            .collect();

        let payload = DripProgramJson {
            version: 1,
            source_module: "test.dll".to_string(),
            source_module_base: 0,
            manager_va: 0,
            drip_impl_va: 0,
            hxv4_key: hex::encode([0x42u8; 32]),
            hxv4_nonce0: hex::encode([0x10u8; 24]),
            hxv4_nonce1: hex::encode([0x21u8; 24]),
            hash_key: Some(hex::encode([0x77u8; 32])),
            media_name: Some("xp3hnp".to_string()),
            holder_words: vec![0, 0, 0x1122_3344, 0x5566_7788, 0x0FFF, 0x40],
            context_va: 0,
            context_u32: vec![0xA5A5_5A5A; 1024],
            callback_rva_base: 0,
            lanes,
        };
        DripProgram::from_json(payload).unwrap()
    }

    #[test]
    fn test_repack_and_decrypt_roundtrip() {
        let drip = make_test_drip();
        let tmp = std::env::temp_dir().join(format!(
            "krkrdumpx_repack_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let src_dir = tmp.join("patch_src");
        std::fs::create_dir_all(src_dir.join("scenario").join("sub")).unwrap();
        std::fs::create_dir_all(src_dir.join("image")).unwrap();

        let files: &[(&str, &[u8])] = &[
            ("Override.TJS", b"// override script\nvar x = 1234567890;\n".as_slice()),
            ("empty.txt", b"".as_slice()),
            ("scenario/sub/Start.ks", b"*start\r\nHello world! Hello world! Hello world!\r\n".as_slice()),
            ("image/test.png", &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
        ];
        for (rel, bytes) in files {
            let p = src_dir.join(rel);
            std::fs::write(&p, bytes).unwrap();
        }

        let out_xp3 = tmp.join("patch.xp3");
        let opts = RepackOptions {
            compress: CompressionMode::Auto,
            compression_level: 6,
            raw_index: false,
            open_flag: 0,
            preserve_case: false,
            raw_hashes: false,
            keyed_hash: false,
            show_progress: false,
        };

        let summary = repack_directory_to_hxv4_xp3(&src_dir, &out_xp3, &drip, &opts).unwrap();
        assert_eq!(summary.file_count, 4);
        assert_eq!(summary.domain_count, 3); // "", "image/", "scenario/sub/"

        let verified = verify_repacked_xp3(&out_xp3, &drip, &summary.expected_hashes).unwrap();
        assert_eq!(verified, 4);

        // Verify exact decrypted bytes and Hxv4 lookup hashes for each file
        let mut archive = Xp3Archive::open(&out_xp3).unwrap();
        assert!(archive.entries[0].is_warning_entry());
        let table = parse_hxv4_table(&mut archive, &drip).unwrap().unwrap();
        let states = table
            .build_filter_states(archive.entries.len(), &drip, None)
            .unwrap();
        let hasher = Hxv4Hasher::default();

        let checks = [
            ("", "override.tjs", files[0].1),
            ("", "empty.txt", files[1].1),
            ("scenario/sub/", "start.ks", files[2].1),
            ("image/", "test.png", files[3].1),
        ];
        for (dir, name, expected_bytes) in checks {
            let dh = hasher.path_hash_hex(dir);
            let fh = hasher.file_hash_hex(name);
            let rec = table
                .records
                .iter()
                .find(|r| r.domain_hash == dh && r.file_hash == fh)
                .unwrap_or_else(|| panic!("missing record for {dir}{name}"));
            let entry_idx = rec.xp3_entry_index.unwrap();
            let entry = archive.entries[entry_idx].clone();
            let ext = archive.extract_entry(&entry, states.get(&entry_idx)).unwrap();
            assert_eq!(ext.adler_ok, Some(true));
            assert_eq!(ext.data.as_slice(), expected_bytes);
        }

        // Also test open_flag = 1 (nonce1 + alternate filter branch) and raw_index = true
        let out_xp3_f1 = tmp.join("patch_f1.xp3");
        let opts_f1 = RepackOptions {
            open_flag: 1,
            raw_index: true,
            compress: CompressionMode::Never,
            show_progress: false,
            ..opts
        };
        let sum_f1 = repack_directory_to_hxv4_xp3(&src_dir, &out_xp3_f1, &drip, &opts_f1).unwrap();
        assert_eq!(sum_f1.compressed_count, 0);
        assert_eq!(
            verify_repacked_xp3(&out_xp3_f1, &drip, &sum_f1.expected_hashes).unwrap(),
            4
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_raw_hashes_mode() {
        let hasher = Hxv4Hasher::default();
        let root_dom = hasher.path_hash_hex("");
        let file_h = hasher.file_hash_hex("custom.tjs");

        let (dh, fh) = compute_entry_hashes(
            &format!("{root_dom}/"),
            &format!("{file_h}.tjs"),
            &hasher,
            false,
            true,
        );
        assert_eq!(hex::encode(dh), root_dom);
        assert_eq!(hex::encode(fh), file_h);
    }
}
