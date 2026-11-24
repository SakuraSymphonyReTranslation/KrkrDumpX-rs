use crate::bootstrap::{
    StaticRecoveryArtifacts, StaticRecoveryOptions, recover_static_from_exe,
};
use crate::classify::classify_bytes;
use crate::cli::{
    AnalyzeArgs, ExtractArgs, HashArgs, KeysArgs, RecoveryOverrides, RepackArgs, RunArgs,
    UnhashArgs,
};
use crate::derive::{DerivedFilterState, derive_from_bootstrap_dll};
use crate::descramble::{descramble_bytes, detect_scramble_mode};
use crate::drip::DripProgram;
use crate::exe_finder::{discover_xp3_archives, find_game_exe};
use crate::hash::{Hxv4Hasher, is_file_hash_hex, is_path_hash_hex};
use crate::hxv4::{Hxv4Record, parse_hxv4_table};
use crate::pe::{parse_resource_ref, parse_u32_radix, parse_u64_radix};
use crate::psb::parse_psb;
use crate::repack::{RepackOptions, repack_directory_to_hxv4_xp3, verify_repacked_xp3};
use crate::salt::SaltOverride;
use crate::unhash::{AutoUnhasher, save_hxnames_lst};
use crate::xp3::Xp3Archive;
use anyhow::{Context, Result, bail};
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

struct ResolvedKeyBundle {
    program: DripProgram,
    artifacts: Option<StaticRecoveryArtifacts>,
    derived: Option<DerivedFilterState>,
    startup_strings: Vec<String>,
}

fn build_recovery_options<'a>(
    ov: &'a RecoveryOverrides,
) -> Result<StaticRecoveryOptions<'a>> {
    let salt_rva = ov
        .salt_rva
        .as_deref()
        .map(parse_u32_radix)
        .transpose()
        .context("invalid --salt-rva")?;
    let salt_file_offset = ov
        .salt_file_offset
        .as_deref()
        .map(parse_u64_radix)
        .transpose()
        .context("invalid --salt-file-offset")?;
    let table_rva = ov
        .table_rva
        .as_deref()
        .map(parse_u32_radix)
        .transpose()
        .context("invalid --table-rva")?;
    let archive_seed_override = ov
        .archive_seed_hex
        .as_deref()
        .map(|s| {
            let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            hex::decode(&clean).context("invalid --archive-seed-hex")
        })
        .transpose()?;

    Ok(StaticRecoveryOptions {
        startup_resource: parse_resource_ref(&ov.startup_resource)?,
        bootstrap_resource: parse_resource_ref(&ov.bootstrap_resource)?,
        text_resource: parse_resource_ref(&ov.text_resource)?,
        plugin_resource: parse_resource_ref(&ov.plugin_resource)?,
        salt_override: SaltOverride {
            salt_file: ov.salt_file.as_deref(),
            salt_rva,
            salt_file_offset,
            allow_full_scan: true,
        },
        table_rva,
        bootstrap_zlib_offset: ov.bootstrap_zlib_offset,
        bootstrap_prefix_override: ov.bootstrap_prefix.clone(),
        archive_seed_override,
        verbose: ov.debug,
    })
}

fn resolve_keys_for_target(
    hint_path: &Path,
    ov: &RecoveryOverrides,
    temp_keys_dir: Option<&Path>,
    total_steps: usize,
) -> Result<ResolvedKeyBundle> {
    if let Some(ref drip_path) = ov.drip_program {
        println!(
            "[1/{total_steps}] Using existing drip program: {}",
            drip_path.display()
        );
        let program = DripProgram::load(drip_path)?;
        return Ok(ResolvedKeyBundle {
            program,
            artifacts: None,
            derived: None,
            startup_strings: Vec::new(),
        });
    }

    let opts = build_recovery_options(ov)?;

    // Step 1: Locate game .exe
    let exe_cand = if let Some(ref explicit_exe) = ov.exe {
        find_game_exe(
            explicit_exe,
            &opts.startup_resource,
            &opts.bootstrap_resource,
            &opts.text_resource,
        )?
    } else {
        find_game_exe(
            hint_path,
            &opts.startup_resource,
            &opts.bootstrap_resource,
            &opts.text_resource,
        )?
    };

    println!("[1/{total_steps}] Found game EXE: {}", exe_cand.path.display());

    // Step 2: Recover static bres/BOOTSTRAP/FilterManager keys
    println!(
        "[2/{total_steps}] Extracting keys statically from EXE (bres salt -> STARTUP.TJS -> BOOTSTRAP DLL -> FilterManager)..."
    );
    let artifacts = recover_static_from_exe(&exe_cand.path, &opts)?;

    println!("      salt_source       : {}", artifacts.salt_source);
    println!("      startup_key       : {}", artifacts.startup_key);
    println!("      bootstrap_key     : {}", artifacts.bootstrap_key);
    println!(
        "      bootstrap_prefix  : {} ({})",
        artifacts.bootstrap_prefix, artifacts.bootstrap_prefix_source
    );
    println!("      archive_unique_key: {}", artifacts.archive_unique_key);
    println!("      media_name        : {}", artifacts.media_name);

    // Write bootstrap.dll to a clean temp or keys dir so LoadLibraryW can load it
    let work_dir = match temp_keys_dir {
        Some(d) => d.to_path_buf(),
        None => std::env::temp_dir().join(format!("krkrdumpx_rs_{}", std::process::id())),
    };
    let should_cleanup = temp_keys_dir.is_none();
    std::fs::create_dir_all(&work_dir)?;
    let dll_path = work_dir.join("bootstrap.dll");
    std::fs::write(&dll_path, &artifacts.dll_bytes)?;

    let derived = derive_from_bootstrap_dll(
        &dll_path,
        &artifacts,
        opts.archive_seed_override.as_deref(),
    )?;

    println!(
        "      hxv4_key          : {}",
        derived.program.raw_json.hxv4_key
    );
    println!(
        "      hxv4_nonce0       : {}",
        derived.program.raw_json.hxv4_nonce0
    );
    println!(
        "      hxv4_nonce1       : {}",
        derived.program.raw_json.hxv4_nonce1
    );
    println!(
        "      archive_seed      : {}",
        hex::encode(derived.key_dump.archive_seed)
    );

    if should_cleanup {
        let _ = std::fs::remove_dir_all(&work_dir);
    }

    let startup_strings = artifacts.startup_strings.clone();
    let program = derived.program.clone();

    Ok(ResolvedKeyBundle {
        program,
        artifacts: Some(artifacts),
        derived: Some(derived),
        startup_strings,
    })
}

pub fn cmd_keys(args: KeysArgs) -> Result<()> {
    let opts = build_recovery_options(&args.recovery)?;
    let target = args.recovery.exe.as_deref().unwrap_or(&args.target);
    let exe_cand = find_game_exe(
        target,
        &opts.startup_resource,
        &opts.bootstrap_resource,
        &opts.text_resource,
    )?;

    println!("[1/2] Found game EXE: {}", exe_cand.path.display());
    println!("[2/2] Recovering static resources and keys...");

    let artifacts = recover_static_from_exe(&exe_cand.path, &opts)?;
    let dll_path = artifacts.write_intermediates(&args.work_dir)?;

    println!("  salt_source       : {}", artifacts.salt_source);
    println!("  salt_sha256       : {}", artifacts.salt_sha256);
    println!("  startup_key       : {}", artifacts.startup_key);
    println!("  bootstrap_key     : {}", artifacts.bootstrap_key);
    println!("  bootstrap_prefix  : {}", artifacts.bootstrap_prefix);
    println!("  archive_unique_key: {}", artifacts.archive_unique_key);
    println!("  dll_table_rva     : 0x{:x}", artifacts.table_rva);
    println!("  media_name        : {}", artifacts.media_name);
    println!("  work_dir          : {}", args.work_dir.display());

    if args.skip_derive {
        println!("(--skip-derive set; stopped after unpacking bootstrap.dll)");
        return Ok(());
    }

    let derived = derive_from_bootstrap_dll(
        &dll_path,
        &artifacts,
        opts.archive_seed_override.as_deref(),
    )?;

    let drip_out = args
        .out
        .unwrap_or_else(|| args.work_dir.join("drip_program.json"));
    derived.program.save(&drip_out)?;
    derived.key_dump.write_to_dir(&args.work_dir)?;

    println!("  hxv4_key          : {}", derived.program.raw_json.hxv4_key);
    println!(
        "  hxv4_nonce0       : {}",
        derived.program.raw_json.hxv4_nonce0
    );
    println!(
        "  hxv4_nonce1       : {}",
        derived.program.raw_json.hxv4_nonce1
    );
    if let Some(ref hk) = derived.program.raw_json.hash_key {
        println!("  hash_key          : {hk}");
    }
    println!(
        "  archive_seed      : {}",
        hex::encode(derived.key_dump.archive_seed)
    );
    println!("  wrote drip_program: {}", drip_out.display());
    Ok(())
}

#[derive(Serialize)]
struct Hxv4ArchiveDump<'a> {
    archive: &'a crate::xp3::Xp3ArchiveInfo,
    hxv4: crate::xp3::Hxv4Descriptor,
    record_count: usize,
    records: &'a [Hxv4Record],
}

#[derive(Serialize)]
struct FilterStateRecordDump {
    record_index: usize,
    archive_slot: u16,
    filter_flag: u16,
    filter_open_flag: u16,
    key: u64,
    key_hex: String,
    xp3_entry_index: Option<usize>,
    xp3_name: Option<String>,
    state_hex: String,
    state_dwords: [u32; 12],
}

#[derive(Serialize)]
struct FilterStatesArchiveDump {
    archive: String,
    path: String,
    record_count: usize,
    records: Vec<FilterStateRecordDump>,
}

pub fn cmd_analyze(args: AnalyzeArgs) -> Result<()> {
    let archives = discover_xp3_archives(&args.targets)?;
    if archives.is_empty() {
        bail!("no .xp3 archives found for {:?}", args.targets);
    }

    let hint = args
        .recovery
        .exe
        .as_deref()
        .unwrap_or_else(|| args.targets[0].as_path());
    let bundle = resolve_keys_for_target(hint, &args.recovery, None, 3)?;

    println!(
        "[3/3] Analyzing {} XP3 archive(s)...",
        archives.len()
    );

    let mut all_hxv4_dumps: Vec<serde_json::Value> = Vec::new();
    let mut all_state_dumps: Vec<FilterStatesArchiveDump> = Vec::new();
    let mut total_failed = 0usize;
    let mut total_unresolved = 0usize;

    for xp3_path in &archives {
        let mut archive = Xp3Archive::open(xp3_path)?;
        let protected = archive.entries.iter().filter(|e| e.is_protected()).count();
        let compressed = archive
            .entries
            .iter()
            .filter(|e| e.segments.iter().any(|s| s.is_compressed()))
            .count();

        let archive_name = xp3_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("archive.xp3");

        println!(
            "\n=== {archive_name} ===\n  size={} bytes | entries={} | protected={} | compressed={} | index=0x{:x} | hxv4={}",
            archive.info.size,
            archive.info.entry_count,
            protected,
            compressed,
            archive.info.resolved_index_offset,
            archive.info.has_hxv4
        );

        let hxv4_table = parse_hxv4_table(&mut archive, &bundle.program)?;
        let filter_states = match &hxv4_table {
            Some(tbl) => {
                println!(
                    "  Hxv4 table: offset=0x{:x} size=0x{:x} flags=0x{:x} records={}",
                    tbl.descriptor.offset,
                    tbl.descriptor.size,
                    tbl.descriptor.flags,
                    tbl.records.len()
                );

                if args.hxv4_json.is_some() {
                    all_hxv4_dumps.push(serde_json::to_value(Hxv4ArchiveDump {
                        archive: &archive.info,
                        hxv4: tbl.descriptor,
                        record_count: tbl.records.len(),
                        records: &tbl.records,
                    })?);
                }
                if args.states_json.is_some() {
                    let open_flag = args
                        .recovery
                        .force_open_flag
                        .unwrap_or(tbl.descriptor.flags & 1);
                    let mut state_recs = Vec::with_capacity(tbl.records.len());
                    for rec in &tbl.records {
                        let st = bundle.program.build_filter_state(rec.key, open_flag)?;
                        let mut dwords = [0u32; 12];
                        for i in 0..12 {
                            dwords[i] =
                                u32::from_le_bytes(st[i * 4..i * 4 + 4].try_into().unwrap());
                        }
                        state_recs.push(FilterStateRecordDump {
                            record_index: rec.record_index,
                            archive_slot: rec.archive_slot,
                            filter_flag: rec.filter_flag,
                            filter_open_flag: open_flag,
                            key: rec.key,
                            key_hex: format!("0x{:016x}", rec.key),
                            xp3_entry_index: rec.xp3_entry_index,
                            xp3_name: rec.xp3_name.clone(),
                            state_hex: hex::encode(st),
                            state_dwords: dwords,
                        });
                    }
                    all_state_dumps.push(FilterStatesArchiveDump {
                        archive: archive_name.to_string(),
                        path: xp3_path.display().to_string(),
                        record_count: state_recs.len(),
                        records: state_recs,
                    });
                }

                tbl.build_filter_states(
                    archive.entries.len(),
                    &bundle.program,
                    args.recovery.force_open_flag,
                )?
            }
            None => {
                println!("  Hxv4 table: none (standard/unencrypted XP3)");
                HashMap::new()
            }
        };

        if args.verify {
            let mut checked = 0usize;
            let mut adler_warn = 0usize;
            let mut failed = 0usize;
            let mut unresolved = 0usize;
            let mut type_counts: BTreeMap<&'static str, usize> = BTreeMap::new();

            let entries_snapshot = archive.entries.clone();
            for entry in &entries_snapshot {
                if entry.is_warning_entry() && !args.include_warning {
                    continue;
                }
                if let Some(limit) = args.max_entries {
                    if checked + adler_warn + failed + unresolved >= limit {
                        break;
                    }
                }
                let fs = filter_states.get(&entry.index);
                match archive.extract_entry(entry, fs) {
                    Ok(res) => {
                        let kind = classify_bytes(&res.data);
                        if res.filter_needed {
                            unresolved += 1;
                            if args.recovery.debug {
                                eprintln!(
                                    "  [unresolved] #{}: {:?} raw_adler=0x{:08x} exp={:?}",
                                    entry.index, entry.name, res.adler32, entry.adler32
                                );
                            }
                        } else if res.adler_ok == Some(false) {
                            if res.filter_applied && kind.is_recognized_header() {
                                adler_warn += 1;
                                *type_counts.entry(kind.label).or_insert(0) += 1;
                                if args.recovery.debug {
                                    eprintln!(
                                        "  [adler-warn/repacked] #{}: {:?} actual=0x{:08x} exp=0x{:08x} ({})",
                                        entry.index,
                                        entry.name,
                                        res.adler32,
                                        entry.adler32.unwrap_or(0),
                                        kind.label
                                    );
                                }
                            } else {
                                failed += 1;
                                if args.recovery.debug {
                                    eprintln!(
                                        "  [mismatch] #{}: {:?} actual=0x{:08x} exp=0x{:08x}",
                                        entry.index,
                                        entry.name,
                                        res.adler32,
                                        entry.adler32.unwrap_or(0)
                                    );
                                }
                            }
                        } else {
                            checked += 1;
                            *type_counts.entry(kind.label).or_insert(0) += 1;
                        }
                    }
                    Err(e) => {
                        failed += 1;
                        if args.recovery.debug {
                            eprintln!("  [error] #{}: {:?}: {e}", entry.index, entry.name);
                        }
                    }
                }
            }

            total_failed += failed;
            total_unresolved += unresolved;
            println!(
                "  verify: checked={checked} adler_warn={adler_warn} failed={failed} unresolved_filter={unresolved}{}",
                args.max_entries
                    .map(|n| format!(" (limited to {n})"))
                    .unwrap_or_default()
            );
            if !type_counts.is_empty() {
                println!("  detected file types:");
                for (label, count) in &type_counts {
                    println!("    {count:>6}  {label}");
                }
            }
        }
    }

    if let Some(ref p) = args.hxv4_json {
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(p, serde_json::to_string_pretty(&all_hxv4_dumps)?)?;
        println!("\nWrote Hxv4 table JSON: {}", p.display());
    }

    if let Some(ref p) = args.states_json {
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(p, serde_json::to_string_pretty(&all_state_dumps)?)?;
        println!("Wrote filter states JSON: {}", p.display());
    }

    if total_failed > 0 || total_unresolved > 0 {
        bail!(
            "verification reported failures (failed={total_failed}, unresolved_filter={total_unresolved})"
        );
    }
    Ok(())
}

#[derive(Serialize)]
struct ManifestEntry {
    archive: String,
    index: usize,
    xp3_name: String,
    flags: u32,
    original_size: u64,
    archived_size: u64,
    expected_adler32: Option<u32>,
    actual_adler32: Option<u32>,
    adler_ok: Option<bool>,
    filter_applied: bool,
    file_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pathname_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    filename_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hxv4_key: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolved_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolved_name: Option<String>,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

struct ExtractedTrack {
    uid: usize,
    manifest_idx: usize,
    archive_base_dir: PathBuf,
    current_path: PathBuf,
    xp3_name: String,
    detected_ext: String,
    domain_hash: Option<String>,
    file_hash: Option<String>,
}

pub fn cmd_run(args: RunArgs) -> Result<()> {
    let targets = if args.xp3.is_empty() {
        vec![args.target.clone()]
    } else {
        args.xp3.clone()
    };

    let output = match args.output {
        Some(o) => o,
        None => {
            let base = if args.target.is_dir() {
                args.target.clone()
            } else {
                args.target
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| PathBuf::from("."))
            };
            base.join("krkrdumpx_out")
        }
    };

    let extract_args = ExtractArgs {
        targets,
        output: output.clone(),
        no_unhash: args.no_unhash,
        descramble: args.descramble,
        names: args.names,
        export_lst: args
            .export_lst
            .or_else(|| Some(output.join("HxNames.auto.lst"))),
        dump_keys: args.dump_keys || args.keys_dir.is_some(),
        include_warning: args.include_warning,
        flat: args.flat,
        keyed_hash: args.keyed_hash,
        recovery: args.recovery,
    };

    run_extract_pipeline(extract_args, args.keys_dir.as_deref(), Some(&args.target))
}

pub fn cmd_extract(args: ExtractArgs) -> Result<()> {
    run_extract_pipeline(args, None, None)
}

fn run_extract_pipeline(
    args: ExtractArgs,
    explicit_keys_dir: Option<&Path>,
    exe_hint_override: Option<&Path>,
) -> Result<()> {
    let archives = discover_xp3_archives(&args.targets)?;
    if archives.is_empty() {
        bail!("no .xp3 archives found for {:?}", args.targets);
    }

    std::fs::create_dir_all(&args.output)?;
    let keys_dir = explicit_keys_dir
        .map(|p| p.to_path_buf())
        .or_else(|| {
            if args.dump_keys {
                Some(args.output.join("_keys"))
            } else {
                None
            }
        });

    let hint = args
        .recovery
        .exe
        .as_deref()
        .or(exe_hint_override)
        .unwrap_or_else(|| args.targets[0].as_path());

    let bundle = resolve_keys_for_target(hint, &args.recovery, keys_dir.as_deref(), 4)?;

    if let Some(ref kd) = keys_dir {
        if let Some(ref art) = bundle.artifacts {
            let _ = art.write_intermediates(kd);
        }
        let _ = bundle.program.save(&kd.join("drip_program.json"));
        if let Some(ref drv) = bundle.derived {
            let _ = drv.key_dump.write_to_dir(kd);
        }
        println!("      saved recovered keys to: {}", kd.display());
    }

    let hasher = Hxv4Hasher::new(
        bundle.program.media_name.clone(),
        bundle.program.hash_key,
        args.keyed_hash,
    );
    let mut unhasher = AutoUnhasher::new(hasher, HashSet::new(), HashSet::new());
    unhasher.seed_strings(&bundle.startup_strings);
    if let Some(ref lst) = args.names {
        let loaded = unhasher.load_optional_names_file(lst)?;
        println!(
            "      loaded {loaded} optional candidate names from {}",
            lst.display()
        );
    }

    println!(
        "[3/4] Analyzing & extracting {} XP3 archive(s) into {}...",
        archives.len(),
        args.output.display()
    );

    let mut manifest_records: Vec<ManifestEntry> = Vec::new();
    let mut tracked_files: Vec<ExtractedTrack> = Vec::new();
    let mut grand_type_counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut total_written = 0usize;
    let mut total_adler_warnings = 0usize;
    let mut total_failed = 0usize;
    let mut total_unresolved = 0usize;
    let mut total_descrambled = 0usize;
    let mut next_uid = 0usize;

    for xp3_path in &archives {
        let archive_name = xp3_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("archive.xp3")
            .to_string();
        let archive_stem = xp3_path
            .file_stem()
            .and_then(|n| n.to_str())
            .unwrap_or("archive")
            .to_string();

        let mut archive = Xp3Archive::open(xp3_path)?;
        let hxv4_table = parse_hxv4_table(&mut archive, &bundle.program)?;
        let (filter_states, entry_hashes): (
            HashMap<usize, crate::filter::FilterRuntimeState>,
            HashMap<usize, (String, String, u64)>,
        ) = match &hxv4_table {
            Some(tbl) => {
                let fs = tbl.build_filter_states(
                    archive.entries.len(),
                    &bundle.program,
                    args.recovery.force_open_flag,
                )?;
                let mut hm = HashMap::with_capacity(tbl.records.len());
                for rec in &tbl.records {
                    if rec.archive_slot == 0 {
                        if let Some(idx) = rec.xp3_entry_index {
                            hm.insert(
                                idx,
                                (rec.domain_hash.clone(), rec.file_hash.clone(), rec.key),
                            );
                        }
                    }
                }
                (fs, hm)
            }
            None => (HashMap::new(), HashMap::new()),
        };

        let archive_out_dir = if args.flat {
            args.output.clone()
        } else {
            args.output.join(&archive_stem)
        };
        std::fs::create_dir_all(&archive_out_dir)?;

        let entries_snapshot = archive.entries.clone();
        let total_entries = entries_snapshot
            .iter()
            .filter(|e| args.include_warning || !e.is_warning_entry())
            .count();

        let pb = ProgressBar::new(total_entries as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "  {prefix:<18} [{bar:32.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("#>-"),
        );
        pb.set_prefix(archive_name.clone());

        for entry in &entries_snapshot {
            if entry.is_warning_entry() && !args.include_warning {
                continue;
            }

            let hash_meta = entry_hashes.get(&entry.index).cloned();
            let fs = filter_states.get(&entry.index);

            let mut mrec = ManifestEntry {
                archive: archive_name.clone(),
                index: entry.index,
                xp3_name: entry.name.clone(),
                flags: entry.flags,
                original_size: entry.original_size,
                archived_size: entry.archived_size,
                expected_adler32: entry.adler32,
                actual_adler32: None,
                adler_ok: None,
                filter_applied: false,
                file_type: String::new(),
                pathname_hash: hash_meta.as_ref().map(|m| m.0.clone()),
                filename_hash: hash_meta.as_ref().map(|m| m.1.clone()),
                hxv4_key: hash_meta.as_ref().map(|m| m.2),
                resolved_dir: None,
                resolved_name: None,
                status: String::new(),
                output: None,
                error: None,
            };

            match archive.extract_entry(entry, fs) {
                Ok(res) => {
                    mrec.actual_adler32 = Some(res.adler32);
                    mrec.adler_ok = res.adler_ok;
                    mrec.filter_applied = res.filter_applied;

                    if res.filter_needed {
                        total_unresolved += 1;
                        mrec.status = "unresolved_filter".to_string();
                        mrec.error = Some(format!(
                            "filter required (raw_adler=0x{:08x}, expected=0x{:08x})",
                            res.adler32,
                            entry.adler32.unwrap_or(0)
                        ));
                        manifest_records.push(mrec);
                        pb.inc(1);
                        continue;
                    }

                    let kind = classify_bytes(&res.data);
                    *grand_type_counts.entry(kind.label).or_insert(0) += 1;
                    mrec.file_type = kind.label.to_string();

                    let mut detected_ext = kind.extension.to_string();
                    if (res.data.starts_with(b"PSB\0") || res.data.starts_with(b"mdf\0"))
                        && detected_ext == "psb"
                    {
                        if let Ok(psb) = parse_psb(&res.data) {
                            detected_ext = psb.kind_extension().to_string();
                        }
                    }

                    // Round 1 streaming scan on the decrypted buffer before dropping it
                    if !args.no_unhash {
                        if let Some((ref dh, ref fh, _)) = hash_meta {
                            unhasher.add_target_hashes(dh.clone(), fh.clone());
                        }
                        unhasher.scan_buffer_round1(&res.data);
                    }

                    // Optionally descramble Kirikiri scrambled UTF-16LE text on write
                    let final_bytes = if args.descramble && detect_scramble_mode(&res.data).is_some()
                    {
                        match descramble_bytes(&res.data) {
                            Ok((_, utf16)) => {
                                total_descrambled += 1;
                                let mut with_bom = Vec::with_capacity(utf16.len() + 2);
                                with_bom.extend_from_slice(&[0xFF, 0xFE]);
                                with_bom.extend_from_slice(&utf16);
                                with_bom
                            }
                            Err(_) => res.data,
                        }
                    } else {
                        res.data
                    };

                    let initial_name =
                        initial_safe_filename(entry.index, &entry.name, &detected_ext, hash_meta.as_ref());
                    let out_path = unique_path(&archive_out_dir, &initial_name);
                    if let Some(parent) = out_path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(&out_path, &final_bytes)?;

                    total_written += 1;
                    mrec.status = if res.adler_ok == Some(false) {
                        if res.filter_applied && kind.is_recognized_header() {
                            total_adler_warnings += 1;
                            "written_adler_ignored".to_string()
                        } else {
                            total_failed += 1;
                            "adler_mismatch".to_string()
                        }
                    } else {
                        "written".to_string()
                    };
                    mrec.output = Some(rel_string(&args.output, &out_path));

                    let manifest_idx = manifest_records.len();
                    manifest_records.push(mrec);

                    tracked_files.push(ExtractedTrack {
                        uid: next_uid,
                        manifest_idx,
                        archive_base_dir: archive_out_dir.clone(),
                        current_path: out_path,
                        xp3_name: entry.name.clone(),
                        detected_ext,
                        domain_hash: hash_meta.as_ref().map(|m| m.0.clone()),
                        file_hash: hash_meta.as_ref().map(|m| m.1.clone()),
                    });
                    next_uid += 1;
                }
                Err(e) => {
                    total_failed += 1;
                    mrec.status = "error".to_string();
                    mrec.error = Some(e.to_string());
                    manifest_records.push(mrec);
                }
            }

            pb.inc(1);
        }
        pb.finish_and_clear();
        println!(
            "  done {:<18}: {} entries",
            archive_name, total_entries
        );
    }

    // Phase B: Cross-archive iterative auto-unhashing and renaming
    let mut unhashed_files = 0usize;
    let mut unhashed_dirs = 0usize;
    let mut total_hashed_entries = 0usize;

    if !args.no_unhash {
        let disk_entries: Vec<(usize, String, PathBuf)> = tracked_files
            .iter()
            .filter_map(|t| {
                t.file_hash
                    .as_ref()
                    .map(|fh| (t.uid, fh.clone(), t.current_path.clone()))
            })
            .collect();
        total_hashed_entries = disk_entries.len();

        if total_hashed_entries > 0 {
            println!(
                "\n[4/4] Running multi-round auto-unhasher on {} hashed entries (no .lst required)...",
                total_hashed_entries
            );
            let unhash_res = unhasher.run_disk_fixed_point(&disk_entries);
            unhashed_dirs = unhash_res.path_map.len();

            for track in &mut tracked_files {
                let resolved_dir = track
                    .domain_hash
                    .as_ref()
                    .and_then(|dh| unhash_res.path_map.get(dh))
                    .cloned();
                let resolved_file = track
                    .file_hash
                    .as_ref()
                    .and_then(|fh| unhash_res.file_map.get(fh))
                    .cloned();

                let mrec = &mut manifest_records[track.manifest_idx];
                mrec.resolved_dir = resolved_dir.clone();
                mrec.resolved_name = resolved_file.clone();

                let target_rel: Option<PathBuf> = match (&resolved_dir, &resolved_file) {
                    (_, Some(fname)) => {
                        unhashed_files += 1;
                        let mut rel = PathBuf::new();
                        if let Some(d) = resolved_dir.as_deref() {
                            for seg in d.split('/').filter(|s| !s.is_empty()) {
                                rel.push(sanitize_component(seg));
                            }
                        }
                        rel.push(sanitize_component(fname));
                        Some(rel)
                    }
                    (Some(d), None) if !d.is_empty() && !has_visible_ascii_name(&track.xp3_name) => {
                        let mut rel = PathBuf::new();
                        for seg in d.split('/').filter(|s| !s.is_empty()) {
                            rel.push(sanitize_component(seg));
                        }
                        let short_hash = track
                            .file_hash
                            .as_deref()
                            .map(|h| &h[..h.len().min(16)])
                            .unwrap_or("unknown");
                        rel.push(format!(
                            "unhashed_{:05}_{short_hash}.{}",
                            track.uid, track.detected_ext
                        ));
                        Some(rel)
                    }
                    _ => None,
                };

                if let Some(rel) = target_rel {
                    let desired = track.archive_base_dir.join(&rel);
                    if desired != track.current_path {
                        if let Some(parent) = desired.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        let final_dest = unique_path_full(&desired);
                        if std::fs::rename(&track.current_path, &final_dest).is_ok() {
                            track.current_path = final_dest.clone();
                            mrec.output = Some(rel_string(&args.output, &final_dest));
                        }
                    }
                }
            }

            if let Some(ref lst_out) = args.export_lst {
                if !unhash_res.file_map.is_empty() || !unhash_res.path_map.is_empty() {
                    save_hxnames_lst(lst_out, &unhash_res)?;
                    println!(
                        "      exported auto-discovered HxNames.lst -> {}",
                        lst_out.display()
                    );
                }
            }

            let pct = if total_hashed_entries > 0 {
                (unhashed_files as f64 / total_hashed_entries as f64) * 100.0
            } else {
                0.0
            };
            println!(
                "      auto-unhash complete ({} rounds, {} candidates tested): \
                 files={}/{} ({:.1}%), dirs={}",
                unhash_res.rounds,
                unhash_res.total_candidates_tested,
                unhashed_files,
                total_hashed_entries,
                pct,
                unhashed_dirs
            );
        }
    }

    // Write manifest.jsonl
    let manifest_path = args.output.join("manifest.jsonl");
    {
        let f = File::create(&manifest_path)?;
        let mut w = BufWriter::new(f);
        for rec in &manifest_records {
            writeln!(w, "{}", serde_json::to_string(rec)?)?;
        }
    }

    println!("\n=== Extraction Summary ===");
    println!("  Output dir        : {}", args.output.display());
    println!("  Manifest          : {}", manifest_path.display());
    println!(
        "  Entries           : written={} adler_warn={} failed={} unresolved_filter={}",
        total_written, total_adler_warnings, total_failed, total_unresolved
    );
    if total_adler_warnings > 0 {
        println!(
            "  Note              : {} entries had non-standard Adler32 (typical for HxCryptTool-repacked patch.xp3) but decrypted to valid file headers.",
            total_adler_warnings
        );
    }
    if total_descrambled > 0 {
        println!("  Descrambled texts : {total_descrambled}");
    }
    if !args.no_unhash && total_hashed_entries > 0 {
        println!(
            "  Unhashed names    : {unhashed_files}/{total_hashed_entries} files, {unhashed_dirs} dirs"
        );
    }
    if !grand_type_counts.is_empty() {
        println!("  File type breakdown:");
        for (label, count) in &grand_type_counts {
            println!("    {count:>6}  {label}");
        }
    }

    if total_failed > 0 || total_unresolved > 0 {
        bail!(
            "extraction completed with errors (failed={total_failed}, unresolved_filter={total_unresolved})"
        );
    }
    Ok(())
}

pub fn cmd_unhash(args: UnhashArgs) -> Result<()> {
    if !args.dir.is_dir() {
        bail!("target directory does not exist: {}", args.dir.display());
    }

    let hash_key = match &args.hash_key {
        Some(h) => {
            let raw = hex::decode(h).context("invalid --hash-key hex")?;
            if raw.len() != 32 {
                bail!("--hash-key must be 32 bytes (64 hex chars)");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&raw);
            Some(arr)
        }
        None => None,
    };

    let hasher = Hxv4Hasher::new(args.media_name.clone(), hash_key, args.keyed);
    let mut unhasher = AutoUnhasher::new(hasher, HashSet::new(), HashSet::new());

    if let Some(ref lst) = args.names {
        let count = unhasher.load_optional_names_file(lst)?;
        println!("Loaded {count} seed names from {}", lst.display());
    }

    // Collect hashed files & dirs and scan raw content in Round 1
    let mut disk_entries: Vec<(usize, String, PathBuf)> = Vec::new();
    let mut hashed_dirs: Vec<(String, PathBuf)> = Vec::new();
    let mut uid = 0usize;

    for entry in WalkDir::new(&args.dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path == args.dir {
            continue;
        }
        let name = entry.file_name().to_string_lossy();
        if entry.file_type().is_dir() {
            let low = name.to_ascii_lowercase();
            if is_path_hash_hex(&low) {
                unhasher.add_target_hashes(low.clone(), String::new());
                hashed_dirs.push((low, path.to_path_buf()));
            } else {
                // Already-unhashed directory name -> seed as path hint
                if let Ok(rel) = path.strip_prefix(&args.dir) {
                    let rel_str = rel.to_string_lossy().replace('\\', "/");
                    unhasher.add_path_candidate(&rel_str);
                }
            }
        } else if entry.file_type().is_file() {
            let stem = name.split('.').next().unwrap_or("");
            let stem_low = stem.to_ascii_lowercase();
            if is_file_hash_hex(&stem_low) {
                unhasher.add_target_hashes(String::new(), stem_low.clone());
                disk_entries.push((uid, stem_low, path.to_path_buf()));
                uid += 1;
            } else {
                unhasher.add_file_candidate(&name);
            }
            if let Ok(data) = std::fs::read(path) {
                unhasher.scan_buffer_round1(&data);
            }
        }
    }

    println!(
        "Scanning {} hashed files and {} hashed directories in {}...",
        disk_entries.len(),
        hashed_dirs.len(),
        args.dir.display()
    );

    let res = unhasher.run_disk_fixed_point(&disk_entries);

    if let Some(ref lst_out) = args.export_lst {
        save_hxnames_lst(lst_out, &res)?;
        println!("Exported HxNames.lst -> {}", lst_out.display());
    }

    let mut renamed_files = 0usize;
    let mut renamed_dirs = 0usize;

    // Rename files first
    for (_id, fh, path) in &disk_entries {
        if let Some(new_name) = res.file_map.get(fh) {
            let parent = path.parent().unwrap_or(&args.dir);
            let dest = unique_path(parent, &sanitize_component(new_name));
            if args.dry_run {
                println!(
                    "  [dry-run file] {} -> {}",
                    rel_string(&args.dir, path),
                    rel_string(&args.dir, &dest)
                );
                renamed_files += 1;
            } else if std::fs::rename(path, &dest).is_ok() {
                renamed_files += 1;
            }
        }
    }

    // Rename directories bottom-up (deepest first)
    hashed_dirs.sort_by(|a, b| b.1.components().count().cmp(&a.1.components().count()));
    for (dh, dir_path) in &hashed_dirs {
        if !dir_path.exists() {
            continue;
        }
        if let Some(rel_target) = res.path_map.get(dh) {
            let clean = rel_target.trim_matches('/');
            if clean.is_empty() {
                continue;
            }
            let parent = dir_path.parent().unwrap_or(&args.dir);
            let mut dest = parent.to_path_buf();
            for seg in clean.split('/').filter(|s| !s.is_empty()) {
                dest.push(sanitize_component(seg));
            }
            if args.dry_run {
                println!(
                    "  [dry-run dir ] {} -> {}",
                    rel_string(&args.dir, dir_path),
                    rel_string(&args.dir, &dest)
                );
                renamed_dirs += 1;
            } else {
                if let Some(p) = dest.parent() {
                    let _ = std::fs::create_dir_all(p);
                }
                if dest.exists() {
                    merge_dir(dir_path, &dest)?;
                    renamed_dirs += 1;
                } else if std::fs::rename(dir_path, &dest).is_ok() {
                    renamed_dirs += 1;
                }
            }
        }
    }

    println!(
        "Unhash complete ({} rounds, {} candidates): renamed {} files and {} directories.",
        res.rounds, res.total_candidates_tested, renamed_files, renamed_dirs
    );
    Ok(())
}

pub fn cmd_repack(args: RepackArgs) -> Result<()> {
    let total_steps = if args.verify { 4 } else { 3 };
    let hint = args.recovery.exe.as_deref().unwrap_or(&args.target);
    let bundle = resolve_keys_for_target(hint, &args.recovery, None, total_steps)?;

    let open_flag = args.recovery.force_open_flag.unwrap_or(args.open_flag);
    println!(
        "[3/{total_steps}] Repacking {} -> {} (Cxdec Hxv4, open_flag={open_flag})...",
        args.input_dir.display(),
        args.output.display()
    );

    let opts = RepackOptions {
        compress: args.compress,
        compression_level: args.compression_level,
        raw_index: args.raw_index,
        open_flag,
        preserve_case: args.preserve_case,
        raw_hashes: args.raw_hashes,
        keyed_hash: args.keyed_hash,
        show_progress: true,
    };

    let summary =
        repack_directory_to_hxv4_xp3(&args.input_dir, &args.output, &bundle.program, &opts)?;

    if args.verify {
        println!(
            "[4/{total_steps}] Verifying {} entries (Hxv4 auth + Cxdec decrypt + Adler32)...",
            summary.file_count
        );
        let verified =
            verify_repacked_xp3(&summary.output_path, &bundle.program, &summary.expected_hashes)?;
        println!("      verified          : {verified}/{} entries OK", summary.file_count);
    }

    println!("\n=== Repack Summary ===");
    println!("  Output XP3        : {}", summary.output_path.display());
    println!(
        "  Files             : {} ({} domain(s), {} compressed)",
        summary.file_count, summary.domain_count, summary.compressed_count
    );
    println!(
        "  Payload bytes     : {} -> {} archived",
        summary.total_original_bytes, summary.total_archived_bytes
    );
    println!(
        "  Hxv4 table        : offset=0x{:x} size={} bytes (flags=0x{:x})",
        summary.hxv4_offset, summary.hxv4_size, open_flag
    );
    println!(
        "  XP3 index         : offset=0x{:x} | total archive={} bytes",
        summary.index_offset, summary.archive_size
    );
    Ok(())
}

pub fn cmd_hash(args: HashArgs) -> Result<()> {
    let hash_key = match &args.hash_key {
        Some(h) => {
            let raw = hex::decode(h).context("invalid --hash-key hex")?;
            if raw.len() != 32 {
                bail!("--hash-key must be 32 bytes (64 hex chars)");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&raw);
            Some(arr)
        }
        None => None,
    };

    let hasher = Hxv4Hasher::new(args.media_name, hash_key, args.keyed);

    if args.paths.is_empty() && args.files.is_empty() {
        println!("pathHash(\"\") = {}", hasher.path_hash_hex(""));
        return Ok(());
    }

    for p in &args.paths {
        println!("pathHash({p:?}) = {}", hasher.path_hash_hex(p));
    }
    for f in &args.files {
        println!("fileHash({f:?}) = {}", hasher.file_hash_hex(f));
    }
    Ok(())
}

fn has_visible_ascii_name(xp3_name: &str) -> bool {
    !xp3_name.is_empty() && xp3_name.contains('.') && xp3_name.is_ascii()
}

fn initial_safe_filename(
    index: usize,
    xp3_name: &str,
    detected_ext: &str,
    hash_meta: Option<&(String, String, u64)>,
) -> String {
    if has_visible_ascii_name(xp3_name) {
        let leaf = xp3_name.replace('\\', "/");
        let leaf = leaf.rsplit('/').next().unwrap_or(&leaf);
        let safe = sanitize_component(leaf);
        if !safe.is_empty() {
            return safe;
        }
    }

    if let Some((_, fh, _)) = hash_meta {
        let short = &fh[..fh.len().min(16)];
        return format!("entry_{index:05}_{short}.{detected_ext}");
    }

    let cps: String = xp3_name
        .chars()
        .take(4)
        .map(|c| format!("{:04x}", c as u32))
        .collect::<Vec<_>>()
        .join("_");
    let tag = if cps.is_empty() { "unnamed" } else { &cps };
    format!("entry_{index:05}_{tag}.{detected_ext}")
}

fn sanitize_component(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') || (ch as u32) < 0x20
        {
            out.push('_');
        } else {
            out.push(ch);
        }
    }
    let trimmed = out.trim_matches(|c| c == ' ' || c == '.');
    if trimmed.is_empty() || trimmed == ".." {
        "_".to_string()
    } else {
        trimmed.to_string()
    }
}

fn unique_path(dir: &Path, name: &str) -> PathBuf {
    unique_path_full(&dir.join(name))
}

fn unique_path_full(candidate: &Path) -> PathBuf {
    if !candidate.exists() {
        return candidate.to_path_buf();
    }
    let parent = candidate.parent().unwrap_or_else(|| Path::new("."));
    let stem = candidate
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let ext = candidate.extension().and_then(|e| e.to_str());
    for i in 1..100_000 {
        let next = match ext {
            Some(e) => parent.join(format!("{stem}.{i}.{e}")),
            None => parent.join(format!("{stem}.{i}")),
        };
        if !next.exists() {
            return next;
        }
    }
    candidate.to_path_buf()
}

fn rel_string(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

fn merge_dir(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let s = entry.path();
        let d = dst.join(entry.file_name());
        if s.is_dir() {
            merge_dir(&s, &d)?;
        } else {
            let final_d = unique_path_full(&d);
            std::fs::rename(&s, &final_d)?;
        }
    }
    let _ = std::fs::remove_dir(src);
    Ok(())
}
