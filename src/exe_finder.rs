use crate::pe::{PeImage, ResourceId, find_resource};
use anyhow::{Result, bail};
use std::path::{Path, PathBuf};

const IGNORED_EXE_SUBSTRINGS: &[&str] = &[
    "krkrdump",
    "unins",
    "uninstall",
    "setup",
    "crash",
    "vc_redist",
    "vcredist",
    "dxsetup",
    "pbd2json",
    "psbdecompile",
    "tlg2png",
    "hxcrypt",
    "garbro",
];

#[derive(Debug, Clone)]
pub struct ExeCandidate {
    pub path: PathBuf,
    pub score: i32,
    pub has_startup: bool,
    pub has_bootstrap: bool,
    pub has_text127: bool,
    pub file_size: u64,
}

/// Inspect an EXE to see if it looks like a Kirikiri bres/BOOTSTRAP/Hxv4 game executable.
pub fn probe_exe(
    path: &Path,
    startup_res: &(ResourceId, ResourceId),
    bootstrap_res: &(ResourceId, ResourceId),
    text_res: &(ResourceId, ResourceId),
) -> Option<ExeCandidate> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let image = PeImage::load(path).ok()?;
    let resources = image.resources().ok()?;

    let has_startup = find_resource(&resources, &startup_res.0, &startup_res.1).is_ok();
    let has_bootstrap = find_resource(&resources, &bootstrap_res.0, &bootstrap_res.1).is_ok();
    let has_text127 = find_resource(&resources, &text_res.0, &text_res.1).is_ok();

    let mut score = 0;
    if has_startup {
        score += 40;
    }
    if has_bootstrap {
        score += 40;
    }
    if has_text127 {
        score += 30;
    }
    if !image.is_64bit {
        score += 5;
    }

    let lower = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if IGNORED_EXE_SUBSTRINGS.iter().any(|s| lower.contains(s)) {
        score -= 100;
    }
    if lower.contains("config") || lower.contains("launcher") {
        score -= 15;
    }

    Some(ExeCandidate {
        path: path.to_path_buf(),
        score,
        has_startup,
        has_bootstrap,
        has_text127,
        file_size: meta.len(),
    })
}

/// Locate the game `.exe` starting from a directory, an `.exe` path, or an `.xp3` path.
pub fn find_game_exe(
    target: &Path,
    startup_res: &(ResourceId, ResourceId),
    bootstrap_res: &(ResourceId, ResourceId),
    text_res: &(ResourceId, ResourceId),
) -> Result<ExeCandidate> {
    if target.is_file() {
        let ext = target
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if ext == "exe" {
            let cand = probe_exe(target, startup_res, bootstrap_res, text_res)
                .ok_or_else(|| anyhow::anyhow!("{} is not a readable PE executable", target.display()))?;
            return Ok(cand);
        }
        // If user passed an `.xp3` file, search its parent directory for the game `.exe`.
        let parent = target.parent().unwrap_or_else(|| Path::new("."));
        return find_game_exe_in_dir(parent, startup_res, bootstrap_res, text_res);
    }

    if target.is_dir() {
        return find_game_exe_in_dir(target, startup_res, bootstrap_res, text_res);
    }

    bail!("target path does not exist: {}", target.display())
}

pub fn find_game_exe_in_dir(
    dir: &Path,
    startup_res: &(ResourceId, ResourceId),
    bootstrap_res: &(ResourceId, ResourceId),
    text_res: &(ResourceId, ResourceId),
) -> Result<ExeCandidate> {
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let is_exe = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("exe"))
            .unwrap_or(false);
        if !is_exe {
            continue;
        }
        if let Some(cand) = probe_exe(&path, startup_res, bootstrap_res, text_res) {
            candidates.push(cand);
        }
    }

    candidates.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| b.file_size.cmp(&a.file_size))
            .then_with(|| a.path.cmp(&b.path))
    });

    if let Some(best) = candidates.into_iter().next() {
        if best.has_startup && best.has_bootstrap && best.has_text127 {
            return Ok(best);
        }
        if best.score > 0 {
            return Ok(best);
        }
    }

    bail!(
        "no Kirikiri Hxv4 game .exe (with STARTUP.TJS / BOOTSTRAP / TEXT/127 resources) found in {}",
        dir.display()
    )
}

/// Discover `.xp3` archive files from a list of files or directories.
pub fn discover_xp3_archives(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut archives = Vec::new();
    for path in paths {
        if path.is_dir() {
            let mut dir_xp3s: Vec<PathBuf> = std::fs::read_dir(path)?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.is_file()
                        && p.extension()
                            .and_then(|e| e.to_str())
                            .map(|e| e.eq_ignore_ascii_case("xp3"))
                            .unwrap_or(false)
                })
                .collect();
            dir_xp3s.sort();
            archives.extend(dir_xp3s);
        } else if path.is_file() {
            let is_xp3 = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("xp3"))
                .unwrap_or(false);
            if is_xp3 {
                archives.push(path.clone());
            } else {
                // When given a game executable, collect all .xp3 archives beside it.
                let parent = path.parent().unwrap_or_else(|| Path::new("."));
                let mut dir_xp3s: Vec<PathBuf> = std::fs::read_dir(parent)?
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| {
                        p.is_file()
                            && p.extension()
                                .and_then(|e| e.to_str())
                                .map(|e| e.eq_ignore_ascii_case("xp3"))
                                .unwrap_or(false)
                    })
                    .collect();
                dir_xp3s.sort();
                archives.extend(dir_xp3s);
            }
        } else {
            bail!("archive path not found: {}", path.display());
        }
    }
    // Deduplicate while preserving order
    let mut seen = std::collections::HashSet::new();
    archives.retain(|p| seen.insert(p.clone()));
    Ok(archives)
}
