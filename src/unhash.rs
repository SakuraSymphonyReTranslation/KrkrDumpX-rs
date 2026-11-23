use crate::descramble::decode_kirikiri_text;
use crate::grammar::induce_family_candidates;
use crate::hash::{Hxv4Hasher, is_file_hash_hex, is_path_hash_hex};
use crate::pbd::{PbdValue, parse_pbd};
use crate::psb::{PsbValue, parse_psb};
use crate::tjs2::Tjs2Bytecode;
use anyhow::Result;
use regex::Regex;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::OnceLock;

/// Built-in seed directory paths common across Kirikiri / KAG / Yuzusoft Hxv4 games.
const SEED_DIRECTORIES: &[&str] = &[
    "",
    "/",
    "data/",
    "main/",
    "scenario/",
    "scn/",
    "bgimage/",
    "fgimage/",
    "evimage/",
    "bgm/",
    "sound/",
    "se/",
    "voice/",
    "voice2/",
    "video/",
    "movie/",
    "rule/",
    "system/",
    "sys/",
    "image/",
    "thum/",
    "thum/chthum/",
    "thum/cgthum/",
    "thum/savethum/",
    "thum/bgthum/",
    "thum/scnthum/",
    "uipsd/",
    "patch/",
    "upgrade/",
    "adult/",
    "locale/",
    "locale/jp/",
    "locale/en/",
    "locale/cn/",
    "locale/tw/",
    "data/main/",
    "data/scenario/",
    "data/bgimage/",
    "data/fgimage/",
    "data/evimage/",
    "data/thum/",
    "data/thum/chthum/",
    "data/uipsd/",
    "data/system/",
    "data/image/",
    "data/rule/",
    "data/locale/",
    "data/locale/jp/",
    "data/locale/en/",
    "data/locale/cn/",
    "data/locale/tw/",
    "data/sysscn/",
    "data/sound/",
    "data/bgm/",
    "data/se/",
    "data/voice/",
    "data/video/",
    "data/movie/",
    "data/font/",
    "data/fonts/",
    "data/sd/",
    "data/motion/",
    "data/others/",
    "data/script/",
    "data/scripts/",
    "data/kag/",
    "data/ui/",
    "data/gui/",
    "data/cg/",
    "data/ev/",
    "data/bg/",
    "data/fg/",
    "data/action/",
    "data/effect/",
    "data/filter/",
    "data/cut/",
    "data/cutin/",
    "data/ed/",
    "data/ending/",
    "data/face/",
    "data/emo/",
    "data/k2compat/",
    "data/trans/",
    "scenario/trans/",
    "trans/",
    "sysscn/",
    "k2compat/",
    "action/",
    "effect/",
    "filter/",
    "extrans/",
    "cut/",
    "cutin/",
    "ed/",
    "ending/",
    "staff/",
    "credit/",
    "face/",
    "emo/",
    "emotion/",
    "chthum/",
    "cgthum/",
    "bgthum/",
    "scnthum/",
    "savethum/",
    "icon/",
    "comu/",
    "phone/",
    "drama/",
    "title/",
    "config/",
    "option/",
    "save/",
    "load/",
    "backlog/",
    "dialog/",
    "extra/",
    "sd/",
    "motion/",
    "font/",
    "fonts/",
    "others/",
    "plugin/",
    "script/",
    "scripts/",
    "init/",
    "kag/",
    "ui/",
    "gui/",
    "cg/",
    "ev/",
    "bg/",
    "fg/",
];

/// Common Kirikiri/KAG/Yuzusoft/CIRCUS filenames used to seed Round 2 parsers.
const SEED_FILENAMES: &[&str] = &[
    "startup.tjs",
    "config.tjs",
    "initialize.tjs",
    "override.tjs",
    "override2.tjs",
    "appconfig.tjs",
    "AppConfig.tjs",
    "first.ks",
    "first.ks.scn",
    "macro.ks",
    "macro.ks.scn",
    "macro_1.ks",
    "macro_1.ks.scn",
    "replay.ks",
    "replay.ks.scn",
    "envplay.ks",
    "envplay.ks.scn",
    "version.ks",
    "version.ks.scn",
    "dramamode.ks",
    "dramamode.ks.scn",
    "cgmode.ks",
    "cgmode.ks.scn",
    "scenemode.ks",
    "scenemode.ks.scn",
    "musicmode.ks",
    "musicmode.ks.scn",
    "voicedrama.ks",
    "voicedrama.ks.scn",
    "base.stage",
    "cglist.csv",
    "charvoice.csv",
    "charinit.csv",
    "charlist.csv",
    "chardef.csv",
    "charadef.csv",
    "char.csv",
    "chara.csv",
    "stand.csv",
    "faceoffset.csv",
    "emooffset.csv",
    "standoffset.csv",
    "emopos.csv",
    "facepos.csv",
    "voicedrama.csv",
    "ngword.csv",
    "sysse.ini",
    "title_anim.ini",
    "currev.ini",
    "FAQbase.ini",
    "help_opt.txt",
    "yomi.txt",
    "speech_defdic.txt",
    "sysmenu.ks",
    "diffimage.txt",
    "imagediff.txt",
    "diffimage.csv",
    "desktop.ini",
    "thumbs.db",
    "aboutdialog.png",
    "brandlogo.png",
    "clickglyph.png",
    "clickglyph.asd",
    "cur_normal.cur",
    "cur_over.cur",
    "lang_jp.ini",
    "lang_en.ini",
    "lang_id.ini",
    "syslang.ini",
    "systext.ini",
    "uistring.ini",
    "_chthum_index.pbd",
    "filegain.csv",
    "imagediffmap.csv",
    "imagedressmap.txt",
    "imageevalmap.csv",
    "imagemulti.txt",
    "imagenamemap.txt",
    "imagepropmap.txt",
    "savelist.csv",
    "scenelist.csv",
    "soundgain.csv",
    "soundlist.csv",
    "systrans.ini",
    "bgm.csv",
    "bgmlist.csv",
    "se.csv",
    "selist.csv",
    "voicelist.csv",
    "voice.csv",
    "cgmode.csv",
    "cgmode.tjs",
    "scenemode.csv",
    "musicmode.csv",
    "charinfo.csv",
    "character.csv",
    "chardefs.tjs",
    "envinit.tjs",
    "custom.tjs",
    "deffontmap.tjs",
    "embfontlist.tjs",
    "embfontloader.tjs",
    "fontalias.tjs",
    "kag3.tjs",
    "mainwindow.tjs",
    "message.tjs",
    "world.tjs",
    "system.tjs",
    // KiriKiriZ / KAG / KAGEx / Yuzusoft engine framework scripts
    "checkboxlayer.tjs",
    "diffimage.tjs",
    "diffimage2.tjs",
    "keybinder.tjs",
    "snapcapture.tjs",
    "textspeedex.tjs",
    "vcutfade.tjs",
    "voicematch.tjs",
    "nameframe.tjs",
    "fonteffect.tjs",
    "exgamepad.tjs",
    "standlevel.tjs",
    "nocfchkdialog.tjs",
    "optrevundo.tjs",
    "designmscur.tjs",
    "append_setup_1.tjs",
    "affinesourcebishamon.tjs",
    "scnchart_ui_sel.tjs",
    "scnchart_ui_smp.tjs",
    "scnchart_ui_opt.tjs",
    "compat.ks",
    "gfx_motion.tjs",
    "gfx_noise.tjs",
    "gfx_texture.tjs",
    "emotetalk.tjs",
    "linebreak_a.png",
    "pagebreak_a.png",
    "help_aspect.png",
    "help_env.png",
    "version.txt",
    "readme.txt",
    "default.ttf",
    "default.otf",
    "op.mp4",
    "op.wmv",
    "op.amv",
    "op1080.mp4",
    "op1080.wmv",
    "ed.mp4",
    "ed.wmv",
];

fn regex_tjs_file_ref() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"["']([^"'\s<>|*?]+\.(?:tjs|ks|scn|ini|csv|txt|png|jpg|jpeg|bmp|tlg|pimg|ogg|opus|wav|mchx|sli|mp4|wmv|amv|webm|psb|pbd|stand|sinfo|mtn|stage|toml|ttf|otf|asd|cur))["']"#).unwrap()
    })
}

fn regex_unquoted_file_ref() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"([^\s"',;:()\[\]{}<>|*?=]+\.(?:tjs|ks|scn|ini|csv|txt|png|jpg|jpeg|bmp|tlg|pimg|ogg|opus|wav|mchx|sli|mp4|wmv|amv|webm|psb|pbd|stand|sinfo|mtn|stage|toml|ttf|otf|asd|cur))"#).unwrap()
    })
}

fn regex_storage_kv() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:storage|file|image|rule|cursor|graphic|icon|stamp)\s*(?:=>|:|=)\s*["']([^"'\r\n]+)["']"#).unwrap()
    })
}

fn regex_ini_asset_kv() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?im)^(?:image|storage|file|graphic|bg|icon|rule|sprite)(?:\.[A-Za-z0-9_]+)?\s*=\s*([^\s#:;,"']{2,64})"#).unwrap()
    })
}

fn regex_trans_method() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\bmethod\s*(?:=>|:|=)\s*["']([A-Za-z0-9_]+)["']"#).unwrap())
}

fn regex_printf_num_fmt() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"([A-Za-z0-9_]{2,32})%0?([1-4])?d"#).unwrap())
}

fn regex_quoted_dir_path() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"["']([^"'\s<>|*?]+/[^"'\s<>|*?]*?)["']"#).unwrap())
}

fn regex_stand_filename() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"["']?filename["']?\s*(?:=>|:|,)\s*['"]([^'"]+)['"]"#).unwrap())
}

fn regex_replay_movie() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\[(?:sysmovie|edmovie|movie)\s+[^\]]*file\s*=\s*"?([^"\s\]]+)"?"#).unwrap())
}

fn regex_tjs_kv_string() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"["']?([A-Za-z0-9_]+)["']?\s*(?:=>|:|,)\s*["']([^"']+)["']"#).unwrap())
}

fn regex_tiled_format() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"format\s*(?:=>|:|=)\s*["']([^"']*\$\{[xy]\}[^"']*)["']"#).unwrap())
}

fn regex_tiled_dim() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\b(horz|vert)\s*(?:=>|:|=)\s*(\d+)"#).unwrap())
}

fn regex_fmt_char_code() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"([A-Za-z0-9]+)%0?\d*d"#).unwrap())
}

fn regex_uipsd_base() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(.+?)(?:_(?:jp|en|cn|tw))?(?:__(?:bg\d+|pack))?\.(?:pbd|tlg)$").unwrap()
    })
}

/// Entry descriptor fed into the automatic no-`.lst` unhasher.
#[allow(dead_code)]
pub struct UnhashTarget<'a> {
    pub id: usize,
    pub domain_hash: String,
    pub file_hash: String,
    pub data: &'a [u8],
}

#[derive(Debug, Default, Clone)]
pub struct UnhashResult {
    /// lowercase 16-hex `domain_hash` -> resolved directory string (e.g. `""` or `"data/main/"`)
    pub path_map: BTreeMap<String, String>,
    /// lowercase 64-hex `file_hash` -> resolved filename (e.g. `"cglist.csv"`)
    pub file_map: BTreeMap<String, String>,
    pub rounds: usize,
    pub total_candidates_tested: usize,
}

pub struct AutoUnhasher {
    hasher: Hxv4Hasher,
    target_path_hashes: HashSet<String>,
    target_file_hashes: HashSet<String>,
    tested_paths: HashSet<String>,
    tested_files: HashSet<String>,
    pub path_map: BTreeMap<String, String>,
    pub file_map: BTreeMap<String, String>,
    pending_paths: Vec<String>,
    pending_files: Vec<String>,
    tjs_ident_tokens: HashSet<String>,
    underscore_prefixes: HashSet<String>,
    known_char_names: HashSet<String>,
    known_char_codes: HashSet<String>,
    voicedrama_stems: HashSet<String>,
    expanded_tjs_tokens: bool,
    last_combo_signature: (usize, usize, usize, usize, usize),
}

impl AutoUnhasher {
    pub fn new(
        hasher: Hxv4Hasher,
        target_path_hashes: HashSet<String>,
        target_file_hashes: HashSet<String>,
    ) -> Self {
        let mut s = Self {
            hasher,
            target_path_hashes,
            target_file_hashes,
            tested_paths: HashSet::new(),
            tested_files: HashSet::new(),
            path_map: BTreeMap::new(),
            file_map: BTreeMap::new(),
            pending_paths: Vec::new(),
            pending_files: Vec::new(),
            tjs_ident_tokens: HashSet::new(),
            underscore_prefixes: HashSet::new(),
            known_char_names: HashSet::new(),
            known_char_codes: HashSet::new(),
            voicedrama_stems: HashSet::new(),
            expanded_tjs_tokens: false,
            last_combo_signature: (0, 0, 0, 0, 0),
        };
        s.seed_defaults();
        s
    }

    fn seed_defaults(&mut self) {
        for &d in SEED_DIRECTORIES {
            self.add_path_candidate(d);
        }
        for &f in SEED_FILENAMES {
            self.add_file_candidate(f);
        }
    }

    /// Load extra candidates from an existing `HxNames.lst` (`hash:name`) or wordlist.
    pub fn load_optional_names_file(&mut self, path: &Path) -> Result<usize> {
        let content = std::fs::read_to_string(path)?;
        let mut count = 0usize;
        for raw_line in content.lines() {
            let line = raw_line.trim().trim_start_matches('\u{feff}');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((h, name)) = line.split_once(':') {
                let h_low = h.trim().to_ascii_lowercase();
                let name = name.trim();
                if name.is_empty() {
                    continue;
                }
                if is_path_hash_hex(&h_low) {
                    if self.target_path_hashes.contains(&h_low) {
                        self.path_map.entry(h_low).or_insert_with(|| name.to_string());
                    }
                    self.add_path_candidate(name);
                    count += 1;
                    continue;
                } else if is_file_hash_hex(&h_low) {
                    if self.target_file_hashes.contains(&h_low) {
                        self.file_map.entry(h_low).or_insert_with(|| name.to_string());
                    }
                    self.add_file_candidate(name);
                    count += 1;
                    continue;
                }
            }
            // Plain path or filename wordlist entry
            let norm = line.replace('\\', "/");
            if norm.ends_with('/') {
                self.add_path_candidate(&norm);
            } else if let Some((dir, file)) = norm.rsplit_once('/') {
                self.add_path_candidate(&format!("{dir}/"));
                self.add_file_candidate(file);
            } else {
                self.add_file_candidate(&norm);
            }
            count += 1;
        }
        Ok(count)
    }

    /// Seed extra strings harvested from `STARTUP.TJS` or other known metadata.
    pub fn seed_strings(&mut self, strings: &[String]) {
        for s in strings {
            self.harvest_string_hint(s);
        }
    }

    pub fn add_path_candidate(&mut self, raw: &str) {
        let cleaned = raw.trim().trim_matches('\u{feff}').replace('\\', "/");
        if cleaned.is_empty() || cleaned == "/" {
            if self.tested_paths.insert(String::new()) {
                self.pending_paths.push(String::new());
            }
            if self.tested_paths.insert("/".to_string()) {
                self.pending_paths.push("/".to_string());
            }
            return;
        }

        let trimmed = cleaned.trim_start_matches("./").trim_start_matches('/');
        if trimmed.is_empty() {
            return;
        }
        let with_slash = if trimmed.ends_with('/') {
            trimmed.to_string()
        } else {
            format!("{trimmed}/")
        };

        // Add full path, prefixes, and suffix sub-paths (like scan_unhashed_directory)
        let parts: Vec<&str> = with_slash.trim_end_matches('/').split('/').collect();
        for start in 0..parts.len() {
            let mut acc = String::new();
            for part in &parts[start..] {
                if part.is_empty() {
                    continue;
                }
                acc.push_str(part);
                acc.push('/');
                self.push_path_with_lower(&acc);
            }
        }
    }

    fn push_path_with_lower(&mut self, p: &str) {
        if self.tested_paths.insert(p.to_string()) {
            self.pending_paths.push(p.to_string());
        }
        let low = p.to_lowercase();
        if low != p && self.tested_paths.insert(low.clone()) {
            self.pending_paths.push(low);
        }
    }

    pub fn add_file_candidate(&mut self, raw: &str) {
        let cleaned = raw
            .trim()
            .trim_matches('\u{feff}')
            .trim_matches('"')
            .trim_matches('\'');
        if cleaned.is_empty() || cleaned.len() > 260 {
            return;
        }
        let norm = cleaned.replace('\\', "/");
        let name = if let Some((dir, file)) = norm.rsplit_once('/') {
            if !dir.is_empty() && !dir.contains("://") {
                self.add_path_candidate(dir);
            }
            file
        } else {
            norm.as_str()
        };
        if name.is_empty() || name.contains("://") {
            return;
        }
        if self.tested_files.insert(name.to_string()) {
            self.pending_files.push(name.to_string());
        }
        let low = name.to_lowercase();
        if low != name && self.tested_files.insert(low.clone()) {
            self.pending_files.push(low);
        }
    }

    /// Hash all newly queued candidates and match them against target Hxv4 hashes.
    /// Returns number of newly resolved target hashes.
    pub fn flush_candidates(&mut self) -> usize {
        let mut newly_resolved = 0usize;

        let paths = std::mem::take(&mut self.pending_paths);
        for p in paths {
            let h = self.hasher.path_hash_hex(&p);
            if self.target_path_hashes.contains(&h) && !self.path_map.contains_key(&h) {
                self.path_map.insert(h, p);
                newly_resolved += 1;
            }
        }

        let files = std::mem::take(&mut self.pending_files);
        for f in files {
            let h = self.hasher.file_hash_hex(&f);
            if self.target_file_hashes.contains(&h) && !self.file_map.contains_key(&h) {
                self.file_map.insert(h, f);
                newly_resolved += 1;
            }
        }

        newly_resolved
    }

    /// Register additional target hashes dynamically (used during streaming extraction).
    pub fn add_target_hashes(&mut self, domain_hash: String, file_hash: String) {
        if !domain_hash.is_empty() {
            self.target_path_hashes.insert(domain_hash);
        }
        if !file_hash.is_empty() {
            self.target_file_hashes.insert(file_hash);
        }
    }

    /// Run Round 1 content scan on a single decrypted entry buffer (streaming-friendly: caller can drop buffer immediately after).
    pub fn scan_buffer_round1(&mut self, data: &[u8]) {
        self.scan_raw_content(data);
    }

    /// Run iterative fixed-point Round 2+ analysis reading matched structured files lazily from disk.
    /// `disk_entries` maps `(entry_uid, file_hash_hex, disk_path)`.
    pub fn run_disk_fixed_point(
        &mut self,
        disk_entries: &[(usize, String, std::path::PathBuf)],
    ) -> UnhashResult {
        let mut rounds = 1usize;
        self.flush_candidates();

        let mut parsed_ids: HashSet<usize> = HashSet::new();
        let mut charvoice_path: Option<std::path::PathBuf> = None;
        let mut sysse_path: Option<std::path::PathBuf> = None;
        let mut charvoice_sysse_done = false;
        let mut grammar_done = false;

        for _ in 0..24 {
            rounds += 1;
            let mut found_work = false;

            let resolved: Vec<(usize, String, std::path::PathBuf)> = disk_entries
                .iter()
                .filter_map(|(id, fh, path)| {
                    self.file_map
                        .get(fh)
                        .map(|name| (*id, name.clone(), path.clone()))
                })
                .collect();

            for (id, name, path) in &resolved {
                let low = name.to_ascii_lowercase();
                if low == "charvoice.csv" {
                    charvoice_path = Some(path.clone());
                } else if low == "sysse.ini" {
                    sysse_path = Some(path.clone());
                }

                if parsed_ids.contains(id) {
                    continue;
                }
                parsed_ids.insert(*id);

                if is_analyzable_named_file(&low) {
                    found_work = true;
                    if let Ok(data) = std::fs::read(path) {
                        self.analyze_named_file(&low, name, &data);
                    }
                }
            }

            if !charvoice_sysse_done {
                if let (Some(cvp), Some(ssp)) = (&charvoice_path, &sysse_path) {
                    charvoice_sysse_done = true;
                    found_work = true;
                    if let (Ok(cv), Ok(ss)) = (std::fs::read(cvp), std::fs::read(ssp)) {
                        self.analyze_char_sys_voices(&cv, &ss);
                    }
                }
            }

            let all_known_names: Vec<String> = self.file_map.values().cloned().collect();
            self.expand_discovered_tokens_and_prefixes();
            self.expand_locale_and_uipsd_variants(&all_known_names);
            self.expand_missing_voices(&all_known_names);
            self.expand_numeric_images(&all_known_names);

            let mut newly_resolved = self.flush_candidates();
            if newly_resolved == 0 && !grammar_done {
                grammar_done = true;
                let known_now: Vec<String> = self.file_map.values().cloned().collect();
                for cand in induce_family_candidates(&known_now, 1_500_000) {
                    self.add_file_candidate(&cand);
                }
                newly_resolved = self.flush_candidates();
            }
            if newly_resolved == 0 && !found_work {
                break;
            }
            if newly_resolved == 0 {
                break;
            }
        }

        UnhashResult {
            path_map: self.path_map.clone(),
            file_map: self.file_map.clone(),
            rounds,
            total_candidates_tested: self.tested_paths.len() + self.tested_files.len(),
        }
    }

    /// Run full multi-round content-driven automatic unhashing on all decrypted archive entries.
    #[allow(dead_code)]
    pub fn run_auto_analysis(&mut self, targets: &[UnhashTarget<'_>]) -> UnhashResult {
        let mut rounds = 0usize;

        // Round 0: flush initial seeds + startup strings
        self.flush_candidates();

        // Round 1: scan raw decrypted entries before filenames are known
        rounds += 1;
        for t in targets {
            self.scan_raw_content(t.data);
        }
        self.flush_candidates();

        // Rounds 2+: iterative fixed-point parsers on resolved files
        let mut parsed_ids: HashSet<usize> = HashSet::new();
        let mut charvoice_buf: Option<&[u8]> = None;
        let mut sysse_buf: Option<&[u8]> = None;
        let mut charvoice_sysse_done = false;
        let mut grammar_done = false;

        for _ in 0..24 {
            rounds += 1;
            let mut found_work = false;

            // Snapshot resolved names by target id
            let resolved: Vec<(usize, String, &[u8])> = targets
                .iter()
                .filter_map(|t| {
                    self.file_map
                        .get(&t.file_hash)
                        .map(|name| (t.id, name.clone(), t.data))
                })
                .collect();

            for (id, name, data) in &resolved {
                let low = name.to_ascii_lowercase();
                if low == "charvoice.csv" {
                    charvoice_buf = Some(*data);
                } else if low == "sysse.ini" {
                    sysse_buf = Some(*data);
                }

                if parsed_ids.contains(id) {
                    continue;
                }
                parsed_ids.insert(*id);
                found_work = true;
                self.analyze_named_file(&low, name, data);
            }

            if !charvoice_sysse_done {
                if let (Some(cv), Some(ss)) = (charvoice_buf, sysse_buf) {
                    charvoice_sysse_done = true;
                    found_work = true;
                    self.analyze_char_sys_voices(cv, ss);
                }
            }

            // Expand tokens, locale/UIPSD variants, and audio/image sequences
            let all_known_names: Vec<String> = self.file_map.values().cloned().collect();
            self.expand_discovered_tokens_and_prefixes();
            self.expand_locale_and_uipsd_variants(&all_known_names);
            self.expand_missing_voices(&all_known_names);
            self.expand_numeric_images(&all_known_names);

            let mut newly_resolved = self.flush_candidates();
            if newly_resolved == 0 && !grammar_done {
                grammar_done = true;
                let known_now: Vec<String> = self.file_map.values().cloned().collect();
                for cand in induce_family_candidates(&known_now, 1_500_000) {
                    self.add_file_candidate(&cand);
                }
                newly_resolved = self.flush_candidates();
            }
            if newly_resolved == 0 && !found_work {
                break;
            }
            if newly_resolved == 0 {
                break;
            }
        }

        UnhashResult {
            path_map: self.path_map.clone(),
            file_map: self.file_map.clone(),
            rounds,
            total_candidates_tested: self.tested_paths.len() + self.tested_files.len(),
        }
    }

    fn harvest_string_hint(&mut self, s: &str) {
        let s = s.trim();
        if s.is_empty() || s.len() > 260 {
            return;
        }
        let norm = s.replace('\\', "/");
        if norm.contains('/') && !norm.contains("://") && !norm.contains(' ') {
            if norm.ends_with('/') {
                self.add_path_candidate(&norm);
            } else if let Some((dir, file)) = norm.rsplit_once('/') {
                self.add_path_candidate(dir);
                if file.contains('.') {
                    self.add_file_candidate(file);
                }
            }
        } else if norm.contains('.') && !norm.contains(' ') && !norm.contains("://") {
            self.add_file_candidate(&norm);
        }
    }

    /// Round 1 scanner operating on raw entry buffers before filenames are resolved.
    fn scan_raw_content(&mut self, data: &[u8]) {
        if data.len() < 4 {
            return;
        }

        // 1. PSB / MDF scenario & image files
        if data.starts_with(b"PSB\0") || data.starts_with(b"mdf\0") {
            if let Ok(psb) = parse_psb(data) {
                self.extract_from_psb(&psb.root);
                for s in &psb.strings {
                    if s.contains('/') && s.len() < 128 && !s.contains(' ') {
                        self.harvest_string_hint(s);
                    }
                    self.record_ident_token(s);
                }
            }
            return;
        }

        // 2. TJS2100 compiled bytecode
        if data.starts_with(b"TJS2100\0") {
            if let Ok(tjs) = Tjs2Bytecode::parse(data) {
                let mut local_prefixes: Vec<String> = Vec::new();
                let mut local_words: Vec<String> = Vec::new();
                for s in &tjs.strings {
                    self.harvest_string_hint(s);
                    if s.ends_with(".ks") {
                        self.add_file_candidate(&format!("{s}.scn"));
                    }
                    self.record_ident_token(s);
                    self.expand_printf_template(s);
                    let st = s.trim();
                    if (2..=24).contains(&st.len())
                        && st
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    {
                        if st.ends_with('_') && !st.starts_with('_') && st.len() >= 3 {
                            local_prefixes.push(st.to_ascii_lowercase());
                        } else if !st.starts_with('_')
                            && st.bytes().all(|b| b.is_ascii_alphanumeric())
                        {
                            local_words.push(st.to_ascii_lowercase());
                        }
                    }
                }
                if !local_prefixes.is_empty()
                    && !local_words.is_empty()
                    && local_prefixes.len().saturating_mul(local_words.len()) <= 4000
                {
                    for p in &local_prefixes {
                        for w in &local_words {
                            for ext in [".png", ".tjs", ".ks", ".ini", ".asd", ".cur"] {
                                self.add_file_candidate(&format!("{p}{w}{ext}"));
                            }
                        }
                    }
                }
            }
            return;
        }

        // 3. TLGref binary reference header (UTF-16LE filename at offset 0x2C)
        if data.len() >= 0x30 && data.starts_with(b"TLGref") {
            let tail = &data[0x2C..data.len().min(0x12C)];
            let mut chars = Vec::new();
            let mut ok = true;
            for chunk in tail.chunks_exact(2) {
                let code = u16::from_le_bytes([chunk[0], chunk[1]]);
                if code == 0 {
                    break;
                }
                if code >= 0x20 {
                    chars.push(code);
                } else {
                    ok = false;
                    break;
                }
            }
            if ok && !chars.is_empty() {
                let name = String::from_utf16_lossy(&chars);
                if name.to_ascii_lowercase().contains(".tlg") {
                    self.add_file_candidate(&name);
                }
            }
            return;
        }

        // 4. Binary PBD (`TJS/ns0` / `TJS/4s0`): extract holdimage refs before naming
        if data.starts_with(b"TJS/ns0") || data.starts_with(b"TJS/4s0") {
            if let Ok(pbd) = parse_pbd(data) {
                self.extract_from_unnamed_pbd(&pbd);
            }
            return;
        }

        // 5. Plain or Kirikiri-scrambled text: scan quoted & unquoted refs, .sinfo self-id,
        //    character/stand definition tables, and tiled image configs even before files are named.
        if data.len() <= 2 * 1024 * 1024 {
            if let Some(text) = decode_kirikiri_text(data) {
                self.scan_decoded_text_round1(&text);
            }
        }
    }

    fn expand_printf_template(&mut self, text: &str) {
        if !text.contains('%') {
            return;
        }
        for cap in regex_printf_num_fmt().captures_iter(text) {
            let Some(stem) = cap.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let width = cap
                .get(2)
                .and_then(|m| m.as_str().parse::<usize>().ok())
                .unwrap_or(2);
            for n in 0..=50usize {
                let name = format!("{stem}{n:0width$}");
                for ext in [".png", ".jpg", ".tlg", ".opus", ".ogg"] {
                    self.add_file_candidate(&format!("{name}{ext}"));
                }
            }
        }
    }

    fn record_ident_token(&mut self, raw: &str) {
        let s = raw.trim();
        if s.len() < 2 || s.len() > 48 || s.contains(' ') {
            return;
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return;
        }
        if s.ends_with('_') && s.len() >= 3 && s.len() <= 32 && !s.starts_with('_') {
            self.underscore_prefixes.insert(s.to_ascii_lowercase());
        } else if !s.starts_with('_') {
            self.tjs_ident_tokens.insert(s.to_ascii_lowercase());
        }
    }

    fn scan_decoded_text_round1(&mut self, text: &str) {
        for cap in regex_tjs_file_ref().captures_iter(text) {
            if let Some(m) = cap.get(1) {
                let reference = m.as_str();
                self.add_file_candidate(reference);
                if reference.to_ascii_lowercase().ends_with(".ks") {
                    self.add_file_candidate(&format!("{reference}.scn"));
                }
            }
        }

        // Quoted directory paths such as `setupSubFolders([ "image/ED/asa", "fgimage/..." ])`
        for cap in regex_quoted_dir_path().captures_iter(text) {
            let Some(m) = cap.get(1) else {
                continue;
            };
            let raw_path = m.as_str().trim();
            if raw_path.len() > 160
                || raw_path.contains("://")
                || raw_path.starts_with("//")
                || raw_path.contains("//")
                || raw_path.contains('*')
                || raw_path.contains('?')
            {
                continue;
            }
            let norm = raw_path.replace('\\', "/");
            let trimmed = norm.trim_start_matches("./").trim_start_matches('/');
            if trimmed.is_empty() {
                continue;
            }
            if let Some((_, tail)) = trimmed.rsplit_once('/') {
                if !tail.contains('.') {
                    self.add_path_candidate(trimmed);
                    // `fgimage/<char>` directories also identify character stand/psd stems
                    let low = trimmed.to_ascii_lowercase();
                    if low.starts_with("fgimage/") && !tail.is_empty() && tail.chars().count() <= 24
                    {
                        self.known_char_names.insert(tail.to_string());
                        self.add_file_candidate(&format!("{tail}.stand"));
                        for suffix in ["1_1", "1_2", "2_1"] {
                            self.add_file_candidate(&format!("{tail}{suffix}.txt"));
                            self.add_file_candidate(&format!("{tail}{suffix}.pbd"));
                            self.add_file_candidate(&format!("{tail}{suffix}.sinfo"));
                        }
                    }
                } else {
                    self.add_file_candidate(trimmed);
                }
            }
        }

        for cap in regex_unquoted_file_ref().captures_iter(text) {
            if let Some(m) = cap.get(1) {
                let reference = m.as_str().trim_start_matches(['#', '.', '/', '\\']);
                if reference.is_empty()
                    || reference.starts_with('.')
                    || reference.contains("://")
                    || reference.len() > 180
                {
                    continue;
                }
                self.add_file_candidate(reference);
                if reference.to_ascii_lowercase().ends_with(".ks") {
                    self.add_file_candidate(&format!("{reference}.scn"));
                }
            }
        }

        // Generic `storage:"..."` / `file:"..."` / `cursor:"..."` refs (ASCII or Unicode stems)
        for cap in regex_storage_kv().captures_iter(text) {
            if let Some(m) = cap.get(1) {
                let val = m.as_str().trim();
                if val.is_empty()
                    || val.chars().count() > 80
                    || val.contains([' ', '*', '?', '$', '%', '\t'])
                {
                    continue;
                }
                if val.contains('.') {
                    self.add_file_candidate(val);
                    if val.to_ascii_lowercase().ends_with(".ks") {
                        self.add_file_candidate(&format!("{val}.scn"));
                    }
                } else {
                    for ext in [
                        ".png", ".jpg", ".tlg", ".pimg", ".asd", ".cur", ".tjs", ".ks", ".ks.scn",
                        ".opus", ".ogg", ".ini",
                    ] {
                        self.add_file_candidate(&format!("{val}{ext}"));
                    }
                }
            }
        }

        // Unquoted INI asset assignments (`image.l1n = sakura_l1`)
        for cap in regex_ini_asset_kv().captures_iter(text) {
            if let Some(m) = cap.get(1) {
                let val = m.as_str().trim();
                if val.contains('.') {
                    self.add_file_candidate(val);
                } else {
                    for ext in [".png", ".jpg", ".tlg", ".pimg", ".asd"] {
                        self.add_file_candidate(&format!("{val}{ext}"));
                    }
                }
            }
        }

        // Transition preset TJS dicts (`%[ method:"blurfade", ... ]` -> `trans_blurfade.tjs`)
        if text.len() <= 4096 && text.contains("%[") {
            for cap in regex_trans_method().captures_iter(text) {
                if let Some(m) = cap.get(1) {
                    self.add_file_candidate(&format!("trans_{}.tjs", m.as_str()));
                }
            }
        }

        self.expand_printf_template(text);

        // Self-identifying `.sinfo` files: first non-empty line starts with `<stem>\tfacexoff\t` etc.
        if let Some(first_line) = text.lines().map(str::trim).find(|l| !l.is_empty()) {
            let mut cols = first_line.split('\t');
            if let (Some(stem), Some(tag)) = (cols.next(), cols.next()) {
                let tag_low = tag.trim().to_ascii_lowercase();
                if matches!(
                    tag_low.as_str(),
                    "facexoff" | "faceyoff" | "leveloffset" | "xoffset" | "yoffset" | "facezoom"
                ) {
                    let stem = stem.trim();
                    if !stem.is_empty() && stem.len() <= 80 && !stem.contains(' ') {
                        for ext in [".sinfo", ".pbd", ".txt", "_info.txt"] {
                            self.add_file_candidate(&format!("{stem}{ext}"));
                        }
                        // Derive `<char>.stand` by stripping trailing `_<digits>` and trailing digits
                        let base_no_us = stem
                            .rsplit_once('_')
                            .filter(|(_, tail)| {
                                !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit())
                            })
                            .map(|(head, _)| head)
                            .unwrap_or(stem);
                        let char_name = base_no_us.trim_end_matches(|c: char| c.is_ascii_digit());
                        if !char_name.is_empty() {
                            self.add_file_candidate(&format!("{char_name}.stand"));
                            self.add_file_candidate(&format!("{char_name}.sinfo"));
                            self.add_path_candidate(&format!("{char_name}/"));
                            self.add_path_candidate(&format!("fgimage/{char_name}/"));
                        }
                        if base_no_us != char_name && !base_no_us.is_empty() {
                            self.add_file_candidate(&format!("{base_no_us}.stand"));
                        }
                    }
                }
            }
        }

        // UIPSD `.func` / `.ini` directives: `psd,<name>` and `incl,<file>`
        for raw_line in text.lines().take(200) {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            if let Some((cmd, rest)) = line.split_once(',') {
                let cmd_low = cmd.trim().to_ascii_lowercase();
                let target = rest.split([',', '\t', ' ']).next().unwrap_or("").trim();
                if target.is_empty() || target.len() > 120 {
                    continue;
                }
                if cmd_low == "psd" {
                    let stem = target
                        .strip_suffix(".pimg")
                        .or_else(|| target.strip_suffix(".psb"))
                        .or_else(|| target.strip_suffix(".psd"))
                        .or_else(|| target.strip_suffix(".pbd"))
                        .unwrap_or(target);
                    for ext in [
                        ".pimg",
                        ".psb",
                        ".pbd",
                        ".func",
                        ".ini",
                        ".txt",
                        "__bg0.tlg",
                        "__pack.tlg",
                    ] {
                        self.add_file_candidate(&format!("{stem}{ext}"));
                    }
                    self.add_path_candidate(&format!("{stem}/"));
                    self.add_path_candidate(&format!("uipsd/{stem}/"));
                } else if cmd_low == "incl" {
                    if target.contains('.') {
                        self.add_file_candidate(target);
                        if let Some((stem, _)) = target.rsplit_once('.') {
                            self.add_file_candidate(&format!("{stem}.func"));
                            self.add_file_candidate(&format!("{stem}.ini"));
                            self.add_file_candidate(&format!("{stem}.pimg"));
                        }
                    } else {
                        self.add_file_candidate(&format!("{target}.ini"));
                        self.add_file_candidate(&format!("{target}.func"));
                    }
                }
            }
        }

        // Character / stand / face-offset / emotion-offset definition tables
        let header_sample: String = text.lines().take(5).collect::<Vec<_>>().join("\n");
        let is_char_stand_table = header_sample.contains("顔窓")
            || header_sample.contains("エモーション")
            || header_sample.contains("標準キャラ定義")
            || header_sample.contains("立ち絵")
            || text.lines().take(40).any(|l| l.contains(".stand"));
        if is_char_stand_table {
            for raw_line in text.lines() {
                let line = raw_line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                    continue;
                }
                let col0 = line
                    .split([',', '\t'])
                    .next()
                    .unwrap_or("")
                    .trim()
                    .trim_matches('"');
                if !col0.is_empty()
                    && col0.chars().count() <= 24
                    && !col0.contains([' ', '/', '\\', ':', '=', '(', ')', '[', ']'])
                {
                    if col0.ends_with(".stand") {
                        self.add_file_candidate(col0);
                    } else {
                        self.add_file_candidate(&format!("{col0}.stand"));
                        for suffix in ["1_1", "1_2", "2_1"] {
                            self.add_file_candidate(&format!("{col0}{suffix}.sinfo"));
                            self.add_file_candidate(&format!("{col0}{suffix}.pbd"));
                            self.add_file_candidate(&format!("{col0}{suffix}.txt"));
                            self.add_file_candidate(&format!("{col0}{suffix}_info.txt"));
                        }
                    }
                }
            }
        }

        // Tiled image configs: `format:"45fd_gred_${y}", horz:0, vert:215`
        if text.contains("format") && (text.contains("${y}") || text.contains("${x}")) {
            let mut max_horz = 0usize;
            let mut max_vert = 0usize;
            for cap in regex_tiled_dim().captures_iter(text) {
                if let (Some(kind), Some(num)) = (cap.get(1), cap.get(2)) {
                    if let Ok(v) = num.as_str().parse::<usize>() {
                        if kind.as_str() == "horz" {
                            max_horz = max_horz.max(v.min(2000));
                        } else {
                            max_vert = max_vert.max(v.min(2000));
                        }
                    }
                }
            }
            for cap in regex_tiled_format().captures_iter(text) {
                let Some(fmt) = cap.get(1).map(|m| m.as_str()) else {
                    continue;
                };
                let has_x = fmt.contains("${x}");
                let has_y = fmt.contains("${y}");
                if has_x && has_y {
                    let hx = max_horz.max(1);
                    let vy = max_vert.max(1);
                    if (hx + 1).saturating_mul(vy + 1) <= 4000 {
                        for x in 0..=hx {
                            for y in 0..=vy {
                                let stem = fmt
                                    .replace("${x}", &x.to_string())
                                    .replace("${y}", &y.to_string());
                                for ext in [".png", ".tlg", ".jpg"] {
                                    self.add_file_candidate(&format!("{stem}{ext}"));
                                }
                            }
                        }
                    }
                } else if has_y {
                    let vy = max_vert.max(300).min(2000);
                    for y in 0..=vy {
                        let stem = fmt.replace("${y}", &y.to_string());
                        for ext in [".png", ".tlg", ".jpg"] {
                            self.add_file_candidate(&format!("{stem}{ext}"));
                        }
                    }
                } else if has_x {
                    let hx = max_horz.max(300).min(2000);
                    for x in 0..=hx {
                        let stem = fmt.replace("${x}", &x.to_string());
                        for ext in [".png", ".tlg", ".jpg"] {
                            self.add_file_candidate(&format!("{stem}{ext}"));
                        }
                    }
                }
            }
        }
    }

    fn collect_psb_speaker_names(&mut self, val: &PsbValue) {
        match val {
            PsbValue::String(s) => {
                for part in s.split(['/', '／']) {
                    let spk = part.trim();
                    if !spk.is_empty()
                        && spk.chars().count() <= 20
                        && !spk.contains([' ', '\\', '\n', '\r', '\t', '「', '」', '（', '）'])
                    {
                        self.known_char_names.insert(spk.to_string());
                    }
                }
            }
            PsbValue::List(list) => {
                for item in list.iter().take(4) {
                    self.collect_psb_speaker_names(item);
                }
            }
            _ => {}
        }
    }

    fn extract_from_psb(&mut self, root: &PsbValue) {
        let Some(obj) = root.as_object() else {
            return;
        };

        // Only scenario PSBs have `scenes` and `name`
        if let (Some(scenes), Some(name_val)) = (obj.get("scenes"), obj.get("name")) {
            if let Some(scn_name) = name_val.as_str() {
                if !scn_name.is_empty() {
                    self.add_file_candidate(&format!("{scn_name}.scn"));
                    if scn_name.ends_with(".ks") {
                        self.add_file_candidate(scn_name);
                    } else {
                        self.add_file_candidate(&format!("{scn_name}.ks"));
                        self.add_file_candidate(&format!("{scn_name}.ks.scn"));
                    }
                }
            }

            // Structured scene extraction (matching `scan_psb_and_decompile.py`)
            if let Some(scene_list) = scenes.as_list() {
                for scene in scene_list {
                    if let Some(texts) = scene.get("texts").and_then(|v| v.as_list()) {
                        for text in texts {
                            if let Some(items) = text.as_list() {
                                for speaker_val in items.iter().take(2) {
                                    self.collect_psb_speaker_names(speaker_val);
                                }
                                // Multi-lang PSB dialogue tuples: `items[2]` holds `[[display_name, text], ...]`
                                if let Some(langs) = items.get(2).and_then(|v| v.as_list()) {
                                    for lang_entry in langs {
                                        if let Some(pair) = lang_entry.as_list() {
                                            if let Some(disp) = pair.first() {
                                                self.collect_psb_speaker_names(disp);
                                            }
                                        }
                                    }
                                }
                                for text_item in items {
                                    if let Some(sublist) = text_item.as_list() {
                                        for sub in sublist {
                                            if let Some(voice) =
                                                sub.get("voice").and_then(|v| v.as_str())
                                            {
                                                self.handle_psb_voice(voice);
                                            }
                                        }
                                    } else if let Some(map) = text_item.as_object() {
                                        if let Some(db) = map.get("data").and_then(|v| v.as_list())
                                        {
                                            self.handle_psb_data_block(db);
                                        }
                                        if let Some(chats) =
                                            map.get("phonechat").and_then(|v| v.as_list())
                                        {
                                            for chat in chats {
                                                if let Some(icon) =
                                                    chat.get("icon").and_then(|v| v.as_str())
                                                {
                                                    self.add_file_candidate(&format!(
                                                        "chaticon_{icon}.png"
                                                    ));
                                                }
                                                if let Some(stamp) =
                                                    chat.get("stamp").and_then(|v| v.as_str())
                                                {
                                                    self.add_file_candidate(&format!(
                                                        "{stamp}.png"
                                                    ));
                                                }
                                            }
                                        }
                                        if let Some(loops) =
                                            map.get("loopVoiceList").and_then(|v| v.as_list())
                                        {
                                            for lv in loops {
                                                if let Some(v) =
                                                    lv.get("voice").and_then(|v| v.as_str())
                                                {
                                                    self.handle_psb_voice(v);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if let Some(lines) = scene.get("lines").and_then(|v| v.as_list()) {
                        for line in lines {
                            if let Some(items) = line.as_list() {
                                for (idx, item) in items.iter().enumerate() {
                                    if let Some(db) = item.get("data").and_then(|v| v.as_list()) {
                                        self.handle_psb_data_block(db);
                                    } else if let Some(sub) = item.as_list() {
                                        for sub_item in sub {
                                            if sub_item.as_object().is_some() {
                                                self.handle_psb_data_item(sub_item);
                                            }
                                        }
                                    } else if let Some(s) = item.as_str() {
                                        if idx > 0 && items[idx - 1].as_str() == Some("voice") {
                                            self.handle_psb_voice(s);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Also run generic JSONPath-style recursive extractor (matching `scan_psb_and_decompile_jsonpath.py`)
            self.walk_psb_generic(root);
        } else {
            // Non-scenario PSBs (UIPSD `.pimg`, motion/stand PSBs)
            self.walk_psb_generic(root);
        }
    }

    fn walk_psb_generic(&mut self, val: &PsbValue) {
        match val {
            PsbValue::List(items) => {
                for item in items {
                    self.walk_psb_generic(item);
                }
            }
            PsbValue::Object(map) => {
                for (k, v) in map {
                    if let Some(s) = v.as_str() {
                        if !s.is_empty() {
                            match k.as_str() {
                                "file" | "image" => {
                                    if !s.starts_with("ev")
                                        && !s.starts_with("sd")
                                        && !s.ends_with(".stand")
                                    {
                                        for ext in [".jpg", ".png", ".tlg", ".pimg", ".sinfo"] {
                                            self.add_file_candidate(&format!("{s}{ext}"));
                                        }
                                        self.add_file_candidate(&format!("bgthum_{s}.jpg"));
                                        self.add_file_candidate(&format!("bgthum_{s}.png"));
                                    }
                                    if s.contains('.') {
                                        self.add_file_candidate(s);
                                    }
                                }
                                "rule" => {
                                    if s.contains('.') {
                                        self.add_file_candidate(s);
                                    } else {
                                        for ext in [".png", ".jpg", ".tlg", ".bmp"] {
                                            self.add_file_candidate(&format!("{s}{ext}"));
                                        }
                                    }
                                }
                                "voice" => {
                                    self.handle_psb_voice(s);
                                }
                                "stamp" => {
                                    if s.contains('.') {
                                        self.add_file_candidate(s);
                                    } else {
                                        self.add_file_candidate(&format!("{s}.png"));
                                        self.add_file_candidate(&format!("{s}.tlg"));
                                        self.add_file_candidate(&format!("{s}.jpg"));
                                    }
                                }
                                "icon" => {
                                    if s.contains('.') {
                                        self.add_file_candidate(s);
                                    } else {
                                        self.add_file_candidate(&format!("{s}.png"));
                                        self.add_file_candidate(&format!("chaticon_{s}.png"));
                                        self.add_file_candidate(&format!("comuicon_{s}.png"));
                                    }
                                }
                                "stand" => {
                                    if s.contains('.') {
                                        self.add_file_candidate(s);
                                    } else {
                                        self.add_file_candidate(&format!("{s}.stand"));
                                        self.add_file_candidate(&format!("{s}.sinfo"));
                                    }
                                }
                                "filename" => {
                                    for ext in [
                                        ".ogg",
                                        ".ogg.sli",
                                        ".opus",
                                        ".opus.sli",
                                        ".mchx",
                                        ".mchx.sli",
                                        ".ini",
                                    ] {
                                        self.add_file_candidate(&format!("{s}{ext}"));
                                    }
                                }
                                "storage" => {
                                    if s.ends_with(".ks") {
                                        self.add_file_candidate(s);
                                        self.add_file_candidate(&format!("{s}.scn"));
                                    } else if s.contains('.') {
                                        self.add_file_candidate(s);
                                    }
                                }
                                _ => {}
                            }
                        }
                    } else {
                        self.walk_psb_generic(v);
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_psb_data_block(&mut self, block: &[PsbValue]) {
        for entry in block {
            if let Some(list) = entry.as_list() {
                for item in list {
                    if item.as_object().is_some() {
                        self.handle_psb_data_item(item);
                    }
                }
            }
        }
    }

    fn handle_psb_data_item(&mut self, item: &PsbValue) {
        let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let class = item.get("class").and_then(|v| v.as_str()).unwrap_or("");

        if matches!(name, "bgm" | "live" | "liveout" | "endsong") {
            if let Some(fname) = item
                .get("replay")
                .and_then(|r| r.get("filename"))
                .and_then(|v| v.as_str())
            {
                for ext in [
                    ".ogg",
                    ".ogg.sli",
                    ".opus",
                    ".opus.sli",
                    ".mchx",
                    ".mchx.sli",
                ] {
                    self.add_file_candidate(&format!("{fname}{ext}"));
                }
            }
        } else if matches!(name, "lse" | "lse2" | "lse3" | "se" | "se2") {
            if let Some(raw) = item
                .get("replay")
                .and_then(|r| r.get("filename"))
                .and_then(|v| v.as_str())
            {
                for fname in raw.split('|') {
                    for ext in [".ogg", ".ogg.sli", ".opus", ".opus.sli", ".ini"] {
                        self.add_file_candidate(&format!("{fname}{ext}"));
                    }
                }
            }
        } else if name == "stage" {
            if let Some(fname) = item
                .get("redraw")
                .and_then(|r| r.get("imageFile"))
                .and_then(|i| i.get("file"))
                .and_then(|v| v.as_str())
            {
                self.add_file_candidate(&format!("{fname}.png"));
                self.add_file_candidate(&format!("{fname}.jpg"));
                self.add_file_candidate(&format!("{fname}.tlg"));
                self.add_file_candidate(&format!("bgthum_{fname}.jpg"));
            }
        } else if matches!(class, "msgwin" | "character") {
            if let Some(redraw) = item.get("redraw") {
                if let Some(clip_img) = redraw
                    .get("clip")
                    .and_then(|c| c.get("image"))
                    .and_then(|v| v.as_str())
                {
                    self.add_file_candidate(&format!("{clip_img}.png"));
                }
                if let Some(st) = redraw
                    .get("imageFile")
                    .and_then(|i| i.get("file"))
                    .and_then(|v| v.as_str())
                {
                    if st.ends_with(".stand") {
                        self.add_file_candidate(st);
                    }
                }
            } else if let Some(st) = item
                .get("stand")
                .and_then(|s| s.get("file"))
                .and_then(|v| v.as_str())
            {
                if st.ends_with(".stand") {
                    self.add_file_candidate(st);
                }
            }
        } else if matches!(class, "event" | "effect") {
            if matches!(name, "ev" | "effect" | "effect2" | "mono_sea") {
                if let Some(redraw) = item.get("redraw") {
                    if let Some(clip_img) = redraw
                        .get("clip")
                        .and_then(|c| c.get("image"))
                        .and_then(|v| v.as_str())
                    {
                        self.add_file_candidate(&format!("{clip_img}.png"));
                        self.add_file_candidate(&format!("{clip_img}.jpg"));
                    }
                    if let Some(raw) = redraw
                        .get("imageFile")
                        .and_then(|i| i.get("file"))
                        .and_then(|v| v.as_str())
                    {
                        for piece in raw.split(',').map(str::trim) {
                            if piece.contains('.') {
                                self.add_file_candidate(piece);
                                if let Some(stem) = piece.strip_suffix(".tjs") {
                                    for loc in ["_jp", "_en", "_cn", "_tw"] {
                                        self.add_file_candidate(&format!("{stem}{loc}.ini"));
                                    }
                                }
                            } else if !piece.is_empty() {
                                self.add_file_candidate(&format!("{piece}.png"));
                                self.add_file_candidate(&format!("{piece}_censored.png"));
                                self.add_file_candidate(&format!("{piece}.jpg"));
                                self.add_file_candidate(&format!("{piece}.pimg"));
                                self.add_file_candidate(&format!("{piece}.tlg"));
                            }
                        }
                    }
                }
            } else if name == "bg_voice" {
                if let Some(st) = item
                    .get("redraw")
                    .and_then(|r| r.get("imageFile"))
                    .and_then(|i| i.get("file"))
                    .and_then(|f| f.get("storage"))
                    .and_then(|v| v.as_str())
                {
                    self.add_file_candidate(st);
                }
            }
        } else if class == "phonechat" && name == "phonescreen" {
            if let Some(f) = item
                .get("redraw")
                .and_then(|r| r.get("imageFile"))
                .and_then(|i| i.get("file"))
                .and_then(|v| v.as_str())
            {
                self.add_file_candidate(&format!("{f}.tlg"));
            }
        } else if matches!(
            class,
            "sdlayer" | "topcenterlayer" | "bottomcenterlayer" | "centerlayer"
        ) {
            if let Some(f) = item
                .get("redraw")
                .and_then(|r| r.get("imageFile"))
                .and_then(|i| i.get("file"))
                .and_then(|v| v.as_str())
            {
                self.add_file_candidate(&format!("{f}.png"));
            }
        } else if matches!(class, "event2" | "stage2") {
            if let Some(redraw) = item.get("redraw") {
                if let Some(f) = redraw
                    .get("clip")
                    .and_then(|c| c.get("image"))
                    .and_then(|v| v.as_str())
                    .or_else(|| {
                        redraw
                            .get("imageFile")
                            .and_then(|i| i.get("file"))
                            .and_then(|v| v.as_str())
                    })
                {
                    self.add_file_candidate(&format!("{f}.png"));
                }
            }
        }
    }

    fn handle_psb_voice(&mut self, raw: &str) {
        for part in raw.split('|') {
            let (voice_name, extra_ext) = match part.split_once('.') {
                Some((n, ext)) => (n, Some(ext)),
                None => (part, None),
            };
            if voice_name.is_empty() {
                continue;
            }
            for ext in ["ogg", "ogg.sli", "opus", "opus.sli", "ini"] {
                self.add_file_candidate(&format!("{voice_name}.{ext}"));
            }
            if let Some(ext) = extra_ext {
                self.add_file_candidate(&format!("{voice_name}.{ext}"));
            }
        }
    }

    fn extract_from_unnamed_pbd(&mut self, val: &PbdValue) {
        if let Some(dict) = val.as_dict() {
            // uipsd PBD has `holdimage: [...]`
            if let Some(arr) = dict.get("holdimage").and_then(|v| v.as_array()) {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        self.add_file_candidate(&format!("{s}.tlg"));
                        self.add_file_candidate(&format!("{s}.png"));
                    }
                }
            }
        }
    }

    /// Round 2+ structured parsers triggered once a file's real name is known.
    fn analyze_named_file(&mut self, low_name: &str, orig_name: &str, data: &[u8]) {
        match low_name {
            "base.stage" => self.analyze_base_stage(data),
            "cglist.csv" => self.analyze_cglist_csv(data),
            "charvoice.csv" => self.analyze_charvoice_csv(data),
            "filegain.csv" => self.analyze_filegain_csv(data),
            "imagediffmap.csv" => self.analyze_imagediffmap_csv(data),
            "imagedressmap.txt" => self.analyze_imagedressmap_txt(data),
            "imageevalmap.csv" => self.analyze_imageevalmap_csv(data),
            "imagemulti.txt" => self.analyze_imagemulti_txt(data),
            "imagenamemap.txt" => self.analyze_imagenamemap_txt(data),
            "imagepropmap.txt" => self.analyze_imagepropmap_txt(data),
            "replay.ks" => self.analyze_replay_ks(data),
            "savelist.csv" => self.analyze_savelist_csv(data),
            "scenelist.csv" => self.analyze_scenelist_csv(data),
            "soundgain.csv" => self.analyze_soundgain_csv(data),
            "soundlist.csv" => self.analyze_soundlist_csv(data),
            "sysse.ini" => self.analyze_sysse_ini(data),
            "systrans.ini" => self.analyze_systrans_ini(data),
            "voicedrama.csv" => self.analyze_voicedrama_csv(data),
            "_chthum_index.pbd" => self.analyze_chthum_index_pbd(data),
            _ => {}
        }

        if low_name.starts_with("bgv") && low_name.ends_with(".csv") {
            self.analyze_bgv_csv(data);
        } else if low_name.ends_with(".stand") {
            self.analyze_stand_file(orig_name, data);
        } else if low_name.ends_with(".pbd") {
            self.analyze_fgimage_pbd(orig_name, data);
        } else if low_name.ends_with(".txt") {
            self.analyze_psd_layer_txt(orig_name, data);
        } else if low_name.ends_with(".tjs") || low_name.ends_with(".ks") {
            self.analyze_script_refs(data);
        }
    }

    fn analyze_base_stage(&mut self, data: &[u8]) {
        let Some(text) = decode_kirikiri_text(data) else {
            return;
        };
        let mut prefixes: HashSet<String> = HashSet::from([String::new()]);
        let mut templates: Vec<String> = Vec::new();
        for cap in regex_tjs_kv_string().captures_iter(&text) {
            let key = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let val = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            if matches!(key, "prefix" | "label") {
                if !val.is_empty() && val.len() <= 16 && !val.contains([' ', '/', '\\']) {
                    prefixes.insert(val.to_string());
                }
            } else if key == "image" {
                templates.push(val.to_string());
            }
        }
        if templates.iter().any(|t| t.contains("TIME")) {
            for def in ["a", "b", "c", "d", "e", "f", "g", "h", "i", "n", "y"] {
                prefixes.insert(def.to_string());
            }
        }
        let locales = ["", "_jp", "_en", "_cn", "_tw"];
        let prefix_list: Vec<String> = prefixes.into_iter().collect();
        for tmpl in &templates {
            let has_time = tmpl.contains("TIME");
            let has_season = tmpl.contains("SEASON");
            let time_iter: &[String] = if has_time {
                &prefix_list
            } else {
                std::slice::from_ref(&prefix_list[0])
            };
            let season_iter: &[String] = if has_season {
                &prefix_list
            } else {
                std::slice::from_ref(&prefix_list[0])
            };
            for tp in time_iter {
                for sp in season_iter {
                    let base = tmpl.replace("TIME", tp).replace("SEASON", sp);
                    for loc in locales {
                        for ext in [".png", ".jpg", ".tlg"] {
                            self.add_file_candidate(&format!("{base}{loc}{ext}"));
                        }
                        self.add_file_candidate(&format!("bgthum_{base}{loc}.jpg"));
                        self.add_file_candidate(&format!("bgthum_{base}{loc}.png"));
                    }
                }
            }
        }
    }

    fn analyze_cglist_csv(&mut self, data: &[u8]) {
        let Some(text) = decode_kirikiri_text(data) else {
            return;
        };
        let locales = ["", "_jp", "_en", "_cn", "_tw"];
        for row in parse_simple_csv(&text) {
            if row.is_empty() {
                continue;
            }
            let cg_filename = row[0].trim().to_ascii_lowercase();
            if cg_filename.is_empty() || cg_filename.starts_with('#') || cg_filename.contains(':') {
                continue;
            }
            let cg_name = cg_filename.replace("thum_", "");
            for ext in [
                ".jpg",
                ".png",
                "_censored.jpg",
                "_censored.png",
                ".psb",
                "_censored.psb",
                ".tlg",
                "_censored.tlg",
                ".pimg",
                "_censored.pimg",
            ] {
                self.add_file_candidate(&format!("{cg_filename}{ext}"));
            }
            for ext in [
                ".tlg",
                ".png",
                ".pimg",
                "_censored.tlg",
                "_censored.png",
                "_censored.pimg",
            ] {
                self.add_file_candidate(&format!("{cg_name}{ext}"));
            }
            if cg_filename.starts_with("thum_") {
                for ext in [".jpg", ".png", ".psb", ".tlg"] {
                    self.add_file_candidate(&format!("save{cg_filename}{ext}"));
                }
            }
            if cg_filename.starts_with("thum_ev") {
                for cell in row.iter().skip(1) {
                    let cleaned = cell.replace('*', "");
                    for cg_diff in cleaned.split('|') {
                        let cg_diff = cg_diff.trim().replace('\t', "");
                        if !cg_diff.starts_with(&cg_name) {
                            continue;
                        }
                        let start_len = cg_name.len();
                        let char_indices: Vec<usize> = cg_diff[start_len..]
                            .char_indices()
                            .map(|(i, _)| start_len + i)
                            .chain(std::iter::once(cg_diff.len()))
                            .collect();
                        for end_idx in char_indices {
                            let fname = &cg_diff[..end_idx];
                            for loc in locales {
                                for ext in [
                                    ".pimg",
                                    "_censored.pimg",
                                    ".tlg",
                                    "_censored.tlg",
                                    ".psb",
                                    "_censored.psb",
                                    ".png",
                                    "_censored.png",
                                ] {
                                    self.add_file_candidate(&format!("{fname}{loc}{ext}"));
                                }
                                for ext in [
                                    ".png",
                                    "_censored.png",
                                    ".jpg",
                                    "_censored.jpg",
                                    ".psb",
                                    "_censored.psb",
                                    ".tlg",
                                    "_censored.tlg",
                                ] {
                                    self.add_file_candidate(&format!("thum_{fname}{loc}{ext}"));
                                }
                                for ext in [".png", ".jpg", ".psb", ".tlg"] {
                                    self.add_file_candidate(&format!("savethum_{fname}{loc}{ext}"));
                                }
                            }
                        }
                    }
                }
            }
            if let Some(sd_name) = cg_filename.strip_prefix("thum_sd") {
                let sd_full = format!("sd{sd_name}");
                for ext in [".mtn", ".psb", ".tlg"] {
                    self.add_file_candidate(&format!("{sd_full}{ext}"));
                }
                for sd_diff in row.iter().skip(1) {
                    let sd_diff = sd_diff.trim().replace('\t', "");
                    if sd_diff.is_empty() {
                        continue;
                    }
                    for loc in locales {
                        for ext in [
                            ".jpg",
                            ".png",
                            ".tlg",
                            ".pimg",
                            ".asd",
                            ".psb",
                            "_censored.jpg",
                            "_censored.png",
                            "_censored.tlg",
                            "_censored.pimg",
                        ] {
                            self.add_file_candidate(&format!("{sd_diff}{loc}{ext}"));
                        }
                    }
                }
            }
        }
    }

    fn parse_sysse_ini_components(
        &mut self,
        ss_text: &str,
    ) -> (HashSet<String>, HashSet<String>) {
        let mut char_keys: HashSet<String> = HashSet::new();
        let mut templates: HashSet<String> = HashSet::new();
        let mut direct_sounds: Vec<String> = Vec::new();

        for raw_line in ss_text.lines() {
            let trimmed = raw_line.trim();
            if trimmed.is_empty() || trimmed.starts_with('?') {
                continue;
            }
            let was_comment = trimmed.starts_with('#');
            let line = if was_comment {
                trimmed.trim_start_matches('#').trim()
            } else {
                trimmed
            };
            let Some((left, right)) = line.split_once('=') else {
                continue;
            };
            let left = left.trim();
            let left_low = left.to_ascii_lowercase();
            let right = right.trim();
            if right.is_empty() || right.starts_with('@') || right.starts_with("alias") {
                continue;
            }

            // `sysvodef.keys = asa nin hiy ...` or `sysvodef.defkeys = asa`
            if left_low == "sysvodef.keys" || left_low == "sysvodef.defkeys" {
                for tok in right.split_whitespace() {
                    if !tok.is_empty()
                        && tok.len() <= 16
                        && tok.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    {
                        char_keys.insert(tok.to_string());
                    }
                }
                continue;
            }

            // `sysvodef.<key> = <key> <label>` (also handles `#sysvodef.hmn = hmn ...`)
            if let Some(sub) = left_low.strip_prefix("sysvodef.") {
                if !sub.is_empty() && sub.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                    char_keys.insert(sub.to_string());
                }
                if let Some(first_tok) = right.split_whitespace().next() {
                    if !first_tok.is_empty()
                        && first_tok.len() <= 16
                        && first_tok
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    {
                        char_keys.insert(first_tok.to_string());
                    }
                }
                continue;
            }

            let sound_name = right.split(':').next().unwrap_or("").trim();
            if sound_name.contains("%s") {
                templates.insert(sound_name.to_string());
            } else if !sound_name.is_empty()
                && !sound_name.contains(' ')
                && sound_name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
            {
                direct_sounds.push(sound_name.to_string());
                // Also infer char key from `voicetest.* = 45fd_sys_tkk011` / `voiceoff2on.* = 45fd_sys_ykn016`
                if left_low.starts_with("voicetest.") || left_low.starts_with("voiceoff2on.") {
                    if let Some((_, tail)) = sound_name.rsplit_once('_') {
                        let key = tail.trim_end_matches(|c: char| c.is_ascii_digit());
                        if (2..=12).contains(&key.len())
                            && key.bytes().all(|b| b.is_ascii_alphanumeric())
                        {
                            char_keys.insert(key.to_string());
                        }
                    }
                }
            }
        }

        for sound_name in direct_sounds {
            for ext in ["ogg", "ogg.sli", "opus", "opus.sli", "ini"] {
                self.add_file_candidate(&format!("{sound_name}.{ext}"));
            }
        }

        (char_keys, templates)
    }

    fn expand_sysvoice_templates(&mut self, prefixes: &HashSet<String>, templates: &HashSet<String>) {
        // Also expand numeric tails of `sysvoice` templates (e.g. `45fd_sys_%s001` -> `001..=030`)
        // to cover unused/commented promo/system voices as well.
        let mut stem_templates: HashSet<(String, usize)> = HashSet::new();
        for tmpl in templates {
            let digits_len = tmpl
                .bytes()
                .rev()
                .take_while(|b| b.is_ascii_digit())
                .count();
            if (2..=4).contains(&digits_len) {
                let stem = &tmpl[..tmpl.len() - digits_len];
                if stem.contains("%s") {
                    stem_templates.insert((stem.to_string(), digits_len));
                }
            }
        }

        for pref in prefixes {
            for tmpl in templates {
                let name = tmpl.replace("%s", pref);
                for ext in ["ogg", "ogg.sli", "opus", "opus.sli"] {
                    self.add_file_candidate(&format!("{name}.{ext}"));
                }
            }
            for (stem, width) in &stem_templates {
                let replaced = stem.replace("%s", pref);
                for n in 0..=50usize {
                    let name = format!("{replaced}{n:0width$}");
                    for ext in ["ogg", "ogg.sli", "opus", "opus.sli"] {
                        self.add_file_candidate(&format!("{name}.{ext}"));
                    }
                    if n <= 30 {
                        for suf in ["_a", "_b", "_c"] {
                            for ext in ["ogg", "opus"] {
                                self.add_file_candidate(&format!("{name}{suf}.{ext}"));
                            }
                        }
                    }
                }
            }
        }
    }

    fn analyze_sysse_ini(&mut self, sysse_data: &[u8]) {
        let Some(ss_text) = decode_kirikiri_text(sysse_data) else {
            return;
        };
        let (char_keys, templates) = self.parse_sysse_ini_components(&ss_text);
        self.known_char_codes.extend(char_keys.iter().cloned());
        if !char_keys.is_empty() && !templates.is_empty() {
            self.expand_sysvoice_templates(&char_keys, &templates);
        }
    }

    fn analyze_charvoice_csv(&mut self, data: &[u8]) {
        let Some(cv_text) = decode_kirikiri_text(data) else {
            return;
        };
        for row in parse_simple_csv(&cv_text) {
            if row.is_empty() {
                continue;
            }
            let raw_name = row[0].trim();
            if raw_name.is_empty() || raw_name.starts_with("DEFAULT") || raw_name.starts_with("#__")
            {
                continue;
            }
            let name = raw_name.trim_start_matches('#').trim();
            if !name.is_empty()
                && name.chars().count() <= 20
                && !name.contains([' ', '/', '\\', ':', '='])
            {
                self.known_char_names.insert(name.to_string());
            }
            if row.len() >= 2 {
                let fmt = row[1].trim();
                if !fmt.is_empty() {
                    let cleaned = fmt.replace("%s", "");
                    if let Some(pref) = cleaned.split('_').next() {
                        let p = pref.trim();
                        if !p.is_empty()
                            && p.len() <= 16
                            && p.bytes().all(|b| b.is_ascii_alphanumeric())
                        {
                            self.known_char_codes.insert(p.to_ascii_lowercase());
                        }
                    }
                    for cap in regex_fmt_char_code().captures_iter(fmt) {
                        if let Some(m) = cap.get(1) {
                            let code = m.as_str();
                            if (2..=12).contains(&code.len()) {
                                self.known_char_codes.insert(code.to_ascii_lowercase());
                            }
                        }
                    }
                }
            }
        }
    }

    fn analyze_voicedrama_csv(&mut self, data: &[u8]) {
        let Some(text) = decode_kirikiri_text(data) else {
            return;
        };
        for row in parse_simple_csv(&text) {
            let Some(raw) = row.first().map(|s| s.trim()) else {
                continue;
            };
            let Some(stem) = clean_csv_stem_allow_comment(raw) else {
                continue;
            };
            self.voicedrama_stems.insert(stem.to_string());
            for ext in [
                ".opus",
                ".opus.sli",
                ".ogg",
                ".ogg.sli",
                ".mchx",
                ".mchx.sli",
                ".ks",
                ".ks.scn",
            ] {
                self.add_file_candidate(&format!("{stem}{ext}"));
            }
        }
    }

    fn analyze_char_sys_voices(&mut self, charvoice_data: &[u8], sysse_data: &[u8]) {
        let (Some(cv_text), Some(ss_text)) = (
            decode_kirikiri_text(charvoice_data),
            decode_kirikiri_text(sysse_data),
        ) else {
            return;
        };

        let (mut prefixes, templates) = self.parse_sysse_ini_components(&ss_text);
        for row in parse_simple_csv(&cv_text) {
            if row.len() < 2 {
                continue;
            }
            let h = row[0].trim();
            if h.is_empty() || h.starts_with("DEFAULT") || h.starts_with("#__") {
                continue;
            }
            let fmt = row[1].trim();
            if fmt.is_empty() {
                continue;
            }
            // Pattern A (Yuzusoft): `yuka%s_%03d` -> `yuka`
            let cleaned = fmt.replace("%s", "");
            if let Some(pref) = cleaned.split('_').next() {
                let p = pref.trim();
                if !p.is_empty()
                    && p.len() <= 16
                    && p.bytes().all(|b| b.is_ascii_alphanumeric())
                {
                    prefixes.insert(p.to_string());
                }
            }
            // Pattern B (CIRCUS/KAGEx): `45fd_%s_asa%02d` -> `asa`
            for cap in regex_fmt_char_code().captures_iter(fmt) {
                if let Some(m) = cap.get(1) {
                    let code = m.as_str();
                    if (2..=12).contains(&code.len()) {
                        prefixes.insert(code.to_string());
                    }
                }
            }
        }

        self.expand_sysvoice_templates(&prefixes, &templates);
    }

    fn analyze_filegain_csv(&mut self, data: &[u8]) {
        let Some(text) = decode_kirikiri_text(data) else {
            return;
        };
        for row in parse_simple_csv(&text) {
            let Some(raw) = row.first().map(|s| s.trim()) else {
                continue;
            };
            let Some(name) = clean_csv_stem_allow_comment(raw) else {
                continue;
            };
            for ext in [
                ".ogg",
                ".ogg.sli",
                ".opus",
                ".opus.sli",
                ".mchx",
                ".mchx.sli",
            ] {
                self.add_file_candidate(&format!("{name}{ext}"));
            }
        }
    }

    fn analyze_imagediffmap_csv(&mut self, data: &[u8]) {
        let Some(text) = decode_kirikiri_text(data) else {
            return;
        };
        for row in parse_simple_csv(&text) {
            if row.len() < 2 {
                continue;
            }
            if row[0].trim().starts_with('#') {
                continue;
            }
            let fname = row[1].trim();
            if fname.is_empty() {
                continue;
            }
            if let Some((names, ext)) = fname.split_once('.') {
                for n in names.split('|') {
                    self.add_file_candidate(&format!("{}.{ext}", n.trim()));
                }
            } else {
                for ext in [
                    ".pimg",
                    "_censored.pimg",
                    ".psb",
                    "_censored.psb",
                    ".tlg",
                    "_censored.tlg",
                ] {
                    self.add_file_candidate(&format!("{fname}{ext}"));
                }
                for ext in [".jpg", ".png", ".psb", ".tlg"] {
                    self.add_file_candidate(&format!("savethum_{fname}{ext}"));
                }
            }
        }
    }

    fn analyze_imagedressmap_txt(&mut self, data: &[u8]) {
        let Some(text) = decode_kirikiri_text(data) else {
            return;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let first = line.split('\t').next().unwrap_or("").trim();
            if first.is_empty() {
                continue;
            }
            if first.ends_with(".stand") {
                self.add_file_candidate(first);
            } else {
                self.add_file_candidate(&format!("{first}.stand"));
            }
        }
    }

    fn analyze_imageevalmap_csv(&mut self, data: &[u8]) {
        let Some(text) = decode_kirikiri_text(data) else {
            return;
        };
        for row in parse_simple_csv(&text) {
            if row.is_empty() || row[0].trim().is_empty() || row[0].trim().starts_with('#') {
                continue;
            }
            for field in row.iter().take(2) {
                let n = field.trim();
                if n.is_empty() || n.starts_with('&') || n.starts_with('#') {
                    continue;
                }
                for ext in [".pimg", ".tlg", ".png", ".psb"] {
                    self.add_file_candidate(&format!("{n}{ext}"));
                    self.add_file_candidate(&format!("{n}_censored{ext}"));
                }
            }
        }
    }

    fn analyze_imagemulti_txt(&mut self, data: &[u8]) {
        let Some(text) = decode_kirikiri_text(data) else {
            return;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            for mut part in line.split('\t').map(str::trim) {
                if let Some((_, rhs)) = part.split_once(':') {
                    part = rhs.trim();
                }
                if part.is_empty() {
                    continue;
                }
                for ext in [".pbd", ".sinfo", ".pimg", ".stand", "_info.txt"] {
                    self.add_file_candidate(&format!("{part}{ext}"));
                }
            }
        }
    }

    fn analyze_imagenamemap_txt(&mut self, data: &[u8]) {
        let Some(text) = decode_kirikiri_text(data) else {
            return;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            for part in line.split('\t').map(str::trim) {
                if part.is_empty() || part.starts_with('_') {
                    continue;
                }
                for ext in [".pimg", ".tlg", ".png", ".psb"] {
                    self.add_file_candidate(&format!("{part}{ext}"));
                    self.add_file_candidate(&format!("{part}_censored{ext}"));
                }
            }
        }
    }

    fn analyze_imagepropmap_txt(&mut self, data: &[u8]) {
        let Some(text) = decode_kirikiri_text(data) else {
            return;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let first = line.split('\t').next().unwrap_or("").trim();
            if first.is_empty() {
                continue;
            }
            let (base, custom_ext) = match first.split_once('.') {
                Some((b, e)) => (b, Some(e)),
                None => (first, None),
            };
            for ext in [".pimg", ".tlg", ".png", ".psb", ".mtn", ".wmv", ".stand"] {
                self.add_file_candidate(&format!("{base}{ext}"));
            }
            if let Some(ext) = custom_ext {
                self.add_file_candidate(&format!("{base}.{ext}"));
            }
        }
    }

    fn analyze_replay_ks(&mut self, data: &[u8]) {
        let Some(text) = decode_kirikiri_text(data) else {
            return;
        };
        let mut movies = vec!["op".to_string(), "ed".to_string()];
        for cap in regex_replay_movie().captures_iter(&text) {
            if let Some(m) = cap.get(1) {
                movies.push(m.as_str().to_string());
            }
        }
        for movie in &movies {
            for loc in ["", "jp_", "en_", "cn_", "tw_"] {
                for ext in ["mp4", "wmv", "amv", "webm"] {
                    self.add_file_candidate(&format!("{loc}{movie}.{ext}"));
                    self.add_file_candidate(&format!("{loc}{movie}1080.{ext}"));
                    self.add_file_candidate(&format!("{loc}{movie}_1080.{ext}"));
                    self.add_file_candidate(&format!("{loc}{movie}720p.{ext}"));
                }
            }
        }
    }

    fn analyze_savelist_csv(&mut self, data: &[u8]) {
        let Some(text) = decode_kirikiri_text(data) else {
            return;
        };
        for row in parse_simple_csv(&text) {
            let Some(fname) = row.first().map(|s| s.trim()) else {
                continue;
            };
            if fname.is_empty() || fname.starts_with('#') {
                continue;
            }
            let thum = fname.replace("savethum_", "thum_");
            for ext in [".jpg", ".png", ".psb"] {
                self.add_file_candidate(&format!("{fname}{ext}"));
                self.add_file_candidate(&format!("{thum}{ext}"));
            }
        }
    }

    fn analyze_scenelist_csv(&mut self, data: &[u8]) {
        let Some(text) = decode_kirikiri_text(data) else {
            return;
        };
        for row in parse_simple_csv(&text) {
            let Some(raw) = row.first().map(|s| s.trim()) else {
                continue;
            };
            let Some(h) = clean_csv_stem_allow_comment(raw) else {
                continue;
            };
            if h.contains(':') {
                continue;
            }
            for fname in h.split('|').map(str::trim) {
                for loc in ["", "_jp", "_en", "_cn", "_tw"] {
                    for ext in [
                        ".jpg",
                        ".png",
                        ".psb",
                        ".tlg",
                        "_censored.jpg",
                        "_censored.png",
                        "_censored.psb",
                        "_censored.tlg",
                    ] {
                        self.add_file_candidate(&format!("{fname}{loc}{ext}"));
                    }
                }
            }
        }
    }

    fn analyze_soundgain_csv(&mut self, data: &[u8]) {
        let Some(text) = decode_kirikiri_text(data) else {
            return;
        };
        for row in parse_simple_csv(&text) {
            let Some(raw) = row.first().map(|s| s.trim()) else {
                continue;
            };
            let Some(name) = clean_csv_stem_allow_comment(raw) else {
                continue;
            };
            for ext in [".ogg", ".ogg.sli", ".opus", ".opus.sli"] {
                self.add_file_candidate(&format!("{name}{ext}"));
            }
        }
    }

    fn analyze_soundlist_csv(&mut self, data: &[u8]) {
        let Some(text) = decode_kirikiri_text(data) else {
            return;
        };
        for row in parse_simple_csv(&text) {
            let Some(raw) = row.first().map(|s| s.trim()) else {
                continue;
            };
            let Some(h) = clean_csv_stem_allow_comment(raw) else {
                continue;
            };
            for ext in [
                ".opus",
                ".opus.sli",
                ".ogg",
                ".ogg.sli",
                ".mchx",
                ".mchx.sli",
            ] {
                self.add_file_candidate(&format!("{h}{ext}"));
            }
        }
    }

    fn analyze_systrans_ini(&mut self, data: &[u8]) {
        let Some(text) = decode_kirikiri_text(data) else {
            return;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((_, rhs)) = line.split_once('=') else {
                continue;
            };
            let rhs = rhs.trim();
            if rhs.starts_with('@') || rhs.starts_with("0:&") {
                continue;
            }
            for part in rhs.split(':').map(str::trim) {
                if !part.is_empty()
                    && !part.chars().all(|c| c.is_ascii_digit())
                    && !part.starts_with('@')
                {
                    for ext in [".png", ".pimg", ".tlg", ".psb"] {
                        self.add_file_candidate(&format!("{part}{ext}"));
                    }
                }
            }
        }
    }

    fn analyze_bgv_csv(&mut self, data: &[u8]) {
        let Some(text) = decode_kirikiri_text(data) else {
            return;
        };
        for row in parse_simple_csv(&text) {
            if row.len() > 2 && !row[0].trim().starts_with('#') {
                let vn = row[2].trim();
                if !vn.is_empty() {
                    for ext in [".ogg", ".ogg.sli", ".opus", ".opus.sli", ".ini"] {
                        self.add_file_candidate(&format!("{vn}{ext}"));
                    }
                }
            }
        }
    }

    fn analyze_stand_file(&mut self, orig_name: &str, data: &[u8]) {
        if let Some((char_stem, _)) = orig_name.rsplit_once('.') {
            self.known_char_names.insert(char_stem.to_string());
            self.add_file_candidate(&format!("{char_stem}.sinfo"));
            self.add_path_candidate(&format!("{char_stem}/"));
            self.add_path_candidate(&format!("fgimage/{char_stem}/"));
        }
        let Some(text) = decode_kirikiri_text(data) else {
            return;
        };
        for cap in regex_stand_filename().captures_iter(&text) {
            if let Some(m) = cap.get(1) {
                let fname = m.as_str();
                for ext in [".pbd", ".sinfo", ".txt", "_0.pbd", "_0.sinfo", "_info.txt"] {
                    self.add_file_candidate(&format!("{fname}{ext}"));
                }
                self.add_path_candidate(&format!("{fname}/"));
                self.add_path_candidate(&format!("fgimage/{fname}/"));
            }
        }
    }

    fn analyze_chthum_index_pbd(&mut self, data: &[u8]) {
        if let Ok(PbdValue::Dict(map)) = parse_pbd(data) {
            for val in map.values() {
                if let Some(fname) = val.as_str() {
                    if fname.contains('.') {
                        self.add_file_candidate(fname);
                    } else {
                        self.add_file_candidate(&format!("{fname}.png"));
                        self.add_file_candidate(&format!("{fname}.jpg"));
                    }
                }
            }
        }
    }

    fn add_fgimage_stem_paths(&mut self, stem: &str) {
        self.add_path_candidate(&format!("{stem}/"));
        self.add_path_candidate(&format!("fgimage/{stem}/"));
        let base_no_us = stem
            .rsplit_once('_')
            .filter(|(_, tail)| !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()))
            .map(|(head, _)| head)
            .unwrap_or(stem);
        let char_name = base_no_us.trim_end_matches(|c: char| c.is_ascii_digit());
        if !char_name.is_empty() {
            self.add_path_candidate(&format!("{char_name}/"));
            self.add_path_candidate(&format!("fgimage/{char_name}/"));
        }
    }

    fn analyze_fgimage_pbd(&mut self, orig_name: &str, data: &[u8]) {
        let stem = orig_name
            .rsplit_once('.')
            .map(|(s, _)| s)
            .unwrap_or(orig_name);
        self.add_file_candidate(&format!("{stem}.txt"));
        self.add_file_candidate(&format!("{stem}_info.txt"));
        self.add_file_candidate(&format!("{stem}.sinfo"));
        self.add_fgimage_stem_paths(stem);
        if let Ok(val) = parse_pbd(data) {
            if let Some(items) = val.as_array() {
                for item in items {
                    if let Some(dict) = item.as_dict() {
                        if let Some(id_val) = dict.get("layer_id") {
                            let id_str = if let Some(n) = id_val.as_i64() {
                                n.to_string()
                            } else if let Some(s) = id_val.as_str() {
                                s.to_string()
                            } else {
                                continue;
                            };
                            self.add_file_candidate(&format!("{stem}_{id_str}.tlg"));
                            self.add_file_candidate(&format!("{stem}_{id_str}.png"));
                        }
                    }
                }
            } else {
                self.extract_from_unnamed_pbd(&val);
            }
        }
    }

    /// Parses Kirikiri/PSDExport text layer tables (`#layer_type\tname\t...\tlayer_id\t...`),
    /// generating `<stem>_<layer_id>.tlg`/`.png` and character directory candidates.
    fn analyze_psd_layer_txt(&mut self, orig_name: &str, data: &[u8]) {
        let Some(text) = decode_kirikiri_text(data) else {
            return;
        };
        let mut lines = text.lines();
        let Some(header) = lines.find(|l| !l.trim().is_empty()) else {
            return;
        };
        let header_trim = header.trim_start_matches('\u{feff}').trim();
        if !header_trim.starts_with("#layer_type\t") {
            return;
        }
        let Some(layer_id_col) = header_trim
            .split('\t')
            .position(|col| col.trim() == "layer_id")
        else {
            return;
        };
        let stem = orig_name
            .rsplit_once('.')
            .map(|(s, _)| s)
            .unwrap_or(orig_name);
        let stem = stem.strip_suffix("_info").unwrap_or(stem);
        self.add_fgimage_stem_paths(stem);
        self.add_file_candidate(&format!("{stem}.sinfo"));
        self.add_file_candidate(&format!("{stem}.pbd"));
        for line in lines {
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(id_str) = line.split('\t').nth(layer_id_col).map(str::trim) {
                if !id_str.is_empty() && id_str.bytes().all(|b| b.is_ascii_digit()) {
                    self.add_file_candidate(&format!("{stem}_{id_str}.tlg"));
                    self.add_file_candidate(&format!("{stem}_{id_str}.png"));
                }
            }
        }
    }

    fn analyze_script_refs(&mut self, data: &[u8]) {
        if data.starts_with(b"TJS2100\0") {
            return;
        }
        if let Some(text) = decode_kirikiri_text(data) {
            for cap in regex_tjs_file_ref().captures_iter(&text) {
                if let Some(m) = cap.get(1) {
                    let r = m.as_str();
                    self.add_file_candidate(r);
                    if r.to_ascii_lowercase().ends_with(".ks") {
                        self.add_file_candidate(&format!("{r}.scn"));
                    }
                }
            }
        }
    }

    fn expand_locale_and_uipsd_variants(&mut self, names: &[String]) {
        let locales = ["", "_cn", "_en", "_tw", "_jp"];
        let uipsd_suffixes = [
            ".pbd",
            "__bg0.tlg",
            "__bg1.tlg",
            "__bg2.tlg",
            "__pack.tlg",
            "_jp.pbd",
            "_jp__pack.tlg",
            "_en.pbd",
            "_en__pack.tlg",
            "_cn.pbd",
            "_cn__pack.tlg",
            "_tw.pbd",
            "_tw__pack.tlg",
        ];

        for name in names {
            // Locale variants
            for loc in &locales[1..] {
                let pat = format!("{loc}.");
                if let Some(idx) = name.rfind(&pat) {
                    let base = &name[..idx];
                    let ext = &name[idx + loc.len()..];
                    for alt in locales {
                        self.add_file_candidate(&format!("{base}{alt}{ext}"));
                    }
                    break;
                }
            }
            // UIPSD multi-lang variants
            if let Some(cap) = regex_uipsd_base().captures(name) {
                if let Some(base) = cap.get(1) {
                    let b = base.as_str();
                    for suf in uipsd_suffixes {
                        self.add_file_candidate(&format!("{b}{suf}"));
                    }
                }
            }
        }
    }

    fn expand_discovered_tokens_and_prefixes(&mut self) {
        // One-time pass: test bare TJS2/PSB identifier tokens with standard Kirikiri extensions
        if !self.expanded_tjs_tokens {
            self.expanded_tjs_tokens = true;
            let tokens: Vec<String> = self.tjs_ident_tokens.iter().cloned().collect();
            let exts = [
                ".tjs", ".ks", ".ini", ".csv", ".txt", ".png", ".jpg", ".tlg", ".asd", ".sinfo",
                ".stand", ".func", ".pimg", ".opus", ".ogg", ".wmv", ".mp4",
            ];
            for tok in &tokens {
                for ext in exts {
                    self.add_file_candidate(&format!("{tok}{ext}"));
                }
            }
        }

        let sig = (
            self.underscore_prefixes.len(),
            self.known_char_names.len(),
            self.known_char_codes.len(),
            self.voicedrama_stems.len(),
            self.path_map.len(),
        );
        if sig == self.last_combo_signature {
            return;
        }
        self.last_combo_signature = sig;

        let prefixes: Vec<String> = self.underscore_prefixes.iter().cloned().collect();
        let char_names: Vec<String> = self.known_char_names.iter().cloned().collect();
        let char_codes: Vec<String> = self.known_char_codes.iter().cloned().collect();
        let vd_stems: Vec<String> = self.voicedrama_stems.iter().cloned().collect();

        // Collect resolved top/leaf directory stems (e.g. "k2compat") to expand matching `<dir>_<token>.tjs`
        let resolved_dir_stems: HashSet<String> = self
            .path_map
            .values()
            .filter_map(|p| {
                let leaf = p.trim_end_matches('/').rsplit('/').next()?;
                if !leaf.is_empty() {
                    Some(leaf.to_ascii_lowercase())
                } else {
                    None
                }
            })
            .collect();
        let short_tjs_words: Vec<String> = self
            .tjs_ident_tokens
            .iter()
            .filter(|t| (2..=24).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_alphanumeric()))
            .cloned()
            .collect();

        let lang_tags = [
            "jp", "en", "cn", "tw", "sc", "tc", "kr", "ko", "id", "ja", "zh", "default",
        ];

        for pref in &prefixes {
            for tag in lang_tags {
                for ext in [".ini", ".txt", ".tjs", ".csv", ".png"] {
                    self.add_file_candidate(&format!("{pref}{tag}{ext}"));
                }
            }
            if pref.len() <= 24 {
                for ch in &char_names {
                    for ext in [".png", ".tlg", ".jpg"] {
                        self.add_file_candidate(&format!("{pref}{ch}{ext}"));
                    }
                }
                for code in &char_codes {
                    for ext in [".png", ".tlg", ".jpg", ".opus", ".ogg"] {
                        self.add_file_candidate(&format!("{pref}{code}{ext}"));
                    }
                }
            }
            let stem_no_us = pref.trim_end_matches('_');
            if resolved_dir_stems.contains(stem_no_us) {
                for w in &short_tjs_words {
                    self.add_file_candidate(&format!("{pref}{w}.tjs"));
                    self.add_file_candidate(&format!("{pref}{w}.ks"));
                    self.add_file_candidate(&format!("{pref}{w}.ini"));
                }
            }
        }

        // Seed voice-drama character stems (`<vd>_<char>001..005.opus`/`.ogg`);
        // matched prefixes are expanded through the full range by `expand_missing_voices`.
        for vd in &vd_stems {
            for code in &char_codes {
                for n in 1..=5usize {
                    self.add_file_candidate(&format!("{vd}_{code}{n:03}.opus"));
                    self.add_file_candidate(&format!("{vd}_{code}{n:03}.ogg"));
                    self.add_file_candidate(&format!("{vd}_{code}{n:02}.opus"));
                }
            }
        }
    }

    fn expand_missing_voices(&mut self, names: &[String]) {
        // Maps `prefix` (including trailing `_` if present) -> (width, max_num, had_letter_or_ref_suffix)
        let mut prefixes: HashMap<String, (usize, usize, bool)> = HashMap::new();
        for name in names {
            let low = name.to_ascii_lowercase();
            if !(low.ends_with(".ogg") || low.ends_with(".opus") || low.ends_with(".sli")) {
                continue;
            }
            let stem = name.split('.').next().unwrap_or("");
            let Some((prefix, width, num, had_suf)) = split_audio_numeric_stem(stem) else {
                continue;
            };
            prefixes
                .entry(prefix)
                .and_modify(|(w, max_n, suf_flag)| {
                    if num > *max_n {
                        *max_n = num;
                    }
                    *w = (*w).max(width);
                    *suf_flag |= had_suf;
                })
                .or_insert((width, num, had_suf));
        }

        for (prefix, (width, max_num, had_suf)) in prefixes {
            let low_pref = prefix.to_ascii_lowercase();
            let cap = if low_pref == "se" || low_pref == "se_" {
                max_num.max(999).min(1500)
            } else if low_pref.starts_with("bgm") {
                (max_num + 20).min(300)
            } else if low_pref.contains("_sys_") {
                (max_num + 15).min(60)
            } else {
                (max_num + 40).min(1500)
            };

            let expand_variants =
                prefix.ends_with('_') || had_suf || low_pref.contains("_sys_") || low_pref.contains("bgm");
            let expand_take_suffixes = cap <= 500;
            for n in 0..=cap {
                let base = format!("{prefix}{n:0width$}");
                self.add_file_candidate(&format!("{base}.ogg"));
                self.add_file_candidate(&format!("{base}.ogg.sli"));
                self.add_file_candidate(&format!("{base}.opus"));
                self.add_file_candidate(&format!("{base}.opus.sli"));
                if expand_take_suffixes && n <= (max_num + 5).min(500) {
                    for suf in ["_a", "_b", "_c"] {
                        self.add_file_candidate(&format!("{base}{suf}.opus"));
                        self.add_file_candidate(&format!("{base}{suf}.opus.sli"));
                        self.add_file_candidate(&format!("{base}{suf}.ogg"));
                        self.add_file_candidate(&format!("{base}{suf}.ogg.sli"));
                    }
                }
                if expand_variants && n <= (max_num + 5).min(500) {
                    for suf in ["a", "b", "c", "_d", "_f", "_1", "_2", "_ref", "_ref2"] {
                        self.add_file_candidate(&format!("{base}{suf}.ogg"));
                        self.add_file_candidate(&format!("{base}{suf}.ogg.sli"));
                        self.add_file_candidate(&format!("{base}{suf}.opus"));
                        self.add_file_candidate(&format!("{base}{suf}.opus.sli"));
                    }
                }
            }
        }
    }

    fn expand_numeric_images(&mut self, names: &[String]) {
        // Key by `(prefix, width, ext)` so 2-digit (`map00`) and 3-digit (`map501`) sets expand independently.
        let mut seqs: HashMap<(String, usize, String), (usize, bool, bool)> = HashMap::new();
        let weekdays = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
        let mut saw_weekday_ext: HashSet<String> = HashSet::new();

        for name in names {
            let low = name.to_ascii_lowercase();
            let Some((stem, ext)) = low.rsplit_once('.') else {
                continue;
            };
            if !matches!(ext, "png" | "jpg" | "tlg") {
                continue;
            }
            if weekdays.contains(&stem) {
                saw_weekday_ext.insert(ext.to_string());
                continue;
            }
            let Some((prefix, width, num, had_letter, zero_pad)) = split_image_numeric_stem(stem)
            else {
                continue;
            };
            // Skip FG layer IDs (`<char>1_1_<layer_id>.tlg`)
            if ext == "tlg" && prefix.ends_with('_') && prefix.contains('_') {
                continue;
            }
            seqs.entry((prefix, width, ext.to_string()))
                .and_modify(|(max_n, letter_f, zpad_f)| {
                    if num > *max_n {
                        *max_n = num;
                    }
                    *letter_f |= had_letter;
                    *zpad_f |= zero_pad;
                })
                .or_insert((num, had_letter, zero_pad));
        }

        for ext in saw_weekday_ext {
            for day in weekdays {
                self.add_file_candidate(&format!("{day}.{ext}"));
            }
        }

        for ((prefix, width, ext), (max_num, had_letter, zero_pad)) in seqs {
            let cap = if prefix.is_empty() {
                max_num.max(50).min(200)
            } else if prefix == "map" && width == 2 {
                max_num.max(99).min(120)
            } else if prefix == "map" && width == 3 && max_num >= 500 {
                max_num.max(620).min(650)
            } else {
                (max_num + 20).min(600)
            };
            let start = if prefix == "map" && width == 3 && max_num >= 500 {
                500
            } else if max_num > 200 {
                max_num.saturating_sub(20)
            } else {
                0
            };

            for n in start..=cap {
                let num_unpadded = n.to_string();
                let num_padded = format!("{n:0width$}");
                if zero_pad || width > 1 {
                    self.add_file_candidate(&format!("{prefix}{num_padded}.{ext}"));
                }
                if !zero_pad || num_unpadded != num_padded {
                    self.add_file_candidate(&format!("{prefix}{num_unpadded}.{ext}"));
                }
                if had_letter && (cap - start) <= 220 {
                    let num_str = if zero_pad || width > 1 {
                        &num_padded
                    } else {
                        &num_unpadded
                    };
                    for ch in b'a'..=b'z' {
                        let c = ch as char;
                        self.add_file_candidate(&format!("{prefix}{num_str}{c}.{ext}"));
                    }
                    if prefix == "map" {
                        for extra in ["b2", "c2", "a2"] {
                            self.add_file_candidate(&format!("{prefix}{num_str}{extra}.{ext}"));
                        }
                    }
                }
            }
        }
    }
}

/// Export resolved hashes in `HxNames.lst` format (`<UPPER_HEX_HASH>:<name>`) for GARbro / KrkrDump compatibility.
pub fn save_hxnames_lst(path: &Path, result: &UnhashResult) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut lines = Vec::new();
    for (h, name) in &result.path_map {
        let display_name = if name.is_empty() { "/" } else { name.as_str() };
        lines.push(format!("{}:{display_name}", h.to_ascii_uppercase()));
    }
    for (h, name) in &result.file_map {
        if !name.is_empty() {
            lines.push(format!("{}:{name}", h.to_ascii_uppercase()));
        }
    }
    std::fs::write(path, lines.join("\n") + if lines.is_empty() { "" } else { "\n" })?;
    Ok(())
}

fn is_analyzable_named_file(low_name: &str) -> bool {
    matches!(
        low_name,
        "base.stage"
            | "cglist.csv"
            | "charvoice.csv"
            | "filegain.csv"
            | "imagediffmap.csv"
            | "imagedressmap.txt"
            | "imageevalmap.csv"
            | "imagemulti.txt"
            | "imagenamemap.txt"
            | "imagepropmap.txt"
            | "replay.ks"
            | "savelist.csv"
            | "scenelist.csv"
            | "soundgain.csv"
            | "soundlist.csv"
            | "sysse.ini"
            | "systrans.ini"
            | "voicedrama.csv"
            | "_chthum_index.pbd"
    ) || (low_name.starts_with("bgv") && low_name.ends_with(".csv"))
        || low_name.ends_with(".stand")
        || low_name.ends_with(".pbd")
        || low_name.ends_with(".txt")
        || low_name.ends_with(".tjs")
        || low_name.ends_with(".ks")
}

/// Returns a clean CSV stem, also allowing `#`-commented asset IDs like `#bgm001` while
/// rejecting prose/header comments.
fn clean_csv_stem_allow_comment(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('#') {
        let cand = rest.trim();
        if (2..=64).contains(&cand.len())
            && cand
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'|'))
            && cand.bytes().any(|b| b.is_ascii_alphabetic())
            && cand.bytes().any(|b| b.is_ascii_digit() || b == b'_')
        {
            return Some(cand);
        }
        return None;
    }
    Some(trimmed)
}

/// Splits an audio stem into `(prefix, digit_width, num, had_suffix)` for both
/// underscore-separated (`asa_0012`) and directly-attached (`45fd_sys_ykn011`, `se223`) numbering.
fn split_audio_numeric_stem(stem: &str) -> Option<(String, usize, usize, bool)> {
    let mut s = stem;
    let mut had_suffix = false;
    if let Some(stripped) = s.strip_suffix("_ref2").or_else(|| s.strip_suffix("_ref")) {
        s = stripped;
        had_suffix = true;
    } else if s.len() >= 3 {
        let bytes = s.as_bytes();
        let n = bytes.len();
        if bytes[n - 2] == b'_'
            && matches!(bytes[n - 1], b'a'..=b'd' | b'A'..=b'D' | b'1'..=b'3')
            && bytes[n - 3].is_ascii_digit()
        {
            s = &s[..n - 2];
            had_suffix = true;
        } else if matches!(bytes[n - 1], b'a'..=b'd' | b'A'..=b'D') && bytes[n - 2].is_ascii_digit()
        {
            s = &s[..n - 1];
            had_suffix = true;
        }
    } else if s.len() >= 2 {
        let bytes = s.as_bytes();
        let last = bytes[bytes.len() - 1];
        let prev = bytes[bytes.len() - 2];
        if matches!(last, b'a'..=b'd' | b'A'..=b'D') && prev.is_ascii_digit() {
            s = &s[..s.len() - 1];
            had_suffix = true;
        }
    }

    let digits_len = s.bytes().rev().take_while(|b| b.is_ascii_digit()).count();
    if !(1..=5).contains(&digits_len) {
        return None;
    }
    let prefix = &s[..s.len() - digits_len];
    if prefix.len() < 2 {
        return None;
    }
    let num = s[s.len() - digits_len..].parse::<usize>().ok()?;
    if num > 50_000 {
        return None;
    }
    Some((prefix.to_string(), digits_len, num, had_suffix))
}

/// Splits a numeric image stem into `(prefix, width, num, had_letter, zero_padded)`.
/// Examples: `"10"` -> `("", 2, 10, false, false)`, `"map00b"` -> `("map", 2, 0, true, true)`,
/// `"bg020do"` -> `("bg", 3, 20, true, true)`.
fn split_image_numeric_stem(stem: &str) -> Option<(String, usize, usize, bool, bool)> {
    let bytes = stem.as_bytes();
    if bytes.is_empty() || !stem.is_ascii() {
        return None;
    }
    // Strip up to 2 trailing ASCII letters if preceded by digits
    let mut end = bytes.len();
    let mut letter_count = 0usize;
    while end > 0 && letter_count < 2 && bytes[end - 1].is_ascii_alphabetic() {
        end -= 1;
        letter_count += 1;
    }
    if end == 0 || !bytes[end - 1].is_ascii_digit() {
        return None;
    }
    let mut dig_start = end;
    while dig_start > 0 && bytes[dig_start - 1].is_ascii_digit() {
        dig_start -= 1;
    }
    let digits_len = end - dig_start;
    if !(1..=4).contains(&digits_len) {
        return None;
    }
    let num_str = &stem[dig_start..end];
    let num = num_str.parse::<usize>().ok()?;
    if num > 1000 {
        return None;
    }
    let prefix = &stem[..dig_start];
    let zero_pad = digits_len > 1 && num_str.starts_with('0');
    Some((
        prefix.to_string(),
        digits_len,
        num,
        letter_count > 0,
        zero_pad,
    ))
}

fn parse_simple_csv(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let mut fields = Vec::new();
        let mut cur = String::new();
        let mut in_quotes = false;
        let mut chars = line.chars().peekable();
        while let Some(ch) = chars.next() {
            if in_quotes {
                if ch == '"' {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        cur.push('"');
                    } else {
                        in_quotes = false;
                    }
                } else {
                    cur.push(ch);
                }
            } else if ch == '"' && cur.is_empty() {
                in_quotes = true;
            } else if ch == ',' {
                fields.push(std::mem::take(&mut cur));
            } else {
                cur.push(ch);
            }
        }
        fields.push(cur);
        rows.push(fields);
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_round_auto_unhash_without_lst() {
        let hasher = Hxv4Hasher::default();
        let cglist_hash = hasher.file_hash_hex("cglist.csv");
        let target_cg_hash = hasher.file_hash_hex("ev01a.pimg");
        let target_thum_hash = hasher.file_hash_hex("savethum_ev01.png");
        let root_dir_hash = hasher.path_hash_hex("");
        let data_dir_hash = hasher.path_hash_hex("data/main/");

        let cglist_csv = b"thum_ev01,ev01a|ev01b\r\n";

        let target_paths = HashSet::from([root_dir_hash.clone(), data_dir_hash.clone()]);
        let target_files = HashSet::from([
            cglist_hash.clone(),
            target_cg_hash.clone(),
            target_thum_hash.clone(),
        ]);

        let mut unhasher = AutoUnhasher::new(hasher, target_paths, target_files);
        let targets = [UnhashTarget {
            id: 0,
            domain_hash: data_dir_hash.clone(),
            file_hash: cglist_hash.clone(),
            data: cglist_csv,
        }];

        let res = unhasher.run_auto_analysis(&targets);
        assert_eq!(res.path_map.get(&root_dir_hash).map(String::as_str), Some(""));
        assert_eq!(
            res.path_map.get(&data_dir_hash).map(String::as_str),
            Some("data/main/")
        );
        assert_eq!(
            res.file_map.get(&cglist_hash).map(String::as_str),
            Some("cglist.csv")
        );
        assert_eq!(
            res.file_map.get(&target_cg_hash).map(String::as_str),
            Some("ev01a.pimg")
        );
        assert_eq!(
            res.file_map.get(&target_thum_hash).map(String::as_str),
            Some("savethum_ev01.png")
        );
    }

    #[test]
    fn test_comma_stage_sysse_tiled_and_sinfo_unhash() {
        let hasher = Hxv4Hasher::default();
        let base_stage_h = hasher.file_hash_hex("base.stage");
        let sysse_h = hasher.file_hash_hex("sysse.ini");
        let bg_h = hasher.file_hash_hex("bg001a.png");
        let bg_c_h = hasher.file_hash_hex("bg002co.png");
        let sysv_h = hasher.file_hash_hex("45fd_sys_ykn017.opus");
        let tile_h = hasher.file_hash_hex("45fd_gred_2.png");
        let sinfo_h = hasher.file_hash_hex("杉並1_1.sinfo");
        let stand_h = hasher.file_hash_hex("杉並.stand");
        let dir_h = hasher.path_hash_hex("");

        let stage_txt = br#"%[ "times", %[ "day", %[ "label", "a" ], "night", %[ "label", "c" ] ], "stages", %[ "s1", %["image", "bg001TIME"], "s2", %["image", "bg002TIMEo"] ] ]"#;
        let sysse_txt = b"sysvodef.keys = ykn aik\nsysvoice.brand = 45fd_sys_%s001\n";
        let tile_txt = br#"%[ format:"45fd_gred_${y}", horz:0, vert:3 ]"#;
        let sinfo_txt = "杉並1_1\tfacexoff\t0\t0\r\n".as_bytes();

        let target_paths = HashSet::from([dir_h.clone()]);
        let target_files = HashSet::from([
            base_stage_h.clone(),
            sysse_h.clone(),
            bg_h.clone(),
            bg_c_h.clone(),
            sysv_h.clone(),
            tile_h.clone(),
            sinfo_h.clone(),
            stand_h.clone(),
        ]);

        let mut unhasher = AutoUnhasher::new(hasher, target_paths, target_files);
        let targets = [
            UnhashTarget {
                id: 0,
                domain_hash: dir_h.clone(),
                file_hash: base_stage_h,
                data: stage_txt,
            },
            UnhashTarget {
                id: 1,
                domain_hash: dir_h.clone(),
                file_hash: sysse_h,
                data: sysse_txt,
            },
            UnhashTarget {
                id: 2,
                domain_hash: dir_h.clone(),
                file_hash: tile_h.clone(),
                data: tile_txt,
            },
            UnhashTarget {
                id: 3,
                domain_hash: dir_h,
                file_hash: sinfo_h.clone(),
                data: sinfo_txt,
            },
        ];

        let res = unhasher.run_auto_analysis(&targets);
        assert_eq!(res.file_map.get(&bg_h).map(String::as_str), Some("bg001a.png"));
        assert_eq!(res.file_map.get(&bg_c_h).map(String::as_str), Some("bg002co.png"));
        assert_eq!(
            res.file_map.get(&sysv_h).map(String::as_str),
            Some("45fd_sys_ykn017.opus")
        );
        assert_eq!(
            res.file_map.get(&tile_h).map(String::as_str),
            Some("45fd_gred_2.png")
        );
        assert_eq!(
            res.file_map.get(&sinfo_h).map(String::as_str),
            Some("杉並1_1.sinfo")
        );
        assert_eq!(
            res.file_map.get(&stand_h).map(String::as_str),
            Some("杉並.stand")
        );
    }

    #[test]
    fn test_quoted_stand_psd_txt_and_uipsd_func_unhash() {
        let hasher = Hxv4Hasher::default();
        let stand_h = hasher.file_hash_hex("kotori.stand");
        let txt_h = hasher.file_hash_hex("KotoRI1_1.txt");
        let tlg_h = hasher.file_hash_hex("KotoRI1_1_18.tlg");
        let char_dir_h = hasher.path_hash_hex("kotori/");
        let func_h = hasher.file_hash_hex("quickmenu.func");
        let pimg_h = hasher.file_hash_hex("quickmenu.pimg");
        let root_h = hasher.path_hash_hex("");

        let stand_data = br#"[%[ "filename"=>"KotoRI1_1", "xoffset"=>0 ]]"#;
        let psd_txt = b"#layer_type\tname\tleft\ttop\twidth\theight\ttype\topacity\tvisible\tlayer_id\tgroup_layer_id\r\n0\tface\t0\t0\t10\t10\t13\t255\t1\t18\t22\r\n";
        let func_data = b"psd,quickmenu\r\nui,#AUTO,\t@markpos:auto:rect\r\n";

        let target_paths = HashSet::from([root_h.clone(), char_dir_h.clone()]);
        let target_files = HashSet::from([
            stand_h.clone(),
            txt_h.clone(),
            tlg_h.clone(),
            func_h.clone(),
            pimg_h.clone(),
        ]);

        let mut unhasher = AutoUnhasher::new(hasher, target_paths, target_files);
        unhasher.add_file_candidate("kotori.stand");
        let targets = [
            UnhashTarget {
                id: 0,
                domain_hash: root_h.clone(),
                file_hash: stand_h,
                data: stand_data,
            },
            UnhashTarget {
                id: 1,
                domain_hash: char_dir_h.clone(),
                file_hash: txt_h.clone(),
                data: psd_txt,
            },
            UnhashTarget {
                id: 2,
                domain_hash: root_h,
                file_hash: func_h.clone(),
                data: func_data,
            },
        ];

        let res = unhasher.run_auto_analysis(&targets);
        assert_eq!(res.path_map.get(&char_dir_h).map(String::as_str), Some("kotori/"));
        assert_eq!(res.file_map.get(&txt_h).map(String::as_str), Some("KotoRI1_1.txt"));
        assert_eq!(res.file_map.get(&tlg_h).map(String::as_str), Some("KotoRI1_1_18.tlg"));
        assert_eq!(res.file_map.get(&func_h).map(String::as_str), Some("quickmenu.func"));
        assert_eq!(res.file_map.get(&pimg_h).map(String::as_str), Some("quickmenu.pimg"));
    }
}
