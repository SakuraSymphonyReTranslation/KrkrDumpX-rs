use std::collections::{HashMap, HashSet};

const SEASONS: [&str; 4] = ["春", "夏", "秋", "冬"];
const LOCALES: [&str; 4] = ["jp", "cn", "en", "tw"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SlotKind {
    Num,
    Letters,
    Season,
    Locale,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SigPart {
    Literal(String),
    Slot(SlotKind),
}

#[derive(Debug, Clone)]
struct ParsedStem {
    slot_values: Vec<(SlotKind, String)>,
}

fn split_ext_double(name: &str) -> (&str, &str) {
    let Some((stem, ext)) = name.rsplit_once('.') else {
        return (name, "");
    };
    let ext_with_dot = &name[stem.len()..];
    if matches!(ext, "sli" | "csv" | "vol" | "scn") {
        if let Some((stem2, _)) = stem.rsplit_once('.') {
            return (stem2, &name[stem2.len()..]);
        }
    }
    (stem, ext_with_dot)
}

fn is_delim(ch: Option<char>) -> bool {
    match ch {
        None => true,
        Some(c) => {
            !c.is_ascii()
                || matches!(
                    c,
                    '_' | '-' | '.' | '/' | '／' | '（' | '）' | '(' | ')' | '[' | ']' | '【' | '】'
                )
        }
    }
}

/// Decompose a filename stem into literals and variable slots (numbers, short
/// bounded lowercase runs, seasonal kanji, and `_jp`/`_cn`/`_en`/`_tw` locale tags).
fn stem_signature(stem: &str) -> (Vec<SigPart>, ParsedStem) {
    let chars: Vec<char> = stem.chars().collect();
    let n = chars.len();
    let mut parts: Vec<SigPart> = Vec::new();
    let mut values: Vec<(SlotKind, String)> = Vec::new();
    let mut lit = String::new();
    let mut i = 0usize;

    let flush_lit = |lit: &mut String, parts: &mut Vec<SigPart>| {
        if !lit.is_empty() {
            parts.push(SigPart::Literal(std::mem::take(lit)));
        }
    };

    while i < n {
        let ch = chars[i];

        // Locale suffix `_jp`, `_cn`, `_en`, `_tw` followed by boundary
        if ch == '_' && i + 3 <= n {
            let tag: String = chars[i + 1..i + 3].iter().collect();
            let after = chars.get(i + 3).copied();
            if LOCALES.contains(&tag.as_str())
                && matches!(after, None | Some('_') | Some('.'))
            {
                flush_lit(&mut lit, &mut parts);
                parts.push(SigPart::Slot(SlotKind::Locale));
                values.push((SlotKind::Locale, format!("_{tag}")));
                i += 3;
                continue;
            }
        }

        // Seasonal kanji
        let ch_str = ch.to_string();
        if SEASONS.contains(&ch_str.as_str()) {
            flush_lit(&mut lit, &mut parts);
            parts.push(SigPart::Slot(SlotKind::Season));
            values.push((SlotKind::Season, ch_str));
            i += 1;
            continue;
        }

        // ASCII digit run
        if ch.is_ascii_digit() {
            let start = i;
            while i < n && chars[i].is_ascii_digit() {
                i += 1;
            }
            let run: String = chars[start..i].iter().collect();
            flush_lit(&mut lit, &mut parts);
            parts.push(SigPart::Slot(SlotKind::Num));
            values.push((SlotKind::Num, run));
            continue;
        }

        // Short bounded lowercase ASCII run (len <= 3) between delimiters
        if ch.is_ascii_lowercase() {
            let start = i;
            while i < n && chars[i].is_ascii_lowercase() {
                i += 1;
            }
            let prev = if start > 0 { Some(chars[start - 1]) } else { None };
            let next = chars.get(i).copied();
            let run_len = i - start;
            if run_len <= 3 && is_delim(prev) && is_delim(next) {
                let run: String = chars[start..i].iter().collect();
                flush_lit(&mut lit, &mut parts);
                parts.push(SigPart::Slot(SlotKind::Letters));
                values.push((SlotKind::Letters, run));
                continue;
            }
            for &c in &chars[start..i] {
                lit.push(c);
            }
            continue;
        }

        lit.push(ch);
        i += 1;
    }

    flush_lit(&mut lit, &mut parts);
    (parts, ParsedStem { slot_values: values })
}

fn render_signature(parts: &[SigPart], values: &[String]) -> String {
    let mut out = String::new();
    let mut vi = 0usize;
    for p in parts {
        match p {
            SigPart::Literal(s) => out.push_str(s),
            SigPart::Slot(_) => {
                if let Some(v) = values.get(vi) {
                    out.push_str(v);
                }
                vi += 1;
            }
        }
    }
    out
}

fn split_dunder_tail(stem: &str) -> Option<(&str, &str)> {
    let (base, tail) = stem.rsplit_once("__")?;
    if base.is_empty() {
        return None;
    }
    let valid_tail = tail == "pack"
        || tail == "frame"
        || tail == "anim"
        || tail
            .strip_prefix("bg")
            .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()));
    if valid_tail {
        Some((base, tail))
    } else {
        None
    }
}

fn emit_letter_combos(len: usize, mut f: impl FnMut(&str) -> bool) {
    match len {
        1 => {
            let mut buf = [0u8; 1];
            for a in b'a'..=b'z' {
                buf[0] = a;
                if !f(std::str::from_utf8(&buf).unwrap()) {
                    return;
                }
            }
        }
        2 => {
            let mut buf = [0u8; 2];
            for a in b'a'..=b'z' {
                buf[0] = a;
                for b in b'a'..=b'z' {
                    buf[1] = b;
                    if !f(std::str::from_utf8(&buf).unwrap()) {
                        return;
                    }
                }
            }
        }
        3 => {
            let mut buf = [0u8; 3];
            for a in b'a'..=b'z' {
                buf[0] = a;
                for b in b'a'..=b'z' {
                    buf[1] = b;
                    for c in b'a'..=b'z' {
                        buf[2] = c;
                        if !f(std::str::from_utf8(&buf).unwrap()) {
                            return;
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

/// Induce naming grammars from already-verified filenames and return candidate
/// sibling filenames (bounded by `max_candidates`).
pub fn induce_family_candidates(known_names: &[String], max_candidates: usize) -> Vec<String> {
    let known: HashSet<&str> = known_names.iter().map(String::as_str).collect();
    let mut out: Vec<String> = Vec::new();
    let mut emitted_set: HashSet<String> = HashSet::new();

    let mut push_cand = |cand: String| -> bool {
        if out.len() >= max_candidates {
            return false;
        }
        if cand.is_empty() || cand.contains("//") || known.contains(cand.as_str()) {
            return true;
        }
        if emitted_set.insert(cand.clone()) {
            out.push(cand);
        }
        out.len() < max_candidates
    };

    let mut groups: HashMap<(Vec<SigPart>, String), Vec<ParsedStem>> = HashMap::new();
    let mut ext_pool: HashSet<String> = HashSet::new();
    let mut wrapper_counts: HashMap<String, usize> = HashMap::new();
    let mut dunder_bases: HashSet<String> = HashSet::new();
    let mut dunder_tails: HashSet<String> = HashSet::new();

    for name in known_names {
        if name.is_empty() {
            continue;
        }
        let (stem, ext) = split_ext_double(name);
        ext_pool.insert(ext.to_string());

        let (sig, parsed) = stem_signature(stem);
        groups
            .entry((sig, ext.to_string()))
            .or_default()
            .push(parsed);

        if let Some((head, _)) = stem.split_once('_') {
            if (2..=12).contains(&head.len()) && head.bytes().all(|b| b.is_ascii_alphabetic()) {
                *wrapper_counts.entry(head.to_ascii_lowercase()).or_insert(0) += 1;
            }
        }

        if let Some((base, tail)) = split_dunder_tail(stem) {
            dunder_bases.insert(base.to_string());
            dunder_tails.insert(tail.to_string());
        }
    }

    // 1. Wrapper prefix cross-product (`<prefix>_<base>.<ext>`), e.g. `logface_` <-> `logname_`, `thum_` <-> `savethum_`
    let wrapper_prefixes: Vec<String> = wrapper_counts
        .into_iter()
        .filter_map(|(p, c)| if c >= 2 { Some(p) } else { None })
        .collect();
    if !wrapper_prefixes.is_empty() {
        let mut bases: Vec<String> = Vec::new();
        let mut base_seen: HashSet<String> = HashSet::new();
        for name in known_names {
            let (stem, _) = split_ext_double(name);
            let low_stem = stem.to_ascii_lowercase();
            for p in &wrapper_prefixes {
                if low_stem.len() > p.len() + 1
                    && low_stem.starts_with(p.as_str())
                    && stem.as_bytes()[p.len()] == b'_'
                {
                    let base = &stem[p.len() + 1..];
                    if !base.is_empty() && base_seen.insert(base.to_string()) {
                        bases.push(base.to_string());
                    }
                }
            }
        }
        for base in bases.iter().take(3000) {
            for p in &wrapper_prefixes {
                for ext in [".png", ".jpg", ".tlg", ".pbd", ".tjs"] {
                    if !push_cand(format!("{p}_{base}{ext}")) {
                        return out;
                    }
                }
            }
        }
    }

    // 2. Dunder layer packaging (`__pack`, `__bg0`, `__frame`, `__anim`)
    for base in &dunder_bases {
        for ext in [".tlg", ".png", ".jpg", ".pbd", ".tjs", ".csv", ".ini"] {
            if ext_pool.contains(ext) && !push_cand(format!("{base}{ext}")) {
                return out;
            }
        }
        for loc in LOCALES {
            for ext in [".pbd", ".tjs", ".png", ".jpg", ".tlg"] {
                if !push_cand(format!("{base}_{loc}{ext}")) {
                    return out;
                }
            }
        }
        for tail in &dunder_tails {
            for ext in [".tlg", ".png", ".jpg"] {
                if !push_cand(format!("{base}__{tail}{ext}")) {
                    return out;
                }
            }
        }
    }

    // 3. Same-signature families (>= 2 observed samples)
    for ((sig, ext), samples) in &groups {
        if samples.len() < 2 {
            continue;
        }
        let slot_count = samples[0].slot_values.len();
        if slot_count == 0 {
            continue;
        }
        let mut group_budget = 4000usize;

        // Count how many slots actually vary across samples
        let varying_slots = (0..slot_count)
            .filter(|&si| {
                let distinct: HashSet<&str> = samples
                    .iter()
                    .filter_map(|s| s.slot_values.get(si).map(|(_, v)| v.as_str()))
                    .collect();
                distinct.len() >= 2
            })
            .count();

        // Detect which slot indices actually vary across samples
        for slot_idx in 0..slot_count {
            if group_budget == 0 {
                break;
            }
            let kind = samples[0].slot_values[slot_idx].0;
            let distinct: HashSet<&str> = samples
                .iter()
                .filter_map(|s| s.slot_values.get(slot_idx).map(|(_, v)| v.as_str()))
                .collect();

            match kind {
                SlotKind::Num => {
                    if distinct.len() < 2 {
                        continue;
                    }
                    let mut min_v = usize::MAX;
                    let mut max_v = 0usize;
                    let mut max_width = 1usize;
                    for v in &distinct {
                        if let Ok(num) = v.parse::<usize>() {
                            if num <= 20_000 {
                                min_v = min_v.min(num);
                                max_v = max_v.max(num);
                                max_width = max_width.max(v.len());
                            }
                        }
                    }
                    if min_v > max_v {
                        continue;
                    }
                    let start = min_v.saturating_sub(8);
                    let end = (max_v + 60).min(start + 1500);

                    // Pick representative templates (deduped on other slots)
                    let mut reps: Vec<Vec<String>> = Vec::new();
                    let mut seen_other: HashSet<Vec<String>> = HashSet::new();
                    for s in samples {
                        let vals: Vec<String> =
                            s.slot_values.iter().map(|(_, v)| v.clone()).collect();
                        let mut key = vals.clone();
                        key[slot_idx].clear();
                        if seen_other.insert(key) {
                            reps.push(vals);
                            if reps.len() >= 16 {
                                break;
                            }
                        }
                    }

                    for v in start..=end {
                        if group_budget == 0 {
                            break;
                        }
                        let formatted = if max_width > 1 {
                            format!("{v:0max_width$}")
                        } else {
                            v.to_string()
                        };
                        for rep in &reps {
                            let mut vals = rep.clone();
                            vals[slot_idx] = formatted.clone();
                            let cand = format!("{}{ext}", render_signature(sig, &vals));
                            if !push_cand(cand) {
                                return out;
                            }
                            group_budget = group_budget.saturating_sub(1);
                            if group_budget == 0 {
                                break;
                            }
                        }
                    }
                }
                SlotKind::Letters => {
                    if distinct.len() < 2 {
                        continue;
                    }
                    let lens: HashSet<usize> = distinct.iter().map(|v| v.len()).collect();
                    let max_len = lens.iter().copied().max().unwrap_or(0);
                    if max_len == 0 || max_len > 3 {
                        continue;
                    }
                    // Allow full 26^3 (17,576) enumeration for compact 3-letter code families (e.g. `eye_xxx.png`, `chaticon_xxx.png`)
                    let allow_3 = max_len == 3 && varying_slots == 1 && samples.len() <= 24;
                    let mut local_budget = if allow_3 { 18_000 } else { group_budget };

                    let mut reps: Vec<Vec<String>> = Vec::new();
                    let mut seen_other: HashSet<Vec<String>> = HashSet::new();
                    for s in samples {
                        let vals: Vec<String> =
                            s.slot_values.iter().map(|(_, v)| v.clone()).collect();
                        let mut key = vals.clone();
                        key[slot_idx].clear();
                        if seen_other.insert(key) {
                            reps.push(vals);
                            if reps.len() >= if allow_3 { 1 } else { 12 } {
                                break;
                            }
                        }
                    }

                    // Also probe 1-letter variants (`eye_a.png`) alongside 3-letter code families (`eye_asa.png`)
                    let mut probe_lens: Vec<usize> = lens.into_iter().collect();
                    if allow_3 && !probe_lens.contains(&1) {
                        probe_lens.push(1);
                    }

                    for run_len in probe_lens {
                        if run_len == 3 && !allow_3 {
                            continue;
                        }
                        let mut exhausted = false;
                        for rep in &reps {
                            emit_letter_combos(run_len, |combo| {
                                if local_budget == 0 {
                                    exhausted = true;
                                    return false;
                                }
                                let mut vals = rep.clone();
                                vals[slot_idx] = combo.to_string();
                                let cand = format!("{}{ext}", render_signature(sig, &vals));
                                if !push_cand(cand) {
                                    exhausted = true;
                                    return false;
                                }
                                local_budget = local_budget.saturating_sub(1);
                                true
                            });
                            if exhausted {
                                break;
                            }
                        }
                    }
                }
                SlotKind::Season => {
                    for s in samples.iter().take(32) {
                        let base_vals: Vec<String> =
                            s.slot_values.iter().map(|(_, v)| v.clone()).collect();
                        for season in SEASONS {
                            let mut vals = base_vals.clone();
                            vals[slot_idx] = season.to_string();
                            let cand = format!("{}{ext}", render_signature(sig, &vals));
                            if !push_cand(cand) {
                                return out;
                            }
                        }
                    }
                }
                SlotKind::Locale => {
                    for s in samples.iter().take(64) {
                        let base_vals: Vec<String> =
                            s.slot_values.iter().map(|(_, v)| v.clone()).collect();
                        for loc in LOCALES {
                            let mut vals = base_vals.clone();
                            vals[slot_idx] = format!("_{loc}");
                            let cand = format!("{}{ext}", render_signature(sig, &vals));
                            if !push_cand(cand) {
                                return out;
                            }
                        }
                    }
                }
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grammar_induces_short_code_and_wrapper_families() {
        let known = vec![
            "eye_asa.png".to_string(),
            "eye_asu.png".to_string(),
            "eye_hiy.png".to_string(),
            "logface_alice.png".to_string(),
            "logface_bob.png".to_string(),
            "logname_alice.png".to_string(),
            "logname_carol.png".to_string(),
            "bg_春01.png".to_string(),
            "bg_夏01.png".to_string(),
        ];

        let cands = induce_family_candidates(&known, 50_000);
        let set: HashSet<&str> = cands.iter().map(String::as_str).collect();
        assert!(set.contains("eye_com.png"));
        assert!(set.contains("eye_pro.png"));
        assert!(set.contains("logface_carol.png"));
        assert!(set.contains("logname_bob.png"));
        assert!(set.contains("bg_秋01.png"));
        assert!(set.contains("bg_冬01.png"));
    }
}
