use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet};

#[inline]
fn align4(v: usize) -> usize {
    (v + 3) & !3
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum TjsDataValue {
    Void,
    Object(i16),
    InterObject(i16),
    String(String),
    Octet(Vec<u8>),
    Real(f64),
    Int(i64),
    Unknown(i16, i16),
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TjsCodeObject {
    pub index: usize,
    pub name: String,
    pub code: Vec<i16>,
    pub data: Vec<TjsDataValue>,
}

#[derive(Debug, Clone)]
pub struct Tjs2Bytecode {
    pub bytes: Vec<i8>,
    pub shorts: Vec<i16>,
    pub ints: Vec<i32>,
    pub int64s: Vec<i64>,
    pub reals: Vec<f64>,
    pub strings: Vec<String>,
    pub octets: Vec<Vec<u8>>,
    pub toplevel: i32,
    pub objects: Vec<TjsCodeObject>,
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let slice = self
            .data
            .get(self.pos..self.pos + n)
            .ok_or_else(|| anyhow::anyhow!("unexpected EOF in TJS2 bytecode at 0x{:x}", self.pos))?;
        self.pos += n;
        Ok(slice)
    }

    fn skip(&mut self, n: usize) -> Result<()> {
        if self.pos + n > self.data.len() {
            bail!("unexpected EOF skipping {n} bytes in TJS2 at 0x{:x}", self.pos);
        }
        self.pos += n;
        Ok(())
    }

    fn read_i8(&mut self) -> Result<i8> {
        Ok(self.read_bytes(1)?[0] as i8)
    }

    fn read_u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.read_bytes(2)?.try_into().unwrap()))
    }

    fn read_i16(&mut self) -> Result<i16> {
        Ok(i16::from_le_bytes(self.read_bytes(2)?.try_into().unwrap()))
    }

    fn read_u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read_bytes(4)?.try_into().unwrap()))
    }

    fn read_i32(&mut self) -> Result<i32> {
        Ok(i32::from_le_bytes(self.read_bytes(4)?.try_into().unwrap()))
    }

    fn read_i64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.read_bytes(8)?.try_into().unwrap()))
    }

    fn read_f64(&mut self) -> Result<f64> {
        Ok(f64::from_le_bytes(self.read_bytes(8)?.try_into().unwrap()))
    }
}

impl Tjs2Bytecode {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 12 || &data[..8] != b"TJS2100\0" {
            bail!("not a TJS2100 bytecode file");
        }

        let mut bc = Self {
            bytes: Vec::new(),
            shorts: Vec::new(),
            ints: Vec::new(),
            int64s: Vec::new(),
            reals: Vec::new(),
            strings: Vec::new(),
            octets: Vec::new(),
            toplevel: -1,
            objects: Vec::new(),
        };

        let mut off = 12usize;
        let mut saw_data = false;

        while off + 8 <= data.len() {
            let tag = &data[off..off + 4];
            let chunk_size = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()) as usize;
            if chunk_size < 8 || off + chunk_size > data.len() {
                bail!("invalid TJS2 chunk size {chunk_size:#x} at {off:#x}");
            }
            let body = &data[off + 8..off + chunk_size];
            match tag {
                b"DATA" => {
                    bc.parse_data_chunk(body)?;
                    saw_data = true;
                }
                b"OBJS" => {
                    // Best-effort OBJS parse (keep strings even if an unusual OBJS fails)
                    let _ = bc.parse_objs_chunk(body);
                }
                _ => {}
            }
            off += chunk_size;
        }

        if !saw_data {
            bail!("TJS2100 bytecode has no DATA chunk");
        }

        Ok(bc)
    }

    fn parse_data_chunk(&mut self, body: &[u8]) -> Result<()> {
        let mut cur = Cursor::new(body);

        // bytes
        let count = cur.read_u32()? as usize;
        self.bytes.reserve(count);
        for _ in 0..count {
            self.bytes.push(cur.read_i8()?);
        }
        cur.skip(align4(count) - count)?;

        // shorts
        let count = cur.read_u32()? as usize;
        self.shorts.reserve(count);
        for _ in 0..count {
            self.shorts.push(cur.read_i16()?);
        }
        if count % 2 != 0 {
            cur.skip(2)?;
        }

        // ints
        let count = cur.read_u32()? as usize;
        self.ints.reserve(count);
        for _ in 0..count {
            self.ints.push(cur.read_i32()?);
        }

        // int64s
        let count = cur.read_u32()? as usize;
        self.int64s.reserve(count);
        for _ in 0..count {
            self.int64s.push(cur.read_i64()?);
        }

        // doubles
        let count = cur.read_u32()? as usize;
        self.reals.reserve(count);
        for _ in 0..count {
            self.reals.push(cur.read_f64()?);
        }

        // strings (UTF-16LE, aligned to 4 bytes)
        let count = cur.read_u32()? as usize;
        self.strings.reserve(count);
        for _ in 0..count {
            let len = cur.read_u32()? as usize;
            let mut units = Vec::with_capacity(len);
            for _ in 0..len {
                units.push(cur.read_u16()?);
            }
            if len % 2 != 0 {
                cur.skip(2)?;
            }
            self.strings.push(String::from_utf16_lossy(&units));
        }

        // octets
        if cur.remaining() >= 4 {
            let count = cur.read_u32()? as usize;
            self.octets.reserve(count);
            for _ in 0..count {
                let len = cur.read_u32()? as usize;
                let raw = cur.read_bytes(len)?.to_vec();
                cur.skip(align4(len) - len)?;
                self.octets.push(raw);
            }
        }

        Ok(())
    }

    fn parse_objs_chunk(&mut self, body: &[u8]) -> Result<()> {
        let mut cur = Cursor::new(body);
        if cur.remaining() < 8 {
            return Ok(());
        }
        self.toplevel = cur.read_i32()?;
        let obj_count = cur.read_u32()? as usize;

        for obj_idx in 0..obj_count {
            if cur.remaining() < 8 {
                break;
            }
            let tag = cur.read_bytes(4)?;
            if tag != b"TJS2" {
                bail!("unexpected TJS2 object tag {tag:?}");
            }
            let obj_size = cur.read_u32()? as usize;
            let obj_start = cur.pos;
            let obj_end = obj_start.saturating_add(obj_size);

            let _parent = cur.read_i32()?;
            let name_idx = cur.read_u32()? as usize;
            let _context_type = cur.read_u32()?;
            let _max_var = cur.read_u32()?;
            let _var_reserve = cur.read_u32()?;
            let _max_frame = cur.read_u32()?;
            let _func_decl_arg = cur.read_u32()?;
            let _func_decl_unnamed = cur.read_u32()?;
            let _func_decl_collapse = cur.read_i32()?;
            let _prop_setter = cur.read_i32()?;
            let _prop_getter = cur.read_i32()?;
            let _super_class_getter = cur.read_i32()?;

            let src_pos_count = cur.read_u32()? as usize;
            cur.skip(src_pos_count * 8)?;

            let code_count = cur.read_u32()? as usize;
            let mut code = Vec::with_capacity(code_count);
            for _ in 0..code_count {
                code.push(cur.read_i16()?);
            }
            if code_count % 2 != 0 {
                cur.skip(2)?;
            }

            let data_count = cur.read_u32()? as usize;
            let mut data = Vec::with_capacity(data_count);
            for _ in 0..data_count {
                let dtype = cur.read_i16()?;
                let index = cur.read_i16()?;
                data.push(self.resolve_data(dtype, index));
            }

            let scg_count = cur.read_u32()? as usize;
            cur.skip(scg_count * 4)?;

            let prop_count = cur.read_u32()? as usize;
            cur.skip(prop_count * 8)?;

            if cur.pos < obj_end && obj_end <= body.len() {
                cur.pos = obj_end;
            }

            let name = self.strings.get(name_idx).cloned().unwrap_or_default();
            self.objects.push(TjsCodeObject {
                index: obj_idx,
                name,
                code,
                data,
            });
        }
        Ok(())
    }

    fn resolve_data(&self, dtype: i16, index: i16) -> TjsDataValue {
        let idx = index as usize;
        match dtype {
            0 => TjsDataValue::Void,
            1 => TjsDataValue::Object(index),
            2 => TjsDataValue::InterObject(index),
            3 => self
                .strings
                .get(idx)
                .cloned()
                .map(TjsDataValue::String)
                .unwrap_or(TjsDataValue::Unknown(dtype, index)),
            4 => self
                .octets
                .get(idx)
                .cloned()
                .map(TjsDataValue::Octet)
                .unwrap_or(TjsDataValue::Unknown(dtype, index)),
            5 => self
                .reals
                .get(idx)
                .copied()
                .map(TjsDataValue::Real)
                .unwrap_or(TjsDataValue::Unknown(dtype, index)),
            6 => self
                .bytes
                .get(idx)
                .map(|&v| TjsDataValue::Int(v as i64))
                .unwrap_or(TjsDataValue::Unknown(dtype, index)),
            7 => self
                .shorts
                .get(idx)
                .map(|&v| TjsDataValue::Int(v as i64))
                .unwrap_or(TjsDataValue::Unknown(dtype, index)),
            8 => self
                .ints
                .get(idx)
                .map(|&v| TjsDataValue::Int(v as i64))
                .unwrap_or(TjsDataValue::Unknown(dtype, index)),
            9 => self
                .int64s
                .get(idx)
                .copied()
                .map(TjsDataValue::Int)
                .unwrap_or(TjsDataValue::Unknown(dtype, index)),
            _ => TjsDataValue::Unknown(dtype, index),
        }
    }

    /// Find `bres://./<key>/bootstrap` in the TJS2 string pool.
    pub fn find_bootstrap_url(&self) -> Result<String> {
        for s in &self.strings {
            if s.starts_with("bres://./") && s.to_ascii_lowercase().ends_with("/bootstrap") {
                return Ok(s.clone());
            }
        }
        bail!("could not find bootstrap bres URL (bres://./.../bootstrap) in STARTUP.TJS strings")
    }

    /// Extract the first string argument passed to `_bootStrap("...")` directly by tracing
    /// TJS2100 VM instructions in `OBJS`, avoiding any external Python decompiler dependency.
    pub fn find_bootstrap_prefix_from_bytecode(&self) -> Option<String> {
        const OP_CONST: i16 = 1;
        const OP_CP: i16 = 2;
        const OP_CL: i16 = 3;
        const OP_CCL: i16 = 4;
        const OP_CALL: i16 = 99;
        const OP_CALLD: i16 = 100;
        const OP_GPD: i16 = 103;
        const OP_GPDS: i16 = 110;

        for obj in &self.objects {
            let code = &obj.code;
            let mut reg_str: HashMap<i16, String> = HashMap::new();
            let mut reg_prop: HashMap<i16, String> = HashMap::new();

            let mut pos = 0usize;
            while pos < code.len() {
                let op = code[pos];
                let size = tjs2_instruction_size(code, pos);

                match op {
                    OP_CONST if pos + 2 < code.len() => {
                        let dest = code[pos + 1];
                        let data_idx = code[pos + 2] as usize;
                        reg_prop.remove(&dest);
                        if let Some(TjsDataValue::String(s)) = obj.data.get(data_idx) {
                            reg_str.insert(dest, s.clone());
                        } else {
                            reg_str.remove(&dest);
                        }
                    }
                    OP_CP if pos + 2 < code.len() => {
                        let dest = code[pos + 1];
                        let src = code[pos + 2];
                        if let Some(s) = reg_str.get(&src).cloned() {
                            reg_str.insert(dest, s);
                        } else {
                            reg_str.remove(&dest);
                        }
                        if let Some(p) = reg_prop.get(&src).cloned() {
                            reg_prop.insert(dest, p);
                        } else {
                            reg_prop.remove(&dest);
                        }
                    }
                    OP_CL if pos + 1 < code.len() => {
                        let dest = code[pos + 1];
                        reg_str.remove(&dest);
                        reg_prop.remove(&dest);
                    }
                    OP_CCL if pos + 2 < code.len() => {
                        let start = code[pos + 1];
                        let count = code[pos + 2];
                        for r in start..start.saturating_add(count) {
                            reg_str.remove(&r);
                            reg_prop.remove(&r);
                        }
                    }
                    OP_GPD | OP_GPDS if pos + 3 < code.len() => {
                        let dest = code[pos + 1];
                        let prop_idx = code[pos + 3] as usize;
                        reg_str.remove(&dest);
                        if let Some(TjsDataValue::String(prop_name)) = obj.data.get(prop_idx) {
                            reg_prop.insert(dest, prop_name.clone());
                        } else {
                            reg_prop.remove(&dest);
                        }
                    }
                    OP_CALLD if pos + 4 < code.len() => {
                        let ret = code[pos + 1];
                        let method_idx = code[pos + 3] as usize;
                        let argc = code[pos + 4];
                        if let Some(TjsDataValue::String(method)) = obj.data.get(method_idx) {
                            if method == "_bootStrap" || method == "bootStrap" {
                                if let Some(arg0_reg) = extract_first_call_arg(code, pos + 4, argc)
                                {
                                    if let Some(val) = reg_str.get(&arg0_reg) {
                                        return Some(val.clone());
                                    }
                                }
                            }
                        }
                        reg_str.remove(&ret);
                        reg_prop.remove(&ret);
                    }
                    OP_CALL if pos + 3 < code.len() => {
                        let ret = code[pos + 1];
                        let func_reg = code[pos + 2];
                        let argc = code[pos + 3];
                        if let Some(func_name) = reg_prop.get(&func_reg) {
                            if func_name == "_bootStrap" || func_name == "bootStrap" {
                                if let Some(arg0_reg) = extract_first_call_arg(code, pos + 3, argc)
                                {
                                    if let Some(val) = reg_str.get(&arg0_reg) {
                                        return Some(val.clone());
                                    }
                                }
                            }
                        }
                        reg_str.remove(&ret);
                        reg_prop.remove(&ret);
                    }
                    _ => {}
                }

                pos += size.max(1);
            }
        }
        None
    }

    /// Fallback: find bootstrap prefix from `DATA` string pool (matches `bres_bootstrap.py`).
    pub fn find_bootstrap_prefix_from_strings(&self) -> Result<String> {
        let mut seen = HashSet::new();
        let mut candidates = Vec::new();
        for s in &self.strings {
            if !s.is_empty() && s.to_ascii_lowercase().contains("all") && seen.insert(s.clone()) {
                candidates.push(s.clone());
            }
        }

        if candidates.len() == 1 {
            return Ok(candidates.remove(0));
        }
        if candidates.is_empty() {
            bail!("could not find System.bootStrap prefix string with 'all' in STARTUP.TJS strings");
        }

        let reserved: Vec<String> = candidates
            .iter()
            .filter(|v| {
                let low = v.to_ascii_lowercase();
                low.contains("right") || low.contains("reserved")
            })
            .cloned()
            .collect();

        if reserved.len() == 1 {
            return Ok(reserved[0].clone());
        }
        let final_cands = if reserved.is_empty() {
            candidates
        } else {
            reserved
        };

        // Pick longest copyright-like string if multiple remain (e.g. contains "(C)" or "©")
        let copyright: Vec<String> = final_cands
            .iter()
            .filter(|v| {
                let low = v.to_ascii_lowercase();
                low.contains("(c)") || v.contains('©')
            })
            .cloned()
            .collect();
        if copyright.len() == 1 {
            return Ok(copyright[0].clone());
        }

        let preview: Vec<String> = final_cands.iter().take(5).map(|v| format!("{v:?}")).collect();
        bail!(
            "ambiguous System.bootStrap prefix in STARTUP.TJS ({} candidates): {}; pass --bootstrap-prefix",
            final_cands.len(),
            preview.join(", ")
        )
    }

    /// Resolve bootstrap prefix using bytecode tracing first, falling back to string pool heuristics.
    pub fn resolve_bootstrap_prefix(&self) -> Result<(String, &'static str)> {
        if let Some(prefix) = self.find_bootstrap_prefix_from_bytecode() {
            return Ok((prefix, "STARTUP.TJS bytecode _bootStrap call"));
        }
        let prefix = self.find_bootstrap_prefix_from_strings()?;
        Ok((prefix, "STARTUP.TJS string-pool heuristic"))
    }
}

/// Derive `CompoundStorageMedia` mediaName from bootstrap prefix (see `startup.tjs` lines 133-134).
pub fn derive_media_name(bootstrap_prefix: &str) -> String {
    let mut parts = bootstrap_prefix.split(':');
    let first = parts.next().unwrap_or("");
    if parts.next().is_some() && !first.is_empty() {
        first.to_string()
    } else {
        "xp3hnp".to_string()
    }
}

fn extract_first_call_arg(code: &[i16], argc_pos: usize, argc: i16) -> Option<i16> {
    if argc >= 1 {
        code.get(argc_pos + 1).copied()
    } else if argc == -2 {
        let real_argc = *code.get(argc_pos + 1)?;
        if real_argc >= 1 {
            // Pair format: (arg_type_flag, arg_reg)
            code.get(argc_pos + 3).copied()
        } else {
            None
        }
    } else {
        None
    }
}

fn tjs2_instruction_size(code: &[i16], pos: usize) -> usize {
    if pos >= code.len() {
        return 1;
    }
    let op = code[pos];
    if !(0..=127).contains(&op) {
        return 1;
    }

    // 1-word ops: NOP(0), NF(14), RET(119), EXTRY(121), REGMEMBER(126), DEBUGGER(127)
    if matches!(op, 0 | 14 | 119 | 121 | 126 | 127) {
        return 1;
    }

    // 2-word ops
    if matches!(
        op,
        3 | 5
            | 6
            | 11
            | 12
            | 13
            | 15
            | 16
            | 17
            | 18
            | 22
            | 82
            | 83
            | 86
            | 87
            | 89
            | 90
            | 91
            | 92
            | 93
            | 94
            | 95
            | 96
            | 97
            | 98
            | 118
            | 122
            | 124
    ) {
        return 2;
    }

    // 3-word ops
    if matches!(
        op,
        1 | 2 | 4 | 7 | 8 | 9 | 10 | 21 | 25 | 88 | 114 | 115 | 120 | 123 | 125
    ) {
        return 3;
    }

    // Binary op families (base = 3, +1 PD = 5, +2 PI = 5, +3 P = 4)
    const BINARY_BASES: &[i16] = &[26, 30, 34, 38, 42, 46, 50, 54, 58, 62, 66, 70, 74, 78];
    for &base in BINARY_BASES {
        if op == base {
            return 3;
        } else if op == base + 1 || op == base + 2 {
            return 5;
        } else if op == base + 3 {
            return 4;
        }
    }

    // 4-word property/index ops
    if matches!(
        op,
        19 | 20
            | 23
            | 24
            | 84
            | 85
            | 103
            | 104
            | 105
            | 106
            | 107
            | 108
            | 109
            | 110
            | 111
            | 112
            | 113
            | 116
            | 117
    ) {
        return 4;
    }

    // CALL(99), NEW(102)
    if matches!(op, 99 | 102) {
        if let Some(&argc) = code.get(pos + 3) {
            return match argc {
                -1 => 4,
                -2 => {
                    let real_argc = code.get(pos + 4).copied().unwrap_or(0).max(0) as usize;
                    5 + real_argc * 2
                }
                n => 4 + n.max(0) as usize,
            };
        }
        return 4;
    }

    // CALLD(100), CALLI(101)
    if matches!(op, 100 | 101) {
        if let Some(&argc) = code.get(pos + 4) {
            return match argc {
                -1 => 5,
                -2 => {
                    let real_argc = code.get(pos + 5).copied().unwrap_or(0).max(0) as usize;
                    6 + real_argc * 2
                }
                n => 5 + n.max(0) as usize,
            };
        }
        return 5;
    }

    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tjs2_bytecode_bootstrap_extraction() {
        // Build a synthetic TJS2100 bytecode containing DATA string pool + OBJS calling _bootStrap("MyGame (C)Studio All Rights Reserved.")
        let mut data_body = Vec::new();
        // bytes, shorts, ints, int64s, doubles = all 0 count
        for _ in 0..5 {
            data_body.extend_from_slice(&0u32.to_le_bytes());
        }
        let strings = [
            "bres://./abc123key/bootstrap",
            "_bootStrap",
            "MyGame (C)Studio All Rights Reserved.",
        ];
        data_body.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        for s in strings {
            let units: Vec<u16> = s.encode_utf16().collect();
            data_body.extend_from_slice(&(units.len() as u32).to_le_bytes());
            for u in &units {
                data_body.extend_from_slice(&u.to_le_bytes());
            }
            if units.len() % 2 != 0 {
                data_body.extend_from_slice(&0u16.to_le_bytes());
            }
        }
        // octets = 0
        data_body.extend_from_slice(&0u32.to_le_bytes());

        // OBJS chunk: 1 TJS2 object
        // CONST r1, data[1] (string 2 = prefix)
        // CALLD r0, r0, data[0] (string 1 = "_bootStrap"), argc=1, arg0=r1
        // RET
        let code: [i16; 10] = [
            1, 1, 1, // CONST r1, data[1]
            100, 0, 0, 0, 1, 1,   // CALLD r0, obj=r0, method=data[0], argc=1, arg0=r1
            119, // RET
        ];
        let mut obj_body = Vec::new();
        // 12 header dwords (48 bytes)
        for _ in 0..12 {
            obj_body.extend_from_slice(&0i32.to_le_bytes());
        }
        obj_body.extend_from_slice(&0u32.to_le_bytes()); // src_pos_count
        obj_body.extend_from_slice(&(code.len() as u32).to_le_bytes());
        for w in code {
            obj_body.extend_from_slice(&w.to_le_bytes());
        }
        // data_count = 2: (STRING=3, idx=1="_bootStrap"), (STRING=3, idx=2=prefix)
        obj_body.extend_from_slice(&2u32.to_le_bytes());
        obj_body.extend_from_slice(&3i16.to_le_bytes());
        obj_body.extend_from_slice(&1i16.to_le_bytes());
        obj_body.extend_from_slice(&3i16.to_le_bytes());
        obj_body.extend_from_slice(&2i16.to_le_bytes());
        obj_body.extend_from_slice(&0u32.to_le_bytes()); // scg_count
        obj_body.extend_from_slice(&0u32.to_le_bytes()); // prop_count

        let mut objs_body = Vec::new();
        objs_body.extend_from_slice(&0i32.to_le_bytes()); // toplevel
        objs_body.extend_from_slice(&1u32.to_le_bytes()); // obj_count
        objs_body.extend_from_slice(b"TJS2");
        objs_body.extend_from_slice(&(obj_body.len() as u32).to_le_bytes());
        objs_body.extend_from_slice(&obj_body);

        let mut blob = Vec::new();
        blob.extend_from_slice(b"TJS2100\0");
        blob.extend_from_slice(&0u32.to_le_bytes()); // total size placeholder
        blob.extend_from_slice(b"DATA");
        blob.extend_from_slice(&((data_body.len() + 8) as u32).to_le_bytes());
        blob.extend_from_slice(&data_body);
        blob.extend_from_slice(b"OBJS");
        blob.extend_from_slice(&((objs_body.len() + 8) as u32).to_le_bytes());
        blob.extend_from_slice(&objs_body);
        let total = blob.len() as u32;
        blob[8..12].copy_from_slice(&total.to_le_bytes());

        let parsed = Tjs2Bytecode::parse(&blob).unwrap();
        assert_eq!(
            parsed.find_bootstrap_url().unwrap(),
            "bres://./abc123key/bootstrap"
        );
        let (prefix, src) = parsed.resolve_bootstrap_prefix().unwrap();
        assert_eq!(prefix, "MyGame (C)Studio All Rights Reserved.");
        assert!(src.contains("bytecode"));
        assert_eq!(derive_media_name(&prefix), "xp3hnp");
        assert_eq!(derive_media_name("custom:GameTitle"), "custom");
    }
}
