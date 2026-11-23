use crate::bootstrap::StaticRecoveryArtifacts;
use crate::drip::{DripLaneJson, DripProgram, DripProgramJson};
use anyhow::Result;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct HxCryptKeyDump {
    pub hxv4_key: [u8; 32],
    pub hxv4_nonce0: [u8; 24],
    pub hxv4_nonce1: [u8; 24],
    pub hash_key: [u8; 32],
    pub archive_seed: [u8; 8],
    pub filter_key: u64,
    pub split_pos_mask: u16,
    pub split_pos: u16,
    pub random_type: u8,
    pub cxdec_table: Vec<u8>,
    pub cxdec_order: [u8; 17],
}

impl HxCryptKeyDump {
    pub fn write_to_dir(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("key.bin"), self.hxv4_key)?;
        std::fs::write(dir.join("nonce0.bin"), self.hxv4_nonce0)?;
        std::fs::write(dir.join("nonce1.bin"), self.hxv4_nonce1)?;
        std::fs::write(dir.join("nonce.bin"), &self.hxv4_nonce0[..16])?;
        std::fs::write(dir.join("hash_key.bin"), self.hash_key)?;
        std::fs::write(dir.join("archive_seed.bin"), self.archive_seed)?;
        std::fs::write(dir.join("CxdecTable.bin"), &self.cxdec_table)?;
        std::fs::write(dir.join("CxdecOrder.bin"), self.cxdec_order)?;

        let info = format!(
            "hxv4_key       = {}\n\
             hxv4_nonce0    = {}\n\
             hxv4_nonce1    = {}\n\
             hash_key       = {}\n\
             archive_seed   = {}\n\
             filter_key     = 0x{:016X}\n\
             split_pos_mask = 0x{:X}\n\
             split_pos      = 0x{:X}\n\
             random_type    = {}\n",
            hex::encode(self.hxv4_key),
            hex::encode(self.hxv4_nonce0),
            hex::encode(self.hxv4_nonce1),
            hex::encode(self.hash_key),
            hex::encode(self.archive_seed),
            self.filter_key,
            self.split_pos_mask,
            self.split_pos,
            self.random_type,
        );
        std::fs::write(dir.join("keys_info.txt"), info)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct DerivedFilterState {
    pub program: DripProgram,
    pub key_dump: HxCryptKeyDump,
}

#[cfg(all(windows, target_arch = "x86"))]
mod native_x86 {
    use super::*;
    use crate::bres::encode_utf16le;
    use anyhow::{Context, bail};
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{FreeLibrary, GetLastError};
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;

    const MANAGER_SIZE: usize = 0x30B0;
    const CONTEXT_OFFSET: usize = 0x28;
    const DRIP_HOLDER_OFFSET: usize = 0x08;
    const DRIP_LANE_BASE_OFFSET: usize = 0x04;
    const LANE_COUNT: usize = 128;
    const LANE_SIZE: usize = 0x10;

    const RVA_ARCHIVE_SEED: usize = 0x81758;
    const RVA_MANAGER_CTOR: usize = 0x0E2D0;
    const RVA_HASH_KEY_DERIVE: usize = 0x10410;
    const RVA_BOOTSTRAP_DERIVE: usize = 0x15630;
    const RVA_ARCHIVE_DERIVE: usize = 0x157D0;

    type ManagerCtorFn = unsafe extern "thiscall" fn(*mut u8) -> *mut u8;
    type BootstrapDeriveFn =
        unsafe extern "thiscall" fn(*mut u8, *const u8, usize, *const u8, usize) -> u8;
    type ArchiveDeriveFn = unsafe extern "thiscall" fn(*mut u8, *const u8, usize, *const u8) -> i32;
    type HashKeyDeriveFn = unsafe extern "C" fn(*mut u8, usize, *const u8, usize, i32);

    struct LoadedLibrary(*mut core::ffi::c_void);

    impl LoadedLibrary {
        fn load(path: &Path) -> Result<Self> {
            let wide: Vec<u16> = OsStr::new(path)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let handle = unsafe { LoadLibraryW(wide.as_ptr()) };
            if handle.is_null() {
                let err = unsafe { GetLastError() };
                bail!(
                    "LoadLibraryW failed for {} (Win32 error {err})",
                    path.display()
                );
            }
            Ok(Self(handle))
        }

        fn base(&self) -> usize {
            self.0 as usize
        }
    }

    impl Drop for LoadedLibrary {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    FreeLibrary(self.0);
                }
            }
        }
    }

    unsafe fn read_u32_ptr(ptr: *const u8) -> u32 {
        unsafe { core::ptr::read_unaligned(ptr as *const u32) }
    }

    unsafe fn read_u16_ptr(ptr: *const u8) -> u16 {
        unsafe { core::ptr::read_unaligned(ptr as *const u16) }
    }

    unsafe fn read_u64_ptr(ptr: *const u8) -> u64 {
        unsafe { core::ptr::read_unaligned(ptr as *const u64) }
    }

    unsafe fn read_bytes_ptr(ptr: *const u8, len: usize) -> Vec<u8> {
        unsafe { core::slice::from_raw_parts(ptr, len).to_vec() }
    }

    fn resolve_archive_seed(base: usize, override_seed: Option<&[u8]>) -> Result<[u8; 8]> {
        if let Some(ov) = override_seed {
            if ov.len() < 8 {
                bail!("--archive-seed-hex must be at least 8 bytes");
            }
            let mut s = [0u8; 8];
            s.copy_from_slice(&ov[..8]);
            return Ok(s);
        }

        let static_seed = unsafe { read_bytes_ptr((base + RVA_ARCHIVE_SEED) as *const u8, 8) };
        if static_seed.iter().any(|&b| b != 0) {
            return Ok(static_seed.try_into().unwrap());
        }

        // Scan FilterManager_ArchiveUpdate body for default 64-bit seed stored via:
        //   C7 45 <disp>   <lo32>
        //   C7 45 <disp+4> <hi32>
        let code = unsafe { read_bytes_ptr((base + RVA_ARCHIVE_DERIVE) as *const u8, 0x80) };
        for i in 0..=code.len().saturating_sub(14) {
            if code[i] == 0xC7
                && code[i + 1] == 0x45
                && code[i + 7] == 0xC7
                && code[i + 8] == 0x45
                && code[i + 2].wrapping_add(4) == code[i + 9]
            {
                let mut seed = [0u8; 8];
                seed[0..4].copy_from_slice(&code[i + 3..i + 7]);
                seed[4..8].copy_from_slice(&code[i + 10..i + 14]);
                return Ok(seed);
            }
        }

        bail!(
            "archive seed at RVA 0x{RVA_ARCHIVE_SEED:x} is zero and default seed constants were not found in ArchiveDerive"
        )
    }

    pub fn derive_from_bootstrap_dll(
        dll_path: &Path,
        artifacts: &StaticRecoveryArtifacts,
        archive_seed_override: Option<&[u8]>,
    ) -> Result<DerivedFilterState> {
        let abs_dll = std::fs::canonicalize(dll_path)
            .with_context(|| format!("failed to canonicalize {}", dll_path.display()))?;
        let lib = LoadedLibrary::load(&abs_dll)?;
        let base = lib.base();

        let params_bytes = artifacts
            .config_table
            .get("PARAMS")
            .ok_or_else(|| anyhow::anyhow!("bootstrap DLL config table missing PARAMS"))?;
        let bootstrap_bytes = encode_utf16le(&artifacts.final_bootstrap);
        let archive_bytes = encode_utf16le(&artifacts.archive_unique_key);
        let seed = resolve_archive_seed(base, archive_seed_override)?;

        // 16-byte aligned zero-initialized FilterManager storage (0x30B0 bytes)
        let mut aligned_buf = vec![0u128; MANAGER_SIZE.div_ceil(16)];
        let manager = aligned_buf.as_mut_ptr() as *mut u8;

        let ctor: ManagerCtorFn = unsafe { core::mem::transmute(base + RVA_MANAGER_CTOR) };
        let bootstrap_derive: BootstrapDeriveFn =
            unsafe { core::mem::transmute(base + RVA_BOOTSTRAP_DERIVE) };
        let archive_derive: ArchiveDeriveFn =
            unsafe { core::mem::transmute(base + RVA_ARCHIVE_DERIVE) };
        let hash_key_derive: HashKeyDeriveFn =
            unsafe { core::mem::transmute(base + RVA_HASH_KEY_DERIVE) };

        let manager_core = unsafe { manager.add(DRIP_HOLDER_OFFSET) };

        // Step 1: FilterManager constructor
        unsafe {
            ctor(manager);
        }

        // Step 2: Bootstrap KDF + DripValue VM initialization
        let ok = unsafe {
            bootstrap_derive(
                manager_core,
                bootstrap_bytes.as_ptr(),
                bootstrap_bytes.len(),
                params_bytes.as_ptr(),
                params_bytes.len(),
            )
        };
        if ok == 0 {
            bail!(
                "bootstrap.dll BootstrapDerive (RVA 0x{RVA_BOOTSTRAP_DERIVE:x}) failed; \
                 check bootstrap prefix and PARAMS"
            );
        }

        // Step 3: Derive 32-byte hash_key octet
        let mut hash_key = [0u8; 32];
        let ready_flags = unsafe { read_u32_ptr(manager.add(0x30A0)) };
        if (ready_flags & 3) == 3 {
            unsafe {
                hash_key_derive(
                    hash_key.as_mut_ptr(),
                    hash_key.len(),
                    manager.add(0x3040),
                    0x40,
                    -1,
                );
            }
        }

        // Step 4: Archive key update (UNIQUE + archive seed -> hxv4_nonce0 + holder_words[0..1])
        unsafe {
            archive_derive(
                manager_core,
                archive_bytes.as_ptr(),
                archive_bytes.len(),
                seed.as_ptr(),
            );
        }

        // Step 5: Read derived FilterManager state
        let drip_impl = unsafe { read_u32_ptr(manager_core) };
        if drip_impl == 0 {
            bail!("DripValueImpl pointer is null after bootstrap derivation");
        }

        let hxv4_key: [u8; 32] = unsafe { read_bytes_ptr(manager_core.add(0x3038), 32) }
            .try_into()
            .unwrap();
        let hxv4_nonce0: [u8; 24] = unsafe { read_bytes_ptr(manager_core.add(0x3078), 24) }
            .try_into()
            .unwrap();
        let hxv4_nonce1: [u8; 24] = unsafe { read_bytes_ptr(manager_core.add(0x3058), 24) }
            .try_into()
            .unwrap();

        let mut holder_words = Vec::with_capacity(6);
        for i in 0..6 {
            holder_words.push(unsafe { read_u32_ptr(manager_core.add(i * 4)) });
        }

        let context_ptr = unsafe { manager.add(CONTEXT_OFFSET) };
        let context_dwords = (MANAGER_SIZE - CONTEXT_OFFSET) / 4;
        let mut context_u32 = Vec::with_capacity(context_dwords);
        for i in 0..context_dwords {
            context_u32.push(unsafe { read_u32_ptr(context_ptr.add(i * 4)) });
        }

        let mut lanes = Vec::with_capacity(LANE_COUNT);
        let module_base_u32 = base as u32;
        for lane_idx in 0..LANE_COUNT {
            let lane_ptr = (drip_impl as usize + DRIP_LANE_BASE_OFFSET + lane_idx * LANE_SIZE)
                as *const u8;
            let begin = unsafe { read_u32_ptr(lane_ptr) };
            let end = unsafe { read_u32_ptr(lane_ptr.add(4)) };
            let current = unsafe { read_u32_ptr(lane_ptr.add(8)) };
            let ctx = unsafe { read_u32_ptr(lane_ptr.add(12)) };

            if end < begin || (end - begin) % 8 != 0 {
                bail!("lane {lane_idx} has invalid record range 0x{begin:08x}..0x{end:08x}");
            }

            let count = ((end - begin) / 8) as usize;
            let mut records = Vec::with_capacity(count);
            for r in 0..count {
                let rec_ptr = (begin as usize + r * 8) as *const u8;
                let param = unsafe { read_u32_ptr(rec_ptr) };
                let cb = unsafe { read_u32_ptr(rec_ptr.add(4)) };
                let cb_rva =
                    if cb >= module_base_u32 && cb < module_base_u32.wrapping_add(0x20_0000) {
                        cb - module_base_u32
                    } else {
                        cb
                    };
                records.push([param, cb_rva]);
            }

            lanes.push(DripLaneJson {
                index: lane_idx,
                begin_va: begin,
                end_va: end,
                current_va: current,
                ctx_va: ctx,
                records,
            });
        }

        // HxCryptTool / KrkrDumpX compatible key dump fields
        let filter_key = unsafe { read_u64_ptr(manager_core.add(0x08)) };
        let split_pos_mask = unsafe { read_u16_ptr(manager_core.add(0x10)) };
        let split_pos = unsafe { read_u16_ptr(manager_core.add(0x14)) };
        let random_type = unsafe { *manager_core.add(0x18) };
        let cxdec_table = unsafe { read_bytes_ptr(manager_core.add(0x20), 0x1000) };
        let cxdec_order: [u8; 17] = unsafe { read_bytes_ptr(manager_core.add(0x3020), 17) }
            .try_into()
            .unwrap();

        let source_module = abs_dll
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("bootstrap.dll")
            .to_string();

        let payload = DripProgramJson {
            version: 1,
            source_module,
            source_module_base: module_base_u32,
            manager_va: manager as u32,
            drip_impl_va: drip_impl,
            hxv4_key: hex::encode(hxv4_key),
            hxv4_nonce0: hex::encode(hxv4_nonce0),
            hxv4_nonce1: hex::encode(hxv4_nonce1),
            hash_key: Some(hex::encode(hash_key)),
            media_name: Some(artifacts.media_name.clone()),
            holder_words,
            context_va: context_ptr as u32,
            context_u32,
            callback_rva_base: module_base_u32,
            lanes,
        };

        let program = DripProgram::from_json(payload)?;
        let key_dump = HxCryptKeyDump {
            hxv4_key,
            hxv4_nonce0,
            hxv4_nonce1,
            hash_key,
            archive_seed: seed,
            filter_key,
            split_pos_mask,
            split_pos,
            random_type,
            cxdec_table,
            cxdec_order,
        };

        // `lib` is dropped cleanly after all memory has been copied out.
        Ok(DerivedFilterState { program, key_dump })
    }
}

#[cfg(all(windows, target_arch = "x86"))]
pub fn derive_from_bootstrap_dll(
    dll_path: &Path,
    artifacts: &StaticRecoveryArtifacts,
    archive_seed_override: Option<&[u8]>,
) -> Result<DerivedFilterState> {
    match pure_rust::derive_pure_rust(artifacts, archive_seed_override) {
        Ok(state) => Ok(state),
        Err(_) => native_x86::derive_from_bootstrap_dll(dll_path, artifacts, archive_seed_override),
    }
}

#[cfg(not(all(windows, target_arch = "x86")))]
pub fn derive_from_bootstrap_dll(
    _dll_path: &Path,
    artifacts: &StaticRecoveryArtifacts,
    archive_seed_override: Option<&[u8]>,
) -> Result<DerivedFilterState> {
    pure_rust::derive_pure_rust(artifacts, archive_seed_override)
}

/// Pure-Rust static FilterManager and DripValue derivation (no DLL execution).
pub mod pure_rust {
    use super::*;
    use crate::bres::encode_utf16le;
    use crate::drip::{
        DRIP_OP_ADD_IMM, DRIP_OP_ADD_SCRATCH, DRIP_OP_BIT_SHUFFLE, DRIP_OP_DEC, DRIP_OP_INC,
        DRIP_OP_MUL_SCRATCH, DRIP_OP_NEG, DRIP_OP_NOT, DRIP_OP_RECURSE,
        DRIP_OP_SCRATCH_MINUS_RESULT, DRIP_OP_SET_IMM, DRIP_OP_SET_SEED, DRIP_OP_SHL_SCRATCH,
        DRIP_OP_SHR_SCRATCH, DRIP_OP_STOP, DRIP_OP_STORE_SCRATCH, DRIP_OP_SUB_IMM,
        DRIP_OP_SUB_SCRATCH, DRIP_OP_TABLE_IMM, DRIP_OP_TABLE_MASKED, DRIP_OP_XOR_IMM,
    };
    use crate::pe::PeImage;
    use anyhow::bail;
    use argon2::{Algorithm, Argon2, Params, Version};
    use blake2::Blake2sVar;
    use blake2::digest::{Update, VariableOutput};
    use std::path::PathBuf;

    const CONTROL_BYTES: usize = 0x1000;
    const DRIP_TABLE_BYTES: usize = 0x2000;
    const LANE_COUNT: usize = 128;
    const PROGRAM_LENGTH_LIMIT: usize = 0x80;
    const RVA_ARCHIVE_SEED: u32 = 0x81758;
    const RVA_ARCHIVE_DERIVE: u32 = 0x157D0;

    const HX_SPLITMIX_INCREMENT: u64 = 0x9e37_79b9_7f4a_7c15;
    const HX_SPLITMIX_MUL1: u64 = 0xbf58_476d_1ce4_e5b9;
    const HX_SPLITMIX_MUL2: u64 = 0x94d0_49bb_1331_11eb;

    const XOPT_ARCHIVE_UNIQUE_KEY_MARKER: &[u8] = &[
        0x2d, 0x00, 0x2d, 0x00, 0x78, 0x00, 0x6f, 0x00, 0x70, 0x00, 0x74, 0x00, 0x2d, 0x00, 0x2d,
        0x00, 0x6e, 0x00, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    struct BootstrapParams {
        raw_order: [u8; 17],
        flags: u8,
        split_pos_mask: u16,
        split_pos: u16,
        prolog_order: [u8; 3],
        odd_branch_order: [u8; 6],
        even_branch_order: [u8; 8],
        random_type: u8,
    }

    fn decode_order<const N: usize>(raw: &[u8], op_by_raw: [u8; N]) -> Result<[u8; N]> {
        if raw.len() != N {
            bail!("invalid PARAMS permutation length: {}", raw.len());
        }
        let mut out = [u8::MAX; N];
        for (raw_idx, &slot) in raw.iter().enumerate() {
            let idx = slot as usize;
            if idx >= N {
                bail!("PARAMS permutation index out of range: {slot}");
            }
            if out[idx] != u8::MAX {
                bail!("duplicate PARAMS permutation value: {slot}");
            }
            out[idx] = op_by_raw[raw_idx];
        }
        Ok(out)
    }

    fn parse_params(data: &[u8]) -> Result<BootstrapParams> {
        if data.len() < 0x16 {
            bail!("bootstrap PARAMS payload too short ({} bytes)", data.len());
        }
        let mut raw_order = [0u8; 17];
        raw_order.copy_from_slice(&data[..17]);
        let flags = data[0x11];
        let split_pos_mask = u16::from_le_bytes([data[0x12], data[0x13]]);
        let split_pos = u16::from_le_bytes([data[0x14], data[0x15]]);
        Ok(BootstrapParams {
            raw_order,
            flags,
            split_pos_mask,
            split_pos,
            prolog_order: decode_order(&data[14..17], [0, 1, 2])?,
            odd_branch_order: decode_order(&data[8..14], [2, 5, 3, 4, 1, 0])?,
            even_branch_order: decode_order(&data[0..8], [0, 2, 3, 1, 5, 6, 7, 4])?,
            random_type: (flags >> 7) & 1,
        })
    }

    struct CxSponge {
        rate: usize,
        pos: usize,
        state: [u64; 25],
        domain: u8,
    }

    impl CxSponge {
        fn new(rate: usize, domain: u8) -> Self {
            Self {
                rate,
                pos: 0,
                state: [0u64; 25],
                domain,
            }
        }

        fn xor_bytes(&mut self, offset: usize, bytes: &[u8]) {
            for (i, &b) in bytes.iter().enumerate() {
                let p = offset + i;
                self.state[p / 8] ^= (b as u64) << (8 * (p % 8));
            }
        }

        fn read_bytes(&self, out: &mut [u8]) {
            for (i, b) in out.iter_mut().enumerate() {
                *b = (self.state[i / 8] >> (8 * (i % 8))) as u8;
            }
        }

        fn absorb(mut self, input: &[u8]) -> Self {
            let mut off = 0usize;
            while off < input.len() {
                let take = (self.rate - self.pos).min(input.len() - off);
                self.xor_bytes(self.pos, &input[off..off + take]);
                self.pos += take;
                off += take;
                if self.pos == self.rate {
                    keccak::f1600(&mut self.state);
                    self.pos = 0;
                }
            }
            self
        }

        fn squeeze(mut self, output: &mut [u8]) {
            self.xor_bytes(self.pos, &[self.domain]);
            let last = self.rate - 1;
            self.state[last / 8] ^= 0x80u64 << (8 * (last % 8));
            keccak::f1600(&mut self.state);

            let mut off = 0usize;
            while off < output.len() {
                let take = self.rate.min(output.len() - off);
                self.read_bytes(&mut output[off..off + take]);
                off += take;
                if off < output.len() {
                    keccak::f1600(&mut self.state);
                }
            }
        }
    }

    fn derive_key_block(input: &[u8], size: usize, seed: u32) -> Result<Vec<u8>> {
        if size == 0 || size % 4 != 0 {
            bail!("invalid key block size: {size}");
        }
        let mut words = vec![0u32; size / 4];
        let mut state = 0x0100_0193u32.wrapping_mul(seed ^ 0x811c_9dc5);
        for (idx, &byte) in input.iter().enumerate() {
            let mut v = (byte as u32) ^ state;
            v ^= v >> 17;
            v = v.wrapping_mul(0xed5a_d4bb);
            v ^= v >> 11;
            v = v.wrapping_mul(0xac4c_1b51);
            v ^= v >> 15;
            v = v.wrapping_mul(0x3184_8bab);
            state = v ^ (v >> 14);
            let w = idx % words.len();
            words[w] ^= state;
        }
        let mut prehash = Vec::with_capacity(size);
        for w in words {
            prehash.extend_from_slice(&w.to_le_bytes());
        }
        let digest_len = size.min(32);
        let mut hasher = Blake2sVar::new(digest_len)
            .map_err(|e| anyhow::anyhow!("Blake2sVar init failed: {e}"))?;
        hasher.update(input);
        hasher.update(&prehash);
        let mut out = vec![0u8; digest_len];
        hasher
            .finalize_variable(&mut out)
            .map_err(|e| anyhow::anyhow!("Blake2sVar finalize failed: {e}"))?;
        out.resize(size, 0);
        Ok(out)
    }

    fn xor_in_place(dst: &mut [u8], rhs: &[u8]) {
        for (d, r) in dst.iter_mut().zip(rhs.iter()) {
            *d ^= *r;
        }
    }

    fn has_archive_kdf_use(window: &[u8]) -> bool {
        let Some(push_seed) = window.windows(2).position(|b| b == [0xff, 0x36]) else {
            return false;
        };
        let tail = &window[push_seed + 2..];
        tail.windows(2).any(|b| b == [0x6a, 0x08]) && tail.contains(&0x56) && tail.contains(&0xe8)
    }

    fn resolve_archive_seed_static(
        dll_bytes: &[u8],
        override_seed: Option<&[u8]>,
    ) -> Result<[u8; 8]> {
        if let Some(ov) = override_seed {
            if ov.len() < 8 {
                bail!("--archive-seed-hex must be at least 8 bytes");
            }
            let mut s = [0u8; 8];
            s.copy_from_slice(&ov[..8]);
            return Ok(s);
        }

        // 1. Check `--xopt--no` UTF-16LE marker in .rdata
        if let Some(pos) = dll_bytes
            .windows(XOPT_ARCHIVE_UNIQUE_KEY_MARKER.len())
            .position(|w| w == XOPT_ARCHIVE_UNIQUE_KEY_MARKER)
        {
            let key_off = pos + XOPT_ARCHIVE_UNIQUE_KEY_MARKER.len();
            if key_off + 8 <= dll_bytes.len() {
                let mut seed = [0u8; 8];
                seed.copy_from_slice(&dll_bytes[key_off..key_off + 8]);
                if seed.iter().any(|&b| b != 0) {
                    return Ok(seed);
                }
            }
        }

        // 2. Check known static seed RVA 0x81758 in bootstrap.dll
        let pe = PeImage::from_bytes(PathBuf::from("bootstrap.dll"), dll_bytes.to_vec()).ok();
        if let Some(ref img) = pe {
            if let Ok(off) = img.rva_to_offset(RVA_ARCHIVE_SEED) {
                if off + 8 <= dll_bytes.len() {
                    let mut seed = [0u8; 8];
                    seed.copy_from_slice(&dll_bytes[off..off + 8]);
                    if seed.iter().any(|&b| b != 0) {
                        return Ok(seed);
                    }
                }
            }
        }

        // 3. Scan for stack-immediate 64-bit seed followed by `cmovne esi, eax` + KDF call
        let mut matches = Vec::new();
        let mut pos = 0usize;
        while pos + 0x50 <= dll_bytes.len() {
            if dll_bytes[pos] == 0xC7
                && dll_bytes[pos + 1] == 0x45
                && dll_bytes[pos + 7] == 0xC7
                && dll_bytes[pos + 8] == 0x45
                && dll_bytes[pos + 2].wrapping_add(4) == dll_bytes[pos + 9]
                && dll_bytes[pos + 14..pos + 17] == [0x0F, 0x45, 0xF0]
                && has_archive_kdf_use(&dll_bytes[pos + 17..pos + 0x50])
            {
                let mut seed = [0u8; 8];
                seed[..4].copy_from_slice(&dll_bytes[pos + 3..pos + 7]);
                seed[4..].copy_from_slice(&dll_bytes[pos + 10..pos + 14]);
                matches.push(seed);
            }
            pos += 1;
        }
        matches.sort_unstable();
        matches.dedup();
        if matches.len() == 1 {
            return Ok(matches[0]);
        }

        // 4. Fallback: scan ArchiveDerive (RVA 0x157D0) body for pair of `mov dword ptr [ebp+disp], imm32`
        if let Some(ref img) = pe {
            if let Ok(off) = img.rva_to_offset(RVA_ARCHIVE_DERIVE) {
                let end = (off + 0x80).min(dll_bytes.len());
                let code = &dll_bytes[off..end];
                for i in 0..=code.len().saturating_sub(14) {
                    if code[i] == 0xC7
                        && code[i + 1] == 0x45
                        && code[i + 7] == 0xC7
                        && code[i + 8] == 0x45
                        && code[i + 2].wrapping_add(4) == code[i + 9]
                    {
                        let mut seed = [0u8; 8];
                        seed[0..4].copy_from_slice(&code[i + 3..i + 7]);
                        seed[4..8].copy_from_slice(&code[i + 10..i + 14]);
                        return Ok(seed);
                    }
                }
            }
        }

        bail!("could not locate 8-byte archive seed in bootstrap.dll")
    }

    struct HxSplittableRandom {
        seed: u64,
    }

    impl HxSplittableRandom {
        fn new(seed: u64) -> Self {
            Self { seed }
        }

        fn next(&mut self) -> u64 {
            self.seed = self.seed.wrapping_add(HX_SPLITMIX_INCREMENT);
            let mut z = self.seed;
            z ^= z >> 30;
            z = z.wrapping_mul(HX_SPLITMIX_MUL1);
            z ^= z >> 27;
            z = z.wrapping_mul(HX_SPLITMIX_MUL2);
            z ^ (z >> 31)
        }
    }

    #[inline]
    fn lo32(v: u64) -> u32 {
        v as u32
    }

    #[inline]
    fn hi32(v: u64) -> u32 {
        (v >> 32) as u32
    }

    #[inline]
    fn pack_u64(lo: u32, hi: u32) -> u64 {
        (lo as u64) | ((hi as u64) << 32)
    }

    fn hx_old_random(seed: &mut [u64; 2]) -> u64 {
        let a = seed[0];
        let b = seed[1];
        let c = pack_u64(hi32(a) ^ hi32(b), lo32(a) ^ lo32(b));
        let e = pack_u64(hi32(c), lo32(c));

        let mut t = (hi32(c) as u64) << 21;
        t ^= a >> 15;
        t ^= hi32(c) as u64;
        let seed0_lo = t as u32;

        t = (hi32(a) >> 15) as u64;
        t |= (lo32(a) as u64) << 17;
        t ^= e >> 11;
        t ^= lo32(c) as u64;
        let seed0_hi = t as u32;

        let seed1_hi = (e >> 4) as u32;
        let seed1_lo = (c >> 4) as u32;

        seed[0] = pack_u64(seed0_lo, seed0_hi);
        seed[1] = pack_u64(seed1_lo, seed1_hi);

        let d = a.wrapping_add(b);
        t = d << 17;
        t |= (hi32(d) >> 15) as u64;
        t.wrapping_add(a)
    }

    fn hx_new_random(seed: &mut [u64; 2]) -> u64 {
        let a = seed[0];
        let b = seed[1];
        let c = pack_u64(lo32(a) ^ lo32(b), hi32(a) ^ hi32(b));

        let mut t = (lo32(a) as u64) << 24;
        t |= (hi32(a) >> 8) as u64;
        t ^= (lo32(c) as u64) << 16;
        t ^= lo32(c) as u64;
        let seed0_lo = t as u32;

        t = c >> 16;
        t ^= a >> 8;
        t ^= hi32(c) as u64;
        let seed0_hi = t as u32;

        t = (hi32(c) >> 27) as u64;
        t |= (lo32(c) as u64) << 5;
        let seed1_hi = t as u32;
        let seed1_lo = (c >> 27) as u32;

        seed[0] = pack_u64(seed0_lo, seed0_hi);
        seed[1] = pack_u64(seed1_lo, seed1_hi);

        let d = 5u64.wrapping_mul(a);
        t = (hi32(d) >> 25) as u64;
        t |= d << 7;
        t.wrapping_mul(9)
    }

    struct DripLaneBuilder<'a> {
        params: &'a BootstrapParams,
        rng_state: [u64; 2],
        length: usize,
        records: Vec<[u32; 2]>,
    }

    impl<'a> DripLaneBuilder<'a> {
        fn new(seed: u32, params: &'a BootstrapParams) -> Self {
            let split_seed = (seed as u64) | ((!seed as u64) << 32);
            let mut sm = HxSplittableRandom::new(split_seed);
            let rng_state = [sm.next(), sm.next()];
            Self {
                params,
                rng_state,
                length: 0,
                records: Vec::with_capacity(64),
            }
        }

        fn next_u32(&mut self) -> u32 {
            if self.params.random_type == 0 {
                hx_old_random(&mut self.rng_state) as u32
            } else {
                hx_new_random(&mut self.rng_state) as u32
            }
        }

        fn reserve(&mut self, bytes: usize) -> bool {
            if self.length + bytes > PROGRAM_LENGTH_LIMIT {
                return false;
            }
            self.length += bytes;
            true
        }

        fn emit_op(&mut self, param: u32, op: u32, bytes: usize) -> bool {
            if !self.reserve(bytes) {
                return false;
            }
            self.records.push([param, op]);
            true
        }

        fn emit_code(&mut self, stage: i32) -> bool {
            self.reserve(5)
                && self.reserve(4)
                && self.emit_body(stage)
                && self.reserve(5)
                && self.emit_op(0, DRIP_OP_STOP, 1)
        }

        fn emit_body(&mut self, stage: i32) -> bool {
            if stage == 1 {
                return self.emit_prolog();
            }
            if !self.emit_op(0, DRIP_OP_RECURSE, 1) {
                return false;
            }
            if (self.next_u32() & 1) != 0 {
                if !self.emit_body(stage - 1) {
                    return false;
                }
            } else if !self.emit_body2(stage - 1) {
                return false;
            }
            if !self.emit_op(0, DRIP_OP_STORE_SCRATCH, 2) {
                return false;
            }
            if (self.next_u32() & 1) != 0 {
                if !self.emit_body(stage - 1) {
                    return false;
                }
            } else if !self.emit_body2(stage - 1) {
                return false;
            }
            self.emit_odd_branch() && self.emit_op(0, DRIP_OP_STOP, 1)
        }

        fn emit_body2(&mut self, stage: i32) -> bool {
            if stage == 1 {
                return self.emit_prolog();
            }
            let ok = if (self.next_u32() & 1) != 0 {
                self.emit_body(stage - 1)
            } else {
                self.emit_body2(stage - 1)
            };
            ok && self.emit_even_branch()
        }

        fn emit_prolog(&mut self) -> bool {
            let idx = (self.next_u32() % 3) as usize;
            match self.params.prolog_order[idx] {
                2 => {
                    if !self.reserve(5) || !self.reserve(2) {
                        return false;
                    }
                    let table_idx = self.next_u32() & 0x3ff;
                    self.emit_op(table_idx, DRIP_OP_TABLE_IMM, 4)
                }
                1 => self.emit_op(0, DRIP_OP_SET_SEED, 2),
                0 => {
                    if !self.reserve(1) {
                        return false;
                    }
                    let val = self.next_u32();
                    self.emit_op(val, DRIP_OP_SET_IMM, 4)
                }
                _ => false,
            }
        }

        fn emit_even_branch(&mut self) -> bool {
            let idx = (self.next_u32() & 7) as usize;
            match self.params.even_branch_order[idx] {
                0 => self.emit_op(0, DRIP_OP_NOT, 2),
                1 => self.emit_op(0, DRIP_OP_DEC, 1),
                2 => self.emit_op(0, DRIP_OP_NEG, 2),
                3 => self.emit_op(0, DRIP_OP_INC, 1),
                4 => self.emit_op(0x3ff, DRIP_OP_TABLE_MASKED, 13),
                5 => self.emit_op(0xaaaa_aaaa, DRIP_OP_BIT_SHUFFLE, 21),
                6 => {
                    if !self.reserve(1) {
                        return false;
                    }
                    let val = self.next_u32();
                    self.emit_op(val, DRIP_OP_XOR_IMM, 4)
                }
                7 => {
                    let is_add = (self.next_u32() & 1) != 0;
                    if !self.reserve(1) {
                        return false;
                    }
                    let val = self.next_u32();
                    let op = if is_add {
                        DRIP_OP_ADD_IMM
                    } else {
                        DRIP_OP_SUB_IMM
                    };
                    self.emit_op(val, op, 4)
                }
                _ => false,
            }
        }

        fn emit_odd_branch(&mut self) -> bool {
            let idx = (self.next_u32() % 6) as usize;
            match self.params.odd_branch_order[idx] {
                0 => self.emit_op(0, DRIP_OP_SHR_SCRATCH, 9),
                1 => self.emit_op(0, DRIP_OP_SHL_SCRATCH, 9),
                2 => self.emit_op(0, DRIP_OP_ADD_SCRATCH, 2),
                3 => self.emit_op(0, DRIP_OP_SCRATCH_MINUS_RESULT, 4),
                4 => self.emit_op(0, DRIP_OP_MUL_SCRATCH, 3),
                5 => self.emit_op(0, DRIP_OP_SUB_SCRATCH, 2),
                _ => false,
            }
        }

        fn build(mut self) -> Result<Vec<[u32; 2]>> {
            for stage in (1..=5).rev() {
                if self.emit_code(stage) {
                    return Ok(self.records);
                }
                self.length = 0;
                self.records.clear();
            }
            bail!("failed to build Drip lane within 128-byte limit")
        }
    }

    pub fn derive_pure_rust(
        artifacts: &StaticRecoveryArtifacts,
        archive_seed_override: Option<&[u8]>,
    ) -> Result<DerivedFilterState> {
        let params_bytes = artifacts
            .config_table
            .get("PARAMS")
            .ok_or_else(|| anyhow::anyhow!("bootstrap DLL config table missing PARAMS"))?;
        let params = parse_params(params_bytes)?;
        let seed = resolve_archive_seed_static(&artifacts.dll_bytes, archive_seed_override)?;

        let password = encode_utf16le(&artifacts.final_bootstrap);
        let mut salt = [0u8; 16];
        CxSponge::new(0x90, 0x06)
            .absorb(params_bytes)
            .squeeze(&mut salt);

        let argon_params = Params::new(8, 3, 1, Some(64))
            .map_err(|e| anyhow::anyhow!("invalid Argon2 params: {e:?}"))?;
        let argon = Argon2::new(Algorithm::Argon2i, Version::V0x13, argon_params);
        let mut material = [0u8; 64];
        argon
            .hash_password_into(&password, &salt, &mut material)
            .map_err(|e| anyhow::anyhow!("Argon2i derivation failed: {e:?}"))?;

        let mut drip_table = [0u8; DRIP_TABLE_BYTES];
        CxSponge::new(0x88, 0x1f)
            .absorb(&material)
            .squeeze(&mut drip_table);
        let secret = &material[..32];

        let mut cxdec_table = drip_table[..CONTROL_BYTES].to_vec();
        if (params.flags & 1) != 0 {
            xor_in_place(&mut cxdec_table, &drip_table[CONTROL_BYTES..DRIP_TABLE_BYTES]);
        }

        let context_u32: Vec<u32> = cxdec_table
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();

        let mut bootstrap_key = derive_key_block(&password, 32, 0)?;
        xor_in_place(&mut bootstrap_key, secret);

        let mut params_key = derive_key_block(params_bytes, 32, 1)?;
        xor_in_place(&mut params_key, secret);

        let archive_bytes = encode_utf16le(&artifacts.archive_unique_key);
        let mut unique_block = derive_key_block(&archive_bytes, 32, 2)?;
        let seed_u32 = u32::from_le_bytes([seed[0], seed[1], seed[2], seed[3]]);
        let seed_mod = derive_key_block(&seed, 32, seed_u32)?;
        xor_in_place(&mut unique_block, &seed_mod);

        let mut state_key = [0u8; 64];
        state_key[..32].copy_from_slice(&bootstrap_key);
        state_key[32..].copy_from_slice(&params_key);
        let hash_key_vec = derive_key_block(&state_key, 32, u32::MAX)?;

        let hxv4_key: [u8; 32] = bootstrap_key.try_into().unwrap();
        let hxv4_nonce0: [u8; 24] = unique_block[..24].try_into().unwrap();
        let hxv4_nonce1: [u8; 24] = params_key[..24].try_into().unwrap();
        let hash_key: [u8; 32] = hash_key_vec.try_into().unwrap();
        let filter_key = u64::from_le_bytes(unique_block[..8].try_into().unwrap());

        let holder_words = vec![
            0u32,
            0u32,
            filter_key as u32,
            (filter_key >> 32) as u32,
            params.split_pos_mask as u32,
            params.split_pos as u32,
        ];

        let mut lanes = Vec::with_capacity(LANE_COUNT);
        for lane_idx in 0..LANE_COUNT {
            let records = DripLaneBuilder::new(lane_idx as u32, &params).build()?;
            lanes.push(DripLaneJson {
                index: lane_idx,
                begin_va: 0,
                end_va: 0,
                current_va: 0,
                ctx_va: 0,
                records,
            });
        }

        let payload = DripProgramJson {
            version: 1,
            source_module: "pure_rust".to_string(),
            source_module_base: 0,
            manager_va: 0,
            drip_impl_va: 0,
            hxv4_key: hex::encode(hxv4_key),
            hxv4_nonce0: hex::encode(hxv4_nonce0),
            hxv4_nonce1: hex::encode(hxv4_nonce1),
            hash_key: Some(hex::encode(hash_key)),
            media_name: Some(artifacts.media_name.clone()),
            holder_words,
            context_va: 0,
            context_u32,
            callback_rva_base: 0,
            lanes,
        };

        let program = DripProgram::from_json(payload)?;
        let key_dump = HxCryptKeyDump {
            hxv4_key,
            hxv4_nonce0,
            hxv4_nonce1,
            hash_key,
            archive_seed: seed,
            filter_key,
            split_pos_mask: params.split_pos_mask,
            split_pos: params.split_pos,
            random_type: params.random_type,
            cxdec_table,
            cxdec_order: params.raw_order,
        };

        Ok(DerivedFilterState { program, key_dump })
    }
}
