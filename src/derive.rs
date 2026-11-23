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
    native_x86::derive_from_bootstrap_dll(dll_path, artifacts, archive_seed_override)
}

#[cfg(not(all(windows, target_arch = "x86")))]
pub fn derive_from_bootstrap_dll(
    _dll_path: &Path,
    _artifacts: &StaticRecoveryArtifacts,
    _archive_seed_override: Option<&[u8]>,
) -> Result<DerivedFilterState> {
    anyhow::bail!(
        "native bootstrap.dll derivation requires 32-bit Windows x86 build \
         (cargo build --target i686-pc-windows-msvc), or supply --drip-program <json>"
    )
}
