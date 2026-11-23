#[derive(Debug, Clone, Copy)]
pub struct FilterBoundary {
    pub pos0: u64,
    pub pos1: u64,
    pub key: u32,
    pub byte0: u8,
    pub byte1: u8,
}

#[derive(Debug, Clone)]
pub struct FilterRuntimeState {
    pub boundary0: FilterBoundary,
    pub boundary1: FilterBoundary,
    pub split_offset: u64,
    pub bulk_key: Option<[u8; 16]>,
}

impl FilterRuntimeState {
    pub fn from_seed_state(seed_state: &[u8; 48]) -> Self {
        let null_mode = seed_state[45] != 0;
        let v0 = u64::from_le_bytes(seed_state[0..8].try_into().unwrap());
        let v1 = u64::from_le_bytes(seed_state[8..16].try_into().unwrap());
        let split_offset = u64::from_le_bytes(seed_state[16..24].try_into().unwrap());
        let has_bulk = seed_state[44] != 0;
        let bulk_key = if has_bulk {
            let mut bk = [0u8; 16];
            bk.copy_from_slice(&seed_state[24..40]);
            Some(bk)
        } else {
            None
        };

        Self {
            boundary0: Self::init_boundary(v0, null_mode),
            boundary1: Self::init_boundary(v1, null_mode),
            split_offset,
            bulk_key,
        }
    }

    fn init_boundary(value: u64, null_mode: bool) -> FilterBoundary {
        let pos0 = (value >> 48) & 0xFFFF;
        let mut pos1 = (value >> 32) & 0xFFFF;
        if pos0 == pos1 {
            pos1 += 1;
        }

        let mut key_byte = (value & 0xFF) as u8;
        let mut byte0 = ((value >> 8) & 0xFF) as u8;
        let mut byte1 = ((value >> 16) & 0xFF) as u8;
        if key_byte == 0 {
            key_byte = if null_mode { 0 } else { 0xA5 };
        }
        let key = (key_byte as u32).wrapping_mul(0x0101_0101);
        if null_mode {
            byte0 = 0;
            byte1 = 0;
        }

        FilterBoundary {
            pos0,
            pos1,
            key,
            byte0,
            byte1,
        }
    }

    #[inline]
    fn xor_rotated_dword_key(data: &mut [u8], logical_start: u64, key: u32) {
        let key_bytes = key.to_le_bytes();
        let mut lane = (logical_start & 3) as usize;
        for b in data.iter_mut() {
            *b ^= key_bytes[lane];
            lane = (lane + 1) & 3;
        }
    }

    #[inline]
    fn xor_boundary_byte(data: &mut [u8], chunk_start: u64, position: u64, value: u8) {
        if value != 0 && position >= chunk_start {
            let rel = position - chunk_start;
            if rel < data.len() as u64 {
                data[rel as usize] ^= value;
            }
        }
    }

    fn apply_boundary(data: &mut [u8], boundary: &FilterBoundary, chunk_start: u64) {
        if data.is_empty() {
            return;
        }
        Self::xor_rotated_dword_key(data, chunk_start, boundary.key);
        Self::xor_boundary_byte(data, chunk_start, boundary.pos0, boundary.byte0);
        Self::xor_boundary_byte(data, chunk_start, boundary.pos1, boundary.byte1);
    }

    /// Apply the 4-layer XOR stream filter in place to `data` starting at logical `offset`.
    pub fn apply(&self, data: &mut [u8], offset: u64) -> bool {
        if data.is_empty() {
            return false;
        }
        let size = data.len() as u64;
        let end = offset + size;

        // Layer 1: Bulk XOR on logical offset [0, 16)
        if let Some(ref bk) = self.bulk_key {
            if offset < 16 {
                let overlap_end = end.min(16);
                for logical in offset..overlap_end {
                    data[(logical - offset) as usize] ^= bk[logical as usize];
                }
            }
        }

        // Layers 2-4: Split boundary + rotated dword XOR + boundary byte XOR
        let split = self.split_offset;
        if split <= offset {
            Self::apply_boundary(data, &self.boundary1, offset);
        } else if split < end {
            let first_size = (split - offset) as usize;
            Self::apply_boundary(&mut data[..first_size], &self.boundary0, offset);
            Self::apply_boundary(&mut data[first_size..], &self.boundary1, split);
        } else {
            Self::apply_boundary(data, &self.boundary0, offset);
        }
        true
    }
}
