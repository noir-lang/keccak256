use super::{LIMBS_PER_BLOCK, NUM_KECCAK_LANES, read_hash_from_state};
use std::hash::keccakf1600;

/// Incremental Keccak-256 with the same padding and output as `keccak256`.
pub struct KeccakHasher {
    state: [u64; NUM_KECCAK_LANES],
    limb_index_to_write: u32,

    current_limb: u64,
    current_limb_shift: u64,
}

impl KeccakHasher {
    pub fn new() -> Self {
        Self {
            state: [0; NUM_KECCAK_LANES],
            limb_index_to_write: 0,
            current_limb: 0,
            current_limb_shift: 0,
        }
    }

    pub fn add_byte(&mut self, byte: u8) {
        self.current_limb += (byte as u64) << self.current_limb_shift;

        if self.current_limb_shift == 56 {
            self.finish_limb();
        } else {
            self.current_limb_shift += 8;
        }
    }

    /// Absorb the 8 bytes of `value` in little-endian order, at any byte alignment.
    pub fn add_u64(&mut self, value: u64) {
        if self.current_limb_shift == 0 {
            self.current_limb = value;
            self.finish_limb();
        } else {
            // Unaligned: the low bytes complete the current limb, the high bytes start the next.
            let shift = self.current_limb_shift;
            self.current_limb += value << shift;
            self.finish_limb();
            self.current_limb = value >> (64 - shift);
            self.current_limb_shift = shift;
        }
    }

    pub fn finish(self) -> [u8; 32] {
        read_hash_from_state(self.squeeze())
    }

    /// Return the digest as four little-endian u64 lanes, as `keccak256_limbs` does.
    pub fn finish_to_limbs(self) -> [u64; 4] {
        let state = self.squeeze();
        [state[0], state[1], state[2], state[3]]
    }

    #[inline_always]
    fn finish_limb(&mut self) {
        self.state[self.limb_index_to_write] ^= self.current_limb;
        self.current_limb = 0;
        self.current_limb_shift = 0;
        if self.limb_index_to_write == LIMBS_PER_BLOCK - 1 {
            self.state = keccakf1600(self.state);
            self.limb_index_to_write = 0;
        } else {
            self.limb_index_to_write += 1;
        }
    }

    // Apply the 0x01 .. 0x80 padding to the pending block and permute it.
    fn squeeze(mut self) -> [u64; NUM_KECCAK_LANES] {
        self.state[self.limb_index_to_write] ^=
            self.current_limb + (0x01 << self.current_limb_shift);
        self.state[LIMBS_PER_BLOCK - 1] ^= 0x80 << 56;
        keccakf1600(self.state)
    }
}
