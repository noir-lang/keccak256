use std::runtime::is_unconstrained;
use std::hash::keccak::keccakf1600;

/// Word size in bytes
global WORD_SIZE: u32 = 8;

/// Block size in bytes
global BLOCK_SIZE_IN_BYTES: u32 = (1600 - 256 * 2) / WORD_SIZE;

/// Lanes per block
global LIMBS_PER_BLOCK: u32 = BLOCK_SIZE_IN_BYTES / WORD_SIZE;

/// Keccak-f lanes
global NUM_KECCAK_LANES: u32 = 25;

#[no_predicates]
pub fn keccak256<let N: u32>(input: [u8; N], msg_len: u32) -> [u8; 32] {
    assert(N >= msg_len);

    let mut block_bytes = [0; (N / BLOCK_SIZE_IN_BYTES + 1) * BLOCK_SIZE_IN_BYTES];

    if is_unconstrained() {
        for i in 0..msg_len {
            block_bytes[i] = input[i];
        }
    } else {
        for i in 0..N {
            if i < msg_len {
                block_bytes[i] = input[i];
            }
        }
    }

    let max_blocks = (N + BLOCK_SIZE_IN_BYTES) / BLOCK_SIZE_IN_BYTES;

    let real_max_blocks = (msg_len + BLOCK_SIZE_IN_BYTES) / BLOCK_SIZE_IN_BYTES;

    block_bytes[msg_len] = 0x01;
    block_bytes[(real_max_blocks * BLOCK_SIZE_IN_BYTES) - 1] = 0x80;

    let mut sliced_buffer =
        [0; (((N / BLOCK_SIZE_IN_BYTES) + 1) * BLOCK_SIZE_IN_BYTES) / WORD_SIZE];

    for i in 0..sliced_buffer.len() {
        let limb_start = WORD_SIZE * i;
        let mut sliced = 0;
        let mut v = 1;

        for k in 0..WORD_SIZE {
            sliced += v * (block_bytes[limb_start + k] as Field);
            v *= 256;
        }

        sliced_buffer[i] = sliced as u64;
    }

    let mut state: [u64; NUM_KECCAK_LANES] = [0; NUM_KECCAK_LANES];

    if is_unconstrained() {
        for i in 0..real_max_blocks {
            if i == 0 {
                for j in 0..LIMBS_PER_BLOCK {
                    state[j] = sliced_buffer[j];
                }
            } else {
                for j in 0..LIMBS_PER_BLOCK {
                    state[j] ^= sliced_buffer[i * LIMBS_PER_BLOCK + j];
                }
            }

            state = keccakf1600(state);
        }
    } else {
        for i in 0..LIMBS_PER_BLOCK {
            state[i] = sliced_buffer[i];
        }

        state = keccakf1600(state);

        for i in 1..max_blocks {
            if i < real_max_blocks {
                for j in 0..LIMBS_PER_BLOCK {
                    state[j] ^= sliced_buffer[i * LIMBS_PER_BLOCK + j];
                }
            }
        }
    }

    let mut result = [0; 32];

    for i in 0..4 {
        let lane: [u8; 8] = (state[i] as Field).to_le_bytes();

        for j in 0..8 {
            result[i * 8 + j] = lane[j];
        }
    }

    result
}
