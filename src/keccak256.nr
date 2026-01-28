mod tests;
mod oracle_tests;
mod benchmarks;

use std::hash::keccakf1600;
use std::runtime::is_unconstrained;
use std::static_assert;

global BLOCK_SIZE_IN_BYTES: u32 = 136; //(1600 - BITS * 2) / WORD_SIZE;
global WORD_SIZE: u32 = 8; // Limbs are made up of u64s so 8 bytes each.
global LIMBS_PER_BLOCK: u32 = BLOCK_SIZE_IN_BYTES / WORD_SIZE;
global NUM_KECCAK_LANES: u32 = 25;

#[no_predicates]
pub fn keccak256<let N: u32>(input: [u8; N], message_size: u32) -> [u8; 32] {
    assert(N >= message_size);

    // Copy input to block bytes. For that we'll need at least input bytes (N)
    // but we want it to be padded to a multiple of BLOCK_SIZE_IN_BYTES.
    let mut block_bytes = [0; ((N / BLOCK_SIZE_IN_BYTES) + 1) * BLOCK_SIZE_IN_BYTES];
    if is_unconstrained() {
        for i in 0..message_size {
            block_bytes[i] = input[i];
        }
    } else {
        for i in 0..N {
            if i < message_size {
                block_bytes[i] = input[i];
            }
        }
    }

    //1. format_input_lanes and apply padding
    let real_max_blocks = (message_size + BLOCK_SIZE_IN_BYTES) / BLOCK_SIZE_IN_BYTES;

    // Apply Keccak padding (0x01 after message, 0x80 at block end)
    apply_keccak_padding(&mut block_bytes, message_size, real_max_blocks);

    let block_array = convert_to_u64_array(block_bytes);

    let state = apply_keccak_permutations(block_array, real_max_blocks);

    //3. sponge_squeeze
    read_hash_from_state(state)
}

fn convert_to_u64_array<let N: u32>(input: [u8; N]) -> [u64; N / WORD_SIZE] {
    static_assert(
        N % WORD_SIZE == 0,
        "Byte array is expected to cleanly divide into chunks",
    );
    // populate a vector of 64-bit limbs from our byte array
    let mut sliced_buffer = [0; N / WORD_SIZE];
    for i in 0..sliced_buffer.len() {
        let limb_start = WORD_SIZE * i;

        let mut sliced = 0;
        let mut v = 1;
        unroll_loop!(
            0u32,
            WORD_SIZE,
            |i: u32| {
                quote {
                    sliced += v * (input[limb_start + $i] as Field);
                    v *= 256;
                }
            },
        );

        sliced.assert_max_bit_size::<64>();
        sliced_buffer[i] = sliced as u64;
    }
    sliced_buffer
}

fn apply_keccak_permutations<let N: u32>(
    flattened_blocks_array: [u64; N],
    num_blocks: u32,
) -> [u64; NUM_KECCAK_LANES] {
    //2. sponge_absorb
    let mut state: [u64; NUM_KECCAK_LANES] = [0; NUM_KECCAK_LANES];
    // `num_blocks` is guaranteed to at least be `1`
    // We peel out the first block as to avoid a conditional inside of the loop.
    // Otherwise, a dynamic predicate can cause a blowup in a constrained runtime.
    unroll_loop!(
        0u32,
        LIMBS_PER_BLOCK,
        |i: u32| {
            quote {
            state[$i] = flattened_blocks_array[$i];
        }
        },
    );
    state = keccakf1600(state);

    let max_blocks = N / LIMBS_PER_BLOCK;
    if is_unconstrained() {
        // When in an unconstrained runtime we can take advantage of runtime loop bounds,
        // thus allowing us to simplify the loop body.
        for i in 1..num_blocks {
            for j in 0..LIMBS_PER_BLOCK {
                state[j] = state[j] ^ flattened_blocks_array[i * LIMBS_PER_BLOCK + j];
            }
            state = keccakf1600(state);
        }

        state
    } else {
        // We store the intermediate states in an array to avoid having a dynamic predicate
        // inside the loop, which can cause a blowup in a constrained runtime.
        let mut intermediate_states = [state; N / LIMBS_PER_BLOCK + 1];
        for i in 1..max_blocks {
            let mut previous_state = intermediate_states[i - 1];
            for j in 0..LIMBS_PER_BLOCK {
                previous_state[j] =
                    previous_state[j] ^ flattened_blocks_array[i * LIMBS_PER_BLOCK + j];
            }
            intermediate_states[i] = keccakf1600(previous_state);
        }

        // We can then take the state as of `num_blocks`, ignoring later permutations.
        intermediate_states[num_blocks - 1]
    }
}

// Apply Keccak padding to the block_bytes array
// Append 0x01 after message, then 0x80 at end of block
// If both padding bytes collide at the same byte, combine them as 0x81
#[inline_always]
pub(crate) fn apply_keccak_padding<let BLOCK_BYTES: u32>(
    block_bytes: &mut [u8; BLOCK_BYTES],
    message_size: u32,
    real_max_blocks: u32,
) {
    let real_blocks_bytes = real_max_blocks * BLOCK_SIZE_IN_BYTES;

    if message_size == real_blocks_bytes - 1 {
        // Combine both padding bits: 0x01 | 0x80 = 0x81
        block_bytes[message_size] = 0x81;
    } else {
        block_bytes[message_size] = 0x01;
        block_bytes[real_blocks_bytes - 1] = 0x80;
    }
}

fn read_hash_from_state(state: [u64; NUM_KECCAK_LANES]) -> [u8; 32] {
    let mut result = [0; 32];
    unroll_loop!(
        0u32,
        4u32,
        |i: u32| {
            quote {
            let lane = state[$i] as Field;
            let lane_le: [u8; 8] = lane.to_le_bytes();
            result[8 * $i] = lane_le[0];
            result[8 * $i + 1] = lane_le[1];
            result[8 * $i + 2] = lane_le[2];
            result[8 * $i + 3] = lane_le[3];
            result[8 * $i + 4] = lane_le[4];
            result[8 * $i + 5] = lane_le[5];
            result[8 * $i + 6] = lane_le[6];
            result[8 * $i + 7] = lane_le[7];
        }
        },
    );

    result
}

comptime fn unroll_loop(start: u32, end: u32, body: fn(u32) -> Quoted) -> Quoted {
    let mut iterations: [Quoted] = &[];
    for i in start..end {
        iterations = iterations.push_back(body(i));
    }
    iterations.join(quote {})
}
