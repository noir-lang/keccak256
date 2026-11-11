mod tests;
mod oracle_tests;
mod benchmarks;

use std::hash::keccakf1600;
use std::runtime::is_unconstrained;

global BLOCK_SIZE_IN_BYTES: u32 = 136; //(1600 - BITS * 2) / WORD_SIZE;
global WORD_SIZE: u32 = 8; // Limbs are made up of u64s so 8 bytes each.
global LIMBS_PER_BLOCK: u32 = BLOCK_SIZE_IN_BYTES / WORD_SIZE;
global NUM_KECCAK_LANES: u32 = 25;
global DIGEST_LANES: u32 = 32 / WORD_SIZE;

/// Hash input[0..message_size]. Active calls require message_size <= N.
/// Disabled calls accept arbitrary lengths; their unused digest is unspecified.
pub fn keccak256<let N: u32>(input: [u8; N], message_size: u32) -> [u8; 32] {
    digest_to_bytes(
        keccak256_digest_lanes(input, bounded_length::<N>(message_size)),
    )
}

// Keep the range assertion predicated, but sanitize the value passed into the
// unpredicated hashing kernel. A disabled caller must not make that kernel fail.
fn bounded_length<let N: u32>(message_size: u32) -> u32 {
    assert(message_size <= N, "Keccak message_size exceeds input capacity");
    if message_size <= N {
        message_size
    } else {
        0
    }
}

/// Hash input[0..message_size] and return the digest as four little-endian u64 lanes:
/// lane i holds digest bytes [8*i..8*i+8]. Same length rules as `keccak256`.
pub fn keccak256_lanes<let N: u32>(input: [u8; N], message_size: u32) -> [u64; DIGEST_LANES] {
    keccak256_digest_lanes(input, bounded_length::<N>(message_size))
}

#[no_predicates]
fn keccak256_digest_lanes<let N: u32>(input: [u8; N], message_size: u32) -> [u64; DIGEST_LANES] {
    assert(N >= message_size);

    if is_unconstrained() {
        // Brillig has runtime loop bounds, so it only absorbs the blocks the message needs.
        let real_max_blocks = (message_size + BLOCK_SIZE_IN_BYTES) / BLOCK_SIZE_IN_BYTES;
        let mut block_array = convert_to_u64_array(input, message_size);
        apply_keccak_padding(&mut block_array, message_size, real_max_blocks);
        let state = apply_keccak_permutations(block_array, real_max_blocks);
        [state[0], state[1], state[2], state[3]]
    } else {
        constrained_digest_lanes(input, message_size)
    }
}

// Constrained sponge. It absorbs every block that an N-byte message could need and
// selects the digest of the block where this message ends.
//
// Write message_size = 8 * L + r with 0 <= r < 8. Padded lane j (counting across blocks) is
//   message lane j                                        if j < L,
//   the first r bytes of message lane L, plus 0x01 << 8r  if j == L,
//   zero                                                  if j > L,
// and the last lane of the final block b (the block with 17b <= L < 17b + 17) also gets
// 0x80 << 56. If r == 7 and lane L ends block b, both padding bytes land in byte 7 (0x81).
//
// One comparison per lane, before[j] = (j < L), replaces a comparison per input byte, the
// division by the block size and the memory tables that a runtime index into the lanes or
// states would need.
fn constrained_digest_lanes<let N: u32>(input: [u8; N], message_size: u32) -> [u64; DIGEST_LANES] {
    let lane_index = message_size / WORD_SIZE;
    let byte_offset = message_size % WORD_SIZE;

    // before[j] = (j < L). Lanes from N / 8 on can never precede the boundary, since L <= N / 8.
    let mut lane_flags = [false; N / WORD_SIZE];
    let mut before = [0; ((N / BLOCK_SIZE_IN_BYTES) + 1) * LIMBS_PER_BLOCK];
    for j in 0..N / WORD_SIZE {
        lane_flags[j] = j < lane_index;
        before[j] = lane_flags[j] as Field;
    }
    // below[k] = (k < r); r <= 7, so below[7] is always zero.
    let mut offset_flags = [false; WORD_SIZE - 1];
    for k in 0..WORD_SIZE - 1 {
        offset_flags[k] = k < byte_offset;
    }

    // Message lane j holds input bytes 8j..8j+8 little-endian, zero past the input.
    let mut message_lanes = [0; N / WORD_SIZE + 1];
    for j in 0..N / WORD_SIZE + 1 {
        let mut lane = 0;
        let mut v = 1;
        for k in 0..WORD_SIZE {
            if j * WORD_SIZE + k < N {
                lane += v * (input[j * WORD_SIZE + k] as Field);
            }
            v *= 256;
        }
        message_lanes[j] = lane;
    }

    // before[j - 1] - before[j] is one at j == L and zero elsewhere: select message lane L.
    let mut boundary = 0;
    for j in 0..N / WORD_SIZE + 1 {
        let previous = if j == 0 { 1 } else { before[j - 1] };
        boundary += (previous - before[j]) * message_lanes[j];
    }
    let boundary_bytes: [u8; 8] = boundary.to_le_bytes();

    // Keep the first r bytes of lane L and put 0x01 at byte r.
    let mut padded_boundary = 0;
    let mut previous_below = 1;
    let mut v = 1;
    for k in 0..WORD_SIZE {
        let below = if k < WORD_SIZE - 1 {
            offset_flags[k] as Field
        } else {
            0
        };
        padded_boundary += below * v * (boundary_bytes[k] as Field) + (previous_below - below) * v;
        previous_below = below;
        v *= 256;
    }

    let mut lanes = [0; ((N / BLOCK_SIZE_IN_BYTES) + 1) * LIMBS_PER_BLOCK];
    for j in 0..N / WORD_SIZE + 1 {
        let previous = if j == 0 { 1 } else { before[j - 1] };
        lanes[j] = before[j] * message_lanes[j] + (previous - before[j]) * padded_boundary;
    }
    for b in 0..(N / BLOCK_SIZE_IN_BYTES) + 1 {
        // Block b is the final block iff 17b <= L < 17b + 17.
        let started = if b == 0 {
            1
        } else {
            before[b * LIMBS_PER_BLOCK - 1]
        };
        let is_final = started - before[b * LIMBS_PER_BLOCK + LIMBS_PER_BLOCK - 1];
        lanes[b * LIMBS_PER_BLOCK + LIMBS_PER_BLOCK - 1] += is_final * 0x8000000000000000;
    }

    let mut state = [0; NUM_KECCAK_LANES];
    let mut digest = [0; DIGEST_LANES];
    for b in 0..(N / BLOCK_SIZE_IN_BYTES) + 1 {
        for j in 0..LIMBS_PER_BLOCK {
            let lane = lanes[b * LIMBS_PER_BLOCK + j];
            lane.assert_max_bit_size::<64>();
            state[j] = state[j] ^ (lane as u64);
        }
        state = keccakf1600(state);

        // Block b is absorbed iff 17b <= L, i.e. iff lane 17b - 1 precedes the boundary.
        if b == 0 {
            digest = [state[0], state[1], state[2], state[3]];
        } else if lane_flags[b * LIMBS_PER_BLOCK - 1] {
            digest = [state[0], state[1], state[2], state[3]];
        }
    }
    digest
}

fn convert_to_u64_array<let N: u32>(
    input: [u8; N],
    message_size: u32,
) -> [u64; ((N / BLOCK_SIZE_IN_BYTES) + 1) * LIMBS_PER_BLOCK] {
    // Output is padded to a multiple of BLOCK_SIZE_IN_BYTES
    let mut sliced_buffer = [0; ((N / BLOCK_SIZE_IN_BYTES) + 1) * LIMBS_PER_BLOCK];

    // Process each byte of the message and accumulate into the appropriate limb
    for i in 0..message_size {
        let limb_index = i / WORD_SIZE;
        let byte_offset = i % WORD_SIZE;
        sliced_buffer[limb_index] += (input[i] as u64) << (8 * (byte_offset as u64));
    }

    sliced_buffer
}

fn apply_keccak_permutations<let N: u32>(
    flattened_blocks_array: [u64; N],
    num_blocks: u32,
) -> [u64; NUM_KECCAK_LANES] {
    let mut state: [u64; NUM_KECCAK_LANES] = [0; NUM_KECCAK_LANES];
    for i in 0..num_blocks {
        for j in 0..LIMBS_PER_BLOCK {
            state[j] = state[j] ^ flattened_blocks_array[i * LIMBS_PER_BLOCK + j];
        }
        state = keccakf1600(state);
    }
    state
}

// Apply Keccak padding to the u64 block array
// Append 0x01 after message, then 0x80 at end of block
// If both padding bytes collide at the same byte, combine them as 0x81
#[inline_always]
pub(crate) fn apply_keccak_padding<let N: u32>(
    block_array: &mut [u64; N],
    message_size: u32,
    real_max_blocks: u32,
) {
    // Calculate limb index and byte offset within the limb (little-endian)
    let start_limb_index = message_size / WORD_SIZE;
    let start_byte_offset = message_size % WORD_SIZE;

    block_array[start_limb_index] += 0x01 << (8 * (start_byte_offset as u64));
    // The end padding byte (0x80) always goes at byte 7 of the last limb
    block_array[real_max_blocks * LIMBS_PER_BLOCK - 1] += 0x80 << 56;
}

fn digest_to_bytes(lanes: [u64; DIGEST_LANES]) -> [u8; 32] {
    let mut result = [0; 32];
    for i in 0..DIGEST_LANES {
        let lane_le: [u8; 8] = (lanes[i] as Field).to_le_bytes();
        for j in 0..WORD_SIZE {
            result[WORD_SIZE * i + j] = lane_le[j];
        }
    }
    result
}
