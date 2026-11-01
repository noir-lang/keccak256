# Keccak256 Hashing Library

> [!WARNING]
> **This library is experimental software. It has not been fully audited and is not guaranteed to be secure. Expect bugs!**
>
> keccak256 is provided "as is", without warranty of any kind (see [LICENSE](LICENSE)). Bugs in this library can lead to under-constrained circuits, allowing invalid proofs to be accepted. Do not rely on it to protect real assets or sensitive data without your own independent review.

This package contains the Keccak256 hashing interface, formerly in the Noir standard library.

## Noir Version Compatibility

This library requires Noir **v1.0.0** or later.

## Installation

In `Nargo.toml`, add the version of this library you want to install:

```toml
[dependencies]
keccak256 = { tag = "v0.1.2", git = "https://github.com/noir-lang/keccak256" }
```

## Usage

```rust
use dep::keccak256::keccak256;

fn main() {
    let input = "Hello world!".as_bytes();
    let hash = keccak256(input, input.len());
    // hash is [u8; 32]
}
```

`keccak256_limbs(input, len)` returns the same digest as four little-endian `u64` lanes (`[u64; 4]`), as held in the Keccak state.

`KeccakHasher` hashes a message incrementally: `KeccakHasher::new()`, then `add_byte(u8)` or `add_u64(u64)` (eight bytes, little-endian, at any alignment), then `finish()` for `[u8; 32]` or `finish_to_limbs()` for `[u64; 4]`. It produces the same digest as `keccak256`.

Each `add_byte`/`add_u64` call that runs under a runtime condition (for example `if i < len { hasher.add_byte(b) }`) costs a `keccakf1600` permutation, because the circuit cannot know where the block boundaries fall. Use the hasher when the sequence of calls is fixed at compile time, and `keccak256(input, message_size)` for runtime-length input.

## Testing

### Unit Tests

Run the standard unit tests:

```bash
nargo test
```

### Oracle-Based Property Tests

The library includes property-based tests that verify correctness against a reference implementation via an oracle server:

```bash
# Run tests with oracle server (from scripts directory)
cd scripts
./run.sh
```

The oracle tests use a TypeScript server to provide reference Keccak256 implementations, testing various input sizes (1, 100, 135, and 256 bytes) with random inputs.

## Benchmarks

Benchmarks are ignored by `git` and checked on pull requests. Generate the benchmark report with:

```bash
nargo export
./scripts/build-gates-report.sh
./scripts/build-brillig-report.sh
```

The benchmark will be generated at `./gates_report.json` and `./brillig_report.json`.
