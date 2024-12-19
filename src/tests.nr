use crate::keccak256::keccak256;

#[export]
fn test_keccak256_0() -> [u8; 32] {
    keccak256([], 0)
}

#[export]
fn test_keccak256_1(input: [u8; 1], len: u32) -> [u8; 32] {
    keccak256(input, len)
}

#[export]
fn test_keccak256_100(input: [u8; 100], len: u32) -> [u8; 32] {
    keccak256(input, len)
}

// TODO: uncomment once keccak works with 135+ bytes
//
// #[export]
// fn test_keccak256_135(input: [u8; 135], len: u32) -> [u8; 32] {
//     keccak256(input, len)
// }

#[test]
fn smoke_test() {
    let input = [0xbd];
    let result = [
        0x5a, 0x50, 0x2f, 0x9f, 0xca, 0x46, 0x7b, 0x26, 0x6d, 0x5b, 0x78, 0x33, 0x65, 0x19, 0x37,
        0xe8, 0x05, 0x27, 0x0c, 0xa3, 0xf3, 0xaf, 0x1c, 0x0d, 0xd2, 0x46, 0x2d, 0xca, 0x4b, 0x3b,
        0x1a, 0xbf,
    ];
    assert_eq(keccak256(input, input.len()), result);
}

#[test]
fn hash_hello_world() {
    let input = "Hello world!".as_bytes();
    let result = [
        0xec, 0xd0, 0xe1, 0x8, 0xa9, 0x8e, 0x19, 0x2a, 0xf1, 0xd2, 0xc2, 0x50, 0x55, 0xf4, 0xe3,
        0xbe, 0xd7, 0x84, 0xb5, 0xc8, 0x77, 0x20, 0x4e, 0x73, 0x21, 0x9a, 0x52, 0x3, 0x25, 0x1f,
        0xea, 0xab,
    ];
    assert_eq(keccak256(input, input.len()), result);
}

#[test]
fn var_size_hash() {
    let input = [
        189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206,
        207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223,
    ];
    let result = [
        226, 37, 115, 94, 94, 196, 72, 116, 194, 105, 79, 233, 65, 12, 30, 94, 181, 131, 170, 219,
        171, 166, 236, 88, 143, 67, 255, 160, 248, 214, 39, 129,
    ];
    assert_eq(keccak256(input, 13), result);
}

#[test]
fn hash_longer_than_136_bytes() {
    let input = "123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789"
        .as_bytes();
    assert(input.len() > 136);

    let result = [
        0x1d, 0xca, 0xeb, 0xdf, 0xd9, 0xd6, 0x24, 0x67, 0x1c, 0x18, 0x16, 0xda, 0xd, 0x8a, 0xeb,
        0xa8, 0x75, 0x71, 0x2c, 0xc, 0x89, 0xe0, 0x25, 0x2, 0xe8, 0xb6, 0x5e, 0x16, 0x5, 0x55, 0xe4,
        0x40,
    ];
    assert_eq(keccak256(input, input.len()), result);
}
