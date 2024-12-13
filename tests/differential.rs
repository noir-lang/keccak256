use std::collections::BTreeMap;
use std::path::PathBuf;

use noir_runner::{NoirRunner, ToNoir};
use proptest::{prelude::prop, prop_assert_eq, test_runner::TestRunner};
use sha3::{Digest, Keccak256};

#[test]
fn test_prop_keccak256_1() {
    let runner = NoirRunner::try_new(PathBuf::new()).unwrap();

    let mut test_runner = TestRunner::new(Default::default());

    let strategy = prop::array::uniform::<_, 1>(0..255u8);

    test_runner
        .run(&strategy, |vector| {
            let input = BTreeMap::from([
                ("input".to_string(), vector.to_noir()),
                ("len".to_string(), vector.len().to_noir()),
            ]);

            let result = runner.run("test_keccak256_1", input).unwrap().unwrap();

            let expected: [u8; 32] = Keccak256::digest(vector).into();

            prop_assert_eq!(result, expected.to_noir());

            Ok(())
        })
        .unwrap();
}

#[test]
fn test_prop_keccak256_100() {
    let runner = NoirRunner::try_new(PathBuf::new()).unwrap();

    let mut test_runner = TestRunner::new(Default::default());

    let strategy = prop::array::uniform::<_, 100>(0..255u8);

    test_runner
        .run(&strategy, |vector| {
            let input = BTreeMap::from([
                ("input".to_string(), vector.clone().to_noir()),
                ("len".to_string(), vector.len().to_noir()),
            ]);

            let result = runner.run("test_keccak256_100", input).unwrap().unwrap();

            let expected: [u8; 32] = Keccak256::digest(vector).into();

            prop_assert_eq!(result, expected.to_noir());

            Ok(())
        })
        .unwrap();
}

// #[test]
// fn test_prop_keccak256_135() {
//     let runner = NoirRunner::try_new(PathBuf::new()).unwrap();

//     let mut test_runner = TestRunner::new(Default::default());

//     let strategy = prop::array::uniform::<_, 135>(0..255u8);

//     test_runner
//         .run(&strategy, |vector| {
//             let input = BTreeMap::from([
//                 ("input".to_string(), vector.clone().to_noir()),
//                 ("len".to_string(), vector.len().to_noir()),
//             ]);

//             let result = runner.run("test_keccak256_135", input).unwrap().unwrap();

//             let expected: [u8; 32] = Keccak256::digest(vector).into();

//             prop_assert_eq!(result, expected.to_noir());

//             Ok(())
//         })
//         .unwrap();
// }

#[test]
fn test_prop_keccak256_256() {
    let runner = NoirRunner::try_new(PathBuf::new()).unwrap();

    let mut test_runner = TestRunner::new(Default::default());

    let strategy = prop::array::uniform::<_, 256>(0..255u8);

    test_runner
        .run(&strategy, |vector| {
            let input = BTreeMap::from([
                ("input".to_string(), vector.clone().to_noir()),
                ("len".to_string(), vector.len().to_noir()),
            ]);

            let result = runner.run("test_keccak256_256", input).unwrap().unwrap();

            let expected: [u8; 32] = Keccak256::digest(vector).into();

            prop_assert_eq!(result, expected.to_noir());

            Ok(())
        })
        .unwrap();
}
