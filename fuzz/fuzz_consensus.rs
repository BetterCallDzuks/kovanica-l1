//! Fuzzing harness for consensus block deserialization
#![no_main]
use kovanica_types::block::StatementBlock;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise block deserialization from arbitrary bytes.
    let _ = bincode::deserialize::<StatementBlock>(data);
});
