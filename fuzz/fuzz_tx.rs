//! Fuzzing harness for Transaction deserialization
#![no_main]
use kovanica_types::Transaction;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to deserialize as Transaction
    if let Ok(tx) = bincode::deserialize::<Transaction>(data) {
        // If successful, verify the transaction structure
        let _ = tx.hash;
        let _ = tx.sender;
        let _ = tx.nonce;
    }
});
