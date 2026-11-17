use kovanica_types::address::Address;
use kovanica_types::block::{BlockReference, StatementBlock};
use kovanica_types::crypto::Signature;
use kovanica_types::hash::Hash;
use kovanica_types::transaction::{Transaction, TransactionKind};
use kovanica_types::Vote;

struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x853c49e6748fea9b } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let val = self.next_u64().to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&val[..len]);
        }
    }

    fn random_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        self.fill_bytes(&mut buf);
        buf
    }
}

fn sample_transfer_tx() -> Transaction {
    Transaction {
        sender: Address([0x11; 32]),
        nonce: 42,
        kind: TransactionKind::Transfer {
            to: Address([0x22; 32]),
            amount: 10_000_000,
        },
        fee: 1_000,
        signature: Signature([0xAA; 64]),
        hash: Hash([0xBB; 32]),
    }
}

fn sample_call_tx() -> Transaction {
    Transaction {
        sender: Address([0x33; 32]),
        nonce: 100,
        kind: TransactionKind::Call {
            contract: Address([0x44; 32]),
            value: 500,
            method: "name_register".to_string(),
            args: vec![1, 2, 3, 4, 5, 6, 7, 8],
            gas_limit: 200_000,
        },
        fee: 5_000,
        signature: Signature([0xCC; 64]),
        hash: Hash([0xDD; 32]),
    }
}

fn sample_block() -> StatementBlock {
    StatementBlock {
        author: 1,
        round: 10,
        parents: vec![
            BlockReference {
                author: 0,
                round: 9,
                digest: Hash([0x01; 32]),
            },
            BlockReference {
                author: 2,
                round: 9,
                digest: Hash([0x02; 32]),
            },
        ],
        transactions: vec![sample_transfer_tx(), sample_call_tx()],
        statements: vec![0xDE, 0xAD, 0xBE, 0xEF],
        signature: Signature([0x55; 64]),
        digest: Hash([0x66; 32]),
        merkle_root: Hash([0x77; 32]),
    }
}

fn sample_vote() -> Vote {
    Vote {
        leader_round: 10,
        leader_hash: Hash([0x88; 32]),
        voter: 3,
        signature: Signature([0x99; 64]),
    }
}

// =========================================================================
// 1. StatementBlock Deserialization Smoke Tests
// =========================================================================

#[test]
fn test_statement_block_valid_roundtrip() {
    let block = sample_block();
    let bytes = bincode::serialize(&block).expect("serialization must succeed");
    assert!(!bytes.is_empty());

    let decoded: StatementBlock =
        bincode::deserialize(&bytes).expect("deserialization of valid vector must succeed");
    assert_eq!(decoded.author, block.author);
    assert_eq!(decoded.round, block.round);
    assert_eq!(decoded.parents.len(), block.parents.len());
    assert_eq!(decoded.transactions.len(), block.transactions.len());
    assert_eq!(decoded.statements, block.statements);
    assert_eq!(decoded.digest, block.digest);
    assert_eq!(decoded.merkle_root, block.merkle_root);
}

#[test]
fn test_statement_block_truncated_headers() {
    let block = sample_block();
    let bytes = bincode::serialize(&block).expect("serialization must succeed");

    // Every prefix shorter than full length must fail closed with Err
    for len in 0..bytes.len() {
        let truncated = &bytes[..len];
        let res = bincode::deserialize::<StatementBlock>(truncated);
        assert!(
            res.is_err(),
            "expected Err for truncated StatementBlock of length {len}/{}",
            bytes.len()
        );
    }
}

#[test]
fn test_statement_block_trailing_garbage() {
    let block = sample_block();
    let bytes = bincode::serialize(&block).expect("serialization must succeed");

    for garbage_len in [1, 4, 16, 64, 256, 1024] {
        let mut with_garbage = bytes.clone();
        with_garbage.extend(vec![0x7A; garbage_len]);

        // Default bincode ignores trailing bytes unless strict limit is set,
        // but must never panic or crash.
        let res = bincode::deserialize::<StatementBlock>(&with_garbage);
        if let Ok(b) = res {
            assert_eq!(b.author, block.author);
            assert_eq!(b.round, block.round);
        }

        // Corrupted payload + trailing garbage must fail closed
        let mut corrupt = bytes[..bytes.len() / 2].to_vec();
        corrupt.extend(vec![0xFF; garbage_len]);
        let corrupt_res = bincode::deserialize::<StatementBlock>(&corrupt);
        assert!(corrupt_res.is_err(), "corrupt block with garbage must fail");
    }
}

#[test]
fn test_statement_block_oversize_payload_length_prefixes() {
    let block = sample_block();
    let bytes = bincode::serialize(&block).expect("serialization must succeed");

    // The wire layout of StatementBlock begins with:
    // author: u16 (2 bytes)
    // round: u64 (8 bytes)
    // parents length prefix: u64 (8 bytes) at offset 10..18
    let oversize_prefixes: [u64; 4] = [
        u64::MAX,
        0x7fff_ffff_ffff_ffff,
        1_000_000_000,
        bytes.len() as u64 + 10_000,
    ];

    for prefix in oversize_prefixes {
        let mut mutated = bytes.clone();
        if mutated.len() >= 18 {
            mutated[10..18].copy_from_slice(&prefix.to_le_bytes());
            let res = bincode::deserialize::<StatementBlock>(&mutated);
            assert!(
                res.is_err(),
                "oversize parents length prefix {prefix} must fail closed"
            );
        }
    }
}

#[test]
fn test_statement_block_random_noise_and_bit_flips() {
    let mut rng = SimpleRng::new(0x1234_5678_9ABC_DEF0);

    // Test zeroed and all-1s buffers across diverse sizes
    for size in [0, 1, 2, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 512, 2048] {
        let zeros = vec![0u8; size];
        let _ = bincode::deserialize::<StatementBlock>(&zeros);

        let ones = vec![0xFFu8; size];
        let _ = bincode::deserialize::<StatementBlock>(&ones);
    }

    // Test bit flips on valid serialized block
    let block = sample_block();
    let bytes = bincode::serialize(&block).expect("serialization must succeed");

    for (i, &byte) in bytes.iter().enumerate() {
        for bit in 0..8 {
            let mut flipped = bytes.clone();
            flipped[i] = byte ^ (1 << bit);
            // Must either parse to a structurally valid block or fail closed with Err, NEVER panic
            if let Ok(b) = bincode::deserialize::<StatementBlock>(&flipped) {
                let _ = b.digest;
                let _ = b.author;
                let _ = b.round;
            }
        }
    }

    // 500 pseudo-random noise buffers of arbitrary lengths
    for _ in 0..500 {
        let len = (rng.next_u64() % 1024) as usize;
        let noise = rng.random_bytes(len);
        let res = bincode::deserialize::<StatementBlock>(&noise);
        if let Ok(b) = res {
            let _ = b.digest;
            let _ = b.author;
            let _ = b.round;
        }
    }
}

// =========================================================================
// 2. Transaction Deserialization Smoke Tests
// =========================================================================

#[test]
fn test_transaction_valid_roundtrips() {
    let tx1 = sample_transfer_tx();
    let bytes1 = bincode::serialize(&tx1).expect("transfer serialization must succeed");
    let decoded1: Transaction =
        bincode::deserialize(&bytes1).expect("transfer deserialization must succeed");
    assert_eq!(decoded1.sender, tx1.sender);
    assert_eq!(decoded1.nonce, tx1.nonce);
    assert_eq!(decoded1.kind, tx1.kind);
    assert_eq!(decoded1.fee, tx1.fee);
    assert_eq!(decoded1.signature, tx1.signature);
    assert_eq!(decoded1.hash, tx1.hash);

    let tx2 = sample_call_tx();
    let bytes2 = bincode::serialize(&tx2).expect("call serialization must succeed");
    let decoded2: Transaction =
        bincode::deserialize(&bytes2).expect("call deserialization must succeed");
    assert_eq!(decoded2.sender, tx2.sender);
    assert_eq!(decoded2.kind, tx2.kind);

    let tx3 = Transaction {
        sender: Address([0x55; 32]),
        nonce: 7,
        kind: TransactionKind::Deploy {
            code: vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
        },
        fee: 50_000,
        signature: Signature([0xEE; 64]),
        hash: Hash([0xFF; 32]),
    };
    let bytes3 = bincode::serialize(&tx3).expect("deploy serialization must succeed");
    let decoded3: Transaction =
        bincode::deserialize(&bytes3).expect("deploy deserialization must succeed");
    assert_eq!(decoded3.kind, tx3.kind);
}

#[test]
fn test_transaction_empty_and_truncated() {
    let empty: [u8; 0] = [];
    assert!(bincode::deserialize::<Transaction>(&empty).is_err());

    let tx = sample_transfer_tx();
    let bytes = bincode::serialize(&tx).expect("serialize");

    for len in 0..bytes.len() {
        let truncated = &bytes[..len];
        assert!(
            bincode::deserialize::<Transaction>(truncated).is_err(),
            "expected Err for truncated Transaction of length {len}/{}",
            bytes.len()
        );
    }
}

#[test]
fn test_transaction_malformed_keys_and_signature_lengths() {
    let tx = sample_transfer_tx();
    let bytes = bincode::serialize(&tx).expect("serialize");

    // Address is at 0..32. If we only have fewer bytes, it fails.
    for len in 1..32 {
        assert!(bincode::deserialize::<Transaction>(&bytes[..len]).is_err());
    }

    // Corrupted discriminant for TransactionKind
    // Sender is 32 bytes, nonce is 8 bytes -> discriminant is at byte 40 (u32 LE in bincode)
    let mut bad_variant = bytes.clone();
    if bad_variant.len() >= 44 {
        bad_variant[40..44].copy_from_slice(&999u32.to_le_bytes());
        assert!(
            bincode::deserialize::<Transaction>(&bad_variant).is_err(),
            "unknown transaction kind discriminant must fail closed"
        );
    }
}

#[test]
fn test_transaction_malformed_call_payloads() {
    let tx = sample_call_tx();
    let bytes = bincode::serialize(&tx).expect("serialize");

    // In a Call transaction:
    // sender: 32 bytes (0..32)
    // nonce: 8 bytes (32..40)
    // kind enum discriminant: 4 bytes (40..44) -> variant 6 is Call
    // Call { contract: 32 bytes (44..76), value: 8 bytes (76..84), method String length: 8 bytes (84..92) }
    // Method string bytes follow.
    if bytes.len() >= 92 {
        // 1. Oversize method name length prefix
        let mut oversize_method = bytes.clone();
        oversize_method[84..92].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(
            bincode::deserialize::<Transaction>(&oversize_method).is_err(),
            "oversize method length prefix must fail closed"
        );

        // 2. Invalid UTF-8 in method name
        let mut invalid_utf8 = bytes.clone();
        // The method "name_register" has length 13
        let method_len = 13usize;
        if invalid_utf8.len() >= 92 + method_len {
            invalid_utf8[92] = 0xFF;
            invalid_utf8[93] = 0xFE;
            assert!(
                bincode::deserialize::<Transaction>(&invalid_utf8).is_err(),
                "invalid UTF-8 in Call method name must fail closed"
            );
        }

        // 3. Oversize args length prefix
        // After method string comes args: Vec<u8> (u64 length prefix)
        let args_offset = 92 + method_len;
        if bytes.len() >= args_offset + 8 {
            let mut oversize_args = bytes.clone();
            oversize_args[args_offset..args_offset + 8]
                .copy_from_slice(&0x7FFF_FFFF_FFFF_FFFFu64.to_le_bytes());
            assert!(
                bincode::deserialize::<Transaction>(&oversize_args).is_err(),
                "oversize args length prefix must fail closed"
            );
        }
    }
}

#[test]
fn test_transaction_random_noise_and_mutations() {
    let mut rng = SimpleRng::new(0xFEED_FACE_CAFE_BABE);

    for _ in 0..500 {
        let len = (rng.next_u64() % 512) as usize;
        let noise = rng.random_bytes(len);
        let res = bincode::deserialize::<Transaction>(&noise);
        if let Ok(tx) = res {
            let _ = tx.hash;
            let _ = tx.sender;
            let _ = tx.nonce;
        }
    }
}

// =========================================================================
// 3. Vote Deserialization Smoke Tests
// =========================================================================

#[test]
fn test_vote_valid_roundtrip() {
    let vote = sample_vote();
    let bytes = bincode::serialize(&vote).expect("vote serialization must succeed");
    assert!(!bytes.is_empty());

    let decoded: Vote = bincode::deserialize(&bytes).expect("vote deserialization must succeed");
    assert_eq!(decoded.leader_round, vote.leader_round);
    assert_eq!(decoded.leader_hash, vote.leader_hash);
    assert_eq!(decoded.voter, vote.voter);
    assert_eq!(decoded.signature, vote.signature);
}

#[test]
fn test_vote_truncated_and_corrupted_hash() {
    let vote = sample_vote();
    let bytes = bincode::serialize(&vote).expect("vote serialization must succeed");

    // All prefixes shorter than full Vote wire format must fail closed
    for len in 0..bytes.len() {
        let truncated = &bytes[..len];
        assert!(
            bincode::deserialize::<Vote>(truncated).is_err(),
            "expected Err for truncated Vote of length {len}/{}",
            bytes.len()
        );
    }

    // Wire layout of Vote in bincode:
    // leader_round: u64 (8 bytes, 0..8)
    // leader_hash: Hash (32 bytes, 8..40)
    // voter: u16 (2 bytes, 40..42)
    // signature: serialize_bytes (8-byte length prefix + 64 bytes = 72 bytes, 42..114)
    assert_eq!(bytes.len(), 114);

    // Truncate inside leader_hash (e.g. 20 bytes total)
    assert!(bincode::deserialize::<Vote>(&bytes[..20]).is_err());
    // Truncate right after leader_hash (40 bytes total, missing voter and signature)
    assert!(bincode::deserialize::<Vote>(&bytes[..40]).is_err());
    // Truncate right after voter (42 bytes total, missing signature)
    assert!(bincode::deserialize::<Vote>(&bytes[..42]).is_err());
}

#[test]
fn test_vote_random_noise_and_fuzz_boundary() {
    let mut rng = SimpleRng::new(0xDEAD_BEEF_0000_1111);

    for _ in 0..500 {
        let len = (rng.next_u64() % 256) as usize;
        let noise = rng.random_bytes(len);
        let res = bincode::deserialize::<Vote>(&noise);
        if let Ok(vote) = res {
            let _ = vote.leader_round;
            let _ = vote.voter;
            let _ = vote.leader_hash;
        }
    }
}

// =========================================================================
// 4. Consensus Block Deserialization Boundary (fuzz_consensus)
// =========================================================================

#[test]
fn test_consensus_block_boundary() {
    let mut rng = SimpleRng::new(0x4321_8765_FEDC_BA98);

    // Exercise consensus block parsing boundary with arbitrary noise
    for _ in 0..500 {
        let len = (rng.next_u64() % 1024) as usize;
        let data = rng.random_bytes(len);
        // Mirrors fuzz/fuzz_consensus.rs
        let _ = bincode::deserialize::<StatementBlock>(&data);
    }
}
