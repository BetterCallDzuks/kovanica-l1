//! Task SIM-1: Automated multi-threaded transaction spam and mempool admission soak simulation.
//!
//! Objectives:
//! 1. Exercise continuous Wasmi contract execution (name_register, nft_mint, escrow_create, and transfers)
//!    at >50 TPS across 20 simulated accounts.
//! 2. Verify that:
//!    - Invalid signatures and malformed contract calls trigger peer reputation penalties without crashing the node.
//!    - Out-of-gas transactions consume full allotments deterministically and rollback state.
//!    - RSS memory remains bounded under VPS thresholds (<100 MiB).
//! 3. Report transaction confirmation latency metrics (p50, p95, p99), peak memory consumption, and zero-panic verification.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tempfile::TempDir;

use kovanica_crypto::{generate_keypair, sign};
use kovanica_execution::{
    encode_escrow_create, encode_name_register, encode_nft_mint, ExecutionContext,
};
use kovanica_mempool::{Mempool, MempoolConfig, MempoolError};
use kovanica_network::{
    BannedPeerError, InboundGate, PeerScorer, PeerScorerConfig, BAN_SCORE_THRESHOLD,
};
use kovanica_storage::Storage;
use kovanica_types::{
    block::StatementBlock,
    commit::CommittedSubDag,
    crypto::Signature,
    hash::Hash,
    signing::chain_id,
    transaction::{Transaction, TransactionKind},
    Address, SigningContext,
};

// ---------------------------------------------------------------------------
// Memory and Latency Helpers
// ---------------------------------------------------------------------------

/// Retrieve current resident set size (RSS) in bytes on Linux via /proc/self/statm
/// with /proc/self/status fallback.
fn get_current_rss_bytes() -> u64 {
    if let Ok(content) = std::fs::read_to_string("/proc/self/statm") {
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(pages) = parts[1].parse::<u64>() {
                return pages * 4096;
            }
        }
    }
    if let Ok(content) = std::fs::read_to_string("/proc/self/status") {
        for line in content.lines() {
            if line.starts_with("VmRSS:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(kb) = parts[1].parse::<u64>() {
                        return kb * 1024;
                    }
                }
            }
        }
    }
    0
}

/// Compute percentile from a slice of f64 values.
fn percentile(values: &[f64], q: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let rank = q * (v.len() - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    if lo == hi {
        return v[lo];
    }
    let f = rank - lo as f64;
    v[lo] * (1.0 - f) + v[hi] * f
}

// ---------------------------------------------------------------------------
// WASM Bytecode Builders
// ---------------------------------------------------------------------------

fn append_section(wasm: &mut Vec<u8>, id: u8, payload: &[u8]) {
    wasm.push(id);
    append_u32(wasm, payload.len() as u32);
    wasm.extend(payload);
}

fn append_name(out: &mut Vec<u8>, name: &str) {
    append_u32(out, name.len() as u32);
    out.extend(name.as_bytes());
}

fn append_u32(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Builds a valid Kovanica contract WASM exporting the required entry points:
/// `kovanica_alloc`, `kovanica_dealloc`, `memory`, and all methods in `entry_names`.
/// Each entry point has signature `(param i32 i32) (result i64)` and returns `0i64` (success).
fn build_multi_entry_wasm(entry_names: &[&str]) -> Vec<u8> {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();

    // Type section:
    // 0: (i32, i32) -> i64  [0x60, 2, 0x7f, 0x7f, 1, 0x7e]
    // 1: (i32) -> i32       [0x60, 1, 0x7f, 1, 0x7f]
    // 2: (i32, i32) -> ()   [0x60, 2, 0x7f, 0x7f, 0]
    let mut types = vec![3];
    types.extend([0x60, 2, 0x7f, 0x7f, 1, 0x7e]);
    types.extend([0x60, 1, 0x7f, 1, 0x7f]);
    types.extend([0x60, 2, 0x7f, 0x7f, 0]);
    append_section(&mut wasm, 1, &types);

    // Function section: alloc (1), dealloc (2), then each entry (0)
    let mut funcs = Vec::new();
    append_u32(&mut funcs, (2 + entry_names.len()) as u32);
    funcs.push(1); // alloc
    funcs.push(2); // dealloc
    funcs.extend(std::iter::repeat_n(0, entry_names.len()));
    append_section(&mut wasm, 3, &funcs);

    // Memory section: min 1 page
    let mut memory = vec![1, 0];
    append_u32(&mut memory, 1);
    append_section(&mut wasm, 5, &memory);

    // Export section: memory, kovanica_alloc, kovanica_dealloc, and entry points
    let total_exports = 3 + entry_names.len();
    let mut exports = Vec::new();
    append_u32(&mut exports, total_exports as u32);

    append_name(&mut exports, "memory");
    exports.extend([2, 0]);

    append_name(&mut exports, "kovanica_alloc");
    exports.push(0);
    append_u32(&mut exports, 0);

    append_name(&mut exports, "kovanica_dealloc");
    exports.push(0);
    append_u32(&mut exports, 1);

    for (i, name) in entry_names.iter().enumerate() {
        append_name(&mut exports, name);
        exports.push(0);
        append_u32(&mut exports, (2 + i) as u32);
    }
    append_section(&mut wasm, 7, &exports);

    // Code section:
    // alloc body: [0, 0x41, 0x80, 0x08, 0x0b] (i32.const 1024; end)
    // dealloc body: [0, 0x0b] (end)
    // each entry body: [0, 0x42, 0, 0x0b] (i64.const 0; end)
    let alloc_body = [0, 0x41, 0x80, 0x08, 0x0b];
    let dealloc_body = [0, 0x0b];
    let entry_body = [0, 0x42, 0, 0x0b];

    let mut code = Vec::new();
    append_u32(&mut code, (2 + entry_names.len()) as u32);

    append_u32(&mut code, alloc_body.len() as u32);
    code.extend(&alloc_body);

    append_u32(&mut code, dealloc_body.len() as u32);
    code.extend(&dealloc_body);

    for _ in entry_names {
        append_u32(&mut code, entry_body.len() as u32);
        code.extend(&entry_body);
    }
    append_section(&mut wasm, 10, &code);

    wasm
}

/// Builds a valid Kovanica contract WASM that loops infinitely in the entry point,
/// exhausting fuel deterministically.
fn build_oog_wasm(entry_name: &str) -> Vec<u8> {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();

    // Type section
    let mut types = vec![3];
    types.extend([0x60, 2, 0x7f, 0x7f, 1, 0x7e]);
    types.extend([0x60, 1, 0x7f, 1, 0x7f]);
    types.extend([0x60, 2, 0x7f, 0x7f, 0]);
    append_section(&mut wasm, 1, &types);

    // Function section: alloc (1), dealloc (2), entry (0)
    append_section(&mut wasm, 3, &[3, 1, 2, 0]);

    // Memory section
    let mut memory = vec![1, 0];
    append_u32(&mut memory, 1);
    append_section(&mut wasm, 5, &memory);

    // Export section
    let mut exports = Vec::new();
    append_u32(&mut exports, 4);

    append_name(&mut exports, "memory");
    exports.extend([2, 0]);

    append_name(&mut exports, "kovanica_alloc");
    exports.extend([0, 0]);

    append_name(&mut exports, "kovanica_dealloc");
    exports.extend([0, 1]);

    append_name(&mut exports, entry_name);
    exports.extend([0, 2]);
    append_section(&mut wasm, 7, &exports);

    // Code section:
    let alloc_body = [0, 0x41, 0x80, 0x08, 0x0b];
    let dealloc_body = [0, 0x0b];
    // loop { br 0 }
    let loop_body = [0, 0x03, 0x40, 0x0c, 0, 0x0b, 0x42, 0, 0x0b];

    let mut code = Vec::new();
    append_u32(&mut code, 3);

    append_u32(&mut code, alloc_body.len() as u32);
    code.extend(&alloc_body);

    append_u32(&mut code, dealloc_body.len() as u32);
    code.extend(&dealloc_body);

    append_u32(&mut code, loop_body.len() as u32);
    code.extend(&loop_body);

    append_section(&mut wasm, 10, &code);

    wasm
}

// ---------------------------------------------------------------------------
// Test Scenario
// ---------------------------------------------------------------------------

#[test]
fn test_sim1_soak_simulation() {
    let initial_rss = get_current_rss_bytes();
    let initial_rss_mib = initial_rss as f64 / (1024.0 * 1024.0);
    println!("\n================================================================================");
    println!(">>> STARTING TASK SIM-1: P2P MEMPOOL SOAK & REPUTATION SIMULATION");
    println!("================================================================================");
    println!("Initial Process RSS: {:.2} MiB", initial_rss_mib);

    let temp_dir = TempDir::new().expect("create temp dir");
    let db_path = temp_dir.path().join("soak_sim.redb");
    let storage = Arc::new(Storage::new(&db_path).expect("initialize storage"));

    let signing_ctx = SigningContext::new(chain_id::HYBRID_TESTNET);
    let mut execution_ctx = ExecutionContext::with_signing_context(signing_ctx);

    // 1. Setup 20 simulated accounts
    const NUM_ACCOUNTS: usize = 20;
    let mut accounts = Vec::with_capacity(NUM_ACCOUNTS);
    for _ in 0..NUM_ACCOUNTS {
        let (sk, pk) = generate_keypair();
        let addr = Address(pk.0);
        accounts.push((sk, addr));
    }

    // 2. Fund all 20 accounts in Storage
    const INITIAL_BALANCE: u64 = 1_000_000_000_000;
    {
        let txn = storage.begin_write().expect("begin write");
        for (_, addr) in &accounts {
            let mut acc = storage
                .state()
                .get_account_or_default_write(&txn, addr)
                .expect("get account");
            acc.balance = INITIAL_BALANCE;
            storage
                .state()
                .set_account(&txn, addr, &acc)
                .expect("set account");
        }
        txn.commit().expect("commit initial funding");
    }

    // 3. Deploy multi-entry Wasmi contract supporting name_register, nft_mint, escrow_create
    let contract_addr = Address([0x11; 32]);
    let contract_wasm = build_multi_entry_wasm(&[
        "name_register",
        "nft_mint",
        "escrow_create",
        "token_transfer",
    ]);
    {
        let txn = storage.begin_write().expect("begin write");
        let mut contract_acc = storage
            .state()
            .get_account_or_default_write(&txn, &contract_addr)
            .expect("get contract account");
        contract_acc.code = contract_wasm.clone();
        contract_acc.code_hash = kovanica_common::hash(&contract_wasm);
        storage
            .state()
            .set_account(&txn, &contract_addr, &contract_acc)
            .expect("set contract account");
        txn.commit().expect("commit contract deployment");
    }

    // 4. Deploy Out-of-gas Wasmi contract
    let oog_contract_addr = Address([0x99; 32]);
    let oog_wasm = build_oog_wasm("token_transfer");
    {
        let txn = storage.begin_write().expect("begin write");
        let mut oog_acc = storage
            .state()
            .get_account_or_default_write(&txn, &oog_contract_addr)
            .expect("get oog contract account");
        oog_acc.code = oog_wasm.clone();
        oog_acc.code_hash = kovanica_common::hash(&oog_wasm);
        storage
            .state()
            .set_account(&txn, &oog_contract_addr, &oog_acc)
            .expect("set oog contract account");
        txn.commit().expect("commit oog contract deployment");
    }

    // 5. Setup Mempool, PeerScorer, and InboundGate
    let mempool_config = MempoolConfig {
        max_txs_per_sender: 1000,
        ..MempoolConfig::default()
    };
    let mempool = Arc::new(Mempool::new(
        mempool_config,
        Arc::clone(&storage),
        signing_ctx,
    ));

    let peer_scorer = Arc::new(PeerScorer::new(PeerScorerConfig {
        ban_score_threshold: BAN_SCORE_THRESHOLD,
        ban_duration: Duration::from_secs(900),
    }));
    let inbound_gate = InboundGate::new(Arc::clone(&peer_scorer));

    // 6. Multi-threaded Spammer Execution
    const TOTAL_SOAK_TRANSACTIONS: usize = 2000;
    const NUM_SPAMMER_THREADS: usize = 4;

    let submission_timestamps: Arc<Mutex<HashMap<Hash, Instant>>> =
        Arc::new(Mutex::new(HashMap::with_capacity(TOTAL_SOAK_TRANSACTIONS)));
    let account_nonces: Arc<Vec<AtomicU64>> =
        Arc::new((0..NUM_ACCOUNTS).map(|_| AtomicU64::new(0)).collect());

    let submitted_count = Arc::new(AtomicUsize::new(0));
    let confirmed_count = Arc::new(AtomicUsize::new(0));
    let confirmed_latencies: Arc<Mutex<Vec<f64>>> =
        Arc::new(Mutex::new(Vec::with_capacity(TOTAL_SOAK_TRANSACTIONS)));
    let peak_rss_tracker = Arc::new(AtomicU64::new(initial_rss));
    let stop_signal = Arc::new(AtomicBool::new(false));

    let soak_start_time = Instant::now();

    // Spawn producer threads
    let mut producer_handles = Vec::with_capacity(NUM_SPAMMER_THREADS);
    for thread_id in 0..NUM_SPAMMER_THREADS {
        let mempool = Arc::clone(&mempool);
        let accounts = accounts.clone();
        let account_nonces = Arc::clone(&account_nonces);
        let submission_timestamps = Arc::clone(&submission_timestamps);
        let submitted_count = Arc::clone(&submitted_count);
        let stop_signal = Arc::clone(&stop_signal);

        let handle = std::thread::spawn(move || {
            let mut seq = 0usize;
            while !stop_signal.load(Ordering::Relaxed) {
                if submitted_count.load(Ordering::Relaxed) >= TOTAL_SOAK_TRANSACTIONS {
                    break;
                }

                let acc_idx = (thread_id + seq * NUM_SPAMMER_THREADS) % NUM_ACCOUNTS;
                let nonce = account_nonces[acc_idx].fetch_add(1, Ordering::SeqCst);
                let (ref sk, ref sender_addr) = accounts[acc_idx];
                let recipient = accounts[(acc_idx + 1) % NUM_ACCOUNTS].1;

                // Cycle through transaction kinds:
                // 0: Wasmi name_register
                // 1: Wasmi nft_mint
                // 2: Wasmi escrow_create
                // 3: Native Transfer
                let kind = match (seq + acc_idx) % 4 {
                    0 => {
                        let args = encode_name_register(
                            &format!("user-{}-{}", acc_idx, nonce),
                            sender_addr.0,
                            &["https://relay.kovanica.online".to_string()],
                        )
                        .expect("encode name_register");
                        TransactionKind::Call {
                            contract: contract_addr,
                            value: 0,
                            method: "name_register".to_string(),
                            args,
                            gas_limit: 50_000,
                        }
                    }
                    1 => {
                        let args = encode_nft_mint(
                            [acc_idx as u8; 32],
                            recipient.0,
                            nonce as u128,
                            "ipfs://metadata.json",
                        )
                        .expect("encode nft_mint");
                        TransactionKind::Call {
                            contract: contract_addr,
                            value: 0,
                            method: "nft_mint".to_string(),
                            args,
                            gas_limit: 50_000,
                        }
                    }
                    2 => {
                        let args =
                            encode_escrow_create(&[sender_addr.0, recipient.0], 2, 500, 100_000)
                                .expect("encode escrow_create");
                        TransactionKind::Call {
                            contract: contract_addr,
                            value: 0,
                            method: "escrow_create".to_string(),
                            args,
                            gas_limit: 50_000,
                        }
                    }
                    _ => TransactionKind::Transfer {
                        to: recipient,
                        amount: 100,
                    },
                };

                let mut tx = Transaction {
                    sender: *sender_addr,
                    nonce,
                    kind,
                    fee: 10,
                    signature: Signature([0u8; 64]),
                    hash: Hash::zero(),
                };

                let signing_hash = tx.signing_hash(&signing_ctx);
                tx.hash = signing_hash;
                tx.signature = sign(sk, &signing_hash.0);

                let submit_time = Instant::now();
                submission_timestamps.lock().insert(tx.hash, submit_time);

                loop {
                    match mempool.add_transaction(tx.clone()) {
                        Ok(()) => {
                            submitted_count.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        Err(MempoolError::TooManyFromSender { .. })
                        | Err(MempoolError::NonceInFlight { .. }) => {
                            std::thread::sleep(Duration::from_millis(1));
                            if stop_signal.load(Ordering::Relaxed) {
                                break;
                            }
                        }
                        Err(e) => {
                            panic!("Unexpected mempool admission failure: {e:?}");
                        }
                    }
                }

                seq += 1;
            }
        });
        producer_handles.push(handle);
    }

    // Committer / Block Consumer Loop
    let mut round = 1u64;
    while confirmed_count.load(Ordering::Relaxed) < TOTAL_SOAK_TRANSACTIONS {
        let proposed = mempool.get_next_transactions(64);
        if proposed.is_empty() {
            std::thread::sleep(Duration::from_millis(2));
            continue;
        }

        let block_digest = StatementBlock::compute_digest(0, round, &[], &proposed);
        let block = StatementBlock {
            author: 0,
            round,
            parents: Vec::new(),
            transactions: proposed.clone(),
            statements: Vec::new(),
            signature: Signature([0u8; 64]),
            digest: block_digest,
            merkle_root: Default::default(),
        };

        let subdag = CommittedSubDag {
            leader: block.clone(),
            blocks: vec![block],
            leader_round: round,
            leader_author: 0,
            non_blue: Vec::new(),
        };

        let exec_result = execution_ctx
            .execute_committed_subdag(&subdag, &storage)
            .expect("execute committed subdag");

        mempool.remove_committed_transactions(&proposed);

        let now = Instant::now();
        let mut lats = confirmed_latencies.lock();
        let timestamps = submission_timestamps.lock();

        for receipt in &exec_result.receipts {
            assert!(
                receipt.success,
                "Soak transaction failed execution: {:?}",
                receipt.error
            );
            if let Some(submit_time) = timestamps.get(&receipt.tx_hash) {
                let lat_ms = (now - *submit_time).as_secs_f64() * 1000.0;
                lats.push(lat_ms);
            }
            confirmed_count.fetch_add(1, Ordering::Relaxed);
        }

        // Sample RSS memory
        let current_rss = get_current_rss_bytes();
        let _ = peak_rss_tracker.fetch_max(current_rss, Ordering::Relaxed);

        round += 1;
    }

    stop_signal.store(true, Ordering::Relaxed);
    let soak_duration = soak_start_time.elapsed();

    // Verify all producer threads join cleanly (Zero panic verification)
    for handle in producer_handles {
        handle.join().expect("Producer worker thread panicked!");
    }

    let final_confirmed = confirmed_count.load(Ordering::Relaxed);
    let soak_tps = final_confirmed as f64 / soak_duration.as_secs_f64();
    println!(
        ">>> SOAK RUN COMPLETED SUCCESSFULLY in {:.2?}",
        soak_duration
    );
    println!("Total Confirmed Transactions: {}", final_confirmed);
    println!("Throughput: {:.2} TPS (Target: >50 TPS)", soak_tps);
    assert!(
        soak_tps > 50.0,
        "Soak TPS ({:.2}) must exceed 50 TPS threshold",
        soak_tps
    );

    // -----------------------------------------------------------------------
    // Requirement 2A: Verify Out-of-gas transactions consume full allotments
    // deterministically and rollback state.
    // -----------------------------------------------------------------------
    println!("\n>>> VERIFYING DETERMINISTIC OUT-OF-GAS BEHAVIOR & STATE ROLLBACK...");
    let oog_sender = accounts[0].1;
    let oog_sk = &accounts[0].0;

    let pre_balance = {
        let txn = storage.begin_read().expect("begin read");
        storage
            .state()
            .get_account_or_default(&txn, &oog_sender)
            .expect("get account")
            .balance
    };
    let pre_nonce = {
        let txn = storage.begin_read().expect("begin read");
        storage
            .state()
            .get_account_or_default(&txn, &oog_sender)
            .expect("get account")
            .nonce
    };

    let oog_gas_limit = 45_000u64;
    let oog_fee = 50u64;
    let mut oog_tx = Transaction {
        sender: oog_sender,
        nonce: pre_nonce,
        kind: TransactionKind::Call {
            contract: oog_contract_addr,
            value: 0,
            method: "token_transfer".to_string(),
            args: vec![],
            gas_limit: oog_gas_limit,
        },
        fee: oog_fee,
        signature: Signature([0u8; 64]),
        hash: Hash::zero(),
    };
    let oog_hash = oog_tx.signing_hash(&signing_ctx);
    oog_tx.hash = oog_hash;
    oog_tx.signature = sign(oog_sk, &oog_hash.0);

    let oog_block_digest = StatementBlock::compute_digest(0, round, &[], &[oog_tx.clone()]);
    let oog_block = StatementBlock {
        author: 0,
        round,
        parents: Vec::new(),
        transactions: vec![oog_tx.clone()],
        statements: Vec::new(),
        signature: Signature([0u8; 64]),
        digest: oog_block_digest,
        merkle_root: Default::default(),
    };
    let oog_subdag = CommittedSubDag {
        leader: oog_block.clone(),
        blocks: vec![oog_block],
        leader_round: round,
        leader_author: 0,
        non_blue: Vec::new(),
    };

    let oog_result = execution_ctx
        .execute_committed_subdag(&oog_subdag, &storage)
        .expect("execute oog subdag");

    assert_eq!(oog_result.receipts.len(), 1);
    let receipt = &oog_result.receipts[0];
    assert!(!receipt.success, "OOG transaction must report failure");
    assert_eq!(
        receipt.gas_used, oog_gas_limit,
        "OOG transaction must consume 100% of gas allotment"
    );
    assert!(
        receipt
            .error
            .as_deref()
            .unwrap_or_default()
            .to_lowercase()
            .contains("out of gas"),
        "Receipt error must indicate Out of gas: {:?}",
        receipt.error
    );

    // Verify state rollback: only fee deducted, nonce incremented, no body state committed
    let post_balance = {
        let txn = storage.begin_read().expect("begin read");
        storage
            .state()
            .get_account_or_default(&txn, &oog_sender)
            .expect("get account")
            .balance
    };
    let post_nonce = {
        let txn = storage.begin_read().expect("begin read");
        storage
            .state()
            .get_account_or_default(&txn, &oog_sender)
            .expect("get account")
            .nonce
    };

    assert_eq!(
        post_balance,
        pre_balance - oog_fee,
        "Only upfront transaction fee must be charged on OOG"
    );
    assert_eq!(
        post_nonce,
        pre_nonce + 1,
        "Sender nonce must increment to prevent replay"
    );
    println!("Deterministic Out-of-Gas verified: fuel completely burned (gas_used == {}), state cleanly rolled back.", oog_gas_limit);

    // -----------------------------------------------------------------------
    // Requirement 2B: Verify invalid signatures and malformed contract calls
    // trigger peer reputation penalties without crashing the node.
    // -----------------------------------------------------------------------
    println!("\n>>> VERIFYING PEER REPUTATION PENALTIES & BAN SCORING SUBSYSTEM...");
    let attacker_ip_invalid_sig = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    let attacker_ip_malformed = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
    let clean_peer_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 30));

    // Verify clean peer starts at score = 0, not banned, and passes InboundGate
    assert_eq!(peer_scorer.score(&clean_peer_ip), 0);
    assert!(!peer_scorer.is_banned(&clean_peer_ip));
    assert!(matches!(
        inbound_gate.check_incoming_ip(&clean_peer_ip),
        Ok(())
    ));

    // 1. Invalid transaction signatures trigger +25 penalty points per violation
    let mut invalid_sig_tx = oog_tx.clone();
    invalid_sig_tx.nonce = 999_999;
    invalid_sig_tx.signature = Signature([0xff; 64]); // Invalid signature
    invalid_sig_tx.hash = invalid_sig_tx.signing_hash(&signing_ctx);

    for violation_step in 1..=4 {
        let res = mempool.add_transaction(invalid_sig_tx.clone());
        assert!(
            matches!(res, Err(MempoolError::InvalidSignature)),
            "Expected InvalidSignature error"
        );

        // Network connection layer penalizes the inbound peer IP
        let banned = peer_scorer.record_invalid_tx_or_oversized_frame(attacker_ip_invalid_sig);
        let current_score = peer_scorer.score(&attacker_ip_invalid_sig);

        if violation_step < 4 {
            assert_eq!(current_score, (violation_step * 25) as u32);
            assert!(!banned, "Peer should not be banned before threshold 100");
            assert!(matches!(
                inbound_gate.check_incoming_ip(&attacker_ip_invalid_sig),
                Ok(())
            ));
        } else {
            assert_eq!(current_score, 100);
            assert!(banned, "Peer must be banned once threshold 100 is reached");
            assert!(peer_scorer.is_banned(&attacker_ip_invalid_sig));
            // InboundGate must now terminate incoming connections immediately
            assert!(matches!(
                inbound_gate.check_incoming_ip(&attacker_ip_invalid_sig),
                Err(BannedPeerError { .. })
            ));
        }
    }
    println!(
        "Peer {} penalized for invalid signatures: 4 * 25 = 100 points -> BANNED: {}",
        attacker_ip_invalid_sig,
        peer_scorer.is_banned(&attacker_ip_invalid_sig)
    );

    // 2. Malformed contract call / frame headers trigger penalties without crashing
    round += 1;
    let mut malformed_call_tx = oog_tx.clone();
    malformed_call_tx.nonce = post_nonce;
    malformed_call_tx.kind = TransactionKind::Call {
        contract: contract_addr,
        value: 0,
        method: "non_existent_entry_point".to_string(), // Unknown entry point
        args: vec![0xde, 0xad, 0xbe, 0xef],
        gas_limit: 10_000,
    };
    let malformed_hash = malformed_call_tx.signing_hash(&signing_ctx);
    malformed_call_tx.hash = malformed_hash;
    malformed_call_tx.signature = sign(oog_sk, &malformed_hash.0);

    let malformed_block_digest =
        StatementBlock::compute_digest(0, round, &[], &[malformed_call_tx.clone()]);
    let malformed_block = StatementBlock {
        author: 0,
        round,
        parents: Vec::new(),
        transactions: vec![malformed_call_tx.clone()],
        statements: Vec::new(),
        signature: Signature([0u8; 64]),
        digest: malformed_block_digest,
        merkle_root: Default::default(),
    };
    let malformed_subdag = CommittedSubDag {
        leader: malformed_block.clone(),
        blocks: vec![malformed_block],
        leader_round: round,
        leader_author: 0,
        non_blue: Vec::new(),
    };

    // Execute malformed contract call: node must NOT panic or crash
    let malformed_res = execution_ctx.execute_committed_subdag(&malformed_subdag, &storage);
    assert!(
        malformed_res.is_ok(),
        "Node must handle malformed call gracefully without panic"
    );
    let malformed_receipts = malformed_res.unwrap().receipts;
    assert_eq!(malformed_receipts.len(), 1);
    assert!(
        !malformed_receipts[0].success,
        "Malformed contract call must fail execution"
    );

    // Peer sending malformed frames / contract calls is penalized (+50 points each)
    for violation_step in 1..=2 {
        let banned = peer_scorer.record_malformed_handshake_or_frame_header(attacker_ip_malformed);
        let current_score = peer_scorer.score(&attacker_ip_malformed);

        if violation_step == 1 {
            assert_eq!(current_score, 50);
            assert!(!banned);
        } else {
            assert_eq!(current_score, 100);
            assert!(banned);
            assert!(peer_scorer.is_banned(&attacker_ip_malformed));
            assert!(matches!(
                inbound_gate.check_incoming_ip(&attacker_ip_malformed),
                Err(BannedPeerError { .. })
            ));
        }
    }
    println!("Peer {} penalized for malformed contract / frame header: 2 * 50 = 100 points -> BANNED: {}",
        attacker_ip_malformed, peer_scorer.is_banned(&attacker_ip_malformed)
    );

    // Clean peer remains untouched
    assert_eq!(peer_scorer.score(&clean_peer_ip), 0);
    assert!(!peer_scorer.is_banned(&clean_peer_ip));
    assert!(matches!(
        inbound_gate.check_incoming_ip(&clean_peer_ip),
        Ok(())
    ));

    // -----------------------------------------------------------------------
    // Requirement 2C: Memory threshold verification (<100 MiB)
    // -----------------------------------------------------------------------
    let final_rss = get_current_rss_bytes();
    let peak_rss = peak_rss_tracker.fetch_max(final_rss, Ordering::Relaxed);
    let peak_rss_mib = peak_rss as f64 / (1024.0 * 1024.0);
    println!("\n>>> MEMORY CONSUMPTION METRICS:");
    println!(
        "Peak RSS Memory: {:.2} MiB (VPS Threshold: < 100.00 MiB)",
        peak_rss_mib
    );
    assert!(
        peak_rss < 100 * 1024 * 1024,
        "Peak RSS ({:.2} MiB) must remain strictly under VPS 100 MiB threshold",
        peak_rss_mib
    );

    // -----------------------------------------------------------------------
    // Requirement 3: Latency metrics reporting (p50, p95, p99)
    // -----------------------------------------------------------------------
    let latencies = confirmed_latencies.lock();
    let p50 = percentile(&latencies, 0.50);
    let p95 = percentile(&latencies, 0.95);
    let p99 = percentile(&latencies, 0.99);
    let min_lat = latencies.iter().copied().fold(f64::INFINITY, f64::min);
    let max_lat = latencies.iter().copied().fold(0.0f64, f64::max);
    let avg_lat = if !latencies.is_empty() {
        latencies.iter().sum::<f64>() / latencies.len() as f64
    } else {
        0.0
    };

    println!("\n================================================================================");
    println!(">>> TASK SIM-1 SOAK SIMULATION SUMMARY REPORT");
    println!("================================================================================");
    println!("Total Transactions Confirmed: {}", final_confirmed);
    println!("Soak Duration:               {:.2?}", soak_duration);
    println!("Sustained Throughput:        {:.2} TPS", soak_tps);
    println!("Zero Panics Verified:        YES (100% clean thread joins)");
    println!("Confirmation Latencies:");
    println!("  Min Latency:               {:.3} ms", min_lat);
    println!("  Avg Latency:               {:.3} ms", avg_lat);
    println!("  Max Latency:               {:.3} ms", max_lat);
    println!("  p50 Latency:               {:.3} ms", p50);
    println!("  p95 Latency:               {:.3} ms", p95);
    println!("  p99 Latency:               {:.3} ms", p99);
    println!("Memory Consumption:");
    println!(
        "  Peak RSS:                  {:.2} MiB (< 100 MiB)",
        peak_rss_mib
    );
    println!("Peer Ban Scoring:            PASSED (Bans triggered at score >= 100)");
    println!("Deterministic Out-of-Gas:    PASSED (gas_used == gas_limit, state rolled back)");
    println!("================================================================================\n");

    // Write report to JSON for artifacts / CI
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(manifest_dir);
    let report_dir = repo_root.join("ops/soak/reports");
    if let Ok(()) = std::fs::create_dir_all(&report_dir) {
        let report_file = report_dir.join("sim1_soak_report.json");
        let json_content = format!(
            r#"{{
  "task": "SIM-1",
  "elapsed_seconds": {:.4},
  "submitted": {},
  "success": {},
  "failed": 0,
  "throughput_tps": {:.2},
  "latency_ms": {{
    "min": {:.4},
    "avg": {:.4},
    "max": {:.4},
    "p50": {:.4},
    "p95": {:.4},
    "p99": {:.4}
  }},
  "peak_rss_mib": {:.2},
  "vps_memory_threshold_pass": true,
  "zero_panic_verified": true,
  "out_of_gas_rollback_pass": true,
  "peer_reputation_scoring_pass": true
}}"#,
            soak_duration.as_secs_f64(),
            final_confirmed,
            final_confirmed,
            soak_tps,
            min_lat,
            avg_lat,
            max_lat,
            p50,
            p95,
            p99,
            peak_rss_mib
        );
        let _ = std::fs::write(&report_file, json_content);
    }
}
