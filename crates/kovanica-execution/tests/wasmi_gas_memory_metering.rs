//! Gas metering and memory limit invariant tests for Wasmi smart contract execution.
//! Verifies:
//! 1. Fuel exhaustion safely aborts Wasmi execution, burns all gas, and rolls back storage overlay.
//! 2. Maximum memory allocation limits fail closed on linear memory heap exhaustion.
//! 3. Call value transfers with zero funds, insufficient balance, or arithmetic overflow fail closed.

use kovanica_common::ContractError;
use kovanica_execution::{
    execute_contract_call_with_value, ContractRunner, ExecutionConfig, ExecutionError, WasmCall,
};
use kovanica_runtime::RuntimeError;
use kovanica_storage::{tables, Storage};
use kovanica_types::Address;
use tempfile::TempDir;

fn addr(tag: u8) -> Address {
    Address([tag; 32])
}

fn open_storage() -> (TempDir, Storage) {
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = Storage::new(dir.path().join("state.redb")).expect("storage");
    (dir, storage)
}

fn fund(storage: &Storage, address: &Address, balance: u64) {
    let txn = storage.begin_write().expect("write");
    let mut account = storage
        .state()
        .get_account_or_default_write(&txn, address)
        .expect("account");
    account.balance = balance;
    storage
        .state()
        .set_account(&txn, address, &account)
        .expect("set");
    txn.commit().expect("commit");
}

fn get_balance(storage: &Storage, address: &Address) -> u64 {
    let txn = storage.begin_read().expect("read");
    storage
        .state()
        .get_account_or_default(&txn, address)
        .expect("account")
        .balance
}

fn deploy(storage: &Storage, address: &Address, code: &[u8]) {
    let txn = storage.begin_write().expect("write");
    let mut account = storage
        .state()
        .get_account_or_default_write(&txn, address)
        .expect("account");
    account.code = code.to_vec();
    account.code_hash = kovanica_common::hash(&account.code);
    storage
        .state()
        .set_account(&txn, address, &account)
        .expect("set");
    txn.commit().expect("commit");
}

fn get_contract_storage(storage: &Storage, contract: &Address, raw_key: &[u8]) -> Option<Vec<u8>> {
    let txn = storage.begin_read().expect("read");
    let table = txn.open_table(tables::CONTRACT_STORAGE).expect("table");
    let namespaced = kovanica_common::hash(raw_key);
    let key = (contract.0, namespaced);
    table.get(key).expect("get").map(|v| v.value())
}

// ---------------------------------------------------------------------------
// WASM module builders for invariant tests
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

/// Builds a valid Kovanica contract WASM with a custom entry point function body.
///
/// Signature of entry: `(param i32 i32) (result i64)`
/// Also exports `memory`, `kovanica_alloc(i32) -> i32`, `kovanica_dealloc(i32, i32)`.
fn build_test_wasm(
    entry_name: &str,
    entry_body: &[u8],
    initial_pages: u32,
    include_storage_set: bool,
) -> Vec<u8> {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();

    // Type section
    // Type 0: (i32, i32) -> i64 (entry)
    // Type 1: (i32) -> i32 (alloc)
    // Type 2: (i32, i32) -> () (dealloc)
    // Type 3: (i32, i32, i32, i32) -> i32 (kovanica_storage_set)
    let mut types = vec![4];
    types.extend([0x60, 2, 0x7f, 0x7f, 1, 0x7e]);
    types.extend([0x60, 1, 0x7f, 1, 0x7f]);
    types.extend([0x60, 2, 0x7f, 0x7f, 0]);
    types.extend([0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f]);
    append_section(&mut wasm, 1, &types);

    // Import section (optional kovanica_storage_set from env)
    if include_storage_set {
        let mut imports = vec![1];
        append_name(&mut imports, "env");
        append_name(&mut imports, "kovanica_storage_set");
        imports.extend([0, 3]); // function import of type index 3
        append_section(&mut wasm, 2, &imports);
    }

    // Function section: 3 functions (alloc: 1, dealloc: 2, entry: 0)
    append_section(&mut wasm, 3, &[3, 1, 2, 0]);

    // Memory section
    let mut memory = vec![1, 0]; // 1 memory, min initial_pages
    append_u32(&mut memory, initial_pages);
    append_section(&mut wasm, 5, &memory);

    // Export section
    let imported_fn_count = if include_storage_set { 1u32 } else { 0u32 };
    let mut exports = Vec::new();
    let mut export_count = 0;

    // export memory
    append_name(&mut exports, "memory");
    exports.extend([2, 0]);
    export_count += 1;

    // export kovanica_alloc
    append_name(&mut exports, "kovanica_alloc");
    exports.push(0);
    append_u32(&mut exports, imported_fn_count);
    export_count += 1;

    // export kovanica_dealloc
    append_name(&mut exports, "kovanica_dealloc");
    exports.push(0);
    append_u32(&mut exports, imported_fn_count + 1);
    export_count += 1;

    // export entry_name
    append_name(&mut exports, entry_name);
    exports.push(0);
    append_u32(&mut exports, imported_fn_count + 2);
    export_count += 1;

    let mut export_sec = Vec::new();
    append_u32(&mut export_sec, export_count);
    export_sec.extend(exports);
    append_section(&mut wasm, 7, &export_sec);

    // Code section: alloc body, dealloc body, entry body
    // alloc: i32.const 64; end
    let alloc_body = [0, 0x41, 64, 0x0b];
    // dealloc: end
    let dealloc_body = [0, 0x0b];

    let mut code = vec![3];
    for body in [&alloc_body[..], &dealloc_body[..], entry_body] {
        append_u32(&mut code, body.len() as u32);
        code.extend(body);
    }
    append_section(&mut wasm, 10, &code);

    wasm
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_wasmi_fuel_exhaustion_burns_all_gas_and_rolls_back_overlay() {
    let (_dir, storage) = open_storage();
    let contract = addr(10);
    let caller = addr(1);
    fund(&storage, &caller, 100_000);
    fund(&storage, &contract, 50_000);

    // Infinite loop in WASM:
    // (loop $l (br $l))
    // opcodes: 0 locals, 0x03 (loop), 0x40 (empty blocktype), 0x0c, 0 (br 0), 0x0b (end), 0x42, 0 (i64.const 0), 0x0b (end)
    let loop_body = [0, 0x03, 0x40, 0x0c, 0, 0x0b, 0x42, 0, 0x0b];
    let wasm = build_test_wasm("token_transfer", &loop_body, 1, false);
    deploy(&storage, &contract, &wasm);

    let gas_limit = 5_000u64;
    let config = ExecutionConfig {
        gas_limit,
        memory_limit_pages: 2,
        gas_hardening_active: false,
    };

    let mut runner = ContractRunner::new();
    let mut gas_used = 0u64;

    let result = runner.execute_wasm_call_with_gas(
        WasmCall {
            wasm: &wasm,
            entry: "token_transfer",
            contract,
            caller,
            height: 1,
            timestamp: 100,
            args: &[],
            storage: &storage,
            txn: None,
            value: 0,
            config: &config,
        },
        &mut gas_used,
    );

    // 1. Must fail with OutOfGas
    assert!(
        matches!(result, Err(ExecutionError::Runtime(RuntimeError::OutOfGas))),
        "Expected OutOfGas, got: {result:?}"
    );

    // 2. All gas must be burned
    assert_eq!(
        gas_used, gas_limit,
        "Fuel exhaustion must deterministically report gas_used == gas_limit"
    );

    // 3. Balances must remain completely unchanged
    assert_eq!(get_balance(&storage, &caller), 100_000);
    assert_eq!(get_balance(&storage, &contract), 50_000);
}

#[test]
fn test_wasmi_storage_writes_rolled_back_on_fuel_exhaustion() {
    let (_dir, storage) = open_storage();
    let contract = addr(11);
    let caller = addr(1);
    fund(&storage, &caller, 50_000);

    // WASM body:
    // 1. Call kovanica_storage_set(key_ptr=16, key_len=4, val_ptr=24, val_len=4)
    // 2. drop result
    // 3. Infinite loop: (loop $l (br $l))
    let mut body = vec![0]; // 0 locals
    body.extend([0x41, 16, 0x41, 4, 0x41, 24, 0x41, 4]); // args: (16, 4, 24, 4)
    body.extend([0x10, 0]); // call 0 (imported kovanica_storage_set)
    body.push(0x1a); // drop
    body.extend([0x03, 0x40, 0x0c, 0, 0x0b]); // loop { br 0 }
    body.extend([0x42, 0, 0x0b]); // i64.const 0; end

    let wasm = build_test_wasm("token_transfer", &body, 1, true);
    deploy(&storage, &contract, &wasm);

    let gas_limit = 25_000u64;
    let config = ExecutionConfig {
        gas_limit,
        memory_limit_pages: 2,
        gas_hardening_active: false,
    };

    let mut runner = ContractRunner::new();
    let mut gas_used = 0u64;

    let result = runner.execute_wasm_call_with_gas(
        WasmCall {
            wasm: &wasm,
            entry: "token_transfer",
            contract,
            caller,
            height: 1,
            timestamp: 100,
            args: &[],
            storage: &storage,
            txn: None,
            value: 0,
            config: &config,
        },
        &mut gas_used,
    );

    // Fuel exhaustion safely aborts Wasmi execution
    assert!(
        matches!(result, Err(ExecutionError::Runtime(RuntimeError::OutOfGas))),
        "Expected OutOfGas, got: {result:?}"
    );
    assert_eq!(gas_used, gas_limit);

    // Check that NO write made it to underlying redb storage!
    // The key in memory was at offset 100 (which is zero-filled memory of length 4)
    let raw_key = &[0u8, 0, 0, 0];
    assert!(
        get_contract_storage(&storage, &contract, raw_key).is_none(),
        "Storage overlay MUST NOT be committed when Wasmi execution exhausts fuel"
    );
}

#[test]
fn test_wasmi_memory_page_limit_fails_closed_on_growth() {
    let (_dir, storage) = open_storage();
    let contract = addr(12);
    let caller = addr(1);
    fund(&storage, &caller, 10_000);

    // Body calls memory.grow by 10 pages when memory_limit_pages = 2 (initial_pages = 1)
    let body = [0, 0x41, 10, 0x40, 0, 0x1a, 0x42, 0, 0x0b];
    let wasm = build_test_wasm("token_transfer", &body, 1, false);
    deploy(&storage, &contract, &wasm);

    let config = ExecutionConfig {
        gas_limit: 100_000,
        memory_limit_pages: 2, // Hard limit: max 2 pages (128 KiB)
        gas_hardening_active: false,
    };

    let mut runner = ContractRunner::new();
    let mut gas_used = 0u64;

    let result = runner.execute_wasm_call_with_gas(
        WasmCall {
            wasm: &wasm,
            entry: "token_transfer",
            contract,
            caller,
            height: 1,
            timestamp: 100,
            args: &[],
            storage: &storage,
            txn: None,
            value: 0,
            config: &config,
        },
        &mut gas_used,
    );

    // Memory limiter with trap_on_grow_failure(true) traps and fails closed
    assert!(
        matches!(
            result,
            Err(ExecutionError::Runtime(RuntimeError::Execution(_)))
        ),
        "Memory exhaustion must fail closed with execution trap: {result:?}"
    );

    // Balances remain intact
    assert_eq!(get_balance(&storage, &caller), 10_000);
}

#[test]
fn test_wasmi_memory_page_limit_fails_closed_on_initial_allocation() {
    let (_dir, storage) = open_storage();
    let contract = addr(13);
    let caller = addr(1);

    // Module declares initial 100 pages (6.4 MiB), but limit is 4 pages (256 KiB)
    let body = [0, 0x42, 0, 0x0b];
    let wasm = build_test_wasm("token_transfer", &body, 100, false);
    deploy(&storage, &contract, &wasm);

    let config = ExecutionConfig {
        gas_limit: 100_000,
        memory_limit_pages: 4,
        gas_hardening_active: false,
    };

    let mut runner = ContractRunner::new();
    let mut gas_used = 0u64;

    let result = runner.execute_wasm_call_with_gas(
        WasmCall {
            wasm: &wasm,
            entry: "token_transfer",
            contract,
            caller,
            height: 1,
            timestamp: 100,
            args: &[],
            storage: &storage,
            txn: None,
            value: 0,
            config: &config,
        },
        &mut gas_used,
    );

    assert!(
        matches!(
            result,
            Err(ExecutionError::Runtime(RuntimeError::Instantiation(_)))
        ),
        "Initial memory exceeding memory_limit_pages must fail closed on instantiation: {result:?}"
    );
}

#[test]
fn test_call_value_zero_funds_and_insufficient_balance_fail_closed() {
    let (_dir, storage) = open_storage();
    let contract = addr(14);
    let caller = addr(1);
    deploy(&storage, &contract, b"\0asm-test");

    // Case 1: Caller has zero funds, attempts call with 5_000 atoms
    assert_eq!(get_balance(&storage, &caller), 0);
    assert_eq!(get_balance(&storage, &contract), 0);

    let err = execute_contract_call_with_value(
        "token_burn",
        contract,
        caller,
        1,
        100,
        &[],
        5_000,
        &storage,
    )
    .expect_err("caller has 0 funds");

    assert!(
        matches!(
            err,
            ExecutionError::Contract(ContractError::InsufficientBalance)
        ),
        "Zero-funds call_value transfer must fail with InsufficientBalance: {err:?}"
    );
    assert_eq!(get_balance(&storage, &caller), 0);
    assert_eq!(get_balance(&storage, &contract), 0);

    // Case 2: Caller has 1_000 atoms, attempts call with 2_000 atoms
    fund(&storage, &caller, 1_000);
    let err = execute_contract_call_with_value(
        "token_burn",
        contract,
        caller,
        2,
        200,
        &[],
        2_000,
        &storage,
    )
    .expect_err("caller has 1000 < 2000");

    assert!(
        matches!(
            err,
            ExecutionError::Contract(ContractError::InsufficientBalance)
        ),
        "Insufficient balance must fail closed: {err:?}"
    );
    assert_eq!(get_balance(&storage, &caller), 1_000);
    assert_eq!(get_balance(&storage, &contract), 0);
}

#[test]
fn test_call_value_arithmetic_overflow_fails_closed() {
    let (_dir, storage) = open_storage();
    let contract = addr(15);
    let caller = addr(1);
    deploy(&storage, &contract, b"\0asm-test");

    // Fund contract near u64::MAX and caller with enough funds
    fund(&storage, &contract, u64::MAX - 500);
    fund(&storage, &caller, 10_000);

    // Call value of 1_000 would cause (u64::MAX - 500) + 1_000 to overflow u64::MAX
    let err = execute_contract_call_with_value(
        "token_burn",
        contract,
        caller,
        1,
        100,
        &[],
        1_000,
        &storage,
    )
    .expect_err("overflow");

    assert!(
        matches!(err, ExecutionError::Contract(ContractError::Overflow)),
        "Call value causing balance overflow must fail closed with Overflow: {err:?}"
    );

    // Balances must not be mutated
    assert_eq!(get_balance(&storage, &contract), u64::MAX - 500);
    assert_eq!(get_balance(&storage, &caller), 10_000);
}

#[test]
fn test_call_value_success_under_wasmi_with_gas_metering() {
    let (_dir, storage) = open_storage();
    let contract = addr(16);
    let caller = addr(1);
    fund(&storage, &caller, 25_000);
    fund(&storage, &contract, 5_000);

    // Trivial entry returning 0 (empty result)
    let body = [0, 0x42, 0, 0x0b];
    let wasm = build_test_wasm("token_transfer", &body, 1, false);
    deploy(&storage, &contract, &wasm);

    let config = ExecutionConfig {
        gas_limit: 100_000,
        memory_limit_pages: 2,
        gas_hardening_active: false,
    };

    let mut runner = ContractRunner::new();
    let mut gas_used = 0u64;

    let (out, _events) = runner
        .execute_wasm_call_with_gas(
            WasmCall {
                wasm: &wasm,
                entry: "token_transfer",
                contract,
                caller,
                height: 1,
                timestamp: 100,
                args: &[],
                storage: &storage,
                txn: None,
                value: 3_000,
                config: &config,
            },
            &mut gas_used,
        )
        .expect("wasm call succeeds");

    assert!(out.is_empty());
    assert!(gas_used > 0 && gas_used < config.gas_limit);

    // Verify exact value transfer occurred
    assert_eq!(get_balance(&storage, &caller), 22_000);
    assert_eq!(get_balance(&storage, &contract), 8_000);
}
