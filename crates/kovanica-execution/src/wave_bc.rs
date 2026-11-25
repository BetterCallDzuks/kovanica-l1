//! Wave B & C live state-transition enforcement helpers:
//! - Refundable storage deposit debit/refund (`STORAGE_DEPOSITS` table)
//! - Scoped session key policy validation & spend tracking (`SESSION_KEYS` table)

use kovanica_storage::StateStore;
use kovanica_types::Address;
use redb::WriteTransaction;

use crate::ExecutionError;

/// Apply a refundable storage deposit delta for `contract` charged/refunded to
/// `payer` inside an open `WriteTransaction`.
///
/// Returns the signed deposit delta in atoms (`> 0` charged, `< 0` refunded).
pub fn apply_storage_deposit_in_txn(
    state_store: &StateStore,
    txn: &WriteTransaction,
    payer: &Address,
    contract: &Address,
    new_bytes: u64,
) -> Result<i128, ExecutionError> {
    let (old_bytes, old_deposit) = state_store.load_storage_deposit_write(txn, contract)?;
    let delta = kovanica_fee::compute_storage_deposit_delta(old_bytes as usize, new_bytes as usize);
    let mut payer_acct = state_store.get_account_or_default_write(txn, payer)?;
    let (new_deposit, signed_delta) = match delta {
        kovanica_fee::StorageDepositDelta::Charge(charge) => {
            if payer_acct.balance < charge {
                return Err(ExecutionError::Other(format!(
                    "insufficient balance for storage deposit: {} has {}, needs {}",
                    payer, payer_acct.balance, charge
                )));
            }
            payer_acct.balance -= charge;
            (old_deposit.saturating_add(charge), i128::from(charge))
        }
        kovanica_fee::StorageDepositDelta::Refund(raw_refund) => {
            let refund = raw_refund.min(old_deposit);
            payer_acct.balance = payer_acct.balance.saturating_add(refund);
            (old_deposit.saturating_sub(refund), -i128::from(refund))
        }
        kovanica_fee::StorageDepositDelta::Unchanged => (old_deposit, 0),
    };
    state_store.set_account(txn, payer, &payer_acct)?;
    state_store.save_storage_deposit(txn, contract, new_bytes, new_deposit)?;
    Ok(signed_delta)
}

/// Validate and charge a scoped session key policy in `SESSION_KEYS`.
///
/// Enforces: policy exists, not revoked, `current_round <= expires_round`,
/// `contract` in `allowed_contracts` (if non-empty), `method` in `allowed_methods`
/// (if non-empty), and `spent_atoms + spend_atoms <= max_spend_atoms`.
#[allow(clippy::too_many_arguments)]
pub fn enforce_session_key_in_txn(
    state_store: &StateStore,
    txn: &WriteTransaction,
    owner: &Address,
    session_pubkey: &[u8; 32],
    contract: &Address,
    method: &str,
    spend_atoms: u64,
    current_round: u64,
) -> Result<(), ExecutionError> {
    let mut policy = state_store
        .load_session_key_write(txn, owner, session_pubkey)?
        .ok_or_else(|| ExecutionError::Other("session key policy not found".to_string()))?;
    let contract_ok = policy.allowed_contracts.is_empty()
        || policy.allowed_contracts.iter().any(|c| c == contract);
    let method_ok =
        policy.allowed_methods.is_empty() || policy.allowed_methods.iter().any(|m| m == method);
    let spend_ok = policy
        .spent_atoms
        .checked_add(spend_atoms)
        .is_some_and(|total| total <= policy.max_spend_atoms);
    if policy.revoked
        || current_round > policy.expires_round
        || !contract_ok
        || !method_ok
        || !spend_ok
    {
        return Err(ExecutionError::Other(
            "session key policy rejected call (revoked, expired, out of scope, or spend cap)"
                .to_string(),
        ));
    }
    policy.spent_atoms = policy.spent_atoms.saturating_add(spend_atoms);
    state_store.save_session_key(txn, &policy)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_storage::state_store::Account;
    use kovanica_types::SessionKeyPolicy;

    #[test]
    fn storage_deposit_charges_on_growth_and_refunds_on_shrink() {
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("wave_bc_exec.redb")).unwrap();
        let store = StateStore::new(&db).unwrap();

        let payer = Address([0x10; 32]);
        let contract = Address([0x20; 32]);
        let initial_balance = 10_000_000_000u64;

        let txn = db.begin_write().unwrap();
        store
            .set_account(
                &txn,
                &payer,
                &Account {
                    balance: initial_balance,
                    nonce: 0,
                    ..Account::default()
                },
            )
            .unwrap();
        let delta1 = apply_storage_deposit_in_txn(&store, &txn, &payer, &contract, 1000).unwrap();
        assert_eq!(
            delta1,
            (1000 * kovanica_params::STORAGE_DEPOSIT_PER_BYTE) as i128
        );
        let acct1 = store.get_account_or_default_write(&txn, &payer).unwrap();
        assert_eq!(acct1.balance, initial_balance - delta1 as u64);

        let delta2 = apply_storage_deposit_in_txn(&store, &txn, &payer, &contract, 400).unwrap();
        assert_eq!(
            delta2,
            -((600 * kovanica_params::STORAGE_DEPOSIT_PER_BYTE) as i128)
        );
        let acct2 = store.get_account_or_default_write(&txn, &payer).unwrap();
        assert_eq!(
            acct2.balance,
            initial_balance - (400 * kovanica_params::STORAGE_DEPOSIT_PER_BYTE)
        );
        txn.commit().unwrap();
    }

    #[test]
    fn session_key_enforces_scope_expiry_and_spend_cap() {
        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("wave_c_exec.redb")).unwrap();
        let store = StateStore::new(&db).unwrap();

        let owner = Address([0xAA; 32]);
        let session_pk = [0xBB; 32];
        let contract = Address([0xCC; 32]);
        let other_contract = Address([0xDD; 32]);

        let txn = db.begin_write().unwrap();
        store
            .save_session_key(
                &txn,
                &SessionKeyPolicy {
                    owner,
                    session_pubkey: Address(session_pk),
                    allowed_contracts: vec![contract],
                    allowed_methods: vec!["rwa_transfer".to_string()],
                    max_spend_atoms: 1_000,
                    spent_atoms: 0,
                    expires_round: 100,
                    revoked: false,
                },
            )
            .unwrap();

        enforce_session_key_in_txn(
            &store,
            &txn,
            &owner,
            &session_pk,
            &contract,
            "rwa_transfer",
            600,
            50,
        )
        .unwrap();
        assert!(enforce_session_key_in_txn(
            &store,
            &txn,
            &owner,
            &session_pk,
            &other_contract,
            "rwa_transfer",
            100,
            50,
        )
        .is_err());
        assert!(enforce_session_key_in_txn(
            &store,
            &txn,
            &owner,
            &session_pk,
            &contract,
            "rwa_transfer",
            500,
            50,
        )
        .is_err());
        assert!(enforce_session_key_in_txn(
            &store,
            &txn,
            &owner,
            &session_pk,
            &contract,
            "rwa_transfer",
            100,
            101,
        )
        .is_err());
        txn.commit().unwrap();
    }
}
