//! Scoped Session Keys & Spending Limits (Wave C #8).
//!
//! Allows an account owner to delegate a temporary, restricted signing key
//! (contract allowlist, method allowlist, cumulative KVNC spend cap, expiry round)
//! for frictionless dApp/mobile UX without exposing the root private key.

use crate::address::Address;
use serde::{Deserialize, Serialize};

/// Error returned when a session key attempts an unauthorized action.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// Session key has been revoked by the owner.
    #[error("session key revoked")]
    Revoked,
    /// Session key has expired at or after `expires_round`.
    #[error("session key expired")]
    Expired,
    /// Target contract is not in the session's allowlist.
    #[error("target contract not allowed by session policy")]
    ContractNotAllowed,
    /// Target method is not in the session's allowlist.
    #[error("method not allowed by session policy")]
    MethodNotAllowed,
    /// Cumulative spend would exceed `max_spend_atoms`.
    #[error("session spending limit exceeded")]
    SpendLimitExceeded,
}

/// On-chain policy governing a delegated temporary session key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKeyPolicy {
    /// Root account owner that authorized this session key.
    pub owner: Address,
    /// Temporary Ed25519 public key address.
    pub session_pubkey: Address,
    /// Allowed target contracts (empty = any contract).
    pub allowed_contracts: Vec<Address>,
    /// Allowed contract entry point names (empty = any method).
    pub allowed_methods: Vec<String>,
    /// Maximum cumulative KVNC atoms (value + fees) this session may spend.
    pub max_spend_atoms: u64,
    /// Cumulative KVNC atoms spent so far under this session.
    pub spent_atoms: u64,
    /// Round at which this session expires (exclusive).
    pub expires_round: u64,
    /// Whether the owner explicitly revoked this session.
    pub revoked: bool,
}

impl SessionKeyPolicy {
    /// Check whether this session key is authorized to invoke `(contract, method)`
    /// spending `spend_atoms` at `current_round`.
    pub fn authorize_call(
        &self,
        contract: &Address,
        method: &str,
        spend_atoms: u64,
        current_round: u64,
    ) -> Result<(), SessionError> {
        if self.revoked {
            return Err(SessionError::Revoked);
        }
        if current_round >= self.expires_round {
            return Err(SessionError::Expired);
        }
        if !self.allowed_contracts.is_empty() && !self.allowed_contracts.contains(contract) {
            return Err(SessionError::ContractNotAllowed);
        }
        if !self.allowed_methods.is_empty() && !self.allowed_methods.iter().any(|m| m == method) {
            return Err(SessionError::MethodNotAllowed);
        }
        let next_spent = self
            .spent_atoms
            .checked_add(spend_atoms)
            .ok_or(SessionError::SpendLimitExceeded)?;
        if next_spent > self.max_spend_atoms {
            return Err(SessionError::SpendLimitExceeded);
        }
        Ok(())
    }

    /// Record `spend_atoms` after an authorized call succeeds.
    pub fn record_spend(&mut self, spend_atoms: u64) -> Result<(), SessionError> {
        let next = self
            .spent_atoms
            .checked_add(spend_atoms)
            .ok_or(SessionError::SpendLimitExceeded)?;
        if next > self.max_spend_atoms {
            return Err(SessionError::SpendLimitExceeded);
        }
        self.spent_atoms = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_policy_enforces_scope_limits_expiry_and_revocation() {
        let nft_contract = Address([0x42; 32]);
        let other_contract = Address([0x99; 32]);
        let mut policy = SessionKeyPolicy {
            owner: Address([1u8; 32]),
            session_pubkey: Address([2u8; 32]),
            allowed_contracts: vec![nft_contract],
            allowed_methods: vec!["nft_mint".to_string()],
            max_spend_atoms: 500_000_000, // 0.5 KVNC
            spent_atoms: 0,
            expires_round: 1_000,
            revoked: false,
        };

        assert!(policy
            .authorize_call(&nft_contract, "nft_mint", 100_000_000, 500)
            .is_ok());
        policy.record_spend(100_000_000).unwrap();

        assert_eq!(
            policy.authorize_call(&other_contract, "nft_mint", 100_000_000, 500),
            Err(SessionError::ContractNotAllowed)
        );
        assert_eq!(
            policy.authorize_call(&nft_contract, "nft_burn", 100_000_000, 500),
            Err(SessionError::MethodNotAllowed)
        );
        assert_eq!(
            policy.authorize_call(&nft_contract, "nft_mint", 400_000_001, 500),
            Err(SessionError::SpendLimitExceeded)
        );
        assert_eq!(
            policy.authorize_call(&nft_contract, "nft_mint", 100_000_000, 1_000),
            Err(SessionError::Expired)
        );
        policy.revoked = true;
        assert_eq!(
            policy.authorize_call(&nft_contract, "nft_mint", 100_000_000, 500),
            Err(SessionError::Revoked)
        );
    }
}
