//! On-Chain Scheduled & Recurring Execution Contract (Wave C #9).
//!
//! Enables automated execution of RWA bond coupon payouts, vault vesting
//! releases, and recurring payments/DCA. Creators fund a KVNC bounty pool;
//! any keeper node can trigger due jobs via `scheduler_execute_job`, which
//! invokes the target contract through Wave A CPI (`Host::call_contract`) and
//! pays the keeper's bounty atomically.

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use kovanica_common::events::{SCHEDULER_JOB_CANCELLED, SCHEDULER_JOB_CREATED, SCHEDULER_JOB_EXECUTED};
use kovanica_common::{Address, Amount, ContractError, ContractResult, Height, Host};

pub const STATE_KEY: &[u8] = b"kvnc/v1/scheduler_state";
pub type JobId = u64;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScheduledJob {
    pub id: JobId,
    pub creator: Address,
    pub target_contract: Address,
    pub method: String,
    pub args: Vec<u8>,
    pub next_run_height: Height,
    /// `0` = one-shot job; `> 0` = recurring interval in block heights.
    pub interval_heights: u64,
    pub runs_remaining: u32,
    pub bounty_per_run: Amount,
    pub escrow_balance: Amount,
    pub active: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SchedulerState {
    pub next_job_id: JobId,
    pub jobs: BTreeMap<JobId, ScheduledJob>,
}

impl SchedulerState {
    pub fn load_or_default(host: &impl Host) -> ContractResult<Self> {
        match host.storage_get(STATE_KEY) {
            Some(bytes) => bincode::deserialize(&bytes).map_err(|_| ContractError::Custom(2)),
            None => Ok(Self::default()),
        }
    }

    fn store(&self, host: &mut impl Host) -> ContractResult<()> {
        let bytes = bincode::serialize(self).map_err(|_| ContractError::Custom(1))?;
        host.storage_set(STATE_KEY, &bytes);
        Ok(())
    }
}

pub struct Scheduler;

impl Scheduler {
    /// Schedule a one-shot or recurring job. Caller must attach `bounty_per_run * max_runs`
    /// KVNC via `Call.value` (verified against `host.call_value()`).
    #[allow(clippy::too_many_arguments)]
    pub fn create_job(
        host: &mut impl Host,
        target_contract: Address,
        method: String,
        args: Vec<u8>,
        execute_after_height: Height,
        interval_heights: u64,
        max_runs: u32,
        bounty_per_run: Amount,
    ) -> ContractResult<JobId> {
        if method.is_empty() || max_runs == 0 || bounty_per_run == 0 {
            return Err(ContractError::InvalidInput);
        }
        if max_runs > 1 && interval_heights == 0 {
            return Err(ContractError::InvalidInput);
        }
        let total_bounty = bounty_per_run
            .checked_mul(u128::from(max_runs))
            .ok_or(ContractError::Overflow)?;
        if host.call_value() < total_bounty {
            return Err(ContractError::InsufficientBalance);
        }

        let mut state = SchedulerState::load_or_default(host)?;
        let id = state.next_job_id;
        state.next_job_id = state
            .next_job_id
            .checked_add(1)
            .ok_or(ContractError::Overflow)?;

        let job = ScheduledJob {
            id,
            creator: host.caller(),
            target_contract,
            method,
            args,
            next_run_height: execute_after_height,
            interval_heights,
            runs_remaining: max_runs,
            bounty_per_run,
            escrow_balance: total_bounty,
            active: true,
        };
        state.jobs.insert(id, job);
        state.store(host)?;
        host.emit_event(SCHEDULER_JOB_CREATED, &id.to_le_bytes());
        Ok(id)
    }

    /// Execute a due scheduled job via CPI (`Host::call_contract`) and pay the
    /// keeper (`host.caller()`) the per-run KVNC bounty.
    pub fn execute_job(host: &mut impl Host, job_id: JobId) -> ContractResult<Vec<u8>> {
        let mut state = SchedulerState::load_or_default(host)?;
        let job = state.jobs.get_mut(&job_id).ok_or(ContractError::NotFound)?;
        if !job.active || job.runs_remaining == 0 {
            return Err(ContractError::Expired);
        }
        let now = host.block_height();
        if now < job.next_run_height {
            return Err(ContractError::NotExpired);
        }

        let target = job.target_contract;
        let method = job.method.clone();
        let args = job.args.clone();
        let bounty = job.bounty_per_run;

        // Invoke target contract via Wave A CPI.
        let ret = host.call_contract(&target, &method, &args, 0)?;

        // Update schedule state after CPI succeeds.
        job.runs_remaining -= 1;
        job.escrow_balance = job.escrow_balance.saturating_sub(bounty);
        if job.runs_remaining == 0 {
            job.active = false;
        } else {
            job.next_run_height = now.saturating_add(job.interval_heights);
        }
        state.store(host)?;

        // Pay keeper bounty from scheduler contract's own account.
        let self_addr = host.contract_address();
        let keeper = host.caller();
        host.transfer(&self_addr, &keeper, bounty)?;
        host.emit_event(SCHEDULER_JOB_EXECUTED, &job_id.to_le_bytes());
        Ok(ret)
    }

    /// Cancel an active job and refund remaining escrowed bounty to the creator.
    pub fn cancel_job(host: &mut impl Host, job_id: JobId) -> ContractResult<Amount> {
        let mut state = SchedulerState::load_or_default(host)?;
        let job = state.jobs.get_mut(&job_id).ok_or(ContractError::NotFound)?;
        if host.caller() != job.creator {
            return Err(ContractError::Unauthorized);
        }
        if !job.active {
            return Err(ContractError::Expired);
        }
        let refund = job.escrow_balance;
        job.escrow_balance = 0;
        job.runs_remaining = 0;
        job.active = false;
        let creator = job.creator;
        state.store(host)?;

        if refund > 0 {
            let self_addr = host.contract_address();
            host.transfer(&self_addr, &creator, refund)?;
        }
        host.emit_event(SCHEDULER_JOB_CANCELLED, &job_id.to_le_bytes());
        Ok(refund)
    }

    pub fn decode_state(bytes: &[u8]) -> Option<SchedulerState> {
        bincode::deserialize(bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use kovanica_common::MemHost;

    struct CpiTestHost {
        inner: MemHost,
        call_val: Amount,
        cpi_calls: Vec<(Address, String)>,
    }

    impl Host for CpiTestHost {
        fn caller(&self) -> Address {
            self.inner.caller()
        }
        fn contract_address(&self) -> Address {
            self.inner.contract_address()
        }
        fn block_height(&self) -> Height {
            self.inner.block_height()
        }
        fn timestamp(&self) -> u64 {
            self.inner.timestamp()
        }
        fn balance_of(&self, addr: &Address) -> Amount {
            self.inner.balance_of(addr)
        }
        fn transfer(&mut self, from: &Address, to: &Address, amount: Amount) -> ContractResult<()> {
            self.inner.transfer(from, to, amount)
        }
        fn emit_event(&mut self, topic: &[u8], data: &[u8]) {
            self.inner.emit_event(topic, data)
        }
        fn call_value(&self) -> Amount {
            self.call_val
        }
        fn storage_get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.inner.storage_get(key)
        }
        fn storage_set(&mut self, key: &[u8], value: &[u8]) {
            self.inner.storage_set(key, value)
        }
        fn call_contract(
            &mut self,
            target: &Address,
            method: &str,
            _args: &[u8],
            _value: Amount,
        ) -> ContractResult<Vec<u8>> {
            self.cpi_calls.push((*target, String::from(method)));
            Ok(vec![1, 2, 3])
        }
    }

    fn addr(n: u8) -> Address {
        let mut a = [0u8; 32];
        a[0] = n;
        a
    }

    #[test]
    fn create_execute_recurring_and_cancel_refunds() {
        let mut inner = MemHost::new(addr(1), addr(90));
        inner.set_block_height(10);
        inner.set_balance(addr(90), 3_000);
        let mut host = CpiTestHost {
            inner,
            call_val: 3_000,
            cpi_calls: Vec::new(),
        };

        let job_id = Scheduler::create_job(
            &mut host,
            addr(50),
            "rwa_mint".into(),
            vec![0xAA],
            20,
            10,
            3,
            1_000,
        )
        .unwrap();
        assert_eq!(job_id, 0);

        // Too early
        assert_eq!(
            Scheduler::execute_job(&mut host, job_id),
            Err(ContractError::NotExpired)
        );

        // Keeper executes at height 20
        host.inner.set_block_height(20);
        host.inner.set_caller(addr(2));
        let out = Scheduler::execute_job(&mut host, job_id).unwrap();
        assert_eq!(out, vec![1, 2, 3]);
        assert_eq!(host.balance_of(&addr(2)), 1_000);
        assert_eq!(host.cpi_calls.len(), 1);

        // Creator cancels remaining 2 runs -> refunds 2_000
        host.inner.set_caller(addr(1));
        let refund = Scheduler::cancel_job(&mut host, job_id).unwrap();
        assert_eq!(refund, 2_000);
        assert_eq!(host.balance_of(&addr(1)), 2_000);
    }
}
