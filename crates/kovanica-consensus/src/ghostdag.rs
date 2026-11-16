//! GHOSTDAG committer with k=5 for Chain 2 (Hybrid PoW + GHOSTDAG).
//!
//! Implements GHOSTDAG block sequencing without stake weighting,
//! committee votes, or certificates (ADR 0003).

use crate::ghostdag_scoped::colour_mergeset;
use crate::non_blue::non_blue_refs;
use kovanica_types::block::{compact_to_target, BlockReference, StatementBlock};
use kovanica_types::hash::Hash;
use kovanica_types::CommittedSubDag;
use std::collections::{HashMap, HashSet, VecDeque};
use tracing::{debug, info};

/// Why [`GhostdagCommitter::commit_uncommitted_selected_chain`] did not emit
/// a new leader, or why it skipped leaders it had already committed.
///
/// The same blocks always produce the same reason and the same emitted order.
/// Arrival order does not change it: the selected parent is the known parent
/// with the greatest `(cumulative work, blue score, digest)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitWaitReason {
    /// The committer has not seen a block yet.
    NoSelectedTip,
    /// The selected tip is already the last committed anchor.
    TipAlreadyCommitted,
    /// One or more new leaders were emitted. `replayed` is zero.
    CommittedNew,
    /// The selected-parent walk did not contain the last committed anchor
    /// (a heavier fork). Already-committed leaders were not re-queued.
    DivergedChain,
}

/// What the last commit attempt considered. Logged and exported so a stall
/// is visible without reading the DAG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitObservation {
    pub reason: CommitWaitReason,
    /// Selected-chain blocks walked for this attempt.
    pub candidates: usize,
    /// Blue-set length of the selected tip.
    pub blue_set_len: usize,
    /// Already-committed leaders the walk saw and did not re-queue.
    pub replayed: u64,
    /// Round of the selected tip, when there is one.
    pub awaited_round: Option<u64>,
    /// New sub-DAGs this attempt returned.
    pub emitted: usize,
}

impl Default for CommitObservation {
    fn default() -> Self {
        Self {
            reason: CommitWaitReason::NoSelectedTip,
            candidates: 0,
            blue_set_len: 0,
            replayed: 0,
            awaited_round: None,
            emitted: 0,
        }
    }
}

/// Calculate scalar work estimate from compact target bits.
#[must_use]
pub fn calculate_work_from_target(target_bits: u32) -> u128 {
    let target = compact_to_target(target_bits);
    if target == [0u8; 32] {
        return 0;
    }
    let high = u128::from_be_bytes(target[0..16].try_into().unwrap());
    if high == 0 {
        u128::MAX
    } else {
        (u128::MAX / high).max(1)
    }
}

/// Whether `chain_id` is a hybrid PoW + GHOSTDAG network.
pub fn is_hybrid_chain(chain_id: u64) -> bool {
    kovanica_types::signing::chain_id::is_hybrid(chain_id)
}

/// GHOSTDAG committer for sequencing PoW blocks on hybrid chains.
#[derive(Debug, Clone)]
pub struct GhostdagCommitter {
    /// GHOSTDAG cluster parameter k (default 5 for Chain 2).
    pub k: usize,
    /// In-memory cache of blocks indexed by digest.
    pub blocks: HashMap<Hash, StatementBlock>,
    /// Selected parent for each block in the DAG.
    pub selected_parent: HashMap<Hash, Option<Hash>>,
    /// Blue score of each block.
    pub blue_score: HashMap<Hash, u64>,
    /// Cumulative PoW difficulty work of each block.
    pub cumulative_work: HashMap<Hash, u128>,
    /// Blue blocks in each block's mergeset, ordered topologically.
    pub blue_sets: HashMap<Hash, Vec<Hash>>,
    /// Red (non-blue) block references in each block's mergeset.
    pub red_sets: HashMap<Hash, Vec<BlockReference>>,
    /// All block digests that have already been committed into a [`CommittedSubDag`].
    pub committed_blocks: HashSet<Hash>,
    /// Selected tip of the DAG with highest cumulative work / blue score.
    pub selected_tip: Option<Hash>,
    /// Last committed selected parent on the main chain.
    pub last_committed_selected_parent: Option<Hash>,
    /// Parent digests named by any stored block, including parents that are
    /// not in the map yet. A stored block is a tip exactly when its digest
    /// is absent from this set.
    referenced_parents: HashSet<Hash>,
    /// Stored blocks that no other stored block lists as a parent.
    tips_set: HashSet<Hash>,
    /// Inclusive ancestor set of [`Self::past_cache_root`]. Chain extension
    /// reuses it instead of walking history again.
    past_cache_root: Option<Hash>,
    past_cache: HashSet<Hash>,
    /// Nodes visited while building the mergeset exclusion set on the last
    /// [`Self::add_block`]. Zero when that set was already cached.
    last_mergeset_visits: usize,
    /// Diagnostic result of the last commit attempt.
    last_observation: CommitObservation,
}

impl Default for GhostdagCommitter {
    fn default() -> Self {
        Self::new(kovanica_params::GHOSTDAG_K as usize)
    }
}

impl GhostdagCommitter {
    /// Create a new GHOSTDAG committer with the specified k parameter (typically 5).
    #[must_use]
    pub fn new(k: usize) -> Self {
        Self {
            k,
            blocks: HashMap::new(),
            selected_parent: HashMap::new(),
            blue_score: HashMap::new(),
            cumulative_work: HashMap::new(),
            blue_sets: HashMap::new(),
            red_sets: HashMap::new(),
            committed_blocks: HashSet::new(),
            selected_tip: None,
            last_committed_selected_parent: None,
            referenced_parents: HashSet::new(),
            tips_set: HashSet::new(),
            past_cache_root: None,
            past_cache: HashSet::new(),
            last_mergeset_visits: 0,
            last_observation: CommitObservation::default(),
        }
    }

    /// Nodes walked to exclude the selected parent's past on the last add.
    ///
    /// A block that only extends the cached selected parent walks nothing.
    #[must_use]
    pub fn last_mergeset_visits(&self) -> usize {
        self.last_mergeset_visits
    }

    /// Diagnostic result of the last commit attempt.
    #[must_use]
    pub fn last_commit_observation(&self) -> CommitObservation {
        self.last_observation
    }

    /// Add a validated PoW block to the GHOSTDAG committer.
    ///
    /// Computes selected parent, mergeset, scoped GHOSTDAG colouring, blue score,
    /// and updates the selected tip if this block establishes a new heaviest path.
    pub fn add_block(&mut self, block: StatementBlock) {
        let digest = block.digest;
        if self.blocks.contains_key(&digest) {
            return;
        }

        let work = if let Some((_, target_bits, _, _, _)) =
            kovanica_types::decode_pow_statement(&block.statements)
        {
            calculate_work_from_target(target_bits)
        } else if let Ok(header) =
            block.extract_pow_header(kovanica_params::CHAIN_ID_HYBRID_TESTNET)
        {
            calculate_work_from_target(header.target_bits)
        } else {
            1u128
        };

        // Determine selected parent among known parents
        let valid_parents: Vec<Hash> = block
            .parents
            .iter()
            .map(|p| p.digest)
            .filter(|h| self.blocks.contains_key(h))
            .collect();

        let sel_parent = valid_parents
            .iter()
            .max_by(|a, b| {
                let work_a = self.cumulative_work.get(*a).copied().unwrap_or(0);
                let work_b = self.cumulative_work.get(*b).copied().unwrap_or(0);
                let score_a = self.blue_score.get(*a).copied().unwrap_or(0);
                let score_b = self.blue_score.get(*b).copied().unwrap_or(0);
                (work_a, score_a, a.0).cmp(&(work_b, score_b, b.0))
            })
            .copied();

        let parent_work = sel_parent
            .and_then(|p| self.cumulative_work.get(&p).copied())
            .unwrap_or(0);
        let parent_score = sel_parent
            .and_then(|p| self.blue_score.get(&p).copied())
            .unwrap_or(0);

        let cum_work = parent_work.saturating_add(work);

        // Compute mergeset: past cone of block minus past cone of selected parent.
        // `ensure_past` caches that cone so a chain extension does not walk it.
        let mergeset_hashes = self.compute_mergeset_hashes(&valid_parents, sel_parent);
        let mergeset_blocks: Vec<StatementBlock> = mergeset_hashes
            .iter()
            .filter_map(|h| self.blocks.get(h).cloned())
            .collect();

        // Run GHOSTDAG colouring on mergeset with k=5
        let previous_tips: Vec<Hash> = sel_parent.into_iter().collect();
        let colouring = colour_mergeset(&mergeset_blocks, self.k, &previous_tips);

        let blue_ordered = colouring.blue_ordered();
        let red_refs = non_blue_refs(&mergeset_blocks, &colouring.blue, &digest);

        let score = parent_score
            .saturating_add(colouring.blue.len() as u64)
            .saturating_add(1);

        // Parent list is needed after `block` moves into the map.
        self.observe_tips(digest, &block.parents);
        self.blocks.insert(digest, block);
        self.selected_parent.insert(digest, sel_parent);
        self.blue_score.insert(digest, score);
        self.cumulative_work.insert(digest, cum_work);
        self.blue_sets.insert(digest, blue_ordered);
        self.red_sets.insert(digest, red_refs);

        // Update selected tip if this block has higher cumulative work / blue score
        let is_new_tip = match self.selected_tip {
            None => true,
            Some(current_tip) => {
                let cur_work = self.cumulative_work.get(&current_tip).copied().unwrap_or(0);
                let cur_score = self.blue_score.get(&current_tip).copied().unwrap_or(0);
                (cum_work, score, digest.0) > (cur_work, cur_score, current_tip.0)
            }
        };

        if is_new_tip {
            self.selected_tip = Some(digest);
        }

        // past(B) = past(selected parent) ∪ mergeset ∪ {B}. The cache now
        // names B, so the next block that selects B does not walk history.
        self.past_cache.extend(mergeset_hashes.iter().copied());
        self.past_cache.insert(digest);
        self.past_cache_root = Some(digest);

        crate::metrics::set_ghostdag_tips(self.tips_set.len());
    }

    /// Remember `digest` as a tip and drop every parent it references.
    ///
    /// A parent that is not stored yet is still recorded. If that parent is
    /// inserted later it does not become a tip, matching a full scan of the
    /// parent lists.
    fn observe_tips(&mut self, digest: Hash, parents: &[BlockReference]) {
        for parent in parents {
            self.referenced_parents.insert(parent.digest);
            self.tips_set.remove(&parent.digest);
        }
        if !self.referenced_parents.contains(&digest) {
            self.tips_set.insert(digest);
        }
    }

    /// Make [`Self::past_cache`] the inclusive ancestor set of `sel_parent`.
    ///
    /// A hit costs nothing. A miss walks that cone once; [`Self::add_block`]
    /// then extends the cache to the block it just stored.
    fn ensure_past(&mut self, sel_parent: Option<Hash>) {
        let Some(sp) = sel_parent else {
            self.past_cache.clear();
            self.past_cache_root = None;
            self.last_mergeset_visits = 0;
            return;
        };
        if self.past_cache_root == Some(sp) {
            self.last_mergeset_visits = 0;
            return;
        }

        self.past_cache.clear();
        self.past_cache.insert(sp);
        let mut queue = VecDeque::new();
        queue.push_back(sp);
        let mut visits = 0usize;
        while let Some(curr) = queue.pop_front() {
            visits = visits.saturating_add(1);
            let parents: Vec<Hash> = self
                .blocks
                .get(&curr)
                .map(|blk| blk.parents.iter().map(|p| p.digest).collect())
                .unwrap_or_default();
            for parent in parents {
                if self.past_cache.insert(parent) {
                    queue.push_back(parent);
                }
            }
        }
        self.past_cache_root = Some(sp);
        self.last_mergeset_visits = visits;
    }

    /// Compute past cone ancestor hashes of `block_parents` excluding past cone of `sel_parent`.
    fn compute_mergeset_hashes(
        &mut self,
        block_parents: &[Hash],
        sel_parent: Option<Hash>,
    ) -> Vec<Hash> {
        // The only known parent is the selected parent: the mergeset is empty
        // and the exclusion set does not need to be rebuilt.
        if block_parents
            .iter()
            .all(|parent| Some(*parent) == sel_parent)
        {
            self.ensure_past(sel_parent);
            return Vec::new();
        }

        self.ensure_past(sel_parent);

        let mut mergeset = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        for parent in block_parents {
            if Some(*parent) != sel_parent
                && !self.past_cache.contains(parent)
                && visited.insert(*parent)
            {
                queue.push_back(*parent);
            }
        }

        while let Some(curr) = queue.pop_front() {
            if self.past_cache.contains(&curr) {
                continue;
            }
            mergeset.push(curr);
            let parents: Vec<Hash> = self
                .blocks
                .get(&curr)
                .map(|blk| blk.parents.iter().map(|p| p.digest).collect())
                .unwrap_or_default();
            for parent in parents {
                if !self.past_cache.contains(&parent) && visited.insert(parent) {
                    queue.push_back(parent);
                }
            }
        }

        mergeset
    }

    /// Commit uncommitted blocks along the selected parent chain up to the selected tip.
    ///
    /// Returns ordered [`CommittedSubDag`]s ready for state execution and reward minting.
    ///
    /// A leader already in [`Self::committed_blocks`] is not returned again.
    /// Execution keys idempotency on that digest and would no-op the whole
    /// sub-DAG, so re-queueing it only blocks the commit path. Newly committed
    /// leaders stay in selected-parent order, oldest first, which is a
    /// function of the blocks and not of which node walks them.
    pub fn commit_uncommitted_selected_chain(&mut self) -> Vec<CommittedSubDag> {
        let Some(tip) = self.selected_tip else {
            self.observe_commit(CommitWaitReason::NoSelectedTip, 0, 0, 0, None, 0);
            debug!(reason = "no_selected_tip", "ghostdag commit waiting");
            return Vec::new();
        };
        let awaited_round = self.blocks.get(&tip).map(|block| block.round);
        let blue_set_len = self.blue_sets.get(&tip).map(|blue| blue.len()).unwrap_or(0);

        if Some(tip) == self.last_committed_selected_parent {
            self.observe_commit(
                CommitWaitReason::TipAlreadyCommitted,
                0,
                blue_set_len,
                0,
                awaited_round,
                0,
            );
            debug!(
                awaited_round,
                blue_set = blue_set_len,
                reason = "tip_already_committed",
                "ghostdag commit waiting"
            );
            return Vec::new();
        }

        // Walk back from the tip until the last committed anchor. If the
        // anchor is not on this chain, a heavier fork won. The walk still
        // reaches genesis; leaders already committed must not be re-queued.
        let mut chain_rev = Vec::new();
        let mut saw_anchor = false;
        let mut curr = Some(tip);
        while let Some(hash) = curr {
            if Some(hash) == self.last_committed_selected_parent {
                saw_anchor = true;
                break;
            }
            chain_rev.push(hash);
            curr = self.selected_parent.get(&hash).copied().flatten();
        }
        let diverged = self.last_committed_selected_parent.is_some() && !saw_anchor;
        chain_rev.reverse();
        let candidates = chain_rev.len();

        let mut subdags = Vec::new();
        let mut replayed = 0u64;

        for selected_hash in chain_rev {
            let Some(leader_block) = self.blocks.get(&selected_hash).cloned() else {
                continue;
            };
            let blue_order = self
                .blue_sets
                .get(&selected_hash)
                .cloned()
                .unwrap_or_default();
            let red_refs = self
                .red_sets
                .get(&selected_hash)
                .cloned()
                .unwrap_or_default();
            let leader_already = self.committed_blocks.contains(&selected_hash);

            let mut ordered_blocks = Vec::new();
            for blue_hash in &blue_order {
                if !self.committed_blocks.contains(blue_hash) {
                    if let Some(blk) = self.blocks.get(blue_hash) {
                        ordered_blocks.push(blk.clone());
                        self.committed_blocks.insert(*blue_hash);
                    }
                }
            }

            let mut uncommitted_red = Vec::new();
            for red in red_refs {
                if !self.committed_blocks.contains(&red.digest) {
                    self.committed_blocks.insert(red.digest);
                    uncommitted_red.push(red);
                }
            }

            if leader_already {
                // The leader digest is the execution idempotency key. A second
                // sub-DAG with that leader would not apply `ordered_blocks`,
                // so marking them committed here matches that no-op and keeps
                // them from being paid later under a different leader.
                replayed = replayed.saturating_add(1);
                self.last_committed_selected_parent = Some(selected_hash);
                continue;
            }

            ordered_blocks.push(leader_block.clone());
            self.committed_blocks.insert(selected_hash);
            crate::metrics::record_ghostdag_blue_blocks(ordered_blocks.len() as u64);
            crate::metrics::record_ghostdag_red_blocks(uncommitted_red.len() as u64);
            subdags.push(CommittedSubDag {
                leader: leader_block.clone(),
                blocks: ordered_blocks,
                leader_round: leader_block.round,
                leader_author: leader_block.author,
                non_blue: uncommitted_red,
            });
            self.last_committed_selected_parent = Some(selected_hash);
        }

        let reason = if diverged {
            CommitWaitReason::DivergedChain
        } else {
            CommitWaitReason::CommittedNew
        };
        self.observe_commit(
            reason,
            candidates,
            blue_set_len,
            replayed,
            awaited_round,
            subdags.len(),
        );
        if replayed > 0 {
            crate::metrics::record_replay_rounds(replayed);
            info!(
                awaited_round,
                candidates,
                blue_set = blue_set_len,
                replayed,
                emitted = subdags.len(),
                reason = if diverged {
                    "selected_parent_chain_diverged"
                } else {
                    "already_committed"
                },
                "ghostdag skipped already-committed leaders"
            );
        } else if subdags.is_empty() {
            debug!(
                awaited_round,
                candidates,
                blue_set = blue_set_len,
                reason = "nothing_new",
                "ghostdag commit waiting"
            );
        } else {
            debug!(
                awaited_round,
                candidates,
                blue_set = blue_set_len,
                emitted = subdags.len(),
                "ghostdag committed selected chain"
            );
        }
        subdags
    }

    fn observe_commit(
        &mut self,
        reason: CommitWaitReason,
        candidates: usize,
        blue_set_len: usize,
        replayed: u64,
        awaited_round: Option<u64>,
        emitted: usize,
    ) {
        self.last_observation = CommitObservation {
            reason,
            candidates,
            blue_set_len,
            replayed,
            awaited_round,
            emitted,
        };
    }

    /// Return the active DAG tips (blocks with no children in memory).
    ///
    /// Sorted by digest so every node hands the same parent list to a miner
    /// that builds on these tips.
    #[must_use]
    pub fn tips(&self) -> Vec<Hash> {
        let mut tips: Vec<Hash> = self.tips_set.iter().copied().collect();
        tips.sort_by(|left, right| left.0.cmp(&right.0));
        tips
    }

    /// Return the current selected tip.
    #[must_use]
    pub fn selected_tip(&self) -> Option<Hash> {
        self.selected_tip
    }

    /// Return the blue score of a block if tracked.
    #[must_use]
    pub fn blue_score(&self, hash: &Hash) -> Option<u64> {
        self.blue_score.get(hash).copied()
    }

    /// Return the cumulative PoW work of a block if tracked.
    #[must_use]
    pub fn cumulative_work(&self, hash: &Hash) -> Option<u128> {
        self.cumulative_work.get(hash).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kovanica_types::block::BlockHeader;

    fn make_pow_block(
        round: u64,
        author: u16,
        parents: Vec<BlockReference>,
        nonce: u64,
    ) -> StatementBlock {
        let mut header = BlockHeader::new(
            kovanica_params::CHAIN_ID_HYBRID_TESTNET,
            round,
            author,
            parents,
            Hash::zero(),
            1_700_000_000_000 + round * 4000,
            0x207fffff,
            nonce,
        );
        header.pow_hash = Some(header.compute_pow_hash());
        header.to_statement_block(Vec::new())
    }

    #[test]
    fn ghostdag_committer_single_chain_linearization() {
        let mut committer = GhostdagCommitter::new(5);

        // Genesis
        let b0 = make_pow_block(0, 0, vec![], 0);
        committer.add_block(b0.clone());

        // B1 -> B0
        let b1 = make_pow_block(1, 1, vec![b0.reference()], 1);
        committer.add_block(b1.clone());

        // B2 -> B1
        let b2 = make_pow_block(2, 2, vec![b1.reference()], 2);
        committer.add_block(b2.clone());

        assert_eq!(committer.selected_tip, Some(b2.digest));

        let subdags = committer.commit_uncommitted_selected_chain();
        assert_eq!(subdags.len(), 3);
        assert_eq!(subdags[0].leader.digest, b0.digest);
        assert_eq!(subdags[1].leader.digest, b1.digest);
        assert_eq!(subdags[2].leader.digest, b2.digest);

        // Second commit without new blocks yields empty
        let empty = committer.commit_uncommitted_selected_chain();
        assert!(empty.is_empty());
    }

    #[test]
    fn ghostdag_committer_mergeset_and_tip_selection() {
        let mut committer = GhostdagCommitter::new(5);

        // B0
        let b0 = make_pow_block(0, 0, vec![], 0);
        committer.add_block(b0.clone());

        // Two concurrent blocks pointing to B0: B1a and B1b
        let b1a = make_pow_block(1, 1, vec![b0.reference()], 10);
        let b1b = make_pow_block(1, 2, vec![b0.reference()], 20);
        committer.add_block(b1a.clone());
        committer.add_block(b1b.clone());

        // B2 points to both B1a and B1b
        let b2 = make_pow_block(2, 3, vec![b1a.reference(), b1b.reference()], 30);
        committer.add_block(b2.clone());

        assert_eq!(committer.selected_tip, Some(b2.digest));
        let sel_p = committer.selected_parent.get(&b2.digest).copied().flatten();
        assert!(sel_p == Some(b1a.digest) || sel_p == Some(b1b.digest));

        let subdags = committer.commit_uncommitted_selected_chain();
        assert!(!subdags.is_empty());

        // All 4 blocks must be committed
        let all_committed_hashes: HashSet<Hash> = subdags
            .iter()
            .flat_map(|s| s.blocks.iter().map(|b| b.digest))
            .collect();
        assert!(all_committed_hashes.contains(&b0.digest));
        assert!(all_committed_hashes.contains(&b1a.digest));
        assert!(all_committed_hashes.contains(&b1b.digest));
        assert!(all_committed_hashes.contains(&b2.digest));
    }

    /// Chain extension must not walk the selected parent's past again.
    #[test]
    fn chain_extension_does_not_rescan_history() {
        let mut committer = GhostdagCommitter::new(5);
        let mut previous = make_pow_block(0, 0, vec![], 0);
        committer.add_block(previous.clone());
        assert_eq!(committer.last_mergeset_visits(), 0);
        assert_eq!(committer.tips(), vec![previous.digest]);

        for round in 1..64 {
            let block = make_pow_block(round, 0, vec![previous.reference()], round);
            committer.add_block(block.clone());
            assert_eq!(
                committer.last_mergeset_visits(),
                0,
                "round {round} walked history"
            );
            assert_eq!(committer.tips(), vec![block.digest]);
            previous = block;
        }
    }

    /// A child inserted before its parent must not leave the parent as a tip.
    #[test]
    fn tip_set_matches_parent_lists_when_parent_arrives_later() {
        let mut committer = GhostdagCommitter::new(5);
        let parent = make_pow_block(0, 0, vec![], 0);
        let child = make_pow_block(1, 1, vec![parent.reference()], 1);
        committer.add_block(child.clone());
        committer.add_block(parent.clone());
        assert_eq!(committer.tips(), vec![child.digest]);
    }

    /// Reorgs must not re-queue already committed leaders, and two committers
    /// fed the same blocks must emit the same new-leader order.
    #[test]
    fn diverged_chain_does_not_replay_committed_leaders_and_order_matches() {
        const TARGET_MS: u64 = 4_000;
        const BLOCKS: u64 = 24;
        const FORK_AT: u64 = 3;

        let mut primary = GhostdagCommitter::new(5);
        let mut secondary = GhostdagCommitter::new(5);
        let mut previous = make_pow_block(0, 0, vec![], 0);
        primary.add_block(previous.clone());
        secondary.add_block(previous.clone());

        let mut last_ts = header_timestamp(&previous);
        let mut committed = Vec::new();
        for round in 0..BLOCKS {
            let block = if round == 0 {
                previous.clone()
            } else {
                let block =
                    make_pow_block(round, (round % 3) as u16, vec![previous.reference()], round);
                primary.add_block(block.clone());
                secondary.add_block(block.clone());
                block
            };
            let left = primary.commit_uncommitted_selected_chain();
            let right = secondary.commit_uncommitted_selected_chain();
            assert_eq!(left.len(), 1, "round {round} did not commit");
            assert_eq!(leader_digests(&left), leader_digests(&right));
            assert!(!committed.contains(&left[0].leader.digest));
            let ts = header_timestamp(&block);
            if round > 0 {
                assert!(
                    ts.saturating_sub(last_ts) <= 3 * TARGET_MS,
                    "commit gap {} ms exceeds 3x target",
                    ts.saturating_sub(last_ts)
                );
            }
            last_ts = ts;
            committed.push(left[0].leader.digest);
            previous = block;
        }
        assert!(primary.commit_uncommitted_selected_chain().is_empty());
        assert_eq!(
            primary.last_commit_observation().reason,
            CommitWaitReason::TipAlreadyCommitted
        );

        // Heavier fork from round 3. The selected-parent chain contains the
        // shared prefix and not the abandoned tip, which is the walk that
        // used to re-queue every round from genesis.
        let mut anchor = make_pow_block(0, 0, vec![], 0);
        for round in 1..=FORK_AT {
            anchor = make_pow_block(round, (round % 3) as u16, vec![anchor.reference()], round);
        }
        let mut fork_parent = anchor;
        // One block longer than the abandoned suffix, so this chain wins on
        // cumulative work and on blue score.
        let mut fork_blocks = Vec::new();
        for offset in 1..=(BLOCKS - FORK_AT + 1) {
            let block = make_pow_block(
                FORK_AT + offset,
                7,
                vec![fork_parent.reference()],
                1_000 + offset,
            );
            fork_blocks.push(block.clone());
            fork_parent = block;
        }

        // Third committer sees the prefix, then the same fork. It has not
        // committed the abandoned suffix, so its first commit still contains
        // the prefix; the fork leaders must match `primary` exactly.
        let mut peer = GhostdagCommitter::new(5);
        let mut prefix = make_pow_block(0, 0, vec![], 0);
        peer.add_block(prefix.clone());
        for round in 1..=FORK_AT {
            prefix = make_pow_block(round, (round % 3) as u16, vec![prefix.reference()], round);
            peer.add_block(prefix.clone());
        }
        for block in &fork_blocks {
            primary.add_block(block.clone());
            peer.add_block(block.clone());
        }

        let again = primary.commit_uncommitted_selected_chain();
        let peer_commit = peer.commit_uncommitted_selected_chain();
        let again_digests = leader_digests(&again);
        for old in &committed {
            assert!(
                !again_digests.contains(old),
                "already committed leader was re-queued"
            );
        }
        assert_eq!(
            again_digests.len(),
            fork_blocks.len(),
            "fork commit emitted the wrong leaders: {again_digests:?}"
        );
        assert_eq!(
            primary.last_commit_observation().reason,
            CommitWaitReason::DivergedChain
        );
        assert!(primary.last_commit_observation().replayed >= 1);
        let again_rounds: Vec<u64> = again.iter().map(|sub| sub.leader_round).collect();
        let peer_fork_rounds: Vec<u64> = peer_commit
            .iter()
            .filter(|sub| sub.leader_round > FORK_AT)
            .map(|sub| sub.leader_round)
            .collect();
        assert_eq!(again_rounds, peer_fork_rounds);
        assert!(again_rounds.windows(2).all(|pair| pair[0] < pair[1]));
    }

    /// Two nodes that see competing siblings in opposite orders still commit
    /// the same leader sequence. The selected parent is work, then blue
    /// score, then digest — not arrival order.
    #[test]
    fn sibling_arrival_order_does_not_change_commit_order() {
        let genesis = make_pow_block(0, 0, vec![], 0);
        let left = make_pow_block(1, 1, vec![genesis.reference()], 1);
        let right = make_pow_block(1, 2, vec![genesis.reference()], 2);
        let merge = make_pow_block(2, 3, vec![left.reference(), right.reference()], 3);
        let tip = make_pow_block(3, 0, vec![merge.reference()], 4);

        let mut first_left = GhostdagCommitter::new(5);
        let mut first_right = GhostdagCommitter::new(5);
        for block in [&genesis, &left, &right, &merge, &tip] {
            first_left.add_block(block.clone());
        }
        for block in [&genesis, &right, &left, &merge, &tip] {
            first_right.add_block(block.clone());
        }
        let left_order = leader_digests(&first_left.commit_uncommitted_selected_chain());
        let right_order = leader_digests(&first_right.commit_uncommitted_selected_chain());
        assert_eq!(left_order, right_order);
        assert_eq!(
            left_order.len(),
            left_order
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            "a leader was committed twice"
        );
    }

    fn header_timestamp(block: &StatementBlock) -> u64 {
        1_700_000_000_000 + block.round * 4_000
    }

    fn leader_digests(subdags: &[CommittedSubDag]) -> Vec<Hash> {
        subdags.iter().map(|sub| sub.leader.digest).collect()
    }
}
