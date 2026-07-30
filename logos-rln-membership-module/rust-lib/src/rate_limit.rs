//! Rate-limit tracking: epoch derivation and per-application `message_id`
//! allocation — the security-critical state the spec's rate-limiting portion
//! rests on.
//!
//! Two proofs that reuse an `(epoch, message_id)` pair under one external
//! nullifier expose Shamir shares that reconstruct the identity secret (which,
//! on a slashing registry, burns the credential). So the allocator MUST never
//! hand out the same slot twice — including across a process restart. This
//! module owns the pure allocation algorithm; the store persists the result
//! **before** the proof is returned (see `store::reserve_message_id`), so a
//! crash after issuing a proof but before persisting can only ever *waste* a
//! slot, never reuse one.
//!
//! Granularity: the external nullifier is `poseidon(epoch, rln_identifier)`,
//! so the same `message_id` is safe to reuse across different applications
//! (distinct `rln_identifier`s) but never within one. Allocation is therefore
//! keyed by `(rln_identifier, epoch)`. A membership belongs to one registry,
//! so every application using it shares that registry's `epoch_size` and thus
//! the same epoch index at a given instant — a new epoch prunes all prior rows.
//! The index's wire encoding (the spec's `epoch[32]`) lives in the proof
//! engine (`proof::epoch_to_bytes`); this module deals only in the `u64`.

use serde::{Deserialize, Serialize};

/// One application's slot usage within one epoch, persisted in the membership
/// sidecar (plaintext-safe — counters, no secret). `used` is both the count
/// issued and the next unused `message_id`.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub(crate) struct EpochAllocation {
    /// The application scope, lowercase hex of the 32-byte `rln_identifier`.
    pub(crate) rln_identifier: String,
    /// The epoch index these slots were issued in.
    pub(crate) epoch: u64,
    /// Next unused `message_id` (== slots already issued this epoch).
    pub(crate) used: u64,
}

/// Outcome of a reservation attempt that did not yield a slot.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AllocError {
    /// The epoch's `rate_limit` slots are all spent; retry next epoch.
    BudgetExhausted,
}

/// The current epoch index: `floor(now_unix / epoch_size_sec)` — the ONE
/// place the division (and its zero-size guard) lives.
///
/// Wall-clock based, following nwaku's `nonce_manager` convention. Verifiers
/// MUST share the same `epoch_size` and time base — per the spec's Appendix A
/// the `logos` time base is the on-chain clock; which time source feeds this
/// is a `start()` configuration item, not hard-coded here.
pub(crate) fn current_epoch(now_unix: u64, epoch_size_sec: u64) -> u64 {
    now_unix / epoch_size_sec.max(1)
}

/// Reserve the next `message_id` for `(rln_identifier, epoch)` within
/// `rate_limit`, mutating `allocations` in place. A new epoch resets every
/// application's budget (stale rows are pruned first). Returns the slot, or
/// `BudgetExhausted` when the epoch's budget is spent.
///
/// The caller MUST durably persist `allocations` before using the returned
/// slot — the whole point of the pre-persist ordering.
pub(crate) fn reserve_slot(
    allocations: &mut Vec<EpochAllocation>,
    rln_identifier_hex: &str,
    epoch: u64,
    rate_limit: u64,
) -> Result<u64, AllocError> {
    // All live applications share this membership's epoch, so anything from a
    // different epoch is stale — dropping it bounds the row count to the set
    // of applications active in the current epoch.
    allocations.retain(|a| a.epoch == epoch);

    if let Some(row) = allocations
        .iter_mut()
        .find(|a| a.rln_identifier == rln_identifier_hex)
    {
        if row.used >= rate_limit {
            return Err(AllocError::BudgetExhausted);
        }
        let slot = row.used;
        row.used += 1;
        return Ok(slot);
    }

    if rate_limit == 0 {
        return Err(AllocError::BudgetExhausted);
    }
    allocations.push(EpochAllocation {
        rln_identifier: rln_identifier_hex.to_string(),
        epoch,
        used: 1,
    });
    Ok(0)
}

/// Remaining slots for `(rln_identifier, epoch)` under `rate_limit` — the
/// quota read's current-epoch budget. A no-op read: never mutates.
pub(crate) fn remaining(
    allocations: &[EpochAllocation],
    rln_identifier_hex: &str,
    epoch: u64,
    rate_limit: u64,
) -> u64 {
    let used = allocations
        .iter()
        .find(|a| a.rln_identifier == rln_identifier_hex && a.epoch == epoch)
        .map(|a| a.used)
        .unwrap_or(0);
    rate_limit.saturating_sub(used)
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP_A: &str = "aa";
    const APP_B: &str = "bb";

    #[test]
    fn epoch_is_floor_division() {
        assert_eq!(current_epoch(0, 600), 0);
        assert_eq!(current_epoch(599, 600), 0);
        assert_eq!(current_epoch(600, 600), 1);
        assert_eq!(current_epoch(1_250, 600), 2);
        // A zero size never divides by zero.
        assert_eq!(current_epoch(5, 0), 5);
    }

    #[test]
    fn slots_increment_from_zero_then_exhaust() {
        let mut allocs = Vec::new();
        assert_eq!(reserve_slot(&mut allocs, APP_A, 1, 3), Ok(0));
        assert_eq!(reserve_slot(&mut allocs, APP_A, 1, 3), Ok(1));
        assert_eq!(reserve_slot(&mut allocs, APP_A, 1, 3), Ok(2));
        assert_eq!(
            reserve_slot(&mut allocs, APP_A, 1, 3),
            Err(AllocError::BudgetExhausted)
        );
        assert_eq!(remaining(&allocs, APP_A, 1, 3), 0);
    }

    #[test]
    fn new_epoch_resets_budget_and_prunes() {
        let mut allocs = Vec::new();
        assert_eq!(reserve_slot(&mut allocs, APP_A, 1, 2), Ok(0));
        assert_eq!(reserve_slot(&mut allocs, APP_A, 1, 2), Ok(1));
        // Advancing the epoch prunes the old row and starts fresh at 0.
        assert_eq!(reserve_slot(&mut allocs, APP_A, 2, 2), Ok(0));
        assert_eq!(allocs.len(), 1);
        assert_eq!(allocs[0].epoch, 2);
        assert_eq!(remaining(&allocs, APP_A, 2, 2), 1);
    }

    #[test]
    fn applications_are_independent_within_an_epoch() {
        let mut allocs = Vec::new();
        assert_eq!(reserve_slot(&mut allocs, APP_A, 1, 2), Ok(0));
        assert_eq!(reserve_slot(&mut allocs, APP_B, 1, 2), Ok(0));
        assert_eq!(reserve_slot(&mut allocs, APP_A, 1, 2), Ok(1));
        assert_eq!(reserve_slot(&mut allocs, APP_B, 1, 2), Ok(1));
        assert_eq!(allocs.len(), 2);
        assert_eq!(remaining(&allocs, APP_A, 1, 2), 0);
        assert_eq!(remaining(&allocs, APP_B, 1, 2), 0);
    }

    #[test]
    fn zero_rate_limit_never_allocates() {
        let mut allocs = Vec::new();
        assert_eq!(
            reserve_slot(&mut allocs, APP_A, 1, 0),
            Err(AllocError::BudgetExhausted)
        );
    }

    #[test]
    fn remaining_before_any_allocation_is_full() {
        let allocs = Vec::new();
        assert_eq!(remaining(&allocs, APP_A, 1, 100), 100);
    }
}
