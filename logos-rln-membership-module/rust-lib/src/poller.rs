//! Confirmation + lifecycle poller: one detached thread (the sibling
//! module's broadcast-thread pattern — no SDK timer exists) that
//!
//! 1. every tick (15s), re-reads each `pending` membership from its
//!    registry: observed ⇒ pending→active with the AUTHORITATIVE
//!    leaf_index + rate_limit re-read into the store (spec MUST — the
//!    submit-time values are estimates); not observed past the
//!    confirmation window ⇒ pending→failed. A provider failure leaves the
//!    record pending — an unreachable registry proves nothing about the
//!    submission, and idempotent re-registration keeps the failure path
//!    safe either way.
//! 2. every 4th tick (60s), refreshes non-terminal states
//!    (active/grace_period/expired transitions come from the registry's
//!    chain clock; a previously-observed record the registry no longer has
//!    ⇒ erased — the involuntary-removal signal consumers must see).
//!
//! Runs whether or not the keystore is unlocked: everything here touches
//! only plaintext-safe sidecar metadata. All provider calls from this
//! thread take `provider_call`'s async+channel path automatically (owner
//! -thread contract). The thread never dies: each tick body runs under
//! `catch_unwind` (pure Rust, no FFI frames — safe to catch).

use std::sync::Once;
use std::time::Duration;

use crate::provider::provider_for;
use crate::registry_id;
use crate::store::{self, MembershipMeta, CONFIRMATION_WINDOW_SECS, ST_ERASED, ST_FAILED};

const TICK: Duration = Duration::from_secs(15);
const REFRESH_EVERY: u32 = 4;

static POLLER: Once = Once::new();

/// Idempotent: the first call (register's Pending write, or
/// `on_context_ready` when persisted pending records exist) spawns the
/// thread; later calls are no-ops.
pub(crate) fn ensure_running() {
    POLLER.call_once(|| {
        std::thread::spawn(|| {
            let mut tick_no: u32 = 0;
            loop {
                std::thread::sleep(TICK);
                tick_no = tick_no.wrapping_add(1);
                let refresh = tick_no.is_multiple_of(REFRESH_EVERY);
                if let Err(payload) = std::panic::catch_unwind(|| tick(refresh)) {
                    eprintln!("membership poller: tick panicked: {payload:?}");
                }
            }
        });
    });
}

/// One registry read for one record; returns the update to apply, or None
/// to leave the record untouched (provider failure).
fn observe(meta: &MembershipMeta) -> Option<RecordUpdate> {
    let registry = match registry_id::parse(&meta.registry_id) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("membership poller: bad stored registry_id {}: {e}", meta.registry_id);
            return None;
        }
    };
    let provider = provider_for(&registry.namespace)?;
    match provider.get_membership(&registry, &meta.identity_commitment) {
        Ok(pm) if pm.registered => Some(RecordUpdate::Observed {
            state: pm.state,
            leaf_index: pm.leaf_index,
            rate_limit: pm.rate_limit,
        }),
        Ok(_) => Some(RecordUpdate::Absent),
        Err(e) => {
            eprintln!(
                "membership poller: {} read failed: {}",
                meta.registry_id, e.message
            );
            None
        }
    }
}

enum RecordUpdate {
    Observed {
        state: String,
        leaf_index: u64,
        rate_limit: u64,
    },
    Absent,
}

/// Confirm/refresh write shared by both Observed branches: record the
/// registry's authoritative state/leaf_index/rate_limit and clear any
/// failed_reason. On the refresh path failed_reason is already None (records
/// there are active/grace/expired), so clearing it is behavior-neutral.
fn apply_observed(
    hash: &str,
    state: &str,
    leaf_index: u64,
    rate_limit: u64,
) -> Result<(), crate::ApiError> {
    store::with_store(|s| {
        s.update(hash, |m| {
            m.state = state.to_string();
            m.leaf_index = leaf_index;
            m.rate_limit = rate_limit;
            m.failed_reason = None;
        })
    })
}

fn tick(refresh_states: bool) {
    let pending = match store::with_store(|s| Ok(s.pending_records())) {
        Ok(records) => records,
        // Store not initialized (no persistence path) — nothing to poll.
        Err(_) => return,
    };
    let now = crate::now_unix();
    for (hash, meta) in pending {
        match observe(&meta) {
            Some(RecordUpdate::Observed {
                state,
                leaf_index,
                rate_limit,
            }) => match apply_observed(&hash, &state, leaf_index, rate_limit) {
                Err(e) => {
                    eprintln!("membership poller: confirm update failed: {}", e.message)
                }
                Ok(()) => eprintln!(
                    "membership poller: {hash} confirmed {state} at leaf {leaf_index}"
                ),
            },
            Some(RecordUpdate::Absent)
                if now.saturating_sub(meta.submitted_at) > CONFIRMATION_WINDOW_SECS =>
            {
                let result = store::with_store(|s| {
                    s.update(&hash, |m| {
                        m.state = ST_FAILED.to_string();
                        m.failed_reason = Some("confirmation_window_elapsed".to_string());
                    })
                });
                if let Err(e) = result {
                    eprintln!("membership poller: fail update failed: {}", e.message);
                } else {
                    eprintln!("membership poller: {hash} failed (window elapsed)");
                }
            }
            _ => {}
        }
    }

    if !refresh_states {
        return;
    }
    let refreshable = match store::with_store(|s| Ok(s.refreshable_records())) {
        Ok(records) => records,
        Err(_) => return,
    };
    for (hash, meta) in refreshable {
        match observe(&meta) {
            Some(RecordUpdate::Observed { state, leaf_index, rate_limit }) => {
                let _ = apply_observed(&hash, &state, leaf_index, rate_limit);
            }
            Some(RecordUpdate::Absent) => {
                // Was on the registry (state ∈ active/grace/expired), now
                // gone: erased/slashed. Consumers MUST stop using it.
                let _ = store::with_store(|s| {
                    s.update(&hash, |m| {
                        m.state = ST_ERASED.to_string();
                        m.failed_reason = Some("removed_from_registry".to_string());
                    })
                });
                eprintln!("membership poller: {hash} vanished from registry — erased");
            }
            None => {}
        }
    }
}
