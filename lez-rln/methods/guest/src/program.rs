//! The RLN registration program: one message handler, run once per delivery
//! to one of the program's actors — the config PDA of a tree or one of its
//! membership PDAs.
//!
//! A handler sees its own actor's state and nothing else. What it needs from
//! another actor it asks for by message: the config tells a membership to
//! initialize itself, a membership tells the config to release or charge,
//! the config tells the merkle program to insert or remove a leaf and the
//! native program to move the price. Messages between the program's own
//! actors are accepted only from the actor they must come from: nothing in
//! the protocol stops a stranger from sending `InitMembership` or `Release`,
//! so each handler checks `from` before it acts.
//!
//! The two one-shot writes (`Initialize`, `InitMembership`) are guarded by an
//! empty pre-state, never by who sent them: authorization says the sender may
//! write the account, not that it is unclaimed.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, Actor, ActorState},
    native_token,
    program::{PdaSeed, ReceiveInput, Response, SyncMessage},
};
use rln_layouts::{
    ConfigState, MembershipState, MerkleMessage, Message, config_seed,
    exit::{
        EXIT_MEMBERSHIP_EXISTS, EXIT_MEMBERSHIP_MISSING, EXIT_NOT_EXPIRED,
        EXIT_NOT_IN_GRACE_PERIOD, EXIT_RATE_LIMIT_FULL,
    },
    is_expired, is_in_grace_period, main_seed, membership_seed, secs_to_millis,
};

use crate::{
    ensure,
    hash::{hash_single, validate_field_element},
    registration::{calculate_payment_amount, compute_registration_leaf, time_window},
};

// ─── PDAs ──────────────────────────────────────────────────────────────

fn pda(program: &AccountId, seed: [u8; 32]) -> AccountId {
    AccountId::for_public_pda(program, &PdaSeed::new(seed))
}

/// This program's actor at the PDA derived from `seed`.
fn own_actor(input: &ReceiveInput, seed: [u8; 32]) -> Actor {
    let program = input.receiver.program_account_id;
    Actor::new(pda(&program, seed), program)
}

// ─── checks ────────────────────────────────────────────────────────────

/// The message was delivered to this program's PDA of `seed`. Every message
/// names its tree (and member), so the PDA is re-derived from the message:
/// a message for another tree is refused by the actor it reaches.
fn require_receiver(input: &ReceiveInput, seed: [u8; 32], what: &str) {
    assert!(
        input.receiver.account_id == pda(&input.receiver.program_account_id, seed),
        "{what} message delivered to the wrong actor"
    );
}

/// The message came from `actor`, one of this program's own.
fn require_from(input: &ReceiveInput, actor: Actor, what: &str, who: &str) {
    assert!(input.from == Some(actor), "{what} may only be sent by {who}");
}

fn encode<T: BorshSerialize>(value: &T) -> Vec<u8> {
    borsh::to_vec(value).expect("borsh serialization is infallible")
}

fn decode_config(pre_state: &[u8]) -> ConfigState {
    assert!(!pre_state.is_empty(), "config not initialized");
    ConfigState::try_from_slice(pre_state).expect("decode ConfigState")
}

/// An empty state means the membership was slashed or erased since the
/// caller read it: a stale view, not a malformed transaction.
fn decode_membership(pre_state: &[u8], empty_msg: &str) -> MembershipState {
    ensure!(!pre_state.is_empty(), EXIT_MEMBERSHIP_MISSING, "{empty_msg}");
    MembershipState::try_from_slice(pre_state).expect("decode MembershipState")
}

// ─── outgoing messages ─────────────────────────────────────────────────

/// Message the merkle program on the tree's main PDA, granting it the PDA.
///
/// The callee is the config's stored `merkle_program_id` and the seed makes
/// its program the tree's writer, so only the config actor ever issues this
/// grant, and only after `require_receiver` proved it is the config.
fn merkle_message(
    input: &ReceiveInput,
    config: &ConfigState,
    tree_id: &[u8; 32],
    msg: &MerkleMessage,
) -> SyncMessage {
    let seed = main_seed(tree_id);
    let tree_main = pda(&input.receiver.program_account_id, seed);
    SyncMessage::new(
        Actor::new(tree_main, AccountId::new(config.merkle_program_id)),
        msg,
    )
    .with_pda_seeds([PdaSeed::new(seed)])
}

/// Move `amount` of the native asset from `payer` to `treasury`. The native
/// program refuses an unauthorized sender (one who did not sign) and an
/// insufficient balance; the destination is the config's treasury.
fn native_payment(payer: [u8; 32], treasury: [u8; 32], amount: u128) -> SyncMessage {
    SyncMessage::new(
        Actor::native_balance(AccountId::new(payer)),
        &native_token::Message::Transfer {
            to: AccountId::new(treasury),
            amount,
        },
    )
}

// ─── handler ───────────────────────────────────────────────────────────

/// Handle one delivered message.
///
/// Entry messages reach the config actor (`Initialize`,
/// `InitializeMerkleTree`, `Register`) or a membership actor (`Slash`,
/// `Extend`, `Erase`); the rest travel between the program's own actors.
/// Sync messages run in emission order, each to completion before the next.
pub fn handle_message(input: &ReceiveInput, msg: Message) -> Response {
    let pre_state: &[u8] = &input.pre_state;
    match msg {
        Message::Initialize {
            merkle_program_id,
            tree_id,
            price_per_unit,
            treasury_account_id,
            max_total_rate_limit,
            active_duration_for_new_memberships_sec,
            grace_period_duration_for_new_memberships_sec,
            min_rate_limit,
            max_rate_limit,
        } => {
            require_receiver(input, config_seed(&tree_id), "config");
            assert!(
                pre_state.is_empty(),
                "AccountAlreadyInitialized: config already exists"
            );
            assert!(
                max_total_rate_limit > 0,
                "Max total rate limit must be positive"
            );
            assert!(
                active_duration_for_new_memberships_sec > 0,
                "Active duration must be positive"
            );
            // A zero minimum would admit a free membership (price 0) whose
            // leaf is H(id_commitment, 0).
            assert!(min_rate_limit > 0, "Min rate limit must be positive");
            assert!(
                min_rate_limit <= max_rate_limit,
                "Min rate limit {} exceeds max rate limit {}",
                min_rate_limit,
                max_rate_limit
            );
            Response::set_state(encode(&ConfigState {
                merkle_program_id,
                tree_id,
                price_per_unit,
                treasury_account_id,
                total_registrations: 0,
                max_total_rate_limit,
                current_total_rate_limit: 0,
                active_duration_for_new_memberships_sec,
                grace_period_duration_for_new_memberships_sec,
                min_rate_limit,
                max_rate_limit,
            }))
        }
        Message::InitializeMerkleTree { tree_id } => {
            require_receiver(input, config_seed(&tree_id), "config");
            let config = decode_config(pre_state);
            // One-shot on the tree's side: the merkle program refuses a
            // non-empty state, so a replay cannot reset a live tree.
            Response::keep_state().send(merkle_message(
                input,
                &config,
                &tree_id,
                &MerkleMessage::Initialize,
            ))
        }
        Message::Register {
            tree_id,
            id_commitment,
            rate_limit,
            payer,
            now_ms,
        } => {
            require_receiver(input, config_seed(&tree_id), "config");
            let mut config = decode_config(pre_state);
            validate_field_element(&id_commitment);
            // Zero is the empty-leaf value and no identity secret hashes to it.
            assert!(id_commitment != [0u8; 32], "id_commitment must not be zero");
            // Fixed at Initialize, so an out-of-range rate is a malformed
            // transaction, not a stale view: assert, full charge.
            assert!(
                config.accepts_rate(rate_limit),
                "rate_limit {} outside the registry's {}..={}",
                rate_limit,
                config.min_rate_limit,
                config.max_rate_limit
            );
            ensure!(
                config.can_register(rate_limit),
                EXIT_RATE_LIMIT_FULL,
                "Would exceed max total rate limit"
            );
            let amount = calculate_payment_amount(rate_limit, config.price_per_unit);
            let leaf = compute_registration_leaf(&id_commitment, rate_limit);
            let membership = MembershipState {
                rate_limit,
                id_commitment,
                grace_period_start_timestamp_ms: now_ms.saturating_add(secs_to_millis(
                    config.active_duration_for_new_memberships_sec,
                )),
                active_duration_sec: config.active_duration_for_new_memberships_sec,
                grace_period_duration_sec: config.grace_period_duration_for_new_memberships_sec,
            };
            let treasury = config.treasury_account_id;
            config.total_registrations = config.total_registrations.saturating_add(1);
            config.current_total_rate_limit =
                config.current_total_rate_limit.saturating_add(rate_limit);

            // The membership write (the duplicate guard, cheap) runs before
            // the tree insert (nine Poseidons), so a duplicate costs little.
            // The tree picks the index (its `next_index`) and refuses a full
            // tree; nothing here names one, so registrations built against
            // the same tree state do not contend.
            let membership_seed = membership_seed(&tree_id, &id_commitment);
            time_window(Response::set_state(encode(&config)), now_ms)
                .send(native_payment(payer, treasury, amount))
                .send(
                    SyncMessage::new(
                        own_actor(input, membership_seed),
                        &Message::InitMembership {
                            tree_id,
                            state: membership,
                        },
                    )
                    .with_pda_seeds([PdaSeed::new(membership_seed)]),
                )
                .send(merkle_message(
                    input,
                    &config,
                    &tree_id,
                    &MerkleMessage::Insert { leaf },
                ))
        }
        // One-shot, and the only duplicate-registration guard: the membership
        // PDA is derived from the id_commitment, and neither the register
        // handler nor the merkle insert dedupes. Weaken this check and
        // re-registering a commitment silently overwrites its membership.
        Message::InitMembership { tree_id, state } => {
            require_receiver(
                input,
                membership_seed(&tree_id, &state.id_commitment),
                "membership",
            );
            require_from(
                input,
                own_actor(input, config_seed(&tree_id)),
                "InitMembership",
                "the tree's config",
            );
            ensure!(
                pre_state.is_empty(),
                EXIT_MEMBERSHIP_EXISTS,
                "AccountAlreadyInitialized: membership already exists"
            );
            Response::set_state(encode(&state))
        }
        Message::Slash {
            tree_id,
            id_commitment,
            identity_secret,
            leaf_index,
        } => {
            require_receiver(
                input,
                membership_seed(&tree_id, &id_commitment),
                "membership",
            );
            let membership = decode_membership(
                pre_state,
                "Membership account is empty - member doesn't exist or already slashed",
            );
            validate_field_element(&identity_secret);
            assert!(
                hash_single(&identity_secret) == id_commitment,
                "id_commitment arg must match hash(identity_secret)"
            );
            assert!(
                membership.id_commitment == id_commitment,
                "membership id_commitment mismatch"
            );
            // `leaf_index` is a hint; the merkle program removes it only if
            // it holds this membership's leaf, computed from the membership's
            // own rate limit.
            Response::set_state(ActorState::empty()).send(SyncMessage::new(
                own_actor(input, config_seed(&tree_id)),
                &Message::Release {
                    tree_id,
                    id_commitment,
                    rate_limit: membership.rate_limit,
                    leaf_index,
                    leaf: compute_registration_leaf(&id_commitment, membership.rate_limit),
                },
            ))
        }
        Message::Erase {
            tree_id,
            id_commitment,
            leaf_index,
            now_ms,
        } => {
            require_receiver(
                input,
                membership_seed(&tree_id, &id_commitment),
                "membership",
            );
            let membership =
                decode_membership(pre_state, "Membership account is empty - nothing to erase");
            assert!(
                membership.id_commitment == id_commitment,
                "membership id_commitment mismatch"
            );
            ensure!(
                is_expired(
                    membership.grace_period_start_timestamp_ms,
                    secs_to_millis(membership.grace_period_duration_sec),
                    now_ms,
                ),
                EXIT_NOT_EXPIRED,
                "CannotEraseUnexpiredMembership: membership has not expired yet"
            );
            time_window(Response::set_state(ActorState::empty()), now_ms).send(SyncMessage::new(
                own_actor(input, config_seed(&tree_id)),
                &Message::Release {
                    tree_id,
                    id_commitment,
                    rate_limit: membership.rate_limit,
                    leaf_index,
                    leaf: compute_registration_leaf(&id_commitment, membership.rate_limit),
                },
            ))
        }
        Message::Release {
            tree_id,
            id_commitment,
            rate_limit,
            leaf_index,
            leaf,
        } => {
            require_receiver(input, config_seed(&tree_id), "config");
            require_from(
                input,
                own_actor(input, membership_seed(&tree_id, &id_commitment)),
                "Release",
                "the member's own membership",
            );
            let mut config = decode_config(pre_state);
            config.current_total_rate_limit =
                config.current_total_rate_limit.saturating_sub(rate_limit);
            config.total_registrations = config.total_registrations.saturating_sub(1);
            Response::set_state(encode(&config)).send(merkle_message(
                input,
                &config,
                &tree_id,
                &MerkleMessage::Remove {
                    index: leaf_index,
                    leaf,
                },
            ))
        }
        // Renewal is priced, not permissioned: the membership records no
        // owner and anyone may pay for anyone's renewal, but it costs what
        // registering the same rate limit costs. `erase` reclaims a rate
        // limit only once the membership expires, so free renewal would let
        // any passer-by keep abandoned memberships alive one tx per grace
        // window and pin `current_total_rate_limit` at its maximum.
        Message::Extend {
            tree_id,
            id_commitment,
            payer,
            now_ms,
        } => {
            require_receiver(
                input,
                membership_seed(&tree_id, &id_commitment),
                "membership",
            );
            let mut membership = decode_membership(
                pre_state,
                "Membership account is empty - cannot extend a non-existent membership",
            );
            assert!(
                membership.id_commitment == id_commitment,
                "membership id_commitment mismatch"
            );
            ensure!(
                is_in_grace_period(
                    membership.grace_period_start_timestamp_ms,
                    secs_to_millis(membership.grace_period_duration_sec),
                    now_ms,
                ),
                EXIT_NOT_IN_GRACE_PERIOD,
                "CannotExtendNonGracePeriodMembership: membership is not in its grace period"
            );
            membership.grace_period_start_timestamp_ms = membership
                .grace_period_start_timestamp_ms
                .saturating_add(secs_to_millis(membership.grace_period_duration_sec))
                .saturating_add(secs_to_millis(membership.active_duration_sec));
            let rate_limit = membership.rate_limit;
            time_window(Response::set_state(encode(&membership)), now_ms).send(SyncMessage::new(
                own_actor(input, config_seed(&tree_id)),
                &Message::ChargeRenewal {
                    tree_id,
                    id_commitment,
                    rate_limit,
                    payer,
                },
            ))
        }
        Message::ChargeRenewal {
            tree_id,
            id_commitment,
            rate_limit,
            payer,
        } => {
            require_receiver(input, config_seed(&tree_id), "config");
            require_from(
                input,
                own_actor(input, membership_seed(&tree_id, &id_commitment)),
                "ChargeRenewal",
                "the member's own membership",
            );
            let config = decode_config(pre_state);
            Response::keep_state().send(native_payment(
                payer,
                config.treasury_account_id,
                calculate_payment_amount(rate_limit, config.price_per_unit),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use lee_core::native_token::NATIVE_TOKEN_PROGRAM_ID;
    use rln_layouts::CLOCK_CLAIM_TOLERANCE_MS;

    use super::*;

    const TREE_ID: [u8; 32] = [0x11; 32];
    const MERKLE: [u8; 32] = [0x22; 32];
    const TREASURY: [u8; 32] = [0x33; 32];
    const PAYER: [u8; 32] = [0x44; 32];
    const PRICE: u128 = 10;
    const ACTIVE_SEC: u32 = 100;
    const GRACE_SEC: u32 = 50;
    const NOW_MS: u64 = 1_000_000;
    const RATE: u64 = 200;
    const MIN_RATE: u64 = 100;
    const MAX_RATE: u64 = 600;

    fn registration_program() -> AccountId {
        AccountId::new([0x55; 32])
    }

    fn config_actor() -> Actor {
        Actor::new(
            pda(&registration_program(), config_seed(&TREE_ID)),
            registration_program(),
        )
    }

    fn membership_actor(id_commitment: &[u8; 32]) -> Actor {
        Actor::new(
            pda(&registration_program(), membership_seed(&TREE_ID, id_commitment)),
            registration_program(),
        )
    }

    fn tree_actor() -> Actor {
        Actor::new(
            pda(&registration_program(), main_seed(&TREE_ID)),
            AccountId::new(MERKLE),
        )
    }

    fn stranger() -> Actor {
        Actor::new(AccountId::new([0x99; 32]), AccountId::new([0x98; 32]))
    }

    /// A valid, non-zero BN254 field element.
    fn commitment() -> [u8; 32] {
        let mut c = [0u8; 32];
        c[0] = 42;
        c
    }

    fn config_state() -> ConfigState {
        ConfigState {
            merkle_program_id: MERKLE,
            tree_id: TREE_ID,
            price_per_unit: PRICE,
            treasury_account_id: TREASURY,
            total_registrations: 3,
            max_total_rate_limit: 1_000,
            current_total_rate_limit: 600,
            active_duration_for_new_memberships_sec: ACTIVE_SEC,
            grace_period_duration_for_new_memberships_sec: GRACE_SEC,
            min_rate_limit: MIN_RATE,
            max_rate_limit: MAX_RATE,
        }
    }

    fn membership_state(grace_start_ms: u64) -> MembershipState {
        MembershipState {
            rate_limit: RATE,
            id_commitment: commitment(),
            grace_period_start_timestamp_ms: grace_start_ms,
            active_duration_sec: ACTIVE_SEC,
            grace_period_duration_sec: GRACE_SEC,
        }
    }

    fn receive<T: BorshSerialize>(receiver: Actor, from: Option<Actor>, pre: &T) -> ReceiveInput {
        ReceiveInput {
            receiver,
            from,
            is_authorized: false,
            pre_state: ActorState::from(encode(pre)),
            message: Vec::new(),
        }
    }

    fn empty(receiver: Actor, from: Option<Actor>) -> ReceiveInput {
        ReceiveInput {
            receiver,
            from,
            is_authorized: false,
            pre_state: ActorState::empty(),
            message: Vec::new(),
        }
    }

    fn initialize() -> Message {
        Message::Initialize {
            merkle_program_id: MERKLE,
            tree_id: TREE_ID,
            price_per_unit: PRICE,
            treasury_account_id: TREASURY,
            max_total_rate_limit: 1_000,
            active_duration_for_new_memberships_sec: ACTIVE_SEC,
            grace_period_duration_for_new_memberships_sec: GRACE_SEC,
            min_rate_limit: MIN_RATE,
            max_rate_limit: MAX_RATE,
        }
    }

    fn register(rate_limit: u64) -> Message {
        Message::Register {
            tree_id: TREE_ID,
            id_commitment: commitment(),
            rate_limit,
            payer: PAYER,
            now_ms: NOW_MS,
        }
    }

    fn merkle_to_tree(msg: &MerkleMessage) -> SyncMessage {
        SyncMessage::new(tree_actor(), msg).with_pda_seeds([PdaSeed::new(main_seed(&TREE_ID))])
    }

    fn payment(amount: u128) -> SyncMessage {
        SyncMessage::new(
            Actor::native_balance(AccountId::new(PAYER)),
            &native_token::Message::Transfer {
                to: AccountId::new(TREASURY),
                amount,
            },
        )
    }

    fn post_state(response: &Response) -> Vec<u8> {
        response
            .post_state
            .clone()
            .expect("the handler wrote a state")
            .into_inner()
    }

    fn assert_window(response: &Response, now_ms: u64) {
        assert_eq!(response.validity.timestamps.start(), Some(now_ms));
        assert_eq!(
            response.validity.timestamps.end(),
            Some(now_ms + CLOCK_CLAIM_TOLERANCE_MS)
        );
        assert_eq!(response.validity.blocks.start(), None);
        assert_eq!(response.validity.blocks.end(), None);
    }

    fn assert_unbounded(response: &Response) {
        assert_eq!(response.validity.timestamps.start(), None);
        assert_eq!(response.validity.timestamps.end(), None);
    }

    // ─── Initialize ────────────────────────────────────────────────────

    #[test]
    fn initialize_writes_the_config_and_sends_nothing() {
        let response = handle_message(&empty(config_actor(), None), initialize());
        let mut expected = config_state();
        expected.total_registrations = 0;
        expected.current_total_rate_limit = 0;
        assert_eq!(post_state(&response), encode(&expected));
        assert!(response.sync_messages.is_empty());
        assert!(response.async_messages.is_empty());
        assert_unbounded(&response);
    }

    #[test]
    #[should_panic(expected = "config message delivered to the wrong actor")]
    fn initialize_refuses_a_foreign_actor() {
        let _ = handle_message(&empty(stranger(), None), initialize());
    }

    #[test]
    #[should_panic(expected = "config already exists")]
    fn initialize_refuses_a_replay() {
        let _ = handle_message(&receive(config_actor(), None, &config_state()), initialize());
    }

    fn initialize_with(min_rate_limit: u64, max_rate_limit: u64) -> Message {
        let Message::Initialize {
            merkle_program_id,
            tree_id,
            price_per_unit,
            treasury_account_id,
            max_total_rate_limit,
            active_duration_for_new_memberships_sec,
            grace_period_duration_for_new_memberships_sec,
            ..
        } = initialize()
        else {
            unreachable!()
        };
        Message::Initialize {
            merkle_program_id,
            tree_id,
            price_per_unit,
            treasury_account_id,
            max_total_rate_limit,
            active_duration_for_new_memberships_sec,
            grace_period_duration_for_new_memberships_sec,
            min_rate_limit,
            max_rate_limit,
        }
    }

    #[test]
    #[should_panic(expected = "Min rate limit must be positive")]
    fn initialize_rejects_zero_min_rate() {
        let _ = handle_message(&empty(config_actor(), None), initialize_with(0, MAX_RATE));
    }

    #[test]
    #[should_panic(expected = "Min rate limit 601 exceeds max rate limit 600")]
    fn initialize_rejects_min_above_max() {
        let _ = handle_message(
            &empty(config_actor(), None),
            initialize_with(MAX_RATE + 1, MAX_RATE),
        );
    }

    // ─── InitializeMerkleTree ──────────────────────────────────────────

    #[test]
    fn initialize_merkle_tree_grants_the_main_pda_to_the_stored_program() {
        let response = handle_message(
            &receive(config_actor(), None, &config_state()),
            Message::InitializeMerkleTree { tree_id: TREE_ID },
        );
        assert_eq!(response.post_state, None);
        assert_eq!(
            response.sync_messages,
            vec![merkle_to_tree(&MerkleMessage::Initialize)]
        );
    }

    #[test]
    #[should_panic(expected = "config not initialized")]
    fn initialize_merkle_tree_needs_a_config() {
        let _ = handle_message(
            &empty(config_actor(), None),
            Message::InitializeMerkleTree { tree_id: TREE_ID },
        );
    }

    // ─── Register ──────────────────────────────────────────────────────

    #[test]
    fn register_counts_pays_inits_the_membership_then_inserts() {
        let response = handle_message(&receive(config_actor(), None, &config_state()), register(RATE));

        let mut expected = config_state();
        expected.total_registrations += 1;
        expected.current_total_rate_limit += RATE;
        assert_eq!(post_state(&response), encode(&expected));
        assert_window(&response, NOW_MS);

        let membership = membership_state(NOW_MS + secs_to_millis(ACTIVE_SEC));
        let seed = membership_seed(&TREE_ID, &commitment());
        assert_eq!(
            response.sync_messages,
            vec![
                payment(RATE as u128 * PRICE),
                SyncMessage::new(
                    membership_actor(&commitment()),
                    &Message::InitMembership {
                        tree_id: TREE_ID,
                        state: membership,
                    },
                )
                .with_pda_seeds([PdaSeed::new(seed)]),
                merkle_to_tree(&MerkleMessage::Insert {
                    leaf: compute_registration_leaf(&commitment(), RATE),
                }),
            ]
        );
        assert!(response.async_messages.is_empty());
    }

    #[test]
    fn register_accepts_rates_at_both_bounds() {
        let mut roomy = config_state();
        roomy.current_total_rate_limit = 0;
        for rate in [MIN_RATE, MAX_RATE] {
            let response = handle_message(&receive(config_actor(), None, &roomy), register(rate));
            let mut expected = roomy.clone();
            expected.total_registrations += 1;
            expected.current_total_rate_limit += rate;
            assert_eq!(post_state(&response), encode(&expected));
        }
    }

    #[test]
    #[should_panic(expected = "rate_limit 99 outside the registry's 100..=600")]
    fn register_rejects_a_rate_below_min() {
        let _ = handle_message(
            &receive(config_actor(), None, &config_state()),
            register(MIN_RATE - 1),
        );
    }

    #[test]
    #[should_panic(expected = "rate_limit 601 outside the registry's 100..=600")]
    fn register_rejects_a_rate_above_max() {
        let _ = handle_message(
            &receive(config_actor(), None, &config_state()),
            register(MAX_RATE + 1),
        );
    }

    #[test]
    #[should_panic(expected = "exit 13: Would exceed max total rate limit")]
    fn register_refuses_over_capacity() {
        let mut full = config_state();
        full.current_total_rate_limit = 900;
        let _ = handle_message(&receive(config_actor(), None, &full), register(RATE));
    }

    #[test]
    #[should_panic(expected = "id_commitment must not be zero")]
    fn register_rejects_a_zero_commitment() {
        let _ = handle_message(
            &receive(config_actor(), None, &config_state()),
            Message::Register {
                tree_id: TREE_ID,
                id_commitment: [0; 32],
                rate_limit: RATE,
                payer: PAYER,
                now_ms: NOW_MS,
            },
        );
    }

    #[test]
    #[should_panic(expected = "not a valid BN254 field element")]
    fn register_rejects_a_non_field_commitment() {
        let _ = handle_message(
            &receive(config_actor(), None, &config_state()),
            Message::Register {
                tree_id: TREE_ID,
                id_commitment: [0xff; 32],
                rate_limit: RATE,
                payer: PAYER,
                now_ms: NOW_MS,
            },
        );
    }

    #[test]
    #[should_panic(expected = "config message delivered to the wrong actor")]
    fn register_refuses_another_trees_config() {
        let other = Actor::new(
            pda(&registration_program(), config_seed(&[0x12; 32])),
            registration_program(),
        );
        let _ = handle_message(&receive(other, None, &config_state()), register(RATE));
    }

    // ─── InitMembership ────────────────────────────────────────────────

    fn init_membership() -> Message {
        Message::InitMembership {
            tree_id: TREE_ID,
            state: membership_state(7),
        }
    }

    #[test]
    fn init_membership_writes_once_from_the_config() {
        let response = handle_message(
            &empty(membership_actor(&commitment()), Some(config_actor())),
            init_membership(),
        );
        assert_eq!(post_state(&response), encode(&membership_state(7)));
        assert!(response.sync_messages.is_empty());
    }

    #[test]
    #[should_panic(expected = "InitMembership may only be sent by the tree's config")]
    fn init_membership_refuses_a_stranger() {
        let _ = handle_message(
            &empty(membership_actor(&commitment()), Some(stranger())),
            init_membership(),
        );
    }

    #[test]
    #[should_panic(expected = "InitMembership may only be sent by the tree's config")]
    fn init_membership_refuses_a_root_message() {
        let _ = handle_message(&empty(membership_actor(&commitment()), None), init_membership());
    }

    #[test]
    #[should_panic(expected = "exit 14: AccountAlreadyInitialized: membership already exists")]
    fn init_membership_refuses_a_duplicate() {
        let _ = handle_message(
            &receive(
                membership_actor(&commitment()),
                Some(config_actor()),
                &membership_state(7),
            ),
            init_membership(),
        );
    }

    #[test]
    #[should_panic(expected = "membership message delivered to the wrong actor")]
    fn init_membership_refuses_another_members_pda() {
        let _ = handle_message(
            &empty(membership_actor(&[9; 32]), Some(config_actor())),
            init_membership(),
        );
    }

    // ─── Slash / Release ───────────────────────────────────────────────

    /// `secret` such that `hash_single(secret) == commitment` is what a real
    /// slash needs; the tests derive the commitment from a secret instead.
    fn secret() -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = 7;
        s
    }

    fn slash() -> (Message, [u8; 32]) {
        let idc = hash_single(&secret());
        (
            Message::Slash {
                tree_id: TREE_ID,
                id_commitment: idc,
                identity_secret: secret(),
                leaf_index: 4,
            },
            idc,
        )
    }

    fn member_with(idc: [u8; 32], grace_start_ms: u64) -> MembershipState {
        MembershipState {
            id_commitment: idc,
            ..membership_state(grace_start_ms)
        }
    }

    #[test]
    fn slash_clears_the_membership_and_asks_the_config_to_release() {
        let (msg, idc) = slash();
        let response = handle_message(
            &receive(membership_actor(&idc), None, &member_with(idc, 7)),
            msg,
        );
        assert_eq!(post_state(&response), Vec::<u8>::new());
        assert_eq!(
            response.sync_messages,
            vec![SyncMessage::new(
                config_actor(),
                &Message::Release {
                    tree_id: TREE_ID,
                    id_commitment: idc,
                    rate_limit: RATE,
                    leaf_index: 4,
                    leaf: compute_registration_leaf(&idc, RATE),
                },
            )]
        );
        assert_unbounded(&response);
    }

    #[test]
    #[should_panic(expected = "exit 15: Membership account is empty")]
    fn slash_refuses_a_missing_membership() {
        let (msg, idc) = slash();
        let _ = handle_message(&empty(membership_actor(&idc), None), msg);
    }

    #[test]
    #[should_panic(expected = "id_commitment arg must match hash(identity_secret)")]
    fn slash_rejects_a_wrong_secret() {
        let (msg, idc) = slash();
        let Message::Slash {
            tree_id,
            id_commitment,
            leaf_index,
            ..
        } = msg
        else {
            unreachable!()
        };
        let mut wrong = secret();
        wrong[1] = 1;
        let _ = handle_message(
            &receive(membership_actor(&idc), None, &member_with(idc, 7)),
            Message::Slash {
                tree_id,
                id_commitment,
                identity_secret: wrong,
                leaf_index,
            },
        );
    }

    fn release(idc: [u8; 32]) -> Message {
        Message::Release {
            tree_id: TREE_ID,
            id_commitment: idc,
            rate_limit: RATE,
            leaf_index: 4,
            leaf: compute_registration_leaf(&idc, RATE),
        }
    }

    #[test]
    fn release_uncounts_and_removes_the_leaf() {
        let idc = commitment();
        let response = handle_message(
            &receive(config_actor(), Some(membership_actor(&idc)), &config_state()),
            release(idc),
        );
        let mut expected = config_state();
        expected.total_registrations -= 1;
        expected.current_total_rate_limit -= RATE;
        assert_eq!(post_state(&response), encode(&expected));
        assert_eq!(
            response.sync_messages,
            vec![merkle_to_tree(&MerkleMessage::Remove {
                index: 4,
                leaf: compute_registration_leaf(&idc, RATE),
            })]
        );
    }

    #[test]
    #[should_panic(expected = "Release may only be sent by the member's own membership")]
    fn release_refuses_another_membership() {
        let _ = handle_message(
            &receive(config_actor(), Some(membership_actor(&[9; 32])), &config_state()),
            release(commitment()),
        );
    }

    #[test]
    #[should_panic(expected = "Release may only be sent by the member's own membership")]
    fn release_refuses_a_root_message() {
        let _ = handle_message(
            &receive(config_actor(), None, &config_state()),
            release(commitment()),
        );
    }

    // ─── Extend / ChargeRenewal ────────────────────────────────────────

    fn extend(now_ms: u64) -> Message {
        Message::Extend {
            tree_id: TREE_ID,
            id_commitment: commitment(),
            payer: PAYER,
            now_ms,
        }
    }

    #[test]
    fn extend_in_grace_renews_and_asks_the_config_to_charge() {
        let grace_start = NOW_MS - 10;
        let response = handle_message(
            &receive(
                membership_actor(&commitment()),
                None,
                &membership_state(grace_start),
            ),
            extend(NOW_MS),
        );
        let mut expected = membership_state(grace_start);
        expected.grace_period_start_timestamp_ms +=
            secs_to_millis(GRACE_SEC) + secs_to_millis(ACTIVE_SEC);
        assert_eq!(post_state(&response), encode(&expected));
        assert_window(&response, NOW_MS);
        assert_eq!(
            response.sync_messages,
            vec![SyncMessage::new(
                config_actor(),
                &Message::ChargeRenewal {
                    tree_id: TREE_ID,
                    id_commitment: commitment(),
                    rate_limit: RATE,
                    payer: PAYER,
                },
            )]
        );
    }

    #[test]
    #[should_panic(expected = "exit 17: CannotExtendNonGracePeriodMembership")]
    fn extend_refuses_outside_the_grace_period() {
        let _ = handle_message(
            &receive(
                membership_actor(&commitment()),
                None,
                &membership_state(NOW_MS + 1),
            ),
            extend(NOW_MS),
        );
    }

    #[test]
    #[should_panic(expected = "exit 15: Membership account is empty")]
    fn extend_refuses_a_missing_membership() {
        let _ = handle_message(&empty(membership_actor(&commitment()), None), extend(NOW_MS));
    }

    fn charge_renewal() -> Message {
        Message::ChargeRenewal {
            tree_id: TREE_ID,
            id_commitment: commitment(),
            rate_limit: RATE,
            payer: PAYER,
        }
    }

    #[test]
    fn charge_renewal_moves_the_price_to_the_stored_treasury() {
        let response = handle_message(
            &receive(
                config_actor(),
                Some(membership_actor(&commitment())),
                &config_state(),
            ),
            charge_renewal(),
        );
        assert_eq!(response.post_state, None);
        assert_eq!(response.sync_messages, vec![payment(RATE as u128 * PRICE)]);
        assert_eq!(
            response.sync_messages[0].to.program_account_id,
            NATIVE_TOKEN_PROGRAM_ID
        );
    }

    #[test]
    #[should_panic(expected = "ChargeRenewal may only be sent by the member's own membership")]
    fn charge_renewal_refuses_a_stranger() {
        let _ = handle_message(
            &receive(config_actor(), Some(stranger()), &config_state()),
            charge_renewal(),
        );
    }

    // ─── Erase ─────────────────────────────────────────────────────────

    fn erase(now_ms: u64) -> Message {
        Message::Erase {
            tree_id: TREE_ID,
            id_commitment: commitment(),
            leaf_index: 4,
            now_ms,
        }
    }

    #[test]
    fn erase_after_expiry_clears_and_releases() {
        let grace_start = NOW_MS - secs_to_millis(GRACE_SEC);
        let response = handle_message(
            &receive(
                membership_actor(&commitment()),
                None,
                &membership_state(grace_start),
            ),
            erase(NOW_MS),
        );
        assert_eq!(post_state(&response), Vec::<u8>::new());
        assert_window(&response, NOW_MS);
        assert_eq!(
            response.sync_messages,
            vec![SyncMessage::new(config_actor(), &release(commitment()))]
        );
    }

    #[test]
    #[should_panic(expected = "exit 18: CannotEraseUnexpiredMembership")]
    fn erase_refuses_an_unexpired_membership() {
        let grace_start = NOW_MS - secs_to_millis(GRACE_SEC) + 1;
        let _ = handle_message(
            &receive(
                membership_actor(&commitment()),
                None,
                &membership_state(grace_start),
            ),
            erase(NOW_MS),
        );
    }
}
