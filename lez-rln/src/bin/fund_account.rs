//! Transfer native balance from this deployment's payer to another account.
//!
//! The one thing a node cannot do for itself. `liblogos_lez_rln_module` derives
//! a payer at bring-up and publishes it, but no program can mint native
//! balance — it enters an account only at genesis, over the L1 bridge, or by a
//! transfer from something already funded. This is that transfer.
//!
//! It lives here rather than in the harness because the harness would otherwise
//! have to rebuild a `lee::public_transaction::Message`, its nonces and the
//! `FeeDeclaration`, and sign it — a wire format that changes with the chain.
//! Funding stays the caller's decision; only the signing is kept in Rust,
//! beside `mint_payer` and `run_setup`, which the same caller runs.
//!
//! ```bash
//! LEE_WALLET_HOME_DIR=<dir> LEZ_RLN_PAYER=<from> \
//!   cargo run --release --bin fund_account -- --to <account-id> --amount <u128>
//! LEE_WALLET_HOME_DIR=<dir> LEZ_RLN_PAYER=<from> \
//!   cargo run --release --bin fund_account -- --to-public-key <66 hex> --amount <u128>
//! ```
//!
//! A credit lands only on an account the chain admits: one that exists, or
//! one whose initial key the transaction presents. `--to` serves an account
//! that already exists on chain (or whose secret this wallet holds); an
//! account that has never been written needs `--to-public-key`, which takes
//! the initial key as `mint_payer` prints it.
//!
//! The amount is atomic units. Budget `rate_limit x price_per_unit` plus the
//! fee reserve (~6.5e8) for each registration the funded account will make —
//! the reserve dominates, so an amount sized only for the price leaves an
//! account that cannot transact.

use logos_lez_rln::rln::client::{
    TxOutcome, await_outcome, init_wallet, parse_account_id, resolve_payer, wait_account_attempts,
};
use nssa::AccountId;
use nssa_core::signing_key::SigningKeyState;
use wallet::{
    AccountIdentity,
    program_facades::{CreditDelivery, native_token_transfer::NativeTokenTransfer},
};

fn usage() -> ! {
    eprintln!(
        "usage: fund_account (--to <account-id> | --to-public-key <66 hex>) --amount <atomic units>\n\
         \n\
         LEE_WALLET_HOME_DIR names the wallet holding the payer; LEZ_RLN_PAYER names\n\
         the payer itself, and its secret must be in that wallet. --to needs an account\n\
         that exists on chain; --to-public-key funds one that never did, by its initial key."
    );
    std::process::exit(2);
}

#[tokio::main]
async fn main() {
    let mut to: Option<String> = None;
    let mut to_public_key: Option<String> = None;
    let mut amount: Option<u128> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--to" => to = args.next(),
            "--to-public-key" => to_public_key = args.next(),
            "--amount" => {
                amount = args.next().and_then(|a| a.trim().parse().ok());
                if amount.is_none() {
                    eprintln!("--amount must be a non-negative integer");
                    std::process::exit(2);
                }
            }
            "-h" | "--help" => usage(),
            other => {
                eprintln!("unknown argument: {other}");
                usage();
            }
        }
    }
    let Some(amount) = amount else { usage() };
    let recipient = match (to, to_public_key) {
        (Some(to), None) => {
            let to = parse_account_id(&to).unwrap_or_else(|e| {
                eprintln!("--to is {e}");
                std::process::exit(2);
            });
            AccountIdentity::Public(to)
        }
        (None, Some(key)) => {
            let key: SigningKeyState = key.trim().parse().unwrap_or_else(|e| {
                eprintln!("--to-public-key is not an initial key: {e}");
                std::process::exit(2);
            });
            AccountIdentity::public_foreign(key).unwrap_or_else(|| {
                eprintln!("--to-public-key is a key of a type no account starts with");
                std::process::exit(2);
            })
        }
        _ => usage(),
    };
    let to: AccountId = recipient.account_id();

    // Resolved before the wallet opens, so a missing LEZ_RLN_PAYER fails on
    // the configuration rather than after a sync.
    let payer = resolve_payer();
    let wallet_core = init_wallet().await;

    if matches!(recipient, AccountIdentity::Public(_))
        && wallet_core.get_account_initial_key(to).is_none()
    {
        let exists = wallet_core
            .get_account_public(to)
            .await
            .unwrap_or_else(|e| {
                eprintln!("cannot read {to}: {e:?}");
                std::process::exit(1);
            })
            .is_some();
        if !exists {
            eprintln!(
                "{to} has never existed on chain and this wallet does not hold its key: a \
                 credit to it cannot be admitted. Pass --to-public-key <its initial key> instead."
            );
            std::process::exit(2);
        }
    }

    println!("funding {to} with {amount} native from {payer}");
    let (hash, _) = NativeTokenTransfer(&wallet_core)
        .transfer(
            AccountIdentity::Public(payer),
            recipient,
            amount,
            CreditDelivery::Automatic,
        )
        .await
        .unwrap_or_else(|e| {
            // The payer's balance has to cover the transfer AND the fee this
            // transaction reserves, so "Incorrect fee" here means the PAYER is
            // short, not the destination.
            eprintln!("transfer failed: {e:?}");
            std::process::exit(1);
        });
    println!("submitted {hash}");
    // Nothing to read back: the block alone decides.
    match await_outcome(&wallet_core, hash, async || None::<()>).await {
        Err(TxOutcome::Included(block)) => println!("included in block {block}"),
        Err(TxOutcome::Reverted(block)) => {
            eprintln!("transfer reverted in block {block}: fee charged, nothing moved");
            std::process::exit(1);
        }
        Ok(()) | Err(TxOutcome::Pending) => {
            eprintln!(
                "the transfer is not in a block after {} s; check the chain before re-sending",
                wait_account_attempts() / 2
            );
            std::process::exit(1);
        }
    }
}
