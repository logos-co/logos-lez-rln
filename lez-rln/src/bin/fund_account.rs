//! Transfer native balance from this deployment's payer to another account.
//!
//! The one thing a node cannot do for itself. `liblogos_lez_rln_module` derives
//! a payer at bring-up and publishes it, but no program can mint native
//! balance — it enters an account only at genesis, over the L1 bridge, or by a
//! transfer from something already funded. This is that transfer.
//!
//! It lives here rather than in the harness because the harness would otherwise
//! have to rebuild a `lee::public_transaction::Message`, its nonces and the
//! v0.2.5 `FeeDeclaration`, and sign it — a wire format that changes with the
//! chain. Funding stays the caller's decision; only the signing is kept in
//! Rust, beside `mint_payer` and `run_setup`, which the same caller runs.
//!
//! ```bash
//! LEE_WALLET_HOME_DIR=<dir> LEZ_RLN_PAYER=<from> \
//!   cargo run --release --bin fund_account -- --to <account-id> --amount <u128>
//! ```
//!
//! The amount is atomic units. Budget `rate_limit x price_per_unit` plus the
//! fee reserve (~6.5e8) for each registration the funded account will make —
//! the reserve dominates, so an amount sized only for the price leaves an
//! account that cannot transact.

use logos_lez_rln::rln::client::{init_wallet, parse_account_id, resolve_payer};
use wallet::{AccountIdentity, program_facades::native_token_transfer::NativeTokenTransfer};

fn usage() -> ! {
    eprintln!(
        "usage: fund_account --to <account-id> --amount <atomic units>\n\
         \n\
         LEE_WALLET_HOME_DIR names the wallet holding the payer; LEZ_RLN_PAYER names\n\
         the payer itself, and its key must be in that wallet."
    );
    std::process::exit(2);
}

#[tokio::main]
async fn main() {
    let mut to: Option<String> = None;
    let mut amount: Option<u128> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--to" => to = args.next(),
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
    let (Some(to), Some(amount)) = (to, amount) else {
        usage()
    };
    let to = parse_account_id(&to).unwrap_or_else(|e| {
        eprintln!("--to is {e}");
        std::process::exit(2);
    });

    // Resolved before the wallet opens, so a missing LEZ_RLN_PAYER fails on
    // the configuration rather than after a sync.
    let payer = resolve_payer();
    let wallet_core = init_wallet().await;

    println!("funding {to} with {amount} native from {payer}");
    NativeTokenTransfer(&wallet_core)
        .send_public_transfer(
            AccountIdentity::Public(payer),
            AccountIdentity::Public(to),
            amount,
        )
        .await
        .unwrap_or_else(|e| {
            // The payer's balance has to cover the transfer AND the fee this
            // transaction reserves, so "Incorrect fee" here means the PAYER is
            // short, not the destination.
            eprintln!("transfer failed: {e:?}");
            std::process::exit(1);
        });
    println!("submitted");
}
