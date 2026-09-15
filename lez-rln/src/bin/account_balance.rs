//! Read the native balance of any public account, as JSON.
//!
//! The registry's economics are otherwise only assertable. `register` moves the
//! price out of the payer and into the treasury by two field assignments in the
//! guest, and consensus rejects a state diff that mints or burns — so a
//! successful registration *implies* the value moved. Implication is not
//! observation, and this is what turns "three registrations succeeded" into
//! "the treasury holds three times the price".
//!
//! Reads only: `get_account_public` asks the sequencer for an account's state,
//! so the id need not be one this wallet has a key for. It does need a wallet,
//! because that is what holds the sequencer endpoint and the synced view.
//!
//! ```bash
//! LEE_WALLET_HOME_DIR=<dir> cargo run --release --bin account_balance -- --of <account-id>
//! ```
//!
//! Answers `{"account":"<64 hex>","balance":"<decimal>"}`. The balance is a
//! string because a u128 exceeds what JSON numbers carry exactly, and a caller
//! comparing one against a price must not lose the low digits.

use logos_lez_rln::rln::client::{init_wallet, parse_account_id};

fn usage() -> ! {
    eprintln!(
        "usage: account_balance --of <account-id>\n\
         \n\
         The id is 64 hex chars or base58. LEE_WALLET_HOME_DIR names a wallet; any\n\
         wallet will do, because this reads an account rather than spending one."
    );
    std::process::exit(2);
}

#[tokio::main]
async fn main() {
    let mut of: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--of" => of = args.next(),
            "-h" | "--help" => usage(),
            other => {
                eprintln!("unknown argument: {other}");
                usage();
            }
        }
    }
    let Some(of) = of else { usage() };
    let of = parse_account_id(&of).unwrap_or_else(|e| {
        eprintln!("--of is {e}");
        std::process::exit(2);
    });

    let wallet_core = init_wallet().await;
    let account = wallet_core
        .get_account_public(of)
        .await
        .unwrap_or_else(|e| {
            // An account that has never been touched still reads: native credit
            // lands on an unwritten account. So this is a transport failure or
            // a sequencer that does not know the id, not "balance zero".
            eprintln!("cannot read {of}: {e:?}");
            std::process::exit(1);
        });

    let hex: String = of.value().iter().map(|b| format!("{b:02x}")).collect();
    println!(
        "{{\"account\":\"{hex}\",\"balance\":\"{}\"}}",
        account.balance
    );
}
