//! Mint (or reuse) the account that pays a deployment's fees, and print its id.
//!
//! v0.2.5 charges a fee on every public transaction we send, and its faucet
//! program runs only in the genesis block — a user transaction to it is
//! refused. So nothing a wallet creates after the chain has started can ever
//! hold native balance, and provisioning cannot bootstrap its own payer.
//!
//! That inverts the local startup order: the payer has to exist before the
//! chain does. This therefore works on the wallet's `Storage` directly rather
//! than through `WalletCore`, which reaches for a sequencer as it opens and
//! fails with "Failed to find leader" when there is none yet. Nothing here
//! needs a chain — it generates a key, labels it, and writes the file.
//!
//! The caller hands the printed id to `dev.sh` as `LEZ_RLN_GENESIS_FUND`, so
//! the chain starts already owing it a balance, and to `run_setup` as
//! `LEZ_RLN_PAYER`.
//!
//! Re-running is safe, and adopting an existing wallet is the normal case: an
//! already-labelled payer is returned untouched, and a wallet that has none
//! gains one while keeping every account it already had.
//!
//! ```bash
//! LEE_WALLET_HOME_DIR=<dir> cargo run --bin mint_payer   # run from lez-rln/
//! ```

use wallet::{
    account::{AccountIdWithPrivacy, Label},
    storage::Storage,
};

/// The label the payer is stored under, so a re-run can find it again.
const PAYER_LABEL: &str = "rln-fee-payer";

fn main() {
    let storage_path =
        wallet::helperfunctions::fetch_persistent_storage_path().expect("storage path");

    let mut storage = if storage_path.exists() {
        Storage::from_path(&storage_path).expect("failed to open wallet storage")
    } else {
        Storage::new("").expect("failed to create wallet storage").0
    };

    let label = Label::new(PAYER_LABEL);
    if let Some(AccountIdWithPrivacy::Public(existing)) = storage.resolve_label(&label) {
        println!("{existing}");
        return;
    }

    let (payer, _) = storage
        .key_chain_mut()
        .generate_new_public_transaction_private_key(None);
    storage
        .add_label(label, AccountIdWithPrivacy::Public(payer))
        .expect("failed to label the payer");
    storage
        .save_to_path(&storage_path)
        .expect("failed to persist wallet storage");
    println!("{payer}");
}
