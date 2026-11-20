//! Mint (or reuse) the account that pays a deployment's fees, and print its
//! id and public key.
//!
//! Every public transaction we send is charged a fee, and native balance
//! enters an account only at genesis, over the bridge, or by transfer, so
//! provisioning cannot bootstrap its own payer: the payer has to exist
//! before the chain does. This therefore works on the wallet's `Storage`
//! directly rather than through `WalletCore`, which reaches for a sequencer
//! as it opens. Nothing here needs a chain — it generates a key, labels it,
//! and writes the file.
//!
//! Output, one per line: the payer's account id (base58), then its public
//! key (64 hex). The caller hands the public key to `dev.sh` as
//! `LEZ_RLN_GENESIS_FUND`, so the chain starts already owing the account a
//! balance, and the id to `run_setup` as `LEZ_RLN_PAYER`. `--public-key`
//! prints only the key.
//!
//! Re-running is safe, and adopting an existing wallet is the normal case: an
//! already-labelled payer is returned untouched, and a wallet that has none
//! gains one while keeping every account it already had. An encrypted
//! storage is opened with `LEE_WALLET_PASSWORD`.
//!
//! ```bash
//! LEE_WALLET_HOME_DIR=<dir> cargo run --bin mint_payer   # run from lez-rln/
//! ```

use logos_lez_rln::rln::client::wallet_password;
use wallet::{
    account::{AccountIdWithPrivacy, Label},
    storage::{Storage, storage_key_for},
};

/// The label the payer is stored under, so a re-run can find it again.
const PAYER_LABEL: &str = "rln-fee-payer";

fn main() {
    let key_only = std::env::args().skip(1).any(|arg| arg == "--public-key");
    let storage_path = wallet::utils::fetch_persistent_storage_path().expect("storage path");
    let password = wallet_password(&storage_path);

    let (mut storage, storage_key) = if storage_path.exists() {
        Storage::from_path(&storage_path, &password).expect("failed to open wallet storage")
    } else {
        let (storage, _mnemonic) = Storage::new();
        (
            storage,
            storage_key_for(&password).expect("failed to derive the storage key"),
        )
    };

    let label = Label::new(PAYER_LABEL);
    let payer = match storage.resolve_label(&label) {
        Some(AccountIdWithPrivacy::Public(existing)) => existing,
        _ => {
            let (payer, _) = storage
                .key_chain_mut()
                .generate_new_public_transaction_private_key(None);
            storage
                .add_label(label, AccountIdWithPrivacy::Public(payer))
                .expect("failed to label the payer");
            storage
                .save_to_path(&storage_path, storage_key.as_ref())
                .expect("failed to persist wallet storage");
            payer
        }
    };
    let public_key = nssa::PublicKey::new_from_private_key(
        storage
            .key_chain()
            .pub_account_signing_key(payer)
            .expect("the payer's signing key is in this wallet"),
    );
    if !key_only {
        println!("{payer}");
    }
    println!("{public_key}");
}
