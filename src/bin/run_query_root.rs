//! Query the current merkle tree root and next_index from the on-chain state.
//!
//! ```bash
//! cargo run --bin run_query_root
//! ```
use logos_lez_rln::merkle_tree::{fetch_next_index, fetch_root};
use nssa::program::Program;
use wallet::WalletCore;

const REGISTRATION_BINARY: &str = "target/riscv32im-risc0-zkvm-elf/docker/rln_registration.bin";
const TREE_ID: [u8; 24] = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23];

#[tokio::main]
async fn main() {
    let wallet_core = WalletCore::from_env().unwrap();

    let registration_bytecode = std::fs::read(REGISTRATION_BINARY)
        .expect("Failed to read registration program binary");
    let registration_program = Program::new(registration_bytecode)
        .expect("Failed to parse registration program");

    let root = fetch_root(&wallet_core, &registration_program, &TREE_ID).await;
    let next_index = fetch_next_index(&wallet_core, &registration_program, &TREE_ID).await;

    println!("Root:       0x{}", hex::encode(root));
    println!("Next index: {}", next_index);
}
