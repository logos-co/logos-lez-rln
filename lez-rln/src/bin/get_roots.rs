use logos_lez_rln::rln::client::{TREE_ID, init_wallet, load_programs};
use logos_lez_rln::merkle_tree::fetch_root;

#[tokio::main]
async fn main() {
    let wallet_core = init_wallet();
    let (registration_program, _) = load_programs();
    let root = fetch_root(&wallet_core, &registration_program, &TREE_ID).await;
    println!("LEZ tree root (LE hex): {}", hex::encode(&root));
}
