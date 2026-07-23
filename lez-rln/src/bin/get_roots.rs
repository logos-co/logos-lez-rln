use logos_lez_rln::{
    merkle_tree::fetch_root,
    rln::client::{init_wallet, load_programs, tree_id_from_env},
};

#[tokio::main]
async fn main() {
    let wallet_core = init_wallet();
    let (registration_program, _) = load_programs();
    let tree_id = tree_id_from_env();
    let root = fetch_root(&wallet_core, &registration_program, &tree_id).await;
    println!("LEZ tree root (LE hex): {}", hex::encode(&root));
}
