use logos_lez_rln::{
    merkle_tree::fetch_root,
    rln::{
        client::{init_wallet, tree_id_from_env},
        program_ids_or_exit,
    },
};

#[tokio::main]
async fn main() {
    let tree_id = tree_id_from_env();
    let programs = program_ids_or_exit(&tree_id);
    let wallet_core = init_wallet().await;
    let root = fetch_root(&wallet_core, &programs, &tree_id).await;
    println!("LEZ tree root (LE hex): {}", hex::encode(root));
}
