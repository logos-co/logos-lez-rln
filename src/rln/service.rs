//! RLN JSON-RPC service implementation.
//!
//! Provides [`RlnService`] which wraps wallet/program interactions behind
//! simple register/query methods, used by the HTTP server binary.

use nssa::{
    AccountId, PublicTransaction,
    program::Program,
    public_transaction::{Message, WitnessSet},
    PrivateKey,
};
use tokio::sync::Mutex;
use wallet::WalletCore;

use crate::merkle_tree::{
    self, MerkleProof, SUBTREE_LEAVES,
};
use crate::rln::{
    CONFIG_OFFSET_TREASURY_ACCOUNT_ID,
    derive_config_account, derive_subtree_account, derive_tree_main_account,
    layouts::Instruction,
};

/// Mutable state that must stay in sync across rapid-fire registrations.
struct RegisterState {
    nonce: u128,
    next_index: u64,
}

/// Long-lived service state shared across JSON-RPC requests.
pub struct RlnService {
    pub wallet_core: WalletCore,
    pub registration_program: Program,
    pub tree_id: [u8; 24],
    pub payment_account_id: AccountId,
    signing_key: PrivateKey,
    register_state: Mutex<RegisterState>,
}

impl RlnService {
    /// Create a new service instance.
    ///
    /// Fetches the current nonce and next_index from chain.
    pub async fn new(
        wallet_core: WalletCore,
        registration_program: Program,
        tree_id: [u8; 24],
        payment_account_id: AccountId,
    ) -> Self {
        let signing_key = wallet_core
            .storage()
            .user_data
            .get_pub_account_signing_key(payment_account_id.clone())
            .expect("Payment account not found in wallet")
            .clone();

        let nonces = wallet_core
            .get_accounts_nonces(vec![payment_account_id.clone()])
            .await
            .expect("Failed to fetch initial nonce");
        let current_nonce = nonces[0];

        let next_index = merkle_tree::fetch_next_index(
            &wallet_core,
            &registration_program,
            &tree_id,
        )
        .await;

        Self {
            wallet_core,
            registration_program,
            tree_id,
            payment_account_id,
            signing_key,
            register_state: Mutex::new(RegisterState {
                nonce: current_nonce,
                next_index,
            }),
        }
    }

    /// Register an identity commitment on-chain.
    /// Returns the leaf index assigned to this registration.
    pub async fn register(
        &self,
        id_commitment: [u8; 32],
        rate_limit: u64,
    ) -> Result<u64, String> {
        let config_account =
            derive_config_account(&self.registration_program.id(), &self.tree_id);
        let tree_main_account =
            derive_tree_main_account(&self.registration_program.id(), &self.tree_id);

        let config_data = self
            .wallet_core
            .get_account_public(config_account.clone())
            .await
            .map_err(|e| format!("Failed to fetch config account: {e:?}"))?;

        let config_bytes = config_data.data.as_ref();
        let treasury_bytes: [u8; 32] = config_bytes
            [CONFIG_OFFSET_TREASURY_ACCOUNT_ID..CONFIG_OFFSET_TREASURY_ACCOUNT_ID + 32]
            .try_into()
            .map_err(|_| "Invalid treasury account ID in config".to_string())?;
        let treasury_account_id = AccountId::new(treasury_bytes);

        // Lock state for the duration of tx construction + send to guarantee ordering
        let mut state = self.register_state.lock().await;

        let subtree_id = (state.next_index / SUBTREE_LEAVES as u64) as u32;
        let subtree_account = derive_subtree_account(
            &self.registration_program.id(),
            &self.tree_id,
            subtree_id,
        );

        let accounts = vec![
            config_account,
            tree_main_account,
            self.payment_account_id.clone(),
            treasury_account_id,
            subtree_account,
        ];

        let instruction = Instruction::Register {
            registration_program_id: bytemuck::cast(self.registration_program.id()),
            id_commitment,
            rate_limit,
        };

        let message = Message::try_new(
            self.registration_program.id(),
            accounts,
            vec![state.nonce],
            instruction,
        )
        .map_err(|e| format!("Failed to create message: {e:?}"))?;

        let witness_set = WitnessSet::for_message(&message, &[&self.signing_key]);
        let tx = PublicTransaction::new(message, witness_set);

        let response = self
            .wallet_core
            .sequencer_client
            .send_tx_public(tx)
            .await
            .map_err(|e| format!("Failed to send registration tx: {e:?}"))?;

        let leaf_index = state.next_index;
        state.nonce += 1;
        state.next_index += 1;

        // Drop the lock before polling — no further state mutation needed
        drop(state);

        // Wait for the transaction to be included in a block so that
        // subsequent queries (getRoots, getMerkleProof) see the updated state.
        self.wallet_core
            .poll_native_token_transfer(response.tx_hash)
            .await
            .map_err(|e| format!("Transaction sent but not confirmed: {e:?}"))?;

        Ok(leaf_index)
    }

    /// Get the current merkle root.
    pub async fn get_root(&self) -> [u8; 32] {
        merkle_tree::fetch_root(
            &self.wallet_core,
            &self.registration_program,
            &self.tree_id,
        )
        .await
    }

    /// Get the current root plus recent previous roots (newest first, non-zero only).
    pub async fn get_root_history(&self) -> Vec<[u8; 32]> {
        merkle_tree::fetch_root_history(
            &self.wallet_core,
            &self.registration_program,
            &self.tree_id,
        )
        .await
    }

    /// Get a merkle proof for a leaf at the given index.
    pub async fn get_merkle_proof(&self, leaf_index: u64) -> MerkleProof {
        merkle_tree::get_merkle_proof(
            &self.wallet_core,
            &self.registration_program,
            &self.tree_id,
            leaf_index,
        )
        .await
    }
}
