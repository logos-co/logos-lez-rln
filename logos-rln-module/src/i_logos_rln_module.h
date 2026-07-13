#ifndef I_LOGOS_RLN_MODULE_H
#define I_LOGOS_RLN_MODULE_H

#include <core/interface.h>

class ILogosRlnModule {
public:
    virtual ~ILogosRlnModule() = default;
    virtual void initLogos(LogosAPI* logosApiInstance) = 0;

    /// Returns JSON array string of hex-encoded 32-byte roots, or empty on failure.
    virtual QString get_valid_roots(const QString& rln_account_id_hex) = 0;

    /// Start periodic broadcasting of valid roots as "valid_roots" events.
    virtual void start_root_broadcast(const QString& rln_account_id) = 0;

    /// Returns JSON array of merkle proofs for the given leaf indices.
    virtual QString get_merkle_proofs(const QString& config_account_id,
                                      const QString& leaf_indices_json) = 0;

    /// Start periodic broadcasting of a merkle proof as "merkle_proof" events.
    virtual void start_merkle_proof_broadcast(const QString& config_account_id,
                                               int leaf_index) = 0;

    /// Generate an RLN identity from a wallet account's signing key.
    /// Returns JSON: {"id_commitment": "hex...", "id_secret_hash": "hex..."} or empty on failure.
    virtual QString generate_identity(const QString& wallet_account_id) = 0;

    /// Compute the rate commitment (leaf value) for a given id_commitment and rate_limit.
    /// Returns hex-encoded 32-byte rate commitment, or empty on failure.
    virtual QString compute_rate_commitment(const QString& id_commitment_hex, int rate_limit) = 0;

    /// Submit an on-chain Register tx for (config, id_commitment). Returns
    /// fast — does NOT wait for confirmation; callers must poll
    /// is_member_registered. Pre-checks the membership PDA and short-circuits
    /// to {leaf_index, already_registered: true} if (id_commitment, tree_id)
    /// is already registered (idempotent for restart / retry-after-tx-loss).
    /// Returns JSON: {"leaf_index": N, "tx_result": <wallet response>, "pending": true}
    ///         or:   {"leaf_index": N, "already_registered": true}
    ///         or:   {"error": "...", ...} on submission failure.
    virtual QString register_member(const QString& config_account_id,
                                    const QString& user_holding_account_id,
                                    const QString& id_commitment_hex,
                                    int rate_limit) = 0;

    /// Cheap query (no on-chain wait): does the membership PDA for
    /// (tree_id, id_commitment) currently hold a valid MembershipState?
    /// Returns JSON: {"registered": true, "leaf_index": N}
    ///         or:   {"registered": false}
    /// Used by callers to poll for register_member confirmation without
    /// blocking the RPC thread.
    virtual QString is_member_registered(const QString& config_account_id,
                                          const QString& id_commitment_hex) = 0;

    /// Mint `amount` payment tokens (decimal u128 string) into
    /// `dest_account_id` via the Token program's Mint instruction. The mint
    /// authority (the payment token's definition account, recorded in the RLN
    /// config as payment_token_id) signs; its key must be in the open wallet
    /// — true for the shared deployment wallets, whose committed test-token
    /// keys make funding mint-on-demand instead of draining a fixed supply.
    /// The destination may be a brand-new, never-credited account (the Token
    /// program zero-initializes the holding and claims it Claim::Authorized —
    /// so a fresh destination must be an account of the open wallet, whose
    /// co-signature authorizes the claim). Returns fast (sequencer accept,
    /// not confirmation); poll get_token_balance for the credited amount.
    /// Returns JSON: {"tx_result": <wallet response>, "definition": hex,
    ///                "pending": true} or empty on failure.
    virtual QString mint_tokens(const QString& config_account_id,
                                const QString& dest_account_id,
                                const QString& amount) = 0;

    /// Live sequencer read of a Token holding account's fungible balance.
    /// Returns JSON: {"exists": true, "balance": "<decimal>", "definition": hex}
    ///         or:   {"exists": false, "balance": "0"} for absent accounts,
    /// or empty on failure (wallet unavailable / account fetch failed / not
    /// a holding) — pollers must treat empty as an error, not a zero balance.
    virtual QString get_token_balance(const QString& account_id) = 0;

    /// Faucet claim (faucet-funded deployments): submit the registration
    /// program's ClaimTokens instruction, minting `amount` (decimal u128
    /// string, capped on-chain by the deployment's faucet_claim_cap) into
    /// `dest_account_id`. The mint authority is the program's own payment
    /// PDA — no key is involved beyond the destination's co-signature (its
    /// key must be in the open wallet; fresh holdings are claimed
    /// Claim::Authorized). Non-blocking; poll get_token_balance.
    /// Returns JSON: {"tx_result": <wallet response>, "payment_definition":
    ///                hex, "pending": true} or empty on failure.
    virtual QString claim_tokens(const QString& config_account_id,
                                 const QString& dest_account_id,
                                 const QString& amount) = 0;
};

#define ILogosRlnModule_iid "org.logos.ilogosrlnmodule"
Q_DECLARE_INTERFACE(ILogosRlnModule, ILogosRlnModule_iid)

#endif
