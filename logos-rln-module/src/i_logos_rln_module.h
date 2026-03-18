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
};

#define ILogosRlnModule_iid "org.logos.ilogosrlnmodule"
Q_DECLARE_INTERFACE(ILogosRlnModule, ILogosRlnModule_iid)

#endif
