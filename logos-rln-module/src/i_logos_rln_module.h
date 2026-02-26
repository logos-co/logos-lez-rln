#ifndef I_LOGOS_RLN_MODULE_H
#define I_LOGOS_RLN_MODULE_H

#include <core/interface.h>

class ILogosRlnModule {
public:
    virtual ~ILogosRlnModule() = default;
    virtual void initLogos(LogosAPI* logosApiInstance) = 0;

    /// Returns JSON array string of hex-encoded 32-byte roots, or empty on failure.
    virtual QString get_valid_roots(const QString& rln_account_id_hex) = 0;
};

#define ILogosRlnModule_iid "org.logos.ilogosrlnmodule"
Q_DECLARE_INTERFACE(ILogosRlnModule, ILogosRlnModule_iid)

#endif
