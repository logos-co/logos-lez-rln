#ifndef LOGOS_RLN_MODULE_H
#define LOGOS_RLN_MODULE_H

#include "i_logos_rln_module.h"

#ifdef __cplusplus
extern "C" {
#endif
#include <lez_rln_ffi.h>
#ifdef __cplusplus
}
#endif

#include <QObject>
#include <QString>

class LogosRlnModule : public QObject, public PluginInterface, public ILogosRlnModule {
    Q_OBJECT
    Q_PLUGIN_METADATA(IID ILogosRlnModule_iid FILE LOGOS_RLN_MODULE_METADATA_FILE)
    Q_INTERFACES(PluginInterface ILogosRlnModule)

public:
    LogosRlnModule();
    ~LogosRlnModule() override;
    [[nodiscard]] QString name() const override;
    [[nodiscard]] QString version() const override;
    Q_INVOKABLE void initLogos(LogosAPI* logosApiInstance) override;
    Q_INVOKABLE QString get_valid_roots(const QString& rln_account_id_hex) override;
};

#endif
