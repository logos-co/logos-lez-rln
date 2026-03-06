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
#include <QTimer>

class QTcpServer;

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
    Q_INVOKABLE void start_root_broadcast(const QString& rln_account_id) override;
    Q_INVOKABLE QString get_merkle_proofs(const QString& config_account_id,
                                          const QString& leaf_indices_json) override;
    Q_INVOKABLE void start_merkle_proof_broadcast(const QString& config_account_id,
                                                    int leaf_index) override;
    Q_INVOKABLE void start_http_service(int port, const QString& config_account) override;

signals:
    void eventResponse(const QString& eventName, const QVariantList& data);

private slots:
    void onBroadcastTimer();
    void onProofBroadcastTimer();
    void onHttpConnection();

private:
    static constexpr int BROADCAST_INTERVAL_MS = 10000;
    QTimer* m_broadcastTimer = nullptr;
    QString m_broadcastAccountId;
    QTimer* m_proofBroadcastTimer = nullptr;
    QString m_proofBroadcastConfigAccount;
    int m_proofBroadcastLeafIndex = -1;
    QTcpServer* m_httpServer = nullptr;
    QString m_httpConfigAccount;

    QByteArray handleJsonRpc(const QByteArray& body);
    QByteArray handleGetRoots(const QJsonValue& id);
    QByteArray handleGetMerkleProof(const QJsonValue& id, const QJsonValue& params);
    static QByteArray jsonRpcSuccess(const QJsonValue& id, const QJsonValue& result);
    static QByteArray jsonRpcError(const QJsonValue& id, int code, const QString& message);
};

#endif
