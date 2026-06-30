#ifndef MIX_SIMULATION_MODULE_H
#define MIX_SIMULATION_MODULE_H

#include "i_mix_simulation_module.h"

#include <QObject>
#include <QString>
#include <QTimer>
#include <QJsonObject>

class LogosAPIClient;

class MixSimulationModule : public QObject, public PluginInterface, public IMixSimulationModule {
    Q_OBJECT
    Q_PLUGIN_METADATA(IID IMixSimulationModule_iid FILE MIX_SIMULATION_MODULE_METADATA_FILE)
    Q_INTERFACES(PluginInterface IMixSimulationModule)

public:
    MixSimulationModule();
    ~MixSimulationModule() override;

    [[nodiscard]] QString name() const override;
    [[nodiscard]] QString version() const override;

    Q_INVOKABLE void initLogos(LogosAPI* logosApiInstance) override;
    Q_INVOKABLE bool start(const QString& configJson) override;
    Q_INVOKABLE void stop() override;

signals:
    void eventResponse(const QString& eventName, const QVariantList& data);

private:
    void executeSequence();
    void scheduleMessages();
    void sendNextMessage();

    LogosAPIClient* m_deliveryClient = nullptr;
    LogosAPIClient* m_rlnClient = nullptr;

    QJsonObject m_config;
    QString m_contentTopic;
    QString m_payload;
    int m_messageCount = 0;
    int m_messagesSent = 0;
    int m_messageDelayMs = 2000;

    QTimer* m_sequenceTimer = nullptr;
    QTimer* m_messageTimer = nullptr;
    bool m_running = false;
};

#endif
