#include "mix_simulation_module.h"

#include <cpp/logos_api_client.h>
#include <QtCore/QDebug>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonArray>

static const char* DELIVERY_MODULE = "delivery_module";
static const char* RLN_MODULE = "liblogos_rln_module";

MixSimulationModule::MixSimulationModule() = default;

MixSimulationModule::~MixSimulationModule() {
    stop();
}

QString MixSimulationModule::name() const {
    return "mix_simulation_module";
}

QString MixSimulationModule::version() const {
    return "1.0.0";
}

void MixSimulationModule::initLogos(LogosAPI* logosApiInstance) {
    logosAPI = logosApiInstance;
}

bool MixSimulationModule::start(const QString& configJson) {
    qDebug() << "MixSimulationModule::start called";

    if (m_running) {
        qWarning() << "MixSimulationModule: Simulation already running";
        return false;
    }

    if (!logosAPI) {
        qWarning() << "MixSimulationModule: LogosAPI not initialized";
        return false;
    }

    // Parse config
    QJsonDocument doc = QJsonDocument::fromJson(configJson.toUtf8());
    if (!doc.isObject()) {
        qWarning() << "MixSimulationModule: Invalid config JSON";
        return false;
    }
    m_config = doc.object();

    // Get module clients
    m_deliveryClient = logosAPI->getClient(DELIVERY_MODULE);
    if (!m_deliveryClient) {
        qWarning() << "MixSimulationModule: delivery_module not available";
        return false;
    }

    m_rlnClient = logosAPI->getClient(RLN_MODULE);
    if (!m_rlnClient) {
        qWarning() << "MixSimulationModule: liblogos_rln_module not available";
        return false;
    }

    // Extract simulation params
    m_contentTopic = m_config.value("contentTopic").toString("/logos/1/mix-sim/proto");
    
    QJsonObject simConfig = m_config.value("simulation").toObject();
    int peerDiscoveryDelayMs = simConfig.value("peerDiscoveryDelayMs").toInt(15000);
    m_messageCount = simConfig.value("messageCount").toInt(10);
    m_messageDelayMs = simConfig.value("messageDelayMs").toInt(2000);
    m_payload = simConfig.value("payload").toString("mix-sim-test-message");
    m_messagesSent = 0;

    m_running = true;

    // Execute the orchestration sequence
    executeSequence();

    // Schedule message sending after peer discovery delay
    if (!m_sequenceTimer) {
        m_sequenceTimer = new QTimer(this);
        m_sequenceTimer->setSingleShot(true);
        connect(m_sequenceTimer, &QTimer::timeout, this, &MixSimulationModule::scheduleMessages);
    }
    m_sequenceTimer->start(peerDiscoveryDelayMs);

    qDebug() << "MixSimulationModule: Started, will send" << m_messageCount 
             << "messages after" << peerDiscoveryDelayMs << "ms peer discovery delay";
    return true;
}

void MixSimulationModule::executeSequence() {
    qDebug() << "MixSimulationModule: Executing orchestration sequence";

    // 1. Create delivery node
    QJsonObject deliveryConfig = m_config.value("delivery").toObject();
    QString deliveryConfigStr = QJsonDocument(deliveryConfig).toJson(QJsonDocument::Compact);
    
    qDebug() << "MixSimulationModule: Calling delivery_module.createNode";
    QVariant createResult = m_deliveryClient->invokeRemoteMethod(
        DELIVERY_MODULE, "createNode", QVariant(deliveryConfigStr));
    if (!createResult.toBool()) {
        qWarning() << "MixSimulationModule: createNode failed";
    }

    // 2. Start delivery node
    qDebug() << "MixSimulationModule: Calling delivery_module.start";
    QVariant startResult = m_deliveryClient->invokeRemoteMethod(
        DELIVERY_MODULE, "start");
    if (!startResult.toBool()) {
        qWarning() << "MixSimulationModule: start failed";
    }

    // 3. Subscribe to content topic
    qDebug() << "MixSimulationModule: Calling delivery_module.subscribe";
    QVariant subResult = m_deliveryClient->invokeRemoteMethod(
        DELIVERY_MODULE, "subscribe", QVariant(m_contentTopic));
    if (!subResult.toBool()) {
        qWarning() << "MixSimulationModule: subscribe failed";
    }

    // 4. Set RLN config (self-register or use pre-set credentials)
    QJsonObject rlnConfig = m_config.value("rln").toObject();
    QString configAccountId = rlnConfig.value("configAccountId").toString();
    QString walletAccountId = rlnConfig.value("walletAccountId").toString();
    int rateLimit = rlnConfig.value("rateLimit").toInt(100);
    int leafIndex = rlnConfig.value("leafIndex").toInt(-1);

    if (!configAccountId.isEmpty() && !walletAccountId.isEmpty()) {
        // Self-register via gifter service
        qDebug() << "MixSimulationModule: Calling delivery_module.selfRegisterRln";
        QVariant regResult = m_deliveryClient->invokeRemoteMethod(
            DELIVERY_MODULE, "selfRegisterRln",
            QVariant(configAccountId), QVariant(walletAccountId), QVariant(rateLimit));
        QString regJson = regResult.toString();
        if (regJson.isEmpty()) {
            qWarning() << "MixSimulationModule: selfRegisterRln failed";
        } else {
            qDebug() << "MixSimulationModule: selfRegisterRln result:" << regJson;
            QJsonDocument regDoc = QJsonDocument::fromJson(regJson.toUtf8());
            leafIndex = static_cast<int>(regDoc.object()["leaf_index"].toDouble());
        }

        // Start RLN root + merkle proof broadcasts
        qDebug() << "MixSimulationModule: Calling liblogos_rln_module.start_root_broadcast";
        m_rlnClient->invokeRemoteMethod(
            RLN_MODULE, "start_root_broadcast", QVariant(configAccountId));

        if (leafIndex >= 0) {
            qDebug() << "MixSimulationModule: Calling liblogos_rln_module.start_merkle_proof_broadcast";
            m_rlnClient->invokeRemoteMethod(
                RLN_MODULE, "start_merkle_proof_broadcast",
                QVariant(configAccountId), QVariant(leafIndex));
        }
    } else if (!configAccountId.isEmpty() && leafIndex >= 0) {
        // Use pre-set credentials
        qDebug() << "MixSimulationModule: Calling delivery_module.setRlnConfig";
        QVariant rlnResult = m_deliveryClient->invokeRemoteMethod(
            DELIVERY_MODULE, "setRlnConfig",
            QVariant(configAccountId), QVariant(leafIndex));
        if (!rlnResult.toBool()) {
            qWarning() << "MixSimulationModule: setRlnConfig failed";
        }

        qDebug() << "MixSimulationModule: Calling liblogos_rln_module.start_root_broadcast";
        m_rlnClient->invokeRemoteMethod(
            RLN_MODULE, "start_root_broadcast", QVariant(configAccountId));

        qDebug() << "MixSimulationModule: Calling liblogos_rln_module.start_merkle_proof_broadcast";
        m_rlnClient->invokeRemoteMethod(
            RLN_MODULE, "start_merkle_proof_broadcast",
            QVariant(configAccountId), QVariant(leafIndex));
    } else {
        qDebug() << "MixSimulationModule: No RLN config provided, skipping RLN setup";
    }

    qDebug() << "MixSimulationModule: Orchestration sequence complete";
}

void MixSimulationModule::scheduleMessages() {
    qDebug() << "MixSimulationModule: Peer discovery delay complete, starting message sends";

    if (!m_messageTimer) {
        m_messageTimer = new QTimer(this);
        connect(m_messageTimer, &QTimer::timeout, this, &MixSimulationModule::sendNextMessage);
    }

    // Send first message immediately, then schedule remaining
    sendNextMessage();
    
    if (m_messagesSent < m_messageCount) {
        m_messageTimer->start(m_messageDelayMs);
    }
}

void MixSimulationModule::sendNextMessage() {
    if (!m_running || m_messagesSent >= m_messageCount) {
        if (m_messageTimer) {
            m_messageTimer->stop();
        }
        qDebug() << "MixSimulationModule: All messages sent (" << m_messagesSent << ")";
        
        QVariantList data;
        data << m_messagesSent;
        emit eventResponse("simulationComplete", data);
        return;
    }

    QString payload = QString("%1-%2").arg(m_payload).arg(m_messagesSent + 1);
    
    qDebug() << "MixSimulationModule: Sending message" << (m_messagesSent + 1) 
             << "of" << m_messageCount;

    QVariant result = m_deliveryClient->invokeRemoteMethod(
        DELIVERY_MODULE, "sendTest",
        QVariant(m_contentTopic), QVariant(payload));

    if (!result.toBool()) {
        qWarning() << "MixSimulationModule: sendTest failed for message" << (m_messagesSent + 1);
    }

    m_messagesSent++;

    if (m_messagesSent >= m_messageCount && m_messageTimer) {
        m_messageTimer->stop();
        qDebug() << "MixSimulationModule: All messages queued";
        
        QVariantList data;
        data << m_messagesSent;
        emit eventResponse("simulationComplete", data);
    }
}

void MixSimulationModule::stop() {
    qDebug() << "MixSimulationModule::stop called";

    m_running = false;

    if (m_sequenceTimer) {
        m_sequenceTimer->stop();
        delete m_sequenceTimer;
        m_sequenceTimer = nullptr;
    }

    if (m_messageTimer) {
        m_messageTimer->stop();
        delete m_messageTimer;
        m_messageTimer = nullptr;
    }

    m_deliveryClient = nullptr;
    m_rlnClient = nullptr;
}
