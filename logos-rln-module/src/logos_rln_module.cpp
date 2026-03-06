#include "logos_rln_module.h"

#include <cpp/logos_api_client.h>
#include <QtCore/QDebug>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtNetwork/QTcpServer>
#include <QtNetwork/QTcpSocket>

static const char* WALLET_MODULE = "liblogos_execution_zone_wallet_module";

static QString bytesToHex(const uint8_t* data, const size_t length) {
    const QByteArray bytearray(reinterpret_cast<const char*>(data), static_cast<int>(length));
    return QString::fromLatin1(bytearray.toHex());
}

static bool hexToBytes(const QString& hex, QByteArray& output_bytes, int expectedLength = -1) {
    QString trimmed_hex = hex.trimmed();
    if (trimmed_hex.startsWith("0x", Qt::CaseInsensitive))
        trimmed_hex = trimmed_hex.mid(2);
    if (trimmed_hex.size() % 2 != 0)
        return false;
    const QByteArray decoded = QByteArray::fromHex(trimmed_hex.toLatin1());
    if (expectedLength != -1 && decoded.size() != expectedLength)
        return false;
    output_bytes = decoded;
    return true;
}

LogosRlnModule::LogosRlnModule() = default;
LogosRlnModule::~LogosRlnModule() = default;

QString LogosRlnModule::name() const {
    return "liblogos_rln_module";
}

QString LogosRlnModule::version() const {
    return "1.0.0";
}

void LogosRlnModule::initLogos(LogosAPI* logosApiInstance) {
    logosAPI = logosApiInstance;
}

void LogosRlnModule::start_root_broadcast(const QString& rln_account_id) {
    m_broadcastAccountId = rln_account_id;

    if (!m_broadcastTimer) {
        m_broadcastTimer = new QTimer(this);
        connect(m_broadcastTimer, &QTimer::timeout, this, &LogosRlnModule::onBroadcastTimer);
    }

    m_broadcastTimer->start(BROADCAST_INTERVAL_MS);
    // Fire immediately as well
    onBroadcastTimer();
}

void LogosRlnModule::onBroadcastTimer() {
    const QString roots = get_valid_roots(m_broadcastAccountId);
    if (roots.isEmpty()) {
        qWarning() << "root broadcast: failed to fetch roots";
        return;
    }

    QVariantList data;
    data << roots;
    emit eventResponse("valid_roots", data);
}

void LogosRlnModule::start_merkle_proof_broadcast(const QString& config_account_id, int leaf_index) {
    m_proofBroadcastConfigAccount = config_account_id;
    m_proofBroadcastLeafIndex = leaf_index;

    if (!m_proofBroadcastTimer) {
        m_proofBroadcastTimer = new QTimer(this);
        connect(m_proofBroadcastTimer, &QTimer::timeout, this, &LogosRlnModule::onProofBroadcastTimer);
    }

    m_proofBroadcastTimer->start(BROADCAST_INTERVAL_MS);
    onProofBroadcastTimer();
}

void LogosRlnModule::onProofBroadcastTimer() {
    const QString indicesJson = "[" + QString::number(m_proofBroadcastLeafIndex) + "]";
    const QString proofsJson = get_merkle_proofs(m_proofBroadcastConfigAccount, indicesJson);
    if (proofsJson.isEmpty()) {
        qWarning() << "proof broadcast: failed to fetch proof for index" << m_proofBroadcastLeafIndex;
        return;
    }

    const QJsonArray arr = QJsonDocument::fromJson(proofsJson.toUtf8()).array();
    if (arr.isEmpty()) {
        qWarning() << "proof broadcast: empty proof array";
        return;
    }

    const QString singleProof = QJsonDocument(arr[0].toObject()).toJson(QJsonDocument::Compact);
    QVariantList data;
    data << singleProof;
    emit eventResponse("merkle_proof", data);
}

static QString resolveAccountId(LogosAPIClient* walletClient, const QString& id) {
    const QString trimmed = id.trimmed();
    const QString stripped = trimmed.startsWith("0x", Qt::CaseInsensitive)
        ? trimmed.mid(2) : trimmed;
    if (stripped.size() == 64)
        return stripped;

    const QVariant hexResult = walletClient->invokeRemoteMethod(
        WALLET_MODULE, "account_id_from_base58", QVariant(id));
    return hexResult.toString();
}

QString LogosRlnModule::get_valid_roots(const QString& rln_account_id_hex) {
    if (!logosAPI) {
        qWarning() << "get_valid_roots: logosAPI not initialized";
        return {};
    }

    // 1. Call wallet module's get_account_public via inter-module RPC
    auto* walletClient = logosAPI->getClient(WALLET_MODULE);
    if (!walletClient) {
        qWarning() << "get_valid_roots: wallet module not available";
        return {};
    }

    const QString accountIdHex = resolveAccountId(walletClient, rln_account_id_hex);
    if (accountIdHex.isEmpty()) {
        qWarning() << "get_valid_roots: failed to resolve account ID";
        return {};
    }

    const QVariant result = walletClient->invokeRemoteMethod(
        WALLET_MODULE, "get_account_public", QVariant(accountIdHex));
    const QString accountJson = result.toString();

    if (accountJson.isEmpty()) {
        qWarning() << "get_valid_roots: empty response from wallet module";
        return {};
    }

    // 2. Parse JSON response and extract "data" hex string
    const QJsonDocument doc = QJsonDocument::fromJson(accountJson.toUtf8());
    if (!doc.isObject()) {
        qWarning() << "get_valid_roots: invalid JSON from wallet module";
        return {};
    }

    const QString dataHex = doc.object().value("data").toString();
    if (dataHex.isEmpty()) {
        qWarning() << "get_valid_roots: no data field in account";
        return {};
    }

    // 3. Hex-decode to raw bytes
    QByteArray rawData;
    if (!hexToBytes(dataHex, rawData)) {
        qWarning() << "get_valid_roots: failed to decode data hex";
        return {};
    }

    // 4. Call FFI to parse roots from tree main layout
    // Buffer for up to 5 roots (1 current + 4 history), each 32 bytes = 160 bytes
    uint8_t rootsBuf[160] = {};
    uint32_t count = 0;

    const RlnFfiError err = rln_ffi_get_valid_roots(
        reinterpret_cast<const uint8_t*>(rawData.constData()),
        static_cast<size_t>(rawData.size()),
        rootsBuf,
        &count);

    if (err != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << "get_valid_roots: FFI error" << static_cast<int>(err);
        return {};
    }

    // 5. Convert each 32-byte root to hex and build JSON array
    QJsonArray array;
    for (uint32_t i = 0; i < count; ++i) {
        array.append(bytesToHex(rootsBuf + i * 32, 32));
    }

    // 6. Return compact JSON string
    return QJsonDocument(array).toJson(QJsonDocument::Compact);
}

static bool fetchAccountData(LogosAPIClient* walletClient,
                              const QString& accountIdHex,
                              QByteArray& outData,
                              QByteArray* outProgramOwner = nullptr) {
    const QVariant result = walletClient->invokeRemoteMethod(
        WALLET_MODULE, "get_account_public", QVariant(accountIdHex));
    const QString json = result.toString();
    if (json.isEmpty()) {
        qWarning() << "fetchAccountData failed: empty response for" << accountIdHex;
        return false;
    }

    const QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
    if (!doc.isObject()) {
        qWarning() << "fetchAccountData failed: not a JSON object for" << accountIdHex
                 << "got:" << json.left(200);
        return false;
    }

    const QJsonObject obj = doc.object();
    const QString dataHex = obj.value("data").toString();
    if (dataHex.isEmpty()) {
        qWarning() << "fetchAccountData failed: empty data for" << accountIdHex;
        return false;
    }

    if (outProgramOwner) {
        const QString ownerHex = obj.value("program_owner").toString();
        if (!ownerHex.isEmpty()) {
            if (!hexToBytes(ownerHex, *outProgramOwner, 32)) {
                qWarning() << "fetchAccountData: malformed program_owner hex:" << ownerHex.left(80);
                return false;
            }
        }
    }

    return hexToBytes(dataHex, outData);
}

QString LogosRlnModule::get_merkle_proofs(const QString& config_account_id,
                                           const QString& leaf_indices_json) {
    if (!logosAPI) {
        qWarning() << "get_merkle_proofs: logosAPI not initialized";
        return {};
    }

    auto* walletClient = logosAPI->getClient(WALLET_MODULE);
    if (!walletClient) {
        qWarning() << "get_merkle_proofs: wallet module not available";
        return {};
    }

    // 1. Parse leaf indices from JSON array
    const QJsonDocument indicesDoc = QJsonDocument::fromJson(leaf_indices_json.toUtf8());
    if (!indicesDoc.isArray()) {
        qWarning() << "get_merkle_proofs: leaf_indices_json is not a JSON array";
        return {};
    }
    const QJsonArray indicesArray = indicesDoc.array();
    if (indicesArray.isEmpty()) {
        return QStringLiteral("[]");
    }

    QVector<uint64_t> leafIndices;
    for (const auto& val : indicesArray) {
        if (!val.isDouble()) {
            qWarning() << "get_merkle_proofs: leaf index is not a number";
            return {};
        }
        leafIndices.append(static_cast<uint64_t>(val.toDouble()));
    }

    // 2. Resolve config account ID and fetch config data
    const QString configHex = resolveAccountId(walletClient, config_account_id);
    if (configHex.isEmpty()) {
        qWarning() << "get_merkle_proofs: failed to resolve config account ID";
        return {};
    }

    QByteArray configData;
    QByteArray programOwnerBytes;
    if (!fetchAccountData(walletClient, configHex, configData, &programOwnerBytes)) {
        qWarning() << "get_merkle_proofs: failed to fetch config account";
        return {};
    }
    if (programOwnerBytes.size() != 32) {
        qWarning() << "get_merkle_proofs: invalid program_owner size" << programOwnerBytes.size();
        return {};
    }

    // 3. Phase 1: ask Rust which accounts we need to fetch
    RlnFfiMerkleProofsPlan plan = {};
    RlnFfiError err = rln_ffi_merkle_proofs_plan(
        reinterpret_cast<const uint8_t*>(configData.constData()),
        static_cast<size_t>(configData.size()),
        reinterpret_cast<const uint8_t*>(programOwnerBytes.constData()),
        leafIndices.constData(),
        static_cast<size_t>(leafIndices.size()),
        &plan);
    if (err != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << "get_merkle_proofs: plan FFI error" << static_cast<int>(err);
        return {};
    }

    // 4. Fetch main account
    const QString mainHex = bytesToHex(plan.main_account_id, 32);
    QByteArray mainData;
    if (!fetchAccountData(walletClient, mainHex, mainData)) {
        qWarning() << "get_merkle_proofs: failed to fetch main account" << mainHex;
        return {};
    }

    // 5. Fetch subtree accounts
    QVector<QByteArray> subtreeDataBufs(static_cast<int>(plan.subtree_count));
    QVector<RlnFfiSubtreeEntry> subtreeEntries(static_cast<int>(plan.subtree_count));
    for (uint32_t i = 0; i < plan.subtree_count; ++i) {
        const QString subtreeHex = bytesToHex(plan.subtree_account_ids[i], 32);
        fetchAccountData(walletClient, subtreeHex, subtreeDataBufs[i]);
        // Empty data is OK — subtree may not exist yet

        subtreeEntries[i].subtree_id = plan.subtree_ids[i];
        subtreeEntries[i].data_ptr = subtreeDataBufs[i].isEmpty()
            ? nullptr
            : reinterpret_cast<const uint8_t*>(subtreeDataBufs[i].constData());
        subtreeEntries[i].data_len = static_cast<size_t>(subtreeDataBufs[i].size());
    }

    // 6. Phase 2: build all proofs in Rust, get JSON back
    uint8_t* jsonPtr = nullptr;
    size_t jsonLen = 0;
    err = rln_ffi_merkle_proofs_exec(
        reinterpret_cast<const uint8_t*>(mainData.constData()),
        static_cast<size_t>(mainData.size()),
        subtreeEntries.isEmpty() ? nullptr : subtreeEntries.constData(),
        static_cast<size_t>(subtreeEntries.size()),
        leafIndices.constData(),
        static_cast<size_t>(leafIndices.size()),
        &jsonPtr, &jsonLen);
    if (err != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << "get_merkle_proofs: exec FFI error" << static_cast<int>(err);
        return {};
    }

    const QString result = QString::fromUtf8(reinterpret_cast<const char*>(jsonPtr),
                                              static_cast<int>(jsonLen));
    rln_ffi_free_string(jsonPtr, jsonLen);
    return result;
}

// ---- HTTP JSON-RPC Server ----

void LogosRlnModule::start_http_service(int port, const QString& config_account) {
    if (m_httpServer) {
        qWarning() << "HTTP service already running";
        return;
    }

    m_httpConfigAccount = config_account;
    m_httpServer = new QTcpServer(this);
    connect(m_httpServer, &QTcpServer::newConnection, this, &LogosRlnModule::onHttpConnection);

    if (!m_httpServer->listen(QHostAddress::Any, static_cast<quint16>(port))) {
        qWarning() << "Failed to start HTTP service on port" << port
                   << m_httpServer->errorString();
        delete m_httpServer;
        m_httpServer = nullptr;
        return;
    }

    qDebug() << "RLN HTTP JSON-RPC service listening on port" << port;
}

void LogosRlnModule::onHttpConnection() {
    while (auto* socket = m_httpServer->nextPendingConnection()) {
        connect(socket, &QTcpSocket::readyRead, socket, [this, socket]() {
            const QByteArray raw = socket->readAll();

            // Extract body from HTTP request (skip headers)
            const int bodyStart = raw.indexOf("\r\n\r\n");
            const QByteArray body = (bodyStart >= 0) ? raw.mid(bodyStart + 4) : raw;

            const QByteArray responseBody = handleJsonRpc(body);
            const QByteArray httpResponse =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: " + QByteArray::number(responseBody.size()) + "\r\n"
                "Connection: close\r\n"
                "\r\n" + responseBody;

            socket->write(httpResponse);
            socket->flush();
            socket->disconnectFromHost();
        });

        connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
    }
}

QByteArray LogosRlnModule::handleJsonRpc(const QByteArray& body) {
    const QJsonDocument doc = QJsonDocument::fromJson(body);
    if (!doc.isObject())
        return jsonRpcError(QJsonValue::Null, -32700, "Parse error");

    const QJsonObject req = doc.object();
    const QString method = req.value("method").toString();
    const QJsonValue id = req.value("id");
    const QJsonValue params = req.value("params");

    if (method == "rln_getRoots")
        return handleGetRoots(id);
    if (method == "rln_getMerkleProof")
        return handleGetMerkleProof(id, params);

    return jsonRpcError(id, -32601, "Method not found: " + method);
}

QByteArray LogosRlnModule::handleGetRoots(const QJsonValue& id) {
    const QString rootsJson = get_valid_roots(m_httpConfigAccount);
    if (rootsJson.isEmpty())
        return jsonRpcError(id, -32000, "Failed to fetch roots");

    // Parse array and add "0x" prefix to each hex root
    const QJsonArray roots = QJsonDocument::fromJson(rootsJson.toUtf8()).array();
    QJsonArray prefixed;
    for (const auto& r : roots)
        prefixed.append("0x" + r.toString());

    return jsonRpcSuccess(id, prefixed);
}

QByteArray LogosRlnModule::handleGetMerkleProof(const QJsonValue& id, const QJsonValue& params) {
    // Extract leaf_index from params: [leaf_index] or {"leaf_index": N}
    int leafIndex = -1;
    if (params.isArray()) {
        const QJsonArray arr = params.toArray();
        if (!arr.isEmpty() && arr[0].isDouble())
            leafIndex = static_cast<int>(arr[0].toDouble());
    } else if (params.isObject()) {
        const QJsonObject obj = params.toObject();
        if (obj.contains("leaf_index"))
            leafIndex = obj.value("leaf_index").toInt(-1);
    }

    if (leafIndex < 0)
        return jsonRpcError(id, -32602, "Expected params: [leaf_index]");

    const QString indicesJson = "[" + QString::number(leafIndex) + "]";
    const QString proofsJson = get_merkle_proofs(m_httpConfigAccount, indicesJson);
    if (proofsJson.isEmpty())
        return jsonRpcError(id, -32000, "Failed to fetch merkle proof");

    const QJsonArray arr = QJsonDocument::fromJson(proofsJson.toUtf8()).array();
    if (arr.isEmpty())
        return jsonRpcError(id, -32000, "Empty proof array");

    // Reformat: rename fields and add "0x" prefix to hex values
    const QJsonObject proof = arr[0].toObject();

    QJsonArray pathElements;
    for (const auto& e : proof.value("path_elements").toArray())
        pathElements.append("0x" + e.toString());

    QJsonArray identityPathIndex;
    for (const auto& idx : proof.value("path_indices").toArray())
        identityPathIndex.append(idx);

    QJsonObject result;
    result["root"] = "0x" + proof.value("root").toString();
    result["pathElements"] = pathElements;
    result["identityPathIndex"] = identityPathIndex;

    return jsonRpcSuccess(id, result);
}

QByteArray LogosRlnModule::jsonRpcSuccess(const QJsonValue& id, const QJsonValue& result) {
    QJsonObject resp;
    resp["jsonrpc"] = "2.0";
    resp["result"] = result;
    resp["id"] = id;
    return QJsonDocument(resp).toJson(QJsonDocument::Compact);
}

QByteArray LogosRlnModule::jsonRpcError(const QJsonValue& id, int code, const QString& message) {
    QJsonObject err;
    err["code"] = code;
    err["message"] = message;
    QJsonObject resp;
    resp["jsonrpc"] = "2.0";
    resp["error"] = err;
    resp["id"] = id;
    return QJsonDocument(resp).toJson(QJsonDocument::Compact);
}
