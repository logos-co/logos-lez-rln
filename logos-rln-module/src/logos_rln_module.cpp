#include "logos_rln_module.h"

#include <cpp/logos_api_client.h>
#include <QtCore/QDebug>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
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

static bool fetchAccountData(LogosAPIClient* walletClient,
                              const QString& accountIdHex,
                              QByteArray& outData,
                              QByteArray* outProgramOwner = nullptr);

QString LogosRlnModule::get_valid_roots(const QString& rln_account_id_hex) {
    qDebug() << "get_valid_roots: called with" << rln_account_id_hex;
    if (!logosAPI) {
        qDebug() << "get_valid_roots: FAIL logosAPI not initialized";
        return {};
    }

    auto* walletClient = logosAPI->getClient(WALLET_MODULE);
    if (!walletClient) {
        qDebug() << "get_valid_roots: FAIL wallet module not available";
        return {};
    }

    const QString configHex = resolveAccountId(walletClient, rln_account_id_hex);
    qDebug() << "get_valid_roots: configHex=" << configHex;
    if (configHex.isEmpty()) {
        qDebug() << "get_valid_roots: FAIL resolve account ID";
        return {};
    }

    // 1. Fetch config account to get program_owner and tree_id
    QByteArray configData;
    QByteArray programOwnerBytes;
    if (!fetchAccountData(walletClient, configHex, configData, &programOwnerBytes)) {
        qDebug() << "get_valid_roots: FAIL fetch config account";
        return {};
    }
    qDebug() << "get_valid_roots: configData.size=" << configData.size()
             << "programOwner.size=" << programOwnerBytes.size();
    if (programOwnerBytes.size() != 32) {
        qDebug() << "get_valid_roots: FAIL program_owner size" << programOwnerBytes.size();
        return {};
    }

    // 2. Parse config to get tree_id, then derive tree main account
    uint8_t merkleProgramId[32] = {};
    uint8_t treeId[24] = {};
    RlnFfiError err = rln_ffi_parse_config(
        reinterpret_cast<const uint8_t*>(configData.constData()),
        static_cast<size_t>(configData.size()),
        merkleProgramId, treeId);
    qDebug() << "get_valid_roots: parse_config result=" << static_cast<int>(err);
    if (err != RLN_FFI_ERROR_SUCCESS) {
        qDebug() << "get_valid_roots: FAIL parse_config FFI error" << static_cast<int>(err);
        return {};
    }

    uint8_t mainAccountId[32] = {};
    err = rln_ffi_derive_main_account_id(
        reinterpret_cast<const uint8_t*>(programOwnerBytes.constData()),
        treeId, mainAccountId);
    qDebug() << "get_valid_roots: derive_main result=" << static_cast<int>(err);
    if (err != RLN_FFI_ERROR_SUCCESS) {
        qDebug() << "get_valid_roots: FAIL derive_main FFI error" << static_cast<int>(err);
        return {};
    }

    // 3. Fetch tree main account data
    const QString mainHex = bytesToHex(mainAccountId, 32);
    qDebug() << "get_valid_roots: mainAccountHex=" << mainHex;
    QByteArray mainData;
    if (!fetchAccountData(walletClient, mainHex, mainData)) {
        qDebug() << "get_valid_roots: FAIL fetch tree main account" << mainHex;
        return {};
    }
    qDebug() << "get_valid_roots: mainData.size=" << mainData.size();

    // 4. Extract roots from tree main data
    uint8_t rootsBuf[160] = {};
    uint32_t count = 0;
    err = rln_ffi_get_valid_roots(
        reinterpret_cast<const uint8_t*>(mainData.constData()),
        static_cast<size_t>(mainData.size()),
        rootsBuf, &count);
    qDebug() << "get_valid_roots: ffi_get_valid_roots result=" << static_cast<int>(err) << "count=" << count;
    if (err != RLN_FFI_ERROR_SUCCESS) {
        qDebug() << "get_valid_roots: FAIL FFI error" << static_cast<int>(err);
        return {};
    }

    // 5. Build JSON array of hex root strings
    QJsonArray array;
    for (uint32_t i = 0; i < count; ++i) {
        array.append(bytesToHex(rootsBuf + i * 32, 32));
    }
    return QJsonDocument(array).toJson(QJsonDocument::Compact);
}

static bool fetchAccountData(LogosAPIClient* walletClient,
                              const QString& accountIdHex,
                              QByteArray& outData,
                              QByteArray* outProgramOwner /* = nullptr */) {
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

QString LogosRlnModule::generate_identity(const QString& seed_or_account_id) {
    QByteArray seedBytes;
    hexToBytes(seed_or_account_id, seedBytes, 32);

    uint8_t idCommitment[32] = {};
    uint8_t idSecretHash[32] = {};
    RlnFfiError err = rln_ffi_generate_identity(
        reinterpret_cast<const uint8_t*>(seedBytes.constData()),
        idCommitment, idSecretHash);

    if (err != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << "generate_identity: FFI error" << static_cast<int>(err);
        return {};
    }

    QJsonObject result;
    result["id_commitment"] = bytesToHex(idCommitment, 32);
    result["id_secret_hash"] = bytesToHex(idSecretHash, 32);
    return QJsonDocument(result).toJson(QJsonDocument::Compact);
}

QString LogosRlnModule::compute_rate_commitment(const QString& id_commitment_hex, int rate_limit) {
    QByteArray idCommitmentBytes;
    if (!hexToBytes(id_commitment_hex, idCommitmentBytes, 32)) {
        qWarning() << "compute_rate_commitment: invalid id_commitment hex";
        return {};
    }

    uint8_t leaf[32] = {};
    RlnFfiError err = rln_ffi_compute_rate_commitment(
        reinterpret_cast<const uint8_t*>(idCommitmentBytes.constData()),
        rate_limit, leaf);

    if (err != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << "compute_rate_commitment: FFI error" << static_cast<int>(err);
        return {};
    }

    return bytesToHex(leaf, 32);
}

QString LogosRlnModule::register_member(const QString& config_account_id,
                                         const QString& user_holding_account_id,
                                         const QString& id_commitment_hex,
                                         int rate_limit) {
    if (!logosAPI) {
        qWarning() << "register_member: logosAPI not initialized";
        return {};
    }

    auto* walletClient = logosAPI->getClient(WALLET_MODULE);
    if (!walletClient) {
        qWarning() << "register_member: wallet module not available";
        return {};
    }

    // Resolve account IDs
    const QString configHex = resolveAccountId(walletClient, config_account_id);
    const QString userHoldingHex = resolveAccountId(walletClient, user_holding_account_id);
    if (configHex.isEmpty() || userHoldingHex.isEmpty()) {
        qWarning() << "register_member: failed to resolve account IDs";
        return {};
    }

    QByteArray idCommitmentBytes;
    if (!hexToBytes(id_commitment_hex, idCommitmentBytes, 32)) {
        qWarning() << "register_member: invalid id_commitment hex";
        return {};
    }

    // Fetch config account
    QByteArray configData;
    QByteArray programOwnerBytes;
    if (!fetchAccountData(walletClient, configHex, configData, &programOwnerBytes)) {
        qWarning() << "register_member: failed to fetch config account";
        return {};
    }
    if (programOwnerBytes.size() != 32) {
        qWarning() << "register_member: invalid program_owner size";
        return {};
    }

    // Parse config to get tree_id
    uint8_t merkleProgramId[32] = {};
    uint8_t treeId[24] = {};
    RlnFfiError err = rln_ffi_parse_config(
        reinterpret_cast<const uint8_t*>(configData.constData()),
        static_cast<size_t>(configData.size()),
        merkleProgramId, treeId);
    if (err != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << "register_member: failed to parse config";
        return {};
    }

    // Derive tree main account and fetch it
    uint8_t treeMainAccountId[32] = {};
    err = rln_ffi_derive_main_account_id(
        reinterpret_cast<const uint8_t*>(programOwnerBytes.constData()),
        treeId, treeMainAccountId);
    if (err != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << "register_member: failed to derive tree main account";
        return {};
    }

    const QString treeMainHex = bytesToHex(treeMainAccountId, 32);
    QByteArray treeMainData;
    if (!fetchAccountData(walletClient, treeMainHex, treeMainData)) {
        qWarning() << "register_member: failed to fetch tree main account";
        return {};
    }

    // Plan the registration
    RlnFfiRlnRegisterPlan plan = {};
    err = rln_ffi_register_plan(
        reinterpret_cast<const uint8_t*>(configData.constData()),
        static_cast<size_t>(configData.size()),
        reinterpret_cast<const uint8_t*>(treeMainData.constData()),
        static_cast<size_t>(treeMainData.size()),
        reinterpret_cast<const uint8_t*>(programOwnerBytes.constData()),
        treeId,
        &plan);
    if (err != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << "register_member: register_plan FFI error" << static_cast<int>(err);
        return {};
    }

    // Build instruction JSON
    uint8_t* instrPtr = nullptr;
    size_t instrLen = 0;
    err = rln_ffi_register_build_instruction(
        reinterpret_cast<const uint8_t*>(programOwnerBytes.constData()),
        reinterpret_cast<const uint8_t*>(idCommitmentBytes.constData()),
        rate_limit,
        &instrPtr, &instrLen);
    if (err != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << "register_member: build_instruction FFI error" << static_cast<int>(err);
        return {};
    }

    const QString instructionHex = bytesToHex(instrPtr, instrLen);
    rln_ffi_free_string(instrPtr, instrLen);

    // Build accounts list for the transaction
    QJsonArray accountsList;
    accountsList.append(bytesToHex(plan.config_account_id, 32));
    accountsList.append(bytesToHex(plan.tree_main_account_id, 32));
    accountsList.append(userHoldingHex);
    accountsList.append(bytesToHex(plan.treasury_account_id, 32));
    accountsList.append(bytesToHex(plan.subtree_account_id, 32));

    // Build transaction request for wallet module
    QJsonObject txRequest;
    txRequest["program_id"] = bytesToHex(
        reinterpret_cast<const uint8_t*>(programOwnerBytes.constData()), 32);
    txRequest["accounts"] = accountsList;
    txRequest["instruction"] = instructionHex;
    txRequest["signer_account"] = userHoldingHex;

    const QString txRequestJson = QJsonDocument(txRequest).toJson(QJsonDocument::Compact);

    // Send the transaction via wallet module
    const QVariant sendResult = walletClient->invokeRemoteMethod(
        WALLET_MODULE, "send_public_transaction", QVariant(txRequestJson));
    const QString sendResultStr = sendResult.toString();

    if (sendResultStr.isEmpty()) {
        qWarning() << "register_member: transaction failed";
        return {};
    }

    // Return result with leaf index
    QJsonObject result;
    result["leaf_index"] = static_cast<qint64>(plan.next_leaf_index);
    result["tx_result"] = sendResultStr;
    return QJsonDocument(result).toJson(QJsonDocument::Compact);
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
