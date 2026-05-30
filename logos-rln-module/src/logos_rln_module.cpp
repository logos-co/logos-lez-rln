#include "logos_rln_module.h"

#include <cpp/logos_api_client.h>
#include <QtCore/QCoreApplication>
#include <QtCore/QDebug>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
static const char* WALLET_MODULE = "logos_execution_zone";

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

    // Drain event loop before blocking RPC — keeps other protocols alive.
    QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
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

    // Derive tree main account via merkle_proofs_plan (no leaves needed).
    RlnFfiMerkleProofsPlan accountsPlan = {};
    RlnFfiError err = rln_ffi_merkle_proofs_plan(
        reinterpret_cast<const uint8_t*>(configData.constData()),
        static_cast<size_t>(configData.size()),
        reinterpret_cast<const uint8_t*>(programOwnerBytes.constData()),
        nullptr, 0,
        &accountsPlan);
    qDebug() << "get_valid_roots: merkle_proofs_plan result=" << static_cast<int>(err);
    if (err != RLN_FFI_ERROR_SUCCESS) {
        qDebug() << "get_valid_roots: FAIL merkle_proofs_plan FFI error" << static_cast<int>(err);
        return {};
    }
    const uint8_t* mainAccountId = accountsPlan.main_account_id;

    const QString mainHex = bytesToHex(mainAccountId, 32);
    qDebug() << "get_valid_roots: mainAccountHex=" << mainHex;
    QByteArray mainData;
    if (!fetchAccountData(walletClient, mainHex, mainData)) {
        qDebug() << "get_valid_roots: FAIL fetch tree main account" << mainHex;
        return {};
    }
    qDebug() << "get_valid_roots: mainData.size=" << mainData.size();

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

    QJsonArray array;
    for (uint32_t i = 0; i < count; ++i) {
        array.append(bytesToHex(rootsBuf + i * 32, 32));
    }
    return QJsonDocument(array).toJson(QJsonDocument::Compact);
}

// Quiet variant: returns false on absent / empty-data accounts without
// logging a warning. Used by the register_member pre-check + poll loops
// where "not yet present" is the expected initial state.
static bool fetchAccountDataQuiet(LogosAPIClient* walletClient,
                                   const QString& accountIdHex,
                                   QByteArray& outData) {
    QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    const QVariant result = walletClient->invokeRemoteMethod(
        WALLET_MODULE, "get_account_public", QVariant(accountIdHex));
    const QString json = result.toString();
    if (json.isEmpty()) return false;
    const QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
    if (!doc.isObject()) return false;
    const QString dataHex = doc.object().value("data").toString();
    if (dataHex.isEmpty()) return false;
    return hexToBytes(dataHex, outData);
}

// Decode a fetched membership PDA's data into its scalar fields. Returns
// true on success. Caller guarantees data.size() >= 64.
static bool decodeMembership(const QByteArray& data,
                              quint64& outLeafIndex,
                              quint64& outRateLimit,
                              QByteArray& outIdCommitment) {
    uint64_t leafIndex = 0;
    uint64_t rateLimit = 0;
    uint8_t idCommitment[32] = {};
    const RlnFfiError err = rln_ffi_decode_membership(
        reinterpret_cast<const uint8_t*>(data.constData()),
        static_cast<size_t>(data.size()),
        &leafIndex, &rateLimit, idCommitment);
    if (err != RLN_FFI_ERROR_SUCCESS) return false;
    outLeafIndex = leafIndex;
    outRateLimit = rateLimit;
    outIdCommitment = QByteArray(reinterpret_cast<const char*>(idCommitment), 32);
    return true;
}

static bool fetchAccountData(LogosAPIClient* walletClient,
                              const QString& accountIdHex,
                              QByteArray& outData,
                              QByteArray* outProgramOwner /* = nullptr */) {
    // Drain event loop before blocking RPC — keeps lightpush etc. alive.
    QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
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

    RlnFfiMerkleProofsPlan accountsPlan = {};
    RlnFfiError err = rln_ffi_merkle_proofs_plan(
        reinterpret_cast<const uint8_t*>(configData.constData()),
        static_cast<size_t>(configData.size()),
        reinterpret_cast<const uint8_t*>(programOwnerBytes.constData()),
        nullptr, 0,
        &accountsPlan);
    if (err != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << "register_member: failed to derive tree main account";
        return {};
    }

    const QString treeMainHex = bytesToHex(accountsPlan.main_account_id, 32);
    QByteArray treeMainData;
    if (!fetchAccountData(walletClient, treeMainHex, treeMainData)) {
        qWarning() << "register_member: failed to fetch tree main account";
        return {};
    }

    // tree_id comes from config; id_commitment seeds the init-marked
    // membership PDA required by the guest's Register instruction.
    RlnFfiRlnRegisterPlan plan = {};
    err = rln_ffi_register_plan(
        reinterpret_cast<const uint8_t*>(configData.constData()),
        static_cast<size_t>(configData.size()),
        reinterpret_cast<const uint8_t*>(treeMainData.constData()),
        static_cast<size_t>(treeMainData.size()),
        reinterpret_cast<const uint8_t*>(programOwnerBytes.constData()),
        reinterpret_cast<const uint8_t*>(idCommitmentBytes.constData()),
        &plan);
    if (err != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << "register_member: register_plan FFI error" << static_cast<int>(err);
        return {};
    }

    const QString membershipPdaHex = bytesToHex(plan.membership_account_id, 32);

    // Idempotency pre-check: if the membership PDA is already populated
    // for this (tree_id, id_commitment) — either from a previous run that
    // persisted credentials, or from a prior submit whose root-poll timed
    // out — skip the tx and return the recovered leaf_index. The on-chain
    // Register handler enforces uniqueness via Claim::Pda on this PDA, so
    // resubmitting always fails (state_tests.rs::test_register_same_commitment_twice_fails).
    {
        QByteArray existing;
        if (fetchAccountDataQuiet(walletClient, membershipPdaHex, existing)
            && existing.size() >= 64) {
            quint64 existingLeaf = 0, existingRateLimit = 0;
            QByteArray existingIdc;
            if (decodeMembership(existing, existingLeaf, existingRateLimit, existingIdc)) {
                qDebug() << "register_member: membership already exists at leaf"
                         << existingLeaf << "— skipping resubmit";
                QJsonObject result;
                result["leaf_index"] = static_cast<qint64>(existingLeaf);
                result["already_registered"] = true;
                return QJsonDocument(result).toJson(QJsonDocument::Compact);
            }
        }
    }

    // SPEL `Instruction::Register` needs all of {tree_id, id_commitment,
    // rate_limit, subtree_id} — missing fields → guest DeserializeUnexpectedEnd.
    // tree_id sits at offset 32..64 of the ConfigState borsh layout.
    if (configData.size() < 64) {
        qWarning() << "register_member: configData too short for tree_id";
        return {};
    }
    const uint8_t* treeIdPtr = reinterpret_cast<const uint8_t*>(configData.constData()) + 32;
    uint8_t* instrPtr = nullptr;
    size_t instrLen = 0;
    err = rln_ffi_register_build_instruction(
        treeIdPtr,
        reinterpret_cast<const uint8_t*>(idCommitmentBytes.constData()),
        rate_limit,
        plan.subtree_id,
        &instrPtr, &instrLen);
    if (err != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << "register_member: build_instruction FFI error" << static_cast<int>(err);
        return {};
    }

    const QString instructionHex = bytesToHex(instrPtr, instrLen);
    rln_ffi_free_string(instrPtr, instrLen);

    // Account order must match methods/guest/src/program.rs::register:
    //   config, tree_main, user_holding (signer), treasury, bottom_subtree,
    //   clock_account, membership (init).
    QJsonArray accountsList;
    accountsList.append(bytesToHex(plan.config_account_id, 32));
    accountsList.append(bytesToHex(plan.tree_main_account_id, 32));
    accountsList.append(userHoldingHex);
    accountsList.append(bytesToHex(plan.treasury_account_id, 32));
    accountsList.append(bytesToHex(plan.subtree_account_id, 32));
    accountsList.append(bytesToHex(plan.clock_account_id, 32));
    accountsList.append(bytesToHex(plan.membership_account_id, 32));

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

    // Submission accepted by the sequencer; we DO NOT block here waiting
    // for on-chain confirmation. Two reasons:
    //   1. waitForFinished() on the caller's QtRO call doesn't drain its
    //      own event loop, so a 120s wait here would stall every other
    //      QtRO request queued on the caller's thread (host CLI -c
    //      commands, lightpush, gossipsub ticks).
    //   2. plan.next_leaf_index is a pre-submit snapshot — it can be
    //      wrong if our tx loses a race. The authoritative leaf_index
    //      lives in the membership PDA after the tx executes; callers
    //      must poll is_member_registered() to recover it.
    QJsonObject result;
    result["leaf_index"] = static_cast<qint64>(plan.next_leaf_index);
    result["tx_result"] = sendResultStr;
    result["pending"] = true;
    return QJsonDocument(result).toJson(QJsonDocument::Compact);
}

QString LogosRlnModule::is_member_registered(const QString& config_account_id,
                                              const QString& id_commitment_hex) {
    if (!logosAPI) {
        qWarning() << "is_member_registered: logosAPI not initialized";
        return {};
    }
    auto* walletClient = logosAPI->getClient(WALLET_MODULE);
    if (!walletClient) {
        qWarning() << "is_member_registered: wallet module not available";
        return {};
    }
    const QString configHex = resolveAccountId(walletClient, config_account_id);
    if (configHex.isEmpty()) {
        qWarning() << "is_member_registered: failed to resolve config account";
        return {};
    }

    QByteArray idCommitmentBytes;
    if (!hexToBytes(id_commitment_hex, idCommitmentBytes, 32)) {
        qWarning() << "is_member_registered: invalid id_commitment hex";
        return {};
    }

    // Reuse the same FFI derivation path as register_member so the
    // membership PDA address is computed identically.
    QByteArray configData, programOwnerBytes;
    if (!fetchAccountData(walletClient, configHex, configData, &programOwnerBytes)
        || programOwnerBytes.size() != 32) {
        qWarning() << "is_member_registered: failed to fetch config account";
        return {};
    }

    RlnFfiMerkleProofsPlan accountsPlan = {};
    if (rln_ffi_merkle_proofs_plan(
            reinterpret_cast<const uint8_t*>(configData.constData()),
            static_cast<size_t>(configData.size()),
            reinterpret_cast<const uint8_t*>(programOwnerBytes.constData()),
            nullptr, 0,
            &accountsPlan) != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << "is_member_registered: derive tree main failed";
        return {};
    }
    const QString treeMainHex = bytesToHex(accountsPlan.main_account_id, 32);
    QByteArray treeMainData;
    if (!fetchAccountData(walletClient, treeMainHex, treeMainData)) {
        qWarning() << "is_member_registered: fetch tree main failed";
        return {};
    }

    RlnFfiRlnRegisterPlan plan = {};
    if (rln_ffi_register_plan(
            reinterpret_cast<const uint8_t*>(configData.constData()),
            static_cast<size_t>(configData.size()),
            reinterpret_cast<const uint8_t*>(treeMainData.constData()),
            static_cast<size_t>(treeMainData.size()),
            reinterpret_cast<const uint8_t*>(programOwnerBytes.constData()),
            reinterpret_cast<const uint8_t*>(idCommitmentBytes.constData()),
            &plan) != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << "is_member_registered: register_plan FFI failed";
        return {};
    }

    const QString membershipPdaHex = bytesToHex(plan.membership_account_id, 32);
    QByteArray membershipData;
    QJsonObject result;
    if (fetchAccountDataQuiet(walletClient, membershipPdaHex, membershipData)
        && membershipData.size() >= 64) {
        quint64 leafIndex = 0, rateLimit = 0;
        QByteArray idc;
        if (decodeMembership(membershipData, leafIndex, rateLimit, idc)) {
            result["registered"] = true;
            result["leaf_index"] = static_cast<qint64>(leafIndex);
            return QJsonDocument(result).toJson(QJsonDocument::Compact);
        }
    }
    result["registered"] = false;
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

    const QString proofsJson = QString::fromUtf8(reinterpret_cast<const char*>(jsonPtr),
                                                  static_cast<int>(jsonLen));
    rln_ffi_free_string(jsonPtr, jsonLen);

    // 7. Extract valid_roots from the SAME mainData buffer we just used to
    //    build the proofs. Avoids a race where a follow-up get_valid_roots
    //    call would re-fetch the main account after another registration TX
    //    landed, returning a roots window that no longer contains the root
    //    encoded in the proofs we just computed.
    uint8_t rootsBuf[160] = {};
    uint32_t rootsCount = 0;
    err = rln_ffi_get_valid_roots(
        reinterpret_cast<const uint8_t*>(mainData.constData()),
        static_cast<size_t>(mainData.size()),
        rootsBuf, &rootsCount);
    QJsonArray rootsArray;
    if (err == RLN_FFI_ERROR_SUCCESS) {
        for (uint32_t i = 0; i < rootsCount; ++i) {
            rootsArray.append(bytesToHex(rootsBuf + i * 32, 32));
        }
    } else {
        qWarning() << "get_merkle_proofs: get_valid_roots FFI error" << static_cast<int>(err);
    }

    // Inject valid_roots into each proof object so a single RPC returns both.
    QJsonArray proofsArr = QJsonDocument::fromJson(proofsJson.toUtf8()).array();
    QJsonArray augmented;
    for (const auto& v : proofsArr) {
        QJsonObject o = v.toObject();
        o["valid_roots"] = rootsArray;
        augmented.append(o);
    }
    return QString::fromUtf8(QJsonDocument(augmented).toJson(QJsonDocument::Compact));
}
