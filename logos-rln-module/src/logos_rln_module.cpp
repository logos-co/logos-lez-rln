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
        QStringLiteral("logos_execution_zone"), QStringLiteral("account_id_from_base58"),
        QVariant(id), Timeout(60000));
    return hexResult.toString();
}

static bool fetchAccountData(LogosAPIClient* walletClient,
                              const QString& accountIdHex,
                              QByteArray& outData,
                              QByteArray* outProgramOwner = nullptr);

// Shared derivation prefix for the on-chain RLN entry points. Bundles the
// wallet client, the resolved config account id, its raw data, and the
// 32-byte program owner — the inputs every method needs before talking FFI.
struct RlnConfigContext {
    LogosAPIClient* walletClient = nullptr;
    QString configHex;
    QByteArray configData;
    QByteArray programOwnerBytes;
};

static bool resolveConfigContext(LogosAPI* logosApi,
                                 const QString& configAccountId,
                                 const char* who,
                                 RlnConfigContext& out);

static bool deriveRegisterPlan(const RlnConfigContext& ctx,
                               const QByteArray& idCommitmentBytes,
                               const char* who,
                               RlnFfiRlnRegisterPlan& outPlan);

QString LogosRlnModule::get_valid_roots(const QString& rln_account_id_hex) {
    RlnConfigContext ctx;
    if (!resolveConfigContext(logosAPI, rln_account_id_hex, "get_valid_roots", ctx)) {
        return {};
    }

    // Derive tree main account via merkle_proofs_plan (no leaves needed).
    RlnFfiMerkleProofsPlan accountsPlan = {};
    RlnFfiError err = rln_ffi_merkle_proofs_plan(
        reinterpret_cast<const uint8_t*>(ctx.configData.constData()),
        static_cast<size_t>(ctx.configData.size()),
        reinterpret_cast<const uint8_t*>(ctx.programOwnerBytes.constData()),
        nullptr, 0,
        &accountsPlan);
    if (err != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << "get_valid_roots: merkle_proofs_plan FFI error" << static_cast<int>(err);
        return {};
    }

    const QString mainHex = bytesToHex(accountsPlan.main_account_id, 32);
    QByteArray mainData;
    if (!fetchAccountData(ctx.walletClient, mainHex, mainData)) {
        qWarning() << "get_valid_roots: failed to fetch tree main account" << mainHex;
        return {};
    }

    uint8_t rootsBuf[160] = {};
    uint32_t count = 0;
    err = rln_ffi_get_valid_roots(
        reinterpret_cast<const uint8_t*>(mainData.constData()),
        static_cast<size_t>(mainData.size()),
        rootsBuf, &count);
    if (err != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << "get_valid_roots: get_valid_roots FFI error" << static_cast<int>(err);
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
        QStringLiteral("logos_execution_zone"), QStringLiteral("get_account_public"),
        QVariant(accountIdHex), Timeout(60000));
    const QString json = result.toString();
    if (json.isEmpty()) return false;
    const QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
    if (!doc.isObject()) return false;
    const QString dataHex = doc.object().value("data").toString();
    if (dataHex.isEmpty()) return false;
    return hexToBytes(dataHex, outData);
}

// Tri-state fetch: distinguishes a legitimately-empty account from a real
// fetch error. Callers that treat both as "no data" silently substitute an
// empty proof leaf when a transient RPC/parse error hits an account that
// actually exists on-chain — producing a proof against the wrong root that
// the verifier rejects ("Expected one of the provided roots"). See
// get_merkle_proofs's subtree loop for the only consumer.
enum class FetchOutcome { Present, Absent, Error };

static FetchOutcome fetchAccountDataTriState(LogosAPIClient* walletClient,
                                              const QString& accountIdHex,
                                              QByteArray& outData) {
    QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    const QVariant result = walletClient->invokeRemoteMethod(
        QStringLiteral("logos_execution_zone"), QStringLiteral("get_account_public"),
        QVariant(accountIdHex), Timeout(60000));
    const QString json = result.toString();
    if (json.isEmpty()) return FetchOutcome::Error;
    const QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
    if (!doc.isObject()) return FetchOutcome::Error;
    const QString dataHex = doc.object().value("data").toString();
    if (dataHex.isEmpty()) return FetchOutcome::Absent;
    if (!hexToBytes(dataHex, outData)) return FetchOutcome::Error;
    return FetchOutcome::Present;
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
        QStringLiteral("logos_execution_zone"), QStringLiteral("get_account_public"),
        QVariant(accountIdHex), Timeout(60000));
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

static bool resolveConfigContext(LogosAPI* logosApi,
                                 const QString& configAccountId,
                                 const char* who,
                                 RlnConfigContext& out) {
    if (!logosApi) {
        qWarning() << who << ": logosAPI not initialized";
        return false;
    }
    out.walletClient = logosApi->getClient(WALLET_MODULE);
    if (!out.walletClient) {
        qWarning() << who << ": wallet module not available";
        return false;
    }
    out.configHex = resolveAccountId(out.walletClient, configAccountId);
    if (out.configHex.isEmpty()) {
        qWarning() << who << ": failed to resolve config account";
        return false;
    }
    if (!fetchAccountData(out.walletClient, out.configHex, out.configData, &out.programOwnerBytes)) {
        qWarning() << who << ": failed to fetch config account";
        return false;
    }
    if (out.programOwnerBytes.size() != 32) {
        qWarning() << who << ": invalid program_owner size" << out.programOwnerBytes.size();
        return false;
    }
    return true;
}

static bool deriveRegisterPlan(const RlnConfigContext& ctx,
                               const QByteArray& idCommitmentBytes,
                               const char* who,
                               RlnFfiRlnRegisterPlan& outPlan) {
    RlnFfiMerkleProofsPlan accountsPlan = {};
    if (rln_ffi_merkle_proofs_plan(
            reinterpret_cast<const uint8_t*>(ctx.configData.constData()),
            static_cast<size_t>(ctx.configData.size()),
            reinterpret_cast<const uint8_t*>(ctx.programOwnerBytes.constData()),
            nullptr, 0,
            &accountsPlan) != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << who << ": derive tree main failed";
        return false;
    }
    const QString treeMainHex = bytesToHex(accountsPlan.main_account_id, 32);
    QByteArray treeMainData;
    if (!fetchAccountData(ctx.walletClient, treeMainHex, treeMainData)) {
        qWarning() << who << ": fetch tree main failed";
        return false;
    }
    if (rln_ffi_register_plan(
            reinterpret_cast<const uint8_t*>(ctx.configData.constData()),
            static_cast<size_t>(ctx.configData.size()),
            reinterpret_cast<const uint8_t*>(treeMainData.constData()),
            static_cast<size_t>(treeMainData.size()),
            reinterpret_cast<const uint8_t*>(ctx.programOwnerBytes.constData()),
            reinterpret_cast<const uint8_t*>(idCommitmentBytes.constData()),
            &outPlan) != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << who << ": register_plan FFI failed";
        return false;
    }
    return true;
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
    QByteArray idCommitmentBytes;
    if (!hexToBytes(id_commitment_hex, idCommitmentBytes, 32)) {
        qWarning() << "register_member: invalid id_commitment hex";
        return {};
    }

    RlnConfigContext ctx;
    if (!resolveConfigContext(logosAPI, config_account_id, "register_member", ctx)) {
        return {};
    }
    auto* walletClient = ctx.walletClient;
    const QByteArray& configData = ctx.configData;
    const QByteArray& programOwnerBytes = ctx.programOwnerBytes;

    const QString userHoldingHex = resolveAccountId(walletClient, user_holding_account_id);
    if (userHoldingHex.isEmpty()) {
        qWarning() << "register_member: failed to resolve user holding account";
        return {};
    }

    // tree_id comes from config; id_commitment seeds the init-marked
    // membership PDA required by the guest's Register instruction.
    RlnFfiRlnRegisterPlan plan = {};
    if (!deriveRegisterPlan(ctx, idCommitmentBytes, "register_member", plan)) {
        return {};
    }

    const QString membershipPdaHex = bytesToHex(plan.membership_account_id, 32);

    // Idempotency pre-check: if the membership PDA is already populated for this
    // (tree_id, id_commitment), recover its leaf_index instead of resubmitting —
    // the on-chain Register handler enforces uniqueness via Claim::Pda, so a
    // resubmit always fails.
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
    RlnFfiError err = rln_ffi_register_build_instruction(
        treeIdPtr,
        reinterpret_cast<const uint8_t*>(idCommitmentBytes.constData()),
        rate_limit,
        plan.subtree_id,
        &instrPtr, &instrLen);
    if (err != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << "register_member: build_instruction FFI error" << static_cast<int>(err);
        return {};
    }

    // Instruction bytes are a borsh Vec<u32> serialized LE; upstream's
    // send_generic_public_transaction takes the u32 words directly.
    if ((instrLen % 4) != 0) {
        qWarning() << "register_member: instruction not word-aligned" << instrLen;
        rln_ffi_free_string(instrPtr, instrLen);
        return {};
    }
    QVariantList instructionWords;
    instructionWords.reserve(static_cast<int>(instrLen / 4));
    for (size_t k = 0; k < instrLen / 4; ++k) {
        const uint8_t* p = instrPtr + k * 4;
        const uint32_t w = static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8)
                         | (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
        instructionWords.append(QVariant(static_cast<uint>(w)));
    }
    rln_ffi_free_string(instrPtr, instrLen);

    // Account order must match methods/guest/src/program.rs::register:
    //   config, tree_main, user_holding (signer), treasury, bottom_subtree,
    //   clock_account, membership (init).
    QVariantList accountIds;
    accountIds << bytesToHex(plan.config_account_id, 32)
               << bytesToHex(plan.tree_main_account_id, 32)
               << userHoldingHex
               << bytesToHex(plan.treasury_account_id, 32)
               << bytesToHex(plan.subtree_account_id, 32)
               << bytesToHex(plan.clock_account_id, 32)
               << bytesToHex(plan.membership_account_id, 32);
    // Only the user-holding (payer) account signs; the rest are read/PDA/init.
    QVariantList signingReqs;
    for (const QVariant& a : accountIds) signingReqs << (a.toString() == userHoldingHex);

    const QString programIdHex = bytesToHex(
        reinterpret_cast<const uint8_t*>(programOwnerBytes.constData()), 32);

    // Submit via the upstream program-id-based generic transaction; the typed
    // multi-arg invokeRemoteMethod marshals the array arguments over QtRO.
    const QVariant sendResult = walletClient->invokeRemoteMethod(
        QStringLiteral("logos_execution_zone"),
        QStringLiteral("send_generic_public_transaction"),
        QVariant(accountIds), QVariant(signingReqs), QVariant(instructionWords),
        QVariant(programIdHex), Timeout(180000));
    const QString sendResultStr = sendResult.toString();

    if (sendResultStr.isEmpty()) {
        qWarning() << "register_member: transaction failed";
        return {};
    }

    // Return once the sequencer accepts the submission; don't block on
    // confirmation. A blocking wait here wouldn't drain the caller's QtRO event
    // loop and would stall its other requests, and next_leaf_index is only a
    // pre-submit estimate. Callers poll is_member_registered() for the
    // authoritative leaf_index from the membership PDA.
    QJsonObject result;
    result["leaf_index"] = static_cast<qint64>(plan.next_leaf_index);
    result["tx_result"] = sendResultStr;
    result["pending"] = true;
    return QJsonDocument(result).toJson(QJsonDocument::Compact);
}

QString LogosRlnModule::is_member_registered(const QString& config_account_id,
                                              const QString& id_commitment_hex) {
    QByteArray idCommitmentBytes;
    if (!hexToBytes(id_commitment_hex, idCommitmentBytes, 32)) {
        qWarning() << "is_member_registered: invalid id_commitment hex";
        return {};
    }

    // Reuse the same FFI derivation path as register_member so the
    // membership PDA address is computed identically.
    RlnConfigContext ctx;
    if (!resolveConfigContext(logosAPI, config_account_id, "is_member_registered", ctx)) {
        return {};
    }

    RlnFfiRlnRegisterPlan plan = {};
    if (!deriveRegisterPlan(ctx, idCommitmentBytes, "is_member_registered", plan)) {
        return {};
    }

    const QString membershipPdaHex = bytesToHex(plan.membership_account_id, 32);
    QByteArray membershipData;
    QJsonObject result;
    if (fetchAccountDataQuiet(ctx.walletClient, membershipPdaHex, membershipData)
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

QString LogosRlnModule::mint_tokens(const QString& config_account_id,
                                    const QString& dest_account_id,
                                    const QString& amount) {
    RlnConfigContext ctx;
    if (!resolveConfigContext(logosAPI, config_account_id, "mint_tokens", ctx)) {
        return {};
    }
    auto* walletClient = ctx.walletClient;

    const QString destHex = resolveAccountId(walletClient, dest_account_id);
    if (destHex.isEmpty()) {
        qWarning() << "mint_tokens: failed to resolve destination account";
        return {};
    }

    // The config's payment_token_id is the mint authority (definition
    // account); its signing key must be in the open wallet. Instruction words
    // + both ids come from one FFI call so the Token-program ABI stays in Rust.
    const QByteArray amountUtf8 = amount.trimmed().toUtf8();
    uint8_t definitionId[32] = {};
    uint8_t tokenProgramId[32] = {};
    uint8_t* instrPtr = nullptr;
    size_t instrLen = 0;
    RlnFfiError err = rln_ffi_token_mint_plan(
        reinterpret_cast<const uint8_t*>(ctx.configData.constData()),
        static_cast<size_t>(ctx.configData.size()),
        reinterpret_cast<const uint8_t*>(amountUtf8.constData()),
        static_cast<size_t>(amountUtf8.size()),
        definitionId, tokenProgramId,
        &instrPtr, &instrLen);
    if (err != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << "mint_tokens: mint_plan FFI error" << static_cast<int>(err);
        return {};
    }

    if ((instrLen % 4) != 0) {
        qWarning() << "mint_tokens: instruction not word-aligned" << instrLen;
        rln_ffi_free_string(instrPtr, instrLen);
        return {};
    }
    QVariantList instructionWords;
    instructionWords.reserve(static_cast<int>(instrLen / 4));
    for (size_t k = 0; k < instrLen / 4; ++k) {
        const uint8_t* p = instrPtr + k * 4;
        const uint32_t w = static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8)
                         | (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
        instructionWords.append(QVariant(static_cast<uint>(w)));
    }
    rln_ffi_free_string(instrPtr, instrLen);

    const QString definitionHex = bytesToHex(definitionId, 32);

    // Token-program Mint account order: definition (authority), then the
    // destination holding — which may be a brand-new, uninitialized account
    // (the program zero-initializes the holding from the definition). BOTH
    // sign: a default destination is claimed with Claim::Authorized (token
    // program mint.rs), so its signature is required for the claim to
    // validate; the wallet silently skips signer flags for accounts whose
    // key it doesn't hold, which keeps already-initialized external
    // destinations working (no claim needed there).
    QVariantList accountIds;
    accountIds << definitionHex << destHex;
    QVariantList signingReqs;
    signingReqs << true << true;

    const QVariant sendResult = walletClient->invokeRemoteMethod(
        QStringLiteral("logos_execution_zone"),
        QStringLiteral("send_generic_public_transaction"),
        QVariant(accountIds), QVariant(signingReqs), QVariant(instructionWords),
        QVariant(bytesToHex(tokenProgramId, 32)), Timeout(180000));
    const QString sendResultStr = sendResult.toString();
    if (sendResultStr.isEmpty()) {
        qWarning() << "mint_tokens: transaction failed";
        return {};
    }

    // Sequencer accept only — callers poll get_token_balance for the credit
    // (same non-blocking contract as register_member).
    QJsonObject result;
    result["tx_result"] = sendResultStr;
    result["definition"] = definitionHex;
    result["pending"] = true;
    return QJsonDocument(result).toJson(QJsonDocument::Compact);
}

QString LogosRlnModule::get_token_balance(const QString& account_id) {
    if (!logosAPI) {
        qWarning() << "get_token_balance: logosAPI not initialized";
        return {};
    }
    auto* walletClient = logosAPI->getClient(WALLET_MODULE);
    if (!walletClient) {
        qWarning() << "get_token_balance: wallet module not available";
        return {};
    }
    const QString accountHex = resolveAccountId(walletClient, account_id);
    if (accountHex.isEmpty()) {
        qWarning() << "get_token_balance: failed to resolve account";
        return {};
    }

    QJsonObject result;
    QByteArray data;
    // Quiet fetch: an absent/empty account is the normal pre-mint state.
    if (!fetchAccountDataQuiet(walletClient, accountHex, data) || data.isEmpty()) {
        result["exists"] = false;
        result["balance"] = QStringLiteral("0");
        return QJsonDocument(result).toJson(QJsonDocument::Compact);
    }

    uint8_t definitionId[32] = {};
    char balanceBuf[48] = {};
    size_t balanceLen = 0;
    const RlnFfiError err = rln_ffi_token_holding_info(
        reinterpret_cast<const uint8_t*>(data.constData()),
        static_cast<size_t>(data.size()),
        definitionId,
        reinterpret_cast<uint8_t*>(balanceBuf), sizeof(balanceBuf), &balanceLen);
    if (err != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << "get_token_balance: holding parse FFI error" << static_cast<int>(err);
        return {};
    }

    result["exists"] = true;
    result["balance"] = QString::fromLatin1(balanceBuf, static_cast<int>(balanceLen));
    result["definition"] = bytesToHex(definitionId, 32);
    return QJsonDocument(result).toJson(QJsonDocument::Compact);
}

QString LogosRlnModule::get_merkle_proofs(const QString& config_account_id,
                                           const QString& leaf_indices_json) {
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
        leafIndices.append(static_cast<uint64_t>(val.toInteger()));
    }

    // 2. Resolve config account ID and fetch config data
    RlnConfigContext ctx;
    if (!resolveConfigContext(logosAPI, config_account_id, "get_merkle_proofs", ctx)) {
        return {};
    }
    auto* walletClient = ctx.walletClient;

    // 3. Phase 1: ask Rust which accounts we need to fetch
    RlnFfiMerkleProofsPlan plan = {};
    RlnFfiError err = rln_ffi_merkle_proofs_plan(
        reinterpret_cast<const uint8_t*>(ctx.configData.constData()),
        static_cast<size_t>(ctx.configData.size()),
        reinterpret_cast<const uint8_t*>(ctx.programOwnerBytes.constData()),
        leafIndices.constData(),
        static_cast<size_t>(leafIndices.size()),
        &plan);
    if (err != RLN_FFI_ERROR_SUCCESS) {
        qWarning() << "get_merkle_proofs: plan FFI error" << static_cast<int>(err);
        return {};
    }

    // 4-7. Stable-snapshot loop. A proof root spans the main account and the
    //   subtree accounts, but the wallet's reads aren't snapshot-bound: a
    //   registration landing mid-read yields a torn (main, subtree) pair whose
    //   root is in no valid_roots window. We bracket the subtree reads with two
    //   main fetches; the valid_roots window is a tree-state digest, so equal
    //   windows prove no mutation occurred and the pair is consistent. On
    //   mismatch we re-read everything.
    const QString mainHex = bytesToHex(plan.main_account_id, 32);

    // Raw concatenated 32-byte valid roots from a main-account buffer. Doubles
    // as the consistency sentinel and as the window injected into the response.
    auto extractValidRoots = [](const QByteArray& md, QByteArray& outRaw) -> bool {
        uint8_t rootsBuf[160] = {};
        uint32_t rootsCount = 0;
        RlnFfiError e = rln_ffi_get_valid_roots(
            reinterpret_cast<const uint8_t*>(md.constData()),
            static_cast<size_t>(md.size()), rootsBuf, &rootsCount);
        if (e != RLN_FFI_ERROR_SUCCESS) return false;
        outRaw = QByteArray(reinterpret_cast<const char*>(rootsBuf),
                            static_cast<int>(rootsCount) * 32);
        return true;
    };

    constexpr int kMaxSnapshotAttempts = 5;
    QString proofsJson;
    QByteArray stableRootsRaw;
    bool consistent = false;

    for (int attempt = 0; attempt < kMaxSnapshotAttempts; ++attempt) {
        // 4. Fetch main account (snapshot A — opens the read window).
        QByteArray mainData;
        if (!fetchAccountData(walletClient, mainHex, mainData)) {
            qWarning() << "get_merkle_proofs: failed to fetch main account" << mainHex;
            return {};
        }
        QByteArray rootsA;
        if (!extractValidRoots(mainData, rootsA)) {
            qWarning() << "get_merkle_proofs: get_valid_roots(A) FFI error";
            return {};
        }

        // 5. Fetch subtree accounts via the tri-state helper. Absent (empty
        //    data — subtree not yet initialized) is legitimate; Error (RPC
        //    failure, malformed JSON) routes into the snapshot retry below
        //    instead of silently substituting "empty" for an existing subtree,
        //    which would produce a proof with the wrong merkle root that the
        //    verifier rejects as "Expected one of the provided roots". [R5]
        QVector<QByteArray> subtreeDataBufs(static_cast<int>(plan.subtree_count));
        QVector<RlnFfiSubtreeEntry> subtreeEntries(static_cast<int>(plan.subtree_count));
        bool subtreeFetchErrored = false;
        for (uint32_t i = 0; i < plan.subtree_count; ++i) {
            const QString subtreeHex = bytesToHex(plan.subtree_account_ids[i], 32);
            const FetchOutcome outcome =
                fetchAccountDataTriState(walletClient, subtreeHex, subtreeDataBufs[i]);
            if (outcome == FetchOutcome::Error) {
                qWarning() << "get_merkle_proofs: subtree fetch errored"
                           << subtreeHex << "(attempt" << attempt << ") — retrying snapshot";
                subtreeFetchErrored = true;
                break;
            }
            // Present → use data; Absent → nullptr/0 (legitimate "not yet on-chain").
            subtreeEntries[i].subtree_id = plan.subtree_ids[i];
            subtreeEntries[i].data_ptr = subtreeDataBufs[i].isEmpty()
                ? nullptr
                : reinterpret_cast<const uint8_t*>(subtreeDataBufs[i].constData());
            subtreeEntries[i].data_len = static_cast<size_t>(subtreeDataBufs[i].size());
        }
        if (subtreeFetchErrored) continue;

        // 6. Refetch main account (snapshot B — closes the read window) and
        //    compare windows. Mismatch ⇒ the tree mutated while we read
        //    subtrees; the (main, subtree) pair is torn — discard and retry.
        QByteArray mainDataB;
        if (!fetchAccountData(walletClient, mainHex, mainDataB)) {
            qWarning() << "get_merkle_proofs: refetch main account failed (attempt"
                       << attempt << ")";
            continue;
        }
        QByteArray rootsB;
        if (!extractValidRoots(mainDataB, rootsB)) {
            qWarning() << "get_merkle_proofs: get_valid_roots(B) FFI error";
            return {};
        }
        if (rootsA != rootsB) {
            qInfo() << "get_merkle_proofs: tree advanced during subtree reads; "
                       "retrying for a consistent snapshot (attempt" << attempt << ")";
            continue;
        }

        // 7. Window stable across the subtree reads ⇒ main and subtrees are from
        //    one consistent state. Build proofs from that main; the proof root
        //    equals the current root, which is in rootsB. Phase 2 in Rust.
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
        proofsJson = QString::fromUtf8(reinterpret_cast<const char*>(jsonPtr),
                                       static_cast<int>(jsonLen));
        rln_ffi_free_string(jsonPtr, jsonLen);
        stableRootsRaw = rootsB;
        consistent = true;
        break;
    }

    if (!consistent) {
        // Never ship an internally-inconsistent proof: erroring lets the Nim
        // pollLoop keep its previous (consistent) cachedProof rather than cache
        // a self-verify-failing one. Sustained churn beyond kMaxSnapshotAttempts
        // is itself a signal worth surfacing.
        qWarning() << "get_merkle_proofs: no consistent tree snapshot after"
                   << kMaxSnapshotAttempts << "attempts";
        return {};
    }

    // Rebuild the valid_roots JSON array from the stable window.
    QJsonArray rootsArray;
    for (int i = 0; i + 32 <= stableRootsRaw.size(); i += 32) {
        rootsArray.append(bytesToHex(
            reinterpret_cast<const uint8_t*>(stableRootsRaw.constData()) + i, 32));
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
