#include "logos_rln_module.h"

#include <cpp/logos_api_client.h>
#include <QtCore/QDebug>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QVariantMap>

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

    // Convert base58 account ID to hex if needed (not a 64-char hex string)
    QString accountIdHex = rln_account_id_hex;
    const QString trimmed = rln_account_id_hex.trimmed();
    const QString stripped = trimmed.startsWith("0x", Qt::CaseInsensitive)
        ? trimmed.mid(2) : trimmed;
    if (stripped.size() != 64) {
        // Assume base58, convert via wallet module
        const QVariant hexResult = walletClient->invokeRemoteMethod(
            WALLET_MODULE, "account_id_from_base58", QVariant(rln_account_id_hex));
        accountIdHex = hexResult.toString();
        if (accountIdHex.isEmpty()) {
            qWarning() << "get_valid_roots: failed to convert base58 account ID";
            return {};
        }
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
