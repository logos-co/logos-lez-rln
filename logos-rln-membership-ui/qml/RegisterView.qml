// Register flow: unlock keystore -> generate identity (sibling rln module)
// -> register -> poll get_membership_state until the pending window settles.
// Mirrors logos-rln-membership-module/tests/e2e_register_testnet.sh. The
// funding holding account is either typed in or auto-filled by the Wallet
// tab's faucet claim (Main.qml wires WalletView.funded to fundingAccount).
import QtQuick
import QtQuick.Layouts
import Logos.Theme
import Logos.Controls
import "membership.js" as M

LogosScrollView {
    id: view

    required property var bridge
    required property string registryId

    // Written by Main.qml when the Wallet tab confirms a funded holding.
    property alias fundingAccount: fundingField.text

    // Keystore session (unlock holds the password module-side; lock drops it).
    property bool unlocked: false
    property int membershipCount: -1

    // Generated identity. The secret stays in QML memory only until register
    // hands it to the module's encrypted keystore.
    property string commitment: ""
    property string secretHash: ""

    // In-flight + registration status.
    property bool busy: false
    property string status: ""
    property bool statusIsError: false
    property string liveState: ""

    function report(text, isError) {
        status = text
        statusIsError = isError === true
    }

    function doUnlock() {
        busy = true
        M.call(bridge, M.MEMBERSHIP_MODULE, "unlock_keystore", [passwordField.text], function (r) {
            view.busy = false
            if (r.error) { view.report(M.errorText(r.error), true); return }
            view.unlocked = r.unlocked === true
            view.membershipCount = r.membership_count !== undefined ? r.membership_count : -1
            view.report(view.membershipCount === 0
                ? "Keystore unlocked (empty) — this password becomes the encryption password when the first credential is stored."
                : "Keystore unlocked — " + view.membershipCount + " stored credential"
                  + (view.membershipCount === 1 ? "" : "s") + ".", false)
        })
    }

    function doLock() {
        busy = true
        M.call(bridge, M.MEMBERSHIP_MODULE, "lock_keystore", [], function (r) {
            view.busy = false
            if (r.error) { view.report(M.errorText(r.error), true); return }
            view.unlocked = false
            view.membershipCount = -1
            view.report("Keystore locked.", false)
        })
    }

    function doGenerate() {
        busy = true
        M.call(bridge, M.RLN_MODULE, "generate_identity", [seedField.text.trim()], function (r) {
            view.busy = false
            if (r.error) { view.report(M.errorText(r.error), true); return }
            if (!r.id_commitment || !r.id_secret_hash) {
                view.report("generate_identity returned no credential: " + JSON.stringify(r), true)
                return
            }
            view.commitment = r.id_commitment
            view.secretHash = r.id_secret_hash
            view.liveState = ""
            view.report("Identity ready — commitment " + M.truncateHex(view.commitment, 16, 8), false)
        })
    }

    function doRegister() {
        // Spec credential JSON (LE hex); options carry the paying account for
        // the logos namespace.
        var credential = JSON.stringify({
            identity_commitment: commitment,
            identity_secret_hash: secretHash
        })
        var options = JSON.stringify({
            funding_holding_account_id: fundingField.text.trim()
        })
        busy = true
        liveState = ""
        M.call(bridge, M.MEMBERSHIP_MODULE, "register",
               [registryId, credential, rateSpin.value, options], function (r) {
            view.busy = false
            if (r.error) { view.report(M.errorText(r.error), true); return }
            view.liveState = r.state || "pending"
            var note = r.rate_limit_mismatch === true
                ? " NOTE: already registered on-chain with a different rate limit." : ""
            view.report("Registration submitted (membership "
                + M.truncateHex(r.membership_hash || "", 12, 6)
                + ") — testnet confirmation takes ~60-90s." + note, false)
            pollTimer.start()
        })
    }

    function pollState() {
        if (commitment === "" || registryId === "") { pollTimer.stop(); return }
        M.call(bridge, M.MEMBERSHIP_MODULE, "get_membership_state",
               [registryId, commitment], function (r) {
            if (r.error) { pollTimer.stop(); view.report(M.errorText(r.error), true); return }
            view.liveState = r.state || "unknown"
            if (view.liveState === "pending") return
            pollTimer.stop()
            if (view.liveState === "active")
                view.report("Membership ACTIVE at leaf " + r.leaf_index
                    + ". On this testnet it stays active ~43 min before grace_period/expired.", false)
            else if (view.liveState === "failed")
                view.report("Registration FAILED — see the Memberships tab for the failure reason.", true)
            else
                view.report("Membership settled in state \"" + view.liveState + "\".", false)
        })
    }

    // The pending confirmation window is bounded (300s) module-side, so the
    // poll always reaches a settled state and stops itself.
    Timer {
        id: pollTimer
        interval: 10000
        repeat: true
        onTriggered: view.pollState()
    }

    ColumnLayout {
        width: view.availableWidth
        spacing: Theme.spacing.medium

        LogosGroupBox {
            Layout.fillWidth: true
            title: "Keystore"

            ColumnLayout {
                spacing: Theme.spacing.small

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.spacing.small

                    LogosTextField {
                        id: passwordField
                        Layout.fillWidth: true
                        echoMode: TextInput.Password
                        placeholderText: "Keystore password"
                        enabled: !view.unlocked
                    }
                    LogosButton {
                        implicitWidth: 110
                        implicitHeight: 40
                        text: view.unlocked ? "Lock" : "Unlock"
                        enabled: !view.busy && (view.unlocked || passwordField.text.length > 0)
                        onClicked: view.unlocked ? view.doLock() : view.doUnlock()
                    }
                }

                LogosText {
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    font.pixelSize: Theme.typography.secondaryText
                    color: Theme.palette.textTertiary
                    text: "First use: with an empty keystore ANY password unlocks and becomes "
                        + "the keystore's encryption password when the first credential is "
                        + "stored (the keystore format has no up-front verifier). Later "
                        + "unlocks are checked against the stored credentials."
                }

                LogosText {
                    visible: view.unlocked
                    font.pixelSize: Theme.typography.secondaryText
                    color: Theme.palette.success
                    text: view.membershipCount < 0 ? "Unlocked"
                        : "Unlocked — " + view.membershipCount + " stored credential"
                          + (view.membershipCount === 1 ? "" : "s")
                }
            }
        }

        LogosGroupBox {
            Layout.fillWidth: true
            title: "Identity"

            ColumnLayout {
                spacing: Theme.spacing.small

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.spacing.small

                    LogosTextField {
                        id: seedField
                        Layout.fillWidth: true
                        placeholderText: "32-byte hex seed"
                        text: M.randomSeedHex()
                    }
                    LogosButton {
                        implicitWidth: 110
                        implicitHeight: 40
                        text: "New seed"
                        enabled: !view.busy
                        onClicked: seedField.text = M.randomSeedHex()
                    }
                    LogosButton {
                        implicitWidth: 150
                        implicitHeight: 40
                        text: "Generate identity"
                        enabled: !view.busy && M.isHex32(seedField.text.trim())
                        onClicked: view.doGenerate()
                    }
                }

                LogosText {
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    font.pixelSize: Theme.typography.secondaryText
                    color: Theme.palette.textTertiary
                    text: "The identity is derived deterministically from the seed by the rln "
                        + "module. The prefilled seed is UI-grade randomness — paste your own "
                        + "entropy (e.g. openssl rand -hex 32) for anything beyond testnet demos."
                }

                RowLayout {
                    visible: view.commitment !== ""
                    spacing: Theme.spacing.small

                    LogosText {
                        text: "Commitment"
                        color: Theme.palette.textSecondary
                        font.pixelSize: Theme.typography.secondaryText
                    }
                    LogosText {
                        text: M.truncateHex(view.commitment, 16, 8)
                        font.pixelSize: Theme.typography.secondaryText
                    }
                }
            }
        }

        LogosGroupBox {
            Layout.fillWidth: true
            title: "Registration"

            ColumnLayout {
                spacing: Theme.spacing.small

                GridLayout {
                    Layout.fillWidth: true
                    columns: 2
                    columnSpacing: Theme.spacing.medium
                    rowSpacing: Theme.spacing.small

                    LogosText {
                        text: "Rate limit"
                        color: Theme.palette.textSecondary
                    }
                    RowLayout {
                        spacing: Theme.spacing.small

                        LogosSpinBox {
                            id: rateSpin
                            from: M.RATE_LIMIT_MIN
                            to: M.RATE_LIMIT_MAX
                            value: M.RATE_LIMIT_DEFAULT
                            stepSize: 10
                        }
                        LogosText {
                            text: "messages per epoch (" + M.RATE_LIMIT_MIN + "–" + M.RATE_LIMIT_MAX + ")"
                            color: Theme.palette.textTertiary
                            font.pixelSize: Theme.typography.secondaryText
                        }
                    }

                    LogosText {
                        text: "Funding account"
                        color: Theme.palette.textSecondary
                    }
                    LogosTextField {
                        id: fundingField
                        Layout.fillWidth: true
                        placeholderText: "Funded holding account (hex or base58) — or claim one on the Wallet tab"
                    }
                }

                RowLayout {
                    spacing: Theme.spacing.small

                    LogosButton {
                        implicitWidth: 180
                        implicitHeight: 40
                        text: "Register membership"
                        enabled: !view.busy && view.unlocked && view.commitment !== ""
                                 && fundingField.text.trim() !== "" && view.registryId !== ""
                        onClicked: view.doRegister()
                    }
                    LogosSpinner {
                        visible: view.busy || pollTimer.running
                        implicitWidth: 22
                        implicitHeight: 22
                        thickness: 2
                        dotSize: 4
                    }
                    StateBadge {
                        visible: view.liveState !== ""
                        membershipState: view.liveState
                    }
                }

                LogosText {
                    visible: view.status !== ""
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    font.pixelSize: Theme.typography.secondaryText
                    color: view.statusIsError ? Theme.palette.error : Theme.palette.textSecondary
                    text: view.status
                }
            }
        }
    }
}
