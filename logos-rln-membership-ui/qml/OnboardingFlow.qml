// Non-visual onboarding controller: wallet -> sync -> keystore password ->
// faucet claim -> registration, as sequential idempotent phases with
// observable progress, no widget references. The flow logic deliberately
// DUPLICATES the live-proven Advanced views (they stay byte-identical —
// their logic is entangled with their widgets); every phase carries a
// "mirrors <view>.<fn> — keep in sync" cross-reference. An Item (not
// QtObject) so it can own the poll Timers; visible:false, zero footprint.
import QtQuick
import "membership.js" as M

Item {
    id: flow
    visible: false

    required property var bridge
    required property string registryId

    // Single password for both stores (wallet storage + keystore). Frozen by
    // the password step once walletCreated — create_new consumed it.
    property string password: ""
    property int rateLimit: M.RATE_LIMIT_DEFAULT
    property string priorNotice: ""

    // Set by Main from the startup probe (any local membership records ->
    // true) so the password step can frame itself as creation vs entry.
    // Imperfect by design: a keystore can exist with zero membership records
    // (unlocked once, never registered) — in that rare case the "new
    // account" framing shows, and a wrong password still surfaces through
    // the bad_password error line, which is acceptable.
    property bool hasExistingAccount: false

    // Phase A — wallet (provision + open/create).
    property string walletPhase: "idle"
    property string walletError: ""
    // Captured from create_new but not displayed; kept for a future
    // recovery/export surface without a wire change.
    property string mnemonic: ""
    property bool walletCreated: false

    // Phase B — sync (auto-chained after A).
    property string syncPhase: "idle"
    property string syncError: ""
    property int syncTarget: 0
    // The wallet's block when this sync began — the progress bar's origin,
    // so a resumed wallet still shows visible movement instead of opening
    // at 90%.
    property int syncStart: 0
    property int lastSynced: -1
    // Total sync_to_block calls this run (hard global bound) and consecutive
    // no-progress failures on the current chunk (small bounded retries).
    property int syncAttempts: 0
    property int syncChunkRetries: 0
    property bool syncToppedUp: false
    // Chunk size measured live 2026-07-16 against the testnet (fresh scratch
    // wallet, temp daemon, serial CLI calls): 500 blocks ≈ 2.7–4.5s,
    // 1000 ≈ 7–11s, 2000 ≈ 13–17s (~110–180 blocks/s). 500 gives a visible
    // bar step every few seconds; a fresh ~23k-block sync is ~47 chunks,
    // well inside the 200-call budget.
    readonly property int syncChunk: 500

    // Phase C — keystore password check (fired by the password step's Next).
    property string unlockPhase: "idle"
    property string unlockError: ""

    // Phase C′ — OS-keychain auto-unlock, fired by Main when routing into
    // onboarding. "done" implies unlockPhase is done and flow.password
    // carries the keychain secret (it feeds the wallet's create_new too);
    // "fallback" means the password screen runs manually — autoUnlockKind
    // keeps the error kind so the step can explain a stale saved sign-in.
    property string autoUnlockPhase: "idle"
    property string autoUnlockKind: ""
    // Set true by OnboardingView once the flow leaves Welcome; fences a late
    // startAutoUnlock from re-deciding the password path mid-flow. Reset to
    // false by restart() (which returns to Welcome).
    property bool started: false

    // Test-tunable poll cadence (production defaults preserved). A
    // deterministic mock-bridge test shrinks these so the flow runs in
    // seconds and the claim timeout is reachable. NOTE: sync is chunk-
    // callback-chained (no interval), so it has no tunable — it already runs
    // as fast as replies arrive. claimPollBudget bounds the claim timeout
    // (36 x claimPollMs = 180s in production).
    property int claimPollMs: 5000
    property int claimPollBudget: 36
    property int statePollMs: 10000

    // Bounded auto-retry for TRANSIENT transport failures on critical wire
    // calls (see callRetry). Same test-tunable pattern: a test sets
    // transientRetryMs tiny so retries run in ms. Max 4: the flaky transport
    // occasionally exhausts 3 retries on idempotent reads; the extra attempt is
    // cheap; claim/create_new are never auto-retried.
    property int transientRetryMs: 1500
    property int transientRetryMax: 4

    // Phase D — faucet claim into a fresh holding.
    property string fundPhase: "idle"
    property string fundError: ""
    property string pricePerUnit: ""
    property int claimAmount: 0
    property string holdingHex: ""
    property int claimPolls: 0

    // Phase E — identity + registration + confirmation poll.
    property string regPhase: "idle"
    property string regError: ""
    property string regState: ""
    property string commitment: ""
    property bool rateLimitMismatch: false
    // The identity secret lives here only between generate_identity and
    // register, which hands it to the module's encrypted keystore.
    property string secretHash: ""

    // ---- Gifter path (alternative to Phases A/B/D) -------------------------
    // "gifter" replaces wallet-provision + sync + faucet with a libp2p dial to
    // a gifter node that pays for the registration, authorized by a Keycard
    // attestation. Phase C (keystore unlock) and the Phase E register+poll tail
    // are REUSED — the gifter registers the identity on-chain, then the
    // idempotent register() records it in the keystore with no funds. Set on
    // Welcome; reset to "wallet" by resetForNewRegistration.
    property string registrationMode: "wallet"
    // idle | running | done | error. gifterStage is the running sub-step, for
    // the progress caption: node -> identity -> capture -> dial -> persist.
    property string gifterPhase: "idle"
    property string gifterStage: ""
    property string gifterError: ""
    // Gifter node coordinates (StepGifter inputs); both prefilled to the local
    // dev gifter's stable peerId + address, freely editable.
    property string gifterPeerId: M.GIFTER_PEER_ID_DEFAULT
    property string gifterMultiaddr: M.GIFTER_MULTIADDR_DEFAULT
    // The seed we derive the identity from and re-hand to rlnGifterRequest (it
    // re-derives the SAME identity internally), and the card's one-shot
    // nullifier from the verified attestation (kept for display/diagnostics).
    property string gifterSeed: ""
    property string gifterNullifier: ""
    // The gifter's on-chain register_member tx hash, passed to register() so the
    // gifted membership's detail view shows the transaction.
    property string gifterTxHash: ""
    // createNode + start are one-time per session; once a node answers peerInfo
    // we skip re-creating it on a retry or a second gifted membership.
    property bool libp2pNodeReady: false
    // The gifter pays for registration, but the CLIENT still needs an OPEN wallet
    // for on-chain READS: get_membership and the idempotent register both fetch
    // accounts through the wallet's sequencer connection ("Null wallet handle"
    // otherwise). Provisioned + opened once, unfunded, unsynced.
    property bool gifterWalletReady: false
    // On-chain confirmation of the gifter's registration (it submits the tx, so
    // the PDA is Pending for a bit before get_membership can read it). Poll until
    // it lands, then persist. Bounded so it always terminates.
    property int giftConfirmPolls: 0
    property int giftConfirmBudget: 40
    property int giftConfirmMs: 6000
    property string giftConfirmCfg: ""

    // Fired by finish() when the user leaves the completed wizard.
    signal completed(string commitment)

    function finish() {
        completed(commitment)
    }

    // Bounded auto-retry wrapper around M.call for the flow's critical wire
    // calls. On a TRANSIENT error (transport/host/sequencer flakiness — see
    // M.isTransientError) it waits transientRetryMs and retries, up to
    // transientRetryMax times, before delivering the error; a NON-transient
    // error (bad_password, invalid_argument, …) is delivered immediately
    // (retrying won't help). The one-shot backoff Timer is created per retry
    // from retryTimerComponent and self-destroys, so concurrent retries never
    // collide. Read-ish and idempotent calls use this; the manual Retry
    // button remains the backstop once auto-retry is exhausted.
    function callRetry(module, method, args, cb, timeoutMs) {
        callRetryAttempt(module, method, args, cb, 0, timeoutMs)
    }

    function callRetryAttempt(module, method, args, cb, attempt, timeoutMs) {
        M.call(bridge, module, method, args, function (r) {
            if (r.error && M.isTransientError(r.error.kind) && attempt < flow.transientRetryMax) {
                var t = retryTimerComponent.createObject(flow, { interval: flow.transientRetryMs })
                t.triggered.connect(function () {
                    t.destroy()
                    flow.callRetryAttempt(module, method, args, cb, attempt + 1, timeoutMs)
                })
                t.start()
            } else {
                cb(r)
            }
        }, timeoutMs)
    }

    // A NEW registration after a completed run: funding and registration
    // must run fresh (their "done" would otherwise no-op the restarts and
    // the progress screen would open pre-completed). Sync also resets to
    // idle so the re-run re-syncs the delta since last time (the wallet is
    // already open → a cheap catch-up); leaving it "done" would register
    // against a stale head and drop the claim into the 180s timeout. The
    // wallet phase stays done — the wallet itself is unchanged.
    function resetForNewRegistration() {
        if (syncPhase !== "running") {
            syncPhase = "idle"
            syncError = ""
            syncStart = 0
            lastSynced = -1
            syncTarget = 0
        }
        if (fundPhase !== "running") {
            fundPhase = "idle"
            fundError = ""
        }
        if (regPhase !== "running") {
            regPhase = "idle"
            regError = ""
            regState = ""
            commitment = ""
            rateLimitMismatch = false
        }
        // A re-run re-offers the Welcome choice, so default back to the wallet
        // path and clear the last gift attempt (a fresh seed/attestation next
        // time). The libp2p node, if up, stays up.
        registrationMode = "wallet"
        if (gifterPhase !== "running") {
            gifterPhase = "idle"
            gifterStage = ""
            gifterError = ""
            gifterSeed = ""
            gifterNullifier = ""
        }
    }

    // ---- Phase A: wallet ---------------------------------------------------
    // mirrors WalletView.doProvision — keep in sync
    function startWallet() {
        if (walletPhase === "running" || walletPhase === "done")
            return
        walletPhase = "running"
        walletError = ""
        callRetry(M.MEMBERSHIP_MODULE, "provision_wallet_home",
               [JSON.stringify({ sequencer_addr: M.TESTNET_SEQUENCER_ADDR })], function (r) {
            if (r.error) { flow.walletPhase = "error"; flow.walletError = M.errorText(r.error); return }
            if (r.storage_exists === true)
                flow.openWallet(String(r.config_path || ""), String(r.storage_path || ""))
            else
                flow.createWallet(String(r.config_path || ""), String(r.storage_path || ""))
        })
    }

    // mirrors WalletView.doOpen — keep in sync (plus the already-open probe:
    // a daemon-lifetime wallet from a previous wizard run reports open!=0,
    // but a working chain-head read proves it is usable).
    function openWallet(configPath, storagePath) {
        callRetry(M.WALLET_MODULE, "open", [configPath, storagePath], function (r) {
            if (!r.error && r.value === 0) {
                flow.walletPhase = "done"
                flow.startSync()
                return
            }
            callRetry(M.WALLET_MODULE, "get_current_block_height", [], function (r2) {
                if (!r2.error && r2.value > 0) {
                    flow.walletPhase = "done"
                    flow.startSync()
                } else {
                    flow.walletPhase = "error"
                    flow.walletError = r.error ? M.errorText(r.error)
                        : "open returned status " + r.value + " and the wallet answers no "
                          + "chain-head probe — wrong files, or the wallet module is wedged."
                }
            })
        })
    }

    // mirrors WalletView.doCreateFresh — keep in sync (no clobber guard
    // needed here: provision_wallet_home just reported storage_exists:false
    // for this exact path).
    function createWallet(configPath, storagePath) {
        M.call(bridge, M.WALLET_MODULE, "create_new",
               [configPath, storagePath, password], function (r) {
            if (r.error) {
                // create_new returns "" (the wallet module's ""-on-error
                // convention -> empty_reply) when a DIFFERENT wallet is
                // already open in the daemon (e.g. opened from the Advanced
                // Wallet tab). That wallet is usable, so recover by opening
                // it — mirrors startWallet's non-zero-open -> chain-head
                // probe. A genuine error still fails the phase.
                if (r.error.kind === "empty_reply") { flow.openWallet(configPath, storagePath); return }
                flow.walletPhase = "error"; flow.walletError = M.errorText(r.error); return
            }
            var words = r.value !== undefined ? String(r.value) : ""
            if (words === "") {
                flow.openWallet(configPath, storagePath)
                return
            }
            flow.mnemonic = words
            flow.walletCreated = true
            M.call(bridge, M.WALLET_MODULE, "save", [], function (r2) {
                flow.walletPhase = "done"
                flow.startSync()
            })
        })
    }

    // ---- Phase B: sync -----------------------------------------------------
    // mirrors WalletView.startSync — keep in sync (plus an already-synced
    // fast-path so "New membership" reruns skip the wait, and the chunked
    // execution divergence documented at syncChunkStep).
    function startSync() {
        if (syncPhase === "running" || syncPhase === "done")
            return
        syncAttempts = 0
        syncChunkRetries = 0
        syncToppedUp = false
        syncPhase = "running"
        syncError = ""
        callRetry(M.WALLET_MODULE, "get_current_block_height", [], function (r) {
            if (r.error || !(r.value > 0)) {
                flow.syncPhase = "error"
                flow.syncError = "Cannot discover the chain head (get_current_block_height "
                    + "returned " + (r.error ? "an error" : r.value) + ") — is the sequencer reachable?"
                return
            }
            flow.syncTarget = r.value
            callRetry(M.WALLET_MODULE, "get_last_synced_block", [], function (r2) {
                var last = (!r2.error && r2.value !== undefined) ? r2.value : 0
                flow.syncStart = last
                flow.lastSynced = last
                if (last >= flow.syncTarget) {
                    flow.syncPhase = "done"
                    return
                }
                flow.syncChunkStep()
            })
        })
    }

    // DELIBERATE divergence from WalletView.runSyncAttempt (which issues ONE
    // sync_to_block(head) and polls a 4s progress timer): measured live
    // 2026-07-16, the wallet module serves NO reads while a sync call is in
    // flight — concurrent get_last_synced_block starves until the sync
    // finishes (and impatient clients disconnecting mid-call can even crash
    // the module host), so the poll never moved and the bar sat gray. Here
    // sync runs in strictly SERIAL chunks — sync_to_block(min(last + chunk,
    // target)), then read the wallet's own last-synced block — so each chunk
    // completion IS the progress tick and no calls ever overlap. Success per
    // chunk is status 0 AND the read reaching the chunk target; a failed or
    // stalled chunk retries ITSELF a few times before the phase fails with
    // the unsynced-wallet diagnostic.
    function syncChunkStep() {
        syncAttempts += 1
        if (syncAttempts > 200) {
            flow.syncPhase = "error"
            flow.syncError = "Sync did not complete (attempt budget exhausted, synced "
                + flow.lastSynced + " / " + flow.syncTarget + "). Transactions from an "
                + "unsynced wallet are accepted but never apply — retry before claiming "
                + "or registering."
            return
        }
        var chunkTarget = Math.min(lastSynced + syncChunk, syncTarget)
        M.call(bridge, M.WALLET_MODULE, "sync_to_block", [chunkTarget], function (r) {
            M.call(bridge, M.WALLET_MODULE, "get_last_synced_block", [], function (r2) {
                var last = (!r2.error && r2.value !== undefined) ? r2.value : -1
                var progressed = last > flow.lastSynced
                if (last >= 0)
                    flow.lastSynced = last
                if (!r.error && r.value === 0 && last >= chunkTarget) {
                    flow.syncChunkRetries = 0
                    if (last >= flow.syncTarget)
                        flow.syncTopUp()
                    else
                        flow.syncChunkStep()
                } else if (progressed || flow.syncChunkRetries < 3) {
                    flow.syncChunkRetries = progressed ? 0 : flow.syncChunkRetries + 1
                    flow.syncChunkStep()
                } else {
                    flow.syncPhase = "error"
                    flow.syncError = "Sync did not complete (last status "
                        + (r.error ? r.error.kind : r.value) + ", synced " + last + " / "
                        + flow.syncTarget + "). Transactions from an unsynced wallet are "
                        + "accepted but never apply — retry before claiming or registering."
                }
            })
        }, 0)
    }

    // The head can advance while a long sync runs: one top-up pass re-reads
    // it and syncs the difference. One pass is enough — the register path
    // tolerates being a few blocks behind the live head.
    function syncTopUp() {
        if (syncToppedUp) {
            syncPhase = "done"
            return
        }
        syncToppedUp = true
        M.call(bridge, M.WALLET_MODULE, "get_current_block_height", [], function (r) {
            if (!r.error && r.value > flow.syncTarget) {
                flow.syncTarget = r.value
                flow.syncChunkStep()
            } else {
                flow.syncPhase = "done"
            }
        })
    }

    // ---- Phase C: keystore password ---------------------------------------
    // mirrors RegisterView.doUnlock — keep in sync. Front-loads bad_password
    // BEFORE the minutes-long sync/claim steps; with an empty keystore any
    // password unlocks and becomes the encryption password at first write.
    function checkPassword() {
        if (unlockPhase === "running" || unlockPhase === "done")
            return
        unlockPhase = "running"
        unlockError = ""
        callRetry(M.MEMBERSHIP_MODULE, "unlock_keystore", [password], function (r) {
            if (r.error) {
                flow.unlockPhase = "error"
                flow.unlockError = M.errorText(r.error)
                return
            }
            flow.unlockPhase = r.unlocked === true ? "done" : "error"
            if (flow.unlockPhase === "error") {
                flow.unlockError = "unlock_keystore did not unlock: " + JSON.stringify(r)
            } else if (flow.autoUnlockPhase === "fallback") {
                // Migration hook: a manual unlock after a keychain miss
                // persists the password module-side (the plaintext never
                // re-crosses the wire) so the next launch is silent.
                // Fire-and-forget — a failure only means the password
                // screen returns next time.
                M.call(bridge, M.MEMBERSHIP_MODULE, "remember_keystore_password", [], function (r2) {
                    if (r2.error)
                        console.warn("remember_keystore_password:", r2.error.kind, r2.error.message)
                })
            }
        })
    }

    // ---- Phase C′: OS-keychain auto-unlock ----------------------------------
    // The module fetches (or generates + persists FIRST) the keystore secret
    // from the macOS Keychain and unlocks through its normal verification
    // seam; the reply's secret becomes flow.password so the wallet's
    // create_new sees the same passphrase a manual entry would have. Any
    // failure (non-macOS, denied keychain, manual-era keystore without an
    // item, stale item -> bad_password) routes to "fallback": the password
    // screen, whose successful unlock then remembers itself (above).
    function startAutoUnlock() {
        if (autoUnlockPhase === "running" || autoUnlockPhase === "done")
            return
        // Fence: once the flow has moved past Welcome, the password decision
        // is already made (manual entry or an earlier auto-unlock) — never
        // let a late startAutoUnlock flip autoUnlockPhase and re-skip the
        // screen out from under an in-progress flow.
        if (started)
            return
        if (unlockPhase === "done") {
            // A manual unlock already happened — possibly with a password
            // that create_new consumed and froze. Never clobber it.
            autoUnlockPhase = "done"
            return
        }
        autoUnlockPhase = "running"
        autoUnlockKind = ""
        callRetry(M.MEMBERSHIP_MODULE, "unlock_keystore_auto", [], function (r) {
            if (r.error || r.unlocked !== true || !r.secret) {
                flow.autoUnlockKind = r.error ? String(r.error.kind) : "bad_reply"
                flow.autoUnlockPhase = "fallback"
                return
            }
            flow.password = String(r.secret)
            flow.unlockPhase = "done"
            flow.autoUnlockPhase = "done"
        })
    }

    // ---- Phase D: faucet claim ---------------------------------------------
    // mirrors WalletView.startClaim — keep in sync (amount comes from
    // M.suggestedClaimAmount instead of an editable field; editing lives in
    // Advanced). Always claims into a FRESH holding: no wire method lists
    // holdings, so a relaunch mid-claim orphans the previous claim's tokens.
    function startFunding() {
        if (fundPhase === "running" || fundPhase === "done")
            return
        var cfg = M.registryConfigHex(registryId)
        if (cfg === "") {
            fundPhase = "error"
            fundError = "Registry id is not logos:<ref>:<64-hex> — cannot derive the config account."
            return
        }
        fundPhase = "running"
        fundError = ""
        holdingHex = ""
        claimPolls = 0
        callRetry(M.RLN_MODULE, "get_registry_bounds", [cfg], function (r) {
            if (r.error || r.price_per_unit === undefined) {
                flow.fundPhase = "error"
                flow.fundError = r.error ? M.errorText(r.error)
                                         : "get_registry_bounds returned no price_per_unit"
                return
            }
            flow.pricePerUnit = String(r.price_per_unit)
            flow.claimAmount = M.suggestedClaimAmount(flow.rateLimit, flow.pricePerUnit)
            if (!(flow.claimAmount > 0)) {
                // Non-numeric price would make a 0-token claim that is
                // accepted and silently dropped — surface it instead.
                flow.fundPhase = "error"
                flow.fundError = "Couldn't determine the registration price (got \""
                    + flow.pricePerUnit + "\")."
                return
            }
            flow.deriveHolding(cfg, 0)
        })
    }

    // Back-to-Tokens path: a failed registration may have consumed the
    // holding, so a revisit can explicitly claim again.
    function restartFunding() {
        if (fundPhase === "running")
            return
        fundPhase = "idle"
        startFunding()
    }

    // mirrors WalletView.deriveHolding — keep in sync (the shared seed
    // wallet replays the same account sequence deterministically, so keep
    // deriving until get_token_balance says exists:false).
    function deriveHolding(cfg, tries) {
        if (tries >= 15) {
            fundPhase = "error"
            fundError = "No unused holding account after 15 derivations."
            return
        }
        callRetry(M.WALLET_MODULE, "create_account_public", [], function (r) {
            if (r.error || r.value === undefined) {
                flow.fundPhase = "error"
                flow.fundError = "create_account_public failed"
                    + (r.error ? ": " + M.errorText(r.error) : "")
                return
            }
            var acc = String(r.value)
            callRetry(M.RLN_MODULE, "get_token_balance", [acc], function (rb) {
                if (rb.error) { flow.fundPhase = "error"; flow.fundError = M.errorText(rb.error); return }
                if (rb.exists === false) {
                    flow.holdingHex = acc
                    flow.submitClaim(cfg, acc)
                } else {
                    flow.deriveHolding(cfg, tries + 1)
                }
            })
        })
    }

    // mirrors WalletView.submitClaim — keep in sync
    function submitClaim(cfg, acc) {
        M.call(bridge, M.RLN_MODULE, "claim_tokens", [cfg, acc, claimAmount], function (r) {
            if (r.error) { flow.fundPhase = "error"; flow.fundError = M.errorText(r.error); return }
            flow.claimPolls = 0
            claimTimer.start()
        })
    }

    // mirrors WalletView.pollClaim — keep in sync. An over-faucet claim is
    // accepted and silently never funds — hence the hard claimPollBudget x
    // claimPollMs timeout (180s in production) naming BOTH causes.
    function pollClaim() {
        claimPolls += 1
        M.call(bridge, M.RLN_MODULE, "get_token_balance", [holdingHex], function (r) {
            if (!r.error) {
                var bal = parseInt(r.balance !== undefined ? r.balance : "0", 10)
                if (r.exists === true && bal >= flow.claimAmount) {
                    claimTimer.stop()
                    flow.fundPhase = "done"
                    return
                }
            }
            if (flow.claimPolls >= flow.claimPollBudget) {
                claimTimer.stop()
                flow.fundPhase = "error"
                flow.fundError = "Claim submitted but never funded within 180s — the faucet may "
                    + "be exhausted or the wallet unsynced (transactions from an unsynced "
                    + "wallet are silently dropped)."
            }
        })
    }

    // ---- Phase E: registration ----------------------------------------------
    // mirrors RegisterView.doGenerate + doRegister — keep in sync. Identity
    // generation is the consumer's job (spec); the seed is UI-grade entropy,
    // same policy as the Advanced register form.
    function startRegistration() {
        if (regPhase === "running" || regPhase === "done")
            return
        regPhase = "running"
        regError = ""
        regState = ""
        rateLimitMismatch = false
        callRetry(M.RLN_MODULE, "generate_identity", [M.randomSeedHex()], function (r) {
            if (r.error) { flow.regPhase = "error"; flow.regError = M.errorText(r.error); return }
            if (!r.id_commitment || !r.id_secret_hash) {
                flow.regPhase = "error"
                flow.regError = "generate_identity returned no credential: " + JSON.stringify(r)
                return
            }
            flow.commitment = r.id_commitment
            flow.secretHash = r.id_secret_hash
            flow.submitRegistration()
        })
    }

    function retryRegistration() {
        if (regPhase === "running")
            return
        regPhase = "idle"
        startRegistration()
    }

    function submitRegistration() {
        var credential = JSON.stringify({
            identity_commitment: commitment,
            identity_secret_hash: secretHash
        })
        // The gifter already funded + registered this identity on-chain, so
        // register() is idempotent here: with no funding account it detects the
        // existing membership and just records it in the keystore (no faucet,
        // no wallet). The wallet path passes its faucet holding as before.
        var options = registrationMode === "gifter"
            ? JSON.stringify({ gifter_tx_hash: gifterTxHash })
            : JSON.stringify({ funding_holding_account_id: holdingHex })
        callRetry(M.MEMBERSHIP_MODULE, "register",
               [registryId, credential, rateLimit, options], function (r) {
            flow.secretHash = ""
            if (r.error) { flow.regPhase = "error"; flow.regError = M.errorText(r.error); return }
            flow.regState = r.state || "pending"
            flow.rateLimitMismatch = r.rate_limit_mismatch === true
            regTimer.start()
        })
    }

    // mirrors RegisterView.pollState — keep in sync. The module bounds the
    // pending window at 300s, so this poll always terminates. Note: this is
    // itself a retry loop (the regTimer re-polls), so a TRANSIENT error is
    // tolerated by simply continuing — the next tick re-reads the state (the
    // poller tolerates the same "empty reply" the same way). Only a
    // non-transient error stops and fails.
    function pollRegistration() {
        M.call(bridge, M.MEMBERSHIP_MODULE, "get_membership_state",
               [registryId, commitment], function (r) {
            if (r.error) {
                if (M.isTransientError(r.error.kind))
                    return
                regTimer.stop()
                flow.regPhase = "error"
                flow.regError = M.errorText(r.error)
                return
            }
            flow.regState = r.state || "unknown"
            if (flow.regState === "pending")
                return
            regTimer.stop()
            if (flow.regState === "active" || flow.regState === "grace_period") {
                flow.regPhase = "done"
            } else if (flow.regState === "failed") {
                flow.fetchFailureReason()
            } else {
                flow.regPhase = "error"
                flow.regError = "Registration settled in state \"" + flow.regState + "\"."
            }
        })
    }

    // The merged-state view carries no reason; the memberships row does.
    function fetchFailureReason() {
        callRetry(M.MEMBERSHIP_MODULE, "get_memberships", [registryId], function (r) {
            var reason = ""
            if (!r.error) {
                var rows = r.memberships || []
                for (var i = 0; i < rows.length; i++) {
                    var full = rows[i].credential ? rows[i].credential.identity_commitment : ""
                    if (full === flow.commitment && rows[i].failed_reason) {
                        reason = String(rows[i].failed_reason)
                        break
                    }
                }
            }
            flow.regPhase = "error"
            flow.regError = "Registration FAILED" + (reason !== "" ? ": " + reason : "")
                + " — Try again re-registers with a fresh identity; if funds ran short, "
                + "get more tokens first."
        })
    }

    // ---- Gifter path ---------------------------------------------------------
    // One callback chain replacing wallet/sync/faucet: bring up a libp2p node,
    // derive an identity from a fresh seed, capture a Keycard attestation bound
    // to its commitment, ask the gifter to register it (the gifter pays), then
    // hand off to the Phase E persist+confirm tail (which drives regPhase, so
    // OnboardingView completes the wizard exactly as the wallet path does).
    // ORDER MATTERS: the attestation must be bound to the commitment, so the
    // identity is derived BEFORE capture.
    function startGifter() {
        if (gifterPhase === "running" || gifterPhase === "done")
            return
        // Keycard grants are clamped server-side to RATE_LIMIT_MIN regardless of
        // the request, so ask for exactly that — otherwise the persist step sees
        // the granted rate differ from the requested one and warns spuriously.
        rateLimit = M.RATE_LIMIT_MIN
        gifterPhase = "running"
        gifterError = ""
        gifterStage = "wallet"
        ensureGifterWallet(function (wErr) {
        if (wErr) { flow.failGifter(wErr); return }
        flow.gifterStage = "node"
        flow.ensureLibp2pNode(function (nodeErr) {
            if (nodeErr) { flow.failGifter(nodeErr); return }
            flow.gifterStage = "identity"
            flow.gifterSeed = M.randomSeedHex()
            flow.callRetry(M.RLN_MODULE, "generate_identity", [flow.gifterSeed], function (r) {
                if (r.error) { flow.failGifter(M.errorText(r.error)); return }
                if (!r.id_commitment || !r.id_secret_hash) {
                    flow.failGifter("generate_identity returned no credential: " + JSON.stringify(r))
                    return
                }
                flow.commitment = r.id_commitment
                flow.secretHash = r.id_secret_hash
                flow.captureAndRequest()
            })
        })
        })
    }

    // Open a wallet for the CLIENT's on-chain reads (the gifter still pays for the
    // registration). provision_wallet_home creates the config/home; then open an
    // existing store or create a fresh one — NO sync, NO faucet. get_membership +
    // the idempotent register need this or they hit "Null wallet handle".
    function ensureGifterWallet(cb) {
        if (gifterWalletReady) { cb(""); return }
        flow.callRetry(M.MEMBERSHIP_MODULE, "provision_wallet_home",
               [JSON.stringify({ sequencer_addr: M.TESTNET_SEQUENCER_ADDR })], function (r) {
            if (r.error) { cb("Couldn't set up the wallet: " + M.errorText(r.error)); return }
            var configPath = String(r.config_path || "")
            var storagePath = String(r.storage_path || "")
            if (r.storage_exists === true) {
                flow.callRetry(M.WALLET_MODULE, "open", [configPath, storagePath], function (ro) {
                    // A non-zero open on an already-open daemon wallet is fine for
                    // reads; proceed either way.
                    flow.gifterWalletReady = true
                    cb("")
                })
            } else {
                M.call(bridge, M.WALLET_MODULE, "create_new", [configPath, storagePath, flow.password], function (rc) {
                    if (rc.error && rc.error.kind !== "empty_reply") {
                        cb("Couldn't create the wallet: " + M.errorText(rc.error)); return
                    }
                    M.call(bridge, M.WALLET_MODULE, "save", [], function () {
                        flow.gifterWalletReady = true
                        cb("")
                    })
                })
            }
        })
    }

    function retryGifter() {
        if (gifterPhase === "running")
            return
        gifterPhase = "idle"
        startGifter()
    }

    function failGifter(msg) {
        flow.gifterStage = ""
        flow.gifterPhase = "error"
        flow.gifterError = msg
    }

    // Every libp2p_module call is RELAYED through rln_gifter_module.libp2p_call
    // — direct libp2p replies marshal to null over the QML bridge. argObj is the
    // libp2p method's single object arg (undefined for no-arg methods); cb gets
    // the parsed {success,value,error}.
    function libp2pCall(method, argObj, cb, timeoutMs) {
        if (!bridge) { cb({ error: "no bridge" }); return }
        var args = (argObj === undefined || argObj === null) ? [] : [JSON.stringify(argObj)]
        bridge.callModuleAsync(M.GIFTER_MODULE, "libp2p_call",
            [JSON.stringify({ method: method, args: args })], function (raw) {
                cb(M.parseLibp2pReply(raw))
            }, timeoutMs === undefined ? 30000 : timeoutMs)
    }

    // Bring up a PLAIN libp2p node with createNode + start — the gifter client
    // only needs to dial the gifter and open a stream, so no RLN/mix context is
    // required (works against vanilla upstream libp2p_module). start's success is
    // the gate. The FIRST libp2p_call can race libp2p_module's token registration
    // ("auth token not recognized"/"Invalid response"); retry a few times.
    function ensureLibp2pNode(cb) {
        if (libp2pNodeReady) { cb(""); return }
        flow.createNodeAttempt(0, cb)
    }

    function createNodeAttempt(attempt, cb) {
        flow.libp2pCall("createNode", M.LIBP2P_NODE_CONFIG, function (r) {
            var err = M.libp2pError(r)
            if (err !== "" && err.indexOf("already") === -1) {
                var racey = err.indexOf("token") !== -1 || err.indexOf("Invalid response") !== -1
                          || err.indexOf("not recognized") !== -1 || err.indexOf("not connected") !== -1
                if (attempt < 8 && racey) {
                    var t = retryTimerComponent.createObject(flow, { interval: 700 })
                    t.triggered.connect(function () { t.destroy(); flow.createNodeAttempt(attempt + 1, cb) })
                    t.start()
                    return
                }
                cb("Could not create the peer-to-peer node: " + err)
                return
            }
            flow.libp2pCall("start", undefined, function (r2) {
                var e2 = M.libp2pError(r2)
                if (e2 !== "" && e2.indexOf("already") === -1) {
                    cb("Could not start the peer-to-peer node: " + e2)
                    return
                }
                flow.libp2pNodeReady = true
                cb("")
            })
        })
    }

    // Capture the attestation (blocks until the card is tapped — no timeout),
    // then dial the gifter. On grant, hand off to the persist+confirm tail.
    function captureAndRequest() {
        gifterStage = "capture"
        M.call(bridge, M.CAPTURE_MODULE, "capture_attestation", [commitment], function (r) {
            if (r.error) { flow.failGifter(M.errorText(r.error)); return }
            if (r.verified !== true || !r.attestation_tlv) {
                flow.failGifter("The Keycard attestation could not be verified. Is a genuine card tapped?")
                return
            }
            flow.gifterNullifier = r.nullifier || ""
            var cfg = M.registryConfigHex(flow.registryId)
            if (cfg === "") {
                flow.failGifter("Registry id is not logos:<ref>:<64-hex> — cannot derive the config account.")
                return
            }
            flow.gifterStage = "dial"
            var reqObj = {
                gifterPeerId: flow.gifterPeerId.trim(),
                gifterMultiaddr: flow.gifterMultiaddr.trim(),
                config: cfg,
                seed: flow.gifterSeed,
                rate: flow.rateLimit,
                attestation: r.attestation_tlv
            }
            // rln_gifter_module.request runs the whole gifter protocol over
            // libp2p_module's generic bridge and returns a plain-String JSON
            // (real value through the QML bridge, unlike a libp2p LogosResult).
            // Its internal timeout is 180s (dial + auth + on-chain register);
            // give the client a little more so we see the real error rather than
            // a client-side cutoff.
            M.call(bridge, M.GIFTER_MODULE, "request", [JSON.stringify(reqObj)], function (rr) {
                if (rr.error) {
                    // The module registers on-chain BEFORE the (best-effort) mix
                    // identity adoption, so a real error here means nothing was
                    // granted — auth refused, dial/timeout. Fail fast.
                    flow.failGifter(M.gifterErrorText(rr.error))
                    return
                }
                if (rr.auth_success !== true && rr.leaf_index === undefined) {
                    flow.failGifter("The gifter did not grant a membership: " + JSON.stringify(rr))
                    return
                }
                // The gifter's on-chain tx — carried into the record so the detail
                // view shows it (the gifter submitted it on our behalf).
                flow.gifterTxHash = rr.tx_hash || ""
                // Granted (identity_adopted may be false — mix adoption is optional
                // and not needed here). The PDA is Pending briefly, so poll for the
                // on-chain confirmation, then persist to the keystore.
                flow.confirmAndPersist(cfg)
            }, 190000)
        }, 0)
    }

    // The gift IS registered on-chain (rlnGifterRequest returned success), but the
    // PDA is Pending for a bit, so poll get_membership until it lands, then
    // persist + confirm. Stays in the running "confirm" stage (progress, not an
    // error); times out with a clear message if it never confirms (e.g. the
    // gifter couldn't apply the tx).
    function confirmAndPersist(cfg) {
        flow.gifterStage = "confirm"
        flow.giftConfirmCfg = cfg
        flow.giftConfirmPolls = 0
        flow.pollGiftConfirm()
        giftConfirmTimer.start()
    }

    function pollGiftConfirm() {
        flow.giftConfirmPolls += 1
        M.call(bridge, M.RLN_MODULE, "get_membership", [flow.giftConfirmCfg, commitment], function (r) {
            if (!r.error && r.registered === true) {
                giftConfirmTimer.stop()
                flow.gifterStage = "persist"
                flow.gifterPhase = "done"
                flow.persistGifterMembership()
                return
            }
            if (flow.giftConfirmPolls >= flow.giftConfirmBudget) {
                giftConfirmTimer.stop()
                flow.failGifter("Your membership was requested, but it didn't confirm on-chain in time. "
                    + "The gifter may be busy — try again in a moment.")
            }
        })
    }

    // Persist the gifted grant + confirm it, reusing Phase E. The identity is
    // already on-chain (the gifter registered it), so register() is idempotent
    // and needs no funds (see submitRegistration's gifter branch); regTimer then
    // polls it to active — driving regPhase, which OnboardingView watches to
    // complete the wizard.
    function persistGifterMembership() {
        regPhase = "running"
        regError = ""
        regState = ""
        rateLimitMismatch = false
        submitRegistration()
    }

    // No sync progress Timer anymore: mid-sync reads starve (and can crash
    // the module host) — chunk completions are the progress ticks.

    Timer {
        id: claimTimer
        interval: flow.claimPollMs
        repeat: true
        onTriggered: flow.pollClaim()
    }

    Timer {
        id: regTimer
        interval: flow.statePollMs
        repeat: true
        onTriggered: flow.pollRegistration()
    }

    Timer {
        id: giftConfirmTimer
        interval: flow.giftConfirmMs
        repeat: true
        onTriggered: flow.pollGiftConfirm()
    }

    // One-shot backoff timer for callRetry, instantiated per retry and
    // self-destroyed on fire.
    Component {
        id: retryTimerComponent
        Timer { repeat: false }
    }
}
