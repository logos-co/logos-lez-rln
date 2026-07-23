//! liblogos_rln_membership_module — RLN Membership Management Module.
//!
//! Implements the RLN-MEMBERSHIP-MANAGEMENT spec (logos-lips
//! docs/anoncomms/raw/rln-membership-management.md): a registry-agnostic
//! membership API over pluggable registry providers and an encrypted
//! keystore storage backend.
//!
//! Architecture (spec concept → crate):
//! - registry_id (CAIP-10) parse/canonicalize/route → `registry_id.rs`
//! - storage backend (WAKU-RLN-KEYSTORE format) → `keystore.rs` (crypto +
//!   file) and `store.rs` (runtime state, lifecycle machine, merged view)
//! - registry provider → `provider.rs` (trait + the lez-rln provider, a raw
//!   lp_* wire client of the sibling liblogos_rln_module)
//! - Pending confirmation window + involuntary-removal detection →
//!   `poller.rs` (detached thread, sibling broadcast-thread pattern)
//! - selection (per-scope RoundRobin etc.) → `select.rs`
//!
//! Wire conventions (this module only): every method returns a compact JSON
//! object (serde_json ⇒ alphabetical keys); failures are
//! `{"error":{"kind":…,"message":…}}` — see `ErrorKind`. The sibling RLN
//! module's ""-on-error v1 conventions are NOT used here.
//!
//! Concurrency is SINGLE, like the sibling: registration is fire-and-record
//! (lp_invoke_async), so no handler blocks on a sequencer submit; the
//! poller thread does the slow reads off the dispatch thread.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

mod keychain;
mod keystore;
mod poller;
mod provider;
mod registry_id;
mod select;
mod store;
mod wallet_home;

mod generated {
    #![allow(warnings)]
    #![allow(clippy::all)]
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/generated/provider_gen.rs"
    ));
}
pub(crate) use generated::*;

use zeroize::Zeroize;

// -------------------------------------------------------------------- errors

/// Reply-envelope error kinds. The spec mandates distinguishing at least
/// unknown_registry / unknown_membership / provider_failure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ErrorKind {
    UnknownRegistry,
    UnknownMembership,
    ProviderFailure,
    Locked,
    BadPassword,
    NoUsableMembership,
    AmbiguousSelection,
    InvalidArgument,
    KeychainUnavailable,
    Internal,
}

impl ErrorKind {
    fn as_str(self) -> &'static str {
        match self {
            ErrorKind::UnknownRegistry => "unknown_registry",
            ErrorKind::UnknownMembership => "unknown_membership",
            ErrorKind::ProviderFailure => "provider_failure",
            ErrorKind::Locked => "locked",
            ErrorKind::BadPassword => "bad_password",
            ErrorKind::NoUsableMembership => "no_usable_membership",
            ErrorKind::AmbiguousSelection => "ambiguous_selection",
            ErrorKind::InvalidArgument => "invalid_argument",
            ErrorKind::KeychainUnavailable => "keychain_unavailable",
            ErrorKind::Internal => "internal",
        }
    }
}

#[derive(Debug)]
pub(crate) struct ApiError {
    pub(crate) kind: ErrorKind,
    pub(crate) message: String,
}

impl ApiError {
    pub(crate) fn new(kind: ErrorKind, message: &str) -> Self {
        ApiError {
            kind,
            message: message.to_string(),
        }
    }

    pub(crate) fn internal(message: &str) -> Self {
        ApiError::new(ErrorKind::Internal, message)
    }

    pub(crate) fn to_json(&self) -> String {
        serde_json::json!({
            "error": { "kind": self.kind.as_str(), "message": self.message }
        })
        .to_string()
    }
}

/// Flatten a handler result into the wire string.
pub(crate) fn reply(result: Result<serde_json::Value, ApiError>) -> String {
    match result {
        Ok(value) => value.to_string(),
        Err(e) => e.to_json(),
    }
}

/// Poison-recovering lock (the sibling module's helper): a poisoned mutex
/// here is a bug elsewhere, not a reason to wedge every future call.
pub(crate) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Wall-clock UNIX seconds — the crate-root time hub shared by the store,
/// poller, and keystore quarantine path (a clock skew before the epoch reads
/// as 0 rather than panicking).
pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// -------------------------------------------------------------------- module

// ------------------------------------------------------------------- helpers

/// Parse a 32-byte LE hex field, returning the bytes and their normalized
/// lowercase re-encoding. Invalid → InvalidArgument "<field> must be 32-byte
/// hex" (the shared shape of the top-level commitment/identifier args).
fn parse_hex32(field: &str, hex: &str) -> Result<([u8; 32], String), ApiError> {
    let bytes = registry_id::hex_to_bytes32(hex).ok_or_else(|| {
        ApiError::new(ErrorKind::InvalidArgument, &format!("{field} must be 32-byte hex"))
    })?;
    let hex = registry_id::bytes_to_hex(&bytes);
    Ok((bytes, hex))
}

/// Parse + normalize the consumer-supplied credential JSON (spec
/// IdentityCredential: commitment + secret hash required, trapdoor /
/// nullifier optional; all 32-byte LE hex, normalized to lowercase).
fn parse_credential(
    credential_json: &str,
    canonical_registry: &str,
) -> Result<store::StoredCredential, ApiError> {
    let v: serde_json::Value = serde_json::from_str(credential_json)
        .map_err(|e| ApiError::new(ErrorKind::InvalidArgument, &format!("credential_json: {e}")))?;
    let hex32 = |key: &str, required: bool| -> Result<Option<String>, ApiError> {
        match v.get(key) {
            None | Some(serde_json::Value::Null) if !required => Ok(None),
            Some(value) => value
                .as_str()
                .and_then(registry_id::hex_to_bytes32)
                .map(|b| Some(registry_id::bytes_to_hex(&b)))
                .ok_or_else(|| {
                    ApiError::new(
                        ErrorKind::InvalidArgument,
                        &format!("credential_json.{key} must be 32-byte hex"),
                    )
                }),
            None => Err(ApiError::new(
                ErrorKind::InvalidArgument,
                &format!("credential_json.{key} is required"),
            )),
        }
    };
    Ok(store::StoredCredential {
        identity_commitment: hex32("identity_commitment", true)?.unwrap(),
        identity_nullifier: hex32("identity_nullifier", false)?,
        identity_secret_hash: hex32("identity_secret_hash", true)?.unwrap(),
        identity_trapdoor: hex32("identity_trapdoor", false)?,
        registry_id: canonical_registry.to_string(),
    })
}

/// The public Membership view (spec Membership minus secrets): the
/// credential exposes only the commitment. `select_membership` is the sole
/// path that releases the full credential.
fn public_membership_json(
    hash: &str,
    meta: &store::MembershipMeta,
    quarantined: bool,
    rate_limit_mismatch: bool,
) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "credential".to_string(),
        serde_json::json!({ "identity_commitment": meta.identity_commitment }),
    );
    if quarantined {
        obj.insert("failed_reason".to_string(), "metadata_tamper".into());
    } else if let Some(reason) = &meta.failed_reason {
        obj.insert("failed_reason".to_string(), reason.as_str().into());
    }
    obj.insert("leaf_index".to_string(), meta.leaf_index.into());
    obj.insert("membership_hash".to_string(), hash.into());
    obj.insert("rate_limit".to_string(), meta.rate_limit.into());
    if rate_limit_mismatch {
        obj.insert("rate_limit_mismatch".to_string(), true.into());
    }
    obj.insert("registry_id".to_string(), meta.registry_id.as_str().into());
    obj.insert(
        "state".to_string(),
        if quarantined { store::ST_FAILED } else { &meta.state }.into(),
    );
    obj.insert("submitted_at".to_string(), meta.submitted_at.into());
    if let Some(tx) = &meta.tx_result {
        obj.insert("tx_result".to_string(), tx.as_str().into());
    }
    serde_json::Value::Object(obj)
}

fn parse_registry(raw: &str) -> Result<registry_id::CanonicalRegistryId, ApiError> {
    registry_id::parse(raw).map_err(|e| ApiError::new(ErrorKind::InvalidArgument, &e))
}

fn provider_of(
    registry: &registry_id::CanonicalRegistryId,
) -> Result<&'static dyn provider::RegistryProvider, ApiError> {
    provider::provider_for(&registry.namespace).ok_or_else(|| {
        ApiError::new(
            ErrorKind::UnknownRegistry,
            &format!("no registry provider for namespace {}", registry.namespace),
        )
    })
}

// -------------------------------------------------------------- method impls

/// Spec register(): validate → local idempotency → registry idempotency
/// pre-check (adopts out-of-band registrations) → Pending record →
/// fire-and-record submit → return Pending immediately. The store lock is
/// NEVER held across a provider call.
fn register_impl(
    registry_id_raw: &str,
    credential_json: &str,
    rate_limit: i64,
    options_json: &str,
) -> Result<serde_json::Value, ApiError> {
    let registry = parse_registry(registry_id_raw)?;
    let prov = provider_of(&registry)?;
    if rate_limit <= 0 {
        return Err(ApiError::new(ErrorKind::InvalidArgument, "rate_limit must be positive"));
    }
    let rate_limit = rate_limit as u64;
    let credential = parse_credential(credential_json, &registry.canonical)?;
    let commitment = registry_id::hex_to_bytes32(&credential.identity_commitment)
        .expect("normalized by parse_credential");
    let hash = registry_id::membership_hash(&registry.canonical, &commitment);

    // Local idempotency: any live (non-failed) record short-circuits —
    // including pending ones, so a double-fired register can't double-submit.
    let existing = store::with_store(|s| Ok(s.get(&hash).cloned()))?;
    if let Some(meta) = &existing {
        if meta.state != store::ST_FAILED {
            let mismatch = meta.rate_limit != rate_limit;
            return Ok(public_membership_json(&hash, meta, false, mismatch));
        }
    }

    // Registry idempotency pre-check (spec MUST: an already-registered
    // commitment returns the existing membership — its on-chain rate_limit,
    // not the requested one, with the mismatch surfaced).
    let pm = prov.get_membership(&registry, &credential.identity_commitment)?;
    if pm.registered {
        let mismatch = pm.rate_limit != rate_limit;
        store::with_store(|s| {
            if s.get(&hash).is_some() {
                s.update(&hash, |m| {
                    m.state = pm.state.clone();
                    m.leaf_index = pm.leaf_index;
                    m.rate_limit = pm.rate_limit;
                    m.failed_reason = None;
                })
            } else {
                let meta = store::MembershipMeta {
                    failed_reason: None,
                    identity_commitment: credential.identity_commitment.clone(),
                    leaf_index: pm.leaf_index,
                    rate_limit: pm.rate_limit,
                    registry_id: registry.canonical.clone(),
                    state: pm.state.clone(),
                    state_history: vec![],
                    submitted_at: now_unix(),
                    tx_result: None,
                };
                s.insert(&hash, meta, &credential)
            }
        })?;
        let meta = store::with_store(|s| Ok(s.get(&hash).cloned()))?
            .ok_or_else(|| ApiError::internal("record vanished after insert"))?;
        return Ok(public_membership_json(&hash, &meta, false, mismatch));
    }

    // Fresh submission: Pending record FIRST (an interrupted submit still
    // leaves an auditable record the poller will resolve), then the async
    // submit, whose callback lands on the owner thread after this handler
    // has returned.
    let meta = store::MembershipMeta {
        failed_reason: None,
        identity_commitment: credential.identity_commitment.clone(),
        leaf_index: 0,
        rate_limit,
        registry_id: registry.canonical.clone(),
        state: store::ST_PENDING.to_string(),
        state_history: vec![],
        submitted_at: now_unix(),
        tx_result: None,
    };
    store::with_store(|s| s.insert(&hash, meta, &credential))?;

    let hash_for_cb = hash.clone();
    let submit = prov.register_async(
        &registry,
        options_json,
        &credential.identity_commitment,
        rate_limit,
        Box::new(move |result| {
            let update = store::with_store(|s| {
                s.update(&hash_for_cb, |m| match &result {
                    Ok(reply) => {
                        m.tx_result = Some(reply.clone());
                        // The reply's leaf_index is a pre-submit ESTIMATE;
                        // recorded for observability, authoritative only
                        // after the poller's read-back.
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(reply) {
                            if let Some(leaf) = v.get("leaf_index").and_then(|x| x.as_u64()) {
                                m.leaf_index = leaf;
                            }
                        }
                    }
                    Err(e) => {
                        m.state = store::ST_FAILED.to_string();
                        m.failed_reason = Some(format!("submit_failed: {}", e.message));
                    }
                })
            });
            if let Err(e) = update {
                eprintln!("membership register callback: {}", e.message);
            }
        }),
    );
    if let Err(e) = submit {
        // Synchronous submission failure (bad options, no client): the
        // record goes Failed immediately and the error surfaces.
        store::with_store(|s| {
            s.update(&hash, |m| {
                m.state = store::ST_FAILED.to_string();
                m.failed_reason = Some(format!("submit_failed: {}", e.message));
            })
        })?;
        return Err(e);
    }
    poller::ensure_running();

    let meta = store::with_store(|s| Ok(s.get(&hash).cloned()))?
        .ok_or_else(|| ApiError::internal("record vanished after insert"))?;
    Ok(public_membership_json(&hash, &meta, false, false))
}

/// Spec get_membership_state(): live registry read overlaid on the local
/// record; transitions the merged view implies are persisted.
fn get_membership_state_impl(
    registry_id_raw: &str,
    identity_commitment_hex: &str,
) -> Result<serde_json::Value, ApiError> {
    let registry = parse_registry(registry_id_raw)?;
    let prov = provider_of(&registry)?;
    let (commitment, commitment_hex) = parse_hex32("identity_commitment", identity_commitment_hex)?;
    let hash = registry_id::membership_hash(&registry.canonical, &commitment);

    // A missing store (no persistence path) degrades to the registry-only
    // view rather than failing the read.
    let local = store::with_store(|s| Ok(s.get(&hash).cloned())).unwrap_or(None);
    let pm = prov.get_membership(&registry, &commitment_hex)?;
    let registry_state = if pm.registered { Some(pm.state.as_str()) } else { None };
    let merged = store::merge_state(local.as_ref(), registry_state, now_unix());

    if let Some(meta) = &local {
        if merged != meta.state {
            let _ = store::with_store(|s| {
                s.update(&hash, |m| {
                    m.state = merged.clone();
                    if pm.registered {
                        // The pending→active re-read (spec MUST).
                        m.leaf_index = pm.leaf_index;
                        m.rate_limit = pm.rate_limit;
                        m.failed_reason = None;
                    } else if merged == store::ST_FAILED {
                        m.failed_reason = Some("confirmation_window_elapsed".to_string());
                    } else if merged == store::ST_ERASED {
                        m.failed_reason = Some("removed_from_registry".to_string());
                    }
                })
            });
        }
    }

    let mut obj = serde_json::Map::new();
    if pm.registered {
        obj.insert("leaf_index".to_string(), pm.leaf_index.into());
        obj.insert("rate_limit".to_string(), pm.rate_limit.into());
    } else if let Some(meta) = &local {
        obj.insert("leaf_index".to_string(), meta.leaf_index.into());
        obj.insert("rate_limit".to_string(), meta.rate_limit.into());
    }
    if pm.registered || local.is_some() {
        obj.insert("membership_hash".to_string(), hash.into());
    }
    obj.insert("registry_id".to_string(), registry.canonical.as_str().into());
    obj.insert("state".to_string(), merged.into());
    Ok(serde_json::Value::Object(obj))
}

/// Spec select(): resolve + decrypt the membership an application should
/// prove with — the module's single plaintext release point.
fn select_membership_impl(
    registry_id_raw: &str,
    rln_identifier_hex: &str,
    selector_json: &str,
) -> Result<serde_json::Value, ApiError> {
    let registry = parse_registry(registry_id_raw)?;
    let (_, rln_identifier_hex) = parse_hex32("rln_identifier", rln_identifier_hex)?;
    let selector = select::parse_selector(selector_json)?;

    let records = store::with_store(|s| Ok(s.records_for(&registry.canonical)))?;
    let hash = select::select_hash(
        &records,
        (&registry.canonical, &rln_identifier_hex),
        &selector,
    )?;
    let credential = store::with_store(|s| s.decrypt_credential(&hash))?;
    let meta = records
        .iter()
        .find(|(h, _, _)| h == &hash)
        .map(|(_, m, _)| m.clone())
        .ok_or_else(|| ApiError::internal("selected record vanished"))?;

    let mut full = serde_json::Map::new();
    full.insert(
        "identity_commitment".to_string(),
        credential.identity_commitment.as_str().into(),
    );
    if let Some(nullifier) = &credential.identity_nullifier {
        full.insert("identity_nullifier".to_string(), nullifier.as_str().into());
    }
    full.insert(
        "identity_secret_hash".to_string(),
        credential.identity_secret_hash.as_str().into(),
    );
    if let Some(trapdoor) = &credential.identity_trapdoor {
        full.insert("identity_trapdoor".to_string(), trapdoor.as_str().into());
    }
    let mut membership = public_membership_json(&hash, &meta, false, false);
    membership["credential"] = serde_json::Value::Object(full);
    Ok(membership)
}

fn get_memberships_impl(registry_id_raw: &str) -> Result<serde_json::Value, ApiError> {
    let registry = parse_registry(registry_id_raw)?;
    // No provider needed: listing LOCAL records is meaningful even for a
    // namespace this build can't reach.
    let records = store::with_store(|s| Ok(s.records_for(&registry.canonical)))?;
    let memberships: Vec<serde_json::Value> = records
        .iter()
        .map(|(hash, meta, quarantined)| public_membership_json(hash, meta, *quarantined, false))
        .collect();
    Ok(serde_json::json!({ "memberships": memberships }))
}

// -------------------------------------------------------------------- module

#[derive(Default)]
struct LogosRlnMembershipModuleImpl;

impl LiblogosRlnMembershipModule for LogosRlnMembershipModuleImpl {
    fn on_context_ready(&mut self, ctx: &RustModuleContext) {
        // The lp client to the sibling RLN module must be created on this
        // (the host's main Qt) thread — see provider.rs.
        provider::init_client();
        if ctx.instance_persistence_path.is_empty() {
            // No cwd fallback: a keystore in an unknown directory is worse
            // than a hard error at the first keystore op (see README).
            eprintln!(
                "membership module: host provided no instance_persistence_path — keystore ops will fail"
            );
        } else {
            store::init(std::path::PathBuf::from(&ctx.instance_persistence_path));
            // Resume confirmation polling for records that were pending at
            // the last shutdown.
            let has_pending =
                store::with_store(|s| Ok(!s.pending_records().is_empty())).unwrap_or(false);
            if has_pending {
                poller::ensure_running();
            }
        }
    }

    fn unlock_keystore(&mut self, mut password: String) -> String {
        let result = store::with_store(|s| s.unlock(&password)).map(|count| {
            serde_json::json!({ "membership_count": count, "unlocked": true })
        });
        password.zeroize();
        reply(result)
    }

    fn lock_keystore(&mut self) -> String {
        reply(store::with_store(|s| {
            s.lock();
            Ok(serde_json::json!({ "locked": true }))
        }))
    }

    fn provision_wallet_home(&mut self, options_json: String) -> String {
        reply(wallet_home::provision_impl(&options_json))
    }

    fn unlock_keystore_auto(&mut self) -> String {
        reply(keychain::auto_unlock_impl())
    }

    fn remember_keystore_password(&mut self) -> String {
        reply(keychain::remember_impl())
    }

    fn register(
        &mut self,
        registry_id: String,
        mut credential_json: String,
        rate_limit: i64,
        options_json: String,
    ) -> String {
        let out = reply(register_impl(
            &registry_id,
            &credential_json,
            rate_limit,
            &options_json,
        ));
        // The raw argument carries the identity secret.
        credential_json.zeroize();
        out
    }

    fn get_membership_state(
        &mut self,
        registry_id: String,
        identity_commitment_hex: String,
    ) -> String {
        reply(get_membership_state_impl(&registry_id, &identity_commitment_hex))
    }

    fn get_memberships(&mut self, registry_id: String) -> String {
        reply(get_memberships_impl(&registry_id))
    }

    fn select_membership(
        &mut self,
        registry_id: String,
        rln_identifier_hex: String,
        selector_json: String,
    ) -> String {
        reply(select_membership_impl(
            &registry_id,
            &rln_identifier_hex,
            &selector_json,
        ))
    }

    fn get_merkle_proof(&mut self, registry_id: String, leaf_index: i64) -> String {
        reply((|| {
            let registry = parse_registry(&registry_id)?;
            let prov = provider_of(&registry)?;
            if leaf_index < 0 {
                return Err(ApiError::new(ErrorKind::InvalidArgument, "leaf_index must be non-negative"));
            }
            prov.get_merkle_proof(&registry, leaf_index as u64)
        })())
    }

    fn get_valid_roots(&mut self, registry_id: String) -> String {
        reply((|| {
            let registry = parse_registry(&registry_id)?;
            let prov = provider_of(&registry)?;
            let roots = prov.get_valid_roots(&registry)?;
            Ok(serde_json::json!({ "valid_roots": roots }))
        })())
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<LogosRlnMembershipModuleImpl>();
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pins the error envelope's byte shape (alphabetical keys).
    #[test]
    fn error_envelope_shape() {
        let e = ApiError::new(ErrorKind::UnknownRegistry, "no provider for namespace");
        assert_eq!(
            e.to_json(),
            r#"{"error":{"kind":"unknown_registry","message":"no provider for namespace"}}"#
        );
    }

    // Frozen cross-crate wire contract: the registry-state consts MUST equal
    // the exact strings logos-rln-module rln_core::membership_status returns.
    // The crates are decoupled (no shared type), so this is the single tested
    // anchor — if the sibling ever renames a state, this pin fails and forces
    // a coordinated bump on both sides.
    #[test]
    fn membership_state_wire_strings() {
        assert_eq!(store::ST_ACTIVE, "active");
        assert_eq!(store::ST_GRACE, "grace_period");
        assert_eq!(store::ST_EXPIRED, "expired");
    }

    #[test]
    fn keystore_ops_without_store_report_internal() {
        // With no store initialized (host provided no persistence path),
        // every keystore op fails with the internal error, never panics.
        let _serial = crate::lock(&store::TEST_STORE_LOCK);
        store::reset_for_tests();
        let mut imp = LogosRlnMembershipModuleImpl;
        let out = imp.lock_keystore();
        assert!(out.contains(r#""kind":"internal""#), "got: {out}");
    }

    #[test]
    fn register_validates_arguments_before_touching_anything() {
        let mut imp = LogosRlnMembershipModuleImpl;
        let ok_credential = serde_json::json!({
            "identity_commitment": "11".repeat(32),
            "identity_secret_hash": "22".repeat(32),
        })
        .to_string();

        let out = imp.register("not-caip10".into(), ok_credential.clone(), 300, String::new());
        assert!(out.contains(r#""kind":"invalid_argument""#), "got: {out}");

        let out = imp.register(
            "eip155:1:0xB9cd878C90E49F797B4431fBF4fb333108CB90e6".into(),
            ok_credential.clone(),
            300,
            String::new(),
        );
        assert!(out.contains(r#""kind":"unknown_registry""#), "got: {out}");

        let logos = format!("logos:local:{}", "ab".repeat(32));
        let out = imp.register(logos.clone(), ok_credential.clone(), 0, String::new());
        assert!(out.contains(r#""kind":"invalid_argument""#), "got: {out}");

        let no_secret = serde_json::json!({ "identity_commitment": "11".repeat(32) }).to_string();
        let out = imp.register(logos, no_secret, 300, String::new());
        assert!(out.contains("identity_secret_hash"), "got: {out}");
    }

    // With the test lp stub the provider is unreachable: a fresh register
    // fails with provider_failure at the idempotency pre-check and stores
    // NOTHING; a live local record short-circuits before any provider call
    // and surfaces a rate-limit mismatch.
    #[test]
    fn register_local_idempotency_and_dead_transport() {
        let _serial = crate::lock(&store::TEST_STORE_LOCK);
        let dir = std::env::temp_dir().join(format!("rln-ms-lib-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        store::init(dir.clone());

        let mut imp = LogosRlnMembershipModuleImpl;
        assert!(imp.unlock_keystore("pw".into()).contains(r#""unlocked":true"#));

        let registry = format!("logos:local:{}", "ab".repeat(32));
        let commitment = [0x11u8; 32];
        let credential_json = serde_json::json!({
            "identity_commitment": registry_id::bytes_to_hex(&commitment),
            "identity_secret_hash": "22".repeat(32),
        })
        .to_string();

        let out = imp.register(registry.clone(), credential_json.clone(), 300, String::new());
        assert!(out.contains(r#""kind":"provider_failure""#), "got: {out}");
        let listed = imp.get_memberships(registry.clone());
        assert_eq!(listed, r#"{"memberships":[]}"#, "failed pre-check must store nothing");

        // Seed a confirmed record, then re-register with a different rate.
        let hash = registry_id::membership_hash(&registry, &commitment);
        store::with_store(|s| {
            let meta = store::MembershipMeta {
                failed_reason: None,
                identity_commitment: registry_id::bytes_to_hex(&commitment),
                leaf_index: 7,
                rate_limit: 300,
                registry_id: registry.clone(),
                state: store::ST_ACTIVE.to_string(),
                state_history: vec![],
                submitted_at: now_unix(),
                tx_result: None,
            };
            let credential = store::StoredCredential {
                identity_commitment: registry_id::bytes_to_hex(&commitment),
                identity_nullifier: None,
                identity_secret_hash: "22".repeat(32),
                identity_trapdoor: None,
                registry_id: registry.clone(),
            };
            s.insert(&hash, meta, &credential)
        })
        .unwrap();

        let out = imp.register(registry.clone(), credential_json, 250, String::new());
        assert!(!out.contains(r#""error""#), "got: {out}");
        assert!(out.contains(r#""state":"active""#), "got: {out}");
        assert!(out.contains(r#""rate_limit":300"#), "existing registration's rate wins");
        assert!(out.contains(r#""rate_limit_mismatch":true"#), "got: {out}");
        assert!(out.starts_with(r#"{"credential":{"identity_commitment":"#), "alphabetical keys");

        // get_membership_state needs the (stubbed) provider → provider_failure.
        let out = imp.get_membership_state(registry.clone(), registry_id::bytes_to_hex(&commitment));
        assert!(out.contains(r#""kind":"provider_failure""#), "got: {out}");

        // get_memberships lists locally without a provider.
        let listed = imp.get_memberships(registry);
        assert!(listed.contains(&hash), "got: {listed}");

        store::reset_for_tests();
        let _ = std::fs::remove_dir_all(&dir);
    }

    // select_membership end to end against a seeded store: locked keystore
    // refuses to release, unlocked returns the full credential (the
    // module's single plaintext release point).
    #[test]
    fn select_membership_releases_credential_only_when_unlocked() {
        let _serial = crate::lock(&store::TEST_STORE_LOCK);
        let dir = std::env::temp_dir().join(format!("rln-ms-select-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        store::init(dir.clone());

        let mut imp = LogosRlnMembershipModuleImpl;
        assert!(imp.unlock_keystore("pw".into()).contains(r#""unlocked":true"#));

        let registry = format!("logos:local:{}", "cd".repeat(32));
        let commitment = [0x66u8; 32];
        let hash = registry_id::membership_hash(&registry, &commitment);
        store::with_store(|s| {
            let meta = store::MembershipMeta {
                failed_reason: None,
                identity_commitment: registry_id::bytes_to_hex(&commitment),
                leaf_index: 3,
                rate_limit: 300,
                registry_id: registry.clone(),
                state: store::ST_ACTIVE.to_string(),
                state_history: vec![],
                submitted_at: now_unix(),
                tx_result: None,
            };
            let credential = store::StoredCredential {
                identity_commitment: registry_id::bytes_to_hex(&commitment),
                identity_nullifier: None,
                identity_secret_hash: "77".repeat(32),
                identity_trapdoor: None,
                registry_id: registry.clone(),
            };
            s.insert(&hash, meta, &credential)
        })
        .unwrap();

        let rln_id = "ef".repeat(32);
        let out = imp.select_membership(registry.clone(), rln_id.clone(), String::new());
        assert!(out.contains(&format!(r#""identity_secret_hash":"{}""#, "77".repeat(32))), "got: {out}");
        assert!(out.contains(&format!(r#""membership_hash":"{hash}""#)), "got: {out}");

        // Locked: metadata reads still work, release refuses.
        assert!(imp.lock_keystore().contains(r#""locked":true"#));
        let out = imp.select_membership(registry.clone(), rln_id, String::new());
        assert!(out.contains(r#""kind":"locked""#), "got: {out}");
        assert!(imp.get_memberships(registry).contains(&hash));

        store::reset_for_tests();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
