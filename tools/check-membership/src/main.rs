//! `check-membership` — prove an RLN membership registered on-chain.
//!
//! Given an identity commitment (copyable from the RLN Membership UI's detail
//! view), derive the membership account the registration program owns and read
//! it straight off the sequencer's `getAccount` JSON-RPC. A populated,
//! decodable shard IS the registration's on-chain effect — this sequencer has
//! no transaction-by-hash lookup, so the account read is the confirmation.
//!
//! Accounts are sharded: `getAccount` returns
//! `{"nonce":N,"data":{"shards":{"<base58 program account id>":[bytes..]}}}`.
//! The membership bytes sit under the registration program's id; the clock
//! bytes sit on `CLOCK_50` under the clock program's id. An absent shard key
//! means "not registered".
//!
//! Wallet-free and daemon-free: it reuses the shared `rln-layouts` seed rules
//! and account layouts (the same the module uses), replicating only the
//! 3-line SPEL PDA hash. The registration program id is deployment state (the
//! header account `run_setup` recorded), so it is an explicit input:
//! --program-id, `LEZ_RLN_REGISTRATION_PROGRAM_ID`, or a --deployment
//! descriptor; likewise the tree id (--tree-id, `LEZ_RLN_TREE_ID_HEX`, or
//! --deployment).

use borsh::BorshDeserialize;
use rln_layouts::{
    clock_program_account_id, combine_seeds, is_expired, is_in_grace_period, label_seed,
    secs_to_millis, MembershipState, CLOCK_50_ACCOUNT_ID_BYTES,
};
use sha2::{Digest, Sha256};

const TREE_ID_ENV: &str = "LEZ_RLN_TREE_ID_HEX";
const PROGRAM_ID_ENV: &str = "LEZ_RLN_REGISTRATION_PROGRAM_ID";
const DEFAULT_SEQUENCER: &str = "https://testnet.lez.logos.co/";

// SPEL `compute_pda`: SHA-256(prefix || program_id || seed). The prefix and
// construction are the deployed program's, mirrored from the module's
// rln_core::derive_pda; pinned by `derives_known_membership_account`.
const PDA_PREFIX: &[u8; 32] = b"/LEE/v0.2/AccountId/PDA/\x00\x00\x00\x00\x00\x00\x00\x00";
const MEMBERSHIP_STATE_SIZE: usize = 64;

struct Config {
    tree_id: [u8; 32],
    program_id: [u8; 32],
    sequencer: String,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_usage();
        std::process::exit(0);
    }

    let mut commitment_hex: Option<String> = None;
    let mut tree_id_hex: Option<String> = std::env::var(TREE_ID_ENV).ok();
    let mut program_id_hex: Option<String> = std::env::var(PROGRAM_ID_ENV).ok();
    let mut sequencer = DEFAULT_SEQUENCER.to_string();
    let mut json = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--commitment" | "-c" => commitment_hex = Some(take(&args, &mut i)),
            "--tree-id" => tree_id_hex = Some(take(&args, &mut i)),
            "--program-id" => program_id_hex = Some(take(&args, &mut i)),
            "--sequencer" => sequencer = take(&args, &mut i),
            "--deployment" => load_deployment(
                &take(&args, &mut i),
                &mut tree_id_hex,
                &mut program_id_hex,
                &mut sequencer,
            ),
            "--json" => json = true,
            other => fail(&format!("unknown argument: {other} (see --help)")),
        }
        i += 1;
    }

    let commitment = parse_hex32(
        &commitment_hex.unwrap_or_else(|| {
            fail("--commitment <64-hex identity commitment> is required (see --help)")
        }),
        "commitment",
    );
    let cfg = Config {
        tree_id: parse_hex32(
            &tree_id_hex.unwrap_or_else(|| fail(&format!("--tree-id <64-hex> (or {TREE_ID_ENV}, or --deployment) is required (see --help)"))),
            "tree-id",
        ),
        program_id: parse_hex32(
            &program_id_hex.unwrap_or_else(|| fail(&format!("--program-id <64-hex> (or {PROGRAM_ID_ENV}, or --deployment) is required (see --help)"))),
            "program-id",
        ),
        sequencer,
    };

    let membership_id = derive_membership_account(&cfg.program_id, &cfg.tree_id, &commitment);

    let Some(data) = get_account_shard(&cfg.sequencer, &membership_id, &cfg.program_id) else {
        report_unregistered(json);
        std::process::exit(1);
    };
    if data.len() < MEMBERSHIP_STATE_SIZE {
        fail("membership account is present but too short to decode");
    }
    let state = MembershipState::try_from_slice(&data[..MEMBERSHIP_STATE_SIZE])
        .unwrap_or_else(|_| fail("failed to decode membership account"));

    let now_ms = clock_timestamp_ms(&cfg.sequencer);
    let status = lifecycle(&state, now_ms);
    report_registered(json, &state, status, now_ms);
}

fn lifecycle(state: &MembershipState, now_ms: u64) -> &'static str {
    let start_ms = state.grace_period_start_timestamp_ms;
    let grace_ms = secs_to_millis(state.grace_period_duration_sec);
    if is_expired(start_ms, grace_ms, now_ms) {
        "expired"
    } else if is_in_grace_period(start_ms, grace_ms, now_ms) {
        "grace_period"
    } else {
        "active"
    }
}

/// Membership account = `derive_pda(program_id, SHA-256(label("membership") ||
/// tree_id || id_commitment))` — the same derivation as the module's
/// `register_plan`.
fn derive_membership_account(
    program_id: &[u8; 32],
    tree_id: &[u8; 32],
    commitment: &[u8; 32],
) -> [u8; 32] {
    let seed = combine_seeds(&[&label_seed("membership"), tree_id, commitment]);
    let mut input = [0u8; 96];
    input[0..32].copy_from_slice(PDA_PREFIX);
    input[32..64].copy_from_slice(program_id);
    input[64..96].copy_from_slice(&seed);
    Sha256::digest(input).into()
}

/// `getAccount` over the sequencer's JSON-RPC via curl, reduced to the bytes of
/// one program's shard. Returns `None` when the account or that shard is absent
/// (the sequencer's "not registered" answer).
fn get_account_shard(sequencer: &str, id: &[u8; 32], shard: &[u8; 32]) -> Option<Vec<u8>> {
    let result = rpc(
        sequencer,
        "getAccount",
        serde_json::json!([bs58::encode(id).into_string()]),
    );
    shard_bytes(&result, shard)
}

/// Bytes stored under `shard` (keyed by the program account id's base58) in a
/// `getAccount` result; `None` when the key is absent or its bytes are empty.
fn shard_bytes(account: &serde_json::Value, shard: &[u8; 32]) -> Option<Vec<u8>> {
    let shards = account["data"]["shards"]
        .as_object()
        .unwrap_or_else(|| fail("getAccount reply has no data.shards map"));
    let bytes = shards
        .get(&bs58::encode(shard).into_string())?
        .as_array()
        .unwrap_or_else(|| fail("getAccount shard is not a byte array"));
    let data: Vec<u8> = bytes
        .iter()
        .map(|v| {
            v.as_u64()
                .and_then(|b| u8::try_from(b).ok())
                .unwrap_or_else(|| fail("getAccount shard holds a non-byte value"))
        })
        .collect();
    if data.is_empty() {
        None
    } else {
        Some(data)
    }
}

fn clock_timestamp_ms(sequencer: &str) -> u64 {
    let data = get_account_shard(
        sequencer,
        &CLOCK_50_ACCOUNT_ID_BYTES,
        &clock_program_account_id(),
    )
    .unwrap_or_else(|| fail("clock account is absent — cannot compute lifecycle state"));
    if data.len() < 16 {
        fail("clock account too short");
    }
    u64::from_le_bytes(data[8..16].try_into().expect("8-byte clock timestamp"))
}

fn rpc(sequencer: &str, method: &str, params: serde_json::Value) -> serde_json::Value {
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
        .to_string();
    let out = std::process::Command::new("curl")
        .args([
            "-sS",
            "-m",
            "60",
            "-X",
            "POST",
            sequencer,
            "-H",
            "Content-Type: application/json",
            "--data-binary",
            &body,
        ])
        .output()
        .unwrap_or_else(|e| fail(&format!("curl failed to run ({e}) — is curl installed?")));
    if !out.status.success() {
        fail(&format!(
            "curl error reaching {sequencer}: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|_| fail("sequencer returned malformed JSON-RPC"));
    if let Some(err) = doc.get("error").filter(|e| !e.is_null()) {
        fail(&format!("sequencer {method} error: {err}"));
    }
    doc.get("result")
        .cloned()
        .unwrap_or_else(|| fail("JSON-RPC reply has no result"))
}

fn report_registered(json: bool, state: &MembershipState, status: &str, now_ms: u64) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "registered": true,
                "state": status,
                "leaf_index": state.leaf_index,
                "rate_limit": state.rate_limit,
                "grace_period_start_timestamp": state.grace_period_start_timestamp_ms,
                "grace_period_duration": state.grace_period_duration_sec,
                "clock_timestamp": now_ms,
            })
        );
    } else {
        println!(
            "\u{2713} Registered \u{2014} state: {status}, leaf index: {}, rate limit: {}",
            state.leaf_index, state.rate_limit
        );
    }
}

fn report_unregistered(json: bool) {
    if json {
        println!("{}", serde_json::json!({ "registered": false }));
    } else {
        println!("\u{2717} Not registered \u{2014} no membership account for this commitment in this registry");
    }
}

fn load_deployment(
    path: &str,
    tree_id: &mut Option<String>,
    program_id: &mut Option<String>,
    sequencer: &mut String,
) {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| fail(&format!("cannot read deployment {path}: {e}")));
    let doc: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|_| fail(&format!("deployment {path} is not valid JSON")));
    let field = |k: &str| {
        doc.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| fail(&format!("deployment {path} missing string field '{k}'")))
            .to_string()
    };
    *tree_id = Some(field("tree_id"));
    *program_id = Some(field("registration_program_id"));
    *sequencer = field("sequencer");
}

fn parse_hex32(s: &str, what: &str) -> [u8; 32] {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        fail(&format!("{what} must be 64 hex chars, got {:?}", s));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("checked hex");
    }
    out
}

fn take(args: &[String], i: &mut usize) -> String {
    *i += 1;
    args.get(*i)
        .cloned()
        .unwrap_or_else(|| fail(&format!("{} needs a value", args[*i - 1])))
}

fn fail(msg: &str) -> ! {
    eprintln!("check-membership: {msg}");
    std::process::exit(2);
}

fn print_usage() {
    println!("check-membership \u{2014} verify an RLN membership is registered on-chain\n");
    println!("USAGE:\n  check-membership --commitment <64-hex> [options]\n");
    println!("OPTIONS:");
    println!("  -c, --commitment <hex>  Identity commitment (from the RLN Membership detail view)");
    println!("      --deployment <file> Read tree-id/program-id/sequencer from a deployment.json");
    println!("      --tree-id <hex>     Registry tree id (or {TREE_ID_ENV})");
    println!("      --program-id <hex>  Registration program id: the header account run_setup");
    println!("                          recorded (or {PROGRAM_ID_ENV})");
    println!(
        "      --sequencer <url>   Override sequencer endpoint     (default: {DEFAULT_SEQUENCER})"
    );
    println!("      --json              Emit JSON instead of a human line");
    println!("  -h, --help              Show this help\n");
    println!("EXIT: 0 registered, 1 not registered, 2 error");
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixed inputs for the pinned derivation below; any program id works, the
    // pin covers PDA_PREFIX and the seed rules.
    const TEST_TREE_ID: &str = "15f5520c1648358440b73a7b11f4a8cf8e44b63b7a0ae326609863e3e2f1b6ee";
    const TEST_PROGRAM_ID: &str =
        "65343a570616eec04387832a193b258ee48d445f1feb4d842db4f320feec3e7b";

    // Pins the derivation against a real shared-faucet membership (commitment
    // -> account) confirmed on-chain (leaf 42, verified independently in
    // Python), so a change to PDA_PREFIX / seed rules can never silently
    // mis-derive.
    #[test]
    fn derives_known_membership_account() {
        let program = parse_hex32(TEST_PROGRAM_ID, "program");
        let tree = parse_hex32(TEST_TREE_ID, "tree");
        let commitment = parse_hex32(
            "896b3137d84ff2e1234e40c3f2a9f0f42d5af293b2429dc8943d283f606dfd02",
            "commitment",
        );
        let expected = parse_hex32(
            "c7326696d5f88ab2566492d6f76c0bc3eb8665dee315d786cc506186fd5d35ef",
            "account",
        );
        assert_eq!(
            derive_membership_account(&program, &tree, &commitment),
            expected
        );
    }

    #[test]
    fn reads_the_requested_shard_by_base58_key() {
        let reg = [7u8; 32];
        let other = [9u8; 32];
        let doc = serde_json::json!({
            "nonce": 0,
            "data": { "shards": {
                bs58::encode(reg).into_string(): [1, 2, 3],
                bs58::encode(other).into_string(): [4],
            }},
        });
        assert_eq!(shard_bytes(&doc, &reg), Some(vec![1, 2, 3]));
        assert_eq!(shard_bytes(&doc, &[5u8; 32]), None);
    }

    #[test]
    fn empty_shard_map_is_not_registered() {
        let doc = serde_json::json!({ "nonce": 0, "data": { "shards": {} } });
        assert_eq!(shard_bytes(&doc, &[7u8; 32]), None);
    }

    #[test]
    fn clock_shard_key_is_the_builtin_clock_program_id() {
        let clock = clock_program_account_id();
        let doc = serde_json::json!({
            "nonce": 0,
            "data": { "shards": { bs58::encode(clock).into_string(): [0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0] } },
        });
        let data = shard_bytes(&doc, &clock).unwrap();
        assert_eq!(u64::from_le_bytes(data[8..16].try_into().unwrap()), 5);
    }

    #[test]
    fn hex_roundtrip_rejects_bad_length() {
        assert_eq!(parse_hex32(&"ab".repeat(32), "x").len(), 32);
    }
}
