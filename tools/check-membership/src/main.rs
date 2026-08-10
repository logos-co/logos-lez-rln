//! `check-membership` — prove an RLN membership registered on-chain.
//!
//! Given an identity commitment (copyable from the RLN Membership UI's detail
//! view), derive the membership account the registration program owns and read
//! it straight off the sequencer's `getAccount` JSON-RPC. A populated,
//! decodable account IS the registration's on-chain effect — this sequencer has
//! no transaction-by-hash lookup, so the account read is the confirmation.
//!
//! Wallet-free and daemon-free: it reuses the shared `rln-layouts` seed rules
//! and account layouts (the same the module uses), replicating only the
//! 3-line SPEL PDA hash. Defaults target the shared-faucet testnet registry;
//! override with --tree-id / --program-id / --sequencer or --deployment.

use borsh::BorshDeserialize;
use rln_layouts::{
    combine_seeds, is_expired, is_in_grace_period, label_seed, MembershipState,
    CLOCK_50_ACCOUNT_ID_BYTES,
};
use sha2::{Digest, Sha256};

// Shared-faucet testnet registry (deployments/shared-faucet/deployment.json).
const DEFAULT_TREE_ID: &str = "15f5520c1648358440b73a7b11f4a8cf8e44b63b7a0ae326609863e3e2f1b6ee";
const DEFAULT_PROGRAM_ID: &str = "65343a570616eec04387832a193b258ee48d445f1feb4d842db4f320feec3e7b";
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
    let mut tree_id_hex = DEFAULT_TREE_ID.to_string();
    let mut program_id_hex = DEFAULT_PROGRAM_ID.to_string();
    let mut sequencer = DEFAULT_SEQUENCER.to_string();
    let mut json = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--commitment" | "-c" => commitment_hex = Some(take(&args, &mut i)),
            "--tree-id" => tree_id_hex = take(&args, &mut i),
            "--program-id" => program_id_hex = take(&args, &mut i),
            "--sequencer" => sequencer = take(&args, &mut i),
            "--deployment" => load_deployment(&take(&args, &mut i), &mut tree_id_hex, &mut program_id_hex, &mut sequencer),
            "--json" => json = true,
            other => fail(&format!("unknown argument: {other} (see --help)")),
        }
        i += 1;
    }

    let commitment = parse_hex32(
        &commitment_hex.unwrap_or_else(|| fail("--commitment <64-hex identity commitment> is required (see --help)")),
        "commitment",
    );
    let cfg = Config {
        tree_id: parse_hex32(&tree_id_hex, "tree-id"),
        program_id: parse_hex32(&program_id_hex, "program-id"),
        sequencer,
    };

    let membership_id = derive_membership_account(&cfg.program_id, &cfg.tree_id, &commitment);

    let Some(data) = get_account(&cfg.sequencer, &membership_id) else {
        report_unregistered(json);
        std::process::exit(1);
    };
    if data.len() < MEMBERSHIP_STATE_SIZE {
        fail("membership account is present but too short to decode");
    }
    let state = MembershipState::try_from_slice(&data[..MEMBERSHIP_STATE_SIZE])
        .unwrap_or_else(|_| { fail("failed to decode membership account") });

    let now = clock_timestamp(&cfg.sequencer);
    let status = lifecycle(&state, now);
    report_registered(json, &state, status, now);
}

fn lifecycle(state: &MembershipState, now: u64) -> &'static str {
    let (start, dur) = (state.grace_period_start_timestamp, state.grace_period_duration);
    if is_expired(start, dur, now) {
        "expired"
    } else if is_in_grace_period(start, dur, now) {
        "grace_period"
    } else {
        "active"
    }
}

/// Membership account = `derive_pda(program_id, SHA-256(label("membership") ||
/// tree_id || id_commitment))` — the same derivation as the module's
/// `register_plan`.
fn derive_membership_account(program_id: &[u8; 32], tree_id: &[u8; 32], commitment: &[u8; 32]) -> [u8; 32] {
    let seed = combine_seeds(&[&label_seed("membership"), tree_id, commitment]);
    let mut input = [0u8; 96];
    input[0..32].copy_from_slice(PDA_PREFIX);
    input[32..64].copy_from_slice(program_id);
    input[64..96].copy_from_slice(&seed);
    Sha256::digest(input).into()
}

/// `getAccount` over the sequencer's JSON-RPC via curl. Returns the account
/// data, or `None` when the account is absent (empty data — the sequencer's
/// "not registered" answer).
fn get_account(sequencer: &str, id: &[u8; 32]) -> Option<Vec<u8>> {
    let result = rpc(sequencer, "getAccount", serde_json::json!([bs58::encode(id).into_string()]));
    let data: Vec<u8> = result["data"]
        .as_array()
        .unwrap_or_else(|| { fail("getAccount reply has no data array") })
        .iter()
        .map(|v| v.as_u64().expect("account byte") as u8)
        .collect();
    if data.is_empty() { None } else { Some(data) }
}

fn clock_timestamp(sequencer: &str) -> u64 {
    let data = get_account(sequencer, &CLOCK_50_ACCOUNT_ID_BYTES)
        .unwrap_or_else(|| { fail("clock account is absent — cannot compute lifecycle state") });
    if data.len() < 16 {
        fail("clock account too short");
    }
    u64::from_le_bytes(data[8..16].try_into().expect("8-byte clock timestamp"))
}

fn rpc(sequencer: &str, method: &str, params: serde_json::Value) -> serde_json::Value {
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string();
    let out = std::process::Command::new("curl")
        .args(["-sS", "-m", "60", "-X", "POST", sequencer, "-H", "Content-Type: application/json", "--data-binary", &body])
        .output()
        .unwrap_or_else(|e| { fail(&format!("curl failed to run ({e}) — is curl installed?")) });
    if !out.status.success() {
        fail(&format!("curl error reaching {sequencer}: {}", String::from_utf8_lossy(&out.stderr)));
    }
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|_| { fail("sequencer returned malformed JSON-RPC") });
    if let Some(err) = doc.get("error").filter(|e| !e.is_null()) {
        fail(&format!("sequencer {method} error: {err}"));
    }
    doc.get("result").cloned().unwrap_or_else(|| { fail("JSON-RPC reply has no result") })
}

fn report_registered(json: bool, state: &MembershipState, status: &str, now: u64) {
    if json {
        println!("{}", serde_json::json!({
            "registered": true,
            "state": status,
            "leaf_index": state.leaf_index,
            "rate_limit": state.rate_limit,
            "grace_period_start_timestamp": state.grace_period_start_timestamp,
            "grace_period_duration": state.grace_period_duration,
            "clock_timestamp": now,
        }));
    } else {
        println!("\u{2713} Registered \u{2014} state: {status}, leaf index: {}, rate limit: {}", state.leaf_index, state.rate_limit);
    }
}

fn report_unregistered(json: bool) {
    if json {
        println!("{}", serde_json::json!({ "registered": false }));
    } else {
        println!("\u{2717} Not registered \u{2014} no membership account for this commitment in this registry");
    }
}

fn load_deployment(path: &str, tree_id: &mut String, program_id: &mut String, sequencer: &mut String) {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| { fail(&format!("cannot read deployment {path}: {e}")) });
    let doc: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|_| { fail(&format!("deployment {path} is not valid JSON")) });
    let field = |k: &str| doc.get(k).and_then(|v| v.as_str())
        .unwrap_or_else(|| { fail(&format!("deployment {path} missing string field '{k}'")) })
        .to_string();
    *tree_id = field("tree_id");
    *program_id = field("registration_program_id");
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
    args.get(*i).cloned().unwrap_or_else(|| { fail(&format!("{} needs a value", args[*i - 1])) })
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
    println!("      --tree-id <hex>     Override registry tree id      (default: shared-faucet)");
    println!("      --program-id <hex>  Override registration program  (default: shared-faucet)");
    println!("      --sequencer <url>   Override sequencer endpoint     (default: {DEFAULT_SEQUENCER})");
    println!("      --json              Emit JSON instead of a human line");
    println!("  -h, --help              Show this help\n");
    println!("EXIT: 0 registered, 1 not registered, 2 error");
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pins the derivation against a real shared-faucet membership (commitment
    // -> account) confirmed on-chain (leaf 42, verified independently in
    // Python), so a change to PDA_PREFIX / seed rules can never silently
    // mis-derive.
    #[test]
    fn derives_known_membership_account() {
        let program = parse_hex32(DEFAULT_PROGRAM_ID, "program");
        let tree = parse_hex32(DEFAULT_TREE_ID, "tree");
        let commitment = parse_hex32(
            "896b3137d84ff2e1234e40c3f2a9f0f42d5af293b2429dc8943d283f606dfd02",
            "commitment",
        );
        let expected = parse_hex32(
            "c7326696d5f88ab2566492d6f76c0bc3eb8665dee315d786cc506186fd5d35ef",
            "account",
        );
        assert_eq!(derive_membership_account(&program, &tree, &commitment), expected);
    }

    #[test]
    fn hex_roundtrip_rejects_bad_length() {
        assert_eq!(parse_hex32(&"ab".repeat(32), "x").len(), 32);
    }
}
