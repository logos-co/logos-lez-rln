//! Where the two deployed programs live.
//!
//! A program's account id is the header account its deployer created and
//! signed, so it cannot be derived from the `.bin`: it is deployment state.
//! `run_setup` records both ids per tree in
//! `~/.logos-lez-rln/programs_<tree_hex>.json` as
//! `{"registration_program_id":"<64hex>","merkle_program_id":"<64hex>"}`, and
//! every tool reads them back from there. `LEZ_RLN_REGISTRATION_PROGRAM_ID`
//! and `LEZ_RLN_MERKLE_PROGRAM_ID` (64 hex each) override the record field by
//! field, which is also how a new tree reuses programs deployed for another.

use std::path::PathBuf;

use nssa::AccountId;

use super::client::DATA_DIR;

pub const REGISTRATION_PROGRAM_ID_ENV: &str = "LEZ_RLN_REGISTRATION_PROGRAM_ID";
pub const MERKLE_PROGRAM_ID_ENV: &str = "LEZ_RLN_MERKLE_PROGRAM_ID";

const REGISTRATION_KEY: &str = "registration_program_id";
const MERKLE_KEY: &str = "merkle_program_id";

/// The account ids of the deployed registration and merkle programs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramIds {
    pub registration: AccountId,
    pub merkle: AccountId,
}

/// Either id, when only one is known.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KnownProgramIds {
    pub registration: Option<AccountId>,
    pub merkle: Option<AccountId>,
}

impl KnownProgramIds {
    pub fn complete(self) -> Option<ProgramIds> {
        Some(ProgramIds {
            registration: self.registration?,
            merkle: self.merkle?,
        })
    }
}

pub fn hex_id(id: &AccountId) -> String {
    hex::encode(id.value())
}

fn parse_hex_id(raw: &str, what: &str) -> Result<AccountId, String> {
    let bytes = hex::decode(raw.trim()).map_err(|e| format!("{what} is not hex: {e}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("{what} must be 32 bytes, got {}", v.len()))?;
    Ok(AccountId::new(bytes))
}

pub fn record_path(tree_id: &[u8; 32]) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(DATA_DIR)
        .join(format!("programs_{}.json", hex::encode(tree_id)))
}

pub fn encode_record(ids: &ProgramIds) -> String {
    serde_json::json!({
        REGISTRATION_KEY: hex_id(&ids.registration),
        MERKLE_KEY: hex_id(&ids.merkle),
    })
    .to_string()
}

pub fn decode_record(json: &str) -> Result<ProgramIds, String> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("not JSON: {e}"))?;
    let field = |key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("missing string field `{key}`"))
            .and_then(|raw| parse_hex_id(raw, key))
    };
    Ok(ProgramIds {
        registration: field(REGISTRATION_KEY)?,
        merkle: field(MERKLE_KEY)?,
    })
}

pub fn save_program_ids(tree_id: &[u8; 32], ids: &ProgramIds) {
    let path = record_path(tree_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, encode_record(ids))
        .unwrap_or_else(|e| panic!("Failed to write {}: {e}", path.display()));
}

fn env_id(var: &str) -> Result<Option<AccountId>, String> {
    match std::env::var(var) {
        Ok(raw) => parse_hex_id(&raw, var).map(Some),
        Err(_) => Ok(None),
    }
}

/// Every id known for `tree_id`: environment first, then the record.
pub fn known_program_ids(tree_id: &[u8; 32]) -> Result<KnownProgramIds, String> {
    let path = record_path(tree_id);
    let record = match std::fs::read_to_string(&path) {
        Ok(json) => Some(decode_record(&json).map_err(|e| format!("{}: {e}", path.display()))?),
        Err(_) => None,
    };
    Ok(KnownProgramIds {
        registration: env_id(REGISTRATION_PROGRAM_ID_ENV)?.or(record.map(|ids| ids.registration)),
        merkle: env_id(MERKLE_PROGRAM_ID_ENV)?.or(record.map(|ids| ids.merkle)),
    })
}

/// Both program ids for `tree_id`, or exit with what to set.
pub fn program_ids_or_exit(tree_id: &[u8; 32]) -> ProgramIds {
    let known = known_program_ids(tree_id).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2);
    });
    known.complete().unwrap_or_else(|| {
        eprintln!(
            "No program ids for tree {}: run `run_setup`, or set {REGISTRATION_PROGRAM_ID_ENV} \
             and {MERKLE_PROGRAM_ID_ENV} (64 hex each), or write {}",
            hex::encode(tree_id),
            record_path(tree_id).display()
        );
        std::process::exit(2);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_round_trips() {
        let ids = ProgramIds {
            registration: AccountId::new([0xA1; 32]),
            merkle: AccountId::new([0xB2; 32]),
        };
        assert_eq!(decode_record(&encode_record(&ids)), Ok(ids));
    }

    #[test]
    fn the_record_spells_ids_as_hex() {
        let ids = ProgramIds {
            registration: AccountId::new([0x01; 32]),
            merkle: AccountId::new([0x02; 32]),
        };
        let value: serde_json::Value = serde_json::from_str(&encode_record(&ids)).unwrap();
        assert_eq!(value[REGISTRATION_KEY], "01".repeat(32));
        assert_eq!(value[MERKLE_KEY], "02".repeat(32));
    }

    #[test]
    fn a_record_missing_a_field_is_refused() {
        let json = format!("{{\"{REGISTRATION_KEY}\":\"{}\"}}", "01".repeat(32));
        assert!(decode_record(&json).is_err());
    }

    #[test]
    fn a_short_id_is_refused() {
        let json = format!(
            "{{\"{REGISTRATION_KEY}\":\"0102\",\"{MERKLE_KEY}\":\"{}\"}}",
            "02".repeat(32)
        );
        assert!(decode_record(&json).is_err());
    }
}
