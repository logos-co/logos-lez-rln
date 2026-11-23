//! Keys of a deployment whose addresses are fixed before its chain exists.
//!
//! Every account a deployment creates is a keyed account or a PDA hanging
//! off one: a program lives at the account its header key signs for, a
//! registry's tree id is `owner_tree_id(owner, label)`, and the config, tree
//! and membership accounts are PDAs of the registration program. Derive the
//! keys from one secret and a deployment name, and every id is a function of
//! those two: computable today, reproduced by any later deploy.
//!
//! ```text
//! key = SHA-256( pad32("lez-rln/deploy-key/v1") ‖ secret ‖ pad32(name) ‖ role… ‖ u32(counter) )
//! ```
//!
//! taking the first counter whose digest is a valid secp256k1 scalar. Every
//! part is a 32-byte seed (`rln_layouts::combine_seeds`); `role` is one or
//! more of them:
//!
//! | key | role |
//! |---|---|
//! | a program's header | `"program"`, `"registration"` or `"merkle"` |
//! | a program's segment | `"segment"`, the program, its image id, `u32(attempt)`, `u32(index)` |
//! | the registry owner | `"registry-owner"` |
//! | a registry's treasury | `"treasury"`, the tree label |
//! | the fee payer | `"payer"` |
//!
//! The name is part of every key, so two deployments of one secret share no
//! account: a rehearsal on another chain signs nothing that the real one's
//! accounts could be replayed with (a LEZ transaction names no chain).
//!
//! The secret is read from a file and never printed. A header key signs only
//! its own deploy: a signature authorizes every actor on the account for the
//! whole transaction, and a segment written into a header account closes it
//! to `CreateHeader` for good.

use std::path::Path;

use nssa::{AccountId, PrivateKey, PublicKey};
use nssa_core::program::ProgramId;
use rln_layouts::{combine_seeds, label_seed, u32_seed};

/// Names a file holding the deployment secret: 64 hex characters.
pub const DEPLOY_SECRET_FILE_ENV: &str = "LEZ_RLN_DEPLOY_SECRET_FILE";
/// The deployment's name: at most 32 bytes of `[a-z0-9._-]`.
pub const DEPLOY_NAME_ENV: &str = "LEZ_RLN_DEPLOY_NAME";

const DOMAIN: &str = "lez-rln/deploy-key/v1";

/// The two programs a deployment places.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgramRole {
    Registration,
    Merkle,
}

impl ProgramRole {
    const fn label(self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::Merkle => "merkle",
        }
    }
}

/// The account `key` signs for.
pub fn account_of(key: &PrivateKey) -> AccountId {
    AccountId::from(&PublicKey::new_from_private_key(key))
}

/// A deployment's secret and name. Holds the secret: not `Debug`, not
/// printable.
pub struct DeployKeys {
    secret: [u8; 32],
    name: String,
}

impl DeployKeys {
    pub fn new(secret: [u8; 32], name: &str) -> Result<Self, String> {
        if secret == [0u8; 32] {
            return Err("the deployment secret is all zeros".to_string());
        }
        let well_formed = !name.is_empty()
            && name.len() <= 32
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b));
        if !well_formed {
            return Err(format!(
                "the deployment name must be 1 to 32 characters of [a-z0-9._-], got {name:?}"
            ));
        }
        Ok(Self {
            secret,
            name: name.to_string(),
        })
    }

    /// The secret from `path` (64 hex characters, surrounding whitespace
    /// ignored). An error never quotes the file's content.
    pub fn from_secret_file(path: &Path, name: &str) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read the deployment secret {}: {e}", path.display()))?;
        let mut secret = [0u8; 32];
        hex::decode_to_slice(raw.trim(), &mut secret).map_err(|_| {
            format!(
                "{} does not hold 64 hex characters (make one with `openssl rand -hex 32`)",
                path.display()
            )
        })?;
        Self::new(secret, name)
    }

    /// The keys the environment names, or `None` when it names no secret.
    pub fn from_env() -> Result<Option<Self>, String> {
        let Some(path) = std::env::var_os(DEPLOY_SECRET_FILE_ENV) else {
            return Ok(None);
        };
        let name = std::env::var(DEPLOY_NAME_ENV)
            .map_err(|_| format!("{DEPLOY_SECRET_FILE_ENV} is set but {DEPLOY_NAME_ENV} is not"))?;
        Self::from_secret_file(Path::new(&path), &name).map(Some)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    fn key(&self, role: &[&[u8; 32]]) -> PrivateKey {
        let domain = label_seed(DOMAIN);
        let name = label_seed(&self.name);
        for counter in 0..=u32::MAX {
            let counter = u32_seed(counter);
            let mut seeds: Vec<&[u8; 32]> = vec![&domain, &self.secret, &name];
            seeds.extend_from_slice(role);
            seeds.push(&counter);
            if let Ok(key) = PrivateKey::try_new(combine_seeds(&seeds)) {
                return key;
            }
        }
        unreachable!("no digest in 2^32 is a valid scalar")
    }

    /// Signs the program's `CreateHeader`: the account is the program's id.
    pub fn program_header(&self, program: ProgramRole) -> PrivateKey {
        self.key(&[&label_seed("program"), &label_seed(program.label())])
    }

    /// Signs one `WriteSegment`. The image id keeps another build's segments
    /// apart, and `attempt` lets a re-run step past an interrupted upload:
    /// segments are write-once.
    pub fn program_segment(
        &self,
        program: ProgramRole,
        image_id: &ProgramId,
        attempt: u32,
        index: u32,
    ) -> PrivateKey {
        self.key(&[
            &label_seed("segment"),
            &label_seed(program.label()),
            &bytemuck::cast(*image_id),
            &u32_seed(attempt),
            &u32_seed(index),
        ])
    }

    /// Signs `Initialize`: the account owns the deployment's registries.
    pub fn registry_owner(&self) -> PrivateKey {
        self.key(&[&label_seed("registry-owner")])
    }

    /// The account a registry's price accrues to.
    pub fn treasury(&self, tree_label: &[u8; 32]) -> PrivateKey {
        self.key(&[&label_seed("treasury"), tree_label])
    }

    /// A fee payer to fund at genesis. No id depends on it: any funded
    /// account can pay for the deploy instead.
    pub fn payer(&self) -> PrivateKey {
        self.key(&[&label_seed("payer")])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(name: &str) -> DeployKeys {
        DeployKeys::new([7u8; 32], name).unwrap()
    }

    fn every_account(keys: &DeployKeys) -> Vec<AccountId> {
        let image = [9u32; 8];
        vec![
            account_of(&keys.program_header(ProgramRole::Registration)),
            account_of(&keys.program_header(ProgramRole::Merkle)),
            account_of(&keys.program_segment(ProgramRole::Registration, &image, 0, 0)),
            account_of(&keys.program_segment(ProgramRole::Registration, &image, 0, 1)),
            account_of(&keys.program_segment(ProgramRole::Registration, &image, 1, 0)),
            account_of(&keys.program_segment(ProgramRole::Merkle, &image, 0, 0)),
            account_of(&keys.program_segment(ProgramRole::Merkle, &[8u32; 8], 0, 0)),
            account_of(&keys.registry_owner()),
            account_of(&keys.treasury(&label_seed("relay"))),
            account_of(&keys.treasury(&label_seed("mix"))),
            account_of(&keys.payer()),
        ]
    }

    #[test]
    fn the_same_secret_and_name_give_the_same_accounts() {
        assert_eq!(
            every_account(&keys("testnet")),
            every_account(&keys("testnet"))
        );
    }

    #[test]
    fn every_role_has_its_own_account() {
        let accounts = every_account(&keys("testnet"));
        for (i, a) in accounts.iter().enumerate() {
            for b in &accounts[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn another_name_or_secret_shares_no_account() {
        let base = every_account(&keys("testnet"));
        let other_name = every_account(&keys("rehearsal"));
        let other_secret = every_account(&DeployKeys::new([8u8; 32], "testnet").unwrap());
        for account in &base {
            assert!(!other_name.contains(account));
            assert!(!other_secret.contains(account));
        }
    }

    /// Pinned against an independent computation (secp256k1 and SHA-256 by
    /// hand): a plan published today must name the account a deploy signs
    /// for later.
    #[test]
    fn a_header_account_is_pinned() {
        let keys = DeployKeys::new([7u8; 32], "testnet").unwrap();
        assert_eq!(
            hex::encode(account_of(&keys.program_header(ProgramRole::Registration)).value()),
            "a36d7c66478c98902dfd80ccf07db3babc75874c39b5ac71cf86976213749fa0"
        );
    }

    #[test]
    fn a_malformed_name_or_secret_is_refused() {
        for name in ["", "Testnet", "a b", "x".repeat(33).as_str()] {
            assert!(DeployKeys::new([7u8; 32], name).is_err(), "{name:?}");
        }
        assert!(DeployKeys::new([0u8; 32], "testnet").is_err());
    }

    #[test]
    fn a_secret_file_error_does_not_quote_the_file() {
        let dir = std::env::temp_dir().join(format!("lez-rln-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret");
        std::fs::write(&path, "not-a-secret-value").unwrap();
        let error = DeployKeys::from_secret_file(&path, "testnet")
            .err()
            .unwrap();
        assert!(!error.contains("not-a-secret-value"), "{error}");
        std::fs::write(&path, format!("{}\n", "07".repeat(32))).unwrap();
        let from_file = DeployKeys::from_secret_file(&path, "testnet").unwrap();
        assert_eq!(every_account(&from_file), every_account(&keys("testnet")));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
