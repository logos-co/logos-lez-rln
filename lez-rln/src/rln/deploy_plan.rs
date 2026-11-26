//! A deployment as it will be: every id a client or a preset needs, computed
//! from the deployment's keys before anything is on chain.
//!
//! A plan is public. It names accounts and public keys, never a private key,
//! and a registry it names cannot be taken by anyone else: the programs live
//! at accounts only the deployment's header keys sign for, and a tree id is
//! `owner_tree_id(owner, label)`, which only the owner can initialize.
//!
//! What a plan does NOT fix is the code: a program's id is its header
//! account, whatever image is deployed there. The image ids of the local
//! guest binaries are recorded when they are at hand, and a deploy refuses
//! binaries that differ from the plan's.
//!
//! The ids hold for a LEZ that derives addresses as `LEZ_TAG` does (a keyed
//! account from its public key, a PDA from a program's account id and a
//! seed, a program at its header account).

use nssa::{AccountId, PrivateKey, PublicKey};
use nssa_core::program::ProgramId;
use rln_layouts::ConfigState;
use serde_json::{Value, json};

use super::{
    ProgramIds,
    client::{RegistryParams, tree_label},
    deploy_keys::{DeployKeys, ProgramRole, account_of},
    derive_config_account, derive_tree_main_account,
    program_ids::hex_id,
};

pub const PLAN_FORMAT: &str = "lez-rln-deployment-plan";
pub const PLAN_VERSION: u64 = 1;
/// The LEZ whose address derivation the plan's ids come from: the tag this
/// crate builds against.
pub const LEZ_TAG: &str = "v0.4.0-rc3";

/// A program's image id as risc0 prints a digest.
pub fn hex_image_id(image_id: &ProgramId) -> String {
    hex::encode(bytemuck::cast::<ProgramId, [u8; 32]>(*image_id))
}

/// A registry to plan: its label and what it is initialized with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrySpec {
    pub label: String,
    pub params: RegistryParams,
}

impl RegistrySpec {
    /// `<label>` or `<label>:<min rate>:<max rate>`; whatever is not given is
    /// `defaults`'.
    pub fn parse(raw: &str, defaults: RegistryParams) -> Result<Self, String> {
        let parts: Vec<&str> = raw.split(':').collect();
        let (label, params) = match parts.as_slice() {
            [label] => (*label, defaults),
            [label, min, max] => {
                let rate = |what: &str, raw: &str| {
                    raw.parse::<u64>()
                        .map_err(|_| format!("{what} rate limit of {label:?} is not a number"))
                };
                (
                    *label,
                    RegistryParams {
                        min_rate_limit: rate("min", min)?,
                        max_rate_limit: rate("max", max)?,
                        ..defaults
                    },
                )
            }
            _ => {
                return Err(format!(
                    "expected <label> or <label>:<min>:<max>, got {raw:?}"
                ));
            }
        };
        if label.is_empty() {
            return Err(format!("a registry needs a label, got {raw:?}"));
        }
        tree_label(label)?;
        if params.min_rate_limit == 0 || params.min_rate_limit > params.max_rate_limit {
            return Err(format!(
                "{label:?}: rate limit bounds must satisfy 0 < min <= max, got {}..={}",
                params.min_rate_limit, params.max_rate_limit
            ));
        }
        Ok(Self {
            label: label.to_string(),
            params,
        })
    }
}

/// One registry of a plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedRegistry {
    pub label: String,
    pub tree_label: [u8; 32],
    pub tree_id: [u8; 32],
    pub config_account: AccountId,
    pub tree_main_account: AccountId,
    pub treasury_account: AccountId,
    pub treasury_public_key: PublicKey,
    pub params: RegistryParams,
}

/// A deployment's programs, owner and registries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentPlan {
    pub name: String,
    pub programs: ProgramIds,
    pub owner: AccountId,
    pub owner_public_key: PublicKey,
    /// The deployment's own fee payer, for a genesis to fund. No id depends
    /// on it.
    pub payer: AccountId,
    pub payer_public_key: PublicKey,
    pub registries: Vec<PlannedRegistry>,
}

impl DeploymentPlan {
    pub fn derive(keys: &DeployKeys, registries: &[RegistrySpec]) -> Result<Self, String> {
        if registries.is_empty() {
            return Err("a deployment plans at least one registry".to_string());
        }
        let programs = ProgramIds {
            registration: account_of(&keys.program_header(ProgramRole::Registration)),
            merkle: account_of(&keys.program_header(ProgramRole::Merkle)),
        };
        let owner_key = keys.registry_owner();
        let owner = account_of(&owner_key);
        let payer_key = keys.payer();
        let mut planned: Vec<PlannedRegistry> = Vec::with_capacity(registries.len());
        for spec in registries {
            if planned.iter().any(|other| other.label == spec.label) {
                return Err(format!("the label {:?} is planned twice", spec.label));
            }
            let tree_label = tree_label(&spec.label)?;
            let tree_id = rln_layouts::owner_tree_id(owner.value(), &tree_label);
            let treasury_key = keys.treasury(&tree_label);
            planned.push(PlannedRegistry {
                label: spec.label.clone(),
                tree_label,
                tree_id,
                config_account: derive_config_account(&programs.registration, &tree_id),
                tree_main_account: derive_tree_main_account(&programs.registration, &tree_id),
                treasury_account: account_of(&treasury_key),
                treasury_public_key: PublicKey::new_from_private_key(&treasury_key),
                params: spec.params,
            });
        }
        Ok(Self {
            name: keys.name().to_string(),
            programs,
            owner,
            owner_public_key: PublicKey::new_from_private_key(&owner_key),
            payer: account_of(&payer_key),
            payer_public_key: PublicKey::new_from_private_key(&payer_key),
            registries: planned,
        })
    }

    /// The plan with the account of `key` as the payer to fund, in place of
    /// the one the deployment secret derives. Nothing else changes.
    #[must_use]
    pub fn paid_by(mut self, key: &PrivateKey) -> Self {
        self.payer = account_of(key);
        self.payer_public_key = PublicKey::new_from_private_key(key);
        self
    }

    /// The plan as JSON. `images` are the image ids of the registration and
    /// the merkle binary, when the binaries are at hand.
    pub fn to_json(&self, images: Option<(&ProgramId, &ProgramId)>) -> Value {
        let image = |id: Option<&ProgramId>| id.map_or(Value::Null, |id| json!(hex_image_id(id)));
        json!({
            "format": PLAN_FORMAT,
            "version": PLAN_VERSION,
            "name": self.name,
            "lez": LEZ_TAG,
            "registration_program_id": hex_id(&self.programs.registration),
            "merkle_program_id": hex_id(&self.programs.merkle),
            "registration_program_account": self.programs.registration.to_string(),
            "merkle_program_account": self.programs.merkle.to_string(),
            "registration_image_id": image(images.map(|(registration, _)| registration)),
            "merkle_image_id": image(images.map(|(_, merkle)| merkle)),
            "owner_account": self.owner.to_string(),
            "owner_public_key": self.owner_public_key.to_string(),
            "payer_account": self.payer.to_string(),
            "payer_public_key": self.payer_public_key.to_string(),
            "registries": self.registries.iter().map(|registry| json!({
                "label": registry.label,
                "tree_id": hex::encode(registry.tree_id),
                "config_account": registry.config_account.to_string(),
                "config_account_hex": hex_id(&registry.config_account),
                "tree_main_account": registry.tree_main_account.to_string(),
                "treasury_account": registry.treasury_account.to_string(),
                "treasury_public_key": registry.treasury_public_key.to_string(),
                "price_per_unit": registry.params.price_per_unit.to_string(),
                "max_total_rate_limit": registry.params.max_total_rate_limit,
                "active_duration_secs": registry.params.active_duration_sec,
                "grace_period_duration_secs": registry.params.grace_period_duration_sec,
                "min_rate_limit": registry.params.min_rate_limit,
                "max_rate_limit": registry.params.max_rate_limit,
            })).collect::<Vec<_>>(),
        })
    }
}

/// The name and the registries a plan file asks for: what `derive` needs, on
/// top of the keys, to compute the same plan again.
pub fn specs_of(plan: &Value) -> Result<(String, Vec<RegistrySpec>), String> {
    if plan.get("format").and_then(Value::as_str) != Some(PLAN_FORMAT)
        || plan.get("version").and_then(Value::as_u64) != Some(PLAN_VERSION)
    {
        return Err(format!(
            "not a {PLAN_FORMAT} file of version {PLAN_VERSION}"
        ));
    }
    let name = plan
        .get("name")
        .and_then(Value::as_str)
        .ok_or("the plan has no name")?;
    let registries = plan
        .get("registries")
        .and_then(Value::as_array)
        .ok_or("the plan has no registries")?;
    let mut specs = Vec::with_capacity(registries.len());
    for registry in registries {
        let label = registry
            .get("label")
            .and_then(Value::as_str)
            .ok_or("a planned registry has no label")?;
        let number = |key: &str| {
            registry
                .get(key)
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("{label:?} has no number `{key}`"))
        };
        let seconds = |key: &str| {
            number(key).and_then(|n| {
                u32::try_from(n).map_err(|_| format!("{label:?}: `{key}` does not fit u32"))
            })
        };
        specs.push(RegistrySpec {
            label: label.to_string(),
            params: RegistryParams {
                price_per_unit: registry
                    .get("price_per_unit")
                    .and_then(Value::as_str)
                    .and_then(|raw| raw.parse().ok())
                    .ok_or_else(|| format!("{label:?} has no decimal string `price_per_unit`"))?,
                max_total_rate_limit: number("max_total_rate_limit")?,
                active_duration_sec: seconds("active_duration_secs")?,
                grace_period_duration_sec: seconds("grace_period_duration_secs")?,
                min_rate_limit: number("min_rate_limit")?,
                max_rate_limit: number("max_rate_limit")?,
            },
        });
    }
    Ok((name.to_string(), specs))
}

/// Where `derived` and a plan `file` differ, one line per field: empty when
/// the file is the plan these keys derive. The file may carry fields of its
/// own (a network reference, a sequencer). Image ids are compared apart
/// (`image_mismatch`): they describe the binaries, not the keys. The payer is
/// not compared: no id depends on it, and the file may name a key of its own
/// (`DeploymentPlan::paid_by`).
pub fn differences(derived: &Value, file: &Value) -> Vec<String> {
    fn walk(path: &str, derived: &Value, file: &Value, out: &mut Vec<String>) {
        match (derived, file) {
            (Value::Object(derived), Value::Object(file)) => {
                for (key, value) in derived {
                    if path.is_empty() && (key.ends_with("_image_id") || key.starts_with("payer_"))
                    {
                        continue;
                    }
                    let at = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    };
                    match file.get(key) {
                        Some(other) => walk(&at, value, other, out),
                        None => out.push(format!("{at}: missing from the plan file")),
                    }
                }
            }
            (Value::Array(derived), Value::Array(file)) if derived.len() == file.len() => {
                for (index, (value, other)) in derived.iter().zip(file).enumerate() {
                    walk(&format!("{path}[{index}]"), value, other, out);
                }
            }
            (derived, file) if derived == file => {}
            (derived, file) => out.push(format!("{path}: derived {derived}, the file says {file}")),
        }
    }
    let mut out = Vec::new();
    walk("", derived, file, &mut out);
    out
}

/// Where a registry's config on chain is not what the plan initializes it
/// with, one line per field: empty when it is. `Initialize` is one-shot, so
/// a difference here is for the registry's life.
pub fn config_differences(
    registry: &PlannedRegistry,
    merkle: &AccountId,
    config: &ConfigState,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut check = |field: &str, planned: String, on_chain: String| {
        if planned != on_chain {
            out.push(format!(
                "{}.{field}: planned {planned}, on chain {on_chain}",
                registry.label
            ));
        }
    };
    check(
        "tree_id",
        hex::encode(registry.tree_id),
        hex::encode(config.tree_id),
    );
    check(
        "merkle_program_id",
        hex_id(merkle),
        hex::encode(config.merkle_program_id),
    );
    check(
        "treasury_account",
        registry.treasury_account.to_string(),
        AccountId::new(config.treasury_account_id).to_string(),
    );
    check(
        "parameters",
        format!("{:?}", registry.params),
        format!("{:?}", RegistryParams::of(config)),
    );
    out
}

/// Why the local binary's image is not the one `plan` recorded under `key`;
/// `None` when it is, or when the plan recorded none.
pub fn image_mismatch(plan: &Value, key: &str, local: &ProgramId) -> Option<String> {
    let planned = plan.get(key).and_then(Value::as_str)?;
    let local = hex_image_id(local);
    (planned != local)
        .then(|| format!("{key}: the plan says {planned}, the local binary is {local}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> DeployKeys {
        DeployKeys::new([7u8; 32], "testnet").unwrap()
    }

    fn defaults() -> RegistryParams {
        RegistryParams {
            price_per_unit: 10_000,
            max_total_rate_limit: 1_000_000,
            active_duration_sec: 2_592_000,
            grace_period_duration_sec: 604_800,
            min_rate_limit: 100,
            max_rate_limit: 600,
        }
    }

    fn specs() -> Vec<RegistrySpec> {
        vec![
            RegistrySpec::parse("relay", defaults()).unwrap(),
            RegistrySpec::parse("mix:20:100", defaults()).unwrap(),
        ]
    }

    fn account(hex_id: &str) -> AccountId {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex_id, &mut bytes).unwrap();
        AccountId::new(bytes)
    }

    /// The registry id of a deployed registry, recomputed from its public
    /// descriptor: the derivation a plan relies on is the one the chain used.
    #[test]
    fn the_config_account_of_a_live_registry_is_reproduced() {
        let registration =
            account("8334e9e23f2779a464c8e76224cda148d09d28be4bd5620f82a6293f5f4d7b38");
        for (tree_id, config) in [
            (
                "12bebb247d086ba51e5b8622e793863a066ed1b40d637012cbbf134e1d5f8960",
                "9XLCUD4tggHKTU2yErjuxtJp75Pb2PHTUNyaQZYrNRgg",
            ),
            (
                "e3375ba1968559947b0ab71d29035cfcaebef68cd27187df184233f01394866d",
                "2RacihuUznbDrerdQqqf7gukkRnRbzXacsb4MnjC6sG9",
            ),
        ] {
            let mut tree = [0u8; 32];
            hex::decode_to_slice(tree_id, &mut tree).unwrap();
            assert_eq!(
                derive_config_account(&registration, &tree).to_string(),
                config
            );
        }
    }

    #[test]
    fn a_plan_is_a_function_of_the_keys_and_the_registries() {
        let plan = DeploymentPlan::derive(&keys(), &specs()).unwrap();
        assert_eq!(plan, DeploymentPlan::derive(&keys(), &specs()).unwrap());

        let [relay, mix] = plan.registries.as_slice() else {
            panic!("two registries were planned")
        };
        assert_eq!(
            relay.tree_id,
            rln_layouts::owner_tree_id(plan.owner.value(), &tree_label("relay").unwrap())
        );
        assert_eq!(
            relay.config_account,
            derive_config_account(&plan.programs.registration, &relay.tree_id)
        );
        assert_ne!(relay.tree_id, mix.tree_id);
        assert_ne!(relay.config_account, mix.config_account);
        assert_ne!(relay.treasury_account, mix.treasury_account);
        assert_eq!(
            (mix.params.min_rate_limit, mix.params.max_rate_limit),
            (20, 100)
        );
        assert_ne!(plan.programs.registration, plan.programs.merkle);
    }

    #[test]
    fn another_name_plans_other_ids_throughout() {
        let plan = DeploymentPlan::derive(&keys(), &specs()).unwrap();
        let other =
            DeploymentPlan::derive(&DeployKeys::new([7u8; 32], "rehearsal").unwrap(), &specs())
                .unwrap();
        assert_ne!(plan.programs.registration, other.programs.registration);
        assert_ne!(plan.programs.merkle, other.programs.merkle);
        assert_ne!(plan.owner, other.owner);
        assert_ne!(
            plan.registries[0].config_account,
            other.registries[0].config_account
        );
    }

    #[test]
    fn a_plan_file_derives_the_plan_it_holds() {
        let plan = DeploymentPlan::derive(&keys(), &specs()).unwrap();
        let mut file = plan.to_json(Some((&[1u32; 8], &[2u32; 8])));
        file["sequencer"] = json!("http://127.0.0.1:1/");

        let (name, from_file) = specs_of(&file).unwrap();
        assert_eq!(name, "testnet");
        assert_eq!(from_file, specs());
        let derived = DeploymentPlan::derive(&keys(), &from_file)
            .unwrap()
            .to_json(None);
        assert_eq!(differences(&derived, &file), Vec::<String>::new());
        assert_eq!(image_mismatch(&file, "merkle_image_id", &[2u32; 8]), None);
        assert!(image_mismatch(&file, "merkle_image_id", &[3u32; 8]).is_some());
        assert_eq!(
            image_mismatch(&derived, "merkle_image_id", &[3u32; 8]),
            None
        );
    }

    /// A payer of its own moves the payer and nothing else, and the file
    /// naming it is still the plan the deployment secret derives.
    #[test]
    fn a_payer_of_its_own_changes_no_id() {
        let derived = DeploymentPlan::derive(&keys(), &specs()).unwrap();
        let payer = PrivateKey::try_new([5u8; 32]).unwrap();
        let paid = derived.clone().paid_by(&payer);
        assert_eq!(paid.payer, account_of(&payer));
        assert_ne!(paid.payer, derived.payer);
        assert_ne!(paid.payer_public_key, derived.payer_public_key);
        assert_eq!(paid.programs, derived.programs);
        assert_eq!(paid.owner, derived.owner);
        assert_eq!(paid.registries, derived.registries);

        let file = paid.to_json(None);
        assert_eq!(file["payer_account"], json!(paid.payer.to_string()));
        assert_eq!(
            differences(&derived.to_json(None), &file),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_plan_file_of_other_keys_is_told_apart() {
        let file = DeploymentPlan::derive(&keys(), &specs())
            .unwrap()
            .to_json(None);
        let derived =
            DeploymentPlan::derive(&DeployKeys::new([8u8; 32], "testnet").unwrap(), &specs())
                .unwrap()
                .to_json(None);
        let found = differences(&derived, &file);
        assert!(
            found
                .iter()
                .any(|line| line.starts_with("registration_program_id:"))
        );
        assert!(
            found
                .iter()
                .any(|line| line.starts_with("registries[0].config_account:"))
        );
    }

    #[test]
    fn a_config_is_held_to_the_plan() {
        let plan = DeploymentPlan::derive(&keys(), &specs()).unwrap();
        let relay = &plan.registries[0];
        let config = ConfigState {
            merkle_program_id: *plan.programs.merkle.value(),
            tree_id: relay.tree_id,
            price_per_unit: relay.params.price_per_unit,
            treasury_account_id: *relay.treasury_account.value(),
            total_registrations: 3,
            max_total_rate_limit: relay.params.max_total_rate_limit,
            current_total_rate_limit: 300,
            active_duration_for_new_memberships_sec: relay.params.active_duration_sec,
            grace_period_duration_for_new_memberships_sec: relay.params.grace_period_duration_sec,
            min_rate_limit: relay.params.min_rate_limit,
            max_rate_limit: relay.params.max_rate_limit,
        };
        assert_eq!(
            config_differences(relay, &plan.programs.merkle, &config),
            Vec::<String>::new()
        );

        let squatted = ConfigState {
            treasury_account_id: [9u8; 32],
            max_rate_limit: relay.params.max_rate_limit + 1,
            ..config
        };
        let found = config_differences(relay, &plan.programs.registration, &squatted);
        for field in ["merkle_program_id", "treasury_account", "parameters"] {
            assert!(
                found
                    .iter()
                    .any(|line| line.starts_with(&format!("relay.{field}:"))),
                "{field}: {found:?}"
            );
        }
    }

    #[test]
    fn malformed_registries_are_refused() {
        for raw in [
            "",
            ":100:600",
            "relay:100",
            "relay:0:600",
            "relay:700:600",
            "relay:a:b",
        ] {
            assert!(RegistrySpec::parse(raw, defaults()).is_err(), "{raw:?}");
        }
        assert!(RegistrySpec::parse(&"x".repeat(33), defaults()).is_err());
        let twice = vec![
            RegistrySpec::parse("relay", defaults()).unwrap(),
            RegistrySpec::parse("relay:20:100", defaults()).unwrap(),
        ];
        assert!(DeploymentPlan::derive(&keys(), &twice).is_err());
        assert!(DeploymentPlan::derive(&keys(), &[]).is_err());
    }

    /// `LEZ_TAG` is what a plan says its ids hold for: the tag in the
    /// manifest.
    #[test]
    fn the_plan_names_the_lez_this_crate_builds_against() {
        let manifest = include_str!("../../Cargo.toml");
        assert!(manifest.contains(&format!("tag = \"{LEZ_TAG}\"")));
        assert!(!manifest.lines().any(|line| {
            line.contains("logos-execution-zone.git")
                && !line.contains(&format!("tag = \"{LEZ_TAG}\""))
        }));
    }
}
