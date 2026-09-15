# Deployment profiles

Each `deployments/<name>/` is one provisioned RLN registry, captured as
`{deployment.json, storage.json}`. The tooling that writes and consumes them
lives in [`tools/deployments/`](../tools/deployments/README.md).

**This directory is currently empty, and that is deliberate.**

Registration became native-asset-only, which changed the guest program. The
config account is a PDA of `(registration_program_id, tree_id)` and the program
id is derived from the guest ELF, so a new guest re-derives **every** PDA of
every tree. The eight profiles that used to live here addressed a program that
no longer exists, and their descriptors describe a config layout — 296 bytes
with a payment token, a faucet cap and a free-quota registrar — that nothing
can decode any more. `stage.sh` refuses them by name; `verify.sh` refuses them
by guest hash.

They were deleted rather than left as history, because a deployment profile
that cannot be staged is not a record of anything: it is a trap for whoever
tries it next. `git log -- deployments/` has them if you need to look.

To provision one against the new program:

```sh
bash tools/deployments/provision.sh --name <name> --payer <account-id>
```

`--payer` must already hold native balance. No program can mint native, so it
arrives at genesis, over the L1 bridge, or by transfer from something already
funded.
