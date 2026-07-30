{
  description = "Logos RLN Membership Management Module";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = fn: nixpkgs.lib.genAttrs systems fn;

      # The builder runs logos-lidl-gen to emit the module-impl C ABI scaffold
      # (+ the typed liblogos_rln_module dependency client) at
      # rust-lib/generated/, compiles the staticlib, and wraps it in the Qt
      # cdylib glue — all driven by metadata.json (codegen.rust +
      # dependency_overrides). Concurrency stays at the single default: the
      # register path is fire-and-record (lp_invoke_async), so no handler
      # blocks on a sequencer submit.
      #
      # No path-deps beyond the staged SDK: the membership logic is pure Rust
      # (CAIP-10 routing, keystore crypto, lifecycle state machine, and the
      # RLN proof engine — zerokit `rln`, stateless, from crates.io) and all
      # lez-rln REGISTRY knowledge lives behind the sibling module's wire —
      # no rln-layouts / risc0 in this crate.
      module = logos-module-builder.lib.mkLogosModule {
        src = ./.;
        configFile = ./metadata.json;
        flakeInputs = inputs;
      };
    in
    {
      packages = forAllSystems (system:
        let m = module.packages.${system};
        in m // {
          liblogos_rln_membership_module = m.default;
        });
    };
}
