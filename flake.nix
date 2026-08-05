{
  description = "Logos LEZ RLN";

  inputs = {
    nixpkgs.follows = "logos-core/nixpkgs";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    logos-core.url = "github:logos-co/logos-cpp-sdk/25c88f4d48fa95ea4437194bcf60bd8d0cf84a74";

    logos-execution-zone.url = "github:logos-blockchain/logos-execution-zone?rev=e37876a64028a335eb693198a1ed6a0e875ec5b4";

    logos-wallet-module = {
      url = "github:logos-blockchain/logos-execution-zone-module?rev=d70225ced646934d2294fd9e8f8b03615c104b80";
      inputs.logos-execution-zone.follows = "logos-execution-zone";
    };

    logos-module-viewer.url = "github:logos-co/logos-module-viewer";

    # Path input: its logos-module-builder closure inlines into flake.lock
    # (roughly doubling it). Deliberately no nested `follows` — the
    # duplicated nixpkgs nodes already lock our same rev, the builder pins
    # its own rust-overlay/toolchain, and dedup is only reachable upstream
    # in the builder.
    logos-rln-module.url = "path:./logos-rln-module";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      logos-wallet-module,
      logos-module-viewer,
      logos-rln-module,
      ...
    }:
    let
      lib = nixpkgs.lib;

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];

      forAll = lib.genAttrs systems;

      mkPkgs =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
    in
    {
      packages = forAll (
        system:
        let
          pkgs = mkPkgs system;

          walletModulePackage = logos-wallet-module.packages.${system}.lgx;

          # The RLN module is the Rust `logos-rln-module` (a flake input). The
          # sim overrides that input with a local `path:` tree at build time
          # (`--override-input logos-rln-module path:...`) so its gitignored
          # staged sources — logos-rust-sdk-src + rust-lib/lez-rln-src — are
          # visible; the default `path:./logos-rln-module` covers in-tree builds.
          rlnModule = logos-rln-module.packages.${system};

          # Standalone membership verifier (tools/check-membership): a small
          # rln-layouts-only crate, built with the repo's pinned toolchain and
          # wrapped so `curl` (its sequencer transport) is on PATH.
          rust = pkgs.rust-bin.stable."1.94.0".minimal;
          checkMembership =
            (pkgs.makeRustPlatform { cargo = rust; rustc = rust; }).buildRustPackage {
              pname = "check-membership";
              version = "0.1.0";
              src = ./.;
              cargoRoot = "tools/check-membership";
              buildAndTestSubdir = "tools/check-membership";
              cargoLock.lockFile = ./tools/check-membership/Cargo.lock;
              nativeBuildInputs = [ pkgs.makeWrapper ];
              postInstall = ''
                wrapProgram $out/bin/check-membership \
                  --prefix PATH : ${pkgs.curl}/bin
              '';
            };
        in
        {
          logos-rln-module = rlnModule.default;
          logos-rln-module-lgx = rlnModule.lgx;
          wallet-module = walletModulePackage;
          check-membership = checkMembership;
          default = rlnModule.lgx;
        }
      );

      apps = forAll (
        system:
        let
          pkgs = mkPkgs system;
          logosRlnModuleLib = self.packages.${system}.logos-rln-module;
          logosModuleViewerPackage = logos-module-viewer.packages.${system}.default;
          extension = if pkgs.stdenv.isDarwin then "dylib" else "so";
          inspectModule = {
            type = "app";
            program =
              "${pkgs.writeShellScriptBin "inspect-module" ''
                exec ${logosModuleViewerPackage}/bin/logos-module-viewer \
                  --module ${logosRlnModuleLib}/lib/liblogos_rln_module_plugin.${extension}
              ''}/bin/inspect-module";
          };
        in
        {
          inspect-module = inspectModule;
          check-membership = {
            type = "app";
            program = "${self.packages.${system}.check-membership}/bin/check-membership";
          };
          default = inspectModule;
        }
      );

      devShells = forAll (
        system:
        let
          pkgs = mkPkgs system;
        in
        {
          # The RLN module lives in `logos-rln-module` — `cd logos-rln-module
          # && nix develop` for its Rust dev shell. This is a minimal shell for
          # the `lez-rln` crate (run_setup, gifter, etc.).
          default = pkgs.mkShell {
            packages = [
              pkgs.rust-bin.stable.latest.default
              pkgs.pkg-config
            ];
          };
        }
      );
    };
}
