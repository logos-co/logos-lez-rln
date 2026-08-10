{
  description = "Logos LEZ RLN";

  inputs = {
    nixpkgs.follows = "logos-core/nixpkgs";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    logos-core.url = "github:logos-co/logos-cpp-sdk/25c88f4d48fa95ea4437194bcf60bd8d0cf84a74";

  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
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
          check-membership = checkMembership;
          default = checkMembership;
        }
      );

      apps = forAll (system: {
        check-membership = {
          type = "app";
          program = "${self.packages.${system}.check-membership}/bin/check-membership";
        };
        default = {
          type = "app";
          program = "${self.packages.${system}.check-membership}/bin/check-membership";
        };
      });

      devShells = forAll (
        system:
        let
          pkgs = mkPkgs system;
        in
        {
          # A minimal shell for the `lez-rln` crate (run_setup, gifter, etc.).
          # The RLN modules live in logos-co/logos-rln-modules.
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
