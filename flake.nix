{
  description = "Logos LEZ RLN";

  inputs = {
    nixpkgs.follows = "logos-core/nixpkgs";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane.url = "github:ipetkov/crane";

    logos-core.url = "github:logos-co/logos-cpp-sdk/25c88f4d48fa95ea4437194bcf60bd8d0cf84a74";

    logos-execution-zone.url = "github:logos-blockchain/logos-execution-zone?rev=e37876a64028a335eb693198a1ed6a0e875ec5b4";

    logos-wallet-module = {
      url = "github:logos-blockchain/logos-execution-zone-module?rev=d70225ced646934d2294fd9e8f8b03615c104b80";
      inputs.logos-execution-zone.follows = "logos-execution-zone";
    };

    logos-module-viewer.url = "github:logos-co/logos-module-viewer";

    nix-bundle-lgx.url = "github:logos-co/nix-bundle-lgx";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      crane,
      logos-core,
      logos-wallet-module,
      logos-module-viewer,
      nix-bundle-lgx,
      ...
    }:
    let
      lib = nixpkgs.lib;

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-windows"
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

          # --- Rust: lez-rln-ffi ---
          rustToolchain = pkgs.rust-bin.stable.latest.default;
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
          # lez-rln consumes lssa/spel as git deps (see lez-rln/Cargo.toml), so the
          # FFI crate builds straight from ./lez-rln — no sibling lssa assembly.
          # crane vendors the git deps from Cargo.lock; each git source needs an
          # entry in gitOutputHashes below. Keep in sync with the git sources in
          # lez-rln/Cargo.lock (grep '^source = "git'); bump when the pins move.
          lezRlnTree = pkgs.lib.cleanSourceWith {
            src = ./lez-rln;
            filter = path: type:
              craneLib.filterCargoSources path type
              || pkgs.lib.hasSuffix ".toml" path
              || pkgs.lib.hasSuffix ".h" path
              || pkgs.lib.hasSuffix ".lock" path;
          };
          gitOutputHashes = {
            "git+https://github.com/logos-blockchain/logos-execution-zone.git?tag=v0.2.0-rc6#e37876a64028a335eb693198a1ed6a0e875ec5b4" = "sha256-ltLcysXUdVUXAe25Tl8x7e7ZsTzj1sHlyS3glp97TAo=";
            "git+https://github.com/logos-blockchain/logos-blockchain.git?rev=d8711bbc3d43d3ef9755ef9b73af32fd0f703160#d8711bbc3d43d3ef9755ef9b73af32fd0f703160" = "sha256-iRrGJzsghtSYSoXoa3W+P4RznLzZQrUGDkj0w1sZBiQ=";
            "git+https://github.com/logos-blockchain/logos-blockchain-circuits.git?tag=v0.5.3#127626881faa975aa8e9868422cf6bbb08fcb512" = "sha256-kzf4l4UywcxMqQwQcACBQl1QZYT9Nl6gbpb5FaphFqo=";
            "git+https://github.com/logos-blockchain/logos-blockchain-rust-rapidsnark.git?rev=e91187f8ccb5bbfc7bb00dac88169112428da78f#e91187f8ccb5bbfc7bb00dac88169112428da78f" = "sha256-A1wVkHRw3/xpV30JUgWxvfW5PgcyrxQxk7b4So5vXNs=";
            "git+https://github.com/logos-co/Overwatch?rev=448c192#448c192895b8311c742b1726a1bb12ee314ad95c" = "sha256-L7R1GdhRNNsymYe3RVyYLAmd6x1YY08TBJp4hG4/YwE=";
            "git+https://github.com/EspressoSystems/jellyfish.git?rev=8d80230358e900f8d63765a937f63f4978ca1daa#8d80230358e900f8d63765a937f63f4978ca1daa" = "sha256-XeOEusSl7YkdE05emaDjH1SccutWZt/6ty5l/9ylxNM=";
            "git+https://github.com/EspressoSystems/jellyfish?tag=jf-crhf-v0.2.0#f1538793f7f0e391495cb17bbb0c8703ec5f689d" = "sha256-fF5gqFm7xYLubl2QzNilcZl3O0NZMFckChrr7kVudok=";
            "git+https://github.com/arkworks-rs/spongefish.git?rev=3ded547f7f56d7f8a1fc4c9a5c0ce965310bba5f#3ded547f7f56d7f8a1fc4c9a5c0ce965310bba5f" = "sha256-prLkGrIavkaiVYKqSy+cLwl2Y1TkTp8vGl0HCeQdILc=";
          };
          cargoVendorDir = craneLib.vendorCargoDeps {
            src = lezRlnTree;
            outputHashes = gitOutputHashes;
          };

          lezRlnFfiPackage = craneLib.buildPackage {
            src = lezRlnTree;
            inherit cargoVendorDir;
            cargoToml = ./lez-rln/Cargo.toml;
            cargoLock = ./lez-rln/Cargo.lock;
            pname = "lez-rln-ffi";
            version = "0.1.0";
            cargoExtraArgs = "-p lez-rln-ffi";
            nativeBuildInputs = [
              pkgs.pkg-config
            ];
            postInstall = ''
              mkdir -p $out/include
              cp lez-rln-ffi/lez_rln_ffi.h $out/include/
            ''
            + pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
              install_name_tool -id @rpath/liblez_rln_ffi.dylib $out/lib/liblez_rln_ffi.dylib
            '';
          };

          # --- C++: logos-rln-module ---
          llvmPkgs = pkgs.llvmPackages;
          logosCore = pkgs.symlinkJoin {
            name = "logos-cpp-sdk";
            paths = [
              logos-core.packages.${system}.logos-cpp-lib
              logos-core.packages.${system}.logos-cpp-include
            ];
          };

          logosRlnModulePackage = pkgs.stdenv.mkDerivation {
            pname = "logos-rln-module";
            version = "dev";
            src = ./logos-rln-module;

            nativeBuildInputs = [
              pkgs.cmake
              pkgs.ninja
              pkgs.pkg-config
              pkgs.qt6.wrapQtAppsHook
            ];

            buildInputs = [
              pkgs.qt6.qtbase
              pkgs.qt6.qtremoteobjects
              pkgs.qt6.qttools
              llvmPkgs.clang
              llvmPkgs.libclang
              lezRlnFfiPackage
            ]
            ++ lib.optionals pkgs.stdenv.isDarwin [
              pkgs.libiconv
              pkgs.cacert
            ];

            LIBCLANG_PATH = "${llvmPkgs.libclang.lib}/lib";
            CLANG_PATH = "${llvmPkgs.clang}/bin/clang";
            SSL_CERT_FILE = lib.optionalString pkgs.stdenv.isDarwin "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";

            cmakeFlags = [
              "-DLOGOS_CORE_ROOT=${logosCore}"
              "-DLEZ_RLN_FFI_LIB=${lezRlnFfiPackage}/lib"
              "-DLEZ_RLN_FFI_INCLUDE=${lezRlnFfiPackage}/include"
            ];
          };

          walletModulePackage = logos-wallet-module.packages.${system}.lgx;

          # Content-addressed .lgx bundle for the rln module. Building this via
          # `nix build .#logos-rln-module-lgx` always produces the .lgx that
          # matches the current source — no /nix/store find + head -1 lottery.
          logosRlnModuleLgx =
            nix-bundle-lgx.bundlers.${system}.default logosRlnModulePackage;
          logosRlnModuleLgxPortable =
            nix-bundle-lgx.bundlers.${system}.portable logosRlnModulePackage;

        in
        {
          lez-rln-ffi = lezRlnFfiPackage;
          logos-rln-module = logosRlnModulePackage;
          logos-rln-module-lgx = logosRlnModuleLgx;
          logos-rln-module-lgx-portable = logosRlnModuleLgxPortable;
          wallet-module = walletModulePackage;
          default = lezRlnFfiPackage;
        }
      );

      apps = forAll (
        system:
        let
          pkgs = mkPkgs system;
          logosRlnModuleLib = self.packages.${system}.logos-rln-module;
          logosModuleViewerPackage = logos-module-viewer.packages.${system}.default;
          extension = if pkgs.stdenv.isDarwin then "dylib"
            else if pkgs.stdenv.hostPlatform.isWindows then "dll"
            else "so";
          inspectModule = {
            type = "app";
            program =
              "${pkgs.writeShellScriptBin "inspect-module" ''
                exec ${logosModuleViewerPackage}/bin/logos-module-viewer \
                  --module ${logosRlnModuleLib}/lib/liblogos_rln_module.${extension}
              ''}/bin/inspect-module";
          };
        in
        {
          inspect-module = inspectModule;
          default = inspectModule;
        }
      );

      devShells = forAll (
        system:
        let
          pkgs = mkPkgs system;
          lezRlnFfiPackage = self.packages.${system}.lez-rln-ffi;
          logosRlnModulePackage = self.packages.${system}.logos-rln-module;
          logosCorePackage = pkgs.symlinkJoin {
            name = "logos-cpp-sdk";
            paths = [
              logos-core.packages.${system}.logos-cpp-lib
              logos-core.packages.${system}.logos-cpp-include
            ];
          };
        in
        {
          default = pkgs.mkShell {
            inputsFrom = [ lezRlnFfiPackage ];
          };

          module = pkgs.mkShell {
            inputsFrom = [ logosRlnModulePackage ];

            inherit (logosRlnModulePackage)
              LIBCLANG_PATH
              CLANG_PATH;

            LOGOS_CORE_ROOT = "${logosCorePackage}";
            LEZ_RLN_FFI_LIB = "${lezRlnFfiPackage}/lib";
            LEZ_RLN_FFI_INCLUDE = "${lezRlnFfiPackage}/include";

            shellHook = ''
              BLUE='\e[1;34m'
              GREEN='\e[1;32m'
              RESET='\e[0m'

              echo -e "\n''${BLUE}=== Logos RLN Module Development Environment ===''${RESET}"
              echo -e "''${GREEN}LOGOS_CORE_ROOT:''${RESET}    $LOGOS_CORE_ROOT"
              echo -e "''${GREEN}LEZ_RLN_FFI_LIB:''${RESET}   $LEZ_RLN_FFI_LIB"
              echo -e "''${GREEN}LEZ_RLN_FFI_INCLUDE:''${RESET} $LEZ_RLN_FFI_INCLUDE"
              echo -e "''${BLUE}------------------------------------------------''${RESET}"
            '';
          };
        }
      );
    };
}
