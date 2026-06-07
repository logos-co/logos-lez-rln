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

    logos-execution-zone.url = "github:adklempner/lssa/feat/rln-sim-98e98c62-wallet-ffi";

    logos-wallet-module = {
      url = "github:logos-blockchain/logos-execution-zone-module";
      inputs.logos-cpp-sdk.follows = "logos-core";
      inputs.logos-execution-zone.follows = "logos-execution-zone";
    };

    logos-module-viewer.url = "github:logos-co/logos-module-viewer";
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
          ffiSrc = pkgs.lib.cleanSourceWith {
            src = ./lez-rln;
            filter = path: type:
              craneLib.filterCargoSources path type
              || pkgs.lib.hasSuffix ".toml" path
              || pkgs.lib.hasSuffix ".h" path;
          };

          lezRlnFfiPackage = craneLib.buildPackage {
            src = ffiSrc;
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

          walletModulePackage = logos-wallet-module.packages.${system}.default;

        in
        {
          lez-rln-ffi = lezRlnFfiPackage;
          logos-rln-module = logosRlnModulePackage;
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
