{
  description = "Logos RLN Module - Qt6 Plugin";

  inputs = {
    nixpkgs.follows = "logos-core/nixpkgs";

    logos-lez-rln.url = "github:logos-blockchain/logos-lez-rln";
    logos-core.url = "github:logos-co/logos-cpp-sdk/a4bd66c";

    logos-wallet-module = {
      url = "github:logos-blockchain/logos-execution-zone-module";
      inputs.logos-core.follows = "logos-core";
    };

    logos-module-viewer.url = "github:logos-co/logos-module-viewer";
  };

  outputs =
    {
      self,
      nixpkgs,
      logos-core,
      logos-lez-rln,
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

      mkPkgs = system: import nixpkgs { inherit system; };
    in
    {
      packages = forAll (
        system:
        let
          pkgs = mkPkgs system;
          llvmPkgs = pkgs.llvmPackages;

          logosCore = logos-core.packages.${system}.default;
          lezRlnFfiPackage = logos-lez-rln.packages.${system}.lez-rln-ffi;
          walletModulePackage = logos-wallet-module.packages.${system}.default;

          logosRlnModulePackage = pkgs.stdenv.mkDerivation {
            pname = "logos-rln-module";
            version = "dev";
            src = ./.;

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
        in
        {
          lib = logosRlnModulePackage;
          wallet-module = walletModulePackage;
          default = logosRlnModulePackage;
        }
      );

      apps = forAll (
        system:
        let
          pkgs = mkPkgs system;
          logosRlnModuleLib = self.packages.${system}.lib;
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
          pkg = self.packages.${system}.default;
          logosCorePackage = logos-core.packages.${system}.default;
          lezRlnFfiPackage = logos-lez-rln.packages.${system}.lez-rln-ffi;
        in
        {
          default = pkgs.mkShell {
            inputsFrom = [ pkg ];

            inherit (pkg)
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
