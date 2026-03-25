{
  description = "Mix Simulation Module - Orchestrates delivery and RLN modules for mix network simulations";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    logos-cpp-sdk.url = "github:logos-co/logos-cpp-sdk/a4bd66c";
  };

  outputs = { self, nixpkgs, logos-cpp-sdk }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f {
        pkgs = import nixpkgs { inherit system; };
        logosSdk = logos-cpp-sdk.packages.${system}.default;
      });
    in
    {
      packages = forAllSystems ({ pkgs, logosSdk }:
        let
          llvmPkgs = pkgs.llvmPackages;

          mixSimulationModule = pkgs.stdenv.mkDerivation {
            pname = "mix-simulation-module";
            version = "1.0.0";
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
            ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
              pkgs.libiconv
            ];

            LIBCLANG_PATH = "${llvmPkgs.libclang.lib}/lib";
            CLANG_PATH = "${llvmPkgs.clang}/bin/clang";

            cmakeFlags = [
              "-DLOGOS_CORE_ROOT=${logosSdk}"
            ];

            meta = with pkgs.lib; {
              description = "Mix Network Simulation Orchestrator Module";
              platforms = platforms.unix;
            };
          };
        in
        {
          default = mixSimulationModule;
          mix-simulation-module = mixSimulationModule;
        }
      );

      devShells = forAllSystems ({ pkgs, logosSdk }: {
        default = pkgs.mkShell {
          nativeBuildInputs = [
            pkgs.cmake
            pkgs.ninja
            pkgs.pkg-config
          ];
          buildInputs = [
            pkgs.qt6.qtbase
            pkgs.qt6.qtremoteobjects
          ];

          shellHook = ''
            export LOGOS_CORE_ROOT="${logosSdk}"
            echo "Mix Simulation Module development environment"
            echo "LOGOS_CORE_ROOT: $LOGOS_CORE_ROOT"
          '';
        };
      });
    };
}
