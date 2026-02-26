{
  description = "Logos LEZ RLN";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      crane,
      ...
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-windows"
      ];

      forAll = nixpkgs.lib.genAttrs systems;

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
          rustToolchain = pkgs.rust-bin.stable.latest.default;
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
          src = ./.;

          lezRlnFfiPackage = craneLib.buildPackage {
            inherit src;
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
        in
        {
          lez-rln-ffi = lezRlnFfiPackage;
          default = lezRlnFfiPackage;
        }
      );

      devShells = forAll (
        system:
        let
          pkgs = mkPkgs system;
          lezRlnFfiPackage = self.packages.${system}.lez-rln-ffi;
        in
        {
          default = pkgs.mkShell {
            inputsFrom = [ lezRlnFfiPackage ];
          };
        }
      );
    };
}
