{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/8d8c1fa5b412c223ffa47410867813290cdedfef";
    umu-launcher = {
      url = "github:Open-Wine-Components/umu-launcher?dir=packaging/nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    protonix = {
      url = "path:/home/tony/code/FEX/Data/nix/WineOnArm/protonix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      umu-launcher,
      protonix,
    }:
    let
      pkgs = nixpkgs.legacyPackages.aarch64-linux;
      pkgs-x86 = nixpkgs.legacyPackages.x86_64-linux;

      repro = pkgs.pkgsCross.mingwW64.stdenv.mkDerivation {
        name = "hangover-issue-225-repro";
        src = ./.;

        buildPhase = ''
          $CC -O2 -o repro.exe main.c -luser32
        '';

        installPhase = ''
          mkdir -p $out/bin
          cp repro.exe $out/bin/
        '';
      };
    in
    {
      packages.aarch64-linux = {
        default = repro;
        inherit repro;
      };

      apps.aarch64-linux = {
        test-arm64ec = {
          type = "app";
          program = "${pkgs.writeShellScript "test-arm64ec" ''
            set -euo pipefail
            export PROTONPATH=${protonix.packages.aarch64-linux.protonix}
            export WINEPREFIX=$(mktemp -d)
            trap 'rm -rf "$WINEPREFIX"' EXIT
            ${umu-launcher.packages.aarch64-linux.default}/bin/umu-run ${repro}/bin/repro.exe
          ''}";
        };
        test-fex-wine = {
          type = "app";
          program = "${pkgs.writeShellScript "test-fex-wine" ''
            set -euo pipefail
            export WINEPREFIX=$(mktemp -d)
            export WINEDLLOVERRIDES="mscoree=d" # Skip mono install prompt
            trap 'rm -rf "$WINEPREFIX"' EXIT
            # ${pkgs.fex}/bin/FEX ${pkgs-x86.wine64}/bin/wine ${repro}/bin/repro.exe
            /home/tony/code/FEX/build/install/bin/FEX ${pkgs-x86.wine64}/bin/wine ${repro}/bin/repro.exe
          ''}";
        };
      };
    };
}
