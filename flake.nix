# Nix flake for FEX that handles all build/runtime dependencies.
# Install Nix: https://determinate.systems/nix-installer
#
# Examples:
#   nix develop:                        Enter a shell for local FEX development
#   nix profile install --impure .#fex: Install FEX to ~/.nix-profile (with pre-configured x86 RootFS)
#   nix fmt:                            Reformat source files
#   nix flake show:                     List all available targets
{
  description = "A fast usermode x86 and x86-64 emulator for Arm64 Linux";

  outputs =
    { self, nixpkgs }:
    let
      pkgs = nixpkgs.legacyPackages.aarch64-linux;
      gitRev = self.rev or (pkgs.lib.removeSuffix "-dirty" (self.dirtyRev or "0000000000000000000000000000000000000000"));

      # Require impure builds to avoid pulling submodules just for the dev shell
      flakeRoot =
        if builtins.getEnv "PWD" == "" then
          throw "Package builds require --impure (from the repo root): nix profile install .#fex --impure"
        else
          builtins.getEnv "PWD";
    in
    {
      # nix develop
      devShells.aarch64-linux.default = import ./Data/nix/shell.nix { inherit pkgs; };

      # FEX builds
      packages.aarch64-linux.fex = pkgs.callPackage ./Data/nix/package.nix {
        inherit gitRev;
        src = builtins.fetchGit {
          url = flakeRoot;
          submodules = true;
        };
      };
      packages.aarch64-linux.default = self.packages.aarch64-linux.fex;

      # nix fmt
      formatter.aarch64-linux = pkgs.writeShellApplication {
        name = "fex-fmt";
        runtimeInputs = [
          pkgs.llvmPackages_19.clang-tools
          pkgs.nixfmt
          pkgs.git
        ];
        text = ''
          git ls-files -z '*.nix' | head -n1 | xargs -0 -n 1 -P "$(nproc)" nixfmt
          git ls-files -z '*.cpp' '*.h' '*.inl' | xargs -0 -n 1 -P "$(nproc)" clang-format -i
        '';
      };
    };
}
