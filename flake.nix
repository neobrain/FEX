# Nix flake for FEX that handles all build/runtime dependencies.
# Install Nix: https://determinate.systems/nix-installer
#
# Examples:
#   nix develop:                           Enter a shell for local FEX development
#   nix profile install .submodules=1#fex: Install FEX to ~/.nix-profile (with pre-configured x86 RootFS)
#   nix run .#install-binfmt /path/to/fex: Register FEX as binfmt handler
#   nix fmt:                               Reformat source files
#   nix flake show:                        List all available targets
{
  description = "A fast usermode x86 and x86-64 emulator for Arm64 Linux";

  outputs =
    { self, nixpkgs }:
    let
      pkgs = nixpkgs.legacyPackages.aarch64-linux;
      gitRev =
        self.rev
          or (pkgs.lib.removeSuffix "-dirty" (self.dirtyRev or "0000000000000000000000000000000000000000"));
    in
    {
      # nix develop
      devShells.aarch64-linux.default = import ./Data/nix/shell.nix { inherit pkgs; };

      # FEX builds
      packages.aarch64-linux.fex = pkgs.callPackage ./Data/nix/package.nix {
        inherit gitRev;
        # TODO: Verify submodules are initialized. if not, point to submodules=1
      };
      packages.aarch64-linux.default = self.packages.aarch64-linux.fex;

      # Installs FEX as a binfmt handler via systemd-binfmt.
      # When called without arguments, FEX will be built in the Nix sandbox first.
      # To use an existing FEX build, pass it as a parameter:
      #   sudo nix run .#install-binfmt /path/to/FEX
      apps.aarch64-linux.install-binfmt = {
        type = "app";
        meta.description = "Install FEX as a binfmt handler (either provided by argument, or built from flake fex target)";
        program = toString (
          pkgs.writeShellScript "fex-install-binfmt" ''
            set -eu
            FEX_BIN="''${1:-}" # TODO: Run realpath on this
            if [ -z "$FEX_BIN" ]; then
              echo "No FEX binary given, building one..." >&2
              FEX_BIN="$(nix build --impure --no-link --print-out-paths .#fex)/bin/FEX"
            fi
            if [ ! -x "$FEX_BIN" ]; then
              echo "FEX binary not found or not executable: $FEX_BIN" >&2
              exit 1
            fi
            if [ "$(id -u)" -ne 0 ]; then
              exec sudo "$0" "$FEX_BIN"
            fi
            mkdir -p /etc/binfmt.d
            for arch in "x86" "x86_64"; do
              sed "s|@CMAKE_INSTALL_PREFIX@/bin/FEX|$FEX_BIN|g" "${self}/Data/binfmts/FEX-$arch.conf.in" > /etc/binfmt.d/FEX-$arch.conf
            done
            systemctl restart systemd-binfmt.service
            echo "Installed $FEX_BIN as binfmt handler" >&2
          ''
        );
      };

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
