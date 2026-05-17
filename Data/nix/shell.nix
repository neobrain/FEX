# Shell for local development (use via flake: nix develop)
{
  pkgs ? import <nixpkgs> { },
  enableConfigUI ? true,
  enableLibraryForwarding ? true,
  linkerPackage ? pkgs.mold,
}:

let
  libForwardingShell = import ./LibraryForwarding/shell.nix { inherit pkgs; };
  fexPkg = import ./package.nix { inherit pkgs enableConfigUI enableLibraryForwarding; };
in
pkgs.mkShell.override { stdenv = pkgs.clangStdenv; } {
  inputsFrom = [ fexPkg ] ++ pkgs.lib.optionals enableLibraryForwarding [ libForwardingShell ];
  inherit (libForwardingShell) FEX_CMAKE_TOOLCHAINS ROOTFS;

  packages = with pkgs; [
    # Build tools
    ccache
    linkerPackage

    # RootFS handling
    erofs-utils
    squashfsTools # unsquashfs, no squashfuse
    squashfuse # TODO: Not verified

    # Avoids spammy warning messages on non-default locales
    glibcLocales
  ];

  # TODO: vulkan-tools-lunarg, enable via VK_INSTANCE_LAYERS=VK_LAYER_LUNARG_api_dump (and maybe VK_LAYER_PATH=${vulkan-tools-lunarg}/share/vulkan/explicit_layer.d)

  env = fexPkg.passthru.env // {
    CMAKE_GENERATOR = "Ninja";

    # Packages like mold must be unwrapped to get the required linker name
    LDFLAGS = "-fuse-ld=${linkerPackage.NIX_MAIN_PROGRAM or linkerPackage.pname}";

    LD_LIBRARY_PATH = with pkgs;
      lib.optionalString enableLibraryForwarding (lib.makeLibraryPath [ vulkan-loader ]);

    # Set Qt runtime paths that wrapQtAppsHook would normally handle
    QT_PLUGIN_PATH = pkgs.lib.optionalString enableConfigUI (
      pkgs.lib.makeSearchPath "lib/qt-6/plugins" [
        pkgs.qt6.qtbase
        pkgs.qt6.qtwayland
      ]
    );
    QML2_IMPORT_PATH = pkgs.lib.optionalString enableConfigUI (
      pkgs.lib.makeSearchPath "lib/qt-6/qml" [
        pkgs.qt6.qtbase
        pkgs.qt6.qtdeclarative
      ]
    );

    # Use portable mode to ignore binfmt handlers
    FEX_PORTABLE = 1;
    FEX_ROOTFS = "${fexPkg.passthru.rootfs}";
  };

  shellHook = ''
    echo "RootFS: ${fexPkg.passthru.rootfs}"
    echo "Configure CMake for FEX build: cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \$FEX_CMAKE_TOOLCHAINS -DBUILD_THUNKS=ON"

    # Drop /nix/store paths of ARM builds for essential tools (bash, ldd) from PATH.
    # Within a FEXBash, these would take priority over the x86 RootFS.
    # Outside a FEXBash, they are also present in /usr/bin anyway.
    strip_bash_from_path() {
      PATH=$(echo "$PATH" | sed -E 's#(${pkgs.bashInteractive}|${pkgs.bashNonInteractive}|${pkgs.glibc.bin}|${pkgs.pkgsCross.gnu64.glibc.bin}|${pkgs.pkgsCross.gnu32.glibc.bin})/bin:##g')
    }
    # Call once for non-interactive shells;
    # add to PROMPT_COMMAND for interactive shells
    strip_bash_from_path
    PROMPT_COMMAND="strip_bash_from_path''${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
  '';

  meta.description = "Shell for local FEX development";
}
