# Shell for local development (use via flake: nix develop)
{
  pkgs ? import <nixpkgs> { },
  enableConfigUI ? true,
  linkerPackage ? pkgs.mold,
}:

let
  fexPkg = import ./package.nix { inherit pkgs enableConfigUI; };
in
pkgs.mkShell.override { stdenv = pkgs.clangStdenv; } {
  inputsFrom = [ fexPkg ];

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

  env = {
    CMAKE_GENERATOR = "Ninja";

    # Packages like mold must be unwrapped to get the required linker name
    LDFLAGS = "-fuse-ld=${linkerPackage.NIX_MAIN_PROGRAM or linkerPackage.pname}";

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
    echo "Configure CMake for FEX build: cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo"
  '';

  meta.description = "Shell for local FEX development";
}
